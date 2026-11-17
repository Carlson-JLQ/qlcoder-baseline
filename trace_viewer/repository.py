from __future__ import annotations

import csv
import difflib
import json
import re
import threading
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RUN_RE = re.compile(
    r"^ql_agent_(CVE-\d{4}-\d+)_(\d{8}_\d{6})_(\d+)-iterations_(.+)$"
)
PHASE3_RE = re.compile(r"^phase3_iter_(\d+)_output\.txt$")
QUERY_RE = re.compile(r"^(CVE-\d{4}-\d+)-query-iter-(\d+)\.ql$")
TEXT_ARTIFACT_SUFFIXES = {".txt", ".json", ".csv", ".ql", ".md", ".yml", ".yaml", ".sarif"}
MAX_ARTIFACT_BYTES = 3 * 1024 * 1024


def _read_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None


def _as_number(value: Any, default: int | float = 0) -> int | float:
    return value if isinstance(value, (int, float)) else default


def _iso_from_timestamp(value: float) -> str:
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()


def _tail_text(path: Path, size: int = 196_608) -> str:
    try:
        with path.open("rb") as handle:
            handle.seek(0, 2)
            length = handle.tell()
            handle.seek(max(0, length - size))
            return handle.read().decode("utf-8", errors="replace")
    except OSError:
        return ""


def _tail_result_summary(path: Path) -> dict[str, Any]:
    tail = _tail_text(path)
    turns = re.findall(r'"num_turns"\s*:\s*(\d+)', tail)
    subtypes = re.findall(r'"subtype"\s*:\s*"([^"]+)"', tail)
    stop_reasons = re.findall(r'"stop_reason"\s*:\s*"([^"]*)"', tail)
    return {
        "num_turns": int(turns[-1]) if turns else None,
        "subtype": subtypes[-1] if subtypes else None,
        "stop_reason": stop_reasons[-1] if stop_reasons else None,
        "has_complete_result": '"type":"result"' in tail or '"type": "result"' in tail,
    }


def _timestamp_ms(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000)
    except ValueError:
        return None


def _safe_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, indent=2)
    except (TypeError, ValueError):
        return str(value)


def _content_to_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return _safe_json(content)
    pieces: list[str] = []
    for block in content:
        if isinstance(block, str):
            pieces.append(block)
        elif isinstance(block, dict):
            if block.get("type") == "text":
                pieces.append(str(block.get("text", "")))
            elif block.get("type") == "tool_reference":
                pieces.append(f"Tool reference: {block.get('tool_name', '')}")
            else:
                pieces.append(_safe_json(block))
        else:
            pieces.append(str(block))
    return "\n".join(piece for piece in pieces if piece)


def tool_category(name: str) -> str:
    lowered = name.lower()
    if name in {"Bash", "Shell", "exec_command"}:
        return "Shell"
    if name in {"Read", "Glob", "Grep"}:
        return "File inspection"
    if name in {"Write", "Edit", "NotebookEdit"}:
        return "File mutation"
    if "codeql" in lowered:
        return "CodeQL LSP"
    if "chroma" in lowered:
        return "RAG / Chroma"
    if name in {"WebSearch", "WebFetch"} or "web" in lowered:
        return "Web research"
    if name == "ToolSearch":
        return "Tool discovery"
    if name in {"Task", "SendMessage", "ListAgents", "TaskCreate", "TaskGet", "TaskList", "TaskUpdate"}:
        return "Agent orchestration"
    return "Other"


@dataclass(frozen=True)
class TraceCacheEntry:
    signature: tuple[int, int]
    events: list[dict[str, Any]]
    stats: dict[str, Any]


class TraceRepository:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.output_root = (self.root / "output").resolve()
        self._trace_cache: dict[str, TraceCacheEntry] = {}
        self._lock = threading.RLock()
        self._cwe_map = self._load_cwe_map()

    def _load_cwe_map(self) -> dict[str, dict[str, str]]:
        result: dict[str, dict[str, str]] = {}
        path = self.root / "data" / "project_info.csv"
        try:
            with path.open(newline="", encoding="utf-8", errors="replace") as handle:
                for row in csv.DictReader(handle):
                    cve = row.get("cve_id")
                    if cve and cve not in result:
                        result[cve] = {
                            "cwe": row.get("cwe_id") or "Unknown",
                            "cwe_name": row.get("cwe_name") or "",
                            "project": row.get("project_slug") or "",
                        }
        except OSError:
            pass
        return result

    def _parse_directory_name(self, path: Path) -> dict[str, Any] | None:
        match = RUN_RE.match(path.name)
        if not match:
            return None
        cve, stamp, max_iterations, tail = match.groups()
        model, mode = (tail.rsplit("_", 1) + [""])[:2] if "_" in tail else (tail, "")
        try:
            started = datetime.strptime(stamp, "%Y%m%d_%H%M%S").replace(tzinfo=timezone.utc)
            started_at = started.isoformat()
        except ValueError:
            started_at = stamp
        return {
            "id": path.name,
            "cve": cve,
            "started_at": started_at,
            "max_iterations": int(max_iterations),
            "model": model,
            "mode": mode,
        }

    def _run_path(self, run_id: str) -> Path:
        if Path(run_id).name != run_id:
            raise ValueError("Invalid run id")
        path = (self.output_root / run_id).resolve()
        if path.parent != self.output_root or not path.is_dir():
            raise FileNotFoundError(run_id)
        return path

    @staticmethod
    def _results_path(run_path: Path) -> Path:
        results = run_path / "results"
        return results if results.is_dir() else run_path

    def _files(self, results: Path) -> list[Path]:
        try:
            return [path for path in results.iterdir() if path.is_file()]
        except OSError:
            return []

    def _derive_status(
        self,
        results: Path,
        metadata: dict[str, Any] | None,
        files: list[Path],
        last_modified: float,
    ) -> tuple[str, str]:
        analysis = (metadata or {}).get("analysis_metadata") or {}
        if isinstance(analysis.get("success"), bool):
            if analysis["success"]:
                return "SUCCESS", "Accepted query found"
            return "FAILED", analysis.get("error") or "Run completed without an accepted query"

        phase1_metrics = _read_json(results / "phase1_metrics.json") or {}
        phase3 = sorted(
            (path for path in files if PHASE3_RE.match(path.name)),
            key=lambda item: int(PHASE3_RE.match(item.name).group(1)),
        )
        latest_trace = phase3[-1] if phase3 else (results / "phase1_output.txt")
        tail = _tail_result_summary(latest_trace) if latest_trace.exists() else {}
        age = datetime.now(tz=timezone.utc).timestamp() - last_modified

        if age < 20:
            if phase3:
                return "ITERATING", f"Phase 3 iteration {PHASE3_RE.match(phase3[-1].name).group(1)}"
            if latest_trace.exists():
                return "PHASE1_RUNNING", "Phase 1 trace is still being written"
            return "DISCOVERED", "Run directory discovered"

        if not phase3 and phase1_metrics and not phase1_metrics.get("success", False):
            if tail.get("subtype") == "error_max_turns":
                return "PHASE1_FAILED", "Phase 1 reached the turn limit"
            return "PHASE1_FAILED", "Phase 1 did not complete successfully"
        if tail.get("subtype") == "error_max_turns":
            return "MAX_TURNS", "Latest iteration reached the turn limit"
        if phase3:
            return "INCOMPLETE", "Phase 3 artifacts exist, but final metadata is missing"
        if latest_trace.exists():
            return "INCOMPLETE", "Trace ended without final run metadata"
        return "DISCOVERED", "No phase output found"

    def _summarize_run(self, path: Path) -> dict[str, Any] | None:
        base = self._parse_directory_name(path)
        if not base:
            return None
        results = self._results_path(path)
        files = self._files(results)
        last_modified = max((item.stat().st_mtime for item in files), default=path.stat().st_mtime)
        metadata = _read_json(results / "iterative_metadata.json")
        analysis = (metadata or {}).get("analysis_metadata") or {}
        phases = self.list_phases(path.name, include_trace_stats=False)
        turns = 0
        known_turns = False
        for phase in phases:
            trace_name = phase.get("trace_file")
            if not trace_name:
                continue
            summary = _tail_result_summary(results / trace_name)
            if summary.get("num_turns") is not None:
                turns += summary["num_turns"]
                known_turns = True
        status, status_detail = self._derive_status(results, metadata, files, last_modified)
        cwe = self._cwe_map.get(base["cve"], {})
        usage = analysis.get("api_usage_summary") or {}
        base.update(
            {
                **cwe,
                "status": status,
                "status_detail": status_detail,
                "results_directory": str(results),
                "last_modified": _iso_from_timestamp(last_modified),
                "iterations": int(_as_number(analysis.get("total_iterations"), len([p for p in phases if p["kind"] == "phase3"]))),
                "runtime_seconds": float(_as_number(analysis.get("duration_seconds"), 0)),
                "tokens": int(_as_number(analysis.get("total_estimated_tokens"), 0)),
                "turns": turns if known_turns else None,
                "cost_cny": float(_as_number(usage.get("total_cost_usd"), 0)),
                "phase_count": len(phases),
                "query_count": len([item for item in files if QUERY_RE.match(item.name)]),
                "artifact_count": len(files),
            }
        )
        return base

    def list_runs(self) -> list[dict[str, Any]]:
        if not self.output_root.is_dir():
            return []
        runs = [summary for path in self.output_root.iterdir() if path.is_dir() if (summary := self._summarize_run(path))]
        return sorted(runs, key=lambda item: (item["started_at"], item["id"]), reverse=True)

    def get_run(self, run_id: str) -> dict[str, Any]:
        path = self._run_path(run_id)
        summary = self._summarize_run(path)
        if summary is None:
            raise FileNotFoundError(run_id)
        results = self._results_path(path)
        metadata = _read_json(results / "iterative_metadata.json") or {}
        analysis = metadata.get("analysis_metadata") or {}
        summary["phases"] = self.list_phases(run_id, include_trace_stats=False)
        summary["iterations_detail"] = analysis.get("iterations") or self._discover_iterations(results)
        summary["token_breakdown_by_phase"] = analysis.get("token_breakdown_by_phase") or {}
        summary["artifacts"] = self.list_artifacts(run_id)
        return summary

    def _discover_iterations(self, results: Path) -> list[dict[str, Any]]:
        numbers: set[int] = set()
        for path in self._files(results):
            for pattern in (PHASE3_RE, QUERY_RE):
                match = pattern.match(path.name)
                if match:
                    numbers.add(int(match.groups()[-1]))
        discovered: list[dict[str, Any]] = []
        for number in sorted(numbers):
            query = next(results.glob(f"CVE-*-query-iter-{number}.ql"), None)
            metrics = _read_json(results / f"phase3_iter_{number}_metrics.json") or {}
            execution = results / f"execution_iter_{number}.txt"
            discovered.append(
                {
                    "iteration": number,
                    "query_path": str(query) if query else None,
                    "success": bool(query),
                    "compilation_successful": (results / f"compilation_iter_{number}.txt").exists(),
                    "execution_summary": execution.read_text(encoding="utf-8", errors="replace") if execution.exists() else None,
                    "error": None if metrics.get("success") else "Context execution failed",
                }
            )
        return discovered

    def list_phases(self, run_id: str, include_trace_stats: bool = False) -> list[dict[str, Any]]:
        run_path = self._run_path(run_id)
        results = self._results_path(run_path)
        phases: list[dict[str, Any]] = []
        phase1 = results / "phase1_output.txt"
        if phase1.exists():
            phases.append(self._phase_descriptor("phase1", "Phase 1", "phase1", None, phase1, results, include_trace_stats))
        phase2 = results / "phase2_output.txt"
        if phase2.exists():
            phases.append(
                {
                    "id": "phase2",
                    "label": "Phase 2 · AST",
                    "kind": "phase2",
                    "iteration": None,
                    "trace_file": None,
                    "artifact_file": phase2.name,
                    "status": "COMPLETE",
                }
            )
        phase3_files = sorted(
            (path for path in self._files(results) if PHASE3_RE.match(path.name)),
            key=lambda item: int(PHASE3_RE.match(item.name).group(1)),
        )
        for path in phase3_files:
            number = int(PHASE3_RE.match(path.name).group(1))
            phases.append(
                self._phase_descriptor(
                    f"phase3_iter_{number}",
                    f"Iteration {number}",
                    "phase3",
                    number,
                    path,
                    results,
                    include_trace_stats,
                )
            )
        return phases

    def _phase_descriptor(
        self,
        phase_id: str,
        label: str,
        kind: str,
        iteration: int | None,
        trace: Path,
        results: Path,
        include_trace_stats: bool,
    ) -> dict[str, Any]:
        metrics = _read_json(results / f"{phase_id}_metrics.json") or {}
        tail = _tail_result_summary(trace)
        query = next(results.glob(f"CVE-*-query-iter-{iteration}.ql"), None) if iteration else None
        status = "COMPLETE" if tail.get("has_complete_result") else "RUNNING"
        if tail.get("subtype") == "error_max_turns":
            status = "MAX_TURNS"
        elif metrics and not metrics.get("success", False):
            status = "ERROR"
        descriptor: dict[str, Any] = {
            "id": phase_id,
            "label": label,
            "kind": kind,
            "iteration": iteration,
            "trace_file": trace.name,
            "metrics_file": f"{phase_id}_metrics.json" if (results / f"{phase_id}_metrics.json").exists() else None,
            "prompt_file": f"{phase_id}_prompt.txt" if (results / f"{phase_id}_prompt.txt").exists() else None,
            "stderr_file": f"{phase_id}_stderr.txt" if (results / f"{phase_id}_stderr.txt").exists() else None,
            "query_file": query.name if query else None,
            "status": status,
            "num_turns": tail.get("num_turns"),
            "stop_reason": tail.get("subtype") or tail.get("stop_reason"),
            "size_bytes": trace.stat().st_size,
            "modified_at": _iso_from_timestamp(trace.stat().st_mtime),
            "metrics": metrics,
        }
        if include_trace_stats:
            descriptor["trace_stats"] = self.load_trace(run_id=results.parent.name, phase_id=phase_id)["stats"]
        return descriptor

    def _trace_path(self, run_id: str, phase_id: str) -> Path:
        results = self._results_path(self._run_path(run_id))
        if phase_id == "phase1":
            name = "phase1_output.txt"
        elif re.fullmatch(r"phase3_iter_\d+", phase_id):
            name = f"{phase_id}_output.txt"
        else:
            raise ValueError("Unknown trace phase")
        path = (results / name).resolve()
        if path.parent != results.resolve() or not path.is_file():
            raise FileNotFoundError(name)
        return path

    def load_trace(self, run_id: str, phase_id: str) -> dict[str, Any]:
        path = self._trace_path(run_id, phase_id)
        stat = path.stat()
        signature = (stat.st_mtime_ns, stat.st_size)
        cache_key = str(path)
        with self._lock:
            cached = self._trace_cache.get(cache_key)
            if cached and cached.signature == signature:
                return {"events": cached.events, "stats": cached.stats}

        raw = _read_json(path)
        if not isinstance(raw, list):
            raise ValueError("Trace is incomplete or is not a JSON event array")
        events, stats = self._normalize_trace(raw)
        entry = TraceCacheEntry(signature=signature, events=events, stats=stats)
        with self._lock:
            self._trace_cache[cache_key] = entry
        return {"events": events, "stats": stats}

    def _normalize_trace(self, raw: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        results: dict[str, dict[str, Any]] = {}
        for event in raw:
            if event.get("type") != "user":
                continue
            message = event.get("message") or {}
            for block in message.get("content") or []:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    tool_id = block.get("tool_use_id")
                    if tool_id:
                        results[tool_id] = {
                            "timestamp": event.get("timestamp"),
                            "is_error": bool(block.get("is_error")),
                            "content": _content_to_text(block.get("content")),
                            "meta": event.get("tool_result_meta"),
                            "structured": event.get("tool_use_result"),
                        }

        normalized: list[dict[str, Any]] = []
        tool_counts: Counter[str] = Counter()
        category_counts: Counter[str] = Counter()
        assistant_message_ids: set[str] = set()
        turn = 0
        thinking_blocks = 0
        system_token_events = 0
        estimated_tokens = 0
        unmatched_calls = 0

        for raw_index, event in enumerate(raw):
            event_type = event.get("type")
            if event_type == "system" and event.get("subtype") == "thinking_tokens":
                system_token_events += 1
                estimated_tokens = max(estimated_tokens, int(_as_number(event.get("estimated_tokens"), 0)))
                continue
            if event_type == "system" and event.get("subtype") == "init":
                normalized.append(
                    {
                        "sequence": len(normalized),
                        "raw_index": raw_index,
                        "kind": "session",
                        "turn": 0,
                        "timestamp": None,
                        "title": "Session initialized",
                        "content": f"Model: {event.get('model', 'unknown')}\nWorking directory: {event.get('cwd', '')}",
                        "details": event,
                    }
                )
                continue
            if event_type == "assistant":
                message = event.get("message") or {}
                message_id = message.get("id") or event.get("uuid") or f"event-{raw_index}"
                if message_id not in assistant_message_ids:
                    assistant_message_ids.add(message_id)
                    turn += 1
                content = message.get("content") or []
                if not isinstance(content, list):
                    content = [{"type": "text", "text": str(content)}]
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    block_type = block.get("type")
                    if block_type == "thinking":
                        thinking_blocks += 1
                        normalized.append(
                            {
                                "sequence": len(normalized),
                                "raw_index": raw_index,
                                "kind": "thinking",
                                "turn": turn,
                                "timestamp": event.get("timestamp"),
                                "title": f"Turn {turn} · Thinking",
                                "content": block.get("thinking") or block.get("text") or "",
                                "details": {"thinking_duration_ms": event.get("thinking_duration_ms")},
                            }
                        )
                    elif block_type == "text":
                        normalized.append(
                            {
                                "sequence": len(normalized),
                                "raw_index": raw_index,
                                "kind": "assistant",
                                "turn": turn,
                                "timestamp": event.get("timestamp"),
                                "title": f"Turn {turn} · Assistant",
                                "content": block.get("text") or "",
                                "details": {},
                            }
                        )
                    elif block_type == "tool_use":
                        name = str(block.get("name") or "Unknown tool")
                        category = tool_category(name)
                        tool_counts[name] += 1
                        category_counts[category] += 1
                        tool_id = block.get("id")
                        result = results.get(tool_id) or {}
                        if not result:
                            unmatched_calls += 1
                        started_ms = _timestamp_ms(event.get("timestamp"))
                        finished_ms = _timestamp_ms(result.get("timestamp"))
                        duration = finished_ms - started_ms if started_ms is not None and finished_ms is not None else None
                        normalized.append(
                            {
                                "sequence": len(normalized),
                                "raw_index": raw_index,
                                "kind": "tool",
                                "turn": turn,
                                "timestamp": event.get("timestamp"),
                                "title": name,
                                "tool_id": tool_id,
                                "tool_name": name,
                                "tool_category": category,
                                "input": block.get("input") or {},
                                "content": result.get("content") or "",
                                "is_error": bool(result.get("is_error")),
                                "result_timestamp": result.get("timestamp"),
                                "duration_ms": duration,
                                "details": {
                                    "result_meta": result.get("meta"),
                                    "structured_result": result.get("structured"),
                                },
                            }
                        )
                continue
            if event_type == "result":
                normalized.append(
                    {
                        "sequence": len(normalized),
                        "raw_index": raw_index,
                        "kind": "result",
                        "turn": turn,
                        "timestamp": None,
                        "title": f"Session result · {event.get('subtype') or event.get('stop_reason') or 'complete'}",
                        "content": "\n".join(event.get("errors") or []) or str(event.get("result") or ""),
                        "is_error": bool(event.get("is_error")),
                        "details": event,
                    }
                )

        stats = {
            "raw_event_count": len(raw),
            "display_event_count": len(normalized),
            "tool_call_count": sum(tool_counts.values()),
            "tool_result_count": len(results),
            "unmatched_tool_calls": unmatched_calls,
            "unmatched_tool_results": len(set(results) - {event.get("tool_id") for event in normalized if event.get("kind") == "tool"}),
            "thinking_blocks": thinking_blocks,
            "assistant_turns_observed": turn,
            "system_token_events": system_token_events,
            "estimated_thinking_tokens": estimated_tokens,
            "tools": dict(tool_counts.most_common()),
            "categories": dict(category_counts.most_common()),
        }
        return normalized, stats

    def get_trace_page(
        self,
        run_id: str,
        phase_id: str,
        offset: int = 0,
        limit: int = 80,
        kind: str | None = None,
        tool: str | None = None,
        search: str | None = None,
    ) -> dict[str, Any]:
        trace = self.load_trace(run_id, phase_id)
        events = trace["events"]
        if kind and kind != "all":
            events = [event for event in events if event.get("kind") == kind]
        if tool:
            lowered_tool = tool.lower()
            events = [event for event in events if lowered_tool in str(event.get("tool_name", "")).lower()]
        if search:
            needle = search.lower()
            events = [
                event
                for event in events
                if needle
                in " ".join(
                    [
                        str(event.get("title", "")),
                        str(event.get("content", "")),
                        _safe_json(event.get("input", {})),
                    ]
                ).lower()
            ]
        total = len(events)
        page = [self._event_preview(event) for event in events[offset : offset + limit]]
        return {
            "events": page,
            "offset": offset,
            "limit": limit,
            "total": total,
            "has_more": offset + limit < total,
            "stats": trace["stats"],
        }

    @staticmethod
    def _event_preview(event: dict[str, Any]) -> dict[str, Any]:
        copy = dict(event)
        content = str(copy.get("content") or "")
        copy["content_length"] = len(content)
        copy["content"] = content[:4_000]
        if len(content) > 4_000:
            copy["content_truncated"] = True
        details = copy.get("details") or {}
        details_text = _safe_json(details)
        if len(details_text) > 8_000:
            copy["details"] = {"preview": details_text[:8_000], "truncated": True}
        return copy

    def get_trace_event(self, run_id: str, phase_id: str, sequence: int) -> dict[str, Any]:
        events = self.load_trace(run_id, phase_id)["events"]
        for event in events:
            if event.get("sequence") == sequence:
                return event
        raise FileNotFoundError(f"Trace event {sequence}")

    def list_artifacts(self, run_id: str) -> list[dict[str, Any]]:
        results = self._results_path(self._run_path(run_id))
        artifacts: list[dict[str, Any]] = []
        for path in sorted(self._files(results), key=lambda item: item.name.lower()):
            if path.name.startswith("."):
                continue
            artifacts.append(
                {
                    "name": path.name,
                    "size_bytes": path.stat().st_size,
                    "modified_at": _iso_from_timestamp(path.stat().st_mtime),
                    "type": self._artifact_type(path.name),
                    "viewable": path.suffix.lower() in TEXT_ARTIFACT_SUFFIXES and path.stat().st_size <= MAX_ARTIFACT_BYTES,
                }
            )
        return artifacts

    @staticmethod
    def _artifact_type(name: str) -> str:
        if QUERY_RE.match(name):
            return "query"
        if name.endswith("_output.txt"):
            return "trace"
        if "results_eval" in name:
            return "evaluation"
        if "results" in name and name.endswith(".csv"):
            return "results"
        if name.startswith("execution_iter_"):
            return "validation"
        if name.startswith("compilation_iter_"):
            return "compilation"
        if name.endswith("metrics.json"):
            return "metrics"
        if name.endswith("prompt.txt"):
            return "prompt"
        return "artifact"

    def read_artifact(self, run_id: str, name: str) -> dict[str, Any]:
        if Path(name).name != name:
            raise ValueError("Invalid artifact name")
        results = self._results_path(self._run_path(run_id)).resolve()
        path = (results / name).resolve()
        if path.parent != results or not path.is_file():
            raise FileNotFoundError(name)
        size = path.stat().st_size
        if path.suffix.lower() not in TEXT_ARTIFACT_SUFFIXES:
            return {"name": name, "size_bytes": size, "binary": True, "content": None}
        if size > MAX_ARTIFACT_BYTES:
            return {
                "name": name,
                "size_bytes": size,
                "binary": False,
                "truncated": True,
                "content": path.read_text(encoding="utf-8", errors="replace")[:MAX_ARTIFACT_BYTES],
            }
        return {
            "name": name,
            "size_bytes": size,
            "binary": False,
            "truncated": False,
            "content": path.read_text(encoding="utf-8", errors="replace"),
        }

    def query_diff(self, run_id: str, from_iteration: int, to_iteration: int) -> dict[str, Any]:
        results = self._results_path(self._run_path(run_id))
        old = next(results.glob(f"CVE-*-query-iter-{from_iteration}.ql"), None)
        new = next(results.glob(f"CVE-*-query-iter-{to_iteration}.ql"), None)
        if not old or not new:
            raise FileNotFoundError("One or both query iterations do not exist")
        old_lines = old.read_text(encoding="utf-8", errors="replace").splitlines()
        new_lines = new.read_text(encoding="utf-8", errors="replace").splitlines()
        diff = "\n".join(
            difflib.unified_diff(old_lines, new_lines, fromfile=old.name, tofile=new.name, lineterm="")
        )
        return {"from": old.name, "to": new.name, "diff": diff}

    def summary(self) -> dict[str, Any]:
        runs = self.list_runs()
        statuses = Counter(run["status"] for run in runs)
        return {
            "run_count": len(runs),
            "cve_count": len({run["cve"] for run in runs}),
            "statuses": dict(statuses),
            "total_tokens": sum(int(run.get("tokens") or 0) for run in runs),
            "total_cost_cny": sum(float(run.get("cost_cny") or 0) for run in runs),
        }
