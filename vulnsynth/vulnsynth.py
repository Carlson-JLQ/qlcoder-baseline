#!/usr/bin/env python3

import asyncio
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import argparse

os.environ["ANONYMIZED_TELEMETRY"] = "false"

SUPPORTED_MODELS = [
    "sonnet-4",
    "sonnet-4.5",
    "sonnet-4.6",
    "gemini-2.5-pro",
    "gemini-2.5-flash",
    "gpt-5",
    "gpt-5.4",
    "gpt-5.5-2026-04-24",
    "deepseek-v4-pro[1m]",
    "deepseek-v4-flash[1m]",
]

DEFAULT_AGENT = "coco"
DEFAULT_MODEL_BY_AGENT = {
    "claude": "sonnet-4.6",
    "coco": "gpt-5.4",
    "gemini": "gemini-2.5-pro",
    "codex": "gpt-5.4",
}

try:
    from .agent_backends_vulnsynth import create_backend
    from .ast_extraction import run_phase2
    from .component_repair_prompts import get_prompt_spec
    from .config import AST_CACHE, CODEQL_PATH, FIX_INFO, NVD_CACHE, get_chroma_client
    from .data_types import IterationResult, VulnAnalysisTask
    from .diff_preprocessor import process_diff_file
    from .probe_evaluation import evaluate_probe_query, markdown_summary
    from .query_repair_pipeline import (
        build_repair_plan,
        render_repair_suggestions,
        render_repair_summary,
        render_selected_prompts,
    )
    from .query_subagents_evaluation import compile_query_once, run_query_with_evaluation_results
    from .repair_template_selector import select_components
    from .utils import extract_last_agent_message, extract_phase1_sections, parse_phase1_json, render_phase1_json_markdown
except ImportError:
    from agent_backends_vulnsynth import create_backend
    from ast_extraction import run_phase2
    from component_repair_prompts import get_prompt_spec
    from config import AST_CACHE, CODEQL_PATH, FIX_INFO, NVD_CACHE, get_chroma_client
    from data_types import IterationResult, VulnAnalysisTask
    from diff_preprocessor import process_diff_file
    from probe_evaluation import evaluate_probe_query, markdown_summary
    from query_repair_pipeline import (
        build_repair_plan,
        render_repair_suggestions,
        render_repair_summary,
        render_selected_prompts,
    )
    from query_subagents_evaluation import compile_query_once, run_query_with_evaluation_results
    from repair_template_selector import select_components
    from utils import extract_last_agent_message, extract_phase1_sections, parse_phase1_json, render_phase1_json_markdown


PROBLEM_COMPONENT_ORDER = ("source", "sink", "barrier", "flow")
PROBLEM_COMPONENT_STATUS_SET = {
    "missing_component",
    "compile_failed",
    "run_failed",
    "empty",
    "only_fixed",
    "off_target",
    "overblocking_suspect",
    "non_discriminative",
    "weak_but_present",
    "weak_bridge",
    "noisy_bridge",
    "others",
}
TOP_HIT_LIMIT = 5
SUPPORTING_FACTS_FIELD_REFERENCE_LINES = [
    "- `present_in_query`: whether the current query explicitly contains this component.",
    "- `compile_success`: whether the standalone component probe compiles successfully.",
    "- `compile_error`: the compile error message for this component probe when compilation fails.",
    "- `run.vulnerable`: execution facts for this component probe on the vulnerable database.",
    "- `run.fixed`: execution facts for this component probe on the fixed database.",
    "- `success`: whether execution on this side succeeds.",
    "- `error`: runtime error message on this side when execution fails.",
    "- `num_results`: total number of results returned on this side.",
    "- `num_aligned_files`: how many hit files on this side overlap with target files.",
    "- `num_aligned_methods`: how many hit methods on this side overlap with target methods.",
    "- `aligned_files`: the overlapping target files found on this side.",
    "- `aligned_methods`: the overlapping target methods found on this side.",
    "- `target_file_coverage`: fraction of target files covered by this side (`num_aligned_files / total_target_files`).",
    "- `target_method_coverage`: fraction of target methods covered by this side (`num_aligned_methods / total_target_methods`).",
    "- `hit_files`: representative files hit by this probe on this side.",
    "- `hit_methods`: representative methods hit by this probe on this side.",
]
SUPPORTING_FACTS_READ_GUIDANCE_LINES = [
    "How to read Supporting Facts:",
    "- For source/sink, alignment fields are usually the most important signal.",
    "- For barrier/flow, result counts and cross-version comparison are usually more important than target alignment.",
    "- Empty arrays or zero values do not necessarily mean the component is useless; interpret them together with Status and Facts abstract.",
]
FACTS_ABSTRACT_BY_STATUS = {
    "missing_component": "The component is not present in the current query.",
    "compile_failed": "The component exists in the query, but its standalone probe fails to compile.",
    "run_failed": "The component compiles, but probe execution failed on at least one side.",
    "empty": "The component produces no results on either vulnerable or fixed versions.",
    "only_fixed": "The component only matches the fixed version, which suggests reversed modeling.",
    "off_target": "The component has matches, but neither side aligns to target methods, indicating off-target modeling.",
    "weak_but_present": "The component has some target alignment, but it still overlaps with the fixed side and is not yet stable enough.",
    "overblocking_suspect": "The barrier suppresses far more vulnerable-side results than fixed-side results, which suggests overblocking.",
    "non_discriminative": "The barrier matches both vulnerable and fixed versions, so it has weak discriminative value.",
    "weak_bridge": "The flow component has bridge evidence, but it is still too weak to clearly support the intended path.",
    "noisy_bridge": "The flow component produces many bridge facts on both sides, and the counts are close, suggesting noisy shared propagation.",
    "others": "The component falls into an uncategorized abnormal state under the current evidence.",
}
COMMON_ALIGNMENT_RUN_FIELDS = [
    "success",
    "num_results",
    "error",
    "num_aligned_files",
    "num_aligned_methods",
    "aligned_files",
    "aligned_methods",
    "target_file_coverage",
    "target_method_coverage",
    "hit_files",
    "hit_methods",
]
STATUS_SUPPORTING_FACTS_SPECS = {
    "missing_component": {
        "top": ["present_in_query"],
    },
    "compile_failed": {
        "top": ["compile_success", "compile_error"],
    },
    "run_failed": {
        "top": ["present_in_query", "compile_success"],
        "run": ["success", "error"],
    },
    "empty": {
        "top": ["present_in_query", "compile_success"],
        "run": ["num_results"],
    },
    "only_fixed": {
        "run": {
            "vulnerable": ["num_results"],
            "fixed": [
                "num_results",
                "num_aligned_files",
                "num_aligned_methods",
                "aligned_files",
                "aligned_methods",
                "target_file_coverage",
                "target_method_coverage",
                "hit_files",
                "hit_methods",
            ],
        },
    },
    "off_target": {
        "top": ["present_in_query", "compile_success", "compile_error"],
        "run": COMMON_ALIGNMENT_RUN_FIELDS,
    },
    "weak_but_present": {
        "top": ["present_in_query", "compile_success", "compile_error"],
        "run": COMMON_ALIGNMENT_RUN_FIELDS,
    },
    "overblocking_suspect": {
        "top": ["present_in_query", "compile_success", "compile_error"],
        "run": COMMON_ALIGNMENT_RUN_FIELDS,
    },
    "non_discriminative": {
        "top": ["present_in_query", "compile_success", "compile_error"],
        "run": COMMON_ALIGNMENT_RUN_FIELDS,
    },
    "weak_bridge": {
        "top": ["present_in_query", "compile_success", "compile_error"],
        "run": COMMON_ALIGNMENT_RUN_FIELDS,
    },
    "noisy_bridge": {
        "top": ["present_in_query", "compile_success", "compile_error"],
        "run": COMMON_ALIGNMENT_RUN_FIELDS,
    },
    "others": {
        "top": ["present_in_query", "compile_success", "compile_error"],
        "run": COMMON_ALIGNMENT_RUN_FIELDS,
    },
}


def _trim_problem_component_value(key: str, value: Any) -> Any:
    if key in {"hit_files", "hit_methods"} and isinstance(value, list):
        return value[:TOP_HIT_LIMIT]
    return value


def _ordered_prompt_problem_components(report: dict[str, Any]) -> list[dict[str, Any]]:
    order = {role: idx for idx, role in enumerate(PROBLEM_COMPONENT_ORDER)}
    items = [
        item for item in (report.get("problem_components") or [])
        if item.get("status") in PROBLEM_COMPONENT_STATUS_SET and item.get("role") in order
    ]
    return sorted(items, key=lambda item: order[item["role"]])


def _render_repair_direction(role: str, status: str) -> str:
    try:
        return get_prompt_spec(role, status).prompt_text_en
    except KeyError:
        return (
            f"The {role} component is marked as `{status}`. "
            "Inspect the component facts and adjust only this component before considering broader query changes.\n"
            "Do not rewrite the whole query."
        )


def _copy_selected_run_fields(side_report: dict[str, Any], fields: list[str]) -> dict[str, Any]:
    selected: dict[str, Any] = {}
    for field in fields:
        if field in side_report:
            selected[field] = _trim_problem_component_value(field, side_report[field])
    return selected


def _build_problem_component_supporting_facts(status: str, component: dict[str, Any]) -> dict[str, Any]:
    spec = STATUS_SUPPORTING_FACTS_SPECS.get(status, STATUS_SUPPORTING_FACTS_SPECS["others"])
    facts: dict[str, Any] = {}
    for key in spec.get("top", []):
        if key in component:
            facts[key] = _trim_problem_component_value(key, component[key])

    run_spec = spec.get("run")
    run = component.get("run")
    if isinstance(run_spec, list) and isinstance(run, dict):
        run_facts: dict[str, Any] = {}
        for side in ("vulnerable", "fixed"):
            side_report = run.get(side)
            if isinstance(side_report, dict):
                selected = _copy_selected_run_fields(side_report, run_spec)
                if selected:
                    run_facts[side] = selected
        if run_facts:
            facts["run"] = run_facts
    elif isinstance(run_spec, dict) and isinstance(run, dict):
        run_facts = {}
        for side in ("vulnerable", "fixed"):
            fields = run_spec.get(side, [])
            side_report = run.get(side)
            if isinstance(side_report, dict) and fields:
                selected = _copy_selected_run_fields(side_report, fields)
                if selected:
                    run_facts[side] = selected
        if run_facts:
            facts["run"] = run_facts

    return facts


def _render_problem_components_section(report: dict[str, Any]) -> str:
    lines = ["## Problem Components", "", "## Supporting Facts Field Reference"]
    lines.extend(SUPPORTING_FACTS_FIELD_REFERENCE_LINES)
    lines.extend(["", *SUPPORTING_FACTS_READ_GUIDANCE_LINES, ""])

    problem_components = _ordered_prompt_problem_components(report)
    if not problem_components:
        lines.extend(["- No problem components were selected.", ""])
        return "\n".join(lines).rstrip() + "\n"

    components = report.get("components", {})
    for item in problem_components:
        role = item["role"]
        status = item["status"]
        component = components.get(role, {})
        repair_direction = _render_repair_direction(role, status)
        facts_abstract = FACTS_ABSTRACT_BY_STATUS.get(status, FACTS_ABSTRACT_BY_STATUS["others"])
        supporting_facts = _build_problem_component_supporting_facts(status, component)
        lines.extend(
            [
                f"## {role}",
                f"- Status: `{status}`",
                "- Repair direction:",
                *[f"  {line}" for line in repair_direction.splitlines()],
                "- Facts abstract:",
                f"  {facts_abstract}",
                "- Supporting Facts",
                "```json",
                json.dumps(supporting_facts, ensure_ascii=False, indent=2),
                "```",
                "",
            ]
        )

    return "\n".join(lines).rstrip() + "\n"


def _render_probe_guided_feedback(report: dict[str, Any]) -> str:
    return "\n\n".join(
        [
            "# Probe-Guided Repair Feedback",
            _render_problem_components_section(report).strip(),
        ]
    )


def _load_backend_config(config_path: Optional[str]) -> Dict[str, Any]:
    if not config_path:
        return {}

    resolved_path = os.path.abspath(config_path)
    with open(resolved_path, "r", encoding="utf-8") as f:
        config = json.load(f)

    if not isinstance(config, dict):
        raise ValueError(f"Backend config must be a JSON object: {resolved_path}")

    return config


def _resolve_model_for_agent(agent_type: str, model: Optional[str]) -> str:
    if model:
        return model
    return DEFAULT_MODEL_BY_AGENT.get(agent_type, "gpt-5.4")


class Vulnsynth_Agent_IterativeCLI:
    def __init__(self, agent_type: str, model: str, ablation_mode: str):
        self.agent_type = agent_type
        self.model = model
        self.ablation_mode = ablation_mode
        self.logger: Optional[logging.Logger] = None
        self.iteration_results: list[IterationResult] = []

    def _setup_logger(self, results_dir: str, cve_id: str) -> logging.Logger:
        logger = logging.getLogger(f"vulnsynth.{cve_id}.{os.getpid()}")
        logger.setLevel(logging.INFO)
        logger.handlers.clear()
        logger.propagate = False

        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        log_path = os.path.join(results_dir, f"vulnsynth_{cve_id}.log")

        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

        logger.info(f"Log file: {log_path}")
        return logger

    def _prepare_output_dirs(self, cve_id: str, output_root: str) -> str:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        run_dir = os.path.join(
            output_root,
            f"vulnsynth_{cve_id}_{timestamp}_{self.model}_{self.ablation_mode}",
            "results",
        )
        os.makedirs(run_dir, exist_ok=True)
        return run_dir

    def _load_text_file(self, path: str) -> str:
        return Path(path).read_text(encoding="utf-8")

    def _build_failure_result(
        self,
        *,
        results_dir: str,
        stdout_path: Optional[str],
        stderr_path: Optional[str],
        structured_path: Optional[str],
        readable_md_path: Optional[str],
        diff_focus_json_path: str,
        diff_focus_md_path: str,
        phase1_success: bool,
        phase2_success: bool,
        phase2_skipped: bool,
        phase2_output_path: Optional[str],
        phase2_metrics_path: Optional[str],
        phase2_result: Optional[Dict[str, Any]],
        stop_reason: str,
        proceed_to_next_stage: bool = False,
    ) -> Dict[str, Any]:
        result = {
            "results_dir": results_dir,
            "phase1_success": phase1_success,
            "phase1_output_file": stdout_path,
            "phase1_stderr_file": stderr_path,
            "phase1_structured_file": structured_path,
            "phase1_readable_markdown": readable_md_path if readable_md_path and os.path.exists(readable_md_path) else None,
            "phase2_success": phase2_success,
            "phase2_skipped": phase2_skipped,
            "phase2_output_file": phase2_output_path if phase2_output_path and os.path.exists(phase2_output_path) else None,
            "phase2_metrics_file": phase2_metrics_path if phase2_metrics_path and os.path.exists(phase2_metrics_path) else None,
            "phase2_result": self._json_safe(phase2_result) if phase2_result is not None else None,
            "diff_focus_json": diff_focus_json_path,
            "diff_focus_markdown": diff_focus_md_path,
            "stop_reason": stop_reason,
            "proceed_to_next_stage": proceed_to_next_stage,
        }
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return result

    def _phase3_collection_name(self, cve_id: str) -> str:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        return f"cve_analysis_{cve_id.lower().replace('-', '_')}_{os.getpid()}_{timestamp}"

    def _store_phase1_structured_to_chroma(
        self,
        *,
        task: VulnAnalysisTask,
        results_dir: str,
        collection_name: str,
        structured: Dict[str, Any],
    ) -> None:
        client = get_chroma_client()
        try:
            collection = client.get_collection(name=collection_name)
        except Exception:
            collection = client.create_collection(
                name=collection_name,
                metadata={
                    "cve_id": task.cve_id or "unknown",
                    "analysis_dir": results_dir,
                    "timestamp": datetime.utcnow().isoformat(),
                },
            )

        docs = []
        metas = []
        ids = []
        mapping = {
            "vulnerability_research_summary": "vulnerability_analysis_summary",
            "cve_information": "cve_info",
            "relevant_files": "relevant_files",
            "sources": "sources",
            "sinks": "sinks",
            "sanitizers": "sanitizers",
            "additional_taint_steps": "additional_taint_steps",
            "vulnerability_summary": "vulnerability_summary",
        }
        for source_key, section_name in mapping.items():
            value = structured.get(source_key)
            if not value:
                continue
            document = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, indent=2)
            ids.append(f"phase1_{section_name}")
            docs.append(document)
            metas.append(
                {
                    "phase": 1,
                    "section": section_name,
                    "cve_id": task.cve_id or "unknown",
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )
        if docs:
            collection.add(ids=ids, documents=docs, metadatas=metas)
            if self.logger:
                self.logger.info(f"Stored {len(docs)} Phase 1 sections in Chroma collection: {collection_name}")

    async def _execute_context_window(
        self,
        *,
        backend,
        prompt: str,
        env: Dict[str, str],
        cwd: str,
        phase_name: str,
        stdin_text: Optional[str] = None,
    ) -> Dict[str, Any]:
        result = await backend.execute_prompt(
            prompt=prompt,
            env=env,
            cwd=cwd,
            phase_name=phase_name,
            stdin_text=stdin_text,
        )
        stdout_path = os.path.join(cwd, f"{phase_name}_output.txt")
        stderr_path = os.path.join(cwd, f"{phase_name}_stderr.txt")
        Path(stdout_path).write_text(result.get("stdout", ""), encoding="utf-8")
        Path(stderr_path).write_text(result.get("stderr", ""), encoding="utf-8")
        metrics = {
            "phase_name": phase_name,
            "success": result.get("returncode", 1) == 0,
            "return_code": result.get("returncode", 1),
            "character_count": len(result.get("stdout", "")),
            "stderr_characters": len(result.get("stderr", "")),
            "output_file": stdout_path,
            "stderr_file": stderr_path,
            "timestamp": datetime.utcnow().isoformat(),
            "api_usage": result.get("api_usage", {}),
        }
        metrics_path = os.path.join(cwd, f"{phase_name}_metrics.json")
        Path(metrics_path).write_text(json.dumps(metrics, indent=2), encoding="utf-8")
        return {
            "success": result.get("returncode", 1) == 0,
            "output": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
            "context_length": len(result.get("stdout", "")),
            "metrics_file": metrics_path,
        }

    async def _test_iteration_query(
        self,
        *,
        context_result: Dict[str, Any],
        task: VulnAnalysisTask,
        results_dir: str,
        iteration: int,
    ) -> IterationResult:
        iteration_result = IterationResult(
            iteration_number=iteration,
            context_length=context_result.get("context_length", 0),
        )
        if not context_result.get("success"):
            iteration_result.error = context_result.get("stderr") or "Context execution failed"
            return iteration_result

        context_output = context_result.get("output", "")
        query_path = self._extract_query_file_path(context_output, results_dir)

        if not query_path:
            expected_filename = f"{task.cve_id}-query-iter-{iteration}.ql"
            expected_path = os.path.join(results_dir, expected_filename)
            if os.path.exists(expected_path):
                query_path = expected_path

        if not query_path:
            iteration_result.error = f"Query file not found for iteration {iteration}"
            return iteration_result

        if not query_path.endswith(".ql"):
            iteration_result.error = f"Extracted query path is not a .ql file: {query_path}"
            return iteration_result

        if not os.path.exists(query_path):
            iteration_result.error = f"Query file does not exist: {query_path}"
            return iteration_result

        if os.path.getsize(query_path) <= 0:
            iteration_result.error = f"Query file is empty: {query_path}"
            return iteration_result

        iteration_result.query_path = query_path
        compilation_summary = await compile_query_once(query_path, self.logger)
        iteration_result.compilation_summary = compilation_summary
        compilation_path = os.path.join(results_dir, f"compilation_iter_{iteration}.txt")
        Path(compilation_path).write_text(compilation_summary, encoding="utf-8")

        if "COMPILATION SUCCESS" not in compilation_summary:
            iteration_result.error = "Compilation failed"
            return iteration_result

        iteration_result.compilation_successful = True
        execution_summary, vuln_eval, fixed_eval, execution_successful = await run_query_with_evaluation_results(
            query_path=query_path,
            vuln_db_path=task.vuln_db_path,
            fixed_db_path=task.fixed_db_path,
            cve_id=task.cve_id,
            iteration_number=iteration,
            output_dir=results_dir,
            logger=self.logger,
        )
        iteration_result.execution_summary = execution_summary
        execution_path = os.path.join(results_dir, f"execution_iter_{iteration}.txt")
        Path(execution_path).write_text(execution_summary, encoding="utf-8")
        iteration_result.vulnerable_results = vuln_eval.num_results if vuln_eval else 0
        iteration_result.fixed_results = fixed_eval.num_results if fixed_eval else 0
        iteration_result.success = execution_successful
        iteration_result.vuln_recall_method = vuln_eval.recall_method if vuln_eval else False
        iteration_result.fixed_recall_method = fixed_eval.recall_method if fixed_eval else False
        iteration_result.vuln_tp_methods = vuln_eval.num_tp_methods if vuln_eval else 0
        iteration_result.fixed_tp_methods = fixed_eval.num_tp_methods if fixed_eval else 0
        iteration_result.vuln_num_results = vuln_eval.num_results if vuln_eval else 0
        iteration_result.fixed_num_results = fixed_eval.num_results if fixed_eval else 0
        iteration_result.vuln_eval_result = vuln_eval
        iteration_result.fixed_eval_result = fixed_eval
        self._update_phase3_metrics_with_query(results_dir, iteration, iteration_result)
        return iteration_result

    def _extract_query_file_path(self, context_output: str, results_dir: str) -> Optional[str]:
        for raw_line in reversed(context_output.splitlines()):
            line = raw_line.strip()
            if not line.startswith("QUERY_FILE_PATH:"):
                continue
            candidate = line.split("QUERY_FILE_PATH:", 1)[1].strip().strip("`'\"* ")
            if not candidate:
                continue
            if os.path.exists(candidate):
                return candidate
            filename = os.path.basename(candidate)
            for location in [
                os.path.join(results_dir, filename),
                os.path.join(".", filename),
            ]:
                if os.path.exists(location):
                    return location
        return None

    def _is_iteration_successful(self, iteration_result: IterationResult) -> bool:
        if not iteration_result.compilation_successful:
            return False
        if iteration_result.vuln_tp_methods <= 0:
            return False
        return iteration_result.fixed_recall_method is False and iteration_result.vuln_tp_methods > 0

    def _build_original_query_summary(self, iteration_result: IterationResult) -> Dict[str, Any]:
        notes = []
        if iteration_result.error:
            notes.append(iteration_result.error)
        return {
            "compile_success": iteration_result.compilation_successful,
            "vuln_num_results": iteration_result.vuln_num_results,
            "fixed_num_results": iteration_result.fixed_num_results,
            "vuln_recall_method": iteration_result.vuln_recall_method,
            "fixed_recall_method": iteration_result.fixed_recall_method,
            "notes": notes,
        }

    def _generate_basic_feedback(self, iteration_result: IterationResult) -> str:
        lines = [f"## Iteration {iteration_result.iteration_number} Results"]
        if iteration_result.query_path and os.path.exists(iteration_result.query_path):
            try:
                lines.append("\n## Previous Query")
                lines.append("```ql")
                lines.append(Path(iteration_result.query_path).read_text(encoding="utf-8"))
                lines.append("```")
            except Exception:
                pass
        if iteration_result.error:
            lines.append(f"\nError: {iteration_result.error}")
        if iteration_result.compilation_summary:
            lines.append("\n## Compilation Results")
            lines.append(iteration_result.compilation_summary)
        if iteration_result.execution_summary:
            lines.append("\n## Execution Results")
            lines.append(iteration_result.execution_summary)
        lines.append("\n## Next Steps")
        if not iteration_result.compilation_successful:
            lines.append("Fix compilation errors and keep the query minimal and valid.")
        elif iteration_result.vuln_tp_methods <= 0:
            lines.append("Improve vulnerable target coverage; the query is not hitting expected vulnerable methods.")
        elif iteration_result.fixed_recall_method:
            lines.append("Reduce false positives on the fixed database by tightening source/sink/sanitizer conditions.")
        else:
            lines.append("Expand coverage while preserving the lack of fixed-version hits.")
        return "\n".join(lines)

    def _generate_feedback(self, iteration_result: IterationResult, task: VulnAnalysisTask, results_dir: str) -> str:
        basic_feedback = self._generate_basic_feedback(iteration_result)
        if not iteration_result.query_path or not os.path.exists(iteration_result.query_path):
            return basic_feedback

        repair_dir = Path(results_dir) / f"repair_iter_{iteration_result.iteration_number}"
        probe_eval_dir = repair_dir / "probe_evaluation"
        try:
            probe_report = evaluate_probe_query(
                query_path=Path(iteration_result.query_path),
                cve_id=task.cve_id,
                vuln_db_path=Path(task.vuln_db_path),
                fixed_db_path=Path(task.fixed_db_path),
                output_dir=probe_eval_dir,
                codeql_path=CODEQL_PATH,
                fix_info_path=Path(FIX_INFO),
                original_query_summary=self._build_original_query_summary(iteration_result),
            )

            selection = select_components(probe_report)
            selection["resolved_query_path"] = iteration_result.query_path
            repair_plan = build_repair_plan(selection)

            repair_dir.mkdir(parents=True, exist_ok=True)
            probe_eval_json = probe_eval_dir / "probe_evaluation.json"
            probe_eval_md = probe_eval_dir / "probe_evaluation.md"
            selected_repairs_json = repair_dir / "selected_repairs.json"
            selected_prompts_md = repair_dir / "selected_prompts.md"
            repair_plan_json = repair_dir / "repair_plan.json"
            repair_suggestions_md = repair_dir / "repair_suggestions.md"
            repair_summary_md = repair_dir / "repair_summary.md"

            probe_eval_json.write_text(json.dumps(probe_report, ensure_ascii=False, indent=2), encoding="utf-8")
            probe_eval_md.write_text(markdown_summary(probe_report), encoding="utf-8")
            selected_repairs_json.write_text(json.dumps(selection, ensure_ascii=False, indent=2), encoding="utf-8")
            selected_prompts_md.write_text(render_selected_prompts(selection), encoding="utf-8")
            repair_plan_json.write_text(json.dumps(repair_plan, ensure_ascii=False, indent=2), encoding="utf-8")
            repair_suggestions_md.write_text(
                render_repair_suggestions(selection, Path(iteration_result.query_path)),
                encoding="utf-8",
            )
            repair_summary_md.write_text(
                render_repair_summary(selection, repair_plan, Path(iteration_result.query_path)),
                encoding="utf-8",
            )

            if self.logger:
                self.logger.info(
                    "Generated repair workflow artifacts for iteration %s in %s",
                    iteration_result.iteration_number,
                    repair_dir,
                )

            return "\n\n".join(
                [
                    basic_feedback,
                    _render_probe_guided_feedback(probe_report).strip(),
                ]
            )
        except Exception as exc:
            if self.logger:
                self.logger.warning(
                    "Probe-guided repair workflow failed for iteration %s: %s",
                    iteration_result.iteration_number,
                    exc,
                )
            return basic_feedback

    async def _run_phase3(
        self,
        *,
        backend,
        task: VulnAnalysisTask,
        results_dir: str,
        use_cache: bool,
        collection_name: str,
        phase1_output: str,
    ) -> Dict[str, Any]:
        env = os.environ.copy()
        previous_feedback = None
        self.iteration_results = []

        for iteration in range(1, task.max_iteration + 1):
            self.logger.info(f"Starting Phase 3 iteration {iteration}/{task.max_iteration}")
            if iteration == 1:
                prompt = backend.create_phase3_initial_prompt(
                    task,
                    use_cache=use_cache,
                    collection_name=collection_name,
                    phase1_output=phase1_output,
                )
            else:
                prompt = backend.create_refinement_prompt(
                    task,
                    previous_feedback,
                    iteration,
                    collection_name,
                )

            phase_name = f"phase3_iter_{iteration}"
            context_result = await self._execute_context_window(
                backend=backend,
                prompt=prompt,
                env=env,
                cwd=results_dir,
                phase_name=phase_name,
            )

            iteration_result = await self._test_iteration_query(
                context_result=context_result,
                task=task,
                results_dir=results_dir,
                iteration=iteration,
            )
            self.iteration_results.append(iteration_result)
            if self.logger:
                self.logger.info(
                    "Phase 3 iteration %s summary: compilation=%s vuln_tp=%s fixed_recall=%s error=%s",
                    iteration,
                    iteration_result.compilation_successful,
                    iteration_result.vuln_tp_methods,
                    iteration_result.fixed_recall_method,
                    iteration_result.error,
                )

            if self._is_iteration_successful(iteration_result):
                self.logger.info(f"Successful Phase 3 query found in iteration {iteration}")
                return {
                    "success": True,
                    "final_query": iteration_result.query_path,
                    "iterations_used": iteration,
                }

            previous_feedback = self._generate_feedback(iteration_result, task, results_dir)
            feedback_path = os.path.join(results_dir, f"feedback_iter_{iteration}.txt")
            Path(feedback_path).write_text(previous_feedback, encoding="utf-8")

        return {
            "success": False,
            "error": f"Max iterations ({task.max_iteration}) reached",
            "iterations_used": task.max_iteration,
        }

    def _json_safe(self, value: Any) -> Any:
        """Recursively convert common non-JSON-native containers into serializable forms."""
        if isinstance(value, dict):
            return {str(k): self._json_safe(v) for k, v in value.items()}
        if isinstance(value, set):
            return sorted(self._json_safe(v) for v in value)
        if isinstance(value, (list, tuple)):
            return [self._json_safe(v) for v in value]
        return value

    def _iteration_to_dict(self, iteration_result: IterationResult) -> Dict[str, Any]:
        return {
            "iteration_number": iteration_result.iteration_number,
            "query_path": iteration_result.query_path,
            "compilation_summary": iteration_result.compilation_summary,
            "execution_summary": iteration_result.execution_summary,
            "success": iteration_result.success,
            "error": iteration_result.error,
            "context_length": iteration_result.context_length,
            "vulnerable_results": iteration_result.vulnerable_results,
            "fixed_results": iteration_result.fixed_results,
            "compilation_successful": iteration_result.compilation_successful,
            "vuln_recall_method": iteration_result.vuln_recall_method,
            "fixed_recall_method": iteration_result.fixed_recall_method,
            "vuln_tp_methods": iteration_result.vuln_tp_methods,
            "fixed_tp_methods": iteration_result.fixed_tp_methods,
            "vuln_num_results": iteration_result.vuln_num_results,
            "fixed_num_results": iteration_result.fixed_num_results,
            "vuln_eval_result": self._json_safe(vars(iteration_result.vuln_eval_result)) if iteration_result.vuln_eval_result else None,
            "fixed_eval_result": self._json_safe(vars(iteration_result.fixed_eval_result)) if iteration_result.fixed_eval_result else None,
        }

    def _update_phase3_metrics_with_query(self, results_dir: str, iteration: int, iteration_result: IterationResult) -> None:
        metrics_file = os.path.join(results_dir, f"phase3_iter_{iteration}_metrics.json")
        if not os.path.exists(metrics_file):
            return
        try:
            with open(metrics_file, "r", encoding="utf-8") as f:
                metrics = json.load(f)
            metrics.update(
                {
                    "query_file_path": iteration_result.query_path,
                    "query_filename": os.path.basename(iteration_result.query_path) if iteration_result.query_path else None,
                    "query_extracted": bool(iteration_result.query_path),
                    "compilation_successful": iteration_result.compilation_successful,
                    "iteration_success": iteration_result.success,
                    "vulnerable_results": iteration_result.vulnerable_results,
                    "fixed_results": iteration_result.fixed_results,
                    "vuln_tp_methods": iteration_result.vuln_tp_methods,
                    "fixed_tp_methods": iteration_result.fixed_tp_methods,
                    "error": iteration_result.error,
                }
            )
            with open(metrics_file, "w", encoding="utf-8") as f:
                json.dump(metrics, f, indent=2)
        except Exception as exc:
            if self.logger:
                self.logger.warning(f"Failed to update iteration metrics {metrics_file}: {exc}")

    def _create_cost_usage_summary(self, results_dir: str, cve_id: str) -> Optional[str]:
        try:
            summary_path = os.path.join(results_dir, "token_usage_summary.txt")
            metrics_files = sorted(Path(results_dir).glob("*_metrics.json"))
            total_cost = 0.0
            total_input_tokens = 0
            total_cache_creation_tokens = 0
            total_cache_read_tokens = 0
            total_output_tokens = 0
            phase_breakdown: list[tuple[str, Dict[str, Any]]] = []

            for metrics_file in metrics_files:
                with open(metrics_file, "r", encoding="utf-8") as f:
                    metrics = json.load(f)
                api_usage = metrics.get("api_usage", {}) or {}
                phase_name = metrics.get("phase_name", metrics_file.name)
                phase_breakdown.append((phase_name, api_usage))
                total_cost += api_usage.get("total_cost_usd", 0.0)
                total_input_tokens += api_usage.get("total_input_tokens", 0)
                total_cache_creation_tokens += api_usage.get("total_cache_creation_tokens", 0)
                total_cache_read_tokens += api_usage.get("total_cache_read_tokens", 0)
                total_output_tokens += api_usage.get("total_output_tokens", 0)

            total_effective_tokens = (
                total_input_tokens
                + total_cache_creation_tokens
                + total_cache_read_tokens
                + total_output_tokens
            )

            with open(summary_path, "w", encoding="utf-8") as f:
                f.write(f"# Token Usage Summary for {cve_id}\n\n")
                f.write(f"**Total Cost**: ${total_cost:.6f}\n")
                f.write(f"**Total Input Tokens**: {total_input_tokens:,}\n")
                f.write(f"**Total Cache Creation Tokens**: {total_cache_creation_tokens:,}\n")
                f.write(f"**Total Cache Read Tokens**: {total_cache_read_tokens:,}\n")
                f.write(f"**Total Output Tokens**: {total_output_tokens:,}\n")
                f.write(f"**Effective Total Tokens**: {total_effective_tokens:,}\n\n")
                f.write("## Breakdown by Phase\n")
                for phase_name, usage in phase_breakdown:
                    phase_tokens = (
                        usage.get("total_input_tokens", 0)
                        + usage.get("total_cache_creation_tokens", 0)
                        + usage.get("total_cache_read_tokens", 0)
                        + usage.get("total_output_tokens", 0)
                    )
                    f.write(
                        f"- **{phase_name}**: ${usage.get('total_cost_usd', 0.0):.6f} "
                        f"({phase_tokens:,} tokens)\n"
                    )

            if self.logger:
                self.logger.info(f"Created token usage summary: {summary_path}")
            return summary_path
        except Exception as exc:
            if self.logger:
                self.logger.error(f"Failed to create token usage summary: {exc}")
            return None

    def _save_run_metadata(
        self,
        *,
        task: VulnAnalysisTask,
        results_dir: str,
        result: Dict[str, Any],
        start_time: datetime,
        end_time: datetime,
        collection_name: Optional[str],
    ) -> Optional[str]:
        try:
            metadata_path = os.path.join(results_dir, "vulnsynth_metadata.json")
            metadata = {
                "analysis_metadata": {
                    "approach": "vulnsynth_phase1_phase2_phase3",
                    "cve_id": task.cve_id,
                    "model": task.model,
                    "ablation_mode": self.ablation_mode,
                    "agent_type": self.agent_type,
                    "success": bool(result.get("phase3_success", False)),
                    "duration_seconds": (end_time - start_time).total_seconds(),
                    "collection_name": collection_name,
                    "total_iterations": len(self.iteration_results),
                },
                "iterations": [self._iteration_to_dict(ir) for ir in self.iteration_results],
                "result_summary": self._json_safe(result),
            }
            with open(metadata_path, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)
            if self.logger:
                self.logger.info(f"Saved run metadata: {metadata_path}")
            return metadata_path
        except Exception as exc:
            if self.logger:
                self.logger.error(f"Failed to save run metadata: {exc}")
            return None

    def _load_phase1_artifact_json(self, artifact_path: str) -> Optional[Dict[str, Any]]:
        if not os.path.exists(artifact_path):
            return None
        try:
            content = self._load_text_file(artifact_path)
            parsed = json.loads(content)
        except Exception as exc:
            if self.logger:
                self.logger.warning(f"Failed to read phase1 artifact JSON {artifact_path}: {exc}")
            return None

        required_keys = {
            "vulnerability_research_summary",
            "cve_information",
            "relevant_files",
            "sources",
            "sinks",
            "sanitizers",
            "additional_taint_steps",
            "vulnerability_summary",
        }
        if isinstance(parsed, dict) and required_keys.issubset(parsed.keys()):
            return parsed
        if self.logger:
            self.logger.warning(f"Phase1 artifact JSON at {artifact_path} did not match expected schema")
        return None

    def _auto_discover_inputs(
        self,
        cve_id: str,
        vuln_db: Optional[str],
        fixed_db: Optional[str],
        diff_file: Optional[str],
    ) -> tuple[Optional[str], Optional[str], Optional[str]]:
        cve_dir = Path("cves") / cve_id
        if not diff_file:
            candidate = cve_dir / f"{cve_id}.diff"
            if candidate.exists():
                diff_file = str(candidate)
        if not vuln_db:
            candidate = cve_dir / f"{cve_id}-vul"
            if candidate.exists():
                vuln_db = str(candidate)
        if not fixed_db:
            candidate = cve_dir / f"{cve_id}-fix"
            if candidate.exists():
                fixed_db = str(candidate)
        return vuln_db, fixed_db, diff_file

    async def analyze_vulnerability(
        self,
        cve_id: str,
        vuln_db: Optional[str],
        fixed_db: Optional[str],
        diff_file: Optional[str],
        output_dir: str,
        max_iteration: int,
        model: str,
        backend_config_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        vuln_db, fixed_db, diff_file = self._auto_discover_inputs(
            cve_id=cve_id,
            vuln_db=vuln_db,
            fixed_db=fixed_db,
            diff_file=diff_file,
        )
        if not diff_file:
            raise ValueError("--diff is required for VulnSynth Phase 1")

        results_dir = self._prepare_output_dirs(cve_id, output_dir)
        self.logger = self._setup_logger(results_dir, cve_id)
        self.logger.info("Starting VulnSynth Phase 1 pipeline")
        start_time = datetime.utcnow()
        backend_config = _load_backend_config(backend_config_path)
        if backend_config_path:
            self.logger.info(f"Loaded backend config: {os.path.abspath(backend_config_path)}")

        raw_diff_path = os.path.abspath(diff_file)
        raw_diff_text = self._load_text_file(raw_diff_path)

        self.logger.info("Running diff preprocessor")
        diff_outputs = process_diff_file(diff_path=raw_diff_path, out_dir=results_dir)
        diff_focus_json_path = os.path.abspath(diff_outputs["json"])
        diff_focus_md_path = os.path.abspath(diff_outputs["markdown"])
        diff_focus_json_text = self._load_text_file(diff_focus_json_path)

        schema_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "docs", "phase1_schema.md"))

        task = VulnAnalysisTask(
            vuln_db_path=vuln_db or "",
            fixed_db_path=fixed_db or "",
            fix_commit_diff=raw_diff_text,
            raw_diff_path=raw_diff_path,
            diff_focus_json_path=diff_focus_json_path,
            diff_focus_md_path=diff_focus_md_path,
            phase1_schema_path=schema_path,
            cve_id=cve_id,
            output_dir=results_dir,
            working_dir=results_dir,
            max_iteration=max_iteration,
            model=model,
            ast_cache=AST_CACHE,
            nvd_cache=NVD_CACHE,
        )

        backend = None
        try:
            backend_kwargs: Dict[str, Any] = {}
            if self.agent_type == "coco" and "mcp_configs" in backend_config:
                backend_kwargs["mcp_configs"] = backend_config.get("mcp_configs")

            backend = create_backend(
                self.agent_type,
                self.model,
                self.logger,
                ablation_mode=self.ablation_mode,
                **backend_kwargs,
            )
            backend.setup_workspace(results_dir, task)

            phase1_prompt = backend.create_phase1_prompt(task)
            prompt_path = os.path.join(results_dir, "phase1_prompt.txt")
            Path(prompt_path).write_text(phase1_prompt, encoding="utf-8")
            stdin_path = os.path.join(results_dir, "phase1_stdin.json")
            Path(stdin_path).write_text(diff_focus_json_text, encoding="utf-8")
            self.logger.info(f"Saved phase1 prompt: {prompt_path}")
            self.logger.info(f"Saved phase1 stdin payload: {stdin_path}")

            env = os.environ.copy()
            self.logger.info("Executing phase1")
            phase1_result = await backend.execute_prompt(
                prompt=phase1_prompt,
                env=env,
                cwd=results_dir,
                phase_name="phase1",
                stdin_text=diff_focus_json_text,
            )

            stdout_path = os.path.join(results_dir, "phase1_output.txt")
            stderr_path = os.path.join(results_dir, "phase1_stderr.txt")
            Path(stdout_path).write_text(phase1_result.get("stdout", ""), encoding="utf-8")
            Path(stderr_path).write_text(phase1_result.get("stderr", ""), encoding="utf-8")

            metrics = {
                "phase_name": "phase1",
                "success": phase1_result.get("returncode", 1) == 0,
                "return_code": phase1_result.get("returncode", 1),
                "output_file": stdout_path,
                "stderr_file": stderr_path,
                "stdin_file": stdin_path,
                "prompt_file": prompt_path,
                "diff_focus_json": diff_focus_json_path,
                "diff_focus_markdown": diff_focus_md_path,
                "api_usage": phase1_result.get("api_usage", {}),
            }
            metrics_path = os.path.join(results_dir, "phase1_metrics.json")
            Path(metrics_path).write_text(json.dumps(metrics, indent=2), encoding="utf-8")

            extract_fn = getattr(backend, "extract_text_output", None)
            phase1_text = extract_fn(phase1_result.get("stdout", "")) if extract_fn else phase1_result.get("stdout", "")
            phase1_last_message = extract_last_agent_message(phase1_result.get("stdout", ""))

            structured = parse_phase1_json(phase1_last_message)
            if structured is None:
                structured = parse_phase1_json(phase1_text)
            phase1_artifact_path = os.path.join(results_dir, f"{cve_id}.phase1.json")
            if structured is None:
                structured = self._load_phase1_artifact_json(phase1_artifact_path)
                if structured is not None:
                    self.logger.info(f"Loaded structured Phase 1 JSON artifact as fallback: {phase1_artifact_path}")
            structured_path = os.path.join(results_dir, f"phase1_structured_{cve_id}.json")
            readable_md_path = os.path.join(results_dir, f"phase1_structured_{cve_id}.md")

            if structured is not None:
                Path(structured_path).write_text(
                    json.dumps(structured, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )
                Path(readable_md_path).write_text(
                    render_phase1_json_markdown(structured),
                    encoding="utf-8",
                )
                self.logger.info(f"Saved structured phase1 JSON: {structured_path}")
            else:
                fallback_sections = extract_phase1_sections(phase1_text)
                Path(structured_path).write_text(
                    json.dumps(fallback_sections, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )
                self.logger.warning("Phase 1 output was not valid structured JSON; saved fallback extracted sections instead")

            phase1_return_ok = phase1_result.get("returncode", 1) == 0
            phase1_success = phase1_return_ok and structured is not None
            if not phase1_success:
                stop_reason = "phase1_execution_failed"
                if phase1_return_ok and structured is None:
                    stop_reason = "phase1_structured_json_missing"
                self.logger.error(f"Stopping pipeline after Phase 1 failure: {stop_reason}")
                return self._build_failure_result(
                    results_dir=results_dir,
                    stdout_path=stdout_path,
                    stderr_path=stderr_path,
                    structured_path=structured_path,
                    readable_md_path=readable_md_path,
                    diff_focus_json_path=diff_focus_json_path,
                    diff_focus_md_path=diff_focus_md_path,
                    phase1_success=False,
                    phase2_success=False,
                    phase2_skipped=True,
                    phase2_output_path=None,
                    phase2_metrics_path=None,
                    phase2_result={
                        "success": False,
                        "skipped": True,
                        "reason": "phase1_failed",
                        "phase": 2,
                    },
                    stop_reason=stop_reason,
                    proceed_to_next_stage=False,
                )

            phase2_result: Dict[str, Any]
            phase2_metrics: Dict[str, Any]
            phase2_output_path = os.path.join(results_dir, "phase2_output.txt")
            phase2_metrics_path = os.path.join(results_dir, "phase2_metrics.json")

            if self.ablation_mode in ("no_tools", "no_ast"):
                self.logger.info(f"Ablation mode '{self.ablation_mode}': skipping Phase 2 (AST extraction)")
                phase2_result = {
                    "success": True,
                    "skipped": True,
                    "reason": f"ablation_mode={self.ablation_mode}",
                    "output": "",
                    "phase": 2,
                }
            elif not task.vuln_db_path or not task.fixed_db_path:
                self.logger.info("Skipping Phase 2 because vulnerable/fixed CodeQL databases were not both provided")
                phase2_result = {
                    "success": True,
                    "skipped": True,
                    "reason": "missing_database_paths",
                    "output": "",
                    "phase": 2,
                }
            else:
                self.logger.info("Executing Phase 2")
                phase2_result = await run_phase2(self, task, results_dir)

            phase2_metrics = {
                "phase_name": "phase2",
                "success": bool(phase2_result.get("success", False)),
                "skipped": bool(phase2_result.get("skipped", False)),
                "reason": phase2_result.get("reason"),
                "cached": bool(phase2_result.get("cached", False)),
                "output_file": phase2_output_path if os.path.exists(phase2_output_path) else None,
                "changed_lines": self._json_safe(phase2_result.get("changed_lines")),
                "vuln_nodes": phase2_result.get("vuln_nodes"),
                "fixed_nodes": phase2_result.get("fixed_nodes"),
                "differences": self._json_safe(phase2_result.get("differences")),
                "output_files": self._json_safe(phase2_result.get("output_files")),
                "error": phase2_result.get("error"),
            }
            Path(phase2_metrics_path).write_text(json.dumps(phase2_metrics, indent=2), encoding="utf-8")

            if not bool(phase2_result.get("success", False)):
                stop_reason = "phase2_execution_failed"
                if bool(phase2_result.get("skipped", False)):
                    stop_reason = f"phase2_skipped:{phase2_result.get('reason')}"
                self.logger.error(f"Stopping pipeline after Phase 2 failure: {stop_reason}")
                return self._build_failure_result(
                    results_dir=results_dir,
                    stdout_path=stdout_path,
                    stderr_path=stderr_path,
                    structured_path=structured_path,
                    readable_md_path=readable_md_path,
                    diff_focus_json_path=diff_focus_json_path,
                    diff_focus_md_path=diff_focus_md_path,
                    phase1_success=True,
                    phase2_success=False,
                    phase2_skipped=bool(phase2_result.get("skipped", False)),
                    phase2_output_path=phase2_output_path,
                    phase2_metrics_path=phase2_metrics_path,
                    phase2_result=phase2_result,
                    stop_reason=stop_reason,
                    proceed_to_next_stage=False,
                )

            phase3_collection_name = self._phase3_collection_name(cve_id)
            if self.ablation_mode != "no_tools":
                try:
                    self._store_phase1_structured_to_chroma(
                        task=task,
                        results_dir=results_dir,
                        collection_name=phase3_collection_name,
                        structured=structured,
                    )
                except Exception as exc:
                    self.logger.error(f"Failed to store Phase 1 structured output to Chroma: {exc}")
                    return self._build_failure_result(
                        results_dir=results_dir,
                        stdout_path=stdout_path,
                        stderr_path=stderr_path,
                        structured_path=structured_path,
                        readable_md_path=readable_md_path,
                        diff_focus_json_path=diff_focus_json_path,
                        diff_focus_md_path=diff_focus_md_path,
                        phase1_success=True,
                        phase2_success=False,
                        phase2_skipped=False,
                        phase2_output_path=phase2_output_path,
                        phase2_metrics_path=phase2_metrics_path,
                        phase2_result={"success": False, "error": f"phase1_chroma_store_failed: {exc}", "phase": 2},
                        stop_reason="phase1_chroma_store_failed",
                        proceed_to_next_stage=False,
                    )

            phase1_for_no_tools = render_phase1_json_markdown(structured)
            self.logger.info("Executing Phase 3")
            phase3_result = await self._run_phase3(
                backend=backend,
                task=task,
                results_dir=results_dir,
                use_cache=self.ablation_mode != "no_tools",
                collection_name=phase3_collection_name,
                phase1_output=phase1_for_no_tools,
            )

            if not phase3_result.get("success", False):
                token_usage_summary = self._create_cost_usage_summary(results_dir, cve_id)
                result = {
                    "results_dir": results_dir,
                    "phase1_success": True,
                    "phase1_output_file": stdout_path,
                    "phase1_stderr_file": stderr_path,
                    "phase1_artifact_file": phase1_artifact_path if os.path.exists(phase1_artifact_path) else None,
                    "phase1_structured_file": structured_path,
                    "phase1_readable_markdown": readable_md_path if os.path.exists(readable_md_path) else None,
                    "phase2_success": True,
                    "phase2_skipped": bool(phase2_result.get("skipped", False)),
                    "phase2_output_file": phase2_output_path if os.path.exists(phase2_output_path) else None,
                    "phase2_metrics_file": phase2_metrics_path,
                    "phase2_result": self._json_safe(phase2_result),
                    "phase3_success": False,
                    "phase3_result": self._json_safe(phase3_result),
                    "phase3_iterations": [self._iteration_to_dict(r) for r in self.iteration_results],
                    "final_query": None,
                    "diff_focus_json": diff_focus_json_path,
                    "diff_focus_markdown": diff_focus_md_path,
                    "phase3_collection_name": phase3_collection_name,
                    "token_usage_summary": token_usage_summary,
                    "stop_reason": "phase3_failed",
                    "proceed_to_next_stage": False,
                }
                metadata_path = self._save_run_metadata(
                    task=task,
                    results_dir=results_dir,
                    result=result,
                    start_time=start_time,
                    end_time=datetime.utcnow(),
                    collection_name=phase3_collection_name,
                )
                result["metadata_file"] = metadata_path
                self.logger.error("Phase 3 failed to produce a successful query")
                print(json.dumps(result, indent=2, ensure_ascii=False))
                return result

            token_usage_summary = self._create_cost_usage_summary(results_dir, cve_id)
            result = {
                "results_dir": results_dir,
                "phase1_success": True,
                "phase1_output_file": stdout_path,
                "phase1_stderr_file": stderr_path,
                "phase1_artifact_file": phase1_artifact_path if os.path.exists(phase1_artifact_path) else None,
                "phase1_structured_file": structured_path,
                "phase1_readable_markdown": readable_md_path if os.path.exists(readable_md_path) else None,
                "phase2_success": True,
                "phase2_skipped": bool(phase2_result.get("skipped", False)),
                "phase2_output_file": phase2_output_path if os.path.exists(phase2_output_path) else None,
                "phase2_metrics_file": phase2_metrics_path,
                "phase2_result": self._json_safe(phase2_result),
                "phase3_success": True,
                "phase3_result": self._json_safe(phase3_result),
                "phase3_iterations": [self._iteration_to_dict(r) for r in self.iteration_results],
                "final_query": phase3_result.get("final_query"),
                "diff_focus_json": diff_focus_json_path,
                "diff_focus_markdown": diff_focus_md_path,
                "phase3_collection_name": phase3_collection_name,
                "token_usage_summary": token_usage_summary,
                "stop_reason": None,
                "proceed_to_next_stage": True,
            }
            metadata_path = self._save_run_metadata(
                task=task,
                results_dir=results_dir,
                result=result,
                start_time=start_time,
                end_time=datetime.utcnow(),
                collection_name=phase3_collection_name,
            )
            result["metadata_file"] = metadata_path
            self.logger.info("Phase 1/2 diagnostics passed and Phase 3 completed")
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return result
        finally:
            if backend is not None:
                await backend.cleanup()


async def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description="Vulnsynth Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--cve-id", required=True, help="CVE identifier")
    parser.add_argument("--vuln-db", help="Path to vulnerable CodeQL database")
    parser.add_argument("--fixed-db", help="Path to fixed CodeQL database")
    parser.add_argument("--diff", help="Path to fix commit diff file")
    parser.add_argument("--output-dir", default="output", help="Output directory")
    parser.add_argument("--max-iteration", default=10, type=int, help="Max iterations")
    parser.add_argument("--cache-phase-output", action="store_true", default=True)
    parser.add_argument("--no-cache-phase-output", dest="cache_phase_output", action="store_false")
    parser.add_argument(
        "--model",
        default=None,
        choices=SUPPORTED_MODELS,
        help="Model name. If omitted, selects an agent-specific default.",
    )
    parser.add_argument(
        "--agent",
        default=DEFAULT_AGENT,
        choices=["claude", "coco", "gemini", "codex"],
        help="Agent backend to use",
    )
    parser.add_argument(
        "--backend-config",
        help="Path to backend JSON config file, e.g. {'mcp_configs': {...}} for coco",
    )
    parser.add_argument(
        "--ablation-mode",
        default="full",
        choices=["full", "no_tools", "no_lsp", "no_docs", "no_ast"],
        help="Ablation mode (default: full)",
    )

    args = parser.parse_args()
    selected_model = _resolve_model_for_agent(args.agent, args.model)

    cli = Vulnsynth_Agent_IterativeCLI(
        agent_type=args.agent,
        model=selected_model,
        ablation_mode=args.ablation_mode,
    )
    await cli.analyze_vulnerability(
        cve_id=args.cve_id,
        vuln_db=args.vuln_db,
        fixed_db=args.fixed_db,
        diff_file=args.diff,
        output_dir=args.output_dir,
        max_iteration=args.max_iteration,
        model=selected_model,
        backend_config_path=args.backend_config,
    )


if __name__ == "__main__":
    asyncio.run(main())
