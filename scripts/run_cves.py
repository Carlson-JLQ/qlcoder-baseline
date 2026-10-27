#!/usr/bin/env python3
"""Run QLCoder for one or more CVEs in isolated child processes.

Examples:
    python3 scripts/run_cves.py --cve CVE-2025-31720
    python3 scripts/run_cves.py --cves CVE-2025-31720,CVE-2025-31721 --model gpt-5 --agent codex
    python3 scripts/run_cves.py --cve-file data/cve.txt --max-iteration 10

Arguments not consumed by this wrapper are forwarded to ``run_cve.sh`` and
ultimately to ``src/ql_agent.py``.  A failure, crash, timeout, or Ctrl-C stops
only the current CVE; the next CVE is then started.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Sequence


ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_RUNNER = ROOT_DIR / "run_cve.sh"
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


@dataclass
class RunResult:
    cve_id: str
    status: str
    exit_code: int | None
    duration_seconds: float
    log_file: str
    reason: str = ""


def parse_cve_file(path: Path) -> List[str]:
    """Read CVE IDs separated by newlines, commas, or whitespace."""
    if not path.is_file():
        raise ValueError(f"CVE file not found: {path}")

    values: List[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if line:
            values.extend(part for part in re.split(r"[,\s]+", line) if part)
    return values


def normalize_cves(values: Iterable[str]) -> List[str]:
    """Validate CVE IDs and remove duplicates while preserving order."""
    result: List[str] = []
    seen = set()
    invalid = []

    for value in values:
        cve_id = value.strip().upper()
        if not CVE_PATTERN.fullmatch(cve_id):
            invalid.append(value)
        elif cve_id not in seen:
            seen.add(cve_id)
            result.append(cve_id)

    if invalid:
        raise ValueError("Invalid CVE ID(s): " + ", ".join(invalid))
    if not result:
        raise ValueError("No CVE IDs were provided")
    return result


def terminate_process_group(process: subprocess.Popen[str], grace_seconds: float = 10.0) -> None:
    """Terminate the current CVE process and all descendants."""
    if process.poll() is not None:
        return

    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return

    try:
        process.wait(timeout=grace_seconds)
        return
    except subprocess.TimeoutExpired:
        pass

    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def stream_output(process: subprocess.Popen[str], log_file, cve_id: str) -> None:
    """Copy combined child output to the terminal and the per-CVE log."""
    assert process.stdout is not None
    for line in process.stdout:
        log_file.write(line)
        log_file.flush()
        sys.stdout.write(f"[{cve_id}] {line}")
        sys.stdout.flush()


def run_one_cve(
    cve_id: str,
    runner: Path,
    forwarded_args: Sequence[str],
    timeout_seconds: float,
    log_path: Path,
) -> RunResult:
    command = [str(runner), cve_id, *forwarded_args]
    started = time.monotonic()

    with log_path.open("w", encoding="utf-8") as log_file:
        log_file.write(f"Command: {' '.join(command)}\n")
        log_file.flush()

        try:
            process = subprocess.Popen(
                command,
                cwd=ROOT_DIR,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                start_new_session=True,
            )
        except Exception as exc:
            duration = time.monotonic() - started
            log_file.write(f"Failed to start: {exc}\n")
            return RunResult(cve_id, "failed", None, duration, str(log_path), str(exc))

        output_thread = threading.Thread(
            target=stream_output,
            args=(process, log_file, cve_id),
            daemon=True,
        )
        output_thread.start()

        try:
            if timeout_seconds > 0:
                exit_code = process.wait(timeout=timeout_seconds)
            else:
                exit_code = process.wait()
            output_thread.join(timeout=5)
        except subprocess.TimeoutExpired:
            terminate_process_group(process)
            output_thread.join(timeout=5)
            duration = time.monotonic() - started
            reason = f"Exceeded timeout of {timeout_seconds:g} seconds"
            log_file.write(f"\n{reason}\n")
            return RunResult(cve_id, "timeout", process.returncode, duration, str(log_path), reason)
        except KeyboardInterrupt:
            # The requested batch behavior is to cancel only this CVE and then
            # continue.  The child has its own process group so Docker and all
            # of its descendants are stopped together.
            terminate_process_group(process)
            output_thread.join(timeout=5)
            duration = time.monotonic() - started
            reason = "Interrupted by user; current CVE terminated"
            log_file.write(f"\n{reason}\n")
            print(f"\n[{cve_id}] {reason}")
            return RunResult(cve_id, "interrupted", process.returncode, duration, str(log_path), reason)

    duration = time.monotonic() - started
    if exit_code == 0:
        return RunResult(cve_id, "success", exit_code, duration, str(log_path))
    return RunResult(
        cve_id,
        "failed",
        exit_code,
        duration,
        str(log_path),
        f"QLCoder exited with status {exit_code}",
    )


def validate_forwarded_args(args: Sequence[str]) -> None:
    reserved = {"--cve-id", "--vuln-db", "--fixed-db", "--diff"}
    conflicts = [arg for arg in args if arg.split("=", 1)[0] in reserved]
    if conflicts:
        raise ValueError(
            "These arguments are managed per CVE and cannot be forwarded: "
            + ", ".join(conflicts)
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run QLCoder sequentially for one or more CVEs; failures affect only the current CVE.",
        epilog="Unknown arguments are forwarded to run_cve.sh, for example --model and --max-iteration.",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--cve", help="Process one CVE")
    source.add_argument("--cves", help="Process comma-separated CVE IDs")
    source.add_argument("--cve-file", type=Path, help="Read CVE IDs from a text file")
    parser.add_argument(
        "--timeout",
        type=float,
        default=0,
        metavar="SECONDS",
        help="Maximum runtime per CVE; 0 disables the wrapper timeout (default: 0)",
    )
    parser.add_argument(
        "--log-dir",
        type=Path,
        help="Batch log directory (default: logs/qlcoder_batch_<timestamp>)",
    )
    parser.add_argument(
        "--runner",
        type=Path,
        default=DEFAULT_RUNNER,
        help=f"Per-CVE runner (default: {DEFAULT_RUNNER})",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print commands without executing them")
    return parser


def main() -> int:
    parser = build_parser()
    args, forwarded_args = parser.parse_known_args()
    if forwarded_args[:1] == ["--"]:
        forwarded_args = forwarded_args[1:]

    try:
        if args.cve:
            cves = normalize_cves([args.cve])
        elif args.cves:
            cves = normalize_cves(args.cves.split(","))
        else:
            cves = normalize_cves(parse_cve_file(args.cve_file))
        validate_forwarded_args(forwarded_args)
    except ValueError as exc:
        parser.error(str(exc))

    if args.timeout < 0:
        parser.error("--timeout cannot be negative")

    runner = args.runner.expanduser().resolve()
    if not runner.is_file():
        parser.error(f"Runner not found: {runner}")
    if not os.access(runner, os.X_OK):
        parser.error(f"Runner is not executable: {runner}")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_dir = (args.log_dir or ROOT_DIR / "logs" / f"qlcoder_batch_{timestamp}").expanduser().resolve()

    print(f"CVEs to process: {len(cves)}")
    print(f"Runner: {runner}")
    print(f"Forwarded QLCoder arguments: {list(forwarded_args)}")

    if args.dry_run:
        for cve_id in cves:
            print("DRY RUN:", " ".join([str(runner), cve_id, *forwarded_args]))
        return 0

    log_dir.mkdir(parents=True, exist_ok=True)
    results: List[RunResult] = []

    for index, cve_id in enumerate(cves, start=1):
        print(f"\n{'=' * 72}")
        print(f"[{index}/{len(cves)}] Starting {cve_id}")
        print(f"{'=' * 72}")
        result = run_one_cve(
            cve_id,
            runner,
            forwarded_args,
            args.timeout,
            log_dir / f"{cve_id}.log",
        )
        results.append(result)
        print(
            f"[{cve_id}] {result.status.upper()} "
            f"({result.duration_seconds:.1f}s)"
            + (f": {result.reason}" if result.reason else "")
        )

    summary_path = log_dir / "summary.json"
    summary_path.write_text(
        json.dumps([asdict(result) for result in results], indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    successful = sum(result.status == "success" for result in results)
    print(f"\n{'=' * 72}")
    print(f"Batch complete: total={len(results)}, successful={successful}, failed={len(results) - successful}")
    for result in results:
        if result.status != "success":
            print(f"  - {result.cve_id}: {result.status} ({result.reason})")
    print(f"Logs and summary: {log_dir}")

    return 0 if successful == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
