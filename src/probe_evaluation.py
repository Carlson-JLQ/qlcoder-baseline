#!/usr/bin/env python3

from __future__ import annotations

import argparse
import asyncio
import csv
import importlib
import json
import logging
import os
import subprocess
import sys
import types
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

try:
    from .structural_extract import extract_and_compile_components
except Exception:
    from structural_extract import extract_and_compile_components


LOGGER = logging.getLogger(__name__)
ROLE_ORDER = ("source", "sink", "barrier", "flow")


def resolve_repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def resolve_default_codeql_path() -> str:
    codeql_home = os.environ.get("CODEQL_HOME", "/path/to/codeql")
    return os.environ.get("CODEQL_PATH", f"{codeql_home}/codeql")


def resolve_default_fix_info_path() -> Path:
    return resolve_repo_root() / "data" / "fix_info.csv"


def iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def is_test_file(file_path: str) -> bool:
    file_path_lower = file_path.lower()
    basename = os.path.basename(file_path_lower)
    if "/test/" in file_path_lower or "/tests/" in file_path_lower:
        return True
    if (
        basename.endswith("test.java")
        or basename.endswith("tests.java")
        or basename.startswith("test")
        or basename.endswith("testcase.java")
        or "unittest" in basename
        or "integrationtest" in basename
    ):
        return True
    return any(
        pattern in basename
        for pattern in ("testutil", "testhelper", "testbase", "abstracttest", "mocktest", "dummytest")
    )


@dataclass
class RunCountResult:
    success: bool
    num_results: int
    error: Optional[str] = None
    bqrs_path: Optional[str] = None
    csv_path: Optional[str] = None


@dataclass
class AlignmentResult:
    success: bool
    num_results: int
    num_aligned_files: int
    num_aligned_methods: int
    aligned_files: list[str]
    aligned_methods: list[str]
    hit_files: list[str]
    hit_methods: list[str]
    target_file_coverage: float
    target_method_coverage: float
    error: Optional[str] = None
    sarif_path: Optional[str] = None


def compile_query(query_path: Path, codeql_path: str) -> dict[str, Any]:
    completed = subprocess.run(
        [codeql_path, "query", "compile", str(query_path)],
        cwd=str(query_path.parent),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return {
        "success": completed.returncode == 0,
        "return_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def load_query_evaluator_class(fix_info_path: Path):
    module_names = []
    if __package__:
        module_names.append(f"{__package__}.evaluation")
    module_names.append("evaluation")

    last_exc: Optional[Exception] = None
    for module_name in module_names:
        try:
            module = importlib.import_module(module_name)
            return module.QueryEvaluator
        except Exception as exc:
            last_exc = exc

    stub = types.ModuleType("config")
    stub.FIX_INFO = str(fix_info_path)
    stub.QUERIES_PATH = str(resolve_repo_root() / "src" / "queries")
    sys.modules["config"] = stub

    src_stub = types.ModuleType("src.config")
    src_stub.FIX_INFO = str(fix_info_path)
    src_stub.QUERIES_PATH = str(resolve_repo_root() / "src" / "queries")
    sys.modules["src.config"] = src_stub

    for module_name in module_names:
        try:
            if module_name in sys.modules:
                del sys.modules[module_name]
            module = importlib.import_module(module_name)
            return module.QueryEvaluator
        except Exception as exc:
            last_exc = exc

    assert last_exc is not None
    raise last_exc


def load_query_execution_runner(codeql_path: str):
    module_names = []
    if __package__:
        module_names.append(f"{__package__}.query_subagents_evaluation")
    module_names.append("query_subagents_evaluation")

    last_exc: Optional[Exception] = None
    for module_name in module_names:
        try:
            module = importlib.import_module(module_name)
            return module.run_query_with_evaluation_results
        except Exception as exc:
            last_exc = exc

    stub = types.ModuleType("config")
    stub.CODEQL_PATH = codeql_path
    sys.modules["config"] = stub

    src_stub = types.ModuleType("src.config")
    src_stub.CODEQL_PATH = codeql_path
    sys.modules["src.config"] = src_stub

    for module_name in module_names:
        try:
            if module_name in sys.modules:
                del sys.modules[module_name]
            module = importlib.import_module(module_name)
            return module.run_query_with_evaluation_results
        except Exception as exc:
            last_exc = exc

    assert last_exc is not None
    raise last_exc


def run_query_count(query_path: Path, database_path: Path, codeql_path: str, work_dir: Path, prefix: str) -> RunCountResult:
    work_dir.mkdir(parents=True, exist_ok=True)
    bqrs_path = work_dir / f"{prefix}.bqrs"
    csv_path = work_dir / f"{prefix}.csv"

    run_cmd = [
        codeql_path,
        "query",
        "run",
        "--database",
        str(database_path),
        "--output",
        str(bqrs_path),
        "--",
        str(query_path),
    ]
    run_completed = subprocess.run(
        run_cmd,
        cwd=str(work_dir),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if run_completed.returncode != 0:
        return RunCountResult(
            success=False,
            num_results=0,
            error=run_completed.stderr.strip() or run_completed.stdout.strip() or "codeql query run failed",
            bqrs_path=str(bqrs_path),
        )

    decode_cmd = [
        codeql_path,
        "bqrs",
        "decode",
        "--format=csv",
        f"--output={csv_path}",
        str(bqrs_path),
    ]
    decode_completed = subprocess.run(
        decode_cmd,
        cwd=str(work_dir),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if decode_completed.returncode != 0:
        return RunCountResult(
            success=False,
            num_results=0,
            error=decode_completed.stderr.strip() or decode_completed.stdout.strip() or "codeql bqrs decode failed",
            bqrs_path=str(bqrs_path),
            csv_path=str(csv_path),
        )

    num_results = 0
    if csv_path.exists() and csv_path.stat().st_size > 0:
        with csv_path.open("r", encoding="utf-8", newline="") as handle:
            num_results = max(0, sum(1 for _ in handle) - 1)

    return RunCountResult(
        success=True,
        num_results=num_results,
        bqrs_path=str(bqrs_path),
        csv_path=str(csv_path),
    )


def build_problem_alignment_probe(probe_path: Path, role: str, output_dir: Path) -> Path:
    text = probe_path.read_text(encoding="utf-8")
    if "@kind problem" in text:
        return probe_path

    output_dir.mkdir(parents=True, exist_ok=True)
    problem_probe_path = output_dir / f"{probe_path.stem}_alignment.ql"
    text = text.replace("@kind table", "@kind problem")

    if "@problem.severity" not in text:
        text = text.replace(
            "@id ",
            "@problem.severity warning\n * @precision low\n * @id ",
            1,
        )

    if "@id " in text:
        text = text.replace(f"{role}-probe", f"{role}-probe-alignment")
        text = text.replace("/source-probe", "/source-probe-alignment")
        text = text.replace("/sink-probe", "/sink-probe-alignment")

    problem_probe_path.write_text(text, encoding="utf-8")
    return problem_probe_path


def extract_methods_from_location_with_project_data(
    evaluator: Any,
    location: dict[str, Any],
    project_classes: Any,
    project_methods: Any,
) -> set[str]:
    methods: set[str] = set()
    physical_location = location.get("physicalLocation", {})
    artifact_location = physical_location.get("artifactLocation", {})
    file_name = artifact_location.get("uri", "")
    region = physical_location.get("region", {})
    start_line = region.get("startLine")

    if not file_name or not start_line:
        return methods

    db_file_name = file_name.replace("file://", "")
    relevant_classes = project_classes[
        (project_classes["file"] == db_file_name)
        & (project_classes["start_line"] <= start_line)
        & (project_classes["end_line"] >= start_line)
    ].sort_values(by="start_line", ascending=False)
    if len(relevant_classes) == 0:
        return methods
    relevant_class = relevant_classes.iloc[0]["name"]

    relevant_methods = project_methods[
        (project_methods["file"] == db_file_name)
        & (project_methods["start_line"] <= start_line)
        & (project_methods["end_line"] >= start_line)
    ].sort_values(by="start_line", ascending=False)
    if len(relevant_methods) == 0:
        return methods
    relevant_method = relevant_methods.iloc[0]["name"]

    path_variants = evaluator._generate_sarif_path_variants(db_file_name)
    for normalized_file_name in path_variants:
        methods.add(f"{normalized_file_name}:{relevant_class}:{relevant_method}")

    return methods


def collect_hit_locations_from_sarif(evaluator: Any, sarif_path: Path, database_path: Path) -> tuple[set[str], set[str]]:
    sarif_data = evaluator._parse_sarif_result(str(sarif_path))
    if not sarif_data:
        return set(), set()

    found_methods: set[str] = set()
    found_files: set[str] = set()

    all_code_flows = list(evaluator._iter_code_flows(sarif_data))
    if all_code_flows:
        for _, _, code_flow in all_code_flows:
            found_methods.update(evaluator._extract_code_flow_passing_methods(code_flow, str(database_path)))
            found_files.update(evaluator._extract_code_flow_passing_files(code_flow))
        return found_methods, found_files

    project_classes, project_methods = evaluator._load_project_structure()
    for _, _, location in evaluator._iter_result_locations(sarif_data):
        found_methods.update(
            extract_methods_from_location_with_project_data(
                evaluator,
                location,
                project_classes,
                project_methods,
            )
        )
        found_files.update(evaluator._extract_location_files(location))

    return found_methods, found_files


def run_alignment_evaluation(
    *,
    role: str,
    probe_path: Path,
    database_path: Path,
    cve_id: str,
    codeql_path: str,
    fix_info_path: Path,
    output_dir: Path,
    prefix: str,
    target_context: dict[str, Any],
) -> AlignmentResult:
    problem_probe_path = build_problem_alignment_probe(probe_path, role, output_dir)
    sarif_path = output_dir / f"{prefix}.sarif"

    analyze_cmd = [
        codeql_path,
        "database",
        "analyze",
        str(database_path),
        str(problem_probe_path),
        "--format=sarif-latest",
        "--output",
        str(sarif_path),
    ]
    analyze_completed = subprocess.run(
        analyze_cmd,
        cwd=str(output_dir),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if analyze_completed.returncode != 0:
        return AlignmentResult(
            success=False,
            num_results=0,
            num_aligned_files=0,
            num_aligned_methods=0,
            aligned_files=[],
            aligned_methods=[],
            hit_files=[],
            hit_methods=[],
            target_file_coverage=0.0,
            target_method_coverage=0.0,
            error=analyze_completed.stderr.strip() or analyze_completed.stdout.strip() or "codeql database analyze failed",
            sarif_path=str(sarif_path),
        )

    QueryEvaluator = load_query_evaluator_class(fix_info_path)
    evaluator = QueryEvaluator(
        input_dir=str(output_dir),
        cve_id=cve_id,
        diff_file="",
        final_output_json_path=str(output_dir / f"{prefix}_eval.json"),
        database_path=str(database_path),
        logger=LOGGER,
    )
    sarif_data = evaluator._parse_sarif_result(str(sarif_path))
    if not sarif_data:
        return AlignmentResult(
            success=False,
            num_results=0,
            num_aligned_files=0,
            num_aligned_methods=0,
            aligned_files=[],
            aligned_methods=[],
            hit_files=[],
            hit_methods=[],
            target_file_coverage=0.0,
            target_method_coverage=0.0,
            error="Failed to parse SARIF output for alignment probe.",
            sarif_path=str(sarif_path),
        )

    found_methods, found_files = collect_hit_locations_from_sarif(evaluator, sarif_path, database_path)

    fixed_methods = set(target_context["fixed_methods"])
    fixed_files = set(target_context["fixed_files"])
    aligned_methods = sorted(found_methods.intersection(fixed_methods))
    aligned_files = sorted(found_files.intersection(fixed_files))

    target_method_count = max(1, target_context["target_method_count"])
    target_file_count = max(1, target_context["target_file_count"])

    return AlignmentResult(
        success=True,
        num_results=len(sarif_data.get("runs", [{}])[0].get("results", [])),
        num_aligned_files=len(aligned_files),
        num_aligned_methods=len(aligned_methods),
        aligned_files=aligned_files,
        aligned_methods=aligned_methods,
        hit_files=sorted(found_files),
        hit_methods=sorted(found_methods),
        target_file_coverage=len(aligned_files) / target_file_count if target_context["target_file_count"] else 0.0,
        target_method_coverage=len(aligned_methods) / target_method_count if target_context["target_method_count"] else 0.0,
        sarif_path=str(sarif_path),
    )


def load_target_context(cve_id: str, fix_info_path: Path) -> dict[str, Any]:
    fixed_files: set[str] = set()
    fixed_methods: set[str] = set()

    with fix_info_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            if row.get("cve_id") != cve_id:
                continue
            file_name = (row.get("file") or "").strip()
            if not file_name.endswith(".java") or is_test_file(file_name):
                continue
            fixed_files.add(file_name)

            class_name = (row.get("class") or "").strip()
            method_name = (row.get("method") or "").strip()
            if class_name and method_name:
                fixed_methods.add(f"{file_name}:{class_name}:{method_name}")

    return {
        "fixed_files": sorted(fixed_files),
        "fixed_methods": sorted(fixed_methods),
        "target_file_count": len(fixed_files),
        "target_method_count": len(fixed_methods),
    }


def build_presence_map(structural_report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    components = {
        role: {
            "present_in_query": False,
            "probe_path": None,
            "compile_success": None,
            "compile_error": None,
            "compile_log": None,
            "generation_mode": None,
            "source_predicate": None,
        }
        for role in ROLE_ORDER
    }
    for generated in structural_report.get("generated_components", []):
        role = generated["role"]
        components[role] = {
            "present_in_query": True,
            "probe_path": generated.get("output_path"),
            "compile_success": generated.get("success"),
            "compile_error": None if generated.get("success") else ((generated.get("stderr") or "").strip() or None),
            "compile_log": (generated.get("stderr") or "").strip() or None,
            "generation_mode": generated.get("generation_mode"),
            "source_predicate": generated.get("source_predicate"),
        }
    return components


def to_component_run_dict(result: Optional[RunCountResult], alignment: Optional[AlignmentResult] = None) -> dict[str, Any]:
    if result is None:
        return {
            "success": False,
            "num_results": 0,
            "error": "not_run",
            "sarif_path": None,
            "num_aligned_files": 0,
            "num_aligned_methods": 0,
            "aligned_files": [],
            "aligned_methods": [],
            "target_file_coverage": 0.0,
            "target_method_coverage": 0.0,
            "hit_files": [],
            "hit_methods": [],
        }
    run_dict = {
        "success": result.success,
        "num_results": result.num_results,
        "error": result.error,
        "sarif_path": None,
        "num_aligned_files": 0,
        "num_aligned_methods": 0,
        "aligned_files": [],
        "aligned_methods": [],
        "target_file_coverage": 0.0,
        "target_method_coverage": 0.0,
        "hit_files": [],
        "hit_methods": [],
    }
    if alignment is not None:
        run_dict.update(
            {
                "sarif_path": alignment.sarif_path,
                "num_aligned_files": alignment.num_aligned_files,
                "num_aligned_methods": alignment.num_aligned_methods,
                "aligned_files": alignment.aligned_files,
                "aligned_methods": alignment.aligned_methods,
                "target_file_coverage": alignment.target_file_coverage,
                "target_method_coverage": alignment.target_method_coverage,
                "hit_files": alignment.hit_files,
                "hit_methods": alignment.hit_methods,
            }
        )
    return run_dict


PROBLEM_STATUS_SET = {
    "missing_component",
    "compile_failed",
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


def _default_confidence(status: str) -> float:
    return {
        "missing_component": 0.95,
        "compile_failed": 0.95,
        "empty": 0.90,
        "only_fixed": 0.85,
        "off_target": 0.82,
        "good_anchor": 0.86,
        "weak_but_present": 0.72,
        "absent": 0.50,
        "repair_only": 0.85,
        "useful_repair_signal": 0.75,
        "overblocking_suspect": 0.85,
        "non_discriminative": 0.60,
        "likely_not_needed": 0.55,
        "useful_bridge": 0.80,
        "noisy_bridge": 0.60,
        "weak_bridge": 0.65,
        "others": 1.0,
    }.get(status, 0.50)


def classify_component_status(
    role: str,
    present_in_query: bool,
    compile_success: Optional[bool],
    vuln_count: int,
    fixed_count: int,
    vuln_aligned_methods: int,
    fixed_aligned_methods: int,
    target_alignment_available: bool,
    original_query_vuln_results: int,
    original_query_fixed_results: int,
) -> tuple[str, float]:
    if not present_in_query:
        if role == "flow" and (original_query_vuln_results > 0 or original_query_fixed_results > 0):
            return ("likely_not_needed", _default_confidence("likely_not_needed"))
        return ("missing_component", _default_confidence("missing_component"))

    if compile_success is False:
        return ("compile_failed", _default_confidence("compile_failed"))

    if role == "barrier":
        if vuln_count == 0 and fixed_count == 0:
            return ("absent", _default_confidence("absent"))
        if vuln_count == 0 and fixed_count > 0:
            return ("repair_only", _default_confidence("repair_only"))
        if fixed_count > vuln_count:
            return ("useful_repair_signal", _default_confidence("useful_repair_signal"))
        if (
            fixed_count >= 0
            and vuln_count > fixed_count * 2
            and original_query_vuln_results == 0
            and original_query_fixed_results == 0
        ):
            return ("overblocking_suspect", _default_confidence("overblocking_suspect"))
        if vuln_count > 0 and fixed_count > 0:
            return ("non_discriminative", _default_confidence("non_discriminative"))
        return ("others", _default_confidence("others"))

    if role == "flow":
        if vuln_count == 0 and fixed_count == 0:
            return ("empty", _default_confidence("empty"))
        if vuln_count > 0 and fixed_count == 0:
            return ("useful_bridge", _default_confidence("useful_bridge"))
        if (
            vuln_count > 0
            and fixed_count > 0
            and abs(vuln_count - fixed_count) <= max(1, min(vuln_count, fixed_count) // 2)
        ):
            return ("noisy_bridge", _default_confidence("noisy_bridge"))
        if vuln_count > 0 or fixed_count > 0:
            return ("weak_bridge", _default_confidence("weak_bridge"))
        return ("others", _default_confidence("others"))

    if vuln_count == 0 and fixed_count == 0:
        return ("empty", _default_confidence("empty"))
    if vuln_count == 0 and fixed_count > 0:
        return ("only_fixed", _default_confidence("only_fixed"))

    if target_alignment_available:
        if vuln_count > 0 and vuln_aligned_methods == 0 and fixed_aligned_methods == 0:
            return ("off_target", _default_confidence("off_target"))
        if vuln_aligned_methods > 0 and fixed_aligned_methods == 0:
            return ("good_anchor", _default_confidence("good_anchor"))
        if vuln_aligned_methods > 0 and fixed_aligned_methods > 0:
            return ("weak_but_present", _default_confidence("weak_but_present"))

    if vuln_count > 0 and fixed_count > 0:
        return ("weak_but_present", _default_confidence("weak_but_present"))

    return ("others", _default_confidence("others"))


def build_problem_components(components: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for role in ROLE_ORDER:
        verdict = components[role]["verdict"]
        status = verdict["status"]
        if status in PROBLEM_STATUS_SET:
            items.append(
                {
                    "role": role,
                    "status": status,
                    "confidence": verdict["confidence"],
                }
            )
    return items


def evaluate_original_query_summary(
    *,
    query_path: Path,
    cve_id: str,
    vuln_db_path: Path,
    fixed_db_path: Path,
    runtime_dir: Path,
    codeql_path: str,
) -> dict[str, Any]:
    compile_result = compile_query(query_path, codeql_path)
    summary = {
        "compile_success": compile_result["success"],
        "vuln_num_results": 0,
        "fixed_num_results": 0,
        "vuln_recall_method": None,
        "fixed_recall_method": None,
        "notes": [],
    }

    if not compile_result["success"]:
        summary["notes"].append("Original query compilation failed.")
        return summary

    try:
        query_runner = load_query_execution_runner(codeql_path)
        _, vuln_eval, fixed_eval, _ = asyncio.run(
            query_runner(
                str(query_path),
                str(vuln_db_path),
                str(fixed_db_path),
                cve_id,
                output_dir=str(runtime_dir),
            )
        )
        summary.update(
            {
                "vuln_num_results": vuln_eval.num_results,
                "fixed_num_results": fixed_eval.num_results,
                "vuln_recall_method": bool(vuln_eval.recall_method),
                "fixed_recall_method": bool(fixed_eval.recall_method),
            }
        )
        return summary
    except Exception as exc:
        LOGGER.warning("Official evaluation fallback for original query failed: %s", exc)

    original_vuln = run_query_count(query_path, vuln_db_path, codeql_path, runtime_dir, "original_vulnerable")
    original_fixed = run_query_count(query_path, fixed_db_path, codeql_path, runtime_dir, "original_fixed")
    summary.update(
        {
            "vuln_num_results": original_vuln.num_results if original_vuln.success else 0,
            "fixed_num_results": original_fixed.num_results if original_fixed.success else 0,
        }
    )
    summary["notes"].append("Fell back to count-only original query evaluation.")
    return summary


def markdown_summary(report: dict[str, Any]) -> str:
    def add_list_block(lines: list[str], label: str, items: list[str], max_items: int = 8) -> None:
        if not items:
            lines.append(f"  - {label}: none")
            return
        lines.append(f"  - {label} ({len(items)}):")
        for item in items[:max_items]:
            lines.append(f"    - `{item}`")
        remaining = len(items) - max_items
        if remaining > 0:
            lines.append(f"    - ... and {remaining} more")

    lines = [
        "# Probe Evaluation Summary",
        "",
        f"- CVE: `{report['meta']['cve_id']}`",
        f"- Query: `{report['meta']['query_path']}`",
        f"- Probe dir: `{report['meta']['probe_dir']}`",
        f"- Target files: `{report['target_context']['target_file_count']}`",
        f"- Target methods: `{report['target_context']['target_method_count']}`",
        "",
        "## Problem Components",
        "",
    ]

    if report["problem_components"]:
        for item in report["problem_components"]:
            lines.append(
                f"- `{item['role']}`: status=`{item['status']}`, confidence=`{item['confidence']}`"
            )
    else:
        lines.append("- none")

    lines.extend(
        [
            "",
            "## Components",
            "",
        ]
    )

    for role in ROLE_ORDER:
        component = report["components"][role]
        verdict = component["verdict"]
        vuln_run = component["run"]["vulnerable"]
        fixed_run = component["run"]["fixed"]
        vuln_num = vuln_run["num_results"]
        fixed_num = fixed_run["num_results"]
        lines.append(
            f"- `{role}`: `{verdict['status']}` | confidence=`{verdict['confidence']}` | vuln=`{vuln_num}` fixed=`{fixed_num}`"
        )
        lines.append(
            "  - target alignment: "
            f"vuln files=`{vuln_run['num_aligned_files']}` methods=`{vuln_run['num_aligned_methods']}`; "
            f"fixed files=`{fixed_run['num_aligned_files']}` methods=`{fixed_run['num_aligned_methods']}`"
        )

        if vuln_run["sarif_path"] or fixed_run["sarif_path"]:
            lines.append(
                "  - target coverage: "
                f"vuln file=`{vuln_run['target_file_coverage']:.2f}` method=`{vuln_run['target_method_coverage']:.2f}`; "
                f"fixed file=`{fixed_run['target_file_coverage']:.2f}` method=`{fixed_run['target_method_coverage']:.2f}`"
            )
            add_list_block(lines, "vuln aligned files", vuln_run["aligned_files"])
            add_list_block(lines, "vuln aligned methods", vuln_run["aligned_methods"])
            add_list_block(lines, "fixed aligned files", fixed_run["aligned_files"])
            add_list_block(lines, "fixed aligned methods", fixed_run["aligned_methods"])
            add_list_block(lines, "vuln hit files", vuln_run["hit_files"])
            add_list_block(lines, "vuln hit methods", vuln_run["hit_methods"])
            add_list_block(lines, "fixed hit files", fixed_run["hit_files"])
            add_list_block(lines, "fixed hit methods", fixed_run["hit_methods"])

    return "\n".join(lines) + "\n"


def evaluate_probe_query(
    *,
    query_path: Path,
    cve_id: str,
    vuln_db_path: Path,
    fixed_db_path: Path,
    output_dir: Optional[Path],
    codeql_path: str,
    fix_info_path: Path,
    probe_kind_mode: str = "hybrid",
    original_query_summary: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    if output_dir is None:
        output_dir = query_path.parent / f"{query_path.stem}-probe-evaluation"
    output_dir.mkdir(parents=True, exist_ok=True)

    structural_report = extract_and_compile_components(
        query_path=query_path,
        output_dir=output_dir,
        codeql_path=codeql_path,
        compile_components=True,
        probe_kind_mode=probe_kind_mode,
    )

    target_context = load_target_context(cve_id, fix_info_path)
    runtime_dir = output_dir / "runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    original_query = original_query_summary or evaluate_original_query_summary(
        query_path=query_path,
        cve_id=cve_id,
        vuln_db_path=vuln_db_path,
        fixed_db_path=fixed_db_path,
        runtime_dir=runtime_dir,
        codeql_path=codeql_path,
    )

    present_components = build_presence_map(structural_report)
    components: dict[str, dict[str, Any]] = {}
    alignment_dir = output_dir / "alignment"
    alignment_dir.mkdir(parents=True, exist_ok=True)
    for role in ROLE_ORDER:
        component = present_components[role]
        vuln_result = None
        fixed_result = None
        vuln_alignment = None
        fixed_alignment = None
        if component["present_in_query"] and component["probe_path"] and component["compile_success"]:
            probe_path = Path(component["probe_path"])
            vuln_result = run_query_count(
                probe_path,
                vuln_db_path,
                codeql_path,
                runtime_dir,
                f"{role}_vulnerable",
            )
            fixed_result = run_query_count(
                probe_path,
                fixed_db_path,
                codeql_path,
                runtime_dir,
                f"{role}_fixed",
            )
            if role in {"source", "sink"}:
                vuln_alignment = run_alignment_evaluation(
                    role=role,
                    probe_path=probe_path,
                    database_path=vuln_db_path,
                    cve_id=cve_id,
                    codeql_path=codeql_path,
                    fix_info_path=fix_info_path,
                    output_dir=alignment_dir,
                    prefix=f"{role}_vulnerable_alignment",
                    target_context=target_context,
                )
                fixed_alignment = run_alignment_evaluation(
                    role=role,
                    probe_path=probe_path,
                    database_path=fixed_db_path,
                    cve_id=cve_id,
                    codeql_path=codeql_path,
                    fix_info_path=fix_info_path,
                    output_dir=alignment_dir,
                    prefix=f"{role}_fixed_alignment",
                    target_context=target_context,
                )

        vuln_count = vuln_result.num_results if vuln_result else 0
        fixed_count = fixed_result.num_results if fixed_result else 0
        vuln_aligned_methods = vuln_alignment.num_aligned_methods if vuln_alignment and vuln_alignment.success else 0
        fixed_aligned_methods = fixed_alignment.num_aligned_methods if fixed_alignment and fixed_alignment.success else 0
        target_alignment_available = bool(
            (vuln_alignment and vuln_alignment.success) or (fixed_alignment and fixed_alignment.success)
        )
        status, confidence = classify_component_status(
            role=role,
            present_in_query=component["present_in_query"],
            compile_success=component["compile_success"],
            vuln_count=vuln_count,
            fixed_count=fixed_count,
            vuln_aligned_methods=vuln_aligned_methods,
            fixed_aligned_methods=fixed_aligned_methods,
            target_alignment_available=target_alignment_available,
            original_query_vuln_results=original_query["vuln_num_results"],
            original_query_fixed_results=original_query["fixed_num_results"],
        )

        components[role] = {
            "present_in_query": component["present_in_query"],
            "probe_path": component["probe_path"],
            "compile_success": component["compile_success"],
            "compile_error": component["compile_error"],
            "generation_mode": component["generation_mode"],
            "source_predicate": component["source_predicate"],
            "run": {
                "vulnerable": to_component_run_dict(vuln_result, vuln_alignment),
                "fixed": to_component_run_dict(fixed_result, fixed_alignment),
            },
            "verdict": {
                "status": status,
                "confidence": confidence,
            },
        }

    problem_components = build_problem_components(components)

    report = {
        "schema_version": "v1",
        "meta": {
            "cve_id": cve_id,
            "language": "java",
            "generated_at": iso_now(),
            "query_path": str(query_path),
            "probe_dir": str(output_dir),
            "evaluator": "probe_evaluation.py",
            "codeql_path": codeql_path,
        },
        "target_context": target_context,
        "original_query": original_query,
        "components": components,
        "problem_components": problem_components,
        "structural_extract_summary_path": structural_report.get("summary_json_path"),
    }

    json_path = output_dir / "probe_evaluation.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    md_path = output_dir / "probe_evaluation.md"
    md_path.write_text(markdown_summary(report), encoding="utf-8")

    report["json_path"] = str(json_path)
    report["markdown_path"] = str(md_path)
    return report


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate decomposed CodeQL probes using count-based diagnostic rules."
    )
    parser.add_argument("--query-path", required=True, type=Path, help="Path to the original .ql query.")
    parser.add_argument("--cve-id", required=True, help="CVE identifier used to load patch target context.")
    parser.add_argument("--vuln-db", required=True, type=Path, help="Path to the vulnerable CodeQL database.")
    parser.add_argument("--fixed-db", required=True, type=Path, help="Path to the fixed CodeQL database.")
    parser.add_argument("--output-dir", type=Path, help="Directory for generated probes and evaluation outputs.")
    parser.add_argument(
        "--fix-info-path",
        type=Path,
        default=resolve_default_fix_info_path(),
        help="Path to fix_info.csv used for target context.",
    )
    parser.add_argument(
        "--codeql-path",
        default=resolve_default_codeql_path(),
        help="Path to the codeql executable.",
    )
    parser.add_argument(
        "--probe-kind-mode",
        default="hybrid",
        choices=("hybrid", "all-table", "all-problem"),
        help="Probe generation mode passed to structural_extract.py.",
    )
    parser.add_argument("--pretty", action="store_true", help="Pretty-print the final JSON report.")
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    try:
        report = evaluate_probe_query(
            query_path=args.query_path.resolve(),
            cve_id=args.cve_id,
            vuln_db_path=args.vuln_db.resolve(),
            fixed_db_path=args.fixed_db.resolve(),
            output_dir=args.output_dir.resolve() if args.output_dir else None,
            codeql_path=args.codeql_path,
            fix_info_path=args.fix_info_path.resolve(),
            probe_kind_mode=args.probe_kind_mode,
        )
    except Exception as exc:  # pragma: no cover
        LOGGER.error("%s", exc)
        return 1

    print(json.dumps(report, indent=2 if args.pretty else None, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
