#!/usr/bin/env python3

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

try:
    from .probe_evaluation import (
        compile_query,
        evaluate_probe_query,
        load_query_execution_runner,
        resolve_default_codeql_path,
        resolve_default_fix_info_path,
    )
    from .query_repair_pipeline import (
        build_repair_plan,
        render_repair_suggestions,
        render_repair_summary,
        render_selected_prompts,
    )
    from .repair_template_selector import select_components
except Exception:
    from probe_evaluation import (
        compile_query,
        evaluate_probe_query,
        load_query_execution_runner,
        resolve_default_codeql_path,
        resolve_default_fix_info_path,
    )
    from query_repair_pipeline import (
        build_repair_plan,
        render_repair_suggestions,
        render_repair_summary,
        render_selected_prompts,
    )
    from repair_template_selector import select_components


LOGGER = logging.getLogger(__name__)


def _json_dumps(data: Any, pretty: bool) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2 if pretty else None)


def _to_plain_dict(obj: Any) -> Any:
    if is_dataclass(obj):
        return asdict(obj)
    return obj


def run_official_evaluation(
    *,
    query_path: Path,
    cve_id: str,
    vuln_db_path: Path,
    fixed_db_path: Path,
    codeql_path: str,
    output_dir: Path,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    compile_result = compile_query(query_path, codeql_path)
    result: dict[str, Any] = {
        "query_path": str(query_path),
        "compile_success": compile_result["success"],
        "execution_success": False,
        "summary": "",
        "vulnerable": None,
        "fixed": None,
        "notes": [],
    }

    if not compile_result["success"]:
        result["notes"].append((compile_result.get("stderr") or "").strip() or "Query compilation failed.")
        return result

    try:
        query_runner = load_query_execution_runner(codeql_path)
        summary, vuln_eval, fixed_eval, execution_success = asyncio.run(
            query_runner(
                str(query_path),
                str(vuln_db_path),
                str(fixed_db_path),
                cve_id,
                output_dir=str(output_dir),
            )
        )
        result.update(
            {
                "execution_success": execution_success,
                "summary": summary,
                "vulnerable": _to_plain_dict(vuln_eval),
                "fixed": _to_plain_dict(fixed_eval),
            }
        )
        if not execution_success:
            result["notes"].append("Official evaluation did not complete successfully on both databases.")
        return result
    except Exception as exc:
        result["notes"].append(f"Official evaluation failed: {exc}")
        return result


def build_original_query_summary(official_eval: dict[str, Any]) -> dict[str, Any]:
    vuln = official_eval.get("vulnerable") or {}
    fixed = official_eval.get("fixed") or {}
    return {
        "compile_success": official_eval.get("compile_success", False),
        "vuln_num_results": int(vuln.get("num_results", 0) or 0),
        "fixed_num_results": int(fixed.get("num_results", 0) or 0),
        "vuln_recall_method": vuln.get("recall_method"),
        "fixed_recall_method": fixed.get("recall_method"),
        "notes": official_eval.get("notes", []),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the full query -> probe -> evaluation -> repair suggestion workflow."
    )
    parser.add_argument("--query-path", type=Path, required=True)
    parser.add_argument("--cve-id", required=True)
    parser.add_argument("--vuln-db", type=Path, required=True)
    parser.add_argument("--fixed-db", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
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
    parser.add_argument("--pretty", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    query_path = args.query_path.resolve()
    vuln_db_path = args.vuln_db.resolve()
    fixed_db_path = args.fixed_db.resolve()
    output_dir = args.output_dir.resolve()
    fix_info_path = args.fix_info_path.resolve()

    official_eval_dir = output_dir / "official_evaluation"
    probe_eval_dir = output_dir / "probe_evaluation"
    repair_dir = output_dir / "repair_suggestions"
    output_dir.mkdir(parents=True, exist_ok=True)

    official_eval = run_official_evaluation(
        query_path=query_path,
        cve_id=args.cve_id,
        vuln_db_path=vuln_db_path,
        fixed_db_path=fixed_db_path,
        codeql_path=args.codeql_path,
        output_dir=official_eval_dir,
    )

    (official_eval_dir / "official_eval_summary.json").write_text(
        _json_dumps(official_eval, args.pretty),
        encoding="utf-8",
    )
    (official_eval_dir / "official_eval_summary.md").write_text(
        official_eval.get("summary", "") or "# Official Evaluation Summary\n\nNo official evaluation summary available.\n",
        encoding="utf-8",
    )

    probe_report = evaluate_probe_query(
        query_path=query_path,
        cve_id=args.cve_id,
        vuln_db_path=vuln_db_path,
        fixed_db_path=fixed_db_path,
        output_dir=probe_eval_dir,
        codeql_path=args.codeql_path,
        fix_info_path=fix_info_path,
        probe_kind_mode=args.probe_kind_mode,
        original_query_summary=build_original_query_summary(official_eval),
    )

    selection = select_components(probe_report)
    selection["resolved_query_path"] = str(query_path)
    repair_plan = build_repair_plan(selection)

    repair_dir.mkdir(parents=True, exist_ok=True)
    (repair_dir / "selected_repairs.json").write_text(_json_dumps(selection, args.pretty), encoding="utf-8")
    (repair_dir / "selected_prompts.md").write_text(render_selected_prompts(selection), encoding="utf-8")
    (repair_dir / "repair_plan.json").write_text(_json_dumps(repair_plan, args.pretty), encoding="utf-8")
    (repair_dir / "repair_suggestions.md").write_text(
        render_repair_suggestions(selection, query_path),
        encoding="utf-8",
    )
    (repair_dir / "repair_summary.md").write_text(
        render_repair_summary(selection, repair_plan, query_path),
        encoding="utf-8",
    )

    workflow_summary = {
        "query_path": str(query_path),
        "official_eval_dir": str(official_eval_dir),
        "probe_eval_dir": str(probe_eval_dir),
        "repair_dir": str(repair_dir),
        "official_eval_summary_json": str(official_eval_dir / "official_eval_summary.json"),
        "probe_evaluation_json": probe_report.get("json_path"),
        "repair_plan_json": str(repair_dir / "repair_plan.json"),
        "selected_repairs_json": str(repair_dir / "selected_repairs.json"),
    }
    (output_dir / "workflow_summary.json").write_text(
        _json_dumps(workflow_summary, args.pretty),
        encoding="utf-8",
    )

    print(json.dumps(workflow_summary, ensure_ascii=False, indent=2 if args.pretty else None))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
