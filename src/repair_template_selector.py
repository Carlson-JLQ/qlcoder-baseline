#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from component_repair_prompts import ROLE_TO_PREDICATE, get_prompt_spec


DEFAULT_COMPONENT_ORDER = ("source", "sink", "barrier", "flow")


@dataclass
class SelectedComponent:
    role: str
    original_status: str
    effective_status: str
    repair_behavior: str
    recommended_action: str
    prompt_title: str
    prompt_text: str
    target_predicate: str | None
    priority: int
    include_in_prompt: bool
    problem_summary: str
    confidence: float
    supporting_facts: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _get_alignment_counts(component: dict[str, Any], side: str) -> tuple[int, int]:
    run = component.get("run", {}).get(side, {})
    return int(run.get("num_aligned_files", 0) or 0), int(run.get("num_aligned_methods", 0) or 0)


def determine_effective_status(role: str, component: dict[str, Any]) -> str:
    verdict = component.get("verdict", {})
    original_status = verdict.get("status", "unknown")
    _, vuln_aligned_methods = _get_alignment_counts(component, "vulnerable")

    if role in {"source", "sink"}:
        if original_status == "weak_but_present" and vuln_aligned_methods == 0:
            return "off_target"
        if original_status == "weak_but_present" and vuln_aligned_methods > 0:
            return "good_anchor"
        return original_status

    if role == "flow" and original_status == "likely_not_needed":
        return "useful_bridge"

    return original_status


def supporting_facts_for_component(role: str, component: dict[str, Any]) -> dict[str, Any]:
    vuln = component.get("run", {}).get("vulnerable", {})
    fixed = component.get("run", {}).get("fixed", {})
    facts = {
        "vuln_num_results": int(vuln.get("num_results", 0) or 0),
        "fixed_num_results": int(fixed.get("num_results", 0) or 0),
        "vuln_num_aligned_files": int(vuln.get("num_aligned_files", 0) or 0),
        "vuln_num_aligned_methods": int(vuln.get("num_aligned_methods", 0) or 0),
        "fixed_num_aligned_files": int(fixed.get("num_aligned_files", 0) or 0),
        "fixed_num_aligned_methods": int(fixed.get("num_aligned_methods", 0) or 0),
        "vuln_target_file_coverage": vuln.get("target_file_coverage"),
        "vuln_target_method_coverage": vuln.get("target_method_coverage"),
        "fixed_target_file_coverage": fixed.get("target_file_coverage"),
        "fixed_target_method_coverage": fixed.get("target_method_coverage"),
        "vuln_aligned_files": vuln.get("aligned_files", []),
        "vuln_aligned_methods": vuln.get("aligned_methods", []),
        "fixed_aligned_files": fixed.get("aligned_files", []),
        "fixed_aligned_methods": fixed.get("aligned_methods", []),
    }
    if role in {"source", "sink"}:
        facts["vuln_hit_files_count"] = len(vuln.get("hit_files", []))
        facts["vuln_hit_methods_count"] = len(vuln.get("hit_methods", []))
        facts["fixed_hit_files_count"] = len(fixed.get("hit_files", []))
        facts["fixed_hit_methods_count"] = len(fixed.get("hit_methods", []))
    return facts


def select_components(report: dict[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {
        "query_path": report["meta"]["query_path"],
        "original_query": report.get("original_query", {}),
        "target_context": report.get("target_context", {}),
        "component_order": list(DEFAULT_COMPONENT_ORDER),
        "components": {},
    }

    for role in DEFAULT_COMPONENT_ORDER:
        component = report["components"][role]
        effective_status = determine_effective_status(role, component)
        spec = get_prompt_spec(role, effective_status)
        selected = SelectedComponent(
            role=role,
            original_status=component.get("verdict", {}).get("status", "unknown"),
            effective_status=effective_status,
            repair_behavior=spec.repair_behavior,
            recommended_action=spec.recommended_action,
            prompt_title=spec.prompt_title,
            prompt_text=spec.prompt_text,
            target_predicate=spec.target_predicate or ROLE_TO_PREDICATE.get(role),
            priority=spec.priority,
            include_in_prompt=spec.include_in_prompt,
            problem_summary=component.get("verdict", {}).get("reason", ""),
            confidence=float(component.get("verdict", {}).get("confidence", 0.0) or 0.0),
            supporting_facts=supporting_facts_for_component(role, component),
        )
        output["components"][role] = selected.to_dict()

    return output


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Select component repair prompts and action suggestions from probe_evaluation.json."
    )
    parser.add_argument("--probe-eval", type=Path, required=True)
    parser.add_argument("--output-path", type=Path, required=True)
    parser.add_argument("--pretty", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = json.loads(args.probe_eval.read_text(encoding="utf-8"))
    selection = select_components(report)
    args.output_path.parent.mkdir(parents=True, exist_ok=True)
    args.output_path.write_text(
        json.dumps(selection, ensure_ascii=False, indent=2 if args.pretty else None),
        encoding="utf-8",
    )
    print(f"Wrote repair prompt selection to {args.output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
