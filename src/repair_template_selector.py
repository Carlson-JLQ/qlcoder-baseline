#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

try:
    from .component_repair_prompts import get_prompt_spec
except Exception:
    from component_repair_prompts import get_prompt_spec


DEFAULT_COMPONENT_ORDER = ("source", "sink", "barrier", "flow")
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


EXCLUDED_COMPONENT_FIELDS = {"generation_mode", "source_predicate", "probe_path"}
EXCLUDED_RUN_FIELDS = {"sarif_path"}
TRUNCATED_LIST_FIELDS = {"hit_files", "hit_methods"}
MAX_LIST_ITEMS = 5


def _ordered_problem_components(report: dict[str, Any]) -> list[dict[str, Any]]:
    items = report.get("problem_components") or []
    order = {role: idx for idx, role in enumerate(DEFAULT_COMPONENT_ORDER)}
    return sorted(items, key=lambda item: order.get(item.get("role"), len(DEFAULT_COMPONENT_ORDER)))


def _fallback_problem_components(report: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for role in DEFAULT_COMPONENT_ORDER:
        component = report.get("components", {}).get(role, {})
        verdict = component.get("verdict", {})
        status = verdict.get("status")
        if status in PROBLEM_STATUS_SET:
            items.append(
                {
                    "role": role,
                    "status": status,
                    "confidence": float(verdict.get("confidence", 0.0) or 0.0),
                }
            )
    return items


def _trim_value(key: str, value: Any) -> Any:
    if key in TRUNCATED_LIST_FIELDS and isinstance(value, list):
        return value[:MAX_LIST_ITEMS]
    return value


def _trim_run_fields(run: dict[str, Any]) -> dict[str, Any]:
    trimmed: dict[str, Any] = {}
    for side, side_report in run.items():
        if not isinstance(side_report, dict):
            trimmed[side] = side_report
            continue
        trimmed_side: dict[str, Any] = {}
        for key, value in side_report.items():
            if key in EXCLUDED_RUN_FIELDS:
                continue
            trimmed_side[key] = _trim_value(key, value)
        trimmed[side] = trimmed_side
    return trimmed


def supporting_facts_for_component(component: dict[str, Any]) -> dict[str, Any]:
    facts: dict[str, Any] = {}
    for key, value in component.items():
        if key in EXCLUDED_COMPONENT_FIELDS:
            continue
        if key == "run" and isinstance(value, dict):
            facts[key] = _trim_run_fields(value)
            continue
        facts[key] = _trim_value(key, value)
    return facts


def build_repair_prompt(role: str, status: str) -> dict[str, str] | None:
    try:
        spec = get_prompt_spec(role, status)
    except KeyError:
        return None
    return {
        "en": spec.prompt_text_en,
        "zh": spec.prompt_text_zh,
    }


def build_component_feedback(role: str, status: str, component: dict[str, Any]) -> dict[str, Any]:
    return {
        "Component": role,
        "Repair Prompt": build_repair_prompt(role, status),
        "Supporting Facts": supporting_facts_for_component(component),
    }


def select_components(report: dict[str, Any]) -> dict[str, Any]:
    problem_components = _ordered_problem_components(report)
    if not problem_components:
        problem_components = _fallback_problem_components(report)

    selected_roles = [item["role"] for item in problem_components]
    output: dict[str, Any] = {
        "query_path": report["meta"]["query_path"],
        "original_query": report.get("original_query", {}),
        "target_context": report.get("target_context", {}),
        "component_order": selected_roles,
        "problem_components": problem_components,
        "selected_components": [],
    }

    for item in problem_components:
        role = item["role"]
        status = item["status"]
        component = report["components"][role]
        output["selected_components"].append(
            build_component_feedback(role, status, component)
        )

    return output


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Select component repair prompts and supporting facts from probe_evaluation.json."
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
