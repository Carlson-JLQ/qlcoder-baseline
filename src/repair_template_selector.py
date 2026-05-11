#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

try:
    from .component_repair_prompts import ROLE_TO_PREDICATE, get_prompt_spec
except Exception:
    from component_repair_prompts import ROLE_TO_PREDICATE, get_prompt_spec


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


@dataclass
class SelectedComponent:
    role: str
    status: str
    repair_behavior: str
    recommended_action: str
    prompt_title: str
    prompt_text: str
    prompt_text_en: str
    prompt_text_zh: str
    target_predicate: str | None
    problem_summary: str
    confidence: float
    supporting_facts: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


PROBLEM_SUMMARY_MAP: dict[str, dict[str, str]] = {
    "source": {
        "missing_component": "Source 组件缺失。",
        "compile_failed": "Source 组件无法独立编译。",
        "empty": "Source 在漏洞版和修复版都没有结果。",
        "only_fixed": "Source 只在修复版出现，建模方向可能反了。",
        "off_target": "Source 有结果，但没有落在目标方法上，说明偏离漏洞入口。",
        "weak_but_present": "Source 存在，但区分性不足，不能作为稳定锚点。",
        "others": "Source 落入未分类异常状态，需要结合运行事实进一步判断。",
    },
    "sink": {
        "missing_component": "Sink 组件缺失。",
        "compile_failed": "Sink 组件无法独立编译。",
        "empty": "Sink 在漏洞版和修复版都没有结果。",
        "only_fixed": "Sink 只在修复版出现，危险点建模方向可能反了。",
        "off_target": "Sink 有结果，但没有落在目标危险方法上。",
        "weak_but_present": "Sink 存在，但区分性不足，不能作为稳定锚点。",
        "others": "Sink 落入未分类异常状态，需要结合运行事实进一步判断。",
    },
    "barrier": {
        "compile_failed": "Barrier 组件无法独立编译。",
        "overblocking_suspect": "Barrier 可能过强，压制了本应存在的漏洞路径。",
        "non_discriminative": "Barrier 在两侧都存在，但区分性不足。",
        "others": "Barrier 落入未分类异常状态，需要结合修复侧逻辑进一步判断。",
    },
    "flow": {
        "missing_component": "Flow 组件缺失，当前 query 缺少额外桥接步骤。",
        "compile_failed": "Flow 组件无法独立编译。",
        "empty": "Flow 在两侧都没有桥接事实。",
        "noisy_bridge": "Flow 两侧边很多且数量接近，桥接边噪声较大。",
        "weak_bridge": "Flow 有一定桥接证据，但还不够明确。",
        "others": "Flow 落入未分类异常状态，需要结合传播边事实进一步判断。",
    },
}


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


def supporting_facts_for_component(component: dict[str, Any]) -> dict[str, Any]:
    return {
        "present_in_query": component.get("present_in_query"),
        "probe_path": component.get("probe_path"),
        "compile_success": component.get("compile_success"),
        "compile_error": component.get("compile_error"),
        "generation_mode": component.get("generation_mode"),
        "predicate_name": component.get("source_predicate"),
        "run": component.get("run", {}),
    }


def summarize_problem(role: str, status: str) -> str:
    return PROBLEM_SUMMARY_MAP.get(role, {}).get(status, f"{role} 组件当前状态为 {status}。")


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
        "components": {},
    }

    for item in problem_components:
        role = item["role"]
        status = item["status"]
        component = report["components"][role]
        spec = get_prompt_spec(role, status)
        selected = SelectedComponent(
            role=role,
            status=status,
            repair_behavior=spec.repair_behavior,
            recommended_action=spec.recommended_action,
            prompt_title=spec.prompt_title,
            prompt_text=spec.prompt_text_en,
            prompt_text_en=spec.prompt_text_en,
            prompt_text_zh=spec.prompt_text_zh,
            target_predicate=spec.target_predicate or ROLE_TO_PREDICATE.get(role),
            problem_summary=summarize_problem(role, status),
            confidence=float(item.get("confidence", 0.0) or 0.0),
            supporting_facts=supporting_facts_for_component(component),
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
