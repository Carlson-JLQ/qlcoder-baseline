#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

try:
    from .repair_template_selector import DEFAULT_COMPONENT_ORDER, select_components
except Exception:
    from repair_template_selector import DEFAULT_COMPONENT_ORDER, select_components


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build component-level repair prompts and action suggestions from a probe "
            "evaluation report and a full CodeQL query."
        )
    )
    parser.add_argument("--probe-eval", type=Path, required=True)
    parser.add_argument("--query-path", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--pretty", action="store_true")
    return parser.parse_args()


def _json_dumps(data: Any, pretty: bool) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2 if pretty else None)


def build_repair_plan(selection: dict[str, Any]) -> dict[str, Any]:
    components: list[dict[str, Any]] = []
    for role in selection.get("component_order", []):
        component = selection["components"][role]
        components.append(
            {
                "role": role,
                "status": component["status"],
                "repair_behavior": component["repair_behavior"],
                "recommended_action": component["recommended_action"],
                "target_predicate": component["target_predicate"],
                "problem_summary": component["problem_summary"],
                "prompt_text_en": component.get("prompt_text_en", component.get("prompt_text")),
                "prompt_text_zh": component.get("prompt_text_zh"),
                "supporting_facts": component["supporting_facts"],
            }
        )

    return {
        "query_path": selection["query_path"],
        "component_order": list(selection.get("component_order", [])),
        "problem_components": selection.get("problem_components", []),
        "num_components": len(components),
        "components": components,
    }


def render_selected_prompts(selection: dict[str, Any]) -> str:
    lines = [
        "# Selected Repair Prompts",
        "",
        f"- Query: `{selection['query_path']}`",
        "",
    ]

    if not selection.get("component_order"):
        lines.extend(["- No problem components were selected.", ""])
        return "\n".join(lines).rstrip() + "\n"

    for role in selection["component_order"]:
        component = selection["components"][role]
        lines.extend(
            [
                f"## {role}",
                "",
                f"- Status: `{component['status']}`",
                f"- Repair behavior: `{component['repair_behavior']}`",
                f"- Recommended action: `{component['recommended_action']}`",
                f"- Predicate: `{component['target_predicate'] or 'n/a'}`",
                f"- Confidence: `{component['confidence']}`",
                "",
                "### Problem",
                "",
                component["problem_summary"],
                "",
                "### Facts",
                "",
                "```json",
                json.dumps(component["supporting_facts"], ensure_ascii=False, indent=2),
                "```",
                "",
                "### Prompt",
                "",
                "#### English",
                "",
                "```text",
                component.get("prompt_text_en", component["prompt_text"]),
                "```",
                "",
                "#### 中文",
                "",
                "```text",
                component.get("prompt_text_zh", ""),
                "```",
                "",
            ]
        )

    return "\n".join(lines).rstrip() + "\n"


def render_repair_suggestions(selection: dict[str, Any], query_path: Path) -> str:
    lines = [
        "# Query Repair Suggestions",
        "",
        f"- Query: `{query_path}`",
        "",
        "## Problem Components",
        "",
    ]

    if not selection.get("component_order"):
        lines.extend(["- No problem components were selected.", ""])
        return "\n".join(lines).rstrip() + "\n"

    for role in selection["component_order"]:
        component = selection["components"][role]
        lines.extend(
            [
                f"### {role}",
                "",
                f"- Status: `{component['status']}`",
                f"- Repair behavior: `{component['repair_behavior']}`",
                f"- Recommended action: `{component['recommended_action']}`",
                f"- Target predicate: `{component['target_predicate'] or 'n/a'}`",
                f"- Problem: {component['problem_summary']}",
                "",
                "#### English",
                "",
                "```text",
                component.get("prompt_text_en", component["prompt_text"]),
                "```",
                "",
                "#### 中文",
                "",
                "```text",
                component.get("prompt_text_zh", ""),
                "```",
                "",
            ]
        )

    return "\n".join(lines).rstrip() + "\n"


def render_repair_summary(selection: dict[str, Any], repair_plan: dict[str, Any], query_path: Path) -> str:
    lines = [
        "# Query Repair Summary",
        "",
        f"- Query: `{query_path}`",
        f"- Problem components: `{repair_plan['num_components']}`",
        "",
        "## Components",
        "",
    ]

    if not selection.get("component_order"):
        lines.extend(["- No problem components were selected.", ""])
        return "\n".join(lines).rstrip() + "\n"

    for role in selection["component_order"]:
        component = selection["components"][role]
        lines.append(
            f"- `{role}`: status=`{component['status']}`, behavior=`{component['repair_behavior']}`, action=`{component['recommended_action']}`"
        )

    lines.extend(["", "## Overall Guidance", ""])
    lines.append("- Combine the selected component prompts directly; do not collapse them into a single primary cause.")
    for component in repair_plan["components"]:
        lines.append(f"- `{component['role']}`: {component['problem_summary']}")

    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    args = parse_args()
    report = json.loads(args.probe_eval.read_text(encoding="utf-8"))
    query_path = args.query_path or Path(report["meta"]["query_path"])

    selection = select_components(report)
    selection["resolved_query_path"] = str(query_path)

    repair_plan = build_repair_plan(selection)

    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    selected_repairs_path = output_dir / "selected_repairs.json"
    selected_prompts_path = output_dir / "selected_prompts.md"
    repair_plan_path = output_dir / "repair_plan.json"
    repair_suggestions_path = output_dir / "repair_suggestions.md"
    repair_summary_path = output_dir / "repair_summary.md"

    selected_repairs_path.write_text(_json_dumps(selection, args.pretty), encoding="utf-8")
    selected_prompts_path.write_text(render_selected_prompts(selection), encoding="utf-8")
    repair_plan_path.write_text(_json_dumps(repair_plan, args.pretty), encoding="utf-8")
    repair_suggestions_path.write_text(
        render_repair_suggestions(selection, query_path),
        encoding="utf-8",
    )
    repair_summary_path.write_text(
        render_repair_summary(selection, repair_plan, query_path),
        encoding="utf-8",
    )

    print(f"Wrote repair artifacts to {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
