#!/usr/bin/env python3

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


ROLE_TO_PREDICATE = {
    "source": "isSource",
    "sink": "isSink",
    "barrier": "isBarrier",
    "flow": "isAdditionalFlowStep",
}


@dataclass(frozen=True)
class PromptSpec:
    role: str
    status: str
    repair_behavior: str
    recommended_action: str
    prompt_title: str
    prompt_text: str
    priority: int
    include_in_prompt: bool
    target_predicate: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


PROMPT_LIBRARY: dict[str, dict[str, PromptSpec]] = {
    "source": {
        "missing_component": PromptSpec(
            role="source",
            status="missing_component",
            repair_behavior="扩张 Source",
            recommended_action="add_new_source_branch",
            prompt_title="Source Missing Prompt",
            prompt_text=(
                "Only modify source-related code.\n"
                "The query does not define an effective source component.\n"
                "Add one new source condition that captures a target-adjacent entry point.\n"
                "Prefer parameters, request values, configuration values, or patch-adjacent inputs near target files and target methods.\n"
                "Do not modify sink, barrier, flow, or the final query structure."
            ),
            priority=1,
            include_in_prompt=True,
            target_predicate="isSource",
        ),
        "compile_failed": PromptSpec(
            role="source",
            status="compile_failed",
            repair_behavior="替换 Source",
            recommended_action="replace_or_rebuild_source",
            prompt_title="Source Compile Failed Prompt",
            prompt_text=(
                "Only modify source-related code.\n"
                "The source component does not compile independently.\n"
                "First repair the local source predicate structure, then keep only target-adjacent source conditions.\n"
                "Prefer a minimal local fix instead of rewriting the whole query.\n"
                "Do not modify sink, barrier, flow, or the final query structure."
            ),
            priority=1,
            include_in_prompt=True,
            target_predicate="isSource",
        ),
        "empty": PromptSpec(
            role="source",
            status="empty",
            repair_behavior="扩张 Source",
            recommended_action="add_target_adjacent_source",
            prompt_title="Source Empty Prompt",
            prompt_text=(
                "Only modify source-related code.\n"
                "The current source probe returns no matches on either vulnerable or fixed versions.\n"
                "Expand the source locally by adding one new source branch.\n"
                "Prefer entry points that are close to target files, target methods, or patch-related code.\n"
                "Do not modify sink, barrier, flow, or rewrite the whole query."
            ),
            priority=1,
            include_in_prompt=True,
            target_predicate="isSource",
        ),
        "only_fixed": PromptSpec(
            role="source",
            status="only_fixed",
            repair_behavior="替换 Source",
            recommended_action="replace_reversed_source",
            prompt_title="Source Only Fixed Prompt",
            prompt_text=(
                "Only modify source-related code.\n"
                "The current source modeling appears reversed because it only matches the fixed version.\n"
                "Narrow or replace the current source so that it captures vulnerable-side entry points instead of fixed-side-only inputs.\n"
                "Add stronger context constraints or replace the broad source condition with a target-adjacent one.\n"
                "Do not modify sink, barrier, flow, or rewrite the whole query."
            ),
            priority=1,
            include_in_prompt=True,
            target_predicate="isSource",
        ),
        "off_target": PromptSpec(
            role="source",
            status="off_target",
            repair_behavior="替换 Source",
            recommended_action="replace_off_target_source",
            prompt_title="Source Off Target Prompt",
            prompt_text=(
                "Only modify source-related code.\n"
                "The source probe has matches, but none align with target files or target methods.\n"
                "Treat this as off-target source modeling.\n"
                "Keep the repair local: add type, declaring-type, enclosing-callable, or parameter-position constraints, or replace broad utility-like sources with target-adjacent entry points.\n"
                "Do not modify sink, barrier, flow, or rewrite the whole query."
            ),
            priority=1,
            include_in_prompt=True,
            target_predicate="isSource",
        ),
        "good_anchor": PromptSpec(
            role="source",
            status="good_anchor",
            repair_behavior="保留",
            recommended_action="keep_source_stable",
            prompt_title="Source Keep Prompt",
            prompt_text=(
                "Do not prioritize source repair.\n"
                "The source component already aligns with vulnerable-side target methods or otherwise behaves like a good anchor.\n"
                "Keep source logic stable unless another change requires a very small local adjustment."
            ),
            priority=3,
            include_in_prompt=True,
            target_predicate=None,
        ),
        "weak_but_present": PromptSpec(
            role="source",
            status="weak_but_present",
            repair_behavior="轻微收缩",
            recommended_action="lightly_refine_source_if_needed",
            prompt_title="Source Weak But Present Prompt",
            prompt_text=(
                "Do not prioritize large source changes.\n"
                "The source component already shows some vulnerable-side evidence.\n"
                "Keep it mostly stable and only add a very small local constraint if later evidence proves it is still too broad."
            ),
            priority=3,
            include_in_prompt=True,
            target_predicate=None,
        ),
    },
    "sink": {
        "missing_component": PromptSpec(
            role="sink",
            status="missing_component",
            repair_behavior="扩张 Sink",
            recommended_action="add_new_sink_branch",
            prompt_title="Sink Missing Prompt",
            prompt_text=(
                "Only modify sink-related code.\n"
                "The query does not define an effective sink component.\n"
                "Add one new sink condition that captures a vulnerability-relevant dangerous operation near target files or target methods.\n"
                "Do not modify source, barrier, flow, or the final query structure."
            ),
            priority=1,
            include_in_prompt=True,
            target_predicate="isSink",
        ),
        "compile_failed": PromptSpec(
            role="sink",
            status="compile_failed",
            repair_behavior="替换 Sink",
            recommended_action="replace_or_rebuild_sink",
            prompt_title="Sink Compile Failed Prompt",
            prompt_text=(
                "Only modify sink-related code.\n"
                "The sink component does not compile independently.\n"
                "First repair the local sink predicate structure, then keep only the most target-relevant dangerous operations.\n"
                "Prefer a minimal local fix instead of rewriting the whole query.\n"
                "Do not modify source, barrier, flow, or the final query structure."
            ),
            priority=1,
            include_in_prompt=True,
            target_predicate="isSink",
        ),
        "empty": PromptSpec(
            role="sink",
            status="empty",
            repair_behavior="扩张 Sink",
            recommended_action="add_target_adjacent_sink",
            prompt_title="Sink Empty Prompt",
            prompt_text=(
                "Only modify sink-related code.\n"
                "The current sink probe returns no matches on either vulnerable or fixed versions.\n"
                "Expand the sink locally by adding one new sink branch that better reflects the dangerous operation in the patch context.\n"
                "Do not modify source, barrier, flow, or rewrite the whole query."
            ),
            priority=1,
            include_in_prompt=True,
            target_predicate="isSink",
        ),
        "only_fixed": PromptSpec(
            role="sink",
            status="only_fixed",
            repair_behavior="替换 Sink",
            recommended_action="replace_reversed_sink",
            prompt_title="Sink Only Fixed Prompt",
            prompt_text=(
                "Only modify sink-related code.\n"
                "The current sink modeling appears reversed because it only matches the fixed version.\n"
                "Narrow or replace the sink so that it captures vulnerable-side dangerous operations rather than fixed-side-only behavior.\n"
                "Do not modify source, barrier, flow, or rewrite the whole query."
            ),
            priority=1,
            include_in_prompt=True,
            target_predicate="isSink",
        ),
        "off_target": PromptSpec(
            role="sink",
            status="off_target",
            repair_behavior="替换 Sink",
            recommended_action="replace_off_target_sink",
            prompt_title="Sink Off Target Prompt",
            prompt_text=(
                "Only modify sink-related code.\n"
                "The sink probe has matches, but it does not align with target methods.\n"
                "Treat this as off-target sink modeling.\n"
                "Refine the sink using method-name, declaring-type, argument-position, or target-context constraints so that it better captures the intended dangerous operation.\n"
                "Do not modify source, barrier, flow, or rewrite the whole query."
            ),
            priority=1,
            include_in_prompt=True,
            target_predicate="isSink",
        ),
        "good_anchor": PromptSpec(
            role="sink",
            status="good_anchor",
            repair_behavior="保留",
            recommended_action="keep_sink_stable",
            prompt_title="Sink Keep Prompt",
            prompt_text=(
                "Do not prioritize sink repair.\n"
                "The sink component already behaves like a useful anchor near the intended dangerous operation.\n"
                "Keep sink logic stable unless another local change requires a very small adjustment."
            ),
            priority=3,
            include_in_prompt=True,
            target_predicate=None,
        ),
        "weak_but_present": PromptSpec(
            role="sink",
            status="weak_but_present",
            repair_behavior="轻微收缩",
            recommended_action="lightly_refine_sink_if_needed",
            prompt_title="Sink Weak But Present Prompt",
            prompt_text=(
                "Do not prioritize large sink changes.\n"
                "The sink component already shows some useful vulnerable-side evidence.\n"
                "Keep it mostly stable and only add a very small local constraint if later evidence proves it is still too broad."
            ),
            priority=3,
            include_in_prompt=True,
            target_predicate=None,
        ),
    },
    "barrier": {
        "compile_failed": PromptSpec(
            role="barrier",
            status="compile_failed",
            repair_behavior="替换 Barrier",
            recommended_action="replace_or_rebuild_barrier",
            prompt_title="Barrier Compile Failed Prompt",
            prompt_text=(
                "Only modify barrier-related code.\n"
                "The barrier component does not compile independently.\n"
                "Repair the local barrier predicate structure first, then keep only the most specific fixed-side validation logic.\n"
                "Do not modify source, sink, or flow."
            ),
            priority=1,
            include_in_prompt=True,
            target_predicate="isBarrier",
        ),
        "absent": PromptSpec(
            role="barrier",
            status="absent",
            repair_behavior="专化 Barrier 到修复逻辑",
            recommended_action="add_repair_side_barrier",
            prompt_title="Barrier Absent Prompt",
            prompt_text=(
                "Only modify barrier-related code.\n"
                "The query currently has no effective barrier behavior.\n"
                "Add a local barrier condition only if the patch introduces validation, sanitization, normalization, or fixed-side guard logic that should suppress paths after repair.\n"
                "Do not modify source, sink, flow, or rewrite the whole query."
            ),
            priority=2,
            include_in_prompt=True,
            target_predicate="isBarrier",
        ),
        "repair_only": PromptSpec(
            role="barrier",
            status="repair_only",
            repair_behavior="专化 Barrier 到修复逻辑",
            recommended_action="specialize_existing_barrier",
            prompt_title="Barrier Repair Only Prompt",
            prompt_text=(
                "Only modify barrier-related code.\n"
                "The barrier appears only on the fixed side, which is a strong repair-side signal.\n"
                "Keep the barrier and make it more explicit around fixed-side validation, sanitization, normalization, or whitelist logic.\n"
                "Do not weaken the barrier unless there is clear evidence that it suppresses vulnerable paths.\n"
                "Do not modify source, sink, or flow."
            ),
            priority=2,
            include_in_prompt=True,
            target_predicate="isBarrier",
        ),
        "useful_repair_signal": PromptSpec(
            role="barrier",
            status="useful_repair_signal",
            repair_behavior="专化 Barrier 到修复逻辑",
            recommended_action="specialize_existing_barrier",
            prompt_title="Barrier Useful Repair Signal Prompt",
            prompt_text=(
                "Only modify barrier-related code.\n"
                "The barrier is stronger in the fixed version than in the vulnerable version, which suggests useful repair-side protection logic.\n"
                "Preserve the barrier, but specialize it toward fixed-side validation helpers instead of generic shared conditions.\n"
                "Do not broadly delete barrier logic.\n"
                "Do not modify source, sink, or flow."
            ),
            priority=2,
            include_in_prompt=True,
            target_predicate="isBarrier",
        ),
        "overblocking_suspect": PromptSpec(
            role="barrier",
            status="overblocking_suspect",
            repair_behavior="弱化 Barrier",
            recommended_action="narrow_or_replace_barrier",
            prompt_title="Barrier Overblocking Prompt",
            prompt_text=(
                "Only modify barrier-related code.\n"
                "The barrier may be too broad and may suppress vulnerable paths that should remain reachable.\n"
                "Weaken the barrier locally by adding stronger guards or replacing generic barrier conditions with more specific fixed-side validation logic.\n"
                "Do not remove all barrier logic unless it is clearly unsupported.\n"
                "Do not modify source, sink, or flow."
            ),
            priority=1,
            include_in_prompt=True,
            target_predicate="isBarrier",
        ),
        "non_discriminative": PromptSpec(
            role="barrier",
            status="non_discriminative",
            repair_behavior="专化 Barrier 到修复逻辑",
            recommended_action="specialize_or_lightly_narrow_barrier",
            prompt_title="Barrier Non Discriminative Prompt",
            prompt_text=(
                "Only modify barrier-related code.\n"
                "The barrier matches both vulnerable and fixed versions with weak discrimination.\n"
                "Do not treat it as a main detection signal.\n"
                "Try to specialize the barrier toward fixed-side validation or sanitization logic; if that is not possible, gently narrow generic barrier conditions.\n"
                "Do not modify source, sink, or flow."
            ),
            priority=2,
            include_in_prompt=True,
            target_predicate="isBarrier",
        ),
    },
    "flow": {
        "missing_component": PromptSpec(
            role="flow",
            status="missing_component",
            repair_behavior="补桥",
            recommended_action="add_new_flow_bridge",
            prompt_title="Flow Missing Prompt",
            prompt_text=(
                "Only modify flow-related code.\n"
                "The query has no effective additional flow-step modeling.\n"
                "Add one new propagation step that helps connect the current source region to the current sink region.\n"
                "Prefer target-adjacent propagation edges over generic utility flows.\n"
                "Do not modify source, sink, barrier, or rewrite the whole query."
            ),
            priority=1,
            include_in_prompt=True,
            target_predicate="isAdditionalFlowStep",
        ),
        "empty": PromptSpec(
            role="flow",
            status="empty",
            repair_behavior="补桥",
            recommended_action="add_new_flow_bridge",
            prompt_title="Flow Empty Prompt",
            prompt_text=(
                "Only modify flow-related code.\n"
                "The flow probe returns no bridge facts on either vulnerable or fixed versions.\n"
                "Add one new local propagation step inside isAdditionalFlowStep or a closely related helper predicate.\n"
                "Prefer propagation edges that appear near target files, target methods, or patch-relevant helper calls.\n"
                "Do not modify source, sink, barrier, or rewrite the whole query."
            ),
            priority=1,
            include_in_prompt=True,
            target_predicate="isAdditionalFlowStep",
        ),
        "compile_failed": PromptSpec(
            role="flow",
            status="compile_failed",
            repair_behavior="替换或重建 Flow",
            recommended_action="replace_or_rebuild_flow",
            prompt_title="Flow Compile Failed Prompt",
            prompt_text=(
                "Only modify flow-related code.\n"
                "The additional flow-step logic does not compile independently.\n"
                "First simplify or repair the current flow predicate structure, then add or keep only the most target-relevant propagation edges.\n"
                "Do not modify source, sink, barrier, or rewrite the whole query."
            ),
            priority=1,
            include_in_prompt=True,
            target_predicate="isAdditionalFlowStep",
        ),
        "noisy_bridge": PromptSpec(
            role="flow",
            status="noisy_bridge",
            repair_behavior="降噪",
            recommended_action="narrow_existing_flow",
            prompt_title="Flow Noisy Bridge Prompt",
            prompt_text=(
                "Only modify flow-related code.\n"
                "The current additional flow-step logic produces many shared edges on both vulnerable and fixed versions.\n"
                "Treat this as noisy bridge modeling.\n"
                "Narrow the flow by adding stronger type, receiver, method-name, or argument-position constraints, and keep only target-adjacent propagation edges.\n"
                "Do not modify source, sink, barrier, or rewrite the whole query."
            ),
            priority=2,
            include_in_prompt=True,
            target_predicate="isAdditionalFlowStep",
        ),
        "weak_bridge": PromptSpec(
            role="flow",
            status="weak_bridge",
            repair_behavior="降噪或补桥",
            recommended_action="narrow_then_add_flow_if_needed",
            prompt_title="Flow Weak Bridge Prompt",
            prompt_text=(
                "Only modify flow-related code.\n"
                "Some bridge evidence exists, but it is not yet specific enough to explain the intended vulnerability path.\n"
                "First try to denoise existing flow edges; if needed, add one new target-adjacent propagation step.\n"
                "Do not modify source, sink, barrier, or rewrite the whole query."
            ),
            priority=2,
            include_in_prompt=True,
            target_predicate="isAdditionalFlowStep",
        ),
        "useful_bridge": PromptSpec(
            role="flow",
            status="useful_bridge",
            repair_behavior="保留",
            recommended_action="keep_flow_stable",
            prompt_title="Flow Keep Prompt",
            prompt_text=(
                "Do not prioritize large flow changes.\n"
                "The current additional flow-step logic already provides useful vulnerable-side bridge evidence.\n"
                "Keep the existing flow mostly stable and only make very small local adjustments if they improve target-adjacent connectivity."
            ),
            priority=3,
            include_in_prompt=True,
            target_predicate=None,
        ),
    },
}


def get_prompt_spec(role: str, effective_status: str) -> PromptSpec:
    try:
        return PROMPT_LIBRARY[role][effective_status]
    except KeyError as exc:
        raise KeyError(f"Unsupported prompt mapping for {role}:{effective_status}") from exc


def list_supported_statuses() -> dict[str, list[str]]:
    return {role: sorted(specs.keys()) for role, specs in PROMPT_LIBRARY.items()}
