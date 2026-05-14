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
    prompt_text_en: str
    prompt_text_zh: str
    target_predicate: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


PROMPT_LIBRARY: dict[str, dict[str, PromptSpec]] = {
    "source": {
        "compile_failed": PromptSpec(
            role="source",
            status="compile_failed",
            repair_behavior="替换 Source",
            recommended_action="replace_or_rebuild_source",
            prompt_title="Source Compile Failed Prompt",
            prompt_text_en=(
                "The current source component does not compile independently.\n"
                "Rebuild or simplify the source definition first, then keep only source logic that is clearly tied to target-adjacent entry points.\n"
                "Do not rewrite the whole query."
            ),
            prompt_text_zh=(
                "当前 source 组件无法独立编译。\n"
                "先重建或简化 source 定义，只保留与目标附近入口点明确相关的 source 逻辑。\n"
                "不要重写整个 query。"
            ),
            target_predicate="isSource",
        ),
        "missing_component": PromptSpec(
            role="source",
            status="missing_component",
            repair_behavior="扩张 Source",
            recommended_action="add_new_source_branch",
            prompt_title="Source Missing Prompt",
            prompt_text_en=(
                "The query does not define an effective source component.\n"
                "Add one new source condition that captures a target-adjacent entry point.\n"
                "Prefer parameters, request values, configuration values, or patch-adjacent inputs near target files and target methods.\n"
                "Keep the overall query structure stable."
            ),
            prompt_text_zh=(
                "当前 query 没有定义出有效的 source 组件。\n"
                "新增一个能覆盖目标附近入口点的 source 条件。\n"
                "优先考虑目标文件、目标方法或补丁附近的参数、请求值、配置值等输入。\n"
                "保持整体 query 结构稳定。"
            ),
            target_predicate="isSource",
        ),
        "empty": PromptSpec(
            role="source",
            status="empty",
            repair_behavior="扩张 Source",
            recommended_action="add_target_adjacent_source",
            prompt_title="Source Empty Prompt",
            prompt_text_en=(
                "The current source probe returns no matches on either vulnerable or fixed versions.\n"
                "Expand the source locally by adding one new source branch.\n"
                "Prefer entry points that are close to target files, target methods, or patch-related code.\n"
                "Do not rewrite the whole query."
            ),
            prompt_text_zh=(
                "当前 source probe 在漏洞版和修复版上都没有结果。\n"
                "在局部扩张 source，新增一个 source 分支。\n"
                "优先选择靠近目标文件、目标方法或补丁相关代码的入口点。\n"
                "不要重写整个 query。"
            ),
            target_predicate="isSource",
        ),
        "only_fixed": PromptSpec(
            role="source",
            status="only_fixed",
            repair_behavior="替换 Source",
            recommended_action="replace_reversed_source",
            prompt_title="Source Only Fixed Prompt",
            prompt_text_en=(
                "The current source modeling appears reversed because it only matches the fixed version.\n"
                "Replace the current source so that it captures vulnerable-side entry points instead of fixed-side-only inputs.\n"
                "Prefer target-adjacent source logic over broad utility-like sources.\n"
                "Do not rewrite the whole query."
            ),
            prompt_text_zh=(
                "当前 source 建模方向可能反了，因为它只命中了修复版。\n"
                "替换现有 source，使其捕获漏洞侧入口点，而不是只在修复侧出现的输入。\n"
                "优先使用贴近目标的 source 逻辑，而不是宽泛的通用型 source。\n"
                "不要重写整个 query。"
            ),
            target_predicate="isSource",
        ),
        "off_target": PromptSpec(
            role="source",
            status="off_target",
            repair_behavior="替换 Source",
            recommended_action="replace_off_target_source",
            prompt_title="Source Off Target Prompt",
            prompt_text_en=(
                "The source probe has matches, but it does not behave like a target-aligned vulnerable-side source.\n"
                "Treat this as off-target source modeling and replace the current source body first.\n"
                "Prefer replacing broad utility-like sources with target-adjacent entry points.\n"
                "Do not rewrite the whole query."
            ),
            prompt_text_zh=(
                "source probe 虽然有结果，但它不像是与目标对齐的漏洞侧 source。\n"
                "把它视为偏靶的 source 建模，优先替换当前 source 主体。\n"
                "优先用目标附近的入口点替换过宽、过通用的 source。\n"
                "不要重写整个 query。"
            ),
            target_predicate="isSource",
        ),
        "weak_but_present": PromptSpec(
            role="source",
            status="weak_but_present",
            repair_behavior="轻微收缩",
            recommended_action="lightly_narrow_source",
            prompt_title="Source Weak But Present Prompt",
            prompt_text_en=(
                "The source component has some evidence, but it is not discriminative enough to act as a stable anchor.\n"
                "Keep the current source shape if it is locally useful, but lightly narrow broad branches and remove obviously generic source conditions.\n"
                "Do not rewrite the whole query."
            ),
            prompt_text_zh=(
                "source 组件有一定证据，但区分性还不足以充当稳定锚点。\n"
                "如果当前 source 形态在局部仍有价值，可以保留，但应轻微收缩过宽分支，去掉明显泛化的 source 条件。\n"
                "不要重写整个 query。"
            ),
            target_predicate="isSource",
        ),
        "others": PromptSpec(
            role="source",
            status="others",
            repair_behavior="替换 Source",
            recommended_action="inspect_and_rebuild_source",
            prompt_title="Source Others Prompt",
            prompt_text_en=(
                "The source component falls into an uncategorized abnormal state.\n"
                "Inspect the existing source definition using the current component fields and either rebuild it or lightly narrow it, but do not expand scope without evidence from target-adjacent facts.\n"
                "Do not rewrite the whole query."
            ),
            prompt_text_zh=(
                "source 组件落入了未分类的异常状态。\n"
                "结合当前组件字段检查现有 source 定义，并选择重建或轻微收缩；如果没有目标附近事实支撑，不要盲目扩张范围。\n"
                "不要重写整个 query。"
            ),
            target_predicate="isSource",
        ),
    },
    "sink": {
        "compile_failed": PromptSpec(
            role="sink",
            status="compile_failed",
            repair_behavior="替换 Sink",
            recommended_action="replace_or_rebuild_sink",
            prompt_title="Sink Compile Failed Prompt",
            prompt_text_en=(
                "The current sink component does not compile independently.\n"
                "Rebuild or simplify the sink definition first, then keep only sink logic that is clearly tied to vulnerability-relevant dangerous operations.\n"
                "Do not rewrite the whole query."
            ),
            prompt_text_zh=(
                "当前 sink 组件无法独立编译。\n"
                "先重建或简化 sink 定义，只保留与漏洞相关危险操作明确相关的 sink 逻辑。\n"
                "不要重写整个 query。"
            ),
            target_predicate="isSink",
        ),
        "missing_component": PromptSpec(
            role="sink",
            status="missing_component",
            repair_behavior="扩张 Sink",
            recommended_action="add_new_sink_branch",
            prompt_title="Sink Missing Prompt",
            prompt_text_en=(
                "The query does not define an effective sink component.\n"
                "Add one new sink condition that captures a vulnerability-relevant dangerous operation near target files or target methods.\n"
                "Keep the overall query structure stable."
            ),
            prompt_text_zh=(
                "当前 query 没有定义出有效的 sink 组件。\n"
                "新增一个 sink 条件，用来捕获靠近目标文件或目标方法的漏洞相关危险操作。\n"
                "保持整体 query 结构稳定。"
            ),
            target_predicate="isSink",
        ),
        "empty": PromptSpec(
            role="sink",
            status="empty",
            repair_behavior="扩张 Sink",
            recommended_action="add_target_adjacent_sink",
            prompt_title="Sink Empty Prompt",
            prompt_text_en=(
                "The current sink probe returns no matches on either vulnerable or fixed versions.\n"
                "Expand the sink locally by adding one new sink branch that better reflects the dangerous operation in the patch context.\n"
                "Do not rewrite the whole query."
            ),
            prompt_text_zh=(
                "当前 sink probe 在漏洞版和修复版上都没有结果。\n"
                "在局部扩张 sink，新增一个更能反映补丁语境中危险操作的 sink 分支。\n"
                "不要重写整个 query。"
            ),
            target_predicate="isSink",
        ),
        "only_fixed": PromptSpec(
            role="sink",
            status="only_fixed",
            repair_behavior="替换 Sink",
            recommended_action="replace_reversed_sink",
            prompt_title="Sink Only Fixed Prompt",
            prompt_text_en=(
                "The current sink modeling appears reversed because it only matches the fixed version.\n"
                "Replace the sink so that it captures vulnerable-side dangerous operations rather than fixed-side-only behavior.\n"
                "Do not rewrite the whole query."
            ),
            prompt_text_zh=(
                "当前 sink 建模方向可能反了，因为它只命中了修复版。\n"
                "替换现有 sink，使其捕获漏洞侧危险操作，而不是只出现在修复侧的行为。\n"
                "不要重写整个 query。"
            ),
            target_predicate="isSink",
        ),
        "off_target": PromptSpec(
            role="sink",
            status="off_target",
            repair_behavior="替换 Sink",
            recommended_action="replace_off_target_sink",
            prompt_title="Sink Off Target Prompt",
            prompt_text_en=(
                "The sink probe has matches, but it does not behave like a target-aligned dangerous operation.\n"
                "Treat this as off-target sink modeling and replace the current sink body first.\n"
                "Prefer replacing broad sink logic with target-adjacent dangerous operations.\n"
                "Do not rewrite the whole query."
            ),
            prompt_text_zh=(
                "sink probe 虽然有结果，但它不像是与目标对齐的危险操作。\n"
                "把它视为偏靶的 sink 建模，优先替换当前 sink 主体。\n"
                "优先用目标附近的危险操作替换过宽的 sink 逻辑。\n"
                "不要重写整个 query。"
            ),
            target_predicate="isSink",
        ),
        "weak_but_present": PromptSpec(
            role="sink",
            status="weak_but_present",
            repair_behavior="轻微收缩",
            recommended_action="lightly_narrow_sink",
            prompt_title="Sink Weak But Present Prompt",
            prompt_text_en=(
                "The sink component has some evidence, but it is not discriminative enough to act as a stable anchor.\n"
                "Keep the current sink shape if it is locally useful, but lightly narrow broad branches and remove obviously generic sink conditions.\n"
                "Do not rewrite the whole query."
            ),
            prompt_text_zh=(
                "sink 组件有一定证据，但区分性还不足以充当稳定锚点。\n"
                "如果当前 sink 形态在局部仍有价值，可以保留，但应轻微收缩过宽分支，去掉明显泛化的 sink 条件。\n"
                "不要重写整个 query。"
            ),
            target_predicate="isSink",
        ),
        "others": PromptSpec(
            role="sink",
            status="others",
            repair_behavior="替换 Sink",
            recommended_action="inspect_and_rebuild_sink",
            prompt_title="Sink Others Prompt",
            prompt_text_en=(
                "The sink component falls into an uncategorized abnormal state.\n"
                "Inspect the existing sink definition using the current component fields and either rebuild it or lightly narrow it, but do not expand scope without evidence from target-adjacent facts.\n"
                "Do not rewrite the whole query."
            ),
            prompt_text_zh=(
                "sink 组件落入了未分类的异常状态。\n"
                "结合当前组件字段检查现有 sink 定义，并选择重建或轻微收缩；如果没有目标附近事实支撑，不要盲目扩张范围。\n"
                "不要重写整个 query。"
            ),
            target_predicate="isSink",
        ),
    },
    "barrier": {
        "compile_failed": PromptSpec(
            role="barrier",
            status="compile_failed",
            repair_behavior="替换或重建 Barrier",
            recommended_action="replace_or_rebuild_barrier",
            prompt_title="Barrier Compile Failed Prompt",
            prompt_text_en=(
                "The current barrier component does not compile independently.\n"
                "Rebuild or simplify the barrier definition first, then decide whether it should preserve repair-side validation logic or be narrowed."
            ),
            prompt_text_zh=(
                "当前 barrier 组件无法独立编译。\n"
                "先重建或简化 barrier 定义，再判断它应保留修复侧校验逻辑，还是应进一步收窄。"
            ),
            target_predicate="isBarrier",
        ),
        "overblocking_suspect": PromptSpec(
            role="barrier",
            status="overblocking_suspect",
            repair_behavior="弱化 Barrier",
            recommended_action="narrow_or_replace_barrier",
            prompt_title="Barrier Overblocking Prompt",
            prompt_text_en=(
                "The barrier may be too broad and may suppress vulnerable paths that should remain reachable.\n"
                "Weaken the barrier locally by adding stronger guards or replacing generic barrier conditions with more specific fixed-side validation logic.\n"
                "Do not remove all barrier logic unless it is clearly unsupported."
            ),
            prompt_text_zh=(
                "当前 barrier 可能过宽，压制了本应可达的漏洞路径。\n"
                "通过增加更强的约束，或用更具体的修复侧校验逻辑替换泛化 barrier 条件，来局部弱化 barrier。\n"
                "除非明显没有依据，否则不要直接移除全部 barrier 逻辑。"
            ),
            target_predicate="isBarrier",
        ),
        "non_discriminative": PromptSpec(
            role="barrier",
            status="non_discriminative",
            repair_behavior="专化 Barrier 到修复逻辑",
            recommended_action="specialize_or_lightly_narrow_barrier",
            prompt_title="Barrier Non Discriminative Prompt",
            prompt_text_en=(
                "The barrier matches both vulnerable and fixed versions with weak discrimination.\n"
                "Do not treat it as a main detection signal.\n"
                "Try to specialize the barrier toward fixed-side validation or sanitization logic; if that is not possible, gently narrow generic barrier conditions."
            ),
            prompt_text_zh=(
                "当前 barrier 在漏洞版和修复版都命中，区分性较弱。\n"
                "不要把它当作主要检测信号。\n"
                "优先把 barrier 专化到修复侧校验或净化逻辑；如果做不到，再轻微收窄泛化的 barrier 条件。"
            ),
            target_predicate="isBarrier",
        ),
        "others": PromptSpec(
            role="barrier",
            status="others",
            repair_behavior="专化 Barrier 到修复逻辑",
            recommended_action="inspect_and_adjust_barrier",
            prompt_title="Barrier Others Prompt",
            prompt_text_en=(
                "The barrier component falls into an uncategorized abnormal state.\n"
                "Inspect whether the current barrier is tied to fixed-side validation or is broadly suppressing paths; then either specialize it toward repair logic or lightly narrow it."
            ),
            prompt_text_zh=(
                "barrier 组件落入了未分类的异常状态。\n"
                "检查当前 barrier 是真正绑定在修复侧校验上，还是在宽泛地压制路径；随后选择把它专化到修复逻辑，或进行轻微收窄。"
            ),
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
            prompt_text_en=(
                "The query has no effective additional flow-step modeling.\n"
                "Add one new propagation step that helps connect the current source region to the current sink region.\n"
                "Prefer target-adjacent propagation edges over generic utility flows.\n"
                "Do not rewrite the whole query."
            ),
            prompt_text_zh=(
                "当前 query 没有有效的 additional flow-step 建模。\n"
                "新增一个传播步骤，帮助连接当前 source 区域和 sink 区域。\n"
                "优先使用目标附近的传播边，而不是泛化的通用流。\n"
                "不要重写整个 query。"
            ),
            target_predicate="isAdditionalFlowStep",
        ),
        "empty": PromptSpec(
            role="flow",
            status="empty",
            repair_behavior="补桥",
            recommended_action="add_new_flow_bridge",
            prompt_title="Flow Empty Prompt",
            prompt_text_en=(
                "The flow probe returns no bridge facts on either vulnerable or fixed versions.\n"
                "Add one new local propagation step inside isAdditionalFlowStep or a closely related helper predicate.\n"
                "Prefer propagation edges that appear near target files, target methods, or patch-relevant helper calls.\n"
                "Do not rewrite the whole query."
            ),
            prompt_text_zh=(
                "当前 flow probe 在漏洞版和修复版上都没有桥接事实。\n"
                "在 `isAdditionalFlowStep` 或紧邻的辅助谓词中新增一个局部传播步骤。\n"
                "优先考虑出现在目标文件、目标方法或补丁相关辅助调用附近的传播边。\n"
                "不要重写整个 query。"
            ),
            target_predicate="isAdditionalFlowStep",
        ),
        "compile_failed": PromptSpec(
            role="flow",
            status="compile_failed",
            repair_behavior="替换或重建 Flow",
            recommended_action="replace_or_rebuild_flow",
            prompt_title="Flow Compile Failed Prompt",
            prompt_text_en=(
                "The additional flow-step logic does not compile independently.\n"
                "First rebuild or simplify the current flow predicate structure, then keep only the most target-relevant propagation edges.\n"
                "Do not rewrite the whole query."
            ),
            prompt_text_zh=(
                "当前 additional flow-step 逻辑无法独立编译。\n"
                "先重建或简化 flow 谓词结构，再只保留与目标最相关的传播边。\n"
                "不要重写整个 query。"
            ),
            target_predicate="isAdditionalFlowStep",
        ),
        "noisy_bridge": PromptSpec(
            role="flow",
            status="noisy_bridge",
            repair_behavior="降噪",
            recommended_action="narrow_existing_flow",
            prompt_title="Flow Noisy Bridge Prompt",
            prompt_text_en=(
                "The current additional flow-step logic produces many shared edges on both vulnerable and fixed versions.\n"
                "Treat this as noisy bridge modeling.\n"
                "Narrow the flow by adding stronger type, receiver, method-name, or argument-position constraints, and keep only target-adjacent propagation edges.\n"
                "Do not rewrite the whole query."
            ),
            prompt_text_zh=(
                "当前 additional flow-step 在漏洞版和修复版上都产生了大量共享边。\n"
                "把它视为带噪声的桥接建模。\n"
                "通过增加更强的类型、接收者、方法名或参数位置约束来收窄 flow，只保留目标附近的传播边。\n"
                "不要重写整个 query。"
            ),
            target_predicate="isAdditionalFlowStep",
        ),
        "weak_bridge": PromptSpec(
            role="flow",
            status="weak_bridge",
            repair_behavior="降噪",
            recommended_action="narrow_then_add_flow_if_needed",
            prompt_title="Flow Weak Bridge Prompt",
            prompt_text_en=(
                "Some bridge evidence exists, but it is not yet specific enough to explain the intended vulnerability path.\n"
                "First try to denoise existing flow edges; if needed, add one new target-adjacent propagation step.\n"
                "Do not rewrite the whole query."
            ),
            prompt_text_zh=(
                "当前已经有一些桥接证据，但还不足以明确解释目标漏洞路径。\n"
                "先尝试对现有 flow 边降噪；如果仍然不够，再新增一个目标附近的传播步骤。\n"
                "不要重写整个 query。"
            ),
            target_predicate="isAdditionalFlowStep",
        ),
        "others": PromptSpec(
            role="flow",
            status="others",
            repair_behavior="降噪",
            recommended_action="inspect_and_adjust_flow",
            prompt_title="Flow Others Prompt",
            prompt_text_en=(
                "The flow component falls into an uncategorized abnormal state.\n"
                "Inspect whether the current additional flow-step logic is too broad or too weak, then either denoise it or add one small target-adjacent bridge if justified by the component facts.\n"
                "Do not rewrite the whole query."
            ),
            prompt_text_zh=(
                "flow 组件落入了未分类的异常状态。\n"
                "检查当前 additional flow-step 逻辑是过宽还是过弱，然后根据组件事实选择降噪，或补充一个小范围、目标附近的桥接步骤。\n"
                "不要重写整个 query。"
            ),
            target_predicate="isAdditionalFlowStep",
        ),
    },
}


def get_prompt_spec(role: str, status: str) -> PromptSpec:
    try:
        return PROMPT_LIBRARY[role][status]
    except KeyError as exc:
        raise KeyError(f"Unsupported prompt mapping for {role}:{status}") from exc


def list_supported_statuses() -> dict[str, list[str]]:
    return {role: sorted(specs.keys()) for role, specs in PROMPT_LIBRARY.items()}