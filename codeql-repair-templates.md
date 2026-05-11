# CodeQL Query Repair Prompts

## 目标

本文档定义一套面向 CodeQL query 修复的提示词驱动方案，参考 `RuleRefiner` 与
`Fact-Aligned and Template-Constrained` 的核心思想：

- 先通过 `source/sink/barrier/flow probe` 收集组件级事实
- 再把这些事实转成组件级问题描述
- 最后对每个组件生成局部、受约束的修复提示词与行为建议

这里的重点不是“自动重写整份 query”，而是：

- 保持 query 的整体结构稳定
- 只在局部组件内给出修复建议
- 让 LLM 或后续自动化修复器在有限编辑空间里工作

## 总体原则

- 尽量保留 query metadata、`import`、配置模块名、flow module 名、最终 `select` 结构
- 优先局部修改：
  - `source` 只改 source 类或 `isSource(...)`
  - `sink` 只改 sink 类或 `isSink(...)`
  - `barrier` 只改 `isBarrier(...)` / `isSanitizer(...)`
  - `flow` 只改 `isAdditionalFlowStep(...)`
- 不要在没有证据时同时大改多个组件
- 每个组件只允许少数几种修复行为：
  - 扩张
  - 收缩
  - 替换
  - 保留
- 输入是完整 query 和 probe 评估结果；输出是修复建议、事实依据和专用 prompt，而不是自动生成的新 query

## 输入与输出

输入：

- 完整 query 文件
- `probe_evaluation.json`

输出：

- 每个组件的修复建议：`repair_behavior` + `recommended_action`
- 每个组件的事实依据：`supporting_facts`
- 每个组件的专用修复 prompt
- 多组件组合后的整体修复建议

说明：

- 本方案不直接产出“自动改写后的 query 代码”
- 评估结果到修复行为的映射继续保留
- `codeql-repair-templates.md` 中关于组件语义和行为边界的描述继续保留
- agent 依据建议去修改 query，本方案负责“诊断 + 建议 + prompt”

## 从 Probe 评估结果直接选择修复行为

为了让后续系统可以从 `probe_evaluation` 的结果直接得到修复建议，行为选择规则必须严格对齐
`probe-evaluation-design.md` 里的 `verdict.status` 和 `problem_components`。

这里采用的原则是：

- 先读取顶层 `problem_components`
- 对于每个 `problem_components[i].role`，回到 `components[role]` 读取该组件完整字段内容
- 只依据这个组件自己的 `verdict.status` 和已有评估字段，选择修复行为与专用 prompt
- 不再额外构造 `localization`、`primary suspect`、`failure_pattern` 之类中间字段

也就是说，推荐的处理路径是：

- `problem_components` 决定“哪些组件值得进入后续修复建议”
- `components[role]` 决定“这个组件当前是什么状态、有哪些事实依据”
- `verdict.status` 决定“应该给什么修复行为和什么 prompt”

这样后续 prompt 就能直接拼成：

- source 问题描述 + source 修复行为 + source prompt
- sink 问题描述 + sink 修复行为 + sink prompt
- barrier 问题描述 + barrier 修复行为 + barrier prompt
- flow 问题描述 + flow 修复行为 + flow prompt

## 组件级映射规则

这一节的主映射只保留会进入 `problem_components` 的问题状态，也就是后续会真正转成修复建议的状态。

### Source 映射

- `missing_component`
  - 主行为：`扩张 Source`
  - 推荐动作：`add_new_source_branch`
  - 说明：query 根本没建立 source，需要新增 source 入口
- `compile_failed`
  - 主行为：`替换 Source`
  - 推荐动作：`replace_or_rebuild_source`
  - 说明：source 结构本身不稳定，应优先重建原 source 定义
- `empty`
  - 主行为：`扩张 Source`
  - 推荐动作：`add_target_adjacent_source`
  - 说明：source 没有任何结果，优先补充 target-adjacent source
- `only_fixed`
  - 主行为：`替换 Source`
  - 推荐动作：`replace_reversed_source`
  - 说明：source 建模方向反了，应直接替换掉错误入口
- `off_target`
  - 主行为：`替换 Source`
  - 推荐动作：`replace_off_target_source`
  - 说明：有结果但不贴近目标文件或目标方法，应直接替换原 source 主体
- `weak_but_present`
  - 主行为：`轻微收缩`
  - 次行为：`保留`
  - 推荐动作：`lightly_narrow_source`
  - 说明：source 有部分有效性，但区分性不足，不应当成稳定锚点
- `others`
  - 主行为：`替换 Source`
  - 次行为：`轻微收缩`
  - 推荐动作：`inspect_and_rebuild_source`
  - 说明：这是 source 的兜底异常状态，应先检查现有 source 是否仍有保留价值

### Sink 映射

- `missing_component`
  - 主行为：`扩张 Sink`
  - 推荐动作：`add_new_sink_branch`
- `compile_failed`
  - 主行为：`替换 Sink`
  - 推荐动作：`replace_or_rebuild_sink`
- `empty`
  - 主行为：`扩张 Sink`
  - 推荐动作：`add_target_adjacent_sink`
- `only_fixed`
  - 主行为：`替换 Sink`
  - 推荐动作：`replace_reversed_sink`
- `off_target`
  - 主行为：`替换 Sink`
  - 推荐动作：`replace_off_target_sink`
  - 说明：sink 有结果但不贴近目标危险操作，应直接替换原 sink 主体
- `weak_but_present`
  - 主行为：`轻微收缩`
  - 次行为：`保留`
  - 推荐动作：`lightly_narrow_sink`
  - 说明：sink 有部分有效性，但区分性不足，不应当成稳定锚点
- `others`
  - 主行为：`替换 Sink`
  - 次行为：`轻微收缩`
  - 推荐动作：`inspect_and_rebuild_sink`
  - 说明：这是 sink 的兜底异常状态，应先检查现有 sink 是否仍有保留价值

### Barrier 映射

- `overblocking_suspect`
  - 主行为：`弱化 Barrier`
  - 推荐动作：`narrow_or_replace_barrier`
  - 说明：barrier 可能正在压掉漏洞路径，应优先收紧
- `non_discriminative`
  - 主行为：`专化 Barrier 到修复逻辑`
  - 次行为：`弱化 Barrier`
  - 推荐动作：`specialize_or_lightly_narrow_barrier`
  - 说明：如果 barrier 只是 shared filter，就应把它往 fixed-side 修复逻辑上专化；若专化无从下手，再考虑弱化
- `compile_failed`
  - 主行为：`替换或重建 Barrier`
  - 推荐动作：`replace_or_rebuild_barrier`
  - 说明：barrier 自身结构不稳定，应先修结构再判断语义
- `others`
  - 主行为：`专化 Barrier 到修复逻辑`
  - 次行为：`弱化 Barrier`
  - 推荐动作：`inspect_and_adjust_barrier`
  - 说明：这是 barrier 的兜底异常状态，应围绕修复侧校验逻辑人工判定去留

### Flow 映射

- `missing_component`
  - 主行为：`补桥`
  - 推荐动作：`add_new_flow_bridge`
- `compile_failed`
  - 主行为：`替换或重建 Flow`
  - 次行为：`补桥`
  - 推荐动作：`replace_or_rebuild_flow`
  - 说明：flow 结构本身不稳定，先修结构，再补语义
- `empty`
  - 主行为：`补桥`
  - 推荐动作：`add_new_flow_bridge`
  - 说明：source/sink 已存在但没有 bridge facts
- `noisy_bridge`
  - 主行为：`降噪`
  - 推荐动作：`narrow_existing_flow`
  - 说明：flow 太泛，需要加 guard
- `weak_bridge`
  - 主行为：`降噪`
  - 次行为：`补桥`
  - 推荐动作：`narrow_then_add_flow_if_needed`
  - 说明：先看是否因为太宽导致弱信号；若不是，再考虑增加 target-adjacent bridge
- `others`
  - 主行为：`降噪`
  - 次行为：`补桥`
  - 推荐动作：`inspect_and_adjust_flow`
  - 说明：这是 flow 的兜底异常状态，应先检查现有传播边是否仍有解释力

## 非问题状态说明

下面这些状态不会进入 `problem_components`，因此不会进入后续修复建议和专用 prompt 的主路径：

- `source.good_anchor`
  - 表示 source 已经是较好的漏洞侧锚点，应默认保持稳定。
- `sink.good_anchor`
  - 表示 sink 已经是较好的危险点锚点，应默认保持稳定。
- `barrier.absent`
  - 表示 barrier 当前没有形成有效信号；按现有 `problem_components` 规则，它不直接进入自动修复主路径。
- `barrier.repair_only`
  - 表示 barrier 只在修复侧出现，这是正向修复侧信号，应默认保留。
- `barrier.useful_repair_signal`
  - 表示 barrier 在修复侧更强，这是正向修复侧信号，应默认保留。
- `flow.useful_bridge`
  - 表示 flow 已经提供有用的漏洞侧桥接证据，应默认保持稳定。
- `flow.likely_not_needed`
  - 表示当前 query 不需要把 flow 当成主要修复方向，应默认不动。

## 推荐的自动修复建议输出

后续系统应先从 `problem_components` 读取需要处理的组件，再回到 `components[role]` 读取完整字段内容，最后生成一个简单的“修复建议结果”，例如：

```text
source:
- status: off_target
- selected_behavior: 替换 Source
- recommended_action: replace_off_target_source

sink:
- status: off_target
- selected_behavior: 替换 Sink
- recommended_action: replace_off_target_sink

barrier:
- status: non_discriminative
- selected_behavior: 专化 Barrier 到修复逻辑
- recommended_action: specialize_or_lightly_narrow_barrier

flow:
- status: noisy_bridge
- selected_behavior: 降噪
- recommended_action: narrow_existing_flow
```

然后 prompt builder 再把这些组件建议组合起来。

## 从 Probe 评估结果直接选择专用提示词

除了行为选择之外，每个进入 `problem_components` 的组件还应对应一套专用提示词。

原因是：

- 修复行为只说明“建议怎么改”
- 提示词还需要说明“为什么改、重点改哪里、不要改什么”

因此，一个完整的组件级修复块应当包含四部分：

- `Problem`
  - 从 probe 评估结果中总结出来的问题描述
- `Repair Behavior`
  - 当前状态对应的修复行为名称
- `Supporting Facts`
  - 来自 probe 评估结果的事实依据
- `Repair Prompt`
  - 面向 LLM 的专用提示词

推荐的统一骨架如下：

```text
[Component]
<source|sink|barrier|flow>

[Status]
<verdict.status>

[Problem]
<summary generated from probe evaluation>

[Repair Behavior]
<selected behavior name>

[Supporting Facts]
<来自 components[role] 的已有字段，如 vuln/fixed counts、aligned files/methods、coverage>

[Repair Prompt]
Focus this prompt on <component-specific scope>.
<component-specific guidance from the current status>.
Do not rewrite the whole query.
If other problem components are also selected, coordinate those edits separately, but keep this prompt focused on the current component.
```

## 组件状态到专用提示词的映射

这一节只保留会进入 `problem_components` 的状态，也就是后续会真正参与修复 prompt 构建的问题状态。

### Source 专用提示词

- `compile_failed`

```text
The current source component does not compile independently.
Rebuild or simplify the source definition first, then keep only source logic that is clearly tied to target-adjacent entry points.
Do not rewrite the whole query. If other problem components are also selected, coordinate those edits separately, but keep this prompt focused on source.
```

中文版本：

```text
当前 source 组件无法独立编译。
先重建或简化 source 定义，只保留那些与目标附近入口点明确相关的 source 逻辑。
不要重写整份 query。如果还有其他问题组件也被选中，可以协同修改它们，但本条提示词应聚焦于 source。
```

- `missing_component`

```text
The query does not define an effective source component.
Add one new source condition that captures a target-adjacent entry point.
Prefer parameters, request values, configuration values, or patch-adjacent inputs near target files and target methods.
Keep the overall query structure stable. If other problem components are also selected, coordinate those edits separately, but keep this prompt focused on source.
```

中文版本：

```text
当前 query 没有定义有效的 source 组件。
新增一个 source 条件，用来捕获靠近目标位置的入口点。
优先考虑靠近目标文件、目标方法或补丁相关代码的参数、请求值、配置值等输入。
保持 query 的整体结构稳定。如果还有其他问题组件也被选中，可以协同修改它们，但本条提示词应聚焦于 source。
```

- `empty`

```text
The current source probe returns no matches on either vulnerable or fixed versions.
Expand the source locally by adding one new source branch.
Prefer entry points that are close to target files, target methods, or patch-related code.
Do not rewrite the whole query. If other problem components are also selected, coordinate those edits separately, but keep this prompt focused on source.
```

中文版本：

```text
当前 source probe 在漏洞版本和修复版本上都没有结果。
通过新增一个 source 分支，在局部扩张 source。
优先选择靠近目标文件、目标方法或补丁相关代码的入口点。
不要重写整份 query。如果还有其他问题组件也被选中，可以协同修改它们，但本条提示词应聚焦于 source。
```

- `only_fixed`

```text
The current source modeling appears reversed because it only matches the fixed version.
Replace the current source so that it captures vulnerable-side entry points instead of fixed-side-only inputs.
Prefer target-adjacent source logic over broad utility-like sources.
Do not rewrite the whole query. If other problem components are also selected, coordinate those edits separately, but keep this prompt focused on source.
```

中文版本：

```text
当前 source 建模方向反了，因为它只命中了修复版本。
替换当前 source，使它捕获漏洞侧入口，而不是只在修复侧出现的输入。
优先使用贴近目标位置的 source 逻辑，而不是宽泛的通用型 source。
不要重写整份 query。如果还有其他问题组件也被选中，可以协同修改它们，但本条提示词应聚焦于 source。
```

- `off_target`

```text
The source probe has matches, but it does not behave like a target-aligned vulnerable-side source.
Treat this as off-target source modeling and replace the current source body first.
Prefer replacing broad utility-like sources with target-adjacent entry points.
Do not rewrite the whole query. If other problem components are also selected, coordinate those edits separately, but keep this prompt focused on source.
```

中文版本：

```text
当前 source probe 虽然有结果，但它并不像一个与目标对齐的漏洞侧 source。
把这种情况视为 source 偏靶建模，优先替换当前 source 主体。
优先用贴近目标位置的入口点替换宽泛的通用型 source。
不要重写整份 query。如果还有其他问题组件也被选中，可以协同修改它们，但本条提示词应聚焦于 source。
```

- `weak_but_present`

```text
The source component has some evidence, but it is not discriminative enough to act as a stable anchor.
Keep the current source shape if it is locally useful, but lightly narrow broad branches and remove obviously generic source conditions.
Do not rewrite the whole query. If other problem components are also selected, coordinate those edits separately, but keep this prompt focused on source.
```

中文版本：

```text
当前 source 组件有一定证据，但区分性不足，不能作为稳定锚点。
如果当前 source 形态在局部仍然有用，可以暂时保留；但应轻微收缩过宽的分支，并去掉明显过于泛化的 source 条件。
不要重写整份 query。如果还有其他问题组件也被选中，可以协同修改它们，但本条提示词应聚焦于 source。
```

- `others`

```text
The source component falls into an uncategorized abnormal state.
Inspect the existing source definition using the current component fields and either rebuild it or lightly narrow it, but do not expand scope without evidence from target-adjacent facts.
Do not rewrite the whole query. If other problem components are also selected, coordinate those edits separately, but keep this prompt focused on source.
```

中文版本：

```text
当前 source 组件落入未分类的异常状态。
结合当前组件字段检查现有 source 定义，并决定是重建它还是轻微收缩它；如果没有目标附近事实支撑，不要盲目扩张范围。
不要重写整份 query。如果还有其他问题组件也被选中，可以协同修改它们，但本条提示词应聚焦于 source。
```

### Sink 专用提示词

- `compile_failed`

```text
The current sink component does not compile independently.
Rebuild or simplify the sink definition first, then keep only sink logic that is clearly tied to vulnerability-relevant dangerous operations.
Do not rewrite the whole query. If other problem components are also selected, coordinate those edits separately, but keep this prompt focused on sink.
```

中文版本：

```text
当前 sink 组件无法独立编译。
先重建或简化 sink 定义，只保留那些与漏洞相关危险操作明确相关的 sink 逻辑。
不要重写整份 query。如果还有其他问题组件也被选中，可以协同修改它们，但本条提示词应聚焦于 sink。
```

- `missing_component`

```text
The query does not define an effective sink component.
Add one new sink condition that captures a vulnerability-relevant dangerous operation near target files or target methods.
Keep the overall query structure stable. If other problem components are also selected, coordinate those edits separately, but keep this prompt focused on sink.
```

中文版本：

```text
当前 query 没有定义有效的 sink 组件。
新增一个 sink 条件，用来捕获靠近目标文件或目标方法的漏洞相关危险操作。
保持 query 的整体结构稳定。如果还有其他问题组件也被选中，可以协同修改它们，但本条提示词应聚焦于 sink。
```

- `empty`

```text
The current sink probe returns no matches on either vulnerable or fixed versions.
Expand the sink locally by adding one new sink branch that better reflects the dangerous operation in the patch context.
Do not rewrite the whole query. If other problem components are also selected, coordinate those edits separately, but keep this prompt focused on sink.
```

中文版本：

```text
当前 sink probe 在漏洞版本和修复版本上都没有结果。
通过新增一个 sink 分支，在局部扩张 sink，使其更贴近补丁语境中的危险操作。
不要重写整份 query。如果还有其他问题组件也被选中，可以协同修改它们，但本条提示词应聚焦于 sink。
```

- `only_fixed`

```text
The current sink modeling appears reversed because it only matches the fixed version.
Replace the sink so that it captures vulnerable-side dangerous operations rather than fixed-side-only behavior.
Do not rewrite the whole query. If other problem components are also selected, coordinate those edits separately, but keep this prompt focused on sink.
```

中文版本：

```text
当前 sink 建模方向反了，因为它只命中了修复版本。
替换当前 sink，使它捕获漏洞侧危险操作，而不是只在修复侧出现的行为。
不要重写整份 query。如果还有其他问题组件也被选中，可以协同修改它们，但本条提示词应聚焦于 sink。
```

- `off_target`

```text
The sink probe has matches, but it does not behave like a target-aligned dangerous operation.
Treat this as off-target sink modeling and replace the current sink body first.
Prefer replacing broad sink logic with target-adjacent dangerous operations.
Do not rewrite the whole query. If other problem components are also selected, coordinate those edits separately, but keep this prompt focused on sink.
```

中文版本：

```text
当前 sink probe 虽然有结果，但它并不像一个与目标对齐的危险操作。
把这种情况视为 sink 偏靶建模，优先替换当前 sink 主体。
优先用贴近目标位置的危险操作替换宽泛的 sink 逻辑。
不要重写整份 query。如果还有其他问题组件也被选中，可以协同修改它们，但本条提示词应聚焦于 sink。
```

- `weak_but_present`

```text
The sink component has some evidence, but it is not discriminative enough to act as a stable anchor.
Keep the current sink shape if it is locally useful, but lightly narrow broad branches and remove obviously generic sink conditions.
Do not rewrite the whole query. If other problem components are also selected, coordinate those edits separately, but keep this prompt focused on sink.
```

中文版本：

```text
当前 sink 组件有一定证据，但区分性不足，不能作为稳定锚点。
如果当前 sink 形态在局部仍然有用，可以暂时保留；但应轻微收缩过宽的分支，并去掉明显过于泛化的 sink 条件。
不要重写整份 query。如果还有其他问题组件也被选中，可以协同修改它们，但本条提示词应聚焦于 sink。
```

- `others`

```text
The sink component falls into an uncategorized abnormal state.
Inspect the existing sink definition using the current component fields and either rebuild it or lightly narrow it, but do not expand scope without evidence from target-adjacent facts.
Do not rewrite the whole query. If other problem components are also selected, coordinate those edits separately, but keep this prompt focused on sink.
```

中文版本：

```text
当前 sink 组件落入未分类的异常状态。
结合当前组件字段检查现有 sink 定义，并决定是重建它还是轻微收缩它；如果没有目标附近事实支撑，不要盲目扩张范围。
不要重写整份 query。如果还有其他问题组件也被选中，可以协同修改它们，但本条提示词应聚焦于 sink。
```

### Barrier 专用提示词

- `compile_failed`

```text
The current barrier component does not compile independently.
Rebuild or simplify the barrier definition first, then decide whether it should preserve repair-side validation logic or be narrowed.
If other problem components are also selected, coordinate those edits separately, but keep this prompt focused on barrier.
```

中文版本：

```text
当前 barrier 组件无法独立编译。
先重建或简化 barrier 定义，然后再判断它应当保留修复侧校验逻辑，还是需要收缩。
如果还有其他问题组件也被选中，可以协同修改它们，但本条提示词应聚焦于 barrier。
```

- `overblocking_suspect`

```text
The barrier may be too broad and may suppress vulnerable paths that should remain reachable.
Weaken the barrier locally by adding stronger guards or replacing generic barrier conditions with more specific fixed-side validation logic.
Do not remove all barrier logic unless it is clearly unsupported.
If other problem components are also selected, coordinate those edits separately, but keep this prompt focused on barrier.
```

中文版本：

```text
当前 barrier 可能过宽，并且可能压掉了本应保持可达的漏洞路径。
通过增加更强的守卫条件，或用更具体的修复侧校验逻辑替换泛化的 barrier 条件，来局部弱化 barrier。
除非有明确证据，否则不要删除全部 barrier 逻辑。
如果还有其他问题组件也被选中，可以协同修改它们，但本条提示词应聚焦于 barrier。
```

- `non_discriminative`

```text
The barrier matches both vulnerable and fixed versions with weak discrimination.
Do not treat it as a main detection signal.
Try to specialize the barrier toward fixed-side validation or sanitization logic; if that is not possible, gently narrow generic barrier conditions.
If other problem components are also selected, coordinate those edits separately, but keep this prompt focused on barrier.
```

中文版本：

```text
当前 barrier 在漏洞版本和修复版本上都命中了，但区分性较弱。
不要把它当成主要检测信号。
尝试把 barrier 专化到修复侧的校验或净化逻辑；如果做不到，再轻微收缩泛化的 barrier 条件。
如果还有其他问题组件也被选中，可以协同修改它们，但本条提示词应聚焦于 barrier。
```

- `others`

```text
The barrier component falls into an uncategorized abnormal state.
Inspect whether the current barrier is tied to fixed-side validation or is broadly suppressing paths; then either specialize it toward repair logic or lightly narrow it.
If other problem components are also selected, coordinate those edits separately, but keep this prompt focused on barrier.
```

中文版本：

```text
当前 barrier 组件落入未分类的异常状态。
检查现有 barrier 是不是与修复侧校验逻辑相关，还是在宽泛地压制路径；然后决定是把它专化到修复逻辑，还是轻微收缩它。
如果还有其他问题组件也被选中，可以协同修改它们，但本条提示词应聚焦于 barrier。
```

### Flow 专用提示词

- `missing_component`

```text
The query has no effective additional flow-step modeling.
Add one new propagation step that helps connect the current source region to the current sink region.
Prefer target-adjacent propagation edges over generic utility flows.
Do not rewrite the whole query. If other problem components are also selected, coordinate those edits separately, but keep this prompt focused on flow.
```

中文版本：

```text
当前 query 没有有效的 additional flow-step 建模。
新增一个传播步骤，用来连接当前 source 区域和当前 sink 区域。
优先选择贴近目标位置的传播边，而不是泛化的通用传播流。
不要重写整份 query。如果还有其他问题组件也被选中，可以协同修改它们，但本条提示词应聚焦于 flow。
```

- `empty`

```text
The flow probe returns no bridge facts on either vulnerable or fixed versions.
Add one new local propagation step inside isAdditionalFlowStep or a closely related helper predicate.
Prefer propagation edges that appear near target files, target methods, or patch-relevant helper calls.
Do not rewrite the whole query. If other problem components are also selected, coordinate those edits separately, but keep this prompt focused on flow.
```

中文版本：

```text
当前 flow probe 在漏洞版本和修复版本上都没有桥接事实。
在 `isAdditionalFlowStep` 或与之紧密相关的 helper predicate 中新增一个局部传播步骤。
优先选择靠近目标文件、目标方法或补丁相关 helper 调用的传播边。
不要重写整份 query。如果还有其他问题组件也被选中，可以协同修改它们，但本条提示词应聚焦于 flow。
```

- `compile_failed`

```text
The additional flow-step logic does not compile independently.
First rebuild or simplify the current flow predicate structure, then keep only the most target-relevant propagation edges.
Do not rewrite the whole query. If other problem components are also selected, coordinate those edits separately, but keep this prompt focused on flow.
```

中文版本：

```text
当前 additional flow-step 逻辑无法独立编译。
先重建或简化当前 flow predicate 结构，只保留那些与目标最相关的传播边。
不要重写整份 query。如果还有其他问题组件也被选中，可以协同修改它们，但本条提示词应聚焦于 flow。
```

- `noisy_bridge`

```text
The current additional flow-step logic produces many shared edges on both vulnerable and fixed versions.
Treat this as noisy bridge modeling.
Narrow the flow by adding stronger type, receiver, method-name, or argument-position constraints, and keep only target-adjacent propagation edges.
Do not rewrite the whole query. If other problem components are also selected, coordinate those edits separately, but keep this prompt focused on flow.
```

中文版本：

```text
当前 additional flow-step 逻辑在漏洞版本和修复版本上都产生了大量共享传播边。
把这种情况视为噪声较大的 bridge 建模。
通过增加更强的类型、接收者、方法名或参数位置约束来收缩 flow，只保留贴近目标位置的传播边。
不要重写整份 query。如果还有其他问题组件也被选中，可以协同修改它们，但本条提示词应聚焦于 flow。
```

- `weak_bridge`

```text
Some bridge evidence exists, but it is not yet specific enough to explain the intended vulnerability path.
First try to denoise existing flow edges; if needed, add one new target-adjacent propagation step.
Do not rewrite the whole query. If other problem components are also selected, coordinate those edits separately, but keep this prompt focused on flow.
```

中文版本：

```text
当前已经有一些 bridge 证据，但还不够具体，无法解释目标漏洞路径。
先尝试给现有 flow 边降噪；如果仍然不足，再新增一个贴近目标位置的传播步骤。
不要重写整份 query。如果还有其他问题组件也被选中，可以协同修改它们，但本条提示词应聚焦于 flow。
```

- `others`

```text
The flow component falls into an uncategorized abnormal state.
Inspect whether the current additional flow-step logic is too broad or too weak, then either denoise it or add one small target-adjacent bridge if justified by the component facts.
Do not rewrite the whole query. If other problem components are also selected, coordinate those edits separately, but keep this prompt focused on flow.
```

中文版本：

```text
当前 flow 组件落入未分类的异常状态。
检查现有 additional flow-step 逻辑是过宽还是过弱；然后根据组件事实决定是给它降噪，还是补一个小的、贴近目标位置的 bridge。
不要重写整份 query。如果还有其他问题组件也被选中，可以协同修改它们，但本条提示词应聚焦于 flow。
```

## 推荐的自动提示词选择输出

后续系统可以把行为选择结果继续扩展成一个“组件级提示词选择结果”，这个结果只针对 `problem_components` 中出现的组件，例如：

```text
source:
- status: only_fixed
- selected_behavior: 替换 Source
- recommended_action: replace_reversed_source
- selected_prompt: Source only_fixed prompt

sink:
- status: off_target
- selected_behavior: 替换 Sink
- recommended_action: replace_off_target_sink
- selected_prompt: Sink off-target prompt

barrier:
- status: non_discriminative
- selected_behavior: 专化 Barrier 到修复逻辑
- recommended_action: specialize_or_lightly_narrow_barrier
- selected_prompt: Barrier non_discriminative prompt

flow:
- status: noisy_bridge
- selected_behavior: 降噪
- recommended_action: narrow_existing_flow
- selected_prompt: Flow noisy_bridge prompt
```

然后 prompt builder 再按组件顺序组装：

- 问题描述
- 修复行为名称
- 事实依据
- 对应状态的专用提示词

## 推荐的整体落地流程

建议最终流程如下：

1. 原 query 失败
2. 跑 `source/sink/barrier/flow probe`
3. 获得每个组件的问题描述
4. 给每个组件选择修复行为和推荐动作
5. 生成组件级 prompt（附事实依据）
6. 组合整体修复建议并交给修复 agent
7. agent 修改 query 代码
8. 编译验证
9. 再跑正式评估

## 一句话总结

参考论文后，CodeQL 版方案的核心不是“自动套模板改 query”，而是：

- `source`：扩张 / 替换 / 保留
- `sink`：扩张 / 替换 / 保留
- `barrier`：弱化 / fixed-side 专化 / 保留
- `flow`：补桥 / 降噪 / 替换重建 / 保留

系统负责从 probe 结果中产出“组件级修复建议 + 事实依据 + 专用提示词”，再由后续 agent 实施代码修改。
