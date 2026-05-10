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

为了让后续系统可以从 `probe_evaluation` 的结果直接得到修复建议，行为选择规则必须和评估标签对齐。

这里采用的原则是：

- 每个组件的 `status` 直接映射到一个主修复行为
- 必要时再给一个次行为，作为备选
- 多个组件同时异常时，不只保留一个主嫌疑，而是允许同时附加多个组件建议

推荐的输出逻辑不是：

- “只给一个 localization 结果”

而是：

- `source` 根据自己的 `status` 选行为
- `sink` 根据自己的 `status` 选行为
- `barrier` 根据自己的 `status` 选行为
- `flow` 根据自己的 `status` 选行为

这样后续 prompt 就能直接拼成：

- source 问题描述 + source 修复行为 + source prompt
- sink 问题描述 + sink 修复行为 + sink prompt
- barrier 问题描述 + barrier 修复行为 + barrier prompt
- flow 问题描述 + flow 修复行为 + flow prompt

## 组件级映射规则

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
- `weak_but_present`
  - 如果 `aligned_methods = 0`
    - 主行为：`替换 Source`
    - 推荐动作：`replace_off_target_source`
    - 说明：有结果但完全不对齐，是典型 `source_off_target`
  - 如果 `aligned_methods > 0`
    - 主行为：`保留`
    - 次行为：`轻微收缩`
    - 推荐动作：`keep_source_stable`
- `good_anchor`
  - 主行为：`保留`
  - 推荐动作：`keep_source_stable`
  - 说明：source 已经足够接近目标，不应优先修改

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
- `weak_but_present`
  - 如果 `aligned_methods = 0`
    - 主行为：`替换 Sink`
    - 推荐动作：`replace_off_target_sink`
    - 说明：命中了文件但没命中目标方法时，也归入这一类
  - 如果 `aligned_methods > 0`
    - 主行为：`保留`
    - 次行为：`轻微收缩`
    - 推荐动作：`keep_sink_stable`
- `good_anchor`
  - 主行为：`保留`
  - 推荐动作：`keep_sink_stable`

### Barrier 映射

- `absent`
  - 主行为：`专化 Barrier 到修复逻辑`
  - 推荐动作：`add_repair_side_barrier`
  - 说明：如果漏洞语义确实需要修复侧保护逻辑，而 barrier 完全不存在，就应补 barrier
- `repair_only`
  - 主行为：`专化 Barrier 到修复逻辑`
  - 推荐动作：`specialize_existing_barrier`
  - 说明：方向是对的，不要删，应该保留并贴近 fixed-side validation
- `useful_repair_signal`
  - 主行为：`专化 Barrier 到修复逻辑`
  - 次行为：`轻微收缩 Barrier`
  - 推荐动作：`specialize_existing_barrier`
  - 说明：barrier 是正向修复信号，但可能还不够具体
- `overblocking_suspect`
  - 主行为：`弱化 Barrier`
  - 推荐动作：`narrow_or_replace_barrier`
  - 说明：barrier 可能正在压掉漏洞路径，应优先收紧
- `non_discriminative`
  - 主行为：`专化 Barrier 到修复逻辑`
  - 次行为：`弱化 Barrier`
  - 推荐动作：`specialize_or_lightly_narrow_barrier`
  - 说明：如果 barrier 只是 shared filter，就应把它往 fixed-side 修复逻辑上专化；若专化无从下手，再考虑弱化

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
- `useful_bridge`
  - 主行为：`保留`
  - 次行为：`轻微补桥`
  - 推荐动作：`keep_flow_stable`
  - 说明：flow 已经提供了有价值传播边，不应大改
- `noisy_bridge`
  - 主行为：`降噪`
  - 推荐动作：`narrow_existing_flow`
  - 说明：flow 太泛，需要加 guard
- `weak_bridge`
  - 主行为：`降噪`
  - 次行为：`补桥`
  - 推荐动作：`narrow_then_add_flow_if_needed`
  - 说明：先看是否因为太宽导致弱信号；若不是，再考虑增加 target-adjacent bridge

## 完整 Query 的修复建议优先级

当多个组件同时有问题时，不建议只保留一个建议，而应按优先级组合多个组件建议。

推荐顺序如下：

1. `source`
   - 当 `source_off_target`、`source_missing`、`source_empty` 时，优先级最高
2. `sink`
   - 当 `sink_off_target`、`sink_missing`、`sink_empty` 时，优先级与 source 同级
3. `barrier`
   - 当 `overblocking_suspect` 时，优先级提升到和 source/sink 接近
4. `flow`
   - 当 `flow_missing` 时，优先级高于一般的 barrier/non-discriminative 情况

一个推荐的总体规则是：

- 如果 `source/sink` 有明显对齐问题，优先修 `source/sink`
- 如果 `source/sink` 基本存在，但 query 仍 `0/0`，再看 `flow`
- 如果 `barrier` 是 `overblocking_suspect`，把 barrier 建议一并加入 prompt
- 如果 `barrier` 只是 `non_discriminative`，通常放在 source/sink/flow 后面

## 推荐的自动修复建议输出

后续系统可以把 `probe_evaluation` 的结果转成一个简单的“修复建议结果”，例如：

```text
source:
- status: source_off_target
- selected_behavior: 替换 Source
- recommended_action: replace_off_target_source

sink:
- status: sink_off_target
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

然后 prompt builder 再按优先级把这些组件建议拼起来。

## 从 Probe 评估结果直接选择专用提示词

除了行为选择之外，每个组件的评估结果还应对应一套专用提示词。

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
<probe status>

[Problem]
<summary generated from probe evaluation>

[Repair Behavior]
<selected behavior name>

[Supporting Facts]
<aligned files/methods, hit counts, coverage, vuln/fixed counts>

[Repair Prompt]
Only modify <component-specific scope>.
<component-specific guidance from the current status>.
Do not rewrite the whole query.
Do not modify unrelated components unless explicitly requested.
```

## 组件状态到专用提示词的映射

### Source 专用提示词

- `missing_component`

```text
Only modify source-related code.
The query does not define an effective source component.
Add one new source condition that captures a target-adjacent entry point.
Prefer parameters, request values, configuration values, or patch-adjacent inputs near target files and target methods.
Do not modify sink, barrier, flow, or the final query structure.
```

- `empty`

```text
Only modify source-related code.
The current source probe returns no matches on either vulnerable or fixed versions.
Expand the source locally by adding one new source branch.
Prefer entry points that are close to target files, target methods, or patch-related code.
Do not modify sink, barrier, flow, or rewrite the whole query.
```

- `only_fixed`

```text
Only modify source-related code.
The current source modeling appears reversed because it only matches the fixed version.
Replace the current source so that it captures vulnerable-side entry points instead of fixed-side-only inputs.
Prefer target-adjacent source logic over broad utility-like sources.
Do not modify sink, barrier, flow, or rewrite the whole query.
```

- `weak_but_present` with `aligned_methods = 0`

```text
Only modify source-related code.
The source probe has matches, but none align with target files or target methods.
Treat this as off-target source modeling.
Prefer replacing broad utility-like sources with target-adjacent entry points.
Do not modify sink, barrier, flow, or rewrite the whole query.
```

- `good_anchor`

```text
Do not prioritize source repair.
The source component already aligns with vulnerable-side target methods or otherwise behaves like a good anchor.
Keep source logic stable unless another change requires a very small local adjustment.
```

### Sink 专用提示词

- `missing_component`

```text
Only modify sink-related code.
The query does not define an effective sink component.
Add one new sink condition that captures a vulnerability-relevant dangerous operation near target files or target methods.
Do not modify source, barrier, flow, or the final query structure.
```

- `empty`

```text
Only modify sink-related code.
The current sink probe returns no matches on either vulnerable or fixed versions.
Expand the sink locally by adding one new sink branch that better reflects the dangerous operation in the patch context.
Do not modify source, barrier, flow, or rewrite the whole query.
```

- `only_fixed`

```text
Only modify sink-related code.
The current sink modeling appears reversed because it only matches the fixed version.
Replace the sink so that it captures vulnerable-side dangerous operations rather than fixed-side-only behavior.
Do not modify source, barrier, flow, or rewrite the whole query.
```

- `weak_but_present` with `aligned_methods = 0`

```text
Only modify sink-related code.
The sink probe has matches, but it does not align with target methods.
Treat this as off-target sink modeling.
Prefer replacing broad sink logic with target-adjacent dangerous operations.
Do not modify source, barrier, flow, or rewrite the whole query.
```

- `good_anchor`

```text
Do not prioritize sink repair.
The sink component already behaves like a useful anchor near the intended dangerous operation.
Keep sink logic stable unless another local change requires a very small adjustment.
```

### Barrier 专用提示词

- `absent`

```text
Only modify barrier-related code.
The query currently has no effective barrier behavior.
Add a local barrier condition only if the patch introduces validation, sanitization, normalization, or fixed-side guard logic that should suppress paths after repair.
Do not modify source, sink, flow, or rewrite the whole query.
```

- `repair_only`

```text
Only modify barrier-related code.
The barrier appears only on the fixed side, which is a strong repair-side signal.
Keep the barrier and make it more explicit around fixed-side validation, sanitization, normalization, or whitelist logic.
Do not weaken the barrier unless there is clear evidence that it suppresses vulnerable paths.
Do not modify source, sink, or flow.
```

- `useful_repair_signal`

```text
Only modify barrier-related code.
The barrier is stronger in the fixed version than in the vulnerable version, which suggests useful repair-side protection logic.
Preserve the barrier, but specialize it toward fixed-side validation helpers instead of generic shared conditions.
Do not broadly delete barrier logic.
Do not modify source, sink, or flow.
```

- `overblocking_suspect`

```text
Only modify barrier-related code.
The barrier may be too broad and may suppress vulnerable paths that should remain reachable.
Weaken the barrier locally by adding stronger guards or replacing generic barrier conditions with more specific fixed-side validation logic.
Do not remove all barrier logic unless it is clearly unsupported.
Do not modify source, sink, or flow.
```

- `non_discriminative`

```text
Only modify barrier-related code.
The barrier matches both vulnerable and fixed versions with weak discrimination.
Do not treat it as a main detection signal.
Try to specialize the barrier toward fixed-side validation or sanitization logic; if that is not possible, gently narrow generic barrier conditions.
Do not modify source, sink, or flow.
```

### Flow 专用提示词

- `missing_component`

```text
Only modify flow-related code.
The query has no effective additional flow-step modeling.
Add one new propagation step that helps connect the current source region to the current sink region.
Prefer target-adjacent propagation edges over generic utility flows.
Do not modify source, sink, barrier, or rewrite the whole query.
```

- `empty`

```text
Only modify flow-related code.
The flow probe returns no bridge facts on either vulnerable or fixed versions.
Add one new local propagation step inside isAdditionalFlowStep or a closely related helper predicate.
Prefer propagation edges that appear near target files, target methods, or patch-relevant helper calls.
Do not modify source, sink, barrier, or rewrite the whole query.
```

- `compile_failed`

```text
Only modify flow-related code.
The additional flow-step logic does not compile independently.
First rebuild or simplify the current flow predicate structure, then keep only the most target-relevant propagation edges.
Do not modify source, sink, barrier, or rewrite the whole query.
```

- `noisy_bridge`

```text
Only modify flow-related code.
The current additional flow-step logic produces many shared edges on both vulnerable and fixed versions.
Treat this as noisy bridge modeling.
Narrow the flow by adding stronger type, receiver, method-name, or argument-position constraints, and keep only target-adjacent propagation edges.
Do not modify source, sink, barrier, or rewrite the whole query.
```

- `weak_bridge`

```text
Only modify flow-related code.
Some bridge evidence exists, but it is not yet specific enough to explain the intended vulnerability path.
First try to denoise existing flow edges; if needed, add one new target-adjacent propagation step.
Do not modify source, sink, barrier, or rewrite the whole query.
```

- `useful_bridge`

```text
Do not prioritize large flow changes.
The current additional flow-step logic already provides useful vulnerable-side bridge evidence.
Keep the existing flow mostly stable and only make very small local adjustments if they improve target-adjacent connectivity.
```

## 推荐的自动提示词选择输出

后续系统可以把行为选择结果继续扩展成一个“组件级提示词选择结果”，例如：

```text
source:
- status: only_fixed
- selected_behavior: 替换 Source
- recommended_action: replace_reversed_source
- selected_prompt: Source only_fixed prompt

sink:
- status: weak_but_present (aligned_methods = 0)
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

## Prompt 中每个组件建议应如何表达

每个组件在 prompt 里建议固定为如下结构：

```text
[Component]
source

[Problem]
Source probe has many matches, but none align with target files or target methods.

[Repair Behavior]
Replace the source locally.

[Supporting Facts]
- vuln_aligned_methods: 0
- fixed_aligned_methods: 0
- vuln_num_results: 105
- fixed_num_results: 105

[Allowed Edits]
- edit source class definitions
- edit isSource predicate
- edit source helper predicates

[Preferred Actions]
- replace broad utility sources with target-adjacent entry points
- add type constraints if a full replacement is not yet justified

[Forbidden Actions]
- do not modify sink
- do not modify barrier
- do not rewrite the whole query
```

其他组件同理，只替换 `Problem`、`Repair Behavior`、`Supporting Facts`、`Allowed Edits`、`Preferred Actions`。

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
