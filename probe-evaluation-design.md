# Probe 评估方案设计

## 目标

`probe_evaluation.py` 的职责不是替代 QLCoder 现有的最终 query 评估体系，而是
在 `structural_extract.py` 生成的组件级 probe 基础上，增加一层中间诊断层，
分析拆分后的 CodeQL query 组件：

- `source`
- `sink`
- `barrier`
- `flow`

这层诊断主要回答四个问题：

1. 每个组件当前是否存在、能否独立编译、在两侧运行表现如何。
2. 每个组件当前处于什么状态，例如缺失、为空、方向反了、过噪、区分性不足。
3. 每个组件的状态是由哪些 `run` 字段和原 query 背景字段共同支撑出来的。
4. 哪些组件存在明显问题，后续修复 prompt 应优先关注哪些组件。


## 设计原则

- probe 评估与最终 query 的成功判定解耦。
- 把 probe 当作“组件级事实采集器”，而不是最终漏洞检测器。
- 不同角色使用不同的判定规则，不能复用同一套标准。
- 顶层聚合结果只做“问题组件汇总”，不强行指定单一主因。
- 状态判定尽量直接基于 `run` 字段完成，不额外引入一层中间诊断信号结构。
- `verdict` 只保留判定结论本身，不提前塞入后续 prompt 选择阶段才需要的解释文本。


## 与现有 QLCoder 评估的关系

当前 QLCoder 的正式评估链路是围绕“最终漏洞 query”设计的：

- 在 `vulnerable` 和 `fixed` 数据库上运行 query。
- 生成 CSV 和 SARIF。
- 用 SARIF 结果对齐补丁相关的目标文件和目标方法。
- 当 query 命中目标漏洞方法、且不再命中修复版本目标方法时，认为 query 成功。

这套逻辑很适合最终 `path query`，但不适合 probe。

例如：

- `source_probe` 同时命中漏洞版和修复版，可能完全合理。
- `barrier_probe` 在修复版命中更多，反而可能是一个正向信号。
- `flow_probe` 表示的是桥接边，而不是最终漏洞告警。

因此，probe 评估应作为独立的诊断层实现，而不是直接复用最终 query 的成功标准。


## 输出文件

建议输出以下文件：

- `probe_evaluation.json`
- `probe_evaluation.md`

它们都应针对“每个原始 query”生成一份，并与 probe 文件、编译结果、运行结果放在同一目录下。


## 顶层 JSON Schema

```json
{
  "schema_version": "v1",
  "meta": {
    "cve_id": "CVE-2025-27526",
    "language": "java",
    "generated_at": "2026-05-07T12:34:56Z",
    "query_path": "/abs/path/original_query.ql",
    "probe_dir": "/abs/path/probes",
    "evaluator": "probe_evaluation.py",
    "codeql_path": "/opt/codeql_2.23.3/codeql"
  },
  "target_context": {
    "fixed_files": [
      "src/main/java/com/example/A.java"
    ],
    "fixed_methods": [
      "src/main/java/com/example/A.java:A:foo"
    ],
    "target_file_count": 1,
    "target_method_count": 1
  },
  "original_query": {
    "compile_success": true,
    "vuln_num_results": 0,
    "fixed_num_results": 0,
    "vuln_recall_method": false,
    "fixed_recall_method": false,
    "notes": [
      "Original query is zero-hit on both versions"
    ]
  },
  "components": {
    "source": {},
    "sink": {},
    "barrier": {},
    "flow": {}
  },
  "problem_components": [
    {
      "role": "source",
      "status": "off_target",
      "confidence": 0.87
    },
    {
      "role": "flow",
      "status": "noisy_bridge",
      "confidence": 0.60
    }
  ]
}
```


## 顶层字段说明

### `meta`

记录执行元信息，方便追踪和下游消费。

建议字段：

- `cve_id`
- `language`
- `generated_at`
- `query_path`
- `probe_dir`
- `evaluator`
- `codeql_path`


### `target_context`

记录从 `fix_info.csv` 中提取出的目标文件和目标方法。

建议字段：

- `fixed_files`
- `fixed_methods`
- `target_file_count`
- `target_method_count`

这里应复用当前 QLCoder 正式评估器使用的目标定义，不另起一套标准。


### `original_query`

记录原始 query 的运行摘要。它是 probe 诊断的背景信息，不是 probe 评估的主体。

建议字段：

- `compile_success`
- `vuln_num_results`
- `fixed_num_results`
- `vuln_recall_method`
- `fixed_recall_method`
- `notes`


### `components`

每个角色都有一份独立诊断块：

- `source`
- `sink`
- `barrier`
- `flow`

即使原 query 中不存在某个角色，也建议在输出中显式保留该角色，并设置
`present_in_query = false`。


### `problem_components`

这是顶层聚合结果，不再做“primary suspect / secondary suspect”的单点定位。

它的作用是：

- 把所有值得后续修复 prompt 关注的组件显式列出来。
- 只保留每个组件的结论性信息：`role`、`status`、`confidence`。
- 具体事实不在这里重复展开，而是直接回到对应组件的 `run` 字段中提取。

建议字段：

- `role`
- `status`
- `confidence`


## 单个组件的 Schema

每个组件的诊断块建议统一为以下结构：

```json
{
  "present_in_query": true,
  "probe_path": "/abs/path/source_probe.ql",
  "compile_success": true,
  "compile_error": null,
  "generation_mode": "hybrid",
  "source_predicate": "isSource",
  "run": {
    "vulnerable": {
      "success": true,
      "num_results": 3,
      "error": null,
      "sarif_path": "/abs/path/source_vuln_alignment.sarif",
      "num_aligned_files": 1,
      "num_aligned_methods": 1,
      "aligned_files": [
        "src/main/java/com/example/A.java"
      ],
      "aligned_methods": [
        "src/main/java/com/example/A.java:A:foo"
      ],
      "target_file_coverage": 1.0,
      "target_method_coverage": 1.0,
      "hit_files": [
        "src/main/java/com/example/A.java"
      ],
      "hit_methods": [
        "src/main/java/com/example/A.java:A:foo"
      ]
    },
    "fixed": {
      "success": true,
      "num_results": 0,
      "error": null,
      "sarif_path": "/abs/path/source_fixed_alignment.sarif",
      "num_aligned_files": 0,
      "num_aligned_methods": 0,
      "aligned_files": [],
      "aligned_methods": [],
      "target_file_coverage": 0.0,
      "target_method_coverage": 0.0,
      "hit_files": [],
      "hit_methods": []
    }
  },
  "verdict": {
    "status": "good_anchor",
    "confidence": 0.86
  }
}
```


## 单个组件字段解释

### 基础字段

- `present_in_query`
  - 原 query 中是否存在该组件对应的 predicate。
  - 例如 `source` 看是否存在 `isSource`，`flow` 看是否存在 `isAdditionalFlowStep`。
- `probe_path`
  - 该组件生成出的 probe 文件路径。
- `compile_success`
  - probe 是否单独编译成功。
- `compile_error`
  - probe 编译失败时的错误信息；成功时应为 `null`。
- `generation_mode`
  - probe 的生成模式，例如 `hybrid`、`all-table`、`all-problem`。
- `source_predicate`
  - 原 query 中被拆出的 predicate 名称，例如 `isSource`、`isSink`。

### `run.vulnerable` / `run.fixed`

表示在 `vulnerable` 和 `fixed` 数据库上的运行结果，两边结构应尽量一致。

建议字段：

- `success`
  - 该侧 probe 是否运行成功。
- `num_results`
  - 该侧 probe 的结果条数。
- `error`
  - 运行失败时的错误信息。
- `sarif_path`
  - 做对齐分析时产出的 SARIF 文件路径。
- `num_aligned_files`
  - 该侧 probe 结果中，与 `target_context.fixed_files` 对齐的文件数量。
- `num_aligned_methods`
  - 该侧 probe 结果中，与 `target_context.fixed_methods` 对齐的方法数量。
- `aligned_files`
  - 真正落在目标文件上的文件列表。
- `aligned_methods`
  - 真正落在目标方法上的方法列表。
- `target_file_coverage`
  - `num_aligned_files / target_file_count`。
- `target_method_coverage`
  - `num_aligned_methods / target_method_count`。
- `hit_files`
  - probe 实际命中过的全部文件，不要求这些文件都属于 target。
- `hit_methods`
  - probe 实际命中过的全部方法，不要求这些方法都属于 target。

### `verdict`

这是最终诊断结论。

建议字段：

- `status`
  - 当前组件状态，例如 `empty`、`good_anchor`、`noisy_bridge`。
- `confidence`
  - 当前判定置信度。

`verdict` 不建议在此阶段额外保存 `reason`，因为：

- 这些解释都可以从 `run` 字段和判定规则中重新推导。
- `reason` 更像后续生成修复 prompt 时才需要的人类可读总结。
- 提前保存会让 schema 混入后续阶段语义。


## 每个组件的最小必需字段

每个组件至少要有以下字段，才能形成稳定诊断：

- `present_in_query`
- `probe_path`
- `compile_success`
- `compile_error`
- `run.vulnerable.success`
- `run.vulnerable.num_results`
- `run.fixed.success`
- `run.fixed.num_results`
- `verdict`

对 `source/sink`，建议同时输出：

- `num_aligned_files`
- `num_aligned_methods`
- `aligned_files`
- `aligned_methods`
- `target_file_coverage`
- `target_method_coverage`
- `hit_files`
- `hit_methods`


## 按组件的检验原则

probe 不能被当成“只看输出行数”的统一对象，而应按组件语义分别定义检验目标：

- `source` / `sink`
  - 重点检查是否命中目标文件、目标方法，以及覆盖了多少 patch 相关方法。
- `barrier`
  - 重点检查是否呈现修复侧信号，以及是否可能过强导致抑制了漏洞路径。
- `flow`
  - 重点检查桥接边是否接近目标区域、是否真正提供了 source 到 sink 的连接，而不是只看边数。

换句话说：

- `source/sink` 重点看 `target alignment`
- `barrier` 重点看修复侧信号
- `flow` 重点看桥接质量


## 默认 Probe 生成策略

建议采用默认的 `hybrid` probe 生成策略，而不是把四类组件强行统一成同一种 `@kind`：

- `source`
  - 默认生成 `@kind problem`
- `sink`
  - 默认生成 `@kind problem`
- `barrier`
  - 默认生成 `@kind table`
- `flow`
  - 默认生成 `@kind table`

这样设计的原因是：

- `source/sink`
  - 更适合通过 `SARIF + locations` 接入现有评估链路。
  - 更容易计算 `aligned_files`、`aligned_methods`、`target_method_coverage`。
- `barrier`
  - 更像修复信号或抑制信号，不应默认按“漏洞告警”语义解释。
- `flow`
  - 本质上是 `n1 -> n2` 的桥接边事实，更适合 `table` 形式。

因此默认行为应保持为：

- `source/sink -> problem`
- `barrier/flow -> table`

可选模式仍可支持：

- `hybrid`
- `all-table`
- `all-problem`


## `run` 到 `verdict.status` 的映射规则

这里不再单独设计一层 `signals`。状态判定直接基于：

- 组件基础字段：`present_in_query`、`compile_success`
- 两侧运行字段：`run.vulnerable.*`、`run.fixed.*`
- 原 query 背景：`original_query.*`
- 对齐字段：`num_aligned_files`、`num_aligned_methods` 等

下面按角色给出明确映射规则。这里描述的都是 `verdict.status` 的映射规则，也就是：在给定 `present_in_query`、`compile_success`、`run.vulnerable.*`、`run.fixed.*`、`original_query.*` 等字段后，应如何确定每个组件最终写入 `verdict.status` 的状态值。


## Source Status 映射规则

### `missing_component`

- 条件：`present_in_query = false`
- 场景：原 query 中没有有效 `isSource`。

### `compile_failed`

- 条件：`present_in_query = true` 且 `compile_success = false`
- 场景：source probe 无法独立编译。

### `empty`

- 条件：
  - `compile_success = true`
  - `run.vulnerable.num_results = 0`
  - `run.fixed.num_results = 0`
- 场景：source 在两侧都没有事实，常见于入口过窄、类型不对或入口选错。

### `only_fixed`

- 条件：
  - `compile_success = true`
  - `run.vulnerable.num_results = 0`
  - `run.fixed.num_results > 0`
- 场景：source 只在修复侧出现，通常表示方向反了。

### `off_target`

- 条件：
  - `compile_success = true`
  - `run.vulnerable.num_results > 0`
  - `run.vulnerable.num_aligned_methods = 0`
  - `run.fixed.num_aligned_methods = 0`
- 场景：source 虽然有结果，但完全没有落在目标方法上，说明定义偏离漏洞入口。

### `good_anchor`

- 条件：
  - `compile_success = true`
  - `run.vulnerable.num_aligned_methods > 0`
  - `run.fixed.num_aligned_methods = 0`
- 场景：source 在漏洞侧命中 target method，而在修复侧不命中，是较强的正向锚点。

### `weak_but_present`

- 条件：满足以下任一类：
  - `run.vulnerable.num_results > 0` 且 `run.fixed.num_results > 0`，但没有更强证据支持 `good_anchor` 或 `off_target`。
  - `run.vulnerable.num_aligned_methods > 0` 且 `run.fixed.num_aligned_methods > 0`。
- 场景：source 存在，但区分性不足；或者虽然对齐到了 target method，但两侧都命中。

### `others`

- 条件：
  - 不满足上面任何已显式列出的 `source` 状态条件。
- 场景：
  - 所有暂未单独拆分、但又不能稳定归入 `missing_component`、`compile_failed`、`empty`、`only_fixed`、`off_target`、`good_anchor`、`weak_but_present` 的边界情况。
  - 例如：
    - `run.vulnerable.num_results > 0`、`run.fixed.num_results = 0`，但只有文件级命中，没有方法级命中。
    - `run.vulnerable.num_results > 0`、`run.fixed.num_results = 0`，且当前对齐结果不足以稳定归入 `good_anchor` 或 `off_target`。
- 说明：
  - 这是 `source` 的兜底状态。
  - `verdict.confidence` 固定记为 `1`。


## Sink Status 映射规则

`sink` 与 `source` 类似，但更偏向“是否命中目标危险方法”。

### `missing_component`

- 条件：`present_in_query = false`
- 场景：原 query 中没有有效 `isSink`。

### `compile_failed`

- 条件：`present_in_query = true` 且 `compile_success = false`
- 场景：sink probe 无法独立编译。

### `empty`

- 条件：
  - `compile_success = true`
  - `run.vulnerable.num_results = 0`
  - `run.fixed.num_results = 0`
- 场景：sink 在两侧都没有结果。

### `only_fixed`

- 条件：
  - `compile_success = true`
  - `run.vulnerable.num_results = 0`
  - `run.fixed.num_results > 0`
- 场景：sink 只在修复侧命中，通常说明危险点建模反了。

### `off_target`

- 条件：
  - `compile_success = true`
  - `run.vulnerable.num_results > 0`
  - `run.vulnerable.num_aligned_methods = 0`
  - `run.fixed.num_aligned_methods = 0`
- 场景：sink 有结果，但没有真正落在目标危险方法上。

### `good_anchor`

- 条件：
  - `compile_success = true`
  - `run.vulnerable.num_aligned_methods > 0`
  - `run.fixed.num_aligned_methods = 0`
- 场景：sink 在漏洞侧命中 target method，而在修复侧不命中，是较强危险点锚点。

### `weak_but_present`

- 条件：满足以下任一类：
  - `run.vulnerable.num_results > 0` 且 `run.fixed.num_results > 0`，但没有更强证据支持 `good_anchor` 或 `off_target`。
  - `run.vulnerable.num_aligned_methods > 0` 且 `run.fixed.num_aligned_methods > 0`。
- 场景：sink 存在，但还不够区分。

### `others`

- 条件：
  - 不满足上面任何已显式列出的 `sink` 状态条件。
- 场景：
  - 所有暂未单独拆分、但又不能稳定归入 `missing_component`、`compile_failed`、`empty`、`only_fixed`、`off_target`、`good_anchor`、`weak_but_present` 的边界情况。
  - 例如：
    - 命中了 target file，但没有命中 target method。
- 说明：
  - 这是 `sink` 的兜底状态。
  - `verdict.confidence` 固定记为 `1`。


## Barrier Status 映射规则

`barrier` 不能沿用最终 query 的“fixed 命中就是误报”那套逻辑。

### `missing_component`

- 条件：`present_in_query = false`
- 场景：原 query 中没有有效 barrier 组件。

### `compile_failed`

- 条件：`present_in_query = true` 且 `compile_success = false`
- 场景：barrier probe 无法独立编译。

### `absent`

- 条件：
  - `compile_success = true`
  - `run.vulnerable.num_results = 0`
  - `run.fixed.num_results = 0`
- 场景：barrier 两侧都没有事实。

### `repair_only`

- 条件：
  - `compile_success = true`
  - `run.vulnerable.num_results = 0`
  - `run.fixed.num_results > 0`
- 场景：barrier 只在修复侧出现，是典型修复侧保护信号。
- 说明：
  - 这通常表示一个合理的 repair-side barrier 信号。
  - 它应保留在组件级 `verdict.status` 中，但默认不作为“有问题组件”进入顶层 `problem_components`。

### `useful_repair_signal`

- 条件：
  - `compile_success = true`
  - `run.fixed.num_results > run.vulnerable.num_results`
  - 且不满足 `repair_only`
- 场景：barrier 在修复侧比漏洞侧更强。
- 说明：
  - 这通常也是正向修复侧信号。
  - 它默认不作为“有问题组件”进入顶层 `problem_components`，除非后续另有更强规则要求关注 barrier。

### `overblocking_suspect`

- 条件：
  - `compile_success = true`
  - `run.vulnerable.num_results > run.fixed.num_results * 2`
  - `original_query.vuln_num_results = 0`
  - `original_query.fixed_num_results = 0`
- 场景：barrier 在漏洞侧过强，而原 query 仍然是 `0/0`，说明它可能把本应存在的漏洞路径压掉了。

### `non_discriminative`

- 条件：
  - `compile_success = true`
  - 两侧都有 barrier 结果。
  - 不满足 `repair_only`、`useful_repair_signal`、`overblocking_suspect`。
- 场景：barrier 在两侧都存在，但区分性不够。

### `others`

- 条件：
  - 不满足上面任何已显式列出的 `barrier` 状态条件。
- 场景：
  - 所有暂未单独拆分、但又不能稳定归入 `missing_component`、`compile_failed`、`absent`、`repair_only`、`useful_repair_signal`、`overblocking_suspect`、`non_discriminative` 的边界情况。
  - 例如：
    - barrier 命中数接近，但明显集中在修复新增 helper 上。
- 说明：
  - 这是 `barrier` 的兜底状态。
  - `verdict.confidence` 固定记为 `1`。


### Barrier 状态设计说明

这里需要强调：`barrier` 的语义和 `source` / `sink` 不同。

- `source` / `sink` 更接近正证据。
  - 它们是在描述“漏洞入口在哪里”“危险点在哪里”。
- `barrier` 更接近负证据或抑制条件。
  - 它描述的是哪些路径会被验证、净化、规范化或直接拦住。

因此，对 `barrier` 不能套用“漏洞侧命中越多越好，修复侧命中就是坏事”这套标准。

当前这组状态的设计意图是：

- `repair_only`
  - 优先解释为正向修复侧信号。
  - 因为它表示 barrier 只在修复侧出现，这通常和补丁引入的新校验、新净化逻辑一致。
- `useful_repair_signal`
  - 也优先解释为正向修复侧信号。
  - 因为它表示 barrier 在两侧都可能存在，但修复侧更强，这通常对应“原来有弱校验，修复后变强”。
- `overblocking_suspect`
  - 才优先解释为 barrier 组件本身有问题。
  - 因为它表示漏洞侧 barrier 特别强，而原 query 又仍然是 `0/0`，这时最合理的怀疑是 barrier 把本应存在的漏洞路径压掉了。
- `non_discriminative`
  - 则表示 barrier 更像共享条件，而不是明确的修复侧保护逻辑。
  - 它不是最严重的问题，但说明 barrier 还不够专化。

换句话说，当前 `barrier` 判定规则背后的原则是：

- 修复侧更强，不一定是坏事，很多时候反而是合理现象。
- 漏洞侧异常强，才更值得怀疑 barrier 过强或方向不对。

这也是为什么：

- `repair_only`
- `useful_repair_signal`

默认不进入顶层 `problem_components`，而：

- `overblocking_suspect`
- `non_discriminative`

仍然保留为需要进一步关注的 barrier 状态。


## Flow Status 映射规则

### `missing_component`

- 条件：
  - `present_in_query = false`
  - `original_query.vuln_num_results = 0`
  - `original_query.fixed_num_results = 0`
- 场景：query 没有显式 `isAdditionalFlowStep`，且整体也没有表现出无需该组件的证据。

### `likely_not_needed`

- 条件：
  - `present_in_query = false`
  - `original_query.vuln_num_results > 0` 或 `original_query.fixed_num_results > 0`
- 场景：query 没有显式 flow step，但原 query 已经能跑出结果。

### `compile_failed`

- 条件：`present_in_query = true` 且 `compile_success = false`
- 场景：flow probe 无法独立编译。

### `empty`

- 条件：
  - `compile_success = true`
  - `run.vulnerable.num_results = 0`
  - `run.fixed.num_results = 0`
- 场景：flow 没有桥接边事实。

### `useful_bridge`

- 条件：
  - `compile_success = true`
  - `run.vulnerable.num_results > 0`
  - `run.fixed.num_results = 0`
- 场景：flow 在漏洞侧提供桥接边，而在修复侧没有。

### `noisy_bridge`

- 条件：
  - `compile_success = true`
  - `run.vulnerable.num_results > 0`
  - `run.fixed.num_results > 0`
  - `abs(run.vulnerable.num_results - run.fixed.num_results)` 很小
- 场景：flow 两侧边很多且数量接近，说明桥接边很噪。

### `weak_bridge`

- 条件：
  - `compile_success = true`
  - `run.vulnerable.num_results > 0` 或 `run.fixed.num_results > 0`
  - 但不满足 `useful_bridge`、`noisy_bridge`
- 场景：flow 有一定桥接证据，但还不够明确。

### `others`

- 条件：
  - 不满足上面任何已显式列出的 `flow` 状态条件。
- 场景：
  - 所有暂未单独拆分、但又不能稳定归入 `missing_component`、`likely_not_needed`、`compile_failed`、`empty`、`useful_bridge`、`noisy_bridge`、`weak_bridge` 的边界情况。
  - 例如：
    - flow 边很多，但只有少量边接近 source/sink 邻域。
- 说明：
  - 这是 `flow` 的兜底状态。
  - `verdict.confidence` 固定记为 `1`。


## 顶层问题组件汇总规则

顶层不再输出“primary suspect / secondary suspect”，而是输出 `problem_components`。

建议规则如下：

- 如果组件状态属于以下集合，就应进入 `problem_components`：
  - `missing_component`
  - `compile_failed`
  - `empty`
  - `only_fixed`
  - `off_target`
  - `overblocking_suspect`
  - `non_discriminative`
  - `weak_but_present`
  - `weak_bridge`
  - `noisy_bridge`
  - `others`
- 如果组件状态属于以下集合，通常不必放入 `problem_components`：
  - `good_anchor`
  - `repair_only`
  - `useful_repair_signal`
  - `useful_bridge`
  - `likely_not_needed`

这样做的目的是：

- 一次性列出所有值得修复 prompt 关注的组件。
- 避免强行把多组件问题压缩成单一失败原因。


## Confidence 启发式

建议保持简单、可解释，不上来就做复杂统计模型。

建议基础分值：

- `compile_failed`: `0.95`
- `empty`: `0.90`
- `only_fixed`: `0.85`
- `off_target`: `0.78` 到 `0.87`
- `good_anchor`: `0.80` 到 `0.86`
- `noisy_bridge`: `0.60`
- `weak_bridge`: `0.65`
- `non_discriminative`: `0.60`
- `others`: `1`

调节项：

- 如果 target alignment 可用并支持当前判断，可适当加分。
- 如果对齐不可用，不应把“没有数据”当成反证。
- 如果计数明显嘈杂、跨组件信号互相冲突，可适当减分。


## 最小示例

```json
{
  "schema_version": "v1",
  "meta": {
    "cve_id": "CVE-2025-27526",
    "query_path": "/abs/original.ql"
  },
  "original_query": {
    "vuln_num_results": 0,
    "fixed_num_results": 0
  },
  "components": {
    "source": {
      "present_in_query": true,
      "compile_success": true,
      "run": {
        "vulnerable": {
          "num_results": 5,
          "num_aligned_methods": 0
        },
        "fixed": {
          "num_results": 5,
          "num_aligned_methods": 0
        }
      },
      "verdict": {
        "status": "off_target",
        "confidence": 0.87
      }
    },
    "sink": {
      "present_in_query": true,
      "compile_success": true,
      "run": {
        "vulnerable": {
          "num_results": 8,
          "num_aligned_methods": 0
        },
        "fixed": {
          "num_results": 7,
          "num_aligned_methods": 0
        }
      },
      "verdict": {
        "status": "off_target",
        "confidence": 0.89
      }
    },
    "barrier": {
      "present_in_query": true,
      "compile_success": true,
      "run": {
        "vulnerable": {
          "num_results": 19
        },
        "fixed": {
          "num_results": 19
        }
      },
      "verdict": {
        "status": "non_discriminative",
        "confidence": 0.60
      }
    },
    "flow": {
      "present_in_query": true,
      "compile_success": true,
      "run": {
        "vulnerable": {
          "num_results": 2230
        },
        "fixed": {
          "num_results": 2233
        }
      },
      "verdict": {
        "status": "noisy_bridge",
        "confidence": 0.60
      }
    }
  },
  "problem_components": [
    {
      "role": "source",
      "status": "off_target",
      "confidence": 0.87
    },
    {
      "role": "sink",
      "status": "off_target",
      "confidence": 0.89
    },
    {
      "role": "barrier",
      "status": "non_discriminative",
      "confidence": 0.60
    },
    {
      "role": "flow",
      "status": "noisy_bridge",
      "confidence": 0.60
    }
  ]
}
```


## 总结

这套设计的核心思想是：

- 不把 probe 当最终告警结果。
- 而是把 probe 当作“组件级事实”。
- 状态判定尽量直接从 `run` 字段推导。
- `verdict` 只保留结论，不提前塞入 prompt 阶段的解释文本。
- 顶层只汇总所有有问题的组件，不强行指定单一主因。

这也更适合后续的组件级 repair prompt 工作流：

- 先采集组件事实。
- 再给每个组件做状态判定。
- 最后把所有问题组件一并交给后续修复系统。

- 但它还不是最终不可扩展的终版，后续可以在 barrier repair 邻域和 flow bridge quality 更强之后，再决定是否细分新状态
