# Probe 评估方案设计

## 目标

本文档给出 `probe_evaluation.py` 的第一版设计草案。

这个模块的目标不是替代 QLCoder 现有的最终 query 评估体系，而是在
`structural_extract.py` 生成的组件级 probe 基础上，增加一层类似
RuleRefiner 的中间诊断层，用来分析拆分后的 CodeQL query 组件：

- `source`
- `sink`
- `barrier`
- `flow`

这层诊断主要回答三个问题：

1. 当前 query 最可能坏在哪个组件上？
2. 这个组件的问题属于“缺失、为空、过噪、还是区分性不足”中的哪一种？
3. 下一轮 refinement 最应该采取什么修复动作？


## 设计原则

- probe 评估与当前最终 query 的成功判定解耦。
- 把 probe 当作“组件级事实采集器”，而不是最终漏洞检测器。
- 不同角色使用不同的判定规则，不能复用同一套标准。
- 输出结构化 JSON，供后续 localization 和 template-guided refinement 使用。


## 与现有 QLCoder 评估的关系

当前 QLCoder 的正式评估链路是围绕“最终漏洞 query”设计的：

- 在 `vulnerable` 和 `fixed` 数据库上运行 query
- 生成 CSV 和 SARIF
- 用 SARIF 结果对齐补丁相关的目标文件和目标方法
- 当 query 命中目标漏洞方法、且不再命中修复版本目标方法时，认为 query 成功

这套逻辑很适合最终 `path query`，但不适合 probe。

例如：

- `source_probe` 同时命中漏洞版和修复版，可能完全合理
- `barrier_probe` 在修复版命中更多，反而可能是一个正向信号
- `flow_probe` 表示的是桥接边，而不是最终漏洞告警

因此，probe 的评估应当作为独立的诊断层实现，而不是硬复用最终 query 的成功标准。


## 输出文件

建议的输出产物为：

- `probe_evaluation.json`

它应该针对“每个原始 query”生成一份，并与 probe 文件、编译结果、运行结果放在同一目录下。


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
  "localization": {
    "primary_suspect": "flow",
    "secondary_suspects": [
      "barrier"
    ],
    "diagnosis": "source/sink both present and aligned, but flow probe is empty; likely missing or broken flow modeling.",
    "confidence": 0.83,
    "failure_pattern": "source_sink_present_but_flow_missing"
  },
  "recommendations": [
    {
      "priority": 1,
      "component": "flow",
      "action": "expand_additional_flow_step",
      "rationale": "Source and sink are present, but no bridge edges are observed."
    }
  ]
}
```


## 字段说明

### `meta`

记录执行元信息，方便后续追踪和下游消费。

建议字段：

- `cve_id`
- `language`
- `generated_at`
- `query_path`
- `probe_dir`
- `evaluator`
- `codeql_path`


### `target_context`

记录从现有 patch ground truth 中提取出的目标文件和目标方法。

建议字段：

- `fixed_files`
- `fixed_methods`
- `target_file_count`
- `target_method_count`

这里应复用当前 QLCoder 评估器已经使用的目标定义，不另起一套标准。


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

如果原 query 中不存在某个角色，也建议在输出中显式保留该角色，并设置
`present_in_query = false`。


### `localization`

对所有组件事实进行聚合后的定位结论。

建议字段：

- `primary_suspect`
- `secondary_suspects`
- `diagnosis`
- `confidence`
- `failure_pattern`


### `recommendations`

供后续 refinement 使用的有序修复建议。

建议字段：

- `priority`
- `component`
- `action`
- `rationale`


## 单个组件的 Schema

每个组件的诊断块建议使用统一结构：

```json
{
  "present_in_query": true,
  "probe_path": "/abs/path/source_probe.ql",
  "compile_success": true,
  "compile_error": null,
  "run": {
    "vulnerable": {
      "success": true,
      "num_results": 3,
      "num_aligned_files": 1,
      "num_aligned_methods": 1,
      "aligned_files": [
        "src/main/java/com/example/A.java"
      ],
      "aligned_methods": [
        "src/main/java/com/example/A.java:A:foo"
      ]
    },
    "fixed": {
      "success": true,
      "num_results": 3,
      "num_aligned_files": 1,
      "num_aligned_methods": 1,
      "aligned_files": [
        "src/main/java/com/example/A.java"
      ],
      "aligned_methods": [
        "src/main/java/com/example/A.java:A:foo"
      ]
    }
  },
  "signals": {
    "vuln_has_hits": true,
    "fixed_has_hits": true,
    "delta_results": 0,
    "target_alignment_available": true,
    "hits_target_on_vuln": true,
    "hits_target_on_fixed": true,
    "discriminative": false
  },
  "verdict": {
    "status": "weak_but_present",
    "confidence": 0.67,
    "reason": "Source probe hits both versions and does not discriminate vulnerable from fixed."
  }
}
```


## 每个组件的最小必需字段

第一版实现建议至少包含：

- `present_in_query`
- `probe_path`
- `compile_success`
- `compile_error`
- `run.vulnerable.success`
- `run.vulnerable.num_results`
- `run.fixed.success`
- `run.fixed.num_results`
- `signals`
- `verdict`

像 `aligned_files`、`aligned_methods` 这类对齐字段，可以在第二版再增强，不必一开始就强依赖。


## 按组件的检验原则

从第二版开始，不应再把所有 probe 都当成“只看输出行数”的统一对象，而应按组件语义分别定义检验目标：

- `source` / `sink`
  - 重点检查是否命中目标文件、目标方法，以及覆盖了多少 patch 相关方法。
- `barrier`
  - 重点检查是否对齐修复逻辑，以及是否在 `fixed` 版本上比 `vulnerable` 更强。
- `flow`
  - 重点检查桥接边是否接近目标区域，是否连接 source 邻域与 sink 邻域，而不是只看边数多少。

换句话说：

- `source/sink` 更适合做 `target alignment`
- `barrier` 更适合做 `repair alignment`
- `flow` 更适合做 `bridge quality`


## 默认 Probe 生成策略

当前实现建议采用默认的 `hybrid` probe 生成策略，而不是把四类组件强行统一成同一种 `@kind`：

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
  - 更适合通过 `SARIF + locations` 接入现有评估链路
  - 更容易计算 `aligned_files`、`aligned_methods`、`target_method_coverage`
- `barrier`
  - 更像修复信号或抑制信号，不应默认按“漏洞告警”语义解释
- `flow`
  - 本质上是 `n1 -> n2` 的桥接边事实，天然更适合 `table` 形式，而不是单点 `problem`

因此，当前代码中的默认行为应保持为：

- `source/sink -> problem`
- `barrier/flow -> table`

如果后续需要做更细的实验，可以额外支持：

- `all-table`
- `all-problem`
- `hybrid`

但默认值仍建议保留 `hybrid`。


## 角色级判定规则

probe 评估不能对所有角色使用同一套规则，必须按语义分别判断。


### Source Rules

可能状态：

- `missing_component`
  - 原 query 中没有 `isSource`
- `compile_failed`
  - source probe 编译失败
- `empty`
  - `vuln_num_results = 0` 且 `fixed_num_results = 0`
- `only_fixed`
  - `vuln_num_results = 0` 且 `fixed_num_results > 0`
- `weak_but_present`
  - 两侧都有结果，但区分度很弱
- `good_anchor`
  - 漏洞版有命中，且对 target 的对齐看起来合理

第二版建议新增的检查字段：

- `num_aligned_files`
- `num_aligned_methods`
- `aligned_files`
- `aligned_methods`
- `target_file_coverage`
- `target_method_coverage`

解释规则：

- `0/0` 通常意味着 source 建模过窄、类型不对，或者入口选错
- `vuln > 0` 且 `fixed > 0` 说明 source 存在，但区分能力较弱
- `vuln > 0` 且 `fixed = 0` 是很强的信号，但对 source 来说不是硬性要求
- 对 `source` 来说，最重要的不只是“是否有结果”，而是“这些 source 是否真正落在补丁相关方法或补丁相关文件附近”
- 如果 `source` 结果很多，但 `aligned_methods = []`，应优先怀疑 source 语义偏离漏洞入口
- 如果 `source` 在 `vulnerable/fixed` 两边都很多，但能稳定命中目标方法，说明 source 可能不是主问题


### Sink Rules

可能状态：

- `missing_component`
- `compile_failed`
- `empty`
- `only_fixed`
- `weak_but_present`
- `good_anchor`

第二版建议新增的检查字段：

- `num_aligned_files`
- `num_aligned_methods`
- `aligned_files`
- `aligned_methods`
- `target_file_coverage`
- `target_method_coverage`

解释规则：

- 如果 sink 是 `0/0`，通常应优先怀疑 sink 层
- 没有 sink 识别，后续 flow 再强也很难恢复最终 query 行为
- `sink` 比 `source` 更适合做“是否命中目标危险方法”的检查
- 如果 sink 结果不为空，但完全不落在目标方法或目标文件附近，通常说明 sink 定义偏了
- 如果 `source` 命中目标区域而 `sink` 不命中，则应优先怀疑 sink，而不是 flow
- 如果 sink 只在 `fixed` 上更强，应视为方向错误或危险点建模反了


### Barrier Rules

`barrier` 不能沿用最终 query 的“fixed 命中就是误报”那套逻辑。

可能状态：

- `missing_component`
- `compile_failed`
- `absent`
  - `0/0`
- `repair_only`
  - `vuln = 0`，`fixed > 0`
- `non_discriminative`
  - 两侧命中情况相似
- `overblocking_suspect`
  - 漏洞版 barrier 信号很强，但原 query 仍然 `0/0`
- `useful_repair_signal`
  - 修复版 barrier 证据明显强于漏洞版

第二版建议新增的检查字段：

- `num_repair_aligned_files`
- `num_repair_aligned_methods`
- `repair_aligned_files`
- `repair_aligned_methods`
- `repair_signal_strength`
- `overblocking_suspect`

解释规则：

- `fixed > vuln` 往往是一个好信号，说明 barrier 更接近修复逻辑
- `vuln >> fixed` 更值得怀疑，可能说明 barrier 过强，把漏洞路径压掉了
- `barrier` 的重点不是“有没有命中 target method”，而是“有没有命中修复逻辑”
- 对 `barrier`，应优先检查是否落在修复新增/修复增强的方法附近，例如 `validateXxx`、`normalize`、`sanitize` 等修复 helper
- 如果 `barrier` 在 `fixed` 中命中更多，且这些命中靠近修复方法，应视为正向修复信号
- 如果 `barrier` 在 `vulnerable` 中命中很多，而原始 query 仍为 `0/0`，应判为 `overblocking_suspect`


### Flow Rules

可能状态：

- `missing_component`
  - 原 query 中没有 `isAdditionalFlowStep`
- `compile_failed`
- `empty`
  - `0/0`
- `weak_bridge`
- `noisy_bridge`
- `useful_bridge`
- `likely_not_needed`

第二版建议新增的检查字段：

- `num_edges_touching_target_files`
- `num_edges_touching_target_methods`
- `num_edges_connecting_source_sink_neighborhood`
- `bridge_density`
- `bridge_noise_ratio`

解释规则：

- 如果 source 和 sink 都存在，但 flow 是 `0/0`，flow 往往是主嫌疑
- flow probe 表示桥接事实，而不是最终漏洞告警
- `flow` 不适合只看“命中了哪个目标方法”，因为它本质上是 `n1 -> n2` 的边事实
- 对 `flow`，更重要的是检查这些边是否靠近目标文件/目标方法，尤其是是否把 source 邻域和 sink 邻域连接起来
- 如果 flow 边很多，但大多不接近目标区域，应判为 `noisy_bridge`
- 如果 source、sink 都能命中目标区域，但 `num_edges_connecting_source_sink_neighborhood = 0`，应优先怀疑 flow 建模断裂
- 如果 query 没有定义 `isAdditionalFlowStep`，但原始 query 本身有稳定命中，可以保留 `likely_not_needed`


## 聚合定位规则

顶层 `localization.primary_suspect` 应根据跨角色组合模式推断。

推荐优先级如下：

1. `source = empty`
   - `failure_pattern = source_missing`

2. `source present` and `sink = empty`
   - `failure_pattern = sink_missing`

3. `source present` and `sink present` and `flow = empty`
   - `failure_pattern = source_sink_present_but_flow_missing`

4. `source present`, `sink present`, `flow present`, and barrier strongly
   suppresses vulnerable-side behavior while original query is still `0/0`
   - `failure_pattern = overblocking_barrier`

5. all components present, but vulnerable and fixed behavior are very similar
   - `failure_pattern = low_discrimination`

6. all probes look healthy but the original query still returns `0/0`
   - `failure_pattern = final_query_constraint_issue`


## Confidence 启发式

第一版建议保持简单、可解释，不要上来就做复杂统计模型。

建议基础分值：

- `compile_failed`: `0.95`
- component `0/0` with upstream/downstream support: `0.90`
- `only_fixed`: `0.85`
- similar vulnerable/fixed counts: `0.60`

调节项：

- 如果 target alignment 可用并支持当前诊断：`+0.10`
- 如果 target alignment 不可用：不加分
- 如果 counts 明显嘈杂、跨组件不一致：`-0.10`


## Target Alignment 策略

从第二版开始，应把“对齐”拆成三类，而不是继续用一个统一的 `target_alignment` 概念：

- `target alignment`
  - 主要用于 `source` / `sink`
  - 检查 probe 结果是否落在目标文件、目标方法中
- `repair alignment`
  - 主要用于 `barrier`
  - 检查 probe 结果是否落在修复逻辑相关的方法、文件中
- `bridge quality`
  - 主要用于 `flow`
  - 检查桥接边是否接近目标区域，以及是否连接 source 邻域和 sink 邻域

因此，`target alignment` 应作为增强项，而不是第一版的硬依赖。

建议字段：

```json
{
  "target_alignment_available": true,
  "hits_target_on_vuln": true,
  "hits_target_on_fixed": false
}
```

如果暂时拿不到稳定的对齐信息：

```json
{
  "target_alignment_available": false,
  "hits_target_on_vuln": null,
  "hits_target_on_fixed": null
}
```

这样第一版就可以先依赖 count pattern 做诊断，同时为后续文件级、方法级对齐预留空间。

第二版推荐的增强字段如下。

对 `source/sink`：

```json
{
  "num_aligned_files": 2,
  "num_aligned_methods": 3,
  "aligned_files": [
    "src/main/java/com/example/A.java"
  ],
  "aligned_methods": [
    "src/main/java/com/example/A.java:A:foo"
  ],
  "target_file_coverage": 0.5,
  "target_method_coverage": 0.3
}
```

对 `barrier`：

```json
{
  "num_repair_aligned_files": 1,
  "num_repair_aligned_methods": 2,
  "repair_aligned_methods": [
    "src/main/java/com/example/A.java:A:validateFilePath"
  ],
  "repair_signal_strength": 0.8,
  "overblocking_suspect": false
}
```

对 `flow`：

```json
{
  "num_edges_touching_target_files": 12,
  "num_edges_touching_target_methods": 4,
  "num_edges_connecting_source_sink_neighborhood": 2,
  "bridge_density": 0.15,
  "bridge_noise_ratio": 0.87
}
```

其中：

- `bridge_density`
  - 可理解为“目标区域附近的有效桥接边”占全部 flow probe 边的比例
- `bridge_noise_ratio`
  - 可理解为“明显不接近目标区域的噪声边”占比
- 这两个值第一版不必强行计算，但第二版应作为重点增强方向


## Recommendation Action 枚举

为了方便后续 prompt 模板和 refinement 逻辑复用，建议把修复动作离散成固定词表。

建议动作：

- `expand_source_definition`
- `narrow_source_definition`
- `expand_sink_definition`
- `narrow_sink_definition`
- `expand_additional_flow_step`
- `remove_overly_broad_barrier`
- `specialize_barrier_to_fixed_only`
- `inspect_final_where_constraints`
- `inspect_path_graph_usage`
- `inspect_helper_predicates`


## 第一版实现范围

第一版建议保持“小而稳”，优先实现核心诊断能力。

建议范围：

- probe compilation success
- vulnerable and fixed result counts
- original query result counts
- cross-component localization rules
- primary suspect inference
- structured repair recommendations

延后到后续版本：

- stable file-level target alignment
- stable method-level target alignment
- source/sink 的目标方法覆盖率计算
- barrier 的修复逻辑对齐与 overblocking 检查
- flow 的 source-sink 邻域桥接质量分析
- more advanced confidence scoring
- ranking multiple candidate failure modes with learned weights


## 第二版实现重点

在第一版“计数级诊断”稳定后，第二版建议优先补这三类能力：

在 probe 生成层面，当前默认前提是：

- `source/sink` 已默认生成为 `problem`
- `barrier/flow` 已默认生成为 `table`

1. `source/sink` 的目标命中检查
   - 复用现有 `evaluation.py` 的路径和方法映射逻辑
   - 计算 `aligned_files`、`aligned_methods`、`target_method_coverage`

2. `barrier` 的修复信号检查
   - 对齐修复 helper、修复新增校验方法、修复新增文件位置
   - 识别 `fixed > vulnerable` 的正向修复信号
   - 识别 `vulnerable >> fixed` 的 `overblocking_suspect`

3. `flow` 的桥接质量检查
   - 检查 flow 边是否接近 target 区域
   - 检查 flow 边是否连接 source 邻域与 sink 邻域
   - 区分“有边但很噪”与“确实形成有效桥接”


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
      "compile_success": true,
      "vuln_num_results": 5,
      "fixed_num_results": 5,
      "status": "weak_but_present"
    },
    "sink": {
      "compile_success": true,
      "vuln_num_results": 2,
      "fixed_num_results": 2,
      "status": "weak_but_present"
    },
    "barrier": {
      "compile_success": true,
      "vuln_num_results": 8,
      "fixed_num_results": 1,
      "status": "overblocking_suspect"
    },
    "flow": {
      "compile_success": true,
      "vuln_num_results": 0,
      "fixed_num_results": 0,
      "status": "empty"
    }
  },
  "localization": {
    "primary_suspect": "flow",
    "failure_pattern": "source_sink_present_but_flow_missing",
    "confidence": 0.90
  },
  "recommendations": [
    {
      "component": "flow",
      "action": "expand_additional_flow_step"
    }
  ]
}
```


## 总结

这套设计的核心思想是：

- 不把 probe 当最终告警结果
- 而是把 probe 当作“组件级事实”

这也是它和 RuleRefiner 风格工作流最一致的地方：

- 先采集局部事实
- 再定位失败组件
- 最后把诊断结果转成受约束的修复建议

第一版实现的重点应放在：

- 结构稳定
- 规则可解释
- 诊断结果可直接进入后续 refinement

而不是一开始就追求非常完整的 precision / recall 统计。
