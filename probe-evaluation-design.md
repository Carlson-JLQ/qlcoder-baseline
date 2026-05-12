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

## 组件级返回格式

组件级反馈建议统一组织成一个 JSON 对象，并且只保留三个字段：

```json
{
  "Component": "source",
  "Repair Prompt": {
    "en": "The source probe has matches, but it does not behave like a target-aligned vulnerable-side source.",
    "zh": "当前 source probe 虽然有结果，但它并不像一个与目标对齐的漏洞侧 source。"
  },
  "Supporting Facts": {
    "present_in_query": true,
    "compile_success": true,
    "compile_error": null,
    "run": {
      "vulnerable": {
        "success": true,
        "num_results": 12,
        "error": null,
        "num_aligned_files": 1,
        "num_aligned_methods": 0,
        "aligned_files": [
          "src/main/java/com/example/A.java"
        ],
        "aligned_methods": [],
        "target_file_coverage": 0.5,
        "target_method_coverage": 0.0,
        "hit_files": [
          "src/main/java/com/example/A.java",
          "src/main/java/com/example/B.java",
          "src/main/java/com/example/C.java",
          "src/main/java/com/example/D.java",
          "src/main/java/com/example/E.java"
        ],
        "hit_methods": [
          "src/main/java/com/example/A.java:A:foo",
          "src/main/java/com/example/B.java:B:bar",
          "src/main/java/com/example/C.java:C:baz",
          "src/main/java/com/example/D.java:D:qux",
          "src/main/java/com/example/E.java:E:quux"
        ]
      },
      "fixed": {
        "success": true,
        "num_results": 10,
        "error": null,
        "num_aligned_files": 0,
        "num_aligned_methods": 0,
        "aligned_files": [],
        "aligned_methods": [],
        "target_file_coverage": 0.0,
        "target_method_coverage": 0.0,
        "hit_files": [
          "src/main/java/com/example/C.java",
          "src/main/java/com/example/D.java",
          "src/main/java/com/example/E.java",
          "src/main/java/com/example/F.java",
          "src/main/java/com/example/G.java"
        ],
        "hit_methods": [
          "src/main/java/com/example/C.java:C:baz",
          "src/main/java/com/example/D.java:D:qux",
          "src/main/java/com/example/E.java:E:quux",
          "src/main/java/com/example/F.java:F:corge",
          "src/main/java/com/example/G.java:G:grault"
        ]
      }
    },
    "verdict": {
      "status": "off_target",
      "confidence": 0.87
    }
  }
}
```

说明：

- `Component`
  - 只返回组件名称本身，例如 `source`、`sink`、`barrier`、`flow`。
- `Repair Prompt`
  - 直接返回对应状态的 prompt。
  - 如果该状态不属于后续修复主路径，则这里可以返回 `null`。
- `Supporting Facts`
  - 直接返回“裁剪后的组件 schema”。
  - 不要改变组件 schema 本身，只是在返回结果里排除少数字段。
  - 默认不包含以下字段：
    - `generation_mode`
    - `source_predicate`
    - `sarif_path`
    - `probe_path`
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。

## Source Status 映射规则

### `missing_component`

- 条件：`present_in_query = false`
- `Component`
  - `source`
- `Repair Prompt`
  - 返回 `source.missing_component`。
  - 具体 prompt 内容从 `codeql-repair-templates.md` 的对应条目读取。
- `Supporting Facts`
  - 返回当前 `source` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
### `compile_failed`

- 条件：`present_in_query = true` 且 `compile_success = false`
- `Component`
  - `source`
- `Repair Prompt`
  - 返回 `source.compile_failed`。
  - 具体 prompt 内容从 `codeql-repair-templates.md` 的对应条目读取。
- `Supporting Facts`
  - 返回当前 `source` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
### `empty`

- 条件：`compile_success = true` 且 `run.vulnerable.num_results = 0` 且 `run.fixed.num_results = 0`
- `Component`
  - `source`
- `Repair Prompt`
  - 返回 `source.empty`。
  - 具体 prompt 内容从 `codeql-repair-templates.md` 的对应条目读取。
- `Supporting Facts`
  - 返回当前 `source` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
### `only_fixed`

- 条件：`compile_success = true` 且 `run.vulnerable.num_results = 0` 且 `run.fixed.num_results > 0`
- `Component`
  - `source`
- `Repair Prompt`
  - 返回 `source.only_fixed`。
  - 具体 prompt 内容从 `codeql-repair-templates.md` 的对应条目读取。
- `Supporting Facts`
  - 返回当前 `source` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
### `off_target`

- 条件：`compile_success = true`，至少一侧有结果，但 `run.vulnerable.num_aligned_methods = 0` 且未满足 `empty`、`only_fixed`、`good_anchor`
- `Component`
  - `source`
- `Repair Prompt`
  - 返回 `source.off_target`。
  - 具体 prompt 内容从 `codeql-repair-templates.md` 的对应条目读取。
- `Supporting Facts`
  - 返回当前 `source` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
### `good_anchor`

- 条件：`compile_success = true` 且 `run.vulnerable.num_aligned_methods > 0` 且 `run.fixed.num_aligned_methods = 0`
- `Component`
  - `source`
- `Repair Prompt`
  - 返回 `null`。
- `Supporting Facts`
  - 返回当前 `source` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
### `weak_but_present`

- 条件：`compile_success = true`，至少一侧有结果，且未满足 `empty`、`only_fixed`、`off_target`、`good_anchor`
- `Component`
  - `source`
- `Repair Prompt`
  - 返回 `source.weak_but_present`。
  - 具体 prompt 内容从 `codeql-repair-templates.md` 的对应条目读取。
- `Supporting Facts`
  - 返回当前 `source` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
### `others`

- 条件：未落入以上任何一种 `source` 状态
- `Component`
  - `source`
- `Repair Prompt`
  - 返回 `source.others`。
  - 具体 prompt 内容从 `codeql-repair-templates.md` 的对应条目读取。
- `Supporting Facts`
  - 返回当前 `source` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
## Sink Status 映射规则

### `missing_component`

- 条件：`present_in_query = false`
- `Component`
  - `sink`
- `Repair Prompt`
  - 返回 `sink.missing_component`。
  - 具体 prompt 内容从 `codeql-repair-templates.md` 的对应条目读取。
- `Supporting Facts`
  - 返回当前 `sink` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
### `compile_failed`

- 条件：`present_in_query = true` 且 `compile_success = false`
- `Component`
  - `sink`
- `Repair Prompt`
  - 返回 `sink.compile_failed`。
  - 具体 prompt 内容从 `codeql-repair-templates.md` 的对应条目读取。
- `Supporting Facts`
  - 返回当前 `sink` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
### `empty`

- 条件：`compile_success = true` 且 `run.vulnerable.num_results = 0` 且 `run.fixed.num_results = 0`
- `Component`
  - `sink`
- `Repair Prompt`
  - 返回 `sink.empty`。
  - 具体 prompt 内容从 `codeql-repair-templates.md` 的对应条目读取。
- `Supporting Facts`
  - 返回当前 `sink` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
### `only_fixed`

- 条件：`compile_success = true` 且 `run.vulnerable.num_results = 0` 且 `run.fixed.num_results > 0`
- `Component`
  - `sink`
- `Repair Prompt`
  - 返回 `sink.only_fixed`。
  - 具体 prompt 内容从 `codeql-repair-templates.md` 的对应条目读取。
- `Supporting Facts`
  - 返回当前 `sink` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
### `off_target`

- 条件：`compile_success = true`，至少一侧有结果，但 `run.vulnerable.num_aligned_methods = 0` 且未满足 `empty`、`only_fixed`、`good_anchor`
- `Component`
  - `sink`
- `Repair Prompt`
  - 返回 `sink.off_target`。
  - 具体 prompt 内容从 `codeql-repair-templates.md` 的对应条目读取。
- `Supporting Facts`
  - 返回当前 `sink` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
### `good_anchor`

- 条件：`compile_success = true` 且 `run.vulnerable.num_aligned_methods > 0` 且 `run.fixed.num_aligned_methods = 0`
- `Component`
  - `sink`
- `Repair Prompt`
  - 返回 `null`。
- `Supporting Facts`
  - 返回当前 `sink` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
### `weak_but_present`

- 条件：`compile_success = true`，至少一侧有结果，且未满足 `empty`、`only_fixed`、`off_target`、`good_anchor`
- `Component`
  - `sink`
- `Repair Prompt`
  - 返回 `sink.weak_but_present`。
  - 具体 prompt 内容从 `codeql-repair-templates.md` 的对应条目读取。
- `Supporting Facts`
  - 返回当前 `sink` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
### `others`

- 条件：未落入以上任何一种 `sink` 状态
- `Component`
  - `sink`
- `Repair Prompt`
  - 返回 `sink.others`。
  - 具体 prompt 内容从 `codeql-repair-templates.md` 的对应条目读取。
- `Supporting Facts`
  - 返回当前 `sink` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
## Barrier Status 映射规则

### `missing_component`

- 条件：`present_in_query = false`
- `Component`
  - `barrier`
- `Repair Prompt`
  - 返回 `null`。
- `Supporting Facts`
  - 返回当前 `barrier` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
### `compile_failed`

- 条件：`present_in_query = true` 且 `compile_success = false`
- `Component`
  - `barrier`
- `Repair Prompt`
  - 返回 `barrier.compile_failed`。
  - 具体 prompt 内容从 `codeql-repair-templates.md` 的对应条目读取。
- `Supporting Facts`
  - 返回当前 `barrier` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
### `absent`

- 条件：`compile_success = true` 且 `run.vulnerable.num_results = 0` 且 `run.fixed.num_results = 0`
- `Component`
  - `barrier`
- `Repair Prompt`
  - 返回 `null`。
- `Supporting Facts`
  - 返回当前 `barrier` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
### `repair_only`

- 条件：`compile_success = true` 且 `run.vulnerable.num_results = 0` 且 `run.fixed.num_results > 0`
- `Component`
  - `barrier`
- `Repair Prompt`
  - 返回 `null`。
- `Supporting Facts`
  - 返回当前 `barrier` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
### `useful_repair_signal`

- 条件：`compile_success = true` 且 `run.fixed.num_results > run.vulnerable.num_results`
- `Component`
  - `barrier`
- `Repair Prompt`
  - 返回 `null`。
- `Supporting Facts`
  - 返回当前 `barrier` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
### `overblocking_suspect`

- 条件：`compile_success = true` 且 `run.vulnerable.num_results > run.fixed.num_results * 2`，并且 `original_query.vuln_num_results = 0` 且 `original_query.fixed_num_results = 0`
- `Component`
  - `barrier`
- `Repair Prompt`
  - 返回 `barrier.overblocking_suspect`。
  - 具体 prompt 内容从 `codeql-repair-templates.md` 的对应条目读取。
- `Supporting Facts`
  - 返回当前 `barrier` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
### `non_discriminative`

- 条件：`compile_success = true` 且 `run.vulnerable.num_results > 0` 且 `run.fixed.num_results > 0`
- `Component`
  - `barrier`
- `Repair Prompt`
  - 返回 `barrier.non_discriminative`。
  - 具体 prompt 内容从 `codeql-repair-templates.md` 的对应条目读取。
- `Supporting Facts`
  - 返回当前 `barrier` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
### `others`

- 条件：未落入以上任何一种 `barrier` 状态
- `Component`
  - `barrier`
- `Repair Prompt`
  - 返回 `barrier.others`。
  - 具体 prompt 内容从 `codeql-repair-templates.md` 的对应条目读取。
- `Supporting Facts`
  - 返回当前 `barrier` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
### Barrier 状态设计说明

- `absent`、`repair_only`、`useful_repair_signal` 默认不进入 `problem_components`。
- `overblocking_suspect`、`non_discriminative`、`others` 默认进入 `problem_components`。
- `missing_component` 是否进入修复主路径，取决于后续实现是否把“缺失 barrier”视为问题组件。

## Flow Status 映射规则

### `missing_component`

- 条件：`present_in_query = false` 且 `original_query.vuln_num_results = 0` 且 `original_query.fixed_num_results = 0`
- `Component`
  - `flow`
- `Repair Prompt`
  - 返回 `flow.missing_component`。
  - 具体 prompt 内容从 `codeql-repair-templates.md` 的对应条目读取。
- `Supporting Facts`
  - 返回当前 `flow` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
### `likely_not_needed`

- 条件：`present_in_query = false` 且 (`original_query.vuln_num_results > 0` 或 `original_query.fixed_num_results > 0`)
- `Component`
  - `flow`
- `Repair Prompt`
  - 返回 `null`。
- `Supporting Facts`
  - 返回当前 `flow` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
### `compile_failed`

- 条件：`present_in_query = true` 且 `compile_success = false`
- `Component`
  - `flow`
- `Repair Prompt`
  - 返回 `flow.compile_failed`。
  - 具体 prompt 内容从 `codeql-repair-templates.md` 的对应条目读取。
- `Supporting Facts`
  - 返回当前 `flow` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
### `empty`

- 条件：`compile_success = true` 且 `run.vulnerable.num_results = 0` 且 `run.fixed.num_results = 0`
- `Component`
  - `flow`
- `Repair Prompt`
  - 返回 `flow.empty`。
  - 具体 prompt 内容从 `codeql-repair-templates.md` 的对应条目读取。
- `Supporting Facts`
  - 返回当前 `flow` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
### `useful_bridge`

- 条件：`compile_success = true` 且 `run.vulnerable.num_results > 0` 且 `run.fixed.num_results = 0`
- `Component`
  - `flow`
- `Repair Prompt`
  - 返回 `null`。
- `Supporting Facts`
  - 返回当前 `flow` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
### `noisy_bridge`

- 条件：`compile_success = true` 且 `run.vulnerable.num_results > 0` 且 `run.fixed.num_results > 0`，并且两侧数量接近
- `Component`
  - `flow`
- `Repair Prompt`
  - 返回 `flow.noisy_bridge`。
  - 具体 prompt 内容从 `codeql-repair-templates.md` 的对应条目读取。
- `Supporting Facts`
  - 返回当前 `flow` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
### `weak_bridge`

- 条件：`compile_success = true` 且至少一侧有结果，但未满足 `empty`、`useful_bridge`、`noisy_bridge`
- `Component`
  - `flow`
- `Repair Prompt`
  - 返回 `flow.weak_bridge`。
  - 具体 prompt 内容从 `codeql-repair-templates.md` 的对应条目读取。
- `Supporting Facts`
  - 返回当前 `flow` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
### `others`

- 条件：未落入以上任何一种 `flow` 状态
- `Component`
  - `flow`
- `Repair Prompt`
  - 返回 `flow.others`。
  - 具体 prompt 内容从 `codeql-repair-templates.md` 的对应条目读取。
- `Supporting Facts`
  - 返回当前 `flow` 组件的裁剪版 schema。
  - 默认保留 `present_in_query`、`compile_success`、`compile_error`、`run`、`verdict` 这些结构。
  - 不包含 `generation_mode`、`source_predicate`、`sarif_path`、`probe_path`。
  - `hit_files` 和 `hit_methods` 如果出现，都只保留前 `5` 个。
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
