# Probe Supporting Facts / Problem Components 章节设计

## 1. 文档用途

本文档**不是**设计 `probe_evaluation.json` 的完整输出 schema；完整 probe 评估设计仍以
`probe-evaluation-design.md:1` 为准。

本文档的用途更具体：

- 用于重构 Phase 3 修复提示词里的 `# Problem Components` 章节。
- 目标对象就是类似 `output/vulnsynth_CVE-2025-49656_20260515_072659_gpt-5.4_full/results/phase3_iter_2_prompt.txt` 这样的完整 prompt。
- 其他章节（如 `Environment Notes`、`Objective`、`Previous Query`、`Task`、`Checklist` 等）**保持不变**。
- 只是在原有 prompt 中插入/替换一个规范化的 `# Problem Components` 章节。

换句话说，这个文档回答的问题是：

> 如何把 probe 评估结果，稳定地转换成一个更适合后续修复 agent 消费的 `# Problem Components` 章节。


## 2. 设计边界

### 2.1 本文档负责什么

- 固定 `# Problem Components` 章节的用途。
- 固定每个组件块的展示格式。
- 解释 `Status`、`Repair direction`、`Facts abstract`、`Supporting Facts` 的语义。
- 规定不同 status 下 `Supporting Facts` 当前应该展示哪些字段。

### 2.2 本文档暂时不负责什么

- 暂时**不改代码**。
- 暂时**不重构** `probe_evaluation.py` 的原始 JSON schema。
- 暂时**不改** Phase 3 prompt 的其他章节。
- 暂时**不定义** renderer / selector 的具体实现细节。


## 3. 与 probe 评估设计的关系

`probe_evaluation.py` 的职责，是为每个组件输出运行事实并给出状态判定；这层设计在
`probe-evaluation-design.md:14` 已经说明，其核心问题是：

1. 组件是否存在、是否能独立编译、在漏洞版/修复版运行表现如何。
2. 组件当前落入什么状态。
3. 状态由哪些事实支撑。
4. 哪些组件值得进入后续修复 prompt。

因此，`# Problem Components` 章节应被理解为：

- 它不是新的评估层；
- 它是 probe 评估结果的**提示词投影层**；
- 它只挑出“问题组件”，并把每个问题组件重排成更适合 LLM 消费的结构化块。


## 4. 章节级目标

`# Problem Components` 章节的目标只有三个：

1. 明确告诉后续 agent：**哪些组件有问题**。
2. 明确告诉后续 agent：**每个组件为什么会被判成这个状态**。
3. 明确告诉后续 agent：**当前应该优先怎么修这个组件**。

因此，这个章节必须做到：

- 比原始 `probe_evaluation.json` 更短；
- 比只给 status 列表更有解释力；
- 比完整复制原始组件 JSON 更适合 prompt；
- 尽量避免无关冗余，但**当前 Supporting Facts 先沿用已有原始字段风格**，只按 status 选择展示范围。


## 5. 固定章节结构

Phase 3 prompt 中新增/替换后的 `# Problem Components` 章节统一写成：

```text
# Problem Components

## Supporting Facts Field Reference
- <unified field explanations>

## <role>
- Status: `<status>`
- Repair direction:
  <repair prompt text>
- Facts abstract:
  <status trigger summary>
- Supporting Facts
```json
{
  ...status-aware supporting facts...
}
```
```

说明：

- `# Problem Components` 下只展示**问题组件**。
- `## Supporting Facts Field Reference` 是放在 `# Problem Components` 下、各组件块之前的统一字段解释章节。
- 这个统一字段解释章节只出现一次，用来帮助 agent 理解后续所有组件块里的字段语义。
- 组件顺序固定为：`source` → `sink` → `barrier` → `flow`。
- 默认不展示 `good_anchor`、`useful_bridge` 等非问题状态，除非未来明确要求进入 prompt。


## 6. 组件块字段语义

### 6.1 `Status`

`Status` 是 probe 评估对该组件的结论标签。

- 它来自组件状态分类逻辑，例如 `vulnsynth/probe_evaluation.py:678`。
- 它只负责给出结论，不解释原因，也不说明怎么修。


### 6.2 `Repair direction`

`Repair direction` 就是**repair 提示词本身**。

它应来自当前的 repair prompt 选择逻辑，也就是按照：

- `role`
- `status`

选择对应的 repair prompt 文本。

它回答的问题是：

> “既然组件落入这个状态，后续 agent 应该优先怎么改？”

要求：

- 它是动作导向的。
- 它可以是自然语言多句文本。
- 它不负责重复原始事实。
- 它不负责复述 status 的触发条件。


### 6.3 `Facts abstract`

`Facts abstract` 是**这个 status 的触发条件摘要**。

它回答的问题是：

> “为什么这个组件会被判成当前这个 status？”

要求：

- 它必须是**诊断性描述**，不是修复建议。
- 它应直接概括 status 的触发条件。
- 它应尽量控制在 **1~2 句**。
- 它不展开完整字段细节；完整证据留给 `Supporting Facts`。

也就是说：

- `Repair direction` = **怎么修**
- `Facts abstract` = **为什么这么判**


### 6.4 `Supporting Facts`

`Supporting Facts` 是**支撑当前 status 的详细事实块**。

它回答的问题是：

> “哪些现有 probe 运行字段足以支撑当前 status 判定？”

这里特别说明：

- 当前阶段，`Supporting Facts` **先按照已有设计风格保留原始字段结构**；
- 也就是尽量沿用现有组件 JSON 中的字段层级，例如：
  - `present_in_query`
  - `compile_success`
  - `compile_error`
  - `run.vulnerable.*`
  - `run.fixed.*`
- 当前**不额外引入**新的中间抽象层字段名（例如新造一层 `diagnosis_summary`、`evidence`、`alignment` 独立 schema）。

换句话说，当前文档的约束是：

> Supporting Facts 先沿用原始字段风格，只按不同 status 选择不同字段范围，而不是改造成一套新的抽象 schema。


## 7. 当前 Supporting Facts 的总体原则

在不改变原始字段风格的前提下，`Supporting Facts` 遵循以下原则：

1. 字段名尽量沿用现有 probe 评估结果中的原始字段。
2. 当前以 `present_in_query / compile_success / compile_error / run` 这一层级为主。
3. `run` 下仍使用：
   - `vulnerable`
   - `fixed`
4. `vulnerable` / `fixed` 下可以继续使用原始字段，例如：
   - `num_results`
   - `num_aligned_files`
   - `num_aligned_methods`
   - `aligned_files`
   - `aligned_methods`
   - `target_file_coverage`
   - `target_method_coverage`
   - `hit_files`
   - `hit_methods`
5. 但不同 status 不需要展示同样多的字段。
6. 当前重点不是“重新发明字段”，而是“把字段裁到刚好够解释该状态”。


## 8. 当前 Problem Components 章节覆盖的状态范围

当前章节优先覆盖“问题状态”，与现有问题组件聚合思路一致，包括：

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

补充说明：

- `run_failed` 在评估逻辑中是合法状态（见 `vulnsynth/probe_evaluation.py:700`），本文档保留它的展示约定。
- `good_anchor`、`absent`、`repair_only`、`useful_repair_signal`、`useful_bridge`、`likely_not_needed` 默认不进入最终 `# Problem Components` 章节。


## 9. Supporting Facts 字段统一解释

这个章节对应的是最终 prompt 里放在 `# Problem Components` 下方、各组件块上方的统一说明区。

推荐结构如下：

```text
# Problem Components

## Supporting Facts Field Reference
- `present_in_query`: whether the component predicate exists in the current query.
- `compile_success`: whether the standalone component probe compiles successfully.
- `compile_error`: compile error message when standalone probe compilation fails.
- `run.vulnerable`: probe results on the vulnerable database.
- `run.fixed`: probe results on the fixed database.
- `success`: whether this side finishes execution successfully.
- `error`: runtime failure reason for this side when execution fails.
- `num_results`: total number of probe results on this side.
- `num_aligned_files`: number of hit files that overlap with target fixed-side files.
- `num_aligned_methods`: number of hit methods that overlap with target fixed-side methods.
- `aligned_files`: overlapping target files found on this side.
- `aligned_methods`: overlapping target methods found on this side.
- `target_file_coverage`: aligned file count divided by total target file count.
- `target_method_coverage`: aligned method count divided by total target method count.
- `hit_files`: top hit files returned by this probe on this side.
- `hit_methods`: top hit methods returned by this probe on this side.
```

这个统一说明区的作用：

- 避免在每个组件块里重复解释字段。
- 让 agent 先建立字段语义，再阅读具体组件事实。
- 保持 `Supporting Facts` 仍然使用原始字段风格，而不需要再对字段名做额外包装。

### 9.1 字段解释写法要求

- 解释应使用统一、简短、面向 agent 的自然语言。
- 每个字段只解释“它表示什么”，不要在这里解释具体 status 触发逻辑。
- status 触发逻辑仍然放在各组件的 `Facts abstract` 中。
- 如果某个字段只在部分角色/状态里常见，也仍然可以在统一说明区解释一次。

### 9.2 统一字段解释的推荐文案

下面是建议直接放进 prompt 的统一字段解释文案：

#### 顶层字段

- `present_in_query`: whether the current query explicitly contains this component.
- `compile_success`: whether the standalone component probe compiles successfully.
- `compile_error`: the compile error message for this component probe when compilation fails.

#### `run` 级字段

- `run.vulnerable`: execution facts for this component probe on the vulnerable database.
- `run.fixed`: execution facts for this component probe on the fixed database.

#### 单侧运行字段（`run.vulnerable.*` / `run.fixed.*`）

- `success`: whether execution on this side succeeds.
- `error`: runtime error message on this side when execution fails.
- `num_results`: total number of results returned on this side.
- `num_aligned_files`: how many hit files on this side overlap with target files.
- `num_aligned_methods`: how many hit methods on this side overlap with target methods.
- `aligned_files`: the overlapping target files found on this side.
- `aligned_methods`: the overlapping target methods found on this side.
- `target_file_coverage`: fraction of target files covered by this side (`num_aligned_files / total_target_files`).
- `target_method_coverage`: fraction of target methods covered by this side (`num_aligned_methods / total_target_methods`).
- `hit_files`: representative files hit by this probe on this side.
- `hit_methods`: representative methods hit by this probe on this side.

### 9.3 对 agent 的理解提示

为了减少误解，可以在统一字段解释后追加一段简短提示：

```text
How to read Supporting Facts:
- For source/sink, alignment fields are usually the most important signal.
- For barrier/flow, result counts and cross-version comparison are usually more important than target alignment.
- Empty arrays or zero values do not necessarily mean the component is useless; interpret them together with Status and Facts abstract.
```


## 10. 按 status 的固定展示规范

下面定义的是：

- `Facts abstract` 应如何表达；
- `Supporting Facts` 当前建议展示哪些原始字段。

### A. `missing_component`

适用角色：`source` / `sink` / `flow`

#### Facts abstract

```text
The component is not present in the current query.
```

#### Supporting Facts

```json
{
  "present_in_query": false
}
```


### B. `compile_failed`

适用角色：全角色

#### Facts abstract

```text
The component exists in the query, but its standalone probe fails to compile.
```

#### Supporting Facts

```json
{
  "compile_success": false,
  "compile_error": "..."
}
```


### C. `run_failed`

适用角色：全角色

#### Facts abstract

```text
The component compiles, but probe execution failed on at least one side.
```

#### Supporting Facts

```json
{
  "present_in_query": true,
  "compile_success": true,
  "run": {
    "vulnerable": {
      "success": false,
      "error": "..."
    },
    "fixed": {
      "success": true
    }
  }
}
```

说明：

- 如果 fixed 失败，则对应调整为 fixed 侧失败信息。
- 当前仍沿用原始 `run` 结构，不额外改名。


### D. `empty`

适用角色：`source` / `sink` / `flow`

#### Facts abstract

```text
The component produces no results on either vulnerable or fixed versions.
```

#### Supporting Facts

```json
{
  "present_in_query": true,
  "compile_success": true,
  "run": {
    "vulnerable": {
      "num_results": 0
    },
    "fixed": {
      "num_results": 0
    }
  }
}
```


### E. `only_fixed`

适用角色：`source` / `sink`

#### Facts abstract

```text
The component only matches the fixed version, which suggests reversed modeling.
```

#### Supporting Facts

```json
{
  "run": {
    "vulnerable": {
      "num_results": 0
    },
    "fixed": {
      "num_results": 12,
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
    }
  }
}
```


### F. `off_target`

适用角色：`source` / `sink`

#### Facts abstract

```text
The component has matches, but neither side aligns to target methods, indicating off-target modeling.
```

#### Supporting Facts

```json
{
  "present_in_query": true,
  "compile_success": true,
  "compile_error": null,
  "run": {
    "vulnerable": {
      "num_results": 12,
      "num_aligned_files": 1,
      "num_aligned_methods": 0,
      "aligned_files": [
        "src/main/java/com/example/A.java"
      ],
      "aligned_methods": [],
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
      "num_results": 10,
      "num_aligned_files": 0,
      "num_aligned_methods": 0,
      "aligned_files": [],
      "aligned_methods": [],
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
  }
}
```


### G. `weak_but_present`

适用角色：`source` / `sink`

#### Facts abstract

```text
The component has some target alignment, but it still overlaps with the fixed side and is not yet stable enough.
```

#### Supporting Facts

```json
{
  "present_in_query": true,
  "compile_success": true,
  "compile_error": null,
  "run": {
    "vulnerable": {
      "num_results": 12,
      "num_aligned_files": 1,
      "num_aligned_methods": 1,
      "aligned_files": [
        "src/main/java/com/example/A.java"
      ],
      "aligned_methods": [
        "src/main/java/com/example/A.java:A:foo"
      ],
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
      "num_results": 10,
      "num_aligned_files": 1,
      "num_aligned_methods": 1,
      "aligned_files": [
        "src/main/java/com/example/A.java"
      ],
      "aligned_methods": [
        "src/main/java/com/example/A.java:A:foo"
      ],
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
  }
}
```


### H. `overblocking_suspect`

适用角色：`barrier`

#### Facts abstract

```text
The barrier suppresses far more vulnerable-side results than fixed-side results, which suggests overblocking.
```

#### Supporting Facts

```json
{
  "present_in_query": true,
  "compile_success": true,
  "compile_error": null,
  "run": {
    "vulnerable": {
      "num_results": 12,
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
      "num_results": 1,
      "hit_files": [
        "src/main/java/com/example/C.java"
      ],
      "hit_methods": [
        "src/main/java/com/example/C.java:C:baz"
      ]
    }
  }
}
```


### I. `non_discriminative`

适用角色：`barrier`

#### Facts abstract

```text
The barrier matches both vulnerable and fixed versions, so it has weak discriminative value.
```

#### Supporting Facts

```json
{
  "present_in_query": true,
  "compile_success": true,
  "compile_error": null,
  "run": {
    "vulnerable": {
      "num_results": 12,
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
      "num_results": 10,
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
  }
}
```


### J. `weak_bridge`

适用角色：`flow`

#### Facts abstract

```text
The flow component has bridge evidence, but it is still too weak to clearly support the intended path.
```

#### Supporting Facts

```json
{
  "present_in_query": true,
  "compile_success": true,
  "compile_error": null,
  "run": {
    "vulnerable": {
      "num_results": 12,
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
      "num_results": 6,
      "hit_files": [
        "src/main/java/com/example/C.java",
        "src/main/java/com/example/D.java",
        "src/main/java/com/example/E.java"
      ],
      "hit_methods": [
        "src/main/java/com/example/C.java:C:baz",
        "src/main/java/com/example/D.java:D:qux",
        "src/main/java/com/example/E.java:E:quux"
      ]
    }
  }
}
```


### K. `noisy_bridge`

适用角色：`flow`

#### Facts abstract

```text
The flow component produces many bridge facts on both sides, and the counts are close, suggesting noisy shared propagation.
```

#### Supporting Facts

```json
{
  "present_in_query": true,
  "compile_success": true,
  "compile_error": null,
  "run": {
    "vulnerable": {
      "num_results": 644,
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
      "num_results": 648,
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
  }
}
```


### L. `others`

适用角色：全角色

#### Facts abstract

```text
The component falls into an uncategorized abnormal state under the current evidence.
```

#### Supporting Facts

```json
{
  "present_in_query": true,
  "compile_success": true,
  "compile_error": null,
  "run": {
    "vulnerable": {
      "num_results": 12,
      "num_aligned_files": 1,
      "num_aligned_methods": 0,
      "aligned_files": [
        "src/main/java/com/example/A.java"
      ],
      "aligned_methods": [],
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
      "num_results": 10,
      "num_aligned_files": 0,
      "num_aligned_methods": 0,
      "aligned_files": [],
      "aligned_methods": [],
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
  }
}
```


## 11. 当前不进入 Problem Components 的状态

下面这些状态默认不进入最终 prompt 的 `# Problem Components` 章节，只在 debug/分析产物里保留：

- `good_anchor`
- `absent`
- `repair_only`
- `useful_repair_signal`
- `useful_bridge`
- `likely_not_needed`

原因：

- 它们不是“问题组件”，或者当前不需要进入修复 prompt。
- 这些状态仍然可以存在于底层 probe 评估 JSON 中，但不应无差别塞入 Phase 3 prompt。


## 12. 当前阶段对 Supporting Facts 的约束

在尚未改代码之前，本文档将 `Supporting Facts` 视为一套**目标展示规范**。

也就是说：

- 底层 `probe_evaluation.json` 仍可保持较完整结构；
- `# Problem Components` 章节只抽取本文档指定的字段范围；
- 当前先按照本文档中每个 status 的字段子集设计，后续再把它落到 renderer / selector 代码里。


## 13. 实施原则（后续落代码时遵循）

后续真正实现 `# Problem Components` 章节时，应遵循：

1. 先从 probe 评估结果中拿到 `role`、`status`、`confidence` 和组件原始事实。
2. 再根据 `role + status` 选择 repair prompt，填入 `Repair direction`。
3. 再根据 `role + status` 生成 `Facts abstract`。
4. 最后根据 `role + status` 从原始字段中裁剪出 `Supporting Facts`。

核心原则是：

> `# Problem Components` 章节不是原始 JSON 的搬运结果，而是在保留原始字段风格前提下，对 probe 评估结果做 prompt-friendly 重排。
