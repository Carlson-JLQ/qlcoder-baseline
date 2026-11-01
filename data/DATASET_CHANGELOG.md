# QLCoder 数据集变更日志

本文档记录 `data/project_info.csv` 和 `data/fix_info.csv` 中所有会影响数据集语义、代码仓库版本、CodeQL 数据库构建或 QLCoder 验证结果的变更。

它不是当前数据内容的重复说明，而是可追溯的变更历史。以后修改任何 CVE 的提交、仓库、Ground Truth 或状态字段时，都必须在这里新增一条记录。

## 维护规则

1. **每个 CVE 单独记录。** 一次修改多个 CVE 时，可以共用日期和批次号，但每个 CVE 必须有独立小节。
2. **只追加，不覆盖历史。** 如果以前的变更结论后来被推翻，应新增“更正”记录，并引用被更正的变更编号。
3. **使用完整的 40 位 commit SHA。** 表格中可以附带短 SHA 便于阅读，但不能只保留短 SHA。
4. **记录字段级 before/after。** 不能只写“修复了 commit”或“调整了 GT”。
5. **区分四类对象：**
   - 数据字段：`project_info.csv`、`fix_info.csv`；
   - 本地仓库状态：`cves/<CVE>/<repo>` 的 HEAD 和可用提交；
   - 生成物：`.diff`、vulnerable/fixed CodeQL database；
   - 管线代码：用于克隆、生成 diff、构建数据库和运行 QLCoder 的脚本。
6. **明确行号基准。** Ground Truth 行号必须注明是基于 buggy、fix，还是某个明确 SHA。不能仅凭 `fix_info.csv` 的 `commit` 字段推断。
7. **明确验证范围。** “提交已验证”不等于“Ground Truth 已验证”；未检查的部分必须标记为未验证或待办。
8. **记录证据而不仅是结论。** 至少包含提交关系、分支、补丁语义、文件/方法存在性及实际运行结果。

## 变更状态

| 状态 | 含义 |
|---|---|
| `proposed` | 已提出但尚未写入数据文件 |
| `applied` | 已写入数据文件，但验证尚未全部完成 |
| `verified` | 已完成该记录所声明范围内的验证 |
| `superseded` | 已被后续变更替代，必须给出后续变更编号 |
| `reverted` | 已回滚，必须说明回滚原因和恢复值 |

## 变更类型

| 类型 | 说明 | 典型影响 |
|---|---|---|
| `commit-pair` | 修改 buggy/fix commit 或多修复提交集合 | 需要重新克隆/获取提交、重新生成 diff 和 CodeQL DB |
| `repository` | 修改仓库 URL、owner、repo 或 tag | 需要重新克隆并重新验证全部提交 |
| `ground-truth` | 修改文件、类、方法、签名或行号 | 影响候选 query 的命中和验证结果 |
| `metadata` | 修改 CWE、advisory、版本等元数据 | 通常不改变数据库，但可能影响分析提示词 |
| `pipeline` | 修改数据生成或消费方式 | 可能需要重新生成派生文件 |
| `cleanup` | 删除测试、重复、重构或无关记录 | 影响 GT 数量和评估口径 |

## 变更索引

| 变更编号 | 日期 | CVE | 类型 | 状态 | 摘要 |
|---|---|---|---|---|---|
| `DS-2026-11-01-001` | 2026-11-01 | CVE-2011-4367 | `commit-pair`, `pipeline` | `verified` | 将 fix commits 从错误的 `2.1.x` 分支映射到 `2.0.x`，并使 diff 管线支持非 UTF-8 历史文件 |

---

## DS-2026-11-01-001 — CVE-2011-4367 分支一致性与 diff 编码修复

### 基本信息

| 项目 | 内容 |
|---|---|
| 日期 | 2026-11-01 |
| CVE | CVE-2011-4367 |
| 项目 | `apache/myfaces` |
| 数据集版本标签 | `2.0.11` |
| 变更类型 | `commit-pair`, `pipeline` |
| 状态 | `verified` |
| 修改文件 | `data/project_info.csv`, `data/fix_info.csv` |
| 关联管线文件 | `scripts/get_cve_repos.py`, `src/ql_agent.py` |

### 问题描述

原数据把 `2.0.x` 分支的 vulnerable release commit 与 `2.1.x` 分支的修复提交放在同一条项目记录中：

- buggy commit `bedac49daffc3cb792fa19884620af01ab5a01ab` 是 `myfaces-core-project-2.0.11` 的 release commit，位于 `2.0.x`。
- 原来的 5 个 fix commits 位于 `2.1.x`。
- buggy commit 不是这 5 个 fix commits 中任何一个的祖先。
- 脚本按提交时间选择 `b9b2e00bb53d3eb435256c5a140b83f7d6251b55` 后，生成了跨分支 tree diff：1020 个文件发生变化，包含大量与漏洞无关的改动。
- 跨分支 diff 中的历史 JavaScript 文件含单字节 `0xA0`。`subprocess.run(..., text=True)` 强制按 UTF-8 解码，最终触发 `UnicodeDecodeError`。

因此这里包含两个独立问题：提交标注跨分支，以及 diff 管线错误地假设所有 Git 内容都是 UTF-8。

### `project_info.csv` 字段级变更

以下字段保持不变：

| 字段 | 值 |
|---|---|
| `project_slug` | `apache__myfaces_CVE-2011-4367_2.0.11` |
| `github_url` | `https://github.com/apache/myfaces` |
| `github_tag` | `2.0.11` |
| `buggy_commit_id` | `bedac49daffc3cb792fa19884620af01ab5a01ab` |

`fix_commit_ids` 逐项映射如下：

| 原 `2.1.x` commit | 新 `2.0.x` commit | 验证依据 |
|---|---|---|
| `9e7e996a4ef83c4d8e673ee6e4431348e598e031` | `d6ed8b8a07f88b3361147e096d4fe78bb7b38f11` | 同一 CVE/MYFACES-3414 修复在 `2.0.x` 的分支适配提交；提交主题和时间对应 |
| `c07c3bf93ad0e0cf530ddece0642783f1553ad89` | `e22e3c3797e0bc9a7d2db376a095ae27cb36f710` | stable patch-id 相同 |
| `99ef1250ca3e28213e85eac14817e1ff93fc9e6a` | `a0cc51d8b10d789e159691619310a452f0b9307c` | stable patch-id 相同 |
| `236cd211327c557825c7fce091bcc68f57a88e8e` | `990766bcaf4e6a96b29b06a87f0d4d8f1c34e9a2` | stable patch-id 相同 |
| `b9b2e00bb53d3eb435256c5a140b83f7d6251b55` | `4c0062a2641ebd61db7bce5167346f9342b7bfb7` | stable patch-id 相同；MYFACES-3454 的 `2.0.x` 对应提交 |

变更前：

```text
236cd211327c557825c7fce091bcc68f57a88e8e;
99ef1250ca3e28213e85eac14817e1ff93fc9e6a;
c07c3bf93ad0e0cf530ddece0642783f1553ad89;
9e7e996a4ef83c4d8e673ee6e4431348e598e031;
b9b2e00bb53d3eb435256c5a140b83f7d6251b55
```

变更后：

```text
990766bcaf4e6a96b29b06a87f0d4d8f1c34e9a2;
a0cc51d8b10d789e159691619310a452f0b9307c;
e22e3c3797e0bc9a7d2db376a095ae27cb36f710;
d6ed8b8a07f88b3361147e096d4fe78bb7b38f11;
4c0062a2641ebd61db7bce5167346f9342b7bfb7
```

这里保留 release commit `bedac49...` 作为 vulnerable 状态，没有将 buggy commit 改成最后一个 fix 的直接父提交。原因是该 CVE 的修复分布在多个提交中，直接使用最后一个修复提交的父提交会把此前的部分安全修复包含在 vulnerable 状态中，不能代表原始 `2.0.11` 漏洞版本。

### `fix_info.csv` 变更

共修改 CVE-2011-4367 的 16 条记录，只替换其 `commit` 字段，使其指向与 `project_info.csv` 一致的 `2.0.x` 对应修复提交。

本次没有修改以下 Ground Truth 字段：

- `file`
- `class`, `class_start`, `class_end`
- `method`, `method_start`, `method_end`
- `signature`
- `Done`

已确认映射后的提交中相关源文件和方法名称存在。本次变更的验证重点是提交分支和提交身份；上述 16 条记录的类/方法完整范围没有在本变更中重新标注。未来若调整这些范围，应建立新的 `ground-truth` 类型变更记录，不应直接修改本条历史说明。

### 管线变更

`scripts/get_cve_repos.py`：

- `generate_diff()` 从返回文本改为返回原始 `bytes`。
- 移除 `text=True`，避免 Python 在生成 diff 时隐式执行 UTF-8 解码。
- `.diff` 使用二进制模式 `wb` 写入，确保内容与 `git diff` 的原始字节完全一致。
- Git 命令失败时，仅对 stderr 使用 `errors="replace"` 做可显示的错误解码。

`src/ql_agent.py`：

- `.diff` 落盘文件保持字节级无损。
- 将 diff 转换为模型提示词时使用 `encoding="utf-8", errors="replace"`。
- 这样只有无法表示为 UTF-8 的少数字节在提示词文本中被替换，不会破坏保存的原始 diff，也不会让 QLCoder 在读取阶段再次崩溃。

### 验证结果

| 检查项 | 结果 |
|---|---|
| 5 个新 fix commits 是否存在 | 通过 |
| buggy commit 是否为 5 个新 commits 的祖先 | 通过 |
| fix commits 是否位于 `2.0.x` | 通过 |
| 脚本按时间选择的最终 fix | `4c0062a2641ebd61db7bce5167346f9342b7bfb7` |
| 强制重新生成 diff | 通过 |
| 保存的 diff 与 `git diff bedac49... 4c0062...` SHA-256 是否一致 | 通过 |
| 非 UTF-8 字节是否导致生成阶段崩溃 | 不再崩溃 |
| QLCoder 文本读取是否可处理非法 UTF-8 | 通过 |
| 最终仓库 HEAD | `bedac49daffc3cb792fa19884620af01ab5a01ab` |
| CSV 结构解析 | 通过；`project_info.csv` 216 条数据记录、`fix_info.csv` 1493 条数据记录 |

实际验证命令：

```bash
uv run python scripts/get_cve_repos.py --cve CVE-2011-4367 --force
git -C cves/CVE-2011-4367/myfaces rev-parse HEAD
git -C cves/CVE-2011-4367/myfaces merge-base --is-ancestor \
  bedac49daffc3cb792fa19884620af01ab5a01ab \
  4c0062a2641ebd61db7bce5167346f9342b7bfb7
git -C cves/CVE-2011-4367/myfaces diff \
  bedac49daffc3cb792fa19884620af01ab5a01ab \
  4c0062a2641ebd61db7bce5167346f9342b7bfb7 | sha256sum
sha256sum cves/CVE-2011-4367/CVE-2011-4367.diff
```

### 派生数据与后续动作

由于提交标注发生变化，已有的以下派生数据不能继续视为有效：

- 旧的 CVE-2011-4367 `.diff`；
- 根据旧提交对构建的 vulnerable/fixed CodeQL databases；
- 使用旧数据库或旧 diff 产生的 QLCoder 输出、缓存和评估结果。

重新运行时应按以下顺序处理：

1. 使用 `get_cve_repos.py --force` 重新生成 diff 并检出 vulnerable commit；
2. 删除或隔离旧提交对生成的 CodeQL databases，然后重新构建；
3. 使 Phase 1/2 缓存失效；
4. 重新运行 QLCoder；
5. 在新的输出记录中注明使用变更 `DS-2026-11-01-001` 后的数据。

`autoql_data` 当前不包含 CVE-2011-4367，因此本次没有修改 `autoql_data`。

---

## 后续变更记录模板

复制以下模板并追加到文档末尾，同时在“变更索引”中增加一行。

```markdown
## DS-YYYY-MM-DD-NNN — CVE-YYYY-NNNN 简短标题

### 基本信息

| 项目 | 内容 |
|---|---|
| 日期 | YYYY-MM-DD |
| CVE | CVE-YYYY-NNNN |
| 项目 | owner/repository |
| 变更类型 | commit-pair / repository / ground-truth / metadata / pipeline / cleanup |
| 状态 | proposed / applied / verified / superseded / reverted |
| 修改文件 | data/project_info.csv, data/fix_info.csv |
| 更正的历史记录 | 无，或 DS-YYYY-MM-DD-NNN |

### 问题描述

说明原标注哪里不正确、如何发现、为什么会影响 QLCoder。

### 字段级变更

| 文件 | 字段/行 | 修改前 | 修改后 | 理由 |
|---|---|---|---|---|
| project_info.csv | buggy_commit_id | ... | ... | ... |
| project_info.csv | fix_commit_ids | ... | ... | ... |
| fix_info.csv | file/method/range | ... | ... | ... |

### 提交验证

- buggy commit 的漏洞语义：
- fix commit 的修复语义：
- 两者关系（直接父子/祖先后代/多提交修复/回移）：
- 所属分支和版本：
- 是否包含无关重构：
- 选择该提交对而不是其他候选的理由：

### Ground Truth 验证

- 行号基准：buggy / fix / 完整 SHA
- 文件是否存在于 vulnerable 和 fixed 两侧：
- 类和方法是否存在于 vulnerable 侧：
- 类范围：
- 方法范围：
- 签名：
- source/sink/漏洞入口语义：
- 删除的候选及理由：

### 验证结果

| 检查项 | 结果/证据 |
|---|---|
| commit 对象存在 | ... |
| ancestry/parent 关系 | ... |
| patch/diff 语义 | ... |
| 保存 diff 字节一致 | ... |
| vulnerable/fixed DB 构建 | ... |
| GT 在 CodeQL 中可定位 | ... |
| QLCoder 回归运行 | ... |

### 派生数据与兼容性

列出必须重建或失效的 diff、仓库、CodeQL DB、缓存、输出和评估结果。

### 回滚信息

说明如何恢复修改前的字段值，以及哪些派生数据需要随之恢复或重建。

### 未完成事项

- 无；或列出尚未验证的内容、负责人/条件和下一步。
```

## 提交与 Ground Truth 的最低验收标准

### 提交标注

- commit 对象在目标仓库中真实存在；
- buggy 与 fix 属于适用于数据集版本的同一历史线，或对跨分支/回移场景给出明确理由；
- buggy 中漏洞成立，fix 中安全条件确实发生变化；
- 单提交修复优先使用最后一个完整漏洞状态和第一个完整修复状态，通常是直接父子提交；
- 多提交修复不能机械地把最后一个 fix 的父提交当作原始 vulnerable 状态；
- 不应仅按时间从多个分支候选中选择最新提交；必须先验证分支和 ancestry；
- 保存的 diff 必须与声明的提交对字节一致。

### Ground Truth 标注

- 优先标注漏洞入口、关键 source/sink 或直接实施缺失安全检查的生产方法；
- 删除纯测试、重复、普通重构和与安全语义无关的方法；
- 作为上下文但不是漏洞入口的方法，只有在评估设计明确需要时才保留；
- 修复中新建且 vulnerable DB 中不存在的方法，默认不作为 vulnerable-side 方法 GT；
- 文件、类、方法和签名必须在声明的行号基准版本中存在；
- `class_start/class_end` 和 `method_start/method_end` 必须说明是否包含注解、声明行和闭合括号，并在同一数据集中保持一致；
- 每次改动 GT 后必须重新检查候选 query 验证逻辑，确认不会因版本侧或行号基准不一致造成假阴性。

### 复核建议

至少由两类证据共同支持一项修改：

1. Git 证据：`show`、`log`、`merge-base`、`diff`、`patch-id`；
2. 源码证据：漏洞路径、输入传播、安全检查和修复语义；
3. 公告证据：CVE、GHSA、厂商公告或修复 PR；
4. 执行证据：CodeQL DB 构建、查询结果、QLCoder 回归输出。

只有提交存在并不足以将记录标记为 `verified`；状态必须与本条记录实际声明的验证范围一致。
