# Phase 1 Schema

本文定义 Phase 1 的 JSON 结构。

要求：

- 使用中文说明
- 结构尽量贴近当前 Phase 1 提示词模板
- 不额外增加模板之外的字段

## 1. 对应的模板章节

Phase 1 当前模板包含以下部分：

- `Vulnerability Research Summary`
- `CVE Information`
- `Relevant Files`
- `Sources`
- `Sinks`
- `Sanitizers`
- `Additional Taint Steps`
- `Vulnerability Summary`

因此，JSON 也只保留这几部分。

## 2. 顶层结构

```json
{
  "vulnerability_research_summary": "",
  "cve_information": "",
  "relevant_files": [],
  "sources": [],
  "sinks": [],
  "sanitizers": [],
  "additional_taint_steps": [],
  "vulnerability_summary": ""
}
```

## 3. 字段说明

### `vulnerability_research_summary`

字符串。

对应模板中的：

- `## Vulnerability Research Summary`

用于保存对漏洞类型、CWE、Chroma 检索结果等内容的总结。

示例：

```json
"vulnerability_research_summary": "这是一个典型的 CWE-89 SQL 注入问题，外部输入参与了 SQL 结构构造。"
```

### `cve_information`

字符串。

对应模板中的：

- `## CVE Information`

用于保存 NIST 或其他来源中的 CVE 基本信息。

示例：

```json
"cve_information": "CVE-2022-45206 影响 Jeecg-boot v3.4.3，漏洞入口为 /sys/duplicate/check。"
```

### `relevant_files`

数组。

对应模板中的：

- `## Relevant Files`

每个元素表示一个相关文件。

结构如下：

```json
{
  "file": "",
  "description": ""
}
```

示例：

```json
[
  {
    "file": "jeecg-boot-base-core/src/main/java/org/jeecg/common/util/SqlInjectionUtil.java",
    "description": "核心过滤逻辑所在文件"
  }
]
```

## 4. Sources / Sinks / Sanitizers / Additional Taint Steps 的统一结构

下面四个字段使用同一种元素结构：

- `sources`
- `sinks`
- `sanitizers`
- `additional_taint_steps`

每个元素结构如下：

```json
{
  "description": "",
  "file": "",
  "location": "",
  "pattern": "",
  "conceptual_role": "",
  "pattern_category": "",
  "ast_elements": [],
  "detection_strategy": ""
}
```

字段含义：

- `description`：条目的标题或简要说明
- `file`：相关文件
- `location`：行号范围或代码位置
- `pattern`：代码模式
- `conceptual_role`：在漏洞链条中的角色
- `pattern_category`：模式类别
- `ast_elements`：涉及的 AST 元素列表
- `detection_strategy`：检测思路

说明：

- `ast_elements` 当前是 agent 根据 diff、代码和检索结果总结出来的，不是程序自动抽取的真实 AST。

### `sources` 示例

```json
[
  {
    "description": "请求参数进入控制器",
    "file": "DuplicateCheckController.java",
    "location": "45-47, 53-54, 64-65",
    "pattern": "控制器方法参数经过 getter 读取 tableName 和 fieldName",
    "conceptual_role": "攻击者可控输入",
    "pattern_category": "CWE-89 外部输入",
    "ast_elements": [
      "controller method parameter",
      "getter call",
      "string concatenation"
    ],
    "detection_strategy": "将请求绑定对象中的字段视为 taint source"
  }
]
```

### `sinks` 示例

```json
[
  {
    "description": "MyBatis 动态 SQL 插值点",
    "file": "SysDictMapper.xml",
    "location": "101-107",
    "pattern": "${tableName} 和 ${fieldName}",
    "conceptual_role": "危险 SQL sink",
    "pattern_category": "CWE-89 SQL 结构插值",
    "ast_elements": [
      "mapped statement",
      "string-template interpolation"
    ],
    "detection_strategy": "将参与 SQL 结构拼接的位置视为 sink"
  }
]
```

### `sanitizers` 示例

```json
[
  {
    "description": "新增 SQL 注释拦截逻辑",
    "file": "SqlInjectionUtil.java",
    "location": "274-284",
    "pattern": "checkSqlAnnotation(String str)",
    "conceptual_role": "修复中新增的 barrier",
    "pattern_category": "拒绝式校验",
    "ast_elements": [
      "method call",
      "regex matcher",
      "exception throw"
    ],
    "detection_strategy": "将修复后新增的校验方法视为 sanitizer"
  }
]
```

### `additional_taint_steps` 示例

```json
[
  {
    "description": "getter 到字符串拼接的传播",
    "file": "DuplicateCheckController.java",
    "location": "64-65",
    "pattern": "tableName + \",\" + fieldName",
    "conceptual_role": "taint 传播步骤",
    "pattern_category": "string-building propagation",
    "ast_elements": [
      "binary +",
      "getter call"
    ],
    "detection_strategy": "字符串拼接保持 taint"
  }
]
```

### `vulnerability_summary`

字符串。

对应模板中的：

- `## Vulnerability Summary`

用于总结漏洞的根因、传播方式和修复方式。

示例：

```json
"vulnerability_summary": "用户可控的 tableName 和 fieldName 经不充分过滤后进入 MyBatis 动态 SQL，修复通过新增注释拦截逻辑阻断该路径。"
```

## 5. 完整示例

```json
{
  "vulnerability_research_summary": "这是一个典型的 CWE-89 SQL 注入问题。",
  "cve_information": "CVE-2022-45206 影响 Jeecg-boot v3.4.3。",
  "relevant_files": [
    {
      "file": "jeecg-boot-base-core/src/main/java/org/jeecg/common/util/SqlInjectionUtil.java",
      "description": "核心过滤逻辑所在文件"
    }
  ],
  "sources": [],
  "sinks": [],
  "sanitizers": [],
  "additional_taint_steps": [],
  "vulnerability_summary": "用户输入经过不充分过滤后进入动态 SQL。"
}
```

