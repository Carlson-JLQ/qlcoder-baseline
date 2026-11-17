# Ground Truth 数据集修正汇总（2026-11-17）

## 范围

本次只处理 `doc/` 根目录中的 CVE 专属 `*-ground-truth-analysis.md`，不处理 `doc/CVE Trace分析/`。最终确认 4 个 CVE 需要修改数据集。

| CVE | `project_info.csv` | `fix_info.csv` 条数 | 主要修正 | 是否加入 `rerun_cve.txt` |
|---|---|---:|---|---|
| CVE-2022-32287 | fixed commit：`1088f615...` → `9c99e071...` | 25 → 1 | 删除整理提交产生的无关方法，仅保留真正加入路径约束的 `FileUtil.extractFilesFromJar(JarFile, File, FileFilter)` | 是 |
| CVE-2025-2240 | 不变 | 9 → 11 | 删除 4 个 hunk 上下文误标，补充构造函数、3 个 `withDescription` 和 2 个 `buildMeteredOperation` | 是 |
| CVE-2025-24789 | 不变 | 2 → 1 | `openBrowser` 改归内部类 `DefaultAuthExternalBrowserHandlers`，删除未修改的 `build` | 是 |
| CVE-2025-26864 | 不变 | 5 → 3 | 删除重复项、`fetchMetadata`、`deserialize`，新增 `User.toString` | 是 |

## 逐项变更

### CVE-2022-32287

- 正确 fixed commit：`9c99e071be79bdb6bbd1bcd3f20431d76ce5143e`。
- 正确核心 GT：`uimaj-core/src/main/java/org/apache/uima/pear/util/FileUtil.java` / `FileUtil.extractFilesFromJar` / 766–814。
- 因提交发生变化，必须重新生成 diff、重建 fixed CodeQL database 并重跑全部阶段。

### CVE-2025-2240

- 删除：`buildAsyncStrategy`、两个 `buildStrategy`、`CdiMeteredOperationImpl` 构造函数。
- 增加：`BasicMeteredOperationImpl` 构造函数；三个 Builder 的 `withDescription`；`FaultToleranceImpl` 和 `TypedGuardImpl` 的 `buildMeteredOperation`。
- 保留：三个 Builder 构造函数、`GuardImpl.buildMeteredOperation`、`DelegatingMetricsCollector.apply`。

### CVE-2025-24789

- `openBrowser` 的外部类误标已更正为内部类 `DefaultAuthExternalBrowserHandlers`。
- 删除补丁未修改的 `build(URI)`。

### CVE-2025-26864

- 保留：`IoTDBDataSourceFactory.setProperties`、`OpenIdAuthorizer.login`。
- 删除：重复 `setProperties`、未修改的 `fetchMetadata`、未修改的 `User.deserialize`。
- 增加：真实修改的 `User.toString`。

## 未修改项

- `CVE-2025-30177`：`initialize()` 确实是补丁所在方法；报告揭示的是 patch-location GT 与数据流路径验证口径不一致，而不是方法位置事实错误，因此本次不改数据标注，也不加入重跑列表。
- `CVE-2025-24399`：其报告位于 `doc/CVE Trace分析/`，按本次限定范围保持原数据不变。

## 重跑清单

`data/rerun_cve.txt` 共 4 条：

```text
CVE-2022-32287
CVE-2025-2240
CVE-2025-24789
CVE-2025-26864
```

详细字段级历史见 `data/DATASET_CHANGELOG.md` 的 `DS-2026-11-17-001` 至 `DS-2026-11-17-004`。
