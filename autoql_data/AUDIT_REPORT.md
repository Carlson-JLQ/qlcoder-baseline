# autoql_data 数据集审计报告

## 审计口径

- 对每个 CVE 使用本地 `cves/<CVE>/<repo>` 仓库核验提交对象、父子关系、提交补丁和安全语义。
- `buggy_commit_id` 必须是所选 `fix_commit_ids` 的直接第一父提交；保存的 `<CVE>.diff` 必须与该提交对的 `git diff` 完全一致。
- Ground Truth 只保留安全修复直接涉及的生产代码位置；删除测试、重复项、普通重构和仅作上下文的候选项。
- 方法级 GT 必须同时存在于 vulnerable 源码中，避免 QLCoder 在 vulnerable DB 上永远无法命中修复中新建的方法。
- 行号均按 GT 行 `commit` 指向的源码版本核对；类和方法范围包含完整声明体。

## 逐项结果

| CVE | buggy → fix | Ground Truth | 结论 |
|---|---|---|---|
| CVE-2022-25842 | `29dc527a5d → a0ab2fa9f4` | `IOUtils.java:IOUtils.unzip [106-161]` | 提交对已纠正；修复删除了整个 unzip，因此该条 GT 有意定位在 buggy commit。 |
| CVE-2022-32287 | `7aab4a82a7 → 9c99e071be` | `FileUtil.java:FileUtil.extractFilesFromJar [766-814]` | 提交对已纠正为真正加入 canonical-path 目录边界检查的 7aab4a82 → 9c99e071；原 1088f615 只是清理提交。 |
| CVE-2022-1274 | `4d0629dcf4 → fc3c61235f` | `ExecuteActionsActionTokenHandler.java:ExecuteActionsActionTokenHandler.getVerifiers [58-72]`<br>`UserResource.java:UserResource.executeActionsEmail [784-861]` | 提交对、安全补丁语义与 GT 均核验通过。 |
| CVE-2021-30181 | `4d5158fcef → 9b7575aa1c` | `ScriptRouter.java:ScriptRouter.route [128-146]` | buggy commit 已纠正为修复提交的直接父提交；GT 聚焦实际执行脚本的 route。 |
| CVE-2023-34468 | `40889f0037 → 6a7a91f0fa` | `DBCPProperties.java:DBCPProperties [字段 36-44]`<br>`HikariCPConnectionPool.java:HikariCPConnectionPool [字段 73-82]` | 切换到 1.22.x 修复分支；安全变更位于两个 DATABASE_URL 字段，属于类/字段级 GT。 |
| CVE-2025-30067 | `bd86f44d59 → 21d98f3ef2` | `ProjectService.java:ProjectService.updateProjectOverrideKylinProps [437-459]` | 提交对、安全补丁语义与 GT 均核验通过。 |
| CVE-2025-30177 | `4ccb68b166 → 9fd8fc30db` | `UndertowHeaderFilterStrategy.java:UndertowHeaderFilterStrategy.initialize [28-37]` | 提交对、安全补丁语义与 GT 均核验通过。 |
| CVE-2025-24399 | `2849bd3945 → 4d7765c854` | `OicSecurityRealm.java:OicSecurityRealm.OicSecurityRealm [320-339]` | 提交对、安全补丁语义与 GT 均核验通过。 |
| CVE-2025-52520 | `434772930f → 927d66fbc2` | `Request.java:Request.parseParts [2598-2779]` | 提交对、安全补丁语义与 GT 均核验通过。 |
| CVE-2025-22227 | `a60f640c99 → 522892307e` | `HttpClientConfig.java:HttpClientConfig.addStreamHandlers [598-685]` | copyState 是修复中新建方法，已改为 vulnerable/fixed 两边均存在的 addStreamHandlers。 |
| CVE-2025-26795 | `946fcbc2d3 → 34fcaff6b7` | `IoTDBDataSourceFactory.java:IoTDBDataSourceFactory.setProperties [43-61]` | 仅标注 JDBC DataSource 日志泄露入口 setProperties。 |
| CVE-2025-26864 | `946fcbc2d3 → 34fcaff6b7` | `OpenIdAuthorizer.java:OpenIdAuthorizer.login [148-181]` | 与 26795 共用修复提交，但按公告拆分为 OpenIdAuthorizer.login。 |
| CVE-2025-53003 | `c8b743763d → 92eea4d463` | `OpenIdAuthorizationService.java:OpenIdAuthorizationService.validateScope [121-205]` | 提交对、安全补丁语义与 GT 均核验通过。 |
| CVE-2025-54380 | `9bda49b602 → 2d3219113e` | `TrustedHttpClientImpl.java:TrustedHttpClientImpl.execute [386-480]` | 提交对、安全补丁语义与 GT 均核验通过。 |
| CVE-2014-3576 | `f62f47b92d → f07e6a5321` | `TransportConnection.java:TransportConnection.processControlCommand [1536-1538]` | 切换到一致的 5.10.2 回移提交对；漏洞逻辑是 processControlCommand 中可远程触发的 shutdown。 |
| CVE-2025-23015 | `3ddccf4521 → 6207a305ba` | `AlterRoleStatement.java:AlterRoleStatement.authorize [69-102]` | 提交对、安全补丁语义与 GT 均核验通过。 |
| CVE-2025-24790 | `3236d9840c → 9e1a5acf12` | `FileCacheManager.java:FileCacheManager.build [113-200]` | 提交对、安全补丁语义与 GT 均核验通过。 |
| CVE-2025-1391 | `4b628610c4 → 5aa2b4c75b` | `OrganizationMembershipMapper.java:OrganizationMembershipMapper.resolveValue [148-185]` | 从不相关的认证解析入口改为真正产生未授权 organization claim 的 resolveValue。 |
| CVE-2025-23367 | `ac0acd8058 → 73406b736a` | `ServerResumeHandler.java:ServerResumeHandler.execute [54-69]`<br>`ServerSuspendHandler.java:ServerSuspendHandler.execute [65-84]` | 提交对、安全补丁语义与 GT 均核验通过。 |
| CVE-2025-48734 | `4d8492104c → bd20740da2` | `PropertyUtilsBean.java:PropertyUtilsBean.resetBeanIntrospectors [1200-1205]` | 提交对、安全补丁语义与 GT 均核验通过。 |
| CVE-2023-51982 | `371a2d7f82 → b8b4cec49a` | `HttpAuthUpstreamHandler.java:HttpAuthUpstreamHandler.addressFromRequestOrChannel [192-200]` | buggy commit 已纠正为修复提交的直接父提交。 |
| CVE-2025-3910 | `0ff4cce318 → e66e2292b9` | `AuthenticationManager.java:AuthenticationManager.executionActions [1258-1271]` | 提交对、安全补丁语义与 GT 均核验通过。 |
| CVE-2025-53103 | `deb3e7c648 → d4fc834c8c` | `OpenTestReportGeneratingListener.java:OpenTestReportGeneratingListener.addGitInfo [172-183]` | 保留两边均存在的 addGitInfo；新建的 obfuscateUserInfo 不适合作为 vulnerable DB 方法 GT。 |
| CVE-2025-27508 | `ff9fed1d59 → da3a81a897` | `ChecksumCalculator.java:ChecksumCalculator.ChecksumCalculator [48-50]` | 提交对、安全补丁语义与 GT 均核验通过。 |
| CVE-2025-7365 | `1183157d86 → 86f0a7864f` | `IdpReviewProfileAuthenticator.java:IdpReviewProfileAuthenticator.actionImpl [112-248]`<br>`IdpEmailVerificationAuthenticator.java:IdpEmailVerificationAuthenticator.authenticateImpl [63-101]` | 纠正 actionImpl 的完整方法范围，并保留与绕过链路直接相关的 authenticateImpl。 |
| CVE-2025-24789 | `9e1a5acf12 → 4f01bb8f9b` | `SessionUtilExternalBrowser.java:SessionUtilExternalBrowser.openBrowser [72-93]` | 提交对、安全补丁语义与 GT 均核验通过。 |
| CVE-2025-27522 | `b37f944f23 → 86c893cfd8` | `MySQLSensitiveUrlUtils.java:MySQLSensitiveUrlUtils.containSensitiveKey [120-128]` | 提交对、安全补丁语义与 GT 均核验通过。 |
| CVE-2025-27531 | `1183e43b44 → ebcd6d3230` | `MySQLSensitiveUrlUtils.java:MySQLSensitiveUrlUtils.filterSensitive [62-118]` | 提交对、安全补丁语义与 GT 均核验通过。 |
| CVE-2025-27505 | `4c124aa2e2 → 507c1cd3bd` | `GeoServerSecurityFilterChain.java:GeoServerSecurityFilterChain [字段 31-42]`<br>`GeoServerSecurityManager.java:GeoServerSecurityManager.reload [376-431]` | 保留过滤链常量与 reload；未把修复中新建、在 vulnerable DB 不存在的 migrateFrom25 当作方法目标。 |
| CVE-2025-31720 | `dddb4598df → bf32018bf0` | `ComputerSet.java:ComputerSet.doCreateItem [276-318]` | 从未改动的 do_launchAll 改为缺少权限检查的 doCreateItem。 |
| CVE-2025-31721 | `bf32018bf0 → b3651b4753` | `ComputerSet.java:ComputerSet.doCreateItem [278-333]` | 提交对、安全补丁语义与 GT 均核验通过。 |
| CVE-2023-51441 | `e84c60c1f0 → 685c309feb` | `ServiceFactory.java:ServiceFactory.getService [91-141]` | 提交对、安全补丁语义与 GT 均核验通过。 |
| CVE-2024-48944 | `b0a6fa3771 → 4e6a5acd79` | `NBasicController.java:NBasicController.decodeHost [642-653]`<br>`NBasicController.java:NBasicController.encodeHost [655-669]` | 提交对、安全补丁语义与 GT 均核验通过。 |
| CVE-2025-2240 | `8da7dae36f → e8bcad3d5e` | `DelegatingMetricsCollector.java:DelegatingMetricsCollector.apply [25-38]` | 从 Builder 辅助方法改为实际阻止 meter cache 无界增长的 DelegatingMetricsCollector.apply。 |
| CVE-2025-48058 | `d6525f9e16 → 72f79dec6d` | `DirectoryDataSource.java:DirectoryDataSource.listNames [125-143]`<br>`ReadOnlyMemDataSource.java:ReadOnlyMemDataSource.listNames [102-107]`<br>`ResourceDataSource.java:ResourceDataSource.listNames [85-91]`<br>`TarArchiveDataSource.java:TarArchiveDataSource.listNames [101-120]`<br>`ZipArchiveDataSource.java:ZipArchiveDataSource.listNames [192-208]` | 移除错误的 AmplNetworkReader，改为公告所述 DataSource.listNames 的五个生产实现。 |
| CVE-2025-48059 | `e6c7c4997a → d8398f689a` | `RegexCriterion.java:RegexCriterion.filter [31-33]` | 从类/导入级候选细化为实际编译并执行用户正则的 RegexCriterion.filter。 |

## 最终一致性检查

- 项目记录：36；覆盖 CVE：36。
- Ground Truth：46 条（从原 139 条候选/重复记录精简）。
- 36/36 提交对均为直接父子关系；36/36 本地仓库均停在 buggy commit。
- 36/36 保存的 diff 与 `git diff buggy fix` 字节一致。
- 46/46 GT 文件均在安全补丁中发生变化；全部是生产源码，无测试文件。
- 46/46 类范围有效；其中 43 条方法级 GT 的方法名与完整范围有效，且目标方法在 vulnerable 源码中存在；3 条为真实的类/字段级变更。
- 所有保留行均设置 `Done=1`。

## 使用提示

当前 `src/config.py` 的 `FIX_INFO` 仍指向 `data/fix_info.csv`。本次按任务要求只更新了 `autoql_data`；正式运行 QLCoder 前，应显式切换配置或确认是否需要把审计结果同步到 `data/fix_info.csv`。


优先使用“最后一个完整漏洞状态”和“第一个完整修复状态”，在单提交修复场景下通常就是直接父子提交。