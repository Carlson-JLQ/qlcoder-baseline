# Debug Session: codeql-diagnostics-timeout
- **Status**: [OPEN]
- **Issue**: `codeql_diagnostics` 请求超时，并伴随 CodeQL language server RSS 瞬间增长到约 2.3 GiB
- **Debug Server**: N/A
- **Log File**: N/A

## Reproduction Steps
1. 启动 `node codeql-lsp-mcp/dist/index.js`
2. 通过 MCP 客户端连接并执行 `codeql_open_file` / `codeql_update_file`
3. 调用 `codeql_diagnostics`
4. 记录超时点、CodeQL language server 日志和内存曲线
5. 关闭服务并确认无残留进程

## Hypotheses & Verification
| ID | Hypothesis | Likelihood | Effort | Evidence |
|----|------------|------------|--------|----------|
| A | `codeql_diagnostics` 触发了 CodeQL language server 的重型全量分析，导致单次内存膨胀 | High | Medium | Rejected |
| B | 诊断请求本身没有及时返回，是因为客户端等待 `publishDiagnostics` 的逻辑卡住或监听条件不满足 | High | Medium | Confirmed |
| C | 打开的 `.ql` 文件或当前 workspace 使 language server 解析了过大的库/工作区范围 | Medium | Medium | Partially Rejected |
| D | 超时后内存高位维持是服务端仍在后台计算，而不是重复请求造成的累积泄漏 | Medium | Medium | Confirmed |
| E | `codeql_diagnostics` 路径存在和 `open/update` 不同的特定实现问题，而非 MCP 传输层问题 | High | Medium | Confirmed |

## Log Evidence
- 实现证据：
  - `getDiagnostics()` 只注册监听器并等待 `publishDiagnostics`，不主动发送任何 LSP 请求来触发诊断。
  - 通知处理逻辑只有在 `params.diagnostics.length > 0` 时才会通知监听器。
- 运行时证据 1：
  - 对有效查询文件，`openDocument()` 后能收到多次 `Received diagnostics ... 0 items`。
  - 即使先调用 `getDiagnostics()` 再 `openDocument()`，依然会在收到 `0 items` 后超时。
  - 这证明不是“错过通知”，而是“收到空诊断通知后没有唤醒监听器”。
- 运行时证据 2：
  - 对无效查询文件，语言服务器会发出 `4 items` 诊断。
  - 当监听器已注册且后续再次收到 `4 items` 时，会出现 `Notifying 1 listener(s)`，并在约 `96ms` 内返回。
  - 说明 `getDiagnostics()` 当前只对“有错误的文件”可靠，对“无错误的文件”会错误超时。
- 运行时证据 3：
  - 仅执行 `openDocument()`，不调用 `getDiagnostics()`，CodeQL language server 内存也会快速上涨：
    - 根目录 workspace 下，有效查询约从 `1.05 GiB` 升到 `1.78 GiB`
    - 最小 workspace 下，有效查询约从 `1.21 GiB` 升到 `2.37 GiB`
  - 这说明内存膨胀由 `didOpen/didChange` 触发的 ON_CHANGE 分析导致，而不是 `getDiagnostics()` 本身触发。
- 运行时证据 4：
  - 最小 workspace 仍然涨到约 `2.37 GiB`，说明根因不主要是 `qlcoder` 仓库目录过大。
  - 但 verbose 日志显示语言服务器会对大量 pack / qlpack / dbscheme 文件发出 `0 items` 诊断，涉及至少 `76` 个不同文件 URI，分析范围仍然很广。
- 运行时证据 5：
  - 无效查询的内存峰值约 `1.35 GiB`，明显低于有效查询约 `1.78` 到 `2.37 GiB`。
  - 说明“可继续做语义分析的有效查询”更容易触发重型分析路径。
- 额外现象：
  - `stop()` 之后存在 `ERR_STREAM_WRITE_AFTER_END`，属于关闭阶段的独立问题，但不是本次 `codeql_diagnostics` 超时的主因。

## Verification Conclusion
- `codeql_diagnostics` 超时的直接根因已经确认：
  - 代码只在 `diagnostics.length > 0` 时通知监听器。
  - 对于合法查询返回 `0 diagnostics` 的正常情况，监听器永远不会被触发，因此必然超时。
- 内存暴涨的直接触发点不是 `codeql_diagnostics`，而是 `openDocument()` / `didChange` 之后的 CodeQL `ON_CHANGE` 分析。
- `codeql_diagnostics` 只是等待这条分析链上的诊断通知，因此把“分析很重”和“空诊断通知不唤醒监听器”两个问题叠加暴露出来。
- workspace 范围不是唯一主因，因为最小 workspace 也复现了高内存；更接近的解释是 CodeQL language server 对 Java QL 有较重的语义分析和 pack 加载成本。

## Post-Fix Verification
- 修复后功能验证：
  - 合法查询现在稳定返回 `0 diagnostics`，不再超时。
  - 非法查询仍然返回 `4 diagnostics`，未出现回归。
- 修复后内存验证：
  - 基线约 `322 MiB`
  - 首轮合法查询后约 `1360 MiB`
  - 第二轮合法更新后约 `1920 MiB`
  - 加入一个非法查询后约 `2599 MiB`
  - 后续 3 轮合法更新后约 `2630` → `2634` → `2644 MiB`
  - 空转 5 秒后约 `2769 MiB`
- 只重复 `getDiagnostics()` 不做更新的对照组：
  - `after_open` 约 `1343 MiB`
  - 第 2 次 `getDiagnostics()` 后跳到约 `2382 MiB`
  - 后续第 3 到第 5 次基本稳定在 `2393 MiB` 左右
- 高位后的多轮更新对照组：
  - 预热后约 `1511 MiB`
  - 第 1 次更新后跳到约 `2954 MiB`
  - 后续第 2 到第 8 次更新基本在 `2959` 到 `3000 MiB` 之间缓慢漂移

## Post-Fix Conclusion
- `codeql_diagnostics` 的逻辑 bug 已解决。
- 内存问题仍然存在，但当前证据更接近：
  - 重型分析触发后的高水位常驻
  - 叠加少量继续增长
- 它不是“每次调用都再上涨 1 GiB”的无限线性爆炸，但也不是“修复后自动恢复正常”的状态。
- 因此本次修复只解决了 diagnostics 语义错误，没有解决 CodeQL language server 的高内存占用问题。
