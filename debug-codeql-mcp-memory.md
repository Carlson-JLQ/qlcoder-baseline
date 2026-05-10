# Debug Session: codeql-mcp-memory
- **Status**: [OPEN]
- **Issue**: 验证 `node codeql-lsp-mcp/dist/index.js` 是否能正常启动，并观察其拉起的 CodeQL language server 内存占用与多次请求后的累积情况
- **Debug Server**: N/A
- **Log File**: N/A

## Reproduction Steps
1. 启动 `node /home/byteide/research/qlcoder/codeql-lsp-mcp/dist/index.js`
2. 观察进程树，确认是否拉起 `CodeQL language-server`
3. 记录服务和子进程内存基线
4. 发送多次 MCP 请求并重复记录内存
5. 关闭服务并确认进程已退出

## Hypotheses & Verification
| ID | Hypothesis | Likelihood | Effort | Evidence |
|----|------------|------------|--------|----------|
| A | `node dist/index.js` 可以正常启动，并以 stdio 方式等待 MCP 请求 | High | Low | Confirmed |
| B | 首次实际请求才会触发 `CodeQL language-server` 懒启动，而不是进程一启动就拉起 | High | Medium | Rejected |
| C | 多次请求后内存会有小幅波动，但不会无限累积 | Medium | Medium | Partially Rejected |
| D | 如果缺少 CodeQL 依赖或初始化失败，MCP 进程会提前退出或 stderr 报错 | Medium | Low | Rejected |

## Log Evidence
- 运行 `node codeql-lsp-mcp/dist/index.js` 后，服务正常启动，且可被 SDK 客户端连接。
- 代码本身在启动末尾主动执行 `ensureCodeQLServer()`，因此会预热拉起 `CodeQL language-server`。
- 连接后的基线内存约为：
  - Node MCP 进程 `86.59 MiB`
  - CodeQL language server `125.35 MiB`
  - 总计 `213.57 MiB`
- `listTools` 后总内存上升到约 `230.18 MiB`，CodeQL language server 约 `141.97 MiB`。
- 连续 5 次 `codeql_set_workspace` 后，总内存维持在约 `215.86 MiB` 到 `230.26 MiB`，没有线性累积。
- `codeql_open_file` 成功后，总内存约 `228.55 MiB`，CodeQL language server 约 `150.39 MiB`。
- 第二轮测试中：
  - `open_file` 后总内存约 `220.50 MiB`
  - 连续 3 次 `update_file` 后总内存稳定在 `220.75 MiB` 到 `221.09 MiB`
  - 第一次 `codeql_diagnostics` 超时后，总内存暴涨到 `2379.88 MiB`
  - 此时 CodeQL language server 约 `2308.27 MiB`
  - 后续第 2、3 次 `codeql_diagnostics` 继续超时，但内存基本持平，没有继续线性增长
- `transport.close()` / `SIGTERM` 后，相关进程全部退出，无残留 PID。

## Verification Conclusion
- `codeql-lsp-mcp` 入口命令可正常启动，配置里的 `node <dist/index.js>` 是可工作的。
- 当前实现不是懒启动，而是预热启动 CodeQL language server。
- 常规请求（`listTools`、`set_workspace`、`open_file`、`update_file`）内存表现稳定，没有明显累积。
- `codeql_diagnostics` 是异常点：请求超时同时伴随 CodeQL language server 内存一次性膨胀到约 `2.3 GiB`，说明真实风险在 diagnostics 路径，而不是服务启动路径。
