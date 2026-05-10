# Debug Session: phase-setup-failure
- **Status**: [OPEN]
- **Issue**: `src/ql_agent.py --agent codex` 在 `Phase 1 & 2 (one-time setup)` 后失败，日志显示 `Failed to parse JSON output`，最终报 `Setup phases failed`
- **Debug Server**: N/A
- **Log File**: `/home/byteide/research/qlcoder/src/output/ql_agent_CVE-2025-49656_20260501_163421_10-iterations_gpt-5.5-2026-04-24_full/results/iterative_vuln_analysis_20260501_163421.log`

## Reproduction Steps
1. 运行 `src/ql_agent.py --cve-id CVE-2025-49656 --agent codex`
2. 观察 Phase 1 执行输出、Phase 2 缓存命中和 JSON 解析日志
3. 定位 setup 返回失败的具体分支
4. 如有必要，添加最小化日志插桩后复现

## Hypotheses & Verification
| ID | Hypothesis | Likelihood | Effort | Evidence |
|----|------------|------------|--------|----------|
| A | Phase 1 的 Codex stdout 不是预期 JSON/JSONL，导致输出提取为空或不可解析 | High | Medium | Pending |
| B | `codex_backend.py` 当前按 chunk 调用 `_jsonl_iter_bytes([chunk])`，跨 chunk 消息被丢弃 | High | Medium | Pending |
| C | Phase 2 缓存内容格式与 `ql_agent.py` 当前解析预期不一致，因此命中缓存后 JSON 解析失败 | High | Medium | Pending |
| D | setup 失败的直接原因不在 Phase 2，而在 Phase 1 缺少有效完成标记或结构化结果 | Medium | Medium | Pending |

## Log Evidence
- `phase1_output.txt` 为空，说明 Phase 1 没有任何 stdout 产出。
- `phase1_metrics.json` 显示：
  - `success = false`
  - `return_code = 1`
  - `character_count = 0`
  - `sessions_count = 0`
  说明 Codex CLI 在真正执行模型前就失败退出，而不是执行后返回了坏格式内容。
- `phase1_stderr.txt` 明确报错：
  - `Error loading config.toml`
  - `/home/byteide/.codex/config.toml:12:15: unknown variant 'undefined', expected 'trusted' or 'untrusted'`
  这是当前运行失败的直接证据。
- `run_report.md` 中 Phase 1 被记录为：
  - `Success: False`
  - `Return code: 1`
  说明 setup 失败在 Phase 1 就已经发生。
- `phase2_output.txt` 能正常读出缓存内容，且格式是普通 Markdown 文本，不是 JSON。
- `utils.py` 中的 `Failed to parse JSON output` 日志来自保存 Phase 2 输出到 Chroma 的 JSON 解析尝试；它是一个伴随警告，不是这次 setup 失败的根因。

## Verification Conclusion
- 这次 `Setup phases failed` 的直接根因已确认：
  - `Codex` 启动前读取 `~/.codex/config.toml` 失败。
  - 失败原因是现有配置文件里同时存在旧式 `[projects."..."] trust_level = "undefined"` 条目和新式 `projects = { ... trusted }` 条目，其中旧式条目包含非法枚举值 `undefined`。
- 因为 Codex CLI 先在配置加载阶段退出，Phase 1 没有执行，所以：
  - 没有 token_count
  - 没有 phase1 stdout
  - 没有 `[PHASE_1_COMPLETE]`
- Hypothesis 状态：
  - A：Rejected
  - B：Not primary cause for this run
  - C：Rejected
  - D：Confirmed, 但更准确地说是 “Phase 1 因 config.toml 解析失败而未开始”
