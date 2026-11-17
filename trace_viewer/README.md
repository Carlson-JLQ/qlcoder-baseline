# QLCoder Trace Viewer

本地、只读的 QLCoder 运行分析界面。它动态扫描仓库根目录的 `output/`，不会依赖成功/失败 Excel，也不会向实验输出目录写入文件。

## 功能

- 自动发现所有 `ql_agent_CVE-*` 运行，支持同一 CVE 多次运行。
- 综合 metadata、phase metrics 和 trace 末尾事件推断运行状态。
- 展示 Phase 1、Phase 2 和所有 Phase 3 iterations。
- 将 `tool_use.id` 与 `tool_result.tool_use_id` 精确关联。
- 聚合大量 `thinking_tokens` 系统事件，只展示实际 thinking/tool/result。
- Trace 服务端分页、搜索和工具/事件类型筛选。
- 查看完整 tool input、result、metadata、permission 信息和耗时。
- 查看 Query、验证结果、CSV、SARIF、metrics 等产物。
- 比较任意两个已落盘 Query 的 unified diff。
- 页面每 5 秒重新扫描活动运行；完整 trace 以 `mtime + size` 为缓存键自动失效。

## 安装

从仓库根目录执行：

```bash
uv pip install --python .venv/bin/python -r trace_viewer/requirements.txt
```

## 启动

```bash
.venv/bin/python -m trace_viewer.server
```

默认地址：

```text
http://127.0.0.1:8765
```

可配置参数：

```bash
.venv/bin/python -m trace_viewer.server --host 0.0.0.0 --port 8765
```

如果从其他位置运行，可以显式指定 QLCoder 根目录：

```bash
.venv/bin/python -m trace_viewer.server --root /root/qlcoder-baseline
```

## 数据与安全边界

- `output/` 只读。
- API 只允许读取已发现 run 的 `results` 直属文件，拒绝路径穿越。
- `.mcp.json` 和隐藏文件不进入产物列表。
- 大于 3 MiB 的文本产物只返回预览；二进制文件只展示元数据。
- 运行中的 trace JSON 可能尚未闭合，此时界面显示“暂不可解析”，文件完成后自动恢复。

## 测试

```bash
.venv/bin/python -m unittest discover -s trace_viewer/tests -v
```

集成测试使用当前 `output/`：验证 14 个成功样本都可发现，并检查 CVE-2025-2240 Iteration 2 的 74 个 tool calls 与 74 个 results 能全部关联。
