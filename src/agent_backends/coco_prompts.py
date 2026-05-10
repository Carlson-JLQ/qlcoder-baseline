"""Coco-specific prompt functions.

Coco uses MCP tool naming with `mcp__<server>__<tool>` like Claude.
We reuse Claude prompt templates and prepend Coco-specific environment notes.
"""

from . import claude_prompts as _base


_CODEQL_LSP_MCP_NOTE = """
## 环境提示（Coco）

- 本项目 CodeQL LSP MCP 默认路径：`/home/byteide/research/qlcoder/codeql-lsp-mcp`（启动入口：`dist/index.js`）。
- 本项目使用独立的 MCP server 名称以避免与用户级配置冲突：
  - Chroma: `mcp__qlcoder_chroma__*`
  - CodeQL LSP: `mcp__qlcoder_codeql__*`
- 如果 `mcp__qlcoder_codeql__*` 工具不可用，优先检查 `.mcp.json` 里 qlcoder_codeql server 的 `command/args` 指向是否正确。
""".strip()


def _prepend_note(text: str) -> str:
    if not text:
        return _CODEQL_LSP_MCP_NOTE
    return f"{_CODEQL_LSP_MCP_NOTE}\n\n{_rewrite_tool_prefixes(text)}"


def _rewrite_tool_prefixes(text: str) -> str:
    # Keep prompts compatible with coco project-unique MCP server names.
    return (
        (text or "")
        .replace("mcp__chroma__", "mcp__qlcoder_chroma__")
        .replace("mcp__codeql__", "mcp__qlcoder_codeql__")
    )


# Phase 1

def phase1_full(task) -> str:
    return _prepend_note(_base.phase1_full(task))


def phase1_no_docs(task) -> str:
    return _prepend_note(_base.phase1_no_docs(task))


# Phase 3 initial

def phase3_full(task, use_cache: bool, collection_name: str, phase1_output: str = None, phase2_output: str = None) -> str:
    return _prepend_note(
        _base.phase3_full(task, use_cache=use_cache, collection_name=collection_name,
                          phase1_output=phase1_output, phase2_output=phase2_output)
    )


def phase3_no_tools(task, phase1_output: str = "") -> str:
    return _prepend_note(_base.phase3_no_tools(task, phase1_output=phase1_output))


def phase3_no_lsp(task, use_cache: bool, collection_name: str) -> str:
    return _prepend_note(_base.phase3_no_lsp(task, use_cache=use_cache, collection_name=collection_name))


def phase3_no_docs(task, use_cache: bool, collection_name: str) -> str:
    return _prepend_note(_base.phase3_no_docs(task, use_cache=use_cache, collection_name=collection_name))


def phase3_no_ast(task, use_cache: bool, collection_name: str) -> str:
    return _prepend_note(_base.phase3_no_ast(task, use_cache=use_cache, collection_name=collection_name))


# Refinement

def refinement_full(task, previous_feedback: str, iteration: int, collection_name: str) -> str:
    return _prepend_note(_base.refinement_full(task, previous_feedback, iteration, collection_name))


def refinement_no_tools(task, previous_feedback: str, iteration: int) -> str:
    return _prepend_note(_base.refinement_no_tools(task, previous_feedback, iteration))


def refinement_no_lsp(task, previous_feedback: str, iteration: int, collection_name: str) -> str:
    return _prepend_note(_base.refinement_no_lsp(task, previous_feedback, iteration, collection_name))


def refinement_no_docs(task, previous_feedback: str, iteration: int, collection_name: str) -> str:
    return _prepend_note(_base.refinement_no_docs(task, previous_feedback, iteration, collection_name))


def refinement_no_ast(task, previous_feedback: str, iteration: int, collection_name: str) -> str:
    return _prepend_note(_base.refinement_no_ast(task, previous_feedback, iteration, collection_name))
