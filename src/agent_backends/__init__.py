"""Agent backend abstraction for multi-CLI support.

Each backend encapsulates:
- CLI invocation (how to run the agent)
- Workspace setup (MCP config, settings files)
- Output parsing (token usage, cost)
- Tool name prefixes (for prompt generation)
"""

from abc import ABC, abstractmethod
from typing import Dict, Optional
import logging
from config import CODEQL_LSP_MCP_PATH

ABLATION_MODES = ("full", "no_tools", "no_lsp", "no_docs", "no_ast")


class AgentBackend(ABC):
    """Abstract base for agent CLI backends."""

    def __init__(self, model: str, logger: logging.Logger, ablation_mode: str = "full"):
        self.model = model
        self.logger = logger
        if ablation_mode not in ABLATION_MODES:
            raise ValueError(f"Unknown ablation_mode {ablation_mode!r}. Choose from {ABLATION_MODES}")
        self.ablation_mode = ablation_mode

    @abstractmethod
    async def execute_prompt(
        self,
        prompt: str,# 提示词
        env: dict, # 环境变量，.env文件中的变量,从config.py中获取
        cwd: str, # 工作目录，输出所在目录，agent 在里面读写文件
        phase_name: str,
    ) -> Dict:
        """Run a single prompt through the agent CLI.

        Returns dict with keys: stdout, stderr, returncode, api_usage
        """

    @abstractmethod
    def setup_workspace(self, output_dir: str, task) -> Optional[str]:
        """Prepare the workspace for this backend.

        MCP server config, config file generation,
        and any CLI-specific directory setup.

        Returns an optional config_path (e.g. for CLAUDE_DESKTOP_CONFIG).
        """

    @abstractmethod
    def get_tool_prefix(self) -> str:
        """Return the MCP tool name prefix used in prompts.

        Claude uses 'mcp__chroma__' and 'mcp__codeql__'.
        Gemini/Codex use '' 
        """

    @abstractmethod
    def parse_usage(self, stdout: str) -> Dict:
        """Parse token/cost metrics from CLI output."""

    @abstractmethod
    def create_refinement_prompt(self, task, previous_feedback: str,
                                 iteration: int, collection_name: str) -> str:
        # 生成强化query的提示词
        # phase 1 / phase 2 的输出会被保存进 ChromaDB，按这次运行单独放到一个 collection 里，collection_name作用是获取前面2阶段的输出
        """Create the prompt for query refinement (iteration 2+).

        Each backend may reference tools with different prefixes and use
        different prompt structures.
        """

    def get_phase3_prompts(self, task, config_path, output_dir, use_cache,
                           collection_name, iteration: int,
                           previous_feedback: Optional[str] = None) -> list:
        #use_cache 是否使用chroma缓存,也就是获取历史信息
        #collection_name 当前这次运行在 ChromaDB 里的 collection 名称
        """Return a list of (prompt, phase_name) tuples for a phase 3 iteration.

        Most backends return a single prompt. Gemini returns two (step2 + step3)
        for iteration 1. Default implementation defers to shared prompts.
        """
        raise NotImplementedError("Subclass should override or use default flow")

    async def cleanup(self):
        """Best-effort cleanup of MCP server processes."""
        ## 异步地启动并等待多个清理命令执行完成，但不阻塞整个事件循环线程
        import asyncio

        for pattern in [
            "pkill -f 'chroma-mcp'",
            # Prefer the repo name used in this project: codeql-lsp-mcp
            "pkill -f 'codeql-lsp-mcp/dist/index.js'",
            "pkill -f '{CODEQL_LSP_MCP_PATH}/dist/index.js'",
            # Backward-compatible pattern (older name)
            "pkill -f 'codeql-mcp/dist/index.js'",
            "pkill -f 'codeql.*language-server'",
        ]:
            try:
                p = await asyncio.create_subprocess_shell(
                    pattern,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await p.communicate()
            except Exception:
                pass

        self.logger.info("MCP servers cleanup completed")


def create_backend(agent_type: str, model: str, logger: logging.Logger,
                   ablation_mode: str = "full") -> AgentBackend:
    """Factory function to create the appropriate backend."""
    if agent_type == "claude":
        from .claude_backend import ClaudeBackend
        return ClaudeBackend(model, logger, ablation_mode=ablation_mode)
    elif agent_type == "gemini":
        from .gemini_backend import GeminiBackend
        return GeminiBackend(model, logger, ablation_mode=ablation_mode)
    elif agent_type == "codex":
        from .codex_backend import CodexBackend
        return CodexBackend(model, logger, ablation_mode=ablation_mode)
    elif agent_type == "coco":
        from .coco_backend import CocoBackend
        return CocoBackend(model, logger, ablation_mode=ablation_mode)
    else:
        raise ValueError(
            f"Unknown agent type: {agent_type!r}. Available: claude, gemini, codex, coco"
        )
