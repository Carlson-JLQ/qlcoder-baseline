import asyncio
import json
import os
import shutil
import sys
from typing import Dict, Optional, Tuple

from . import AgentBackend

# Keep import compatible with both execution styles:
# - `python src/ql_agent.py` (sys.path contains `src/`, so `import config` works)
# - `python -m src.ql_agent` or package imports (repo root on sys.path)
try:
    from config import CHROMA_AUTH_TOKEN, CHROMA_HOST, CHROMA_PORT, CODEQL_LSP_MCP_PATH  # type: ignore
except Exception:  # pragma: no cover
    from src.config import CHROMA_AUTH_TOKEN, CHROMA_HOST, CHROMA_PORT, CODEQL_LSP_MCP_PATH
from . import coco_prompts as prompts


# Ablation modes that skip Chroma MCP setup
_NO_CHROMA_MODES = ("no_tools",)
# Ablation modes that skip CodeQL LSP MCP setup
_NO_LSP_MODES = ("no_tools", "no_lsp")


# Coco supports direct model override via: -c model.name=<model>
MODELS = {
    # Keep compatibility with qlcoder CLI model aliases
    "sonnet-4": "claude-sonnet-4-20250514",
    "sonnet-4.5": "claude-sonnet-4-5-20250929",
    "gemini-2.5-pro": "gemini-2.5-pro",
    "gemini-2.5-flash": "gemini-2.5-flash",
    "gpt-5": "gpt-5",
}


def _resolve_codeql_lsp_mcp_path() -> str:
    """Resolve CodeQL LSP MCP path.

    CODEQL_LSP_MCP_PATH should be configured via `.env` / `config.py`.
    """
    return (CODEQL_LSP_MCP_PATH or "").strip()


def _resolve_chroma_mcp_command() -> str:
    """Prefer the chroma-mcp co-located with the current Python env."""
    py_bin = os.path.dirname(sys.executable)
    candidate = os.path.join(py_bin, "chroma-mcp")
    if os.path.exists(candidate):
        return candidate
    return shutil.which("chroma-mcp") or "chroma-mcp"


class CocoBackend(AgentBackend):

    def __init__(self, model: str, logger, ablation_mode: str = "full"):
        super().__init__(model, logger, ablation_mode=ablation_mode)
        self.cli_path = os.environ.get(
            "COCO_PATH", shutil.which("coco") or "coco"
        )
        self._project_mcp_path: Optional[str] = None
        self._project_mcp_backup: Optional[bytes] = None

    @staticmethod
    def _find_git_root(start_dir: str) -> Optional[str]:
        cur = os.path.abspath(start_dir)
        while True:
            if os.path.isdir(os.path.join(cur, ".git")):
                return cur
            parent = os.path.dirname(cur)
            if parent == cur:
                return None
            cur = parent

    def get_tool_prefix(self) -> str:
        # Use a project-unique MCP server name to avoid clashing with user-level config.
        return "mcp__qlcoder_chroma__"

    def get_codeql_tool_prefix(self) -> str:
        # Use a project-unique MCP server name to avoid clashing with user-level config.
        return "mcp__qlcoder_codeql__"

    @staticmethod
    def extract_text_output(stdout: str) -> str:
        # execute_prompt already returns assistant text for Coco
        return (stdout or "").strip()

    def parse_usage(self, stdout: str) -> Dict:
        usage = {
            "total_cost_usd": 0.0,
            "total_input_tokens": 0,
            "total_cache_creation_tokens": 0,
            "total_cache_read_tokens": 0,
            "total_output_tokens": 0,
            "total_reasoning_tokens": 0,
            "sessions_count": 0,
            "parsing_errors": [],
        }
        if not stdout:
            return usage

        try:
            data = json.loads(stdout)
            stats = (data or {}).get("stats", {}) or {}
            model_usage = stats.get("model_usage", {}) or {}
            for _, mu in model_usage.items():
                usage["total_input_tokens"] += int(mu.get("input_tokens", 0) or 0)
                usage["total_output_tokens"] += int(mu.get("output_tokens", 0) or 0)
                usage["total_cache_read_tokens"] += int(mu.get("cache_read_tokens", 0) or 0)
                usage["total_cache_creation_tokens"] += int(mu.get("cache_creation_tokens", 0) or 0)
                usage["total_reasoning_tokens"] += int(mu.get("reasoning_tokens", 0) or 0)
                usage["sessions_count"] += int(mu.get("requests", 0) or 0)
        except Exception as e:
            usage["parsing_errors"].append(f"Failed to parse Coco usage JSON: {e}")

        return usage

    def setup_workspace(self, output_dir: str, task) -> Optional[str]:
        """Write project-scoped `.mcp.json` for Coco.

        Coco scans `mcp.json`/`.mcp.json` in the project root as project-level MCP config.
        We generate a `.mcp.json` inside the run output directory, since coco runs with
        cwd=output_dir.
        """
        # NOTE: Coco resolves project-level MCP config from the git root.
        # We still keep a copy in `output_dir` for debugging, but also write
        # to the repo root so coco consistently picks it up.
        mcp_json_path = os.path.join(output_dir, ".mcp.json")
        git_root = self._find_git_root(output_dir)
        project_mcp_path = os.path.join(git_root, ".mcp.json") if git_root else None

        if self.ablation_mode in _NO_CHROMA_MODES:
            # Remove any existing MCP config so no MCP tools are available
            if os.path.exists(mcp_json_path):
                os.remove(mcp_json_path)
            if project_mcp_path and os.path.exists(project_mcp_path):
                # Best-effort: don't delete user config; just leave it.
                self.logger.info(
                    f"Ablation mode '{self.ablation_mode}': skipping all MCP setup (leaving existing project .mcp.json)"
                )
            self.logger.info(f"Ablation mode '{self.ablation_mode}': skipping all MCP setup")
            return None

        include_codeql = self.ablation_mode not in _NO_LSP_MODES
        if not include_codeql:
            self.logger.info(f"Ablation mode '{self.ablation_mode}': skipping CodeQL LSP MCP setup")

        config = self._build_mcp_config(include_codeql=include_codeql)
        with open(mcp_json_path, "w") as f:
            json.dump(config, f, indent=2)
        self.logger.info(f"Wrote Coco MCP config: {mcp_json_path}")

        # Also write to git root so coco picks it up reliably.
        if project_mcp_path:
            try:
                if os.path.exists(project_mcp_path):
                    with open(project_mcp_path, "rb") as bf:
                        self._project_mcp_backup = bf.read()
                else:
                    self._project_mcp_backup = None

                with open(project_mcp_path, "w", encoding="utf-8") as f:
                    json.dump(config, f, indent=2)
                self._project_mcp_path = project_mcp_path
                self.logger.info(f"Wrote Coco project MCP config: {project_mcp_path}")
            except Exception as e:
                self.logger.warning(f"Failed to write project .mcp.json at git root: {e}")
        return None

    def cleanup_workspace(self) -> None:
        """Restore project-level `.mcp.json` if we overwrote it."""
        if not self._project_mcp_path:
            return
        try:
            if self._project_mcp_backup is None:
                # We created it; remove.
                if os.path.exists(self._project_mcp_path):
                    os.remove(self._project_mcp_path)
            else:
                with open(self._project_mcp_path, "wb") as f:
                    f.write(self._project_mcp_backup)
        except Exception as e:
            self.logger.warning(f"Failed to restore project .mcp.json: {e}")
        finally:
            self._project_mcp_path = None
            self._project_mcp_backup = None

    async def cleanup(self):
        # Kill any lingering MCP processes then restore `.mcp.json`.
        try:
            await super().cleanup()
        finally:
            self.cleanup_workspace()

    def _build_mcp_config(self, include_codeql: bool) -> Dict:
        chroma_host = CHROMA_HOST or "localhost"
        chroma_cmd = _resolve_chroma_mcp_command()
        servers = {
            "qlcoder_chroma": {
                "type": "stdio",
                "command": chroma_cmd,
                "args": [
                    "--client-type",
                    "http",
                    "--host",
                    chroma_host,
                    "--port",
                    str(CHROMA_PORT),
                    "--custom-auth-credentials",
                    CHROMA_AUTH_TOKEN,
                    "--ssl",
                    "false",
                ],
            }
        }

        if include_codeql:
            codeql_mcp_path = _resolve_codeql_lsp_mcp_path()
            servers["qlcoder_codeql"] = {
                "type": "stdio",
                "command": "node",
                "args": [f"{codeql_mcp_path}/dist/index.js"],
            }

        return {"mcpServers": servers}

    def _build_tool_flags(self) -> Tuple[list, list]:
        """Return (allowed_tools_args, disallowed_tools_args) lists.

        Coco supports repeated --allowed-tool/--disallowed-tool flags.
        We use disallowed tools to enforce ablation modes.
        """
        allowed: list = []
        disallowed: list = []

        if self.ablation_mode == "no_tools":
            disallowed += ["mcp__qlcoder_chroma__*", "mcp__qlcoder_codeql__*"]
        elif self.ablation_mode == "no_lsp":
            disallowed += ["mcp__qlcoder_codeql__*"]

        return allowed, disallowed

    @staticmethod
    def _extract_message_and_error(raw_json: str) -> Tuple[str, str]:
        """Extract assistant message and error string from Coco --json output."""
        try:
            data = json.loads(raw_json)
            err = (data or {}).get("error") or ""
            msg = (data or {}).get("message") or {}
            content = (msg.get("content") or "").strip()
            return content, str(err).strip()
        except Exception:
            return raw_json.strip(), ""

    @staticmethod
    def _extract_tool_calls(raw_json: str) -> list:
        """Extract tool calls (including MCP tools) from Coco --json output.

        Coco stores tool calls in `agent_states[*].messages[*].tool_calls`.
        """
        try:
            data = json.loads(raw_json)
            calls: list = []
            for st in (data.get("agent_states") or []):
                for m in (st.get("messages") or []):
                    for tc in (m.get("tool_calls") or []):
                        calls.append(tc)
            return calls
        except Exception:
            return []

    def _log_and_persist_tool_calls(self, cwd: str, phase_name: str, tool_calls: list) -> None:
        """Best-effort: log and persist tool calls for later analysis."""
        if not tool_calls:
            self.logger.info(f"[coco] phase={phase_name} tool_calls=0")
            return

        counts: Dict[str, int] = {}
        for tc in tool_calls:
            fn = ((tc or {}).get("function") or {})
            name = fn.get("name") or (tc or {}).get("name") or "<unknown>"
            counts[name] = counts.get(name, 0) + 1

        counts_str = ", ".join(f"{k}={v}" for k, v in sorted(counts.items(), key=lambda x: (-x[1], x[0])))
        self.logger.info(f"[coco] phase={phase_name} tool_calls={len(tool_calls)} ({counts_str})")

        try:
            out_path = os.path.join(cwd, f"{phase_name}_coco_tool_calls.json")
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(tool_calls, f, ensure_ascii=False, indent=2)
        except Exception as e:
            self.logger.warning(f"[coco] Failed to persist tool calls for phase={phase_name}: {e}")

    async def execute_prompt(
        self,
        prompt: str,
        env: dict,
        cwd: str,
        phase_name: str,
    ) -> Dict:
        """Execute a single Coco non-interactive query.

        Important: Coco's non-interactive mode requires the prompt via argv.
        QLCoder prompts can be very large (e.g., diffs), so we avoid passing the
        full prompt string by instead referencing the already-written prompt file
        (ql_agent.py writes `<phase_name>_prompt.txt` before calling the backend).
        """

        model_id = MODELS.get(self.model, self.model)

        prompt_path = os.path.join(cwd, f"{phase_name}_prompt.txt")
        wrapper_prompt = (
            "你现在在执行 QLCoder 的一个阶段。\n"
            f"1) 先用 Read 工具完整读取这个文件：`{prompt_path}`。\n"
            "   - 如果文件超过 2000 行，请多次调用 Read（调整 offset/limit）直到读完。\n"
            "2) 读取完成后，把文件内容当作本轮的完整任务指令，严格逐条执行。\n"
            "3) 最终按指令要求输出（例如需要 `QUERY_FILE_PATH:` 时必须输出）。\n"
        )

        allowed, disallowed = self._build_tool_flags()
        cmd = [
            self.cli_path,
            "--print",
            "--json",
            "--query-timeout",
            "1h",
            "--bash-tool-timeout",
            "30m",
            "-c",
            f"model.name={model_id}",
        ]

        # YOLO is the safest default for automation; disallowed tools still apply.
        cmd.append("--yolo")

        for t in allowed:
            cmd += ["--allowed-tool", t]
        for t in disallowed:
            cmd += ["--disallowed-tool", t]

        cmd.append(wrapper_prompt)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
            )

            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=3600
            )

            stdout_raw = stdout_bytes.decode("utf-8", errors="replace")
            stderr_str = stderr_bytes.decode("utf-8", errors="replace")
            api_usage = self.parse_usage(stdout_raw)

            # Record tool calls (especially MCP tools) per phase for debugging/analysis.
            tool_calls = self._extract_tool_calls(stdout_raw)
            self._log_and_persist_tool_calls(cwd=cwd, phase_name=phase_name, tool_calls=tool_calls)

            msg_text, json_err = self._extract_message_and_error(stdout_raw)
            # In --json mode, errors may be reported in JSON while exit code stays 0.
            if json_err:
                stderr_str = (stderr_str + "\n" + json_err).strip()
                returncode = 1
            else:
                returncode = proc.returncode

            return {
                # Return assistant text so ql_agent can find QUERY_FILE_PATH markers
                "stdout": msg_text,
                "stderr": stderr_str,
                "returncode": returncode,
                "api_usage": api_usage,
            }

        except Exception as e:
            self.logger.error(f"Coco execution failed: {e}")
            return {
                "stdout": "",
                "stderr": str(e),
                "returncode": 1,
                "api_usage": self.parse_usage(""),
            }

    # Prompt generation

    def create_phase1_prompt(self, task) -> str:
        if self.ablation_mode in ("no_tools", "no_docs"):
            return prompts.phase1_no_docs(task)
        return prompts.phase1_full(task)

    def create_phase3_initial_prompt(
        self,
        task,
        use_cache: bool,
        collection_name: str,
        phase1_output: str = "",
    ) -> str:
        if self.ablation_mode == "no_tools":
            return prompts.phase3_no_tools(task, phase1_output=phase1_output)
        elif self.ablation_mode == "no_lsp":
            return prompts.phase3_no_lsp(task, use_cache, collection_name)
        elif self.ablation_mode == "no_docs":
            return prompts.phase3_no_docs(task, use_cache, collection_name)
        elif self.ablation_mode == "no_ast":
            return prompts.phase3_no_ast(task, use_cache, collection_name)
        else:
            return prompts.phase3_full(task, use_cache=use_cache, collection_name=collection_name)

    def create_refinement_prompt(
        self,
        task,
        previous_feedback: str,
        iteration: int,
        collection_name: str,
    ) -> str:
        if self.ablation_mode == "no_tools":
            return prompts.refinement_no_tools(task, previous_feedback, iteration)
        elif self.ablation_mode == "no_lsp":
            return prompts.refinement_no_lsp(task, previous_feedback, iteration, collection_name)
        elif self.ablation_mode == "no_docs":
            return prompts.refinement_no_docs(task, previous_feedback, iteration, collection_name)
        elif self.ablation_mode == "no_ast":
            return prompts.refinement_no_ast(task, previous_feedback, iteration, collection_name)
        else:
            return prompts.refinement_full(task, previous_feedback, iteration, collection_name)
