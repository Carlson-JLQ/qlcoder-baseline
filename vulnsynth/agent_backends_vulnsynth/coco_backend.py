import asyncio
import json
import os
import shutil
import sys
from typing import Any, Dict, Optional, Tuple

from . import AgentBackend

try:
    from ..config import CHROMA_AUTH_TOKEN, CHROMA_HOST, CHROMA_PORT, CODEQL_LSP_MCP_PATH
except Exception:
    try:
        from config import CHROMA_AUTH_TOKEN, CHROMA_HOST, CHROMA_PORT, CODEQL_LSP_MCP_PATH
    except Exception:
        CHROMA_HOST = os.environ.get("CHROMA_HOST", None)
        CHROMA_PORT = int(os.environ.get("CHROMA_PORT", "8000"))
        CHROMA_AUTH_TOKEN = os.environ.get("CHROMA_AUTH_TOKEN", "test")
        CODEQL_LSP_MCP_PATH = os.environ.get("CODEQL_LSP_MCP_PATH", "")

from . import coco_prompts as prompts


_NO_CHROMA_MODES = ("no_tools",)
_NO_LSP_MODES = ("no_tools", "no_lsp")
_CANONICAL_MCP_SERVER_NAMES = ("qlcoder_chroma", "qlcoder_codeql")
_BASE_DISALLOWED_TOOLS = (
    "mcp__qlcoder_chroma__chroma_list_collections",
    "mcp__qlcoder_chroma__chroma_modify_collection",
    "mcp__qlcoder_chroma__chroma_delete_collection",
    "mcp__qlcoder_chroma__chroma_add_documents",
    "mcp__qlcoder_chroma__chroma_update_documents",
    "mcp__qlcoder_chroma__chroma_delete_documents",
)
_FULL_MODE_DISALLOWED_TOOLS = (
    "WebSearch",
    "WebFetch",
    "Bash",
    "BashOutput",
    "KillShell",
    "Agent",
    "AskUserQuestion",
)


MODELS = {
    "sonnet-4": "claude-sonnet-4-20250514",
    "sonnet-4.5": "claude-sonnet-4-5-20250929",
    "sonnet-4.6": "claude-sonnet-4-6",
    "gemini-2.5-pro": "gemini-2.5-pro",
    "gemini-2.5-flash": "gemini-2.5-flash",
    "gpt-5": "gpt-5",
    "gpt-5.4": "gpt-5.4",
    "gpt-5.5-2026-04-24": "gpt-5.5-2026-04-24",
    "deepseek-v4-pro[1m]": "deepseek-v4-pro[1m]",
    "deepseek-v4-flash[1m]": "deepseek-v4-flash[1m]",
}


def _resolve_codeql_lsp_mcp_path() -> str:
    return (CODEQL_LSP_MCP_PATH or "").strip()


def _resolve_chroma_mcp_command() -> str:
    py_bin = os.path.dirname(sys.executable)
    candidate = os.path.join(py_bin, "chroma-mcp")
    if os.path.exists(candidate):
        return candidate
    return shutil.which("chroma-mcp") or "chroma-mcp"


class CocoBackend(AgentBackend):

    def __init__(
        self,
        model: str,
        logger,
        ablation_mode: str = "full",
        mcp_configs: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(model, logger, ablation_mode=ablation_mode)
        self.cli_path = os.environ.get("COCO_PATH", shutil.which("coco") or "coco")
        self.mcp_configs = mcp_configs
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

    @staticmethod
    def _normalize_mcp_config(mcp_configs: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if not mcp_configs:
            return {}
        if not isinstance(mcp_configs, dict):
            raise ValueError("backend config field 'mcp_configs' must be a JSON object")

        def _validate_server_names(servers: Dict[str, Any]) -> Dict[str, Any]:
            normalized_servers = dict(servers)
            invalid_names = sorted(set(normalized_servers) - set(_CANONICAL_MCP_SERVER_NAMES))
            if invalid_names:
                allowed_names = ", ".join(_CANONICAL_MCP_SERVER_NAMES)
                invalid_names_text = ", ".join(invalid_names)
                raise ValueError(
                    "backend config field 'mcp_configs' only supports canonical MCP server names "
                    f"[{allowed_names}]; got unsupported server name(s): {invalid_names_text}"
                )
            return normalized_servers

        if "mcpServers" in mcp_configs:
            servers = mcp_configs.get("mcpServers")
            if not isinstance(servers, dict):
                raise ValueError("backend config field 'mcp_configs.mcpServers' must be a JSON object")
            normalized = dict(mcp_configs)
            normalized["mcpServers"] = _validate_server_names(servers)
            return normalized

        return {"mcpServers": _validate_server_names(mcp_configs)}

    def get_tool_prefix(self) -> str:
        return "mcp__qlcoder_chroma__"

    def get_codeql_tool_prefix(self) -> str:
        return "mcp__qlcoder_codeql__"

    @staticmethod
    def extract_text_output(stdout: str) -> str:
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
            for _, model_stats in model_usage.items():
                usage["total_input_tokens"] += int(model_stats.get("input_tokens", 0) or 0)
                usage["total_output_tokens"] += int(model_stats.get("output_tokens", 0) or 0)
                usage["total_cache_read_tokens"] += int(model_stats.get("cache_read_tokens", 0) or 0)
                usage["total_cache_creation_tokens"] += int(model_stats.get("cache_creation_tokens", 0) or 0)
                usage["total_reasoning_tokens"] += int(model_stats.get("reasoning_tokens", 0) or 0)
                usage["sessions_count"] += int(model_stats.get("requests", 0) or 0)
        except Exception as exc:
            usage["parsing_errors"].append(f"Failed to parse Coco usage JSON: {exc}")

        return usage

    def setup_workspace(self, output_dir: str, task) -> Optional[str]:
        """Write project-scoped `.mcp.json` for Coco."""
        mcp_json_path = os.path.join(output_dir, ".mcp.json")
        git_root = self._find_git_root(output_dir)
        project_mcp_path = os.path.join(git_root, ".mcp.json") if git_root else None

        if self.ablation_mode in _NO_CHROMA_MODES:
            if os.path.exists(mcp_json_path):
                os.remove(mcp_json_path)
            if project_mcp_path:
                try:
                    if os.path.exists(project_mcp_path):
                        with open(project_mcp_path, "rb") as bf:
                            self._project_mcp_backup = bf.read()
                    else:
                        self._project_mcp_backup = None

                    with open(project_mcp_path, "w", encoding="utf-8") as f:
                        json.dump({"mcpServers": {}}, f, indent=2, ensure_ascii=False)
                    self._project_mcp_path = project_mcp_path
                    self.logger.info(
                        f"Ablation mode '{self.ablation_mode}': wrote empty project MCP config to isolate Coco tools"
                    )
                except Exception as exc:
                    self.logger.warning(f"Failed to isolate project .mcp.json at git root: {exc}")
            self.logger.info(f"Ablation mode '{self.ablation_mode}': skipping all MCP setup")
            return None

        include_codeql = self.ablation_mode not in _NO_LSP_MODES
        if not include_codeql:
            self.logger.info(f"Ablation mode '{self.ablation_mode}': skipping CodeQL LSP MCP setup")

        config = self._build_mcp_config(include_codeql=include_codeql)
        with open(mcp_json_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        self.logger.info(f"Wrote Coco MCP config: {mcp_json_path}")

        if project_mcp_path:
            try:
                if os.path.exists(project_mcp_path):
                    with open(project_mcp_path, "rb") as bf:
                        self._project_mcp_backup = bf.read()
                else:
                    self._project_mcp_backup = None

                with open(project_mcp_path, "w", encoding="utf-8") as f:
                    json.dump(config, f, indent=2, ensure_ascii=False)
                self._project_mcp_path = project_mcp_path
                self.logger.info(f"Wrote Coco project MCP config: {project_mcp_path}")
            except Exception as exc:
                self.logger.warning(f"Failed to write project .mcp.json at git root: {exc}")
        return None

    def cleanup_workspace(self) -> None:
        if not self._project_mcp_path:
            return
        try:
            if self._project_mcp_backup is None:
                if os.path.exists(self._project_mcp_path):
                    os.remove(self._project_mcp_path)
            else:
                with open(self._project_mcp_path, "wb") as f:
                    f.write(self._project_mcp_backup)
        except Exception as exc:
            self.logger.warning(f"Failed to restore project .mcp.json: {exc}")
        finally:
            self._project_mcp_path = None
            self._project_mcp_backup = None

    async def cleanup(self):
        try:
            await super().cleanup()
        finally:
            self.cleanup_workspace()

    def _build_default_mcp_servers(self, include_codeql: bool) -> Dict[str, Dict[str, Any]]:
        chroma_host = CHROMA_HOST or "localhost"
        chroma_command = _resolve_chroma_mcp_command()
        if os.path.isabs(chroma_command):
            chroma_exists = os.path.exists(chroma_command)
        else:
            chroma_exists = shutil.which(chroma_command) is not None
        if not chroma_exists:
            raise ValueError(
                "Unable to resolve chroma-mcp executable for Coco backend; checked command "
                f"'{chroma_command}'"
            )
        servers = {
            "qlcoder_chroma": {
                "type": "stdio",
                "command": chroma_command,
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
            if not codeql_mcp_path:
                raise ValueError(
                    "CODEQL_LSP_MCP_PATH is empty, but Coco backend needs it when ablation mode enables CodeQL MCP"
                )
            codeql_entry = os.path.join(codeql_mcp_path, "dist", "index.js")
            if not os.path.exists(codeql_entry):
                raise ValueError(
                    "CODEQL_LSP_MCP_PATH does not contain the expected entry file: "
                    f"{codeql_entry}"
                )
            servers["qlcoder_codeql"] = {
                "type": "stdio",
                "command": "node",
                "args": [codeql_entry],
            }

        return servers

    def _build_mcp_config(self, include_codeql: bool) -> Dict[str, Any]:
        config = self._normalize_mcp_config(self.mcp_configs)
        merged_servers = self._build_default_mcp_servers(include_codeql=include_codeql)

        custom_servers = dict(config.get("mcpServers", {}))
        invalid_names = sorted(set(custom_servers) - set(_CANONICAL_MCP_SERVER_NAMES))
        if invalid_names:
            allowed_names = ", ".join(_CANONICAL_MCP_SERVER_NAMES)
            invalid_names_text = ", ".join(invalid_names)
            raise ValueError(
                "backend config field 'mcp_configs' only supports canonical MCP server names "
                f"[{allowed_names}]; got unsupported server name(s): {invalid_names_text}"
            )
        if not include_codeql:
            custom_servers.pop("qlcoder_codeql", None)

        merged_servers.update(custom_servers)

        final_config = dict(config)
        final_config["mcpServers"] = merged_servers
        return final_config

    def _build_tool_flags(self) -> Tuple[list, list]:
        allowed: list = []
        disallowed: list = list(_BASE_DISALLOWED_TOOLS)

        if self.ablation_mode == "full":
            disallowed += list(_FULL_MODE_DISALLOWED_TOOLS)

        if self.ablation_mode == "no_tools":
            disallowed += ["mcp__qlcoder_chroma__*", "mcp__qlcoder_codeql__*"]
        elif self.ablation_mode == "no_lsp":
            disallowed += ["mcp__qlcoder_codeql__*"]

        return allowed, disallowed

    @staticmethod
    def _extract_message_and_error(raw_json: str) -> Tuple[str, str]:
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
        try:
            data = json.loads(raw_json)
            calls: list = []
            for state in data.get("agent_states") or []:
                for message in state.get("messages") or []:
                    for tool_call in message.get("tool_calls") or []:
                        calls.append(tool_call)
            return calls
        except Exception:
            return []

    def _log_and_persist_tool_calls(self, cwd: str, phase_name: str, tool_calls: list) -> None:
        if not tool_calls:
            self.logger.info(f"[coco] phase={phase_name} tool_calls=0")
            return

        counts: Dict[str, int] = {}
        for tool_call in tool_calls:
            fn = ((tool_call or {}).get("function") or {})
            name = fn.get("name") or (tool_call or {}).get("name") or "<unknown>"
            counts[name] = counts.get(name, 0) + 1

        counts_str = ", ".join(
            f"{name}={count}" for name, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        )
        self.logger.info(f"[coco] phase={phase_name} tool_calls={len(tool_calls)} ({counts_str})")

        try:
            out_path = os.path.join(cwd, f"{phase_name}_coco_tool_calls.json")
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(tool_calls, f, ensure_ascii=False, indent=2)
        except Exception as exc:
            self.logger.warning(f"[coco] Failed to persist tool calls for phase={phase_name}: {exc}")

    async def execute_prompt(
        self,
        prompt: str,
        env: dict,
        cwd: str,
        phase_name: str,
        stdin_text: Optional[str] = None,
    ) -> Dict:
        """Execute a single Coco query.

        `stdin_text` is intentionally ignored for Coco. It is kept only to stay
        compatible with the shared `AgentBackend.execute_prompt` interface used
        by other backends and the main orchestration flow.
        """
        model_id = MODELS.get(self.model, self.model)
        prompt_path = os.path.join(cwd, f"{phase_name}_prompt.txt")
        if stdin_text:
            self.logger.debug(
                "[coco] Ignoring stdin_text for phase=%s; Coco reads task payloads from files instead.",
                phase_name,
            )
        try:
            with open(prompt_path, "w", encoding="utf-8") as f:
                f.write(prompt)
        except Exception as exc:
            self.logger.error(f"Failed to persist Coco prompt file for phase={phase_name}: {exc}")
            return {
                "stdout": "",
                "stderr": f"Failed to persist prompt file: {exc}",
                "returncode": 1,
                "api_usage": self.parse_usage(""),
            }
        wrapper_prompt = (
            "你现在在执行 VulnSynth 的一个阶段。\n"
            f"1) 先用 Read 工具完整读取这个文件：`{prompt_path}`。\n"
            "   - 如果文件超过 2000 行，请多次调用 Read（调整 offset/limit）直到读完。\n"
            "2) 读取完成后，把文件内容当作本轮的完整任务指令，严格逐条执行。\n"
            "3) 最终按指令要求输出；如果要求输出 `QUERY_FILE_PATH:`，必须原样输出。\n"
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
            "--yolo",
        ]

        for tool_name in allowed:
            cmd += ["--allowed-tool", tool_name]
        for tool_name in disallowed:
            cmd += ["--disallowed-tool", tool_name]

        cmd.append(wrapper_prompt)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                env=env,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
            )

            stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=3600)
            stdout_raw = stdout_bytes.decode("utf-8", errors="replace")
            stderr_str = stderr_bytes.decode("utf-8", errors="replace")
            api_usage = self.parse_usage(stdout_raw)

            tool_calls = self._extract_tool_calls(stdout_raw)
            self._log_and_persist_tool_calls(cwd=cwd, phase_name=phase_name, tool_calls=tool_calls)

            msg_text, json_err = self._extract_message_and_error(stdout_raw)
            if json_err:
                stderr_str = (stderr_str + "\n" + json_err).strip()
                returncode = 1
            else:
                returncode = proc.returncode

            return {
                "stdout": msg_text,
                "stderr": stderr_str,
                "returncode": returncode,
                "api_usage": api_usage,
            }
        except Exception as exc:
            self.logger.error(f"Coco execution failed: {exc}")
            return {
                "stdout": "",
                "stderr": str(exc),
                "returncode": 1,
                "api_usage": self.parse_usage(""),
            }

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
        if self.ablation_mode == "no_lsp":
            return prompts.phase3_no_lsp(task, use_cache, collection_name)
        if self.ablation_mode == "no_docs":
            return prompts.phase3_no_docs(task, use_cache, collection_name)
        if self.ablation_mode == "no_ast":
            return prompts.phase3_no_ast(task, use_cache, collection_name)
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
        if self.ablation_mode == "no_lsp":
            return prompts.refinement_no_lsp(task, previous_feedback, iteration, collection_name)
        if self.ablation_mode == "no_docs":
            return prompts.refinement_no_docs(task, previous_feedback, iteration, collection_name)
        if self.ablation_mode == "no_ast":
            return prompts.refinement_no_ast(task, previous_feedback, iteration, collection_name)
        return prompts.refinement_full(task, previous_feedback, iteration, collection_name)
