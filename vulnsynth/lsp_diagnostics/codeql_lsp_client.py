"""
CodeQL LSP client for direct Python integration.
Spawns `codeql execute language-server` and communicates via JSON-RPC over stdin/stdout.
"""

import asyncio
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Optional, Any

logger = logging.getLogger(__name__)


class CodeQLLspClient:
    """Python-side CodeQL LSP client.

    Communicates directly with `codeql execute language-server` process
    using the Language Server Protocol (JSON-RPC 2.0) over stdin/stdout.

    Usage:
        client = CodeQLLspClient()
        await client.start(workspace_dir="/path/to/workspace")
        await client.open_document("file:///path/to/query.ql", content)
        diags = await client.get_diagnostics("file:///path/to/query.ql")
        hover = await client.get_hover("file:///path/to/query.ql", line=5, char=10)
        completions = await client.get_completions("file:///path/to/query.ql", line=5, char=10)
        await client.stop()
    """

    def __init__(self, codeql_path: str = "codeql", timeout: float = 30.0,
                 search_path: str = None):
        self.codeql_path = codeql_path
        self.timeout = timeout
        self.search_path = search_path or self._detect_search_path(codeql_path)
        self.process: Optional[asyncio.subprocess.Process] = None
        self._seq = 0
        self._pending_requests: dict[int, asyncio.Future] = {}
        self._diagnostics_cache: dict[str, list[dict]] = {}
        self._diagnostics_events: dict[str, asyncio.Event] = {}
        self._reader_task: Optional[asyncio.Task] = None
        self._buffer = b""
        self._initialized = False

    @staticmethod
    def _detect_search_path(codeql_path: str) -> str:
        """Auto-detect the CodeQL qlpack search path."""
        # Try to find the codeql bundle directory
        import subprocess
        try:
            result = subprocess.run(
                [codeql_path, "resolve", "packs"],
                capture_output=True, text=True, timeout=15,
            )
            # Extract the qlpack root from the resolve output
            for line in result.stdout.splitlines():
                if "java-all@" in line and "qlpack.yml" in line:
                    # e.g., "codeql/java-all@7.7.2: (library) /opt/.../qlpacks/codeql/java-all/.../qlpack.yml"
                    parts = line.split()
                    if len(parts) >= 3:
                        qlpack_path = parts[-1]
                        # Walk up to find the qlpacks root directory
                        p = Path(qlpack_path)
                        while p.parent != p:
                            if p.name == "qlpacks":
                                return str(p)
                            p = p.parent
        except Exception:
            pass
        return ""

    def _next_id(self) -> int:
        self._seq += 1
        return self._seq

    async def start(self, workspace_dir: str) -> None:
        """Start the CodeQL language server process and initialize."""
        logger.info(f"Starting CodeQL LSP, workspace={workspace_dir}")

        # Build LSP process arguments
        lsp_args = [
            self.codeql_path, "execute", "language-server",
            "--check-errors", "ON_CHANGE",
        ]
        if self.search_path:
            lsp_args.extend(["--search-path", self.search_path])
            logger.info(f"LSP search path: {self.search_path}")

        self.process = await asyncio.create_subprocess_exec(
            *lsp_args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=workspace_dir,
        )

        # Start background reader for LSP notifications/responses
        self._reader_task = asyncio.create_task(self._read_loop())

        # Initialize the LSP session
        init_params = {
            "processId": os.getpid(),
            "rootUri": f"file://{workspace_dir}",
            "capabilities": {
                "textDocument": {
                    "completion": {"completionItem": {"snippetSupport": True}},
                    "hover": {"contentFormat": ["markdown", "plaintext"]},
                    "definition": {},
                    "references": {},
                    "synchronization": {"didSave": True},
                },
            },
        }

        result = await self._send_request("initialize", init_params)
        if result is None:
            raise RuntimeError("LSP initialization failed — no response from server")
        logger.info(f"LSP initialized: server={result.get('serverInfo', {}).get('name', 'unknown')}")

        await self._send_notification("initialized", {})
        await asyncio.sleep(0.5)  # Let server settle
        self._initialized = True
        logger.info("CodeQL LSP ready")

    async def open_document(self, uri: str, content: str) -> None:
        """Open or update a document in the LSP, triggering analysis."""
        self._diagnostics_cache.pop(uri, None)
        self._diagnostics_events.pop(uri, None)

        await self._send_notification("textDocument/didOpen", {
            "textDocument": {
                "uri": uri,
                "languageId": "ql",
                "version": 1,
                "text": content,
            }
        })
        logger.debug(f"Opened document: {uri}")

    async def update_document(self, uri: str, content: str, version: int = 2) -> None:
        """Update an already-open document."""
        self._diagnostics_cache.pop(uri, None)
        self._diagnostics_events.pop(uri, None)

        await self._send_notification("textDocument/didChange", {
            "textDocument": {"uri": uri, "version": version},
            "contentChanges": [{"text": content}],
        })
        logger.debug(f"Updated document: {uri} v{version}")

    async def get_diagnostics(
        self, uri: str, wait_ms: int = 1500
    ) -> list[dict]:
        """Get diagnostics for a document.

        Waits for publishDiagnostics notification from LSP.
        Falls back to sending didSave to force re-analysis.
        """
        # Trigger re-analysis via didSave
        await self._send_notification("textDocument/didSave", {
            "textDocument": {"uri": uri}
        })

        # Wait for diagnostics to arrive asynchronously
        event = asyncio.Event()
        self._diagnostics_events[uri] = event

        try:
            await asyncio.wait_for(event.wait(), timeout=wait_ms / 1000.0)
        except asyncio.TimeoutError:
            logger.debug(f"Timeout waiting for diagnostics for {uri}")

        # Small extra wait for any trailing notifications
        await asyncio.sleep(0.3)

        return self._diagnostics_cache.get(uri, [])

    async def get_hover(self, uri: str, line: int, character: int) -> Optional[dict]:
        """Get hover information (type, documentation) at a position."""
        result = await self._send_request("textDocument/hover", {
            "textDocument": {"uri": uri},
            "position": {"line": line, "character": character},
        })
        return result

    async def get_completions(self, uri: str, line: int, character: int) -> list[str]:
        """Get completion items at a position. Returns list of labels."""
        result = await self._send_request("textDocument/completion", {
            "textDocument": {"uri": uri},
            "position": {"line": line, "character": character},
        })
        if result and "items" in result:
            return [
                item.get("label", "")
                for item in result["items"]
                if item.get("label")
            ]
        # Some servers return a CompletionList
        if isinstance(result, list):
            return [item.get("label", "") for item in result if item.get("label")]
        return []

    async def get_definition(self, uri: str, line: int, character: int) -> Optional[list[dict]]:
        """Get definition location(s) for a symbol."""
        result = await self._send_request("textDocument/definition", {
            "textDocument": {"uri": uri},
            "position": {"line": line, "character": character},
        })
        return result

    async def stop(self) -> None:
        """Shut down the LSP server cleanly."""
        logger.info("Stopping CodeQL LSP...")
        try:
            await self._send_request("shutdown", {})
            await self._send_notification("exit", {})
        except Exception:
            pass

        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass

        if self.process:
            try:
                self.process.stdin.close()
            except Exception:
                pass
            try:
                await asyncio.wait_for(self.process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                self.process.kill()
                await self.process.wait()

        self._initialized = False
        logger.info("CodeQL LSP stopped")

    # ── internal JSON-RPC communication ──────────────────────────

    def _build_message(self, payload: dict) -> bytes:
        body = json.dumps(payload, ensure_ascii=False)
        header = f"Content-Length: {len(body.encode('utf-8'))}\r\n\r\n"
        return header.encode("utf-8") + body.encode("utf-8")

    async def _send_request(self, method: str, params: dict) -> Optional[dict]:
        req_id = self._next_id()
        msg = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}

        future: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending_requests[req_id] = future

        if self.process and self.process.stdin:
            self.process.stdin.write(self._build_message(msg))
            await self.process.stdin.drain()
        else:
            return None

        try:
            return await asyncio.wait_for(future, timeout=self.timeout)
        except asyncio.TimeoutError:
            logger.warning(f"LSP request timeout: {method}")
            return None
        finally:
            self._pending_requests.pop(req_id, None)

    async def _send_notification(self, method: str, params: dict) -> None:
        msg = {"jsonrpc": "2.0", "method": method, "params": params}
        if self.process and self.process.stdin:
            self.process.stdin.write(self._build_message(msg))
            await self.process.stdin.drain()

    async def _read_loop(self) -> None:
        """Background reader: parse LSP messages from stdout."""
        while self.process and not self.process.stdout.at_eof():
            try:
                # Read headers
                content_length = 0
                while True:
                    line = await self.process.stdout.readline()
                    if not line:
                        return
                    line = line.decode("utf-8", errors="replace").strip()
                    if not line:
                        break
                    if line.lower().startswith("content-length:"):
                        content_length = int(line.split(":", 1)[1].strip())

                if content_length <= 0:
                    continue

                # Read body
                body = await self.process.stdout.readexactly(content_length)

                try:
                    message = json.loads(body.decode("utf-8", errors="replace"))
                except json.JSONDecodeError:
                    continue

                # Handle response (has id)
                if "id" in message and message["id"] is not None:
                    req_id = message["id"]
                    future = self._pending_requests.get(req_id)
                    if future and not future.done():
                        if "error" in message:
                            future.set_exception(
                                RuntimeError(message["error"].get("message", "LSP error"))
                            )
                        else:
                            future.set_result(message.get("result"))

                # Handle notification
                elif "method" in message:
                    await self._handle_notification(message)

            except asyncio.IncompleteReadError:
                break
            except Exception as e:
                logger.debug(f"LSP reader error: {e}")
                continue

    async def _handle_notification(self, msg: dict) -> None:
        """Handle an incoming LSP notification."""
        method = msg.get("method", "")

        if method == "textDocument/publishDiagnostics":
            params = msg.get("params", {})
            uri = params.get("uri", "")
            diagnostics = params.get("diagnostics", [])
            self._diagnostics_cache[uri] = diagnostics

            # Signal any waiter
            event = self._diagnostics_events.get(uri)
            if event and not event.is_set():
                event.set()

            error_count = sum(1 for d in diagnostics if d.get("severity", 0) == 1)
            logger.debug(f"Diagnostics for {uri}: {error_count} errors, "
                         f"{len(diagnostics) - error_count} warnings")

        elif method == "window/logMessage":
            params = msg.get("params", {})
            logger.debug(f"LSP log: {params.get('message', '')}")
