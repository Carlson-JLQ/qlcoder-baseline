import assert from "node:assert/strict";
import { chmodSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const workspace = join(root, "test-workspace");
const fakeCodeQL = join(here, "fake-codeql-lsp.mjs");
chmodSync(fakeCodeQL, 0o755);

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [join(root, "dist", "index.js")],
  cwd: workspace,
  env: { ...process.env, CODEQL_PATH: fakeCodeQL, CODEQL_LSP_INITIALIZE_TIMEOUT_MS: "2000" },
  stderr: "pipe",
});
const client = new Client({ name: "codeql-lsp-mcp-test", version: "1.0.0" });

try {
  await client.connect(transport);
  const tools = await client.listTools();
  const names = new Set(tools.tools.map(tool => tool.name));
  assert.ok(names.has("codeql_validate"));
  assert.ok(names.has("codeql_status"));

  const queryPath = join(workspace, "valid.ql");
  const validation = await client.callTool({
    name: "codeql_validate",
    arguments: { file_uri: pathToFileURL(queryPath).href, content: readFileSync(queryPath, "utf8"), timeout_ms: 1000 },
  });
  assert.equal(validation.isError, undefined);
  const validationBody = JSON.parse(validation.content[0].text);
  assert.deepEqual(validationBody.diagnostics, []);

  const status = await client.callTool({ name: "codeql_status", arguments: {} });
  assert.equal(JSON.parse(status.content[0].text).status, "healthy");

  const missing = await client.callTool({
    name: "codeql_diagnostics",
    arguments: { file_uri: pathToFileURL(join(workspace, "missing.ql")).href, timeout_ms: 100 },
  });
  assert.equal(missing.isError, true, "tool failures must be MCP errors, not successful text responses");
  assert.equal(JSON.parse(missing.content[0].text).code, "DOCUMENT_NOT_OPEN");
  process.stdout.write("MCP tool smoke tests passed\n");
} finally {
  await client.close();
}
