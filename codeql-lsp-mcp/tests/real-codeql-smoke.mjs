import assert from "node:assert/strict";
import { dirname, join } from "node:path";
import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { CodeQLLanguageServer } from "../dist/codeql-lsp-client.js";

const here = dirname(fileURLToPath(import.meta.url));
const workspace = join(here, "..", "test-workspace");
const query = join(workspace, "valid.ql");
const client = new CodeQLLanguageServer({ verbose: process.env.CODEQL_LSP_VERBOSE === "true" });

try {
  await client.start([workspace]);
  const uri = pathToFileURL(query).href;
  await client.updateDocument(uri, readFileSync(query, "utf8"));
  const result = await client.getDiagnostics(uri);
  assert.equal(result.status, "ok");
  const format = await client.formatDocument(uri, undefined, false);
  assert.ok(format.status === "ok" || format.status === "unsupported");
  process.stdout.write(`${JSON.stringify({ diagnostics: result, format, status: client.getStatus() }, null, 2)}\n`);
} finally {
  await client.stop();
}
