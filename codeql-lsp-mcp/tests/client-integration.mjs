import assert from "node:assert/strict";
import { chmodSync, copyFileSync, readFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { CodeQLLanguageServer } from "../dist/codeql-lsp-client.js";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const workspace = join(root, "test-workspace");
const fakeCodeQL = join(here, "fake-codeql-lsp.mjs");
const sourceValid = join(workspace, "valid.ql");
const workingValid = join(workspace, "valid-working.ql");
const invalid = join(workspace, "invalid.ql");
const hangingFormat = join(workspace, "hang-format.ql");
chmodSync(fakeCodeQL, 0o755);
copyFileSync(sourceValid, workingValid);
process.env.CODEQL_LSP_FORMAT_TIMEOUT_MS = "100";

const client = new CodeQLLanguageServer({
  codeqlPath: fakeCodeQL,
  verbose: process.env.CODEQL_LSP_VERBOSE === "true",
});
try {
  await client.start([workspace]);

  const validUri = pathToFileURL(workingValid).href;
  const validContent = readFileSync(workingValid, "utf8");
  await client.updateDocument(validUri, validContent);
  const clean = await client.getDiagnostics(validUri, 1_000);
  assert.deepEqual(clean.diagnostics, [], "empty diagnostics must be treated as a successful result");
  const cachedClean = await client.getDiagnostics(validUri, 1_000);
  assert.equal(cachedClean.fromCache, true, "the latest empty diagnostics must be retained in the cache");

  const invalidUri = pathToFileURL(invalid).href;
  const invalidContent = readFileSync(invalid, "utf8");
  await client.updateDocument(invalidUri, invalidContent);
  const broken = await client.getDiagnostics(invalidUri, 1_000);
  assert.equal(broken.diagnostics.length, 1, "invalid query must return a diagnostic");

  const formatted = await client.formatDocument(validUri, undefined, true);
  assert.equal(formatted.status, "ok");
  assert.equal(formatted.editsApplied, 1);
  assert.match(readFileSync(workingValid, "utf8"), /^from int i/);

  const status = client.getStatus();
  assert.equal(status.status, "healthy");
  assert.equal(status.openDocuments, 2);
  assert.equal(status.pendingDiagnostics, 0);
  assert.equal(status.capabilities.formatting, true);

  const hangingUri = pathToFileURL(hangingFormat).href;
  await client.updateDocument(hangingUri, readFileSync(hangingFormat, "utf8"));
  await assert.rejects(
    client.formatDocument(hangingUri),
    error => error.code === "LSP_REQUEST_TIMEOUT",
    "formatting must stop at its own timeout",
  );
  assert.equal(client.getStatus().status, "degraded");

  // The next operation restarts the server, reopens documents, and succeeds.
  const recovered = await client.getDiagnostics(validUri, 1_000);
  assert.deepEqual(recovered.diagnostics, []);
  assert.equal(client.getStatus().status, "healthy");
  process.stdout.write("client integration tests passed\n");
} finally {
  await client.stop();
  rmSync(workingValid, { force: true });
}
