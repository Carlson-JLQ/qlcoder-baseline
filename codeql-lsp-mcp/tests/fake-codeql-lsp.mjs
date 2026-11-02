#!/usr/bin/env node

if (process.argv.includes("version")) {
  process.stdout.write("fake-codeql 1.0.0\n");
  process.exit(0);
}

let input = Buffer.alloc(0);
const documents = new Map();

function send(message) {
  const body = Buffer.from(JSON.stringify(message));
  const framed = Buffer.concat([Buffer.from(`Content-Length: ${body.length}\r\n\r\n`), body]);
  if (process.env.FAKE_LSP_DEBUG === "true") process.stderr.write(`sending ${framed.length} bytes: ${JSON.stringify(framed.toString())}\n`);
  process.stdout.write(framed);
}

function diagnostics(uri, version, text) {
  const items = text.includes("BROKEN") ? [{
    range: { start: { line: 1, character: 10 }, end: { line: 1, character: 16 } },
    severity: 1,
    source: "fake-codeql",
    message: "BROKEN is not a valid expression",
  }] : [];
  // Deliberately publish immediately to exercise the listener/cache race.
  send({ jsonrpc: "2.0", method: "textDocument/publishDiagnostics", params: { uri, version, diagnostics: items } });
}

function handle(message) {
  const { id, method, params } = message;
  if (method === "initialize") {
    send({ jsonrpc: "2.0", id, result: { capabilities: {
      textDocumentSync: 1,
      completionProvider: {}, hoverProvider: true, definitionProvider: true,
      referencesProvider: true, documentFormattingProvider: true,
      documentRangeFormattingProvider: true,
      workspace: { workspaceFolders: { supported: true, changeNotifications: true } },
    } } });
  } else if (method === "shutdown") {
    send({ jsonrpc: "2.0", id, result: null });
  } else if (method === "exit") {
    process.exit(0);
  } else if (method === "textDocument/didOpen") {
    const doc = params.textDocument;
    documents.set(doc.uri, { version: doc.version, text: doc.text });
    diagnostics(doc.uri, doc.version, doc.text);
  } else if (method === "textDocument/didChange") {
    const doc = { version: params.textDocument.version, text: params.contentChanges[0].text };
    documents.set(params.textDocument.uri, doc);
    diagnostics(params.textDocument.uri, doc.version, doc.text);
  } else if (method === "textDocument/formatting" || method === "textDocument/rangeFormatting") {
    const text = documents.get(params.textDocument.uri)?.text ?? "";
    if (text.includes("HANG_FORMAT")) return;
    const edits = text.startsWith("from   int") ? [{
      range: { start: { line: 0, character: 4 }, end: { line: 0, character: 7 } },
      newText: " ",
    }] : [];
    send({ jsonrpc: "2.0", id, result: edits });
  } else if (method === "textDocument/completion") {
    send({ jsonrpc: "2.0", id, result: { isIncomplete: false, items: [] } });
  } else if (id !== undefined) {
    send({ jsonrpc: "2.0", id, result: null });
  }
}

process.stdin.on("data", chunk => {
  if (process.env.FAKE_LSP_DEBUG === "true") process.stderr.write(`received ${chunk.length} bytes: ${JSON.stringify(chunk.toString())}\n`);
  input = Buffer.concat([input, chunk]);
  while (true) {
    const boundary = input.indexOf("\r\n\r\n");
    if (boundary < 0) return;
    const headers = input.slice(0, boundary).toString("ascii");
    const match = /Content-Length:\s*(\d+)/i.exec(headers);
    if (!match) process.exit(2);
    const length = Number(match[1]);
    const end = boundary + 4 + length;
    if (input.length < end) return;
    const message = JSON.parse(input.slice(boundary + 4, end).toString("utf8"));
    input = input.slice(end);
    handle(message);
  }
});
