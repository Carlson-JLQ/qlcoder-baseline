import { spawn, ChildProcessWithoutNullStreams, execFileSync } from "child_process";
import {
    InitializeParams, InitializeResult, ServerCapabilities,
    CompletionParams, CompletionList, HoverParams, Hover,
    DefinitionParams, Location, DocumentFormattingParams, DocumentRangeFormattingParams,
    TextEdit, PublishDiagnosticsParams, Diagnostic, DidOpenTextDocumentParams,
    DidChangeTextDocumentParams, Range,
} from "vscode-languageserver-protocol";
import {
    createMessageConnection, MessageConnection, StreamMessageReader, StreamMessageWriter,
} from "vscode-jsonrpc/node.js";
import {
    existsSync, readFileSync, writeFileSync, appendFileSync, mkdirSync,
    renameSync, unlinkSync,
} from "fs";
import { homedir } from "os";
import { dirname, join, delimiter } from "path";
import { fileURLToPath } from "url";

export interface CodeQLClientOptions {
    codeqlPath?: string;
    verbose?: boolean;
    logDir?: string;
}

export interface DiagnosticsResult {
    status: "ok";
    uri: string;
    documentVersion: number;
    diagnosticsVersion: number;
    fromCache: boolean;
    durationMs: number;
    diagnostics: Diagnostic[];
}

export interface FormatResult {
    status: "ok" | "unsupported";
    uri: string;
    editsApplied: number;
    fileUpdated: boolean;
    documentVersion: number;
    message?: string;
}

export type HealthState = "starting" | "healthy" | "degraded" | "stopped" | "failed";

export class CodeQLLspError extends Error {
    constructor(
        public readonly code: string,
        message: string,
        public readonly recoverable = false,
        public readonly details: Record<string, unknown> = {},
    ) {
        super(message);
        this.name = "CodeQLLspError";
    }
}

interface DiagnosticsWaiter {
    resolve: (params: PublishDiagnosticsParams) => void;
    reject: (error: Error) => void;
    timer: NodeJS.Timeout;
    expectedVersion: number;
}

interface DocumentState {
    uri: string;
    version: number;
    content: string;
    isOpen: boolean;
    diagnostics?: Diagnostic[];
    diagnosticsVersion?: number;
    diagnosticsReceivedAt?: number;
}

function envTimeout(name: string, fallback: number): number {
    const parsed = Number(process.env[name]);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

export class CodeQLLanguageServer {
    private process: ChildProcessWithoutNullStreams | null = null;
    private connection: MessageConnection | null = null;
    private workspaceFolders: string[] = [];
    private readonly instanceId = `${process.pid}-${Date.now()}`;
    private readonly logFilePath: string | null;
    private readonly verbose: boolean;
    private codeqlPath?: string;
    private capabilities: ServerCapabilities = {};
    private documents = new Map<string, DocumentState>();
    private diagnosticsWaiters = new Map<string, Set<DiagnosticsWaiter>>();
    private health: HealthState = "stopped";
    private startedAt: number | null = null;
    private lastDiagnosticsAt: number | null = null;
    private timeoutCounts = new Map<string, number>();
    private stopping = false;

    private readonly initializeTimeoutMs = envTimeout("CODEQL_LSP_INITIALIZE_TIMEOUT_MS", 120_000);
    private readonly diagnosticsTimeoutMs = envTimeout("CODEQL_LSP_DIAGNOSTICS_TIMEOUT_MS", 60_000);
    private readonly requestTimeoutMs = envTimeout("CODEQL_LSP_REQUEST_TIMEOUT_MS", 30_000);
    private readonly formatTimeoutMs = envTimeout("CODEQL_LSP_FORMAT_TIMEOUT_MS", 15_000);
    private readonly shutdownTimeoutMs = envTimeout("CODEQL_LSP_SHUTDOWN_TIMEOUT_MS", 5_000);

    constructor(options: CodeQLClientOptions = {}) {
        this.verbose = options.verbose ?? process.env.CODEQL_LSP_VERBOSE === "true";
        this.codeqlPath = options.codeqlPath;
        if (this.verbose) {
            const logDir = options.logDir ?? process.env.CODEQL_LSP_LOG_DIR ?? process.cwd();
            mkdirSync(logDir, { recursive: true });
            this.logFilePath = join(logDir, `codeql-lsp-${this.instanceId}.jsonl`);
            writeFileSync(this.logFilePath, "", { encoding: "utf8", flag: "a" });
            this.log("client_initialized", { logFilePath: this.logFilePath });
        } else {
            this.logFilePath = null;
        }
        if (!this.codeqlPath) this.codeqlPath = this.findCodeQLPath();
        if (!this.codeqlPath) {
            throw new CodeQLLspError("CODEQL_NOT_FOUND", "CodeQL CLI not found. Set CODEQL_PATH or add codeql to PATH.");
        }
    }

    private log(event: string, details: Record<string, unknown> = {}): void {
        if (!this.verbose) return;
        const record = JSON.stringify({ timestamp: new Date().toISOString(), instanceId: this.instanceId, event, ...details });
        console.error(record);
        if (this.logFilePath) appendFileSync(this.logFilePath, `${record}\n`);
    }

    private findCodeQLPath(): string | undefined {
        const paths = [
            process.env.CODEQL_PATH,
            process.env.PATH?.split(delimiter).map(dir => join(dir, "codeql")).find(existsSync),
            join(homedir(), "codeql", "codeql"), join(homedir(), ".codeql", "codeql"), "codeql",
        ].filter(Boolean) as string[];
        return paths.find(path => {
            try { execFileSync(path, ["version"], { stdio: "ignore" }); return true; }
            catch { return false; }
        });
    }

    private requireConnection(): MessageConnection {
        if (!this.connection) throw new CodeQLLspError("LSP_NOT_RUNNING", "CodeQL language server is not running.", true);
        return this.connection;
    }

    private async withTimeout<T>(operation: string, promise: Promise<T>, timeoutMs: number): Promise<T> {
        const started = Date.now();
        let timer: NodeJS.Timeout | undefined;
        this.log("request_started", { operation, timeoutMs });
        try {
            const result = await Promise.race([
                promise,
                new Promise<T>((_, reject) => {
                    timer = setTimeout(() => reject(new CodeQLLspError(
                        "LSP_REQUEST_TIMEOUT", `${operation} timed out after ${timeoutMs}ms`, true,
                        { operation, timeoutMs },
                    )), timeoutMs);
                }),
            ]);
            this.log("request_completed", { operation, durationMs: Date.now() - started });
            return result;
        } catch (error) {
            if (error instanceof CodeQLLspError && error.code === "LSP_REQUEST_TIMEOUT") {
                this.health = "degraded";
                this.timeoutCounts.set(operation, (this.timeoutCounts.get(operation) ?? 0) + 1);
            }
            this.log("request_failed", { operation, durationMs: Date.now() - started, error: error instanceof Error ? error.message : String(error) });
            throw error;
        } finally {
            if (timer) clearTimeout(timer);
        }
    }

    async start(workspaceFolders?: string[]): Promise<void> {
        if (this.process && this.connection) {
            if (workspaceFolders?.length) await this.setWorkspaceFolders(workspaceFolders);
            return;
        }
        this.health = "starting";
        this.stopping = false;
        if (workspaceFolders) this.workspaceFolders = workspaceFolders;
        const args = ["execute", "language-server", "--check-errors", "ON_CHANGE"];
        if (process.env.CODEQL_VERBOSE === "true") args.push("-v", "--log-to-stderr");
        this.log("server_starting", { codeqlPath: this.codeqlPath, args, workspaceFolders: this.workspaceFolders });
        this.process = spawn(this.codeqlPath!, args, { stdio: ["pipe", "pipe", "pipe"] }) as ChildProcessWithoutNullStreams;
        if (!this.process.pid) {
            this.health = "failed";
            throw new CodeQLLspError("LSP_START_FAILED", "Failed to start CodeQL language server.", true);
        }
        const child = this.process;
        child.on("exit", (code, signal) => {
            this.log("server_exited", { code, signal, stopping: this.stopping });
            this.rejectDiagnosticsWaiters(new CodeQLLspError(
                "LSP_EXITED",
                `CodeQL language server exited (code=${code}, signal=${signal}).`,
                true,
            ));
            if (this.process === child) {
                this.process = null;
                this.connection = null;
                this.health = this.stopping ? "stopped" : "degraded";
            }
        });
        child.stderr.on("data", data => this.log("server_stderr", { message: data.toString().trim() }));
        this.connection = createMessageConnection(new StreamMessageReader(child.stdout), new StreamMessageWriter(child.stdin));
        this.connection.onError(error => {
            this.health = "degraded";
            this.log("connection_error", { error: String(error[0] ?? error) });
        });
        this.connection.onClose(() => {
            if (!this.stopping) this.health = "degraded";
            this.log("connection_closed", { stopping: this.stopping });
        });
        this.connection.onNotification("textDocument/publishDiagnostics", (params: PublishDiagnosticsParams) => this.handleDiagnostics(params));
        this.connection.listen();

        const root = this.workspaceFolders[0] ?? process.cwd();
        const initParams: InitializeParams = {
            processId: process.pid,
            capabilities: {
                textDocument: {
                    completion: { completionItem: { snippetSupport: true, documentationFormat: ["markdown", "plaintext"] } },
                    hover: { contentFormat: ["markdown", "plaintext"] },
                    synchronization: { willSave: false, willSaveWaitUntil: false, didSave: true },
                    definition: { dynamicRegistration: false }, references: { dynamicRegistration: false },
                    formatting: { dynamicRegistration: false }, rangeFormatting: { dynamicRegistration: false },
                },
                workspace: { workspaceFolders: true },
            },
            rootUri: `file://${root}`,
            workspaceFolders: (this.workspaceFolders.length ? this.workspaceFolders : [root]).map((folder, index) => ({ uri: `file://${folder}`, name: `workspace${index}` })),
        };
        try {
            const result = await this.withTimeout("initialize", this.connection.sendRequest<InitializeResult>("initialize", initParams), this.initializeTimeoutMs);
            this.capabilities = result.capabilities;
            await this.connection.sendNotification("initialized", {});
            this.health = "healthy";
            this.startedAt = Date.now();
            this.log("server_ready", { pid: child.pid, capabilities: this.capabilities });
        } catch (error) {
            this.health = "failed";
            await this.forceStopProcess();
            throw error;
        }
    }

    private handleDiagnostics(params: PublishDiagnosticsParams): void {
        const state = this.documents.get(params.uri);
        const version = params.version ?? state?.version ?? 0;
        const stale = params.version !== undefined && state !== undefined && params.version < state.version;
        if (state && !stale) {
            state.diagnostics = params.diagnostics;
            state.diagnosticsVersion = version;
            state.diagnosticsReceivedAt = Date.now();
        }
        this.lastDiagnosticsAt = Date.now();
        this.log("diagnostics_received", { uri: params.uri, count: params.diagnostics.length, diagnosticsVersion: version });
        const waiters = this.diagnosticsWaiters.get(params.uri);
        if (waiters) {
            for (const waiter of [...waiters]) {
                if (params.version === undefined || params.version >= waiter.expectedVersion) {
                    clearTimeout(waiter.timer);
                    waiter.resolve(params);
                    waiters.delete(waiter);
                }
            }
            if (waiters.size === 0) this.diagnosticsWaiters.delete(params.uri);
        }
    }

    private rejectDiagnosticsWaiters(error: Error): void {
        for (const waiters of this.diagnosticsWaiters.values()) {
            for (const waiter of waiters) { clearTimeout(waiter.timer); waiter.reject(error); }
        }
        this.diagnosticsWaiters.clear();
    }

    private async forceStopProcess(): Promise<void> {
        const child = this.process;
        this.connection?.dispose();
        this.connection = null;
        if (child) {
            child.stdin.end(); child.kill("SIGTERM"); child.stdout.destroy(); child.stderr.destroy();
        }
        this.process = null;
    }

    async stop(): Promise<void> {
        this.stopping = true;
        this.rejectDiagnosticsWaiters(new CodeQLLspError("LSP_STOPPED", "CodeQL language server stopped."));
        if (this.connection) {
            try {
                await this.withTimeout("shutdown", this.connection.sendRequest("shutdown"), this.shutdownTimeoutMs);
                await this.connection.sendNotification("exit");
            } catch (error) {
                this.log("shutdown_failed", { error: error instanceof Error ? error.message : String(error) });
            }
        }
        await this.forceStopProcess();
        this.health = "stopped";
        this.stopping = false;
    }

    private async ensureOperational(): Promise<void> {
        if (this.health === "degraded" || this.health === "failed" || !this.connection) await this.restart();
    }

    private async restart(): Promise<void> {
        const snapshots = [...this.documents.values()].map(state => ({ ...state }));
        this.log("server_restarting", { openDocuments: snapshots.length });
        await this.stop();
        this.documents.clear();
        await this.start(this.workspaceFolders);
        for (const snapshot of snapshots) if (snapshot.isOpen) await this.openDocument(snapshot.uri, snapshot.content);
    }

    private async sendDidChange(state: DocumentState): Promise<void> {
        state.version += 1;
        state.diagnostics = undefined;
        state.diagnosticsVersion = undefined;
        const params: DidChangeTextDocumentParams = {
            textDocument: { uri: state.uri, version: state.version }, contentChanges: [{ text: state.content }],
        };
        await this.requireConnection().sendNotification("textDocument/didChange", params);
        this.log("document_changed", { uri: state.uri, version: state.version, contentLength: state.content.length });
    }

    async openDocument(uri: string, content: string): Promise<void> {
        await this.ensureOperational();
        const state: DocumentState = { uri, version: 1, content, isOpen: true };
        this.documents.set(uri, state);
        const params: DidOpenTextDocumentParams = { textDocument: { uri, languageId: "ql", version: 1, text: content } };
        await this.requireConnection().sendNotification("textDocument/didOpen", params);
        await this.requireConnection().sendNotification("textDocument/codeQLDidChangeVisibleFiles", { visibleFiles: [uri] });
        this.log("document_opened", { uri, version: 1, contentLength: content.length });
    }

    async updateDocument(uri: string, content: string): Promise<void> {
        await this.ensureOperational();
        let state = this.documents.get(uri);
        if (!state?.isOpen) {
            await this.openDocument(uri, content);
            state = this.documents.get(uri)!;
        } else state.content = content;
        await this.sendDidChange(state);
    }

    private async request<T>(operation: string, method: string, params: unknown, timeoutMs = this.requestTimeoutMs): Promise<T> {
        await this.ensureOperational();
        return this.withTimeout(operation, this.requireConnection().sendRequest<T>(method, params), timeoutMs);
    }

    private requireCapability(name: keyof ServerCapabilities, operation: string): void {
        if (this.capabilities[name] === undefined || this.capabilities[name] === false) {
            throw new CodeQLLspError("LSP_CAPABILITY_UNSUPPORTED", `The active CodeQL language server does not support ${operation}.`, false, { capability: name });
        }
    }

    async getCompletions(uri: string, line: number, character: number, triggerCharacter?: string): Promise<CompletionList> {
        this.requireCapability("completionProvider", "completion");
        const params: CompletionParams = { textDocument: { uri }, position: { line, character }, context: triggerCharacter ? { triggerKind: 2, triggerCharacter } : { triggerKind: 1 } };
        return this.request("completion", "textDocument/completion", params, 20_000);
    }

    async getHover(uri: string, line: number, character: number): Promise<Hover | null> {
        this.requireCapability("hoverProvider", "hover");
        const params: HoverParams = { textDocument: { uri }, position: { line, character } };
        return this.request("hover", "textDocument/hover", params, 20_000);
    }

    async getDefinition(uri: string, line: number, character: number): Promise<Location | Location[] | null> {
        this.requireCapability("definitionProvider", "definition");
        const params: DefinitionParams = { textDocument: { uri }, position: { line, character } };
        return this.request("definition", "textDocument/definition", params);
    }

    async getDiagnostics(uri: string, timeoutMs = this.diagnosticsTimeoutMs): Promise<DiagnosticsResult> {
        await this.ensureOperational();
        let state = this.documents.get(uri);
        if (!state) {
            let content: string;
            try { content = readFileSync(fileURLToPath(uri), "utf8"); }
            catch (error) {
                throw new CodeQLLspError("DOCUMENT_NOT_OPEN", `Document is not open and could not be read: ${uri}`, false, { cause: error instanceof Error ? error.message : String(error) });
            }
            await this.openDocument(uri, content);
            state = this.documents.get(uri)!;
        }
        if (state.diagnostics && state.diagnosticsVersion !== undefined && state.diagnosticsVersion >= state.version) {
            return { status: "ok", uri, documentVersion: state.version, diagnosticsVersion: state.diagnosticsVersion, fromCache: true, durationMs: 0, diagnostics: state.diagnostics };
        }
        const started = Date.now();
        const diagnosticsPromise = new Promise<PublishDiagnosticsParams>((resolve, reject) => {
            const waiter = {} as DiagnosticsWaiter;
            waiter.resolve = resolve; waiter.reject = reject;
            waiter.expectedVersion = state!.version + 1;
            waiter.timer = setTimeout(() => {
                this.diagnosticsWaiters.get(uri)?.delete(waiter);
                if (this.diagnosticsWaiters.get(uri)?.size === 0) this.diagnosticsWaiters.delete(uri);
                this.health = "degraded";
                this.timeoutCounts.set("diagnostics", (this.timeoutCounts.get("diagnostics") ?? 0) + 1);
                reject(new CodeQLLspError("DIAGNOSTICS_TIMEOUT", `Diagnostics timed out after ${timeoutMs}ms`, true, { uri, timeoutMs }));
            }, timeoutMs);
            const waiters = this.diagnosticsWaiters.get(uri) ?? new Set<DiagnosticsWaiter>();
            waiters.add(waiter); this.diagnosticsWaiters.set(uri, waiters);
        });
        // Listener registration deliberately precedes didChange, preventing lost empty notifications.
        await this.sendDidChange(state);
        const params = await diagnosticsPromise;
        return {
            status: "ok", uri, documentVersion: state.version,
            diagnosticsVersion: params.version ?? state.version, fromCache: false,
            durationMs: Date.now() - started, diagnostics: params.diagnostics,
        };
    }

    private offsetAt(content: string, line: number, character: number): number {
        const lines = content.split(/(?<=\n)/);
        if (line < 0 || line >= lines.length) throw new CodeQLLspError("INVALID_TEXT_EDIT", `Invalid line ${line}`);
        const prefix = lines.slice(0, line).reduce((sum, value) => sum + value.length, 0);
        const current = lines[line].replace(/\r?\n$/, "");
        if (character < 0 || character > current.length) throw new CodeQLLspError("INVALID_TEXT_EDIT", `Invalid character ${character} on line ${line}`);
        return prefix + character;
    }

    private applyTextEdits(content: string, edits: TextEdit[]): string {
        const normalized = edits.map(edit => ({
            start: this.offsetAt(content, edit.range.start.line, edit.range.start.character),
            end: this.offsetAt(content, edit.range.end.line, edit.range.end.character), newText: edit.newText,
        })).sort((a, b) => b.start - a.start || b.end - a.end);
        let result = content;
        let priorStart = content.length + 1;
        for (const edit of normalized) {
            if (edit.end > priorStart) throw new CodeQLLspError("OVERLAPPING_TEXT_EDITS", "Formatting returned overlapping edits.");
            result = result.slice(0, edit.start) + edit.newText + result.slice(edit.end);
            priorStart = edit.start;
        }
        return result;
    }

    private atomicWriteUri(uri: string, content: string): void {
        const path = fileURLToPath(uri);
        const temporary = join(dirname(path), `.${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}.tmp`);
        try { writeFileSync(temporary, content, "utf8"); renameSync(temporary, path); }
        catch (error) { try { unlinkSync(temporary); } catch { /* no-op */ } throw error; }
    }

    async formatDocument(uri: string, range?: Range, applyEdits = true): Promise<FormatResult> {
        await this.ensureOperational();
        const capability = range ? this.capabilities.documentRangeFormattingProvider : this.capabilities.documentFormattingProvider;
        if (capability === undefined || capability === false) {
            return { status: "unsupported", uri, editsApplied: 0, fileUpdated: false, documentVersion: this.documents.get(uri)?.version ?? 0, message: `The active CodeQL language server does not support ${range ? "range " : ""}formatting.` };
        }
        let state = this.documents.get(uri);
        if (!state) {
            await this.openDocument(uri, readFileSync(fileURLToPath(uri), "utf8"));
            state = this.documents.get(uri)!;
        }
        const params = range
            ? ({ textDocument: { uri }, range, options: { tabSize: 2, insertSpaces: true } } as DocumentRangeFormattingParams)
            : ({ textDocument: { uri }, options: { tabSize: 2, insertSpaces: true } } as DocumentFormattingParams);
        const method = range ? "textDocument/rangeFormatting" : "textDocument/formatting";
        const edits = await this.request<TextEdit[]>("format", method, params, this.formatTimeoutMs) ?? [];
        if (applyEdits && edits.length) {
            const formatted = this.applyTextEdits(state.content, edits);
            this.atomicWriteUri(uri, formatted);
            state.content = formatted;
            await this.sendDidChange(state);
        }
        return { status: "ok", uri, editsApplied: edits.length, fileUpdated: applyEdits && edits.length > 0, documentVersion: state.version };
    }

    async getReferences(uri: string, line: number, character: number): Promise<Location[] | null> {
        this.requireCapability("referencesProvider", "references");
        return this.request("references", "textDocument/references", { textDocument: { uri }, position: { line, character }, context: { includeDeclaration: true } });
    }

    /** Preserve the existing workspace tool behavior as requested. */
    async setWorkspaceFolders(folders: string[]): Promise<void> {
        const oldFolders = [...this.workspaceFolders];
        if (!this.connection) { this.workspaceFolders = folders; return; }
        const oldUris = oldFolders.map((folder, index) => ({ uri: `file://${folder}`, name: `workspace${index}` }));
        const newUris = folders.map((folder, index) => ({ uri: `file://${folder}`, name: `workspace${index}` }));
        await this.connection.sendNotification("workspace/didChangeWorkspaceFolders", { event: { added: newUris, removed: oldUris } });
        this.workspaceFolders = folders;
        this.log("workspace_changed", { oldFolders, folders });
    }

    getStatus(): Record<string, unknown> {
        const enabled = (value: unknown) => value !== undefined && value !== false;
        return {
            status: this.health, pid: this.process?.pid ?? null,
            uptimeSeconds: this.startedAt ? Math.floor((Date.now() - this.startedAt) / 1000) : 0,
            codeqlPath: this.codeqlPath, workspaceFolders: this.workspaceFolders,
            capabilities: {
                completion: enabled(this.capabilities.completionProvider), hover: enabled(this.capabilities.hoverProvider),
                definition: enabled(this.capabilities.definitionProvider), references: enabled(this.capabilities.referencesProvider),
                formatting: enabled(this.capabilities.documentFormattingProvider), rangeFormatting: enabled(this.capabilities.documentRangeFormattingProvider),
            },
            openDocuments: [...this.documents.values()].filter(document => document.isOpen).length,
            pendingDiagnostics: [...this.diagnosticsWaiters.values()].reduce((total, waiters) => total + waiters.size, 0),
            lastDiagnosticsAt: this.lastDiagnosticsAt ? new Date(this.lastDiagnosticsAt).toISOString() : null,
            timeouts: Object.fromEntries(this.timeoutCounts), logFilePath: this.logFilePath,
        };
    }

    getLogFilePath(): string | null { return this.logFilePath; }
    isRunning(): boolean { return this.process !== null && !this.process.killed; }
}
