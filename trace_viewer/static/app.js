const app = document.querySelector("#app");

const state = {
  runs: [],
  summary: {},
  run: null,
  phaseId: null,
  trace: null,
  traceEvents: [],
  traceOffset: 0,
  selectedEvent: null,
  filters: { search: "", kind: "all", tool: "" },
  dashboardFilters: { search: "", status: "all" },
  tab: "trace",
  poller: null,
};

const esc = (value) => String(value ?? "")
  .replaceAll("&", "&amp;")
  .replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;")
  .replaceAll("'", "&#039;");

const fmtNumber = (value) => Number(value || 0).toLocaleString("zh-CN");
const fmtTokens = (value) => {
  const number = Number(value || 0);
  if (number >= 1_000_000) return `${(number / 1_000_000).toFixed(2)}M`;
  if (number >= 1_000) return `${(number / 1_000).toFixed(1)}K`;
  return fmtNumber(number);
};
const fmtBytes = (value) => {
  const number = Number(value || 0);
  if (number >= 1024 ** 2) return `${(number / 1024 ** 2).toFixed(1)} MB`;
  if (number >= 1024) return `${(number / 1024).toFixed(1)} KB`;
  return `${number} B`;
};
const fmtDuration = (seconds) => {
  const total = Math.round(Number(seconds || 0));
  if (!total) return "—";
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  return `${h ? `${h}h ` : ""}${m}m ${s}s`;
};
const fmtTime = (value) => {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("zh-CN", { hour12: false });
};
const fmtClock = (value) => {
  if (!value) return "";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "" : date.toLocaleTimeString("zh-CN", { hour12: false });
};

async function api(path) {
  const response = await fetch(path, { headers: { Accept: "application/json" } });
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try { detail = (await response.json()).detail || detail; } catch (_) { /* ignore */ }
    throw new Error(detail);
  }
  return response.json();
}

function statusBadge(status) {
  const label = String(status || "UNKNOWN").replaceAll("_", " ");
  return `<span class="badge ${esc(String(status || "").toLowerCase())}">${esc(label)}</span>`;
}

function shell(content, { live = true } = {}) {
  return `<div class="shell">
    <header class="topbar">
      <a class="logo" href="#/">
        <span class="logo-box">QL</span>
        <span>QLCoder Trace Viewer</span>
      </a>
      <div class="spacer"></div>
      ${live ? '<span class="live-dot">动态扫描 output</span>' : ""}
      <button class="icon-button" id="refresh-button">刷新</button>
    </header>
    ${content}
  </div>`;
}

async function loadDashboard({ silent = false } = {}) {
  if (!silent) app.innerHTML = shell('<div class="loading-line"></div><main class="page"><div class="empty-state">正在扫描 output…</div></main>');
  try {
    const data = await api("/api/runs");
    state.runs = data.runs;
    state.summary = data.summary;
    renderDashboard();
  } catch (error) {
    renderError(error);
  }
}

function renderDashboard() {
  const statuses = state.summary.statuses || {};
  const success = statuses.SUCCESS || 0;
  const active = (statuses.ITERATING || 0) + (statuses.PHASE1_RUNNING || 0) + (statuses.DISCOVERED || 0);
  const failed = (statuses.FAILED || 0) + (statuses.PHASE1_FAILED || 0) + (statuses.MAX_TURNS || 0);
  const content = `<main class="page">
    <div class="page-title-row">
      <div><h1>QLCoder Runs</h1><p class="subtitle">直接读取 output 目录，展示所有成功、失败、中断和正在运行的任务。</p></div>
    </div>
    <section class="stat-grid">
      ${statCard("Runs", state.summary.run_count, `${state.summary.cve_count || 0} 个不同 CVE`)}
      ${statCard("Success", success, "已找到通过验证的 Query")}
      ${statCard("Active", active, "正在执行或刚被发现")}
      ${statCard("Failed", failed, "包含 Phase 1 和迭代失败")}
      ${statCard("Indexed cost", `¥${Number(state.summary.total_cost_cny || 0).toFixed(2)}`, `${fmtTokens(state.summary.total_tokens)} tokens`)}
    </section>
    <section class="panel">
      <div class="toolbar">
        <input id="run-search" class="search-input" placeholder="搜索 CVE、CWE、模型或目录…" value="${esc(state.dashboardFilters.search)}" />
        <select id="status-filter" class="select-input">
          <option value="all">全部状态</option>
          ${Object.keys(statuses).sort().map(status => `<option value="${esc(status)}" ${state.dashboardFilters.status === status ? "selected" : ""}>${esc(status.replaceAll("_", " "))} (${statuses[status]})</option>`).join("")}
        </select>
        <span class="push subtitle">最后刷新：${esc(new Date().toLocaleTimeString("zh-CN", { hour12: false }))}</span>
      </div>
      <div id="run-table-wrap">${runTable()}</div>
    </section>
  </main>`;
  app.innerHTML = shell(content);
  bindCommonRefresh(() => loadDashboard({ silent: true }));
  document.querySelector("#run-search").addEventListener("input", event => {
    state.dashboardFilters.search = event.target.value;
    document.querySelector("#run-table-wrap").innerHTML = runTable();
  });
  document.querySelector("#status-filter").addEventListener("change", event => {
    state.dashboardFilters.status = event.target.value;
    document.querySelector("#run-table-wrap").innerHTML = runTable();
  });
  startPolling(() => loadDashboard({ silent: true }), 5000);
}

function statCard(label, value, note) {
  return `<div class="stat-card"><div class="stat-label">${esc(label)}</div><div class="stat-value">${esc(value)}</div><div class="stat-note">${esc(note)}</div></div>`;
}

function filteredRuns() {
  const needle = state.dashboardFilters.search.toLowerCase().trim();
  return state.runs.filter(run => {
    if (state.dashboardFilters.status !== "all" && run.status !== state.dashboardFilters.status) return false;
    if (!needle) return true;
    return [run.cve, run.cwe, run.cwe_name, run.model, run.mode, run.id, run.project].join(" ").toLowerCase().includes(needle);
  });
}

function runTable() {
  const rows = filteredRuns();
  if (!rows.length) return '<div class="empty-state"><strong>没有匹配的运行</strong>调整搜索或状态筛选。</div>';
  return `<table class="run-table">
    <thead><tr><th>CVE / Run</th><th>CWE</th><th>Started</th><th>Model</th><th>Iteration</th><th>Turns</th><th>Tokens</th><th>Runtime</th><th>Cost</th><th>Status</th></tr></thead>
    <tbody>${rows.map(run => `<tr>
      <td><a class="run-link" href="#/runs/${encodeURIComponent(run.id)}">${esc(run.cve)}<small>${esc(run.id)}</small></a></td>
      <td>${esc(run.cwe || "Unknown")}</td>
      <td class="numeric">${esc(fmtTime(run.started_at))}</td>
      <td>${esc(run.model)}<small class="subtitle"> ${esc(run.mode)}</small></td>
      <td class="numeric">${esc(run.iterations)}/${esc(run.max_iterations)}</td>
      <td class="numeric">${run.turns == null ? "—" : fmtNumber(run.turns)}</td>
      <td class="numeric">${run.tokens ? fmtTokens(run.tokens) : "—"}</td>
      <td class="numeric">${fmtDuration(run.runtime_seconds)}</td>
      <td class="numeric">${run.cost_cny ? `¥${Number(run.cost_cny).toFixed(2)}` : "—"}</td>
      <td>${statusBadge(run.status)}<small class="subtitle" style="display:block;margin-top:5px;max-width:180px">${esc(run.status_detail)}</small></td>
    </tr>`).join("")}</tbody>
  </table>`;
}

async function loadRun(runId, { silent = false } = {}) {
  stopPolling();
  if (!silent) app.innerHTML = shell('<div class="loading-line"></div><main class="page"><div class="empty-state">正在读取运行产物…</div></main>');
  try {
    state.run = await api(`/api/runs/${encodeURIComponent(runId)}`);
    if (!state.phaseId || !state.run.phases.some(phase => phase.id === state.phaseId && phase.trace_file)) {
      state.phaseId = state.run.phases.find(phase => phase.trace_file)?.id || null;
    }
    state.trace = null;
    state.traceEvents = [];
    state.traceOffset = 0;
    state.selectedEvent = null;
    renderRun();
    if (state.phaseId) await loadTrace(true);
    if (["ITERATING", "PHASE1_RUNNING", "DISCOVERED"].includes(state.run.status)) {
      startPolling(() => loadRun(runId, { silent: true }), 5000);
    }
  } catch (error) {
    renderError(error);
  }
}

function renderRun() {
  const run = state.run;
  const content = `<main class="page">
    <div class="breadcrumbs"><a href="#/">QLCoder Runs</a> / ${esc(run.cve)} / ${esc(run.started_at)}</div>
    <div class="page-title-row">
      <div>
        <div class="run-heading"><h1>${esc(run.cve)}</h1>${statusBadge(run.status)}</div>
        <p class="subtitle">${esc(run.cwe || "Unknown CWE")} · ${esc(run.cwe_name || "")} · ${esc(run.project || "")}</p>
        <div class="run-meta">
          <span>模型 <b>${esc(run.model)}</b></span><span>模式 <b>${esc(run.mode)}</b></span>
          <span>迭代 <b>${esc(run.iterations)}/${esc(run.max_iterations)}</b></span><span>Turns <b>${run.turns ?? "—"}</b></span>
          <span>Tokens <b>${fmtTokens(run.tokens)}</b></span><span>Cost <b>¥${Number(run.cost_cny || 0).toFixed(2)}</b></span>
          <span>Runtime <b>${fmtDuration(run.runtime_seconds)}</b></span>
        </div>
      </div>
      <div><span class="subtitle">${esc(run.status_detail)}</span></div>
    </div>
    <section class="detail-grid">
      <aside class="phase-sidebar">
        <div class="sidebar-heading">Phases & Iterations</div>
        ${run.phases.map(phaseButton).join("") || '<div class="empty-state">暂无阶段产物</div>'}
      </aside>
      <section class="trace-column">
        <div class="trace-toolbar">
          <input id="trace-search" class="search-input" placeholder="搜索 reasoning、参数或结果…" value="${esc(state.filters.search)}" />
          <select id="kind-filter" class="select-input">
            ${[["all", "全部事件"], ["thinking", "Thinking"], ["tool", "Tool"], ["assistant", "Assistant"], ["result", "Result"]].map(([value, label]) => `<option value="${value}" ${state.filters.kind === value ? "selected" : ""}>${label}</option>`).join("")}
          </select>
          <input id="tool-filter" class="search-input" style="max-width:150px" placeholder="工具名" value="${esc(state.filters.tool)}" />
          <button id="apply-trace-filter" class="secondary-button">应用</button>
        </div>
        <div id="trace-summary" class="trace-summary"><span>选择包含 Trace 的阶段</span></div>
        <div id="trace-list" class="trace-list"><div class="empty-state">正在解析 Trace…</div></div>
      </section>
      <aside class="inspector" id="inspector">${emptyInspector()}</aside>
    </section>
    <nav class="tab-strip">
      ${tabButton("trace", "工具统计")}${tabButton("iterations", "Query 迭代")}${tabButton("artifacts", `全部产物 (${run.artifacts.length})`)}
    </nav>
    <section class="lower-panel" id="lower-panel">${renderLowerPanel()}</section>
  </main>`;
  app.innerHTML = shell(content);
  bindCommonRefresh(() => loadRun(run.id));
  bindRunEvents();
}

function phaseButton(phase) {
  const active = phase.id === state.phaseId;
  const statusClass = String(phase.status || "").toLowerCase();
  return `<button class="phase-button ${active ? "active" : ""}" data-phase="${esc(phase.id)}" ${phase.trace_file ? "" : "data-artifact-phase=\"true\""}>
    <span class="phase-name"><span>${esc(phase.label)}</span><i class="phase-status ${esc(statusClass)}"></i></span>
    <small>${esc(phase.status)}${phase.num_turns ? ` · ${phase.num_turns} turns` : ""}${phase.query_file ? " · Query" : ""}</small>
  </button>`;
}

function tabButton(id, label) {
  return `<button class="tab-button ${state.tab === id ? "active" : ""}" data-tab="${id}">${esc(label)}</button>`;
}

function bindRunEvents() {
  document.querySelectorAll(".phase-button").forEach(button => button.addEventListener("click", async () => {
    const phase = state.run.phases.find(item => item.id === button.dataset.phase);
    if (!phase) return;
    if (!phase.trace_file && phase.artifact_file) {
      state.tab = "artifacts";
      renderRun();
      await showArtifact(phase.artifact_file);
      return;
    }
    state.phaseId = phase.id;
    state.traceEvents = [];
    state.traceOffset = 0;
    state.selectedEvent = null;
    document.querySelectorAll(".phase-button").forEach(item => item.classList.toggle("active", item.dataset.phase === state.phaseId));
    document.querySelector("#inspector").innerHTML = emptyInspector();
    await loadTrace(true);
  }));
  document.querySelector("#apply-trace-filter").addEventListener("click", () => {
    state.filters.search = document.querySelector("#trace-search").value;
    state.filters.kind = document.querySelector("#kind-filter").value;
    state.filters.tool = document.querySelector("#tool-filter").value;
    state.traceEvents = [];
    state.traceOffset = 0;
    loadTrace(true);
  });
  document.querySelector("#trace-search").addEventListener("keydown", event => {
    if (event.key === "Enter") document.querySelector("#apply-trace-filter").click();
  });
  document.querySelectorAll(".tab-button").forEach(button => button.addEventListener("click", () => {
    state.tab = button.dataset.tab;
    document.querySelectorAll(".tab-button").forEach(item => item.classList.toggle("active", item.dataset.tab === state.tab));
    document.querySelector("#lower-panel").innerHTML = renderLowerPanel();
    bindLowerPanel();
  }));
  bindLowerPanel();
}

async function loadTrace(reset = false) {
  if (!state.phaseId) return;
  const list = document.querySelector("#trace-list");
  if (reset && list) list.innerHTML = '<div class="empty-state">正在解析并关联 Tool Call / Result…</div>';
  const params = new URLSearchParams({ offset: String(reset ? 0 : state.traceOffset), limit: "80" });
  if (state.filters.kind !== "all") params.set("kind", state.filters.kind);
  if (state.filters.tool) params.set("tool", state.filters.tool);
  if (state.filters.search) params.set("search", state.filters.search);
  try {
    const data = await api(`/api/runs/${encodeURIComponent(state.run.id)}/trace/${encodeURIComponent(state.phaseId)}?${params}`);
    state.trace = data;
    state.traceEvents = reset ? data.events : [...state.traceEvents, ...data.events];
    state.traceOffset = state.traceEvents.length;
    renderTrace();
    if (state.tab === "trace") {
      const lower = document.querySelector("#lower-panel");
      if (lower) lower.innerHTML = renderToolStats();
    }
  } catch (error) {
    if (list) list.innerHTML = `<div class="empty-state"><strong>Trace 暂不可解析</strong>${esc(error.message)}<br />如果任务仍在运行，文件闭合后会自动恢复。</div>`;
  }
}

function renderTrace() {
  const stats = state.trace.stats || {};
  const summary = document.querySelector("#trace-summary");
  if (summary) summary.innerHTML = `<span>显示 ${fmtNumber(state.trace.total)} 个事件</span><span>${fmtNumber(stats.tool_call_count)} tool calls</span><span>${fmtNumber(stats.tool_result_count)} results</span><span>${fmtNumber(stats.thinking_blocks)} thinking blocks</span><span>${fmtNumber(stats.raw_event_count)} raw events</span>`;
  const list = document.querySelector("#trace-list");
  if (!list) return;
  if (!state.traceEvents.length) {
    list.innerHTML = '<div class="empty-state"><strong>没有匹配事件</strong>调整筛选条件后重试。</div>';
    return;
  }
  list.innerHTML = state.traceEvents.map(eventCard).join("") + (state.trace.has_more ? '<div class="load-row"><button id="load-more" class="secondary-button">加载更多</button></div>' : "");
  list.querySelectorAll(".event-card").forEach(card => card.addEventListener("click", () => selectEvent(Number(card.dataset.sequence))));
  document.querySelector("#load-more")?.addEventListener("click", () => loadTrace(false));
}

function eventCard(event) {
  const input = event.kind === "tool" ? JSON.stringify(event.input || {}, null, 2) : "";
  const preview = input || event.content || "";
  return `<article class="event-card ${state.selectedEvent?.sequence === event.sequence ? "selected" : ""}" data-sequence="${event.sequence}">
    <div class="event-head"><span class="event-kind ${esc(event.kind)}">${esc(event.kind)}</span><span class="event-title">${esc(event.title)}</span><span class="event-time">${esc(fmtClock(event.timestamp))}</span></div>
    ${preview ? `<div class="event-body">${esc(preview)}</div>` : ""}
    ${event.kind === "tool" ? `<div class="event-tool-meta"><span>${esc(event.tool_category)}</span><span>${event.duration_ms == null ? "duration —" : `${fmtNumber(event.duration_ms)} ms`}</span><span class="${event.is_error ? "error" : "ok"}">${event.is_error ? "ERROR" : "RESULT"}</span><span>${fmtNumber(event.content_length)} chars</span></div>` : ""}
  </article>`;
}

async function selectEvent(sequence) {
  try {
    state.selectedEvent = await api(`/api/runs/${encodeURIComponent(state.run.id)}/trace/${encodeURIComponent(state.phaseId)}/events/${sequence}`);
    document.querySelectorAll(".event-card").forEach(card => card.classList.toggle("selected", Number(card.dataset.sequence) === sequence));
    document.querySelector("#inspector").innerHTML = eventInspector(state.selectedEvent);
  } catch (error) {
    document.querySelector("#inspector").innerHTML = `<div class="error-banner">${esc(error.message)}</div>`;
  }
}

function emptyInspector() {
  return '<div class="inspector-head"><h2>Event Inspector</h2><p>选择左侧事件查看完整信息</p></div><div class="empty-state">Tool 参数、完整结果和 metadata 将显示在这里。</div>';
}

function eventInspector(event) {
  const input = event.input ? JSON.stringify(event.input, null, 2) : "";
  const details = JSON.stringify(event.details || {}, null, 2);
  return `<div class="inspector-head"><h2>${esc(event.title)}</h2><p>sequence ${event.sequence} · turn ${event.turn ?? "—"} · raw ${event.raw_index}</p></div>
    <div class="inspector-body">
      ${event.tool_name ? inspectorSection("Tool", `${event.tool_name}\nCategory: ${event.tool_category}\nID: ${event.tool_id}\nDuration: ${event.duration_ms ?? "—"} ms\nError: ${event.is_error ? "yes" : "no"}`) : ""}
      ${input ? inspectorSection("Input", input) : ""}
      ${event.content ? inspectorSection(event.kind === "tool" ? "Full result" : "Content", event.content) : ""}
      ${details !== "{}" ? inspectorSection("Metadata", details) : ""}
    </div>`;
}

function inspectorSection(title, content) {
  return `<section class="inspector-section"><h3>${esc(title)}</h3><pre class="code-block">${esc(content)}</pre></section>`;
}

function renderLowerPanel() {
  if (state.tab === "iterations") return renderIterations();
  if (state.tab === "artifacts") return renderArtifacts();
  return renderToolStats();
}

function renderToolStats() {
  const stats = state.trace?.stats;
  if (!stats) return '<div class="empty-state">选择并加载一个 Trace 后显示工具统计。</div>';
  const tools = Object.entries(stats.tools || {});
  const max = Math.max(1, ...tools.map(([, count]) => count));
  return `<div class="toolbar"><strong>当前阶段工具分布</strong><span class="subtitle">${fmtNumber(stats.tool_call_count)} calls · ${fmtNumber(stats.unmatched_tool_calls)} unmatched</span></div>
    <div class="tool-bars">${tools.map(([name, count]) => `<div class="tool-bar-row"><span class="tool-bar-name" title="${esc(name)}">${esc(name)}</span><span class="tool-bar-track"><span class="tool-bar-fill" style="width:${count / max * 100}%"></span></span><span class="tool-bar-count">${count}</span></div>`).join("") || '<div class="empty-state">没有工具调用。</div>'}</div>`;
}

function renderIterations() {
  const iterations = state.run.iterations_detail || [];
  const queries = iterations.filter(item => item.query_path).map(item => item.iteration);
  return `<div class="toolbar"><strong>Query 演化</strong><span class="subtitle">仅展示实际产生的产物，不推断缺失文件。</span></div>
    <table class="iterations-table"><thead><tr><th>Iteration</th><th>Query</th><th>Compile</th><th>Vulnerable</th><th>Fixed</th><th>Coverage / Error</th><th>Actions</th></tr></thead>
      <tbody>${iterations.map(item => `<tr>
        <td class="numeric">${item.iteration}</td><td>${item.query_path ? "Generated" : "—"}</td>
        <td>${item.compilation_successful ? "Success" : "—"}</td><td class="numeric">${item.vulnerable_results ?? "—"}</td><td class="numeric">${item.fixed_results ?? "—"}</td>
        <td>${esc(item.error || compactExecution(item.execution_summary))}</td>
        <td><div class="iteration-actions">${item.query_path ? `<button class="secondary-button query-view" data-iteration="${item.iteration}">Query</button>` : ""}</div></td>
      </tr>`).join("")}</tbody></table>
    ${queries.length >= 2 ? `<div class="diff-controls"><strong>Query Diff</strong><select id="diff-from" class="select-input">${queries.map(value => `<option>${value}</option>`).join("")}</select><span>→</span><select id="diff-to" class="select-input">${queries.map((value, index) => `<option ${index === queries.length - 1 ? "selected" : ""}>${value}</option>`).join("")}</select><button id="show-diff" class="primary-button">比较</button></div>` : ""}
    <div id="iteration-viewer" class="artifact-viewer"><div class="empty-state">选择 Query 或比较两个迭代。</div></div>`;
}

function compactExecution(text) {
  if (!text) return "—";
  const match = text.match(/Coverage:\s*([^\n]+)/);
  return match ? `Coverage ${match[1]}` : text.split("\n")[0];
}

function renderArtifacts() {
  return `<div class="toolbar"><strong>Run Artifacts</strong><span class="subtitle">output 保持只读；大型或二进制文件仅显示元数据。</span></div>
    <div class="artifact-grid">${state.run.artifacts.map(item => `<div class="artifact-card"><button class="artifact-open" data-name="${esc(item.name)}" ${item.viewable ? "" : "disabled"} title="${esc(item.name)}">${esc(item.name)}</button><small><span>${esc(item.type)}</span><span>${fmtBytes(item.size_bytes)}</span></small></div>`).join("")}</div>
    <div id="artifact-viewer" class="artifact-viewer"><div class="empty-state">选择可查看的文本产物。</div></div>`;
}

function bindLowerPanel() {
  document.querySelectorAll(".query-view").forEach(button => button.addEventListener("click", () => {
    const iteration = Number(button.dataset.iteration);
    const artifact = state.run.artifacts.find(item => item.name.endsWith(`query-iter-${iteration}.ql`));
    if (artifact) showArtifact(artifact.name, "#iteration-viewer");
  }));
  document.querySelector("#show-diff")?.addEventListener("click", showDiff);
  document.querySelectorAll(".artifact-open").forEach(button => button.addEventListener("click", () => showArtifact(button.dataset.name)));
}

async function showArtifact(name, selector = "#artifact-viewer") {
  const viewer = document.querySelector(selector);
  if (!viewer) return;
  viewer.innerHTML = '<div class="empty-state">正在读取产物…</div>';
  try {
    const data = await api(`/api/runs/${encodeURIComponent(state.run.id)}/artifacts/${encodeURIComponent(name)}`);
    viewer.innerHTML = `<h3>${esc(name)} · ${fmtBytes(data.size_bytes)}${data.truncated ? " · preview truncated" : ""}</h3><pre class="code-block">${esc(data.content ?? "该文件为二进制格式，未加载内容。")}</pre>`;
    viewer.scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (error) {
    viewer.innerHTML = `<div class="error-banner">${esc(error.message)}</div>`;
  }
}

async function showDiff() {
  const from = document.querySelector("#diff-from")?.value;
  const to = document.querySelector("#diff-to")?.value;
  const viewer = document.querySelector("#iteration-viewer");
  if (!from || !to || !viewer) return;
  viewer.innerHTML = '<div class="empty-state">正在生成 Diff…</div>';
  try {
    const data = await api(`/api/runs/${encodeURIComponent(state.run.id)}/query-diff?from_iteration=${from}&to_iteration=${to}`);
    viewer.innerHTML = `<h3>${esc(data.from)} → ${esc(data.to)}</h3><pre class="code-block">${diffHtml(data.diff)}</pre>`;
  } catch (error) {
    viewer.innerHTML = `<div class="error-banner">${esc(error.message)}</div>`;
  }
}

function diffHtml(diff) {
  return diff.split("\n").map(line => {
    const cls = line.startsWith("+") && !line.startsWith("+++") ? "diff-add" : line.startsWith("-") && !line.startsWith("---") ? "diff-del" : "";
    return `<span class="${cls}">${esc(line)}</span>`;
  }).join("\n");
}

function bindCommonRefresh(callback) {
  document.querySelector("#refresh-button")?.addEventListener("click", callback);
}

function startPolling(callback, milliseconds) {
  stopPolling();
  state.poller = setInterval(callback, milliseconds);
}

function stopPolling() {
  if (state.poller) clearInterval(state.poller);
  state.poller = null;
}

function renderError(error) {
  app.innerHTML = shell(`<main class="page"><div class="error-banner"><strong>无法加载 Trace Viewer</strong>\n${esc(error.message || error)}</div></main>`, { live: false });
  bindCommonRefresh(route);
}

function route() {
  stopPolling();
  const hash = location.hash || "#/";
  const match = hash.match(/^#\/runs\/(.+)$/);
  if (match) loadRun(decodeURIComponent(match[1]));
  else loadDashboard();
}

window.addEventListener("hashchange", route);
route();
