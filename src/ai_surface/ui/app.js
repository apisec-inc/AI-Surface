/* ============================================================================
 * ai-surface · "AI Attack Surface Map"
 * Renders a schema-1.0 report (docs/SCHEMA_v1.md). It does ZERO scanning.
 * App-shaped layout: a welcome/input front door, then a hero (map + rail)
 * with a tabbed workspace (Overview / Findings / MCP Audit / Validate) and a
 * slide-in detail drawer.
 * Network calls allowed: fetch("./report.json") and POST "/api/scan". Scanning
 * is done by the endpoint, never in JS; the endpoint may be absent (static
 * hosted demo) and that is handled gracefully.
 * Vanilla JS, no framework, no CDN, works fully offline.
 * ========================================================================== */

(() => {
  "use strict";

  /* ---- constants ---------------------------------------------------------- */
  const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
  const SEV_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

  // category presentation (icon + short description). Renders generically;
  // unknown categories fall back to a sensible default.
  const CATS = {
    "llm-sdk":         { label: "LLM SDKs",        desc: "LLM provider SDK call sites",            icon: "chip"   },
    "agent-framework": { label: "Agents",          desc: "Agent definitions and their tools",      icon: "agent"  },
    "mcp-server":      { label: "MCP Servers",     desc: "MCP servers (discovery + deep-dive audit)", icon: "plug" },
    "model-gateway":   { label: "Model Gateways",  desc: "Proxy / routing layers",                 icon: "route"  },
    "ai-infra":        { label: "AI Infra",        desc: "Self-hosted runtimes, cloud endpoints",  icon: "server" },
    "env-key":         { label: "Env Keys",        desc: "AI provider key names",                  icon: "key"    },
    "api":             { label: "APIs",            desc: "HTTP / REST endpoints + OpenAPI specs",  icon: "globe"  },
    "vector-store":    { label: "Vector / RAG",    desc: "Vector stores and retrieval pipelines",  icon: "vector" },
  };
  const CAT_ORDER = ["mcp-server", "agent-framework", "vector-store", "llm-sdk", "model-gateway", "ai-infra", "env-key", "api"];

  // OWASP LLM Top 10 (2025) · for badge tooltips.
  const OWASP = {
    LLM01: "Prompt Injection",
    LLM02: "Sensitive Information Disclosure",
    LLM03: "Supply Chain",
    LLM04: "Data and Model Poisoning",
    LLM05: "Improper Output Handling",
    LLM06: "Excessive Agency",
    LLM07: "System Prompt Leakage",
    LLM08: "Vector and Embedding Weaknesses",
    LLM09: "Misinformation",
    LLM10: "Unbounded Consumption",
  };

  // Human-readable names for audit risk flags (the UI must not show raw ids).
  const FLAG_LABELS = {
    "secrets-detected": "Secrets in config", "secrets-in-env": "Secrets in env",
    "admin-credentials": "Admin credentials", "financial-action": "Financial action",
    "destructive-action": "Destructive action", "high-blast-radius": "High blast radius",
    "excessive-agency": "Excessive agency", "messaging-action": "Outbound messaging",
    "pii-to-llm": "PII into LLM", "broad-permissions": "Broad permissions",
    "shell-access": "Shell access", "filesystem-access": "Filesystem access",
    "filesystem-write": "Filesystem write", "database-access": "Database access",
    "network-access": "Network access", "unverified-source": "Unverified source",
    "local-binary": "Local binary", "remote-mcp": "Remote MCP endpoint",
    "no-human-oversight": "No human approval gate", "no-observability": "No logging or tracing",
  };
  // Framework full names, for badge tooltips.
  const FW_DESC = {
    "eu-ai-act": "EU AI Act requirement",
    "nist-ai-rmf": "NIST AI Risk Management Framework",
    "iso-42001": "ISO/IEC 42001 Annex A control",
  };

  const ICONS = {
    chip:   '<path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/><rect x="6" y="6" width="12" height="12" rx="2.5" stroke="currentColor" stroke-width="1.6"/><rect x="9.5" y="9.5" width="5" height="5" rx="1" stroke="currentColor" stroke-width="1.6"/>',
    agent:  '<circle cx="12" cy="8" r="4" stroke="currentColor" stroke-width="1.6"/><path d="M4 21a8 8 0 0116 0" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>',
    plug:   '<path d="M9 2v6M15 2v6" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/><path d="M7 8h10v3a5 5 0 01-5 5 5 5 0 01-5-5V8z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M12 16v6" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>',
    route:  '<circle cx="5" cy="6" r="2.5" stroke="currentColor" stroke-width="1.6"/><circle cx="19" cy="18" r="2.5" stroke="currentColor" stroke-width="1.6"/><path d="M5 8.5V12a4 4 0 004 4h6" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>',
    server: '<rect x="3" y="4" width="18" height="7" rx="2" stroke="currentColor" stroke-width="1.6"/><rect x="3" y="13" width="18" height="7" rx="2" stroke="currentColor" stroke-width="1.6"/><circle cx="7" cy="7.5" r="1" fill="currentColor"/><circle cx="7" cy="16.5" r="1" fill="currentColor"/>',
    key:    '<circle cx="8" cy="8" r="4.5" stroke="currentColor" stroke-width="1.6"/><path d="M11.2 11.2L20 20M17 17l2-2M15 15l2-2" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>',
    globe:  '<circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.6"/><path d="M3 12h18M12 3c3 3.5 3 14.5 0 18M12 3c-3 3.5-3 14.5 0 18" stroke="currentColor" stroke-width="1.6"/>',
    node:   '<circle cx="12" cy="12" r="6" stroke="currentColor" stroke-width="1.6"/>',
    vector: '<ellipse cx="12" cy="6" rx="7" ry="3" stroke="currentColor" stroke-width="1.6"/><path d="M5 6v12c0 1.66 3.13 3 7 3s7-1.34 7-3V6" stroke="currentColor" stroke-width="1.6" fill="none"/><path d="M5 12c0 1.66 3.13 3 7 3s7-1.34 7-3" stroke="currentColor" stroke-width="1.6" fill="none"/>',
    file:   '<path d="M5 3h8l6 6v12a0 0 0 010 0H5a0 0 0 010 0V3z" stroke="currentColor" stroke-width="1.4" fill="none"/><path d="M13 3v6h6" stroke="currentColor" stroke-width="1.4"/>',
    arrow:  '<path d="M5 12h14M13 6l6 6-6 6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" fill="none"/>',
    close:  '<path d="M5 5l14 14M19 5L5 19" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>',
    search: '<circle cx="11" cy="11" r="7" stroke="currentColor" stroke-width="1.7"/><path d="M16.5 16.5L21 21" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>',
    caret:  '<path d="M6 9l6 6 6-6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" fill="none"/>',
    lock:   '<rect x="5" y="11" width="14" height="9" rx="2" stroke="currentColor" stroke-width="1.6"/><path d="M8 11V8a4 4 0 018 0v3" stroke="currentColor" stroke-width="1.6"/>',
    shield: '<path d="M12 2l8 3v6c0 5-3.5 9-8 11-4.5-2-8-6-8-11V5l8-3z" stroke="currentColor" stroke-width="1.6" fill="none" stroke-linejoin="round"/>',
    warn:   '<path d="M12 3l10 18H2L12 3z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round" fill="none"/><path d="M12 10v5M12 18h.01" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>',
    info:   '<circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.6"/><path d="M12 11v5M12 8h.01" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>',
    sun:    '<circle cx="12" cy="12" r="4.5" stroke="currentColor" stroke-width="1.7"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5L19 19M19 5l-1.5 1.5M6.5 17.5L5 19" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>',
    moon:   '<path d="M21 12.8A8.5 8.5 0 1111.2 3a6.5 6.5 0 009.8 9.8z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round" fill="none"/>',
    download: '<path d="M12 3v12M7 10l5 5 5-5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" fill="none"/><path d="M4 19h16" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>',
    gov:    '<path d="M4 9l8-5 8 5M5 9v8m4-8v8m6-8v8m4-8v8M3 21h18" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/>',
  };

  /* ---- tiny helpers ------------------------------------------------------- */
  const $ = (sel, root = document) => root.querySelector(sel);
  const esc = (s) => String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  const icon = (name, cls = "") =>
    `<svg viewBox="0 0 24 24" fill="none" class="${cls}" aria-hidden="true">${ICONS[name] || ICONS.node}</svg>`;
  const sevColor = (s) => s ? `var(--sev-${s})` : "var(--sev-none)";
  const catMeta = (c) => CATS[c] || { label: titleCase(c), desc: "Detected AI surface", icon: "node" };
  const titleCase = (s) => String(s || "").replace(/[-_]/g, " ").replace(/\b\w/g, (m) => m.toUpperCase());
  const catRank = (c) => { const i = CAT_ORDER.indexOf(c); return i < 0 ? 99 : i; };

  /* ---- state -------------------------------------------------------------- */
  let REPORT = null;
  let FINDINGS = [];           // augmented with stable index id
  const TABS = ["overview", "findings", "mcp-audit", "validate"];
  const state = { q: "", cat: "all", sev: "all", tab: "overview" };

  /* ======================================================================== *
   * BOOT  ·  show the welcome / input front door first.
   * No report is loaded until the user picks "View demo" or runs a scan.
   * Exception: ?demo (used by the hosted demo) auto-loads the sample report
   * so visitors land on the populated map, not a form they cannot act on.
   * ======================================================================== */
  initTheme();
  if (/(\?|&)demo\b/.test(location.search) || location.hash === "#demo") {
    loadDemo();
  } else {
    renderWelcome();
  }

  /* ---- theme -------------------------------------------------------------- */
  function initTheme() {
    let saved = null;
    try { saved = localStorage.getItem("ai-surface-theme"); } catch (_) {}
    if (saved === "light" || saved === "dark") {
      document.documentElement.setAttribute("data-theme", saved);
    } else {
      const prefersLight = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches;
      document.documentElement.setAttribute("data-theme", prefersLight ? "light" : "dark");
    }
  }
  function toggleTheme() {
    const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("ai-surface-theme", next); } catch (_) {}
    // map colors are baked from CSS vars at draw time -> redraw
    if (REPORT) drawMap();
  }

  /* ======================================================================== *
   * FATAL (report.json load failure)
   * ======================================================================== */
  function renderFatal(err) {
    const app = $("#app");
    app.removeAttribute("aria-busy");
    app.innerHTML = `
      <div class="shell">
        ${topbarHTML()}
        <div class="fatal reveal">
          <div class="ic">${icon("warn")}</div>
          <h2>Couldn't load <span class="mono">report.json</span></h2>
          <p>This viewer renders a <span class="mono">schema-1.0</span> report emitted by the
             ai-surface engine. It does no scanning itself. Serve this directory over HTTP so
             the page can <span class="mono">fetch("./report.json")</span> (opening via
             <span class="mono">file://</span> is blocked by the browser).</p>
          <pre>cd ui
python3 -m http.server 8000
# then open http://localhost:8000</pre>
          <p class="detail">${esc(err && err.message ? err.message : String(err))}</p>
        </div>
      </div>`;
    wireTopbar();
  }

  /* ======================================================================== *
   * WELCOME · the front door (no report loaded yet)
   * ======================================================================== *
   * Input options: scan a GitHub repo URL, or a local path; primary "Scan"
   * (POSTs to /api/scan) and secondary "View demo" (fetches ./report.json).
   * Scanning is NEVER done in JS. If /api/scan is unavailable (static hosted
   * demo with no local server), we degrade gracefully to a clear message.
   */
  function renderWelcome() {
    const app = $("#app");
    app.removeAttribute("aria-busy");
    app.innerHTML = `
      <div class="shell">
        ${topbarHTML()}
        <section class="welcome">
          <div class="welcome-inner reveal">
            <span class="eyebrow"><span class="dot"></span>AI Inventory and CI Governance Gate &middot; Offline</span>
            <h1 class="welcome-title">Map your codebase's<br><span class="grad">AI attack surface</span></h1>
            <p class="welcome-lede">Map every LLM call, agent, MCP server, gateway, key, and API in your repo
               as one view and a standard AI-BOM. That is the inventory the EU AI Act, NIST AI RMF, and ISO 42001
               expect, and it runs fully offline.</p>

            <form class="scan-form reveal d1" id="scan-form" novalidate>
              <label class="scan-field">
                <span class="fl">Scan a GitHub repo URL</span>
                <input id="scan-repo" type="url" name="repo_url" inputmode="url" autocomplete="off"
                       placeholder="https://github.com/org/repo" />
              </label>
              <label class="scan-field">
                <span class="fl">or scan a local path</span>
                <input id="scan-path" type="text" name="path" autocomplete="off" value="." placeholder="/path/to/your/project" />
              </label>
              <div class="scan-actions">
                <button type="submit" class="btn btn-primary" id="scan-go">
                  ${icon("search")}<span>Scan</span>
                </button>
                <button type="button" class="btn btn-ghost" id="scan-demo">View demo</button>
              </div>
              <p class="scan-status" id="scan-status" role="status" aria-live="polite"></p>
              <p class="scan-hint">Terminal user? Run <code>ai-surface scan . --ui</code></p>
            </form>
          </div>
        </section>
        ${footerHTML(true)}
      </div>`;
    wireTopbar();
    wireWelcome();
  }

  function wireWelcome() {
    const form = $("#scan-form");
    const demo = $("#scan-demo");
    if (demo) demo.addEventListener("click", loadDemo);
    if (form) form.addEventListener("submit", (e) => { e.preventDefault(); runScan(); });
  }

  function setScanStatus(html, kind) {
    const el = $("#scan-status");
    if (!el) return;
    el.className = "scan-status" + (kind ? " " + kind : "");
    el.innerHTML = html;
  }
  function setScanBusy(busy) {
    const go = $("#scan-go"), demo = $("#scan-demo");
    [go, demo].forEach((b) => { if (b) b.disabled = !!busy; });
    if (go) go.classList.toggle("loading", !!busy);
  }

  // "View demo" · always works, even on a static host (just fetch the bundled report).
  function loadDemo() {
    setScanBusy(true);
    setScanStatus("Loading demo report&hellip;", "");
    fetch("./report.json", { cache: "no-store" })
      .then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status} ${r.statusText}`); return r.json(); })
      .then((data) => { REPORT = data; renderApp(); })
      .catch((err) => { setScanBusy(false); setScanStatus(
        `Could not load <code>report.json</code>: ${esc(err && err.message ? err.message : String(err))}. ` +
        `Serve this folder over HTTP (<code>python3 -m http.server</code>); <code>file://</code> blocks fetch.`, "err"); });
  }

  // "Scan" · POST to /api/scan. The endpoint does the scanning (it may not
  // exist yet). On absence/failure we degrade gracefully with instructions.
  function runScan() {
    const repo = ($("#scan-repo") && $("#scan-repo").value || "").trim();
    const path = ($("#scan-path") && $("#scan-path").value || "").trim();
    if (!repo && !path) {
      setScanStatus("Enter a GitHub repo URL or a local path, or use View demo.", "err");
      return;
    }
    const body = {};
    if (repo) body.repo_url = repo;
    if (path) body.path = path;

    setScanBusy(true);
    setScanStatus("Scanning&hellip; this runs the local tool against your code.", "");

    fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    })
      .then((r) => {
        if (r.status === 404) throw new Error("__NO_ENDPOINT__");
        if (!r.ok) return r.text().then((t) => { throw new Error(`HTTP ${r.status}${t ? ": " + t.slice(0, 200) : ""}`); });
        return r.json();
      })
      .then((data) => {
        if (!data || !data.schema_version) throw new Error("Response was not a schema-1.0 report.");
        REPORT = data; renderApp();
      })
      .catch((err) => {
        setScanBusy(false);
        const noEndpoint = err && (err.message === "__NO_ENDPOINT__" ||
          err.message === "Failed to fetch" || /NetworkError|load failed/i.test(err.message || ""));
        if (noEndpoint) {
          setScanStatus(
            `Live scanning needs the local tool. Install ai-surface and run ` +
            `<code>ai-surface scan . --ui</code>, or use View demo.`, "warn");
        } else {
          setScanStatus(`Scan failed: ${esc(err && err.message ? err.message : String(err))}`, "err");
        }
      });
  }

  /* ======================================================================== *
   * RENDER APP  (a report is loaded)
   * ======================================================================== */
  function renderApp() {
    FINDINGS = (REPORT.findings || []).map((f, i) => ({ ...f, _id: i }));
    if (!TABS.includes(state.tab)) state.tab = "overview";
    const tm = /(?:#|&)tab=([a-z-]+)/.exec(location.hash);
    if (tm && TABS.includes(tm[1])) state.tab = tm[1];
    const cm = /(?:#|&)cat=([a-z-]+)/.exec(location.hash);
    if (cm) state.cat = cm[1];
    const app = $("#app");
    app.removeAttribute("aria-busy");
    app.innerHTML = `
      <div class="shell">
        ${topbarHTML(true)}
        ${heroHTML()}
        ${tabsHTML()}
        <div class="tab-panels" id="tab-panels"></div>
        ${errorsHTML()}
        ${footerHTML()}
      </div>`;
    wireTopbar();
    drawMap();
    wireMapInteraction();
    wireHero();
    wireDrawer();
    wireTooltips();
    wireTabs();
    renderActiveTab();
    // deep-link: #open=<finding id> opens that finding's drawer directly
    const om = /(?:#|&)open=(\d+)/.exec(location.hash);
    if (om) openDrawer(Number(om[1]));
  }

  /* ---- topbar ------------------------------------------------------------- */
  function topbarHTML(loaded) {
    const root = loaded && REPORT && REPORT.scan_root ? REPORT.scan_root : "";
    const ver = loaded && REPORT && REPORT.tool_version ? REPORT.tool_version : "";
    return `
      <header class="topbar">
        <div class="logo">
          <span class="logo-mark"></span>
          <b>ai-surface</b>
          <span class="by">by APIsec</span>
        </div>
        <span class="topbar-spacer"></span>
        ${root ? `<span class="chip-mono">${esc(root)}</span>` : ""}
        ${ver ? `<span class="chip-mono">v${esc(ver)}</span>` : ""}
        ${loaded ? `<a class="topbar-btn" href="./ai-bom.json" download="ai-bom.json" title="Download the CycloneDX AI-BOM">${icon("download")}<span>AI-BOM</span></a>` : ""}
        ${loaded ? `<button class="topbar-btn" id="new-scan" title="Scan another target">${icon("search")}<span>New scan</span></button>` : ""}
        <button class="theme-toggle" id="theme-toggle" aria-label="Toggle color theme" title="Toggle theme">
          <span class="ic-sun">${icon("sun")}</span><span class="ic-moon">${icon("moon")}</span>
        </button>
      </header>`;
  }
  function wireTopbar() {
    const t = $("#theme-toggle");
    if (t) t.addEventListener("click", toggleTheme);
    const ns = $("#new-scan");
    if (ns) ns.addEventListener("click", () => { closeDrawer(); REPORT = null; FINDINGS = []; state.tab = "overview"; renderWelcome(); });
  }

  /* ======================================================================== *
   * HERO  (map + metrics rail)
   * ======================================================================== */
  function heroHTML() {
    const s = REPORT.summary || {};
    const total = s.total_findings != null ? s.total_findings : FINDINGS.length;
    const bySev = s.by_severity || {};
    const byCat = s.by_category || {};
    const catCount = Object.keys(byCat).length || new Set(FINDINGS.map((f) => f.category)).size;
    const assessed = FINDINGS.filter((f) => f.severity).length;
    const inventoried = Math.max(total - assessed, 0);
    const assessedPct = total ? Math.round((assessed / total) * 100) : 0;
    const ts = fmtDate(REPORT.scan_timestamp);
    const ver = REPORT.tool_version ? "v" + REPORT.tool_version : "";
    const resolveHere = s.resolve_here_count != null ? s.resolve_here_count
      : FINDINGS.filter((f) => f.disposition === "resolve-here").length;
    const validateRt = s.validate_runtime_count != null ? s.validate_runtime_count
      : FINDINGS.filter((f) => f.disposition === "validate-runtime").length;

    return `
      <section class="hero">
        <div class="hero-head reveal">
          <span class="eyebrow"><span class="dot"></span>ai-surface &middot; AI Attack Surface</span>
          <h1 class="hero-target">${esc(rootName())}</h1>
          <div class="hero-meta">
            <span><b>${total}</b> AI surface${total === 1 ? "" : "s"}</span>
            <span><b>${catCount}</b> categor${catCount === 1 ? "y" : "ies"}</span>
            <span><b>${resolveHere}</b> resolve here</span>
            <span><b>${validateRt}</b> validate at runtime</span>
            ${ts ? `<span>scanned ${esc(ts)}</span>` : ""}
            ${ver ? `<span class="mono">${esc(ver)}</span>` : ""}
          </div>
        </div>

        <div class="stage reveal d3">
          <div class="panel map-panel" id="map-panel">
            <div class="panel-head">
              <h2>Attack Surface Map</h2>
              <span class="sub">radial cluster &middot; click any node</span>
              <span class="grow"></span>
            </div>
            <div class="map-wrap" id="map-wrap">
              <div class="map-hint">hover to focus &middot; click to inspect</div>
              ${mapLegendHTML()}
            </div>
          </div>

          <div class="rail">
            <div class="panel metric-card">
              <div class="metric-top">
                <span class="big">${total}</span>
                <span class="label">AI surface${total === 1 ? "" : "s"} discovered<br>across ${catCount} categor${catCount === 1 ? "y" : "ies"}</span>
              </div>
              <div class="assess-split">
                <div class="split-bar" title="${assessed} assessed of ${total}">
                  <i class="assessed" style="width:${assessedPct}%"></i>
                </div>
                <div class="split-legend">
                  <span><b>${inventoried}</b> inventoried</span>
                  <span><b>${assessed}</b> assessed for risk</span>
                </div>
              </div>
            </div>

            <div class="panel metric-card">
              <div class="panel-head" style="margin:-18px -20px 14px;border-radius:var(--radius) var(--radius) 0 0;">
                <h2>By category</h2>
                <span class="grow"></span>
                <span class="sub">${catCount} present</span>
              </div>
              ${categoryChipsHTML(byCat)}
            </div>
          </div>
        </div>
      </section>`;
  }

  function mapLegendHTML() {
    const items = SEV_ORDER.map((s) =>
      `<span class="lg"><span class="sw" style="background:var(--sev-${s})"></span>${s}</span>`).join("");
    return `<div class="map-legend">
      ${items}
      <span class="lg"><span class="sw" style="background:var(--sev-none)"></span>inventoried</span>
      <span class="lg" style="color:var(--brand)"><span class="sw ring"></span>assessed (risk ring)</span>
    </div>`;
  }

  function severityDistHTML(bySev, assessed) {
    if (!assessed) {
      return `<div class="sev-empty">No findings have been assessed for severity yet.
        Severity comes from the deep-dive audit layer (MCP servers and agents, plus checks for
        missing approval gates and missing observability). Everything else is inventoried, not assessed.</div>`;
    }
    const peak = Math.max(...SEV_ORDER.map((s) => bySev[s] || 0), 1);
    const rows = SEV_ORDER.filter((s) => (bySev[s] || 0) > 0).map((s) => {
      const n = bySev[s] || 0;
      const pct = Math.round((n / peak) * 100);
      return `<div class="sev-row">
        <span class="name">${s}</span>
        <span class="track"><i style="width:${pct}%;background:var(--sev-${s})"></i></span>
        <span class="n">${n}</span>
      </div>`;
    }).join("");
    return `<div class="sev-dist">${rows}</div>`;
  }

  function categoryChipsHTML(byCat) {
    const entries = Object.entries(byCat);
    if (!entries.length) return `<div class="sev-empty">No categories present.</div>`;
    entries.sort((a, b) => catRank(a[0]) - catRank(b[0]));
    return `<div class="cat-grid">` + entries.map(([c, n]) => {
      const m = catMeta(c);
      return `<button class="cat-pill clickable" data-cat="${esc(c)}" title="View ${esc(m.label)} in Findings">` +
        `<span class="ic">${icon(m.icon)}</span>${esc(m.label)}<span class="n">${n}</span></button>`;
    }).join("") + `</div>`;
  }

  /* ======================================================================== *
   * TABBED WORKSPACE  ·  Overview / Findings / MCP Audit / Validate
   * ======================================================================== *
   * The core reorganization: instead of one long scroll, the detail surfaces
   * are split into keyboard-accessible tabs. Drawer is shared across all tabs.
   */
  function tabsHTML() {
    const mcpCount = FINDINGS.filter((f) => f.audit).length;
    const validateCount = countBridges();
    const defs = [
      { id: "overview",  label: "Overview" },
      { id: "findings",  label: "Findings",  n: FINDINGS.length },
      { id: "mcp-audit", label: "Audits", n: mcpCount },
      { id: "validate",  label: "Validate",  n: validateCount },
    ];
    const tabs = defs.map((t) => {
      const active = state.tab === t.id;
      return `<button role="tab" class="tab" id="tab-${t.id}" data-tab="${t.id}"
        aria-selected="${active}" aria-controls="tab-panels" tabindex="${active ? "0" : "-1"}">
        ${esc(t.label)}${t.n != null ? `<span class="n">${t.n}</span>` : ""}</button>`;
    }).join("");
    return `<div class="tabs" role="tablist" aria-label="Workspace">${tabs}</div>`;
  }

  function wireTabs() {
    const list = $(".tabs");
    if (!list) return;
    const tabs = [...list.querySelectorAll(".tab")];
    tabs.forEach((t) => t.addEventListener("click", () => setTab(t.dataset.tab)));
    list.addEventListener("keydown", (e) => {
      const i = tabs.findIndex((t) => t.dataset.tab === state.tab);
      let ni = -1;
      if (e.key === "ArrowRight" || e.key === "ArrowDown") ni = (i + 1) % tabs.length;
      else if (e.key === "ArrowLeft" || e.key === "ArrowUp") ni = (i - 1 + tabs.length) % tabs.length;
      else if (e.key === "Home") ni = 0;
      else if (e.key === "End") ni = tabs.length - 1;
      if (ni < 0) return;
      e.preventDefault();
      setTab(tabs[ni].dataset.tab);
      tabs[ni].focus();
    });
  }

  function setTab(id) {
    if (!TABS.includes(id)) id = "overview";
    state.tab = id;
    document.querySelectorAll(".tabs .tab").forEach((t) => {
      const active = t.dataset.tab === id;
      t.setAttribute("aria-selected", String(active));
      t.tabIndex = active ? 0 : -1;
    });
    renderActiveTab();
  }

  function renderActiveTab() {
    const root = $("#tab-panels");
    if (!root) return;
    if (state.tab === "overview")       root.innerHTML = overviewHTML();
    else if (state.tab === "findings")  { root.innerHTML = findingsTabHTML(); wireExplorer(); }
    else if (state.tab === "mcp-audit") root.innerHTML = mcpAuditHTML();
    else if (state.tab === "validate")  root.innerHTML = validateHTML();
    root.setAttribute("role", "tabpanel");
    root.setAttribute("aria-labelledby", "tab-" + state.tab);
    // wire any finding rows / cards in this panel to the drawer
    wirePanelRows(root);
  }

  // any element with [data-open-id] opens that finding in the drawer
  function wirePanelRows(root) {
    root.querySelectorAll("[data-open-id]").forEach((el) => {
      const open = (e) => {
        if (e.target.closest("a")) return;
        if (e.type === "keydown" && e.key !== "Enter" && e.key !== " ") return;
        if (e.type === "keydown") e.preventDefault();
        openDrawer(Number(el.dataset.openId));
      };
      el.addEventListener("click", open);
      if (el.hasAttribute("tabindex")) el.addEventListener("keydown", open);
    });
  }

  function countBridges() {
    const set = new Set();
    FINDINGS.forEach((f) => (f.bridges || []).forEach((b) => { if (b && b.sku) set.add(b.sku); }));
    return set.size;
  }

  /* ======================================================================== *
   * MAP · hand-rolled radial cluster layout in SVG
   * ======================================================================== *
   * Layout algorithm:
   *  - Center node = scan root (the app/repo).
   *  - Ring 1 = one hub per category present, evenly spaced around a circle.
   *    Hub angular position derived from index; we bias starting angle so the
   *    densest categories don't collide visually.
   *  - Ring 2 = the findings (leaves) for each category, fanned out in a small
   *    arc centered on their hub's angle. Arc width and leaf radius scale with
   *    the number of leaves so 4 nodes and 40 nodes both look intentional.
   *  - Node radius (size) encodes importance: assessed findings are larger,
   *    higher severity larger still; hubs sized by child count.
   *  - Color: severity palette when assessed; neutral when inventory-only.
   *    Assessed-with-risk nodes get a glowing severity ring.
   *  Everything is pure trig; no physics, deterministic, stable across redraws.
   */
  function drawMap() {
    const wrap = $("#map-wrap");
    if (!wrap) return;
    // clear previous svg/empty (keep hint + legend)
    wrap.querySelectorAll("svg, .map-empty").forEach((n) => n.remove());

    const W = 1000, H = 688;               // viewBox units (16:11)
    const cx = W / 2, cy = H / 2;

    const byCat = {};
    FINDINGS.forEach((f) => { (byCat[f.category] = byCat[f.category] || []).push(f); });
    const cats = Object.keys(byCat);

    // empty scan
    if (!FINDINGS.length) {
      const root = REPORT.scan_root ? `<span class="mono">${esc(REPORT.scan_root)}</span>` : "this codebase";
      const div = document.createElement("div");
      div.className = "map-empty";
      div.innerHTML = `<div class="big">No AI surface detected</div>
        <div>ai-surface found nothing to map in ${root}.<br>That's a clean result, not an error.</div>`;
      wrap.appendChild(div);
      return;
    }

    const NS = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(NS, "svg");
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    svg.setAttribute("preserveAspectRatio", "xMidYMid meet");
    const g = document.createElementNS(NS, "g");
    g.setAttribute("class", "graph");
    svg.appendChild(g);

    const edgeLayer = mk(NS, "g");
    const nodeLayer = mk(NS, "g");
    g.appendChild(edgeLayer); g.appendChild(nodeLayer);

    // radii scale to fit the viewport regardless of count
    const minWH = Math.min(W, H);
    const hubR = minWH * 0.205;
    const leafBase = minWH * 0.40;   // first ring of leaves
    const leafMax = minWH * 0.47;    // outer ring (crowded categories band outward)
    const sector = (Math.PI * 2) / cats.length;  // angular wedge owned by each category
    const startAngle = -Math.PI / 2; // top

    // --- center node ---
    const center = mk(NS, "g"); center.setAttribute("class", "node node-center");
    center.appendChild(disc(NS, cx, cy, 34, "var(--hub-fill)", "var(--line-2)", 1.5));
    const cinner = disc(NS, cx, cy, 30, "url(#coreGrad)", "none", 0);
    center.appendChild(cinner);
    const clabel = text(NS, cx, cy + 60, rootName(), "lbl");
    clabel.setAttribute("text-anchor", "middle");
    center.appendChild(clabel);
    nodeLayer.appendChild(center);

    // gradient def for core (built node-by-node; innerHTML on SVG is unreliable)
    const defs = mk(NS, "defs");
    const grad = mk(NS, "radialGradient");
    grad.setAttribute("id", "coreGrad");
    grad.setAttribute("cx", "38%"); grad.setAttribute("cy", "32%");
    [["0%", "#a98bff"], ["55%", "#7c5cff"], ["100%", "#4f6dff"]].forEach(([o, c]) => {
      const st = mk(NS, "stop");
      st.setAttribute("offset", o); st.setAttribute("stop-color", c);
      grad.appendChild(st);
    });
    defs.appendChild(grad);
    svg.insertBefore(defs, g);

    // --- hubs + leaves ---
    cats.forEach((cat, i) => {
      const ang = startAngle + (i / cats.length) * Math.PI * 2;
      const hx = cx + Math.cos(ang) * hubR;
      const hy = cy + Math.sin(ang) * hubR;
      const leaves = byCat[cat];
      const m = catMeta(cat);

      // edge center -> hub (tagged so hover can light up only this wedge)
      const hubEdge = edge(NS, cx, cy, hx, hy, 1.7, .7);
      hubEdge.dataset.cat = cat;
      edgeLayer.appendChild(hubEdge);

      // hub size by child count
      const hr = 13 + Math.min(leaves.length, 12) * 1.6;

      const hub = mk(NS, "g");
      hub.setAttribute("class", "node node-hub");
      hub.dataset.cat = cat;
      hub.appendChild(ringEl(NS, hx, hy, hr + 6, "var(--brand-2)", 1.2, .35));
      hub.appendChild(disc(NS, hx, hy, hr, "var(--hub-fill)", "var(--line-2)", 1.4));
      // category count
      const ct = text(NS, hx, hy + 4, String(leaves.length), "count");
      ct.setAttribute("text-anchor", "middle"); ct.setAttribute("fill", "var(--text)");
      hub.appendChild(ct);
      // hub label (outside)
      const lx = cx + Math.cos(ang) * (hubR + hr + 14);
      const ly = cy + Math.sin(ang) * (hubR + hr + 14);
      const hl = text(NS, lx, ly + 4, m.label, "lbl");
      hl.setAttribute("text-anchor", Math.cos(ang) < -0.25 ? "end" : Math.cos(ang) > 0.25 ? "start" : "middle");
      hub.appendChild(hl);
      nodeLayer.appendChild(hub);

      // Leaves stay INSIDE this category's own angular wedge so categories
      // never visually overlap (a leaf only ever sits under its real hub).
      // Crowded categories fan into concentric radial bands instead of widening
      // past their wedge, so a large app stays legible.
      const n = leaves.length;
      const arc = n <= 1 ? 0 : Math.min(sector * 0.74, 0.16 * n);
      const bands = Math.max(1, Math.ceil(n / 6));
      const bandGap = bands > 1 ? (leafMax - leafBase) / (bands - 1) : 0;
      leaves.forEach((f, j) => {
        const band = j % bands;
        const t = n === 1 ? 0 : (j / (n - 1)) - 0.5;
        const la = ang + t * arc;
        const lr = leafBase + band * bandGap;
        const lx2 = cx + Math.cos(la) * lr;
        const ly2 = cy + Math.sin(la) * lr;

        const leafEdge = edge(NS, hx, hy, lx2, ly2, 1.2, .5);
        leafEdge.dataset.cat = cat;
        edgeLayer.appendChild(leafEdge);

        const sev = f.severity;
        const assessed = !!sev;
        // size: base + severity bump
        const r = assessed ? 9 + (SEV_RANK[sev] || 0) * 1.7 : 7.5;
        const fill = assessed ? sevColor(sev) : "var(--node-fill)";
        const stroke = assessed ? "transparent" : "var(--line-2)";

        const node = mk(NS, "g");
        node.setAttribute("class", "node node-leaf");
        node.dataset.id = String(f._id);
        node.dataset.cat = cat;

        // generous transparent hit target so small nodes are easy to click
        node.appendChild(disc(NS, lx2, ly2, Math.max(r + 9, 17), "transparent", "none", 0, "hit"));

        if (assessed) {
          // glowing severity ring
          node.appendChild(ringEl(NS, lx2, ly2, r + 6, sevColor(sev), 2, .9, "ring"));
        }
        const d = disc(NS, lx2, ly2, r, fill, stroke, assessed ? 0 : 1.4, "disc");
        node.appendChild(d);

        // short label (only when not too crowded, else show on hover via title)
        if (n <= 8) {
          const showLeft = Math.cos(la) < 0;
          const tl = text(NS, lx2 + (showLeft ? -(r + 7) : (r + 7)), ly2 + 4, shortName(f.surface), "lbl");
          tl.setAttribute("text-anchor", showLeft ? "end" : "start");
          node.appendChild(tl);
        }
        const title = mk(NS, "title");
        title.textContent = `${f.surface}${sev ? " · " + sev : " · inventoried"}`;
        node.appendChild(title);

        nodeLayer.appendChild(node);
      });
    });

    wrap.insertBefore(svg, wrap.firstChild);
  }

  // svg builders
  function mk(NS, tag) { return document.createElementNS(NS, tag); }
  function disc(NS, x, y, r, fill, stroke, sw, cls) {
    const c = mk(NS, "circle");
    c.setAttribute("cx", x); c.setAttribute("cy", y); c.setAttribute("r", r);
    c.setAttribute("fill", fill); c.setAttribute("stroke", stroke); c.setAttribute("stroke-width", sw);
    if (cls) c.setAttribute("class", cls);
    return c;
  }
  function ringEl(NS, x, y, r, stroke, sw, op, cls) {
    const c = mk(NS, "circle");
    c.setAttribute("cx", x); c.setAttribute("cy", y); c.setAttribute("r", r);
    c.setAttribute("fill", "none"); c.setAttribute("stroke", stroke);
    c.setAttribute("stroke-width", sw); c.setAttribute("opacity", op);
    c.setAttribute("class", cls ? cls : "ring");
    return c;
  }
  function edge(NS, x1, y1, x2, y2, sw, op) {
    const l = mk(NS, "path");
    // gentle quadratic curve for organic feel
    const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
    const dx = x2 - x1, dy = y2 - y1;
    const off = 0.12;
    const qx = mx - dy * off, qy = my + dx * off;
    l.setAttribute("d", `M${x1.toFixed(1)} ${y1.toFixed(1)} Q${qx.toFixed(1)} ${qy.toFixed(1)} ${x2.toFixed(1)} ${y2.toFixed(1)}`);
    l.setAttribute("class", "edge");
    l.setAttribute("opacity", op);
    return l;
  }
  function text(NS, x, y, str, cls) {
    const t = mk(NS, "text");
    t.setAttribute("x", x); t.setAttribute("y", y); t.setAttribute("class", cls);
    t.textContent = str;
    return t;
  }
  function rootName() {
    const r = REPORT.scan_root || "app";
    const parts = String(r).split("/").filter(Boolean);
    return parts[parts.length - 1] || r;
  }
  function shortName(s) {
    s = String(s || "");
    s = s.replace(/^(MCP Server|REST API|LangChain Agent|.*Agent):\s*/i, "");
    return s.length > 22 ? s.slice(0, 21) + "…" : s;
  }

  function wireMapInteraction() {
    const g = $("#map-wrap .graph");
    if (!g) return;
    g.querySelectorAll(".node-leaf, .node-hub").forEach((node) => {
      node.addEventListener("mouseenter", () => focusCategory(g, node.dataset.cat));
      node.addEventListener("mouseleave", () => unfocus(g));
    });
    // Delegated click: robust to tiny SVG targets and re-renders. closest()
    // walks from the clicked shape up to its node group.
    g.addEventListener("click", (e) => {
      const node = e.target.closest(".node-leaf, .node-hub");
      if (!node) return;
      if (node.classList.contains("node-leaf")) {
        openDrawer(Number(node.dataset.id));
      } else { // hub -> jump to that category in the Findings tab
        state.cat = node.dataset.cat;
        setTab("findings");
        const exp = $("#tab-panels"); if (exp) exp.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    });
  }

  // Hero category bubbles -> open that category in the Findings tab.
  function wireHero() {
    document.querySelectorAll(".cat-pill[data-cat]").forEach((el) => {
      el.addEventListener("click", () => {
        state.cat = el.dataset.cat;
        setTab("findings");
        const exp = $("#tab-panels"); if (exp) exp.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    });
  }
  function focusCategory(g, cat) {
    g.classList.add("dim");
    g.querySelectorAll(".node").forEach((n) => {
      if (n.classList.contains("node-center") || n.dataset.cat === cat) n.classList.add("related");
    });
    // Light up only the edges wiring this category, so unrelated leaves never
    // look connected to the hovered hub.
    g.querySelectorAll(".edge").forEach((e) => {
      if (e.dataset.cat === cat) e.classList.add("related");
    });
  }
  function unfocus(g) {
    g.classList.remove("dim");
    g.querySelectorAll(".related").forEach((n) => n.classList.remove("related"));
  }

  /* ======================================================================== *
   * OVERVIEW TAB  ·  "where do I start"
   * summary stats + severity distribution + top-risks triage list
   * ======================================================================== */
  function overviewHTML() {
    const s = REPORT.summary || {};
    const total = s.total_findings != null ? s.total_findings : FINDINGS.length;
    const bySev = s.by_severity || {};
    const assessed = FINDINGS.filter((f) => f.severity).length;
    const inventoried = Math.max(total - assessed, 0);
    const owaspSet = new Set();
    FINDINGS.forEach((f) => f.audit && (f.audit.owasp_mappings || []).forEach((o) => owaspSet.add(o)));

    const resolveHere = s.resolve_here_count != null ? s.resolve_here_count
      : FINDINGS.filter((f) => f.disposition === "resolve-here").length;
    const validateRt = s.validate_runtime_count != null ? s.validate_runtime_count
      : FINDINGS.filter((f) => f.disposition === "validate-runtime").length;

    const stats = `
      <div class="stat-row">
        ${statCard(total, "Surfaces discovered")}
        ${statCard(resolveHere, "Resolve here, fix now", "accent")}
        ${statCard(validateRt, "Validate at runtime", "neutral")}
        ${statCard(assessed, "Assessed for risk")}
      </div>`;

    const sevPanel = `
      <div class="panel ov-panel">
        <div class="panel-head"><h2>Assessed severity</h2><span class="grow"></span><span class="sub">${assessed} of ${total}</span></div>
        <div class="ov-pad">${severityDistHTML(bySev, assessed)}</div>
      </div>`;

    return `
      <section class="tab-section reveal">
        ${stats}
        ${governancePanelHTML()}
        <div class="ov-grid">
          ${sevPanel}
          ${topRisksPanelHTML()}
        </div>
      </section>`;
  }

  // Governance evidence: which AI-governance frameworks this scan produces
  // evidence for. Honest framing: "produces evidence for", not "compliant".
  function governancePanelHTML() {
    const fws = REPORT.frameworks || [];
    const bom = `<a class="gov-bom" href="./ai-bom.json" download="ai-bom.json">${icon("download")}<span>Download AI-BOM</span><span class="gov-bom-sub">CycloneDX</span></a>`;
    const head = `<div class="panel-head"><h2>${icon("gov")}Governance evidence</h2><span class="grow"></span><span class="sub">evidence for, not a compliance claim</span></div>`;
    const badges = fws.length
      ? `<div class="gov-badges">${fws.map((fw) =>
          `<span class="gov-badge" title="${esc((fw.provides || []).join("  •  "))}">${esc(fw.name)}</span>`).join("")}</div>`
      : `<div class="sev-empty">No framework evidence in this scan.</div>`;
    return `
      <div class="panel gov-panel">
        ${head}
        <div class="ov-pad gov-compact">
          ${badges}
          ${bom}
        </div>
      </div>`;
  }

  function statCard(n, label, kind) {
    return `<div class="stat ${kind || ""}"><span class="num">${n}</span><span class="lbl">${esc(label)}</span></div>`;
  }

  // Top risks: the triage shortlist (severity-ordered). Distinct from the
  // Findings tab (full inventory). Items resolve to their finding in the drawer.
  function topRisksPanelHTML() {
    const risks = (REPORT.summary && REPORT.summary.top_risks) || [];
    const head = `<div class="panel-head"><h2>Top risks</h2><span class="grow"></span><span class="sub">severity-ordered triage</span></div>`;
    if (!risks.length) {
      return `<div class="panel ov-panel">${head}<div class="ov-pad"><div class="sev-empty">No risks to triage.
        Discovery is severity-free; severity comes from the deep-dive audit layer (MCP servers and agents,
        plus approval-gate and observability checks), and nothing in this scan was flagged.</div></div></div>`;
    }
    const items = risks.slice(0, 10).map((r, i) => {
      // resolve to a finding so clicking opens its drawer; the surface is the
      // longest finding-surface that the risk string starts with.
      const fid = resolveRiskFinding(r);
      const f = fid != null ? FINDINGS.find((x) => x._id === fid) : null;
      const sev = f ? f.severity : null;
      // label split: prefer the matched surface as the "source"
      let src = "", rest = r;
      if (f && r.startsWith(f.surface)) {
        src = f.surface;
        rest = r.slice(f.surface.length).replace(/^[:\s]+/, "");
      } else {
        const idx = r.indexOf(":");
        if (idx > 0 && idx < 60) { src = r.slice(0, idx); rest = r.slice(idx + 1).trim(); }
      }
      const open = fid != null ? `data-open-id="${fid}" tabindex="0" role="button"` : "";
      return `<div class="risk-item ${fid != null ? "clickable" : ""}" ${open}>
        <span class="rank">${String(i + 1).padStart(2, "0")}</span>
        ${sev ? `<span class="risk-dot" style="background:${sevColor(sev)}" title="${esc(sev)}"></span>` : ""}
        <span class="txt">${src ? `<span class="src">${esc(src)}:</span> ` : ""}${esc(rest)}</span>
        ${fid != null ? `<span class="risk-go">${icon("arrow")}</span>` : ""}
      </div>`;
    }).join("");
    return `<div class="panel ov-panel">${head}<div class="ov-pad"><div class="risks-strip">${items}</div></div></div>`;
  }

  // best-effort: a top_risk line starts with the finding's surface ("Surface: reason")
  function resolveRiskFinding(r) {
    if (!r) return null;
    let best = null;
    FINDINGS.forEach((f) => {
      if (f.surface && r.startsWith(f.surface) && (!best || f.surface.length > best.surface.length)) best = f;
    });
    return best ? best._id : null;
  }

  /* ======================================================================== *
   * VALIDATE TAB  ·  the three paid bridges, deduped by sku
   * ======================================================================== */
  function validateHTML() {
    // de-dup by sku across all findings; preserve summary order if given
    const map = new Map();
    FINDINGS.forEach((f) => (f.bridges || []).forEach((b) => { if (b && b.sku && !map.has(b.sku)) map.set(b.sku, b); }));
    const order = (REPORT.summary && REPORT.summary.bridges_available) || [];
    const ordered = [];
    order.forEach((sku) => { if (map.has(sku)) { ordered.push(map.get(sku)); map.delete(sku); } });
    map.forEach((b) => ordered.push(b));

    if (!ordered.length) {
      return `<section class="tab-section reveal"><div class="empty-tab">
        <div class="big">No validation paths yet</div>
        <div>Bridges to runtime validation attach to findings as you discover AI and API surface.
        Nothing in this scan has a bridge.</div></div></section>`;
    }

    const cards = ordered.map((b) => {
      const n = FINDINGS.filter((f) => (f.bridges || []).some((x) => x.sku === b.sku)).length;
      return `
      <a class="bridge" href="${esc(b.url)}" target="_blank" rel="noopener noreferrer">
        <span class="sku">${esc(b.sku)}</span>
        <span class="lbl">${esc(b.label)}</span>
        <span class="cnt">${n} surface${n === 1 ? "" : "s"} route here</span>
        <span class="go">Open in APIsec ${icon("arrow")}</span>
      </a>`;
    }).join("");

    return `
      <section class="tab-section reveal">
        <div class="bridges-band">
          <div class="lead">
            <h3>Validate exploitability at runtime in APIsec</h3>
            <p>ai-surface maps what exists in your code. APIsec proves what's actually exploitable against your
               running system. These are the next steps for what we found here. Per-finding bridges also appear
               in each finding's drawer.</p>
          </div>
          <div class="bridge-grid">${cards}</div>
        </div>
      </section>`;
  }

  /* ======================================================================== *
   * FINDINGS TAB  ·  full inventory explorer (search + filter by cat/sev)
   * ======================================================================== */
  function findingsTabHTML() {
    const sevPresent = SEV_ORDER.filter((s) => FINDINGS.some((f) => f.severity === s));
    const cats = uniqueCats();

    const catFilters = [`<button class="filter-chip" data-cat="all" aria-pressed="${state.cat === "all"}">All categories <span class="n">${FINDINGS.length}</span></button>`]
      .concat(cats.map((c) => {
        const n = FINDINGS.filter((f) => f.category === c).length;
        return `<button class="filter-chip" data-cat="${esc(c)}" aria-pressed="${state.cat === c}">${esc(catMeta(c).label)} <span class="n">${n}</span></button>`;
      })).join("");

    const sevFilters = sevPresent.length ? (
      `<button class="filter-chip" data-sev="all" aria-pressed="${state.sev === "all"}">Any severity</button>` +
      sevPresent.map((s) => {
        const n = FINDINGS.filter((f) => f.severity === s).length;
        return `<button class="filter-chip" data-sev="${s}" aria-pressed="${state.sev === s}"><span class="swatch" style="background:var(--sev-${s})"></span>${s} <span class="n">${n}</span></button>`;
      }).join("")
    ) : "";

    return `
      <section class="tab-section reveal" id="explorer">
        <div class="explorer-controls">
          <label class="search">
            ${icon("search")}
            <input id="search" type="search" placeholder="Search surfaces, files, tools, paths&hellip;" autocomplete="off" />
          </label>
        </div>
        <div class="explorer-controls" style="margin-top:-8px;">
          <div class="filter-group" id="cat-filters">${catFilters}</div>
          ${sevFilters ? `<span style="width:1px;height:22px;background:var(--line);"></span><div class="filter-group" id="sev-filters">${sevFilters}</div>` : ""}
        </div>
        <div id="results"></div>
      </section>`;
  }

  /* ======================================================================== *
   * MCP AUDIT TAB  ·  the differentiator. A dedicated home for every audited
   * surface. Renders generically from finding.audit so future audited
   * categories (not just MCP) show here automatically.
   * ======================================================================== */
  function mcpAuditHTML() {
    const audited = FINDINGS.filter((f) => f.audit).sort((a, b) =>
      (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0));

    const intro = `
      <div class="mcp-intro">
        <div class="ic">${icon("shield")}</div>
        <div>
          <h3>Deep-dive audits</h3>
          <p>Discovery is severity-free. Severity comes only from this audit layer. Each audited surface
             (MCP servers, agents) is scored against the OWASP LLM Top 10, checked for secrets (names and
             types only, never values), risky tool/permission combinations, and source trust.</p>
        </div>
      </div>`;

    if (!audited.length) {
      return `<section class="tab-section reveal">${intro}
        <div class="empty-tab"><div class="big">Nothing audited in this scan</div>
        <div>No MCP servers (or other deep-divable surfaces) were found to assess.
        Inventoried surfaces stay severity-free by design.</div></div></section>`;
    }

    const cards = audited.map(mcpCardHTML).join("");
    return `<section class="tab-section reveal">${intro}<div class="mcp-grid">${cards}</div></section>`;
  }

  // Compact summary card. Full audit detail lives in the drawer (click to open).
  function mcpCardHTML(f) {
    const a = f.audit || {};
    const sev = f.severity;
    const sevTag = sev
      ? `<span class="sev-tag" style="--accent:${sevColor(sev)}">${esc(sev)}</span>`
      : `<span class="sev-tag none">audited</span>`;

    const tools = (f.permissions || ((f.evidence && f.evidence.metadata && f.evidence.metadata.tools)) || [])
      .slice(0, 6).map((t) => `<span class="perm">${esc(t)}</span>`).join("");

    const flagChips = (a.risk_flags || []).map((rf) =>
      `<span class="flag-chip" style="--accent:${sevColor(rf.severity)}">${esc(rf.flag)}</span>`).join("")
      || `<span class="sev-empty">No risk flags raised.</span>`;

    const meta = [];
    const ns = (a.secrets || []).length;
    if (ns) meta.push(`<span class="mcp-meta-chip">${ns} secret${ns === 1 ? "" : "s"}</span>`);
    if (a.trust_label) meta.push(`<span class="mcp-meta-chip">trust ${esc(a.trust_label)}</span>`);
    const owaspSet = [...new Set((a.risk_flags || []).flatMap((rf) => rf.owasp || []))];
    if (owaspSet.length) meta.push(`<span class="mcp-meta-chip">${esc(owaspSet.join(", "))}</span>`);

    return `
      <article class="mcp-card" data-open-id="${f._id}" tabindex="0" role="button">
        <div class="mcp-head">
          <span class="ic">${icon(catMeta(f.category).icon)}</span>
          <span class="title">${esc(f.surface)}</span>
          ${sevTag}
        </div>
        ${tools ? `<div class="mcp-tools tag-list">${tools}</div>` : ""}
        <div class="mcp-flagchips">${flagChips}</div>
        ${meta.length ? `<div class="mcp-metarow">${meta.join("")}</div>` : ""}
        <div class="mcp-foot"><span class="open">Open full detail ${icon("arrow")}</span></div>
      </article>`;
  }

  function uniqueCats() {
    const present = [...new Set(FINDINGS.map((f) => f.category))];
    present.sort((a, b) => {
      const ia = CAT_ORDER.indexOf(a), ib = CAT_ORDER.indexOf(b);
      return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
    });
    return present;
  }

  function wireExplorer() {
    const search = $("#search");
    if (search) {
      if (state.q) search.value = state.q;
      search.addEventListener("input", (e) => { state.q = e.target.value.trim().toLowerCase(); applyFilters(); });
    }
    document.querySelectorAll("#cat-filters .filter-chip").forEach((b) =>
      b.addEventListener("click", () => { state.cat = b.dataset.cat; syncFilterUI(); applyFilters(); }));
    document.querySelectorAll("#sev-filters .filter-chip").forEach((b) =>
      b.addEventListener("click", () => { state.sev = b.dataset.sev; syncFilterUI(); applyFilters(); }));
    applyFilters();
  }
  function syncFilterUI() {
    document.querySelectorAll("#cat-filters .filter-chip").forEach((b) =>
      b.setAttribute("aria-pressed", String(b.dataset.cat === state.cat)));
    document.querySelectorAll("#sev-filters .filter-chip").forEach((b) =>
      b.setAttribute("aria-pressed", String(b.dataset.sev === state.sev)));
  }

  function matches(f) {
    if (state.cat !== "all" && f.category !== state.cat) return false;
    if (state.sev !== "all" && f.severity !== state.sev) return false;
    if (state.q) {
      const hay = JSON.stringify([
        f.surface, f.category, f.permissions, f.risk_indicators,
        f.evidence && f.evidence.files, f.evidence && f.evidence.snippet,
        f.evidence && f.evidence.metadata,
        f.audit && f.audit.owasp_mappings,
        f.audit && (f.audit.risk_flags || []).map((x) => [x.flag, x.description]),
      ]).toLowerCase();
      if (!hay.includes(state.q)) return false;
    }
    return true;
  }

  function applyFilters() {
    const root = $("#results");
    if (!root) return;
    const shown = FINDINGS.filter(matches);

    if (!shown.length) {
      root.innerHTML = `<div class="no-results">
        <div class="big">No matching surfaces</div>
        <div>Try clearing the search or filters.</div></div>`;
      return;
    }

    const byCat = {};
    shown.forEach((f) => { (byCat[f.category] = byCat[f.category] || []).push(f); });
    const cats = Object.keys(byCat).sort((a, b) => {
      const ia = CAT_ORDER.indexOf(a), ib = CAT_ORDER.indexOf(b);
      return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
    });

    root.innerHTML = cats.map((c) => groupHTML(c, byCat[c])).join("");

    // wire group toggles (collapsed by default; click/Enter to drill in)
    root.querySelectorAll(".cat-group-head").forEach((h) => {
      const toggle = () => {
        const grp = h.closest(".cat-group");
        const next = grp.dataset.open === "false" ? "true" : "false";
        grp.dataset.open = next;
        h.setAttribute("aria-expanded", next);
      };
      h.addEventListener("click", toggle);
      h.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
    });
    // wire card -> drawer
    root.querySelectorAll(".card").forEach((c) => {
      c.addEventListener("click", (e) => {
        if (e.target.closest("a")) return;
        openDrawer(Number(c.dataset.id));
      });
    });
    // API table rows open the same drawer
    root.querySelectorAll(".api-row").forEach((r) => {
      const open = () => openDrawer(Number(r.dataset.openId));
      r.addEventListener("click", open);
      r.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); } });
    });
  }

  function groupHTML(cat, items) {
    const m = catMeta(cat);
    const assessed = items.filter((f) => f.severity).length;
    // Collapsed by default so the list is scannable. Open only the focused
    // category, so a node/bubble click lands on that section already expanded.
    const open = state.cat !== "all" && state.cat === cat;
    return `
      <div class="cat-group" data-open="${open ? "true" : "false"}">
        <div class="cat-group-head" role="button" tabindex="0" aria-expanded="${open ? "true" : "false"}">
          <span class="ic">${icon(m.icon)}</span>
          <span class="meta"><b>${esc(m.label)}</b><span class="d">${esc(m.desc)}</span></span>
          ${assessed ? `<span class="count" title="${assessed} assessed">${assessed} assessed</span>` : ""}
          <span class="count">${items.length}</span>
          <span class="caret">${icon("caret")}</span>
        </div>
        ${cat === "api"
          ? apiTableHTML(items)
          : `<div class="cards">${items.map(cardHTML).join("")}</div>`}
      </div>`;
  }

  // APIs are tabular and high-volume: a dense table scales to hundreds of
  // endpoints where cards do not. Rows open the same drawer.
  function apiTableHTML(items) {
    const meth = (m) => {
      const v = String(m || "*");
      const cls = ["GET", "POST", "PUT", "PATCH", "DELETE"].includes(v.toUpperCase()) ? v.toLowerCase() : "any";
      return `<span class="chip method ${cls}">${esc(v)}</span>`;
    };
    const rows = items.map((f) => {
      const md = (f.evidence && f.evidence.metadata) || {};
      const path = md.path || f.surface;
      const bola = (f.risk_indicators || []).some((r) => /bola/i.test(r));
      return `<tr class="api-row" data-open-id="${f._id}" tabindex="0" role="button">
        <td class="c-meth">${meth(md.method)}</td>
        <td class="c-path mono">${esc(path)}</td>
        <td class="c-auth">${esc(md.auth || "·")}</td>
        <td class="c-fw">${esc(md.framework || "·")}</td>
        <td class="c-risk">${bola ? `<span class="bola-dot">BOLA candidate</span>` : `<span class="t3">·</span>`}</td>
        <td class="c-go">${icon("arrow")}</td>
      </tr>`;
    }).join("");
    return `<div class="api-table-wrap"><table class="api-table">
      <thead><tr><th>Method</th><th>Path</th><th>Auth</th><th>Framework</th><th>Risk</th><th></th></tr></thead>
      <tbody>${rows}</tbody></table></div>`;
  }

  function cardHTML(f) {
    const sev = f.severity;
    const accent = sevColor(sev);
    const sevTag = sev
      ? `<span class="sev-tag" style="--accent:${accent}">${sev}</span>`
      : `<span class="sev-tag none">inventoried</span>`;

    const chips = cardChips(f);
    const files = (f.evidence && f.evidence.files) || [];
    const fileChips = files.slice(0, 3).map((fp) =>
      `<span class="file">${icon("file")}${esc(fp)}</span>`).join("") +
      (files.length > 3 ? `<span class="file">+${files.length - 3} more</span>` : "");

    // foot: audit flag dots or risk indicator count
    let foot = "";
    if (f.audit && (f.audit.risk_flags || []).length) {
      const dots = (f.audit.risk_flags || []).map((rf) =>
        `<span class="b" style="background:${sevColor(rf.severity)}"></span>`).join("");
      foot = `<span class="flags">${dots}${f.audit.risk_flags.length} risk flag${f.audit.risk_flags.length === 1 ? "" : "s"}</span>`;
    } else if ((f.risk_indicators || []).length) {
      foot = `<span class="flags">${f.risk_indicators.length} risk indicator${f.risk_indicators.length === 1 ? "" : "s"}</span>`;
    } else {
      foot = `<span class="flags">inventory record</span>`;
    }

    return `
      <article class="card" data-id="${f._id}" style="--accent:${accent}" tabindex="0">
        <div class="card-head">
          <span class="title">${esc(f.surface)}</span>
          ${sevTag}
        </div>
        ${chips ? `<div class="chips">${chips}</div>` : ""}
        ${fileChips ? `<div class="files">${fileChips}</div>` : ""}
        <div class="card-foot">
          ${foot}
          <span class="open">Inspect ${icon("arrow")}</span>
        </div>
      </article>`;
  }

  // category-aware chips (generic fallback included)
  function cardChips(f) {
    const md = (f.evidence && f.evidence.metadata) || {};
    const out = [];
    if (f.category === "api") {
      if (md.method) {
        const meth = String(md.method);
        const cls = ["GET", "POST", "PUT", "PATCH", "DELETE"].includes(meth.toUpperCase())
          ? meth.toLowerCase() : "any";
        out.push(`<span class="chip method ${cls}">${esc(meth)}</span>`);
      }
      if (md.path) out.push(`<span class="chip path">${esc(md.path)}</span>`);
      if (md.framework) out.push(`<span class="chip"><b>framework</b> ${esc(md.framework)}</span>`);
      if (md.auth) out.push(`<span class="chip"><b>auth</b> ${esc(md.auth)}</span>`);
      if (md.source_spec) out.push(`<span class="chip mono">${esc(md.source_spec)}</span>`);
      if ((f.risk_indicators || []).some((r) => /bola/i.test(r))) out.push(`<span class="chip bola">BOLA candidate</span>`);
    } else if (f.category === "llm-sdk") {
      if (md.model) out.push(`<span class="chip"><b>model</b> ${esc(md.model)}</span>`);
      if (md.non_literal_input) out.push(`<span class="chip">non-literal input</span>`);
      (f.permissions || []).slice(0, 2).forEach((p) => out.push(`<span class="chip mono">${esc(p)}</span>`));
    } else if (f.category === "mcp-server" || f.category === "agent-framework") {
      const tools = (md.tools || f.permissions || []);
      tools.slice(0, 4).forEach((t) => out.push(`<span class="chip mono">${esc(t)}</span>`));
      if (tools.length > 4) out.push(`<span class="chip">+${tools.length - 4}</span>`);
      if (f.audit && (f.audit.owasp_mappings || []).length) {
        [...new Set(f.audit.owasp_mappings)].slice(0, 3).forEach((o) =>
          out.push(owaspChip(o)));
      }
    } else {
      // generic fallback: surface a few metadata key/values, then permissions
      Object.entries(md).slice(0, 3).forEach(([k, v]) => {
        if (v == null || typeof v === "object") return;
        out.push(`<span class="chip"><b>${esc(k)}</b> ${esc(v)}</span>`);
      });
      (f.permissions || []).slice(0, 2).forEach((p) => out.push(`<span class="chip mono">${esc(p)}</span>`));
    }
    return out.join("");
  }

  function owaspChip(code) {
    const name = OWASP[code] || "OWASP LLM";
    return `<span class="chip owasp" data-tip="${esc(code)}|${esc(name)}">${esc(code)}</span>`;
  }

  /* ======================================================================== *
   * DRAWER (finding inspector)
   * ======================================================================== */
  function wireDrawer() {
    const drawer = $("#drawer");
    drawer.querySelectorAll("[data-close]").forEach((e) => e.addEventListener("click", closeDrawer));
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });
  }

  function openDrawer(id) {
    const f = FINDINGS.find((x) => x._id === id);
    if (!f) return;
    const drawer = $("#drawer");
    const panel = $(".drawer-panel", drawer);
    panel.innerHTML = drawerHTML(f);
    panel.scrollTop = 0;
    drawer.setAttribute("aria-hidden", "false");
    $(".dr-close", panel).addEventListener("click", closeDrawer);
    document.body.style.overflow = "hidden";
    // highlight matching node in the map
    document.querySelectorAll(".node-leaf.active").forEach((n) => n.classList.remove("active"));
    const mn = document.querySelector(`.node-leaf[data-id="${id}"]`);
    if (mn) mn.classList.add("active");
  }
  function closeDrawer() {
    const drawer = $("#drawer");
    if (drawer.getAttribute("aria-hidden") === "true") return;
    drawer.setAttribute("aria-hidden", "true");
    document.body.style.overflow = "";
    document.querySelectorAll(".node-leaf.active").forEach((n) => n.classList.remove("active"));
  }

  function drawerHTML(f) {
    const m = catMeta(f.category);
    const sev = f.severity;
    const sevTag = sev
      ? `<span class="sev-tag" style="--accent:${sevColor(sev)}">${sev}</span>`
      : `<span class="sev-tag none">inventoried</span>`;
    const dispTag = f.disposition === "resolve-here"
      ? `<span class="disp-pill resolve">resolve here</span>`
      : f.disposition === "validate-runtime"
      ? `<span class="disp-pill validate">validate at runtime</span>` : "";

    const ev = f.evidence || {};
    const md = ev.metadata || {};
    const a = f.audit;

    /* ---- 1 - INFORMATION: what this is (humanized, no internal plumbing) ---- */
    // Internal/plumbing keys the user does not need to see, plus keys rendered
    // elsewhere (tools -> Capabilities, reaches/models -> their own sub-sections).
    const META_HIDE = new Set(["server_name", "config_keys", "tools", "source", "reaches", "models"]);
    const META_LABELS = {
      server_type: "Connection", mcp_source: "Package", method: "Method",
      path: "Route", framework: "Framework", auth: "Auth", source_spec: "Spec file",
      model: "Model", non_literal_input: "Dynamic input",
    };
    const CONN = { remote: "remote endpoint", npm: "npm package", node: "Node script",
                   python: "Python module", docker: "Docker image", local: "local binary", unknown: "unknown" };
    const metaVal = (k, v) => {
      if (k === "server_type") return CONN[v] || v;
      if (k === "non_literal_input") return v ? "yes" : "no";
      return Array.isArray(v) ? v.join(", ") : String(v);
    };
    const kv = [`<dt>Type</dt><dd>${esc(catMeta(f.category).label)}</dd>`];
    Object.entries(md).forEach(([k, v]) => {
      if (META_HIDE.has(k) || v == null || v === "" || typeof v === "object") return;
      kv.push(`<dt>${esc(META_LABELS[k] || titleCase(k))}</dt><dd>${esc(metaVal(k, v))}</dd>`);
    });
    const lineSuffix = (ev.line_numbers && ev.line_numbers.length) ? ":" + ev.line_numbers[0] : "";
    const files = (ev.files || []).map((fp, i) =>
      `<span class="perm">${esc(fp)}${i === 0 ? esc(lineSuffix) : ""}</span>`).join("");
    const snippet = ev.snippet ? `<div class="snippet">${esc(ev.snippet)}</div>` : "";
    const perms = (f.permissions || []).map((p) => `<span class="perm">${esc(p)}</span>`).join("");
    let info = `<dl class="kv">${kv.join("")}</dl>`;
    if (files || snippet) info += `<div class="dr-sub">Evidence</div>${files ? `<div class="tag-list">${files}</div>` : ""}${snippet}`;
    if (perms) info += `<div class="dr-sub">Permissions / capabilities</div><div class="tag-list">${perms}</div>`;
    const reaches = md.reaches || [];
    if (reaches.length) info += `<div class="dr-sub">Reaches (APIs / services)</div><div class="tag-list">${
      reaches.map((r) => `<span class="perm" title="${esc(r.source_key || "")}">${esc(r.category)}: ${esc(r.url)}</span>`).join("")}</div>`;
    const models = md.models || [];
    if (models.length) info += `<div class="dr-sub">Models used</div><div class="tag-list">${
      models.map((mm) => `<span class="perm">${esc(mm)}</span>`).join("")}</div>`;

    /* ---- 2 - RISKS: what's wrong (no fixes here) ---- */
    const ris = (f.risk_indicators || []).map((r) => `<span class="ri">${esc(r)}</span>`).join("");
    let risks = "";
    if (ris) risks += `<div class="tag-list">${ris}</div>`;
    if (a && (a.risk_flags || []).length) risks += auditFlagsHTML(a.risk_flags);
    if (a && (a.secrets || []).length) risks += secretsHTML(a.secrets);
    const trust = a ? trustHTML(a) : "";
    if (trust) risks += `<div class="dr-sub">Source trust</div>${trust}`;
    if (!risks) risks = `<div class="secret-note">${icon("info")}<span>Inventoried, not assessed for risk. Severity comes from the deep-dive audit layer (MCP servers and agents, plus approval-gate and observability checks).</span></div>`;

    /* ---- 3 - REMEDIATION: the fixes, pulled together ---- */
    const rem = [];
    if (a) (a.risk_flags || []).forEach((rf) => { if (rf.remediation) rem.push(`<li><b>${esc(flagLabel(rf.flag))}</b> ${esc(rf.remediation)}</li>`); });
    if (a) (a.secrets || []).forEach((s) => rem.push(`<li><b>${esc(s.name)}</b> Move to a secrets manager and rotate; reference by name only.</li>`));
    const remediation = rem.length
      ? `<ul class="rem-list">${rem.join("")}</ul>`
      : `<div class="secret-note">${icon("info")}<span>No code-level remediation items.${f.disposition === "validate-runtime" ? " Exploitability is proven at runtime, see below." : ""}</span></div>`;

    /* ---- 4 - VALIDATE AT RUNTIME: the CTA ----
       Only surfaces the platform validates today (status "live", i.e. API) get
       a working CTA. The rest are shown disabled: the platform does not run
       runtime tests for them yet, so there is no live destination to link to.
       Their label already reads "Coming soon ...". */
    const bridges = (f.bridges || []).map((b) =>
      b.status === "live"
        ? `<a class="dr-bridge" href="${esc(b.url)}" target="_blank" rel="noopener noreferrer">
        <span class="lbl">${esc(b.label)} ${icon("arrow", "")}</span>
      </a>`
        : `<div class="dr-bridge disabled" aria-disabled="true">
        <span class="lbl">${esc(b.label)}</span>
      </div>`
    ).join("");
    let validate;
    let stPill = "";
    if (f.disposition === "validate-runtime") {
      const st = f.runtime_status === "live" ? "live" : (f.runtime_status === "coming" ? "coming soon" : "");
      stPill = st ? `<span class="rt-status ${esc(f.runtime_status)}">${st}</span>` : "";
      const q = f.runtime_question
        ? `<div class="rt-q">${icon("info")}<span><b>Only runtime can answer:</b> ${esc(f.runtime_question)}</span></div>` : "";
      validate = `${q}${bridges}`;
    } else if (f.disposition === "resolve-here") {
      validate = `<div class="secret-note">${icon("info")}<span>Resolvable in code: fix it in place (above). No runtime validation needed for this surface.</span></div>`;
    } else {
      validate = bridges || `<div class="secret-note">${icon("info")}<span>No runtime validation journey for this surface.</span></div>`;
    }

    const sec = (n, title, extra, body) => `
      <section class="dr-sec">
        <div class="dr-sec-h"><span class="dr-sec-n">${n}</span>${title}${extra || ""}</div>
        <div class="dr-sec-body">${body}</div>
      </section>`;

    return `
      <div class="dr-head">
        <button class="dr-close" aria-label="Close">${icon("close")}</button>
        <div class="ey"><span class="ic" style="color:var(--brand-2)">${icon(m.icon)}</span>
          <span class="cat">${esc(m.label)}</span>${sevTag}${dispTag}</div>
        <h3>${esc(f.surface)}</h3>
      </div>
      <div class="dr-body">
        <div class="dr-col">
          ${sec("1", "Information", "", info)}
          ${sec("2", "Risks", "", risks)}
        </div>
        <div class="dr-col">
          ${sec("3", "Remediation", "", remediation)}
          ${sec("4", "Validate at runtime", stPill, validate)}
        </div>
      </div>`;
  }

  // Audit risk flags WITHOUT remediation (remediation lives in its own section).
  function auditFlagsHTML(flags) {
    return flags.map((rf) => {
      const owasp = (rf.owasp || []).map(owaspChip).join("");
      const stds = (rf.standards || []).map(stdChip).join("");
      const badges = owasp + stds;
      return `
        <div class="flag">
          <div class="flag-top">
            <span class="sev-tag" style="--accent:${sevColor(rf.severity)}">${esc(rf.severity || "info")}</span>
            <span class="fid">${esc(flagLabel(rf.flag))}</span>
          </div>
          <div class="flag-body">
            ${rf.description ? `<p class="desc">${esc(rf.description)}</p>` : ""}
            ${badges ? `<div class="badge-row">${badges}</div>` : ""}
          </div>
        </div>`;
    }).join("");
  }

  const flagLabel = (f) => FLAG_LABELS[f] || titleCase(f);

  // Governance-standard badge (EU AI Act / NIST / ISO) next to OWASP badges.
  function stdChip(s) {
    const fw = s.framework || "";
    const clause = s.clause || "";
    const cls = s.framework_id ? `std-${s.framework_id}` : "";
    const name = FW_DESC[s.framework_id] || fw;
    return `<span class="chip std ${cls}" data-tip="${esc(fw + " · " + clause)}|${esc(name)}">${esc(fw)} ${esc(clause)}</span>`;
  }

  function secretsHTML(secrets) {
    const rows = secrets.map((s) => `
      <div class="secret-row">
        <span class="lock">${icon("lock")}</span>
        <span style="flex:1">
          <span class="sname">${esc(s.name)}</span>
          <span class="smeta">${esc(s.secret_type || "secret")}${s.confidence ? " &middot; " + esc(s.confidence) + " confidence" : ""}${s.location ? " &middot; " + esc(s.location) : ""}</span>
        </span>
        ${s.severity ? `<span class="sev-tag" style="--accent:${sevColor(s.severity)}">${esc(s.severity)}</span>` : ""}
      </div>`).join("");
    return `<div class="dr-sub">Detected secrets <span class="ct">${secrets.length}</span></div>${rows}
      <div class="secret-note">${icon("lock")}<span>Names and types only. ai-surface never reads or stores a secret value.</span></div>`;
  }

  function trustHTML(a) {
    const t = [];
    if (a.trust_label) {
      const cls = a.trust_label === "verified" ? "verified" : a.trust_label === "unknown" ? "unknown" : "";
      t.push(`<span class="trust-badge ${cls}">trust <b>${esc(a.trust_label)}</b></span>`);
    }
    if (a.trust_score != null) t.push(`<span class="trust-badge">score <b>${esc(a.trust_score)}</b></span>`);
    if (a.registry_match) t.push(`<span class="trust-badge">registry <b>${esc(a.registry_match)}</b></span>`);
    return t.length ? `<div class="trust-row">${t.join("")}</div>` : "";
  }

  /* ======================================================================== *
   * OWASP TOOLTIPS
   * ======================================================================== */
  function wireTooltips() {
    let tip = $(".tip");
    if (!tip) { tip = document.createElement("div"); tip.className = "tip"; document.body.appendChild(tip); }
    const show = (el) => {
      const data = el.getAttribute("data-tip");
      if (!data) return;
      const [code, name] = data.split("|");
      tip.innerHTML = `<span class="t">${esc(code)}</span>${esc(name)}`;
      const r = el.getBoundingClientRect();
      tip.style.left = Math.min(window.innerWidth - 290, r.left) + "px";
      tip.style.top = (r.bottom + 8) + "px";
      tip.classList.add("show");
    };
    const hide = () => tip.classList.remove("show");
    document.addEventListener("mouseover", (e) => {
      const el = e.target.closest("[data-tip]");
      if (el) show(el);
    });
    document.addEventListener("mouseout", (e) => {
      if (e.target.closest("[data-tip]")) hide();
    });
  }

  /* ======================================================================== *
   * ERRORS + FOOTER
   * ======================================================================== */
  function errorsHTML() {
    const errs = REPORT.errors || [];
    if (!errs.length) return "";
    return `
      <section class="errors-banner">
        <h4>${icon("warn")} ${errs.length} non-fatal detector ${errs.length === 1 ? "note" : "notes"}</h4>
        <ul>${errs.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>
      </section>`;
  }

  function footerHTML(minimal) {
    if (minimal || !REPORT) {
      return `
        <footer>
          <div class="row"><b>Privacy</b> ai-surface runs locally and fully offline. Secrets are reported by name and type only: no value is ever read.</div>
          <div class="row"><b>Scope</b> Discovery and code-level audit only. Runtime exploitability is the paid APIsec platform; this free tool routes to it via bridges.</div>
          <div class="row" style="margin-top:6px;color:var(--text-3)">ai-surface by APIsec</div>
        </footer>`;
    }
    const detectors = (REPORT.detectors_run || []).map((d) => `<span class="chip-mono">${esc(d)}</span>`).join(" ");
    return `
      <footer>
        <div class="row"><b>Privacy</b> ai-surface runs locally and fully offline. Secrets are reported by name and type only: no value is ever read into the report.</div>
        <div class="row"><b>Scope</b> Discovery and code-level audit only. Runtime exploitability is the paid APIsec platform; this free tool routes to it via the Validate bridges.</div>
        ${detectors ? `<div class="row" style="margin-top:6px;"><b>Detectors run</b> ${detectors}</div>` : ""}
        <div class="row" style="margin-top:6px;color:var(--text-3)">schema ${esc(REPORT.schema_version || "1.0")} &middot; ai-surface by APIsec</div>
      </footer>`;
  }

  /* ---- misc --------------------------------------------------------------- */
  function fmtDate(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    if (isNaN(d.getTime())) return "";
    try {
      return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
    } catch (_) { return iso.slice(0, 10); }
  }
})();
