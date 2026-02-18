/**
 * vibe-sec Telemetry Worker (Cloudflare Workers + D1)
 *
 * Endpoints:
 *   POST /v1/event            — Ingest an event
 *   GET  /public/stats        — Aggregated statistics (JSON, cached 1h)
 *   GET  /public/events?page= — Paginated raw events (JSON)
 *   GET  /telemetry-row       — Human-readable stats page (HTML)
 *   GET  /health              — Health check
 */

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS });
    }

    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/v1/event") {
      return handleIngest(request, env);
    }
    if (request.method === "GET" && url.pathname === "/public/stats") {
      return handleStats(request, env);
    }
    if (request.method === "GET" && url.pathname === "/public/events") {
      return handleEvents(request, env);
    }
    if (request.method === "GET" && url.pathname === "/telemetry-row") {
      return handleTelemetryRow(request, env);
    }
    if (url.pathname === "/health") {
      return json({ ok: true });
    }

    return new Response("Not found", { status: 404 });
  },
};

// ─── Ingest ───────────────────────────────────────────────────────────────────

async function handleIngest(request, env) {
  let body;
  try { body = await request.json(); }
  catch { return json({ error: "invalid json" }, 400); }

  const { event, device_id, version, os_version, node_version, ts } = body;
  if (!event || typeof event !== "string" || event.length > 60) {
    return json({ error: "invalid event" }, 400);
  }
  if (!device_id || !/^[0-9a-f-]{36}$/.test(device_id)) {
    return json({ error: "invalid device_id" }, 400);
  }

  // Rate limiting: max 10 events/device/hour
  if (env.TELEMETRY_RL) {
    const rlKey = `rl:${device_id}`;
    const count = parseInt(await env.TELEMETRY_RL.get(rlKey) || "0");
    if (count >= 10) return json({ error: "rate limited" }, 429);
    await env.TELEMETRY_RL.put(rlKey, String(count + 1), { expirationTtl: 3600 });
  }

  const ALLOWED_EVENTS = new Set([
    "setup_complete", "scan_complete", "block_triggered",
    "report_opened", "allow_added", "uninstall",
  ]);
  if (!ALLOWED_EVENTS.has(event)) return json({ error: "unknown event" }, 400);

  const row = {
    ts:               sanitizeStr(ts || new Date().toISOString(), 30),
    event,
    device_id,
    version:          sanitizeStr(version, 20),
    os_version:       sanitizeStr(os_version, 20),
    node_version:     sanitizeStr(node_version, 20),
    // scan_complete
    findings_total:   safeInt(body.findings_total),
    findings_critical:safeInt(body.findings_critical),
    findings_high:    safeInt(body.findings_high),
    findings_medium:  safeInt(body.findings_medium),
    finding_types:    safeJsonArr(body.finding_types, 50),
    scan_source:      sanitizeStr(body.source, 10),
    skipped:          safeJsonArr(body.skipped, 10),
    // block_triggered
    block_level:      sanitizeStr(body.block_level, 5),
    block_type:       sanitizeStr(body.block_type, 30),
    tool:             sanitizeStr(body.tool, 10),
    cmd_len:          sanitizeStr(body.cmd_len, 5),
    interpreter:      sanitizeStr(body.interpreter, 20),
    // setup_complete
    daemon_installed: body.daemon_installed === true ? 1 : body.daemon_installed === false ? 0 : null,
    gemini_configured:body.gemini_configured === true ? 1 : body.gemini_configured === false ? 0 : null,
    ai_tools:         safeJsonObj(body.ai_tools),
  };

  await env.TELEMETRY_DB.prepare(`
    INSERT INTO events (
      ts, event, device_id, version, os_version, node_version,
      findings_total, findings_critical, findings_high, findings_medium, finding_types,
      scan_source, skipped,
      block_level, block_type, tool, cmd_len, interpreter,
      daemon_installed, gemini_configured, ai_tools
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
  `).bind(
    row.ts, row.event, row.device_id, row.version, row.os_version, row.node_version,
    row.findings_total, row.findings_critical, row.findings_high, row.findings_medium, row.finding_types,
    row.scan_source, row.skipped,
    row.block_level, row.block_type, row.tool, row.cmd_len, row.interpreter,
    row.daemon_installed, row.gemini_configured, row.ai_tools,
  ).run();

  return json({ ok: true });
}

// ─── Public stats (JSON, cached 1h) ──────────────────────────────────────────

async function handleStats(request, env) {
  const cacheKey = new Request("https://cache.internal/stats");
  const cache = caches.default;
  const cached = await cache.match(cacheKey);
  if (cached) return addCors(cached);

  const stats = await fetchStats(env);
  const response = json(stats);
  response.headers.set("Cache-Control", "public, max-age=3600");
  await cache.put(cacheKey, response.clone());
  return addCors(response);
}

async function fetchStats(env) {
  const [
    totals, byEvent, topFindings, topBlocks, topInterpreters,
    scanSources, recentVersions, aiTools, dailyActive,
  ] = await Promise.all([
    env.TELEMETRY_DB.prepare(`
      SELECT COUNT(*) as total_events, COUNT(DISTINCT device_id) as unique_devices
      FROM events
    `).first(),

    env.TELEMETRY_DB.prepare(`
      SELECT event, COUNT(*) as count FROM events
      GROUP BY event ORDER BY count DESC
    `).all(),

    env.TELEMETRY_DB.prepare(`
      SELECT value as finding_type, COUNT(*) as occurrences
      FROM events, json_each(events.finding_types)
      WHERE event = 'scan_complete' AND finding_types IS NOT NULL
      GROUP BY value ORDER BY occurrences DESC LIMIT 20
    `).all(),

    env.TELEMETRY_DB.prepare(`
      SELECT block_type, block_level, COUNT(*) as count
      FROM events WHERE event = 'block_triggered'
      GROUP BY block_type, block_level ORDER BY count DESC LIMIT 20
    `).all(),

    env.TELEMETRY_DB.prepare(`
      SELECT interpreter, COUNT(*) as count
      FROM events WHERE event = 'block_triggered' AND interpreter IS NOT NULL
      GROUP BY interpreter ORDER BY count DESC LIMIT 15
    `).all(),

    env.TELEMETRY_DB.prepare(`
      SELECT scan_source, COUNT(*) as count
      FROM events WHERE event = 'scan_complete' AND scan_source IS NOT NULL
      GROUP BY scan_source ORDER BY count DESC
    `).all(),

    env.TELEMETRY_DB.prepare(`
      SELECT version, COUNT(DISTINCT device_id) as devices
      FROM events WHERE version IS NOT NULL
      GROUP BY version ORDER BY devices DESC LIMIT 10
    `).all(),

    env.TELEMETRY_DB.prepare(`
      SELECT ai_tools FROM events
      WHERE event = 'setup_complete' AND ai_tools IS NOT NULL
      ORDER BY rowid DESC LIMIT 1000
    `).all(),

    env.TELEMETRY_DB.prepare(`
      SELECT substr(ts, 1, 10) as day, COUNT(DISTINCT device_id) as devices
      FROM events WHERE ts >= datetime('now', '-30 days')
      GROUP BY day ORDER BY day DESC
    `).all(),
  ]);

  const toolCounts = {};
  for (const row of (aiTools.results || [])) {
    try {
      const tools = JSON.parse(row.ai_tools);
      for (const [k, v] of Object.entries(tools)) {
        if (v === true) toolCounts[k] = (toolCounts[k] || 0) + 1;
      }
    } catch {}
  }

  return {
    generated_at:    new Date().toISOString(),
    totals,
    events_by_type:  byEvent.results,
    top_findings:    topFindings.results,
    top_blocks:      topBlocks.results,
    top_interpreters:topInterpreters.results,
    scan_sources:    scanSources.results,
    versions:        recentVersions.results,
    ai_tools:        toolCounts,
    daily_active:    dailyActive.results,
  };
}

// ─── /telemetry-row — human-readable HTML stats ───────────────────────────────

async function handleTelemetryRow(request, env) {
  const stats = await fetchStats(env);

  const bar = (count, max, width = 24) => {
    const filled = max > 0 ? Math.round((count / max) * width) : 0;
    return "█".repeat(filled) + "░".repeat(width - filled);
  };

  const rows = (arr, keyFn, valFn, label) => {
    if (!arr || arr.length === 0) return `<tr><td colspan="3" class="empty">no data yet</td></tr>`;
    const max = valFn(arr[0]);
    return arr.map(r => `
      <tr>
        <td class="key">${esc(keyFn(r))}</td>
        <td class="chart">${bar(valFn(r), max)}</td>
        <td class="val">${valFn(r)}</td>
      </tr>`).join("");
  };

  const dailyRows = (stats.daily_active || []).slice(0, 14).map(r => `
    <tr>
      <td class="key">${esc(r.day)}</td>
      <td class="chart">${bar(r.devices, Math.max(...(stats.daily_active || []).map(x => x.devices)))}</td>
      <td class="val">${r.devices}</td>
    </tr>`).join("");

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>vibe-sec / telemetry</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0a0a0a; color: #c8c8c8; font-family: 'SF Mono', 'Fira Code', monospace; font-size: 13px; padding: 32px 24px; max-width: 860px; margin: 0 auto; }
  h1 { color: #fff; font-size: 1.1rem; font-weight: 600; letter-spacing: .5px; margin-bottom: 4px; }
  .subtitle { color: #555; font-size: .8rem; margin-bottom: 36px; }
  .subtitle a { color: #555; text-decoration: none; }
  .subtitle a:hover { color: #888; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 12px; margin-bottom: 36px; }
  .card { background: #111; border: 1px solid #1e1e1e; border-radius: 6px; padding: 14px 16px; }
  .card-label { color: #555; font-size: .72rem; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px; }
  .card-value { color: #e0e0e0; font-size: 1.6rem; font-weight: 700; }
  h2 { color: #888; font-size: .72rem; text-transform: uppercase; letter-spacing: 1.5px; margin: 28px 0 10px; border-bottom: 1px solid #1a1a1a; padding-bottom: 6px; }
  table { width: 100%; border-collapse: collapse; }
  td { padding: 4px 8px 4px 0; vertical-align: middle; }
  td.key { color: #aaa; min-width: 160px; white-space: nowrap; }
  td.chart { color: #2563eb; letter-spacing: -1px; font-size: .8rem; padding-right: 10px; }
  td.val { color: #e0e0e0; text-align: right; min-width: 44px; }
  td.empty { color: #333; padding: 8px 0; }
  .ts { color: #333; font-size: .72rem; margin-top: 40px; }
</style>
</head>
<body>

<h1>vibe-sec / telemetry</h1>
<p class="subtitle">
  anonymous usage data — all public •
  <a href="https://github.com/kobzevvv/vibe-sec" target="_blank">github.com/kobzevvv/vibe-sec</a>
</p>

<div class="grid">
  <div class="card">
    <div class="card-label">total events</div>
    <div class="card-value">${stats.totals?.total_events ?? 0}</div>
  </div>
  <div class="card">
    <div class="card-label">unique devices</div>
    <div class="card-value">${stats.totals?.unique_devices ?? 0}</div>
  </div>
  <div class="card">
    <div class="card-label">scans run</div>
    <div class="card-value">${(stats.events_by_type || []).find(e => e.event === "scan_complete")?.count ?? 0}</div>
  </div>
  <div class="card">
    <div class="card-label">attacks blocked</div>
    <div class="card-value">${(stats.events_by_type || []).find(e => e.event === "block_triggered")?.count ?? 0}</div>
  </div>
</div>

<h2>events by type</h2>
<table>${rows(stats.events_by_type, r => r.event, r => r.count)}</table>

<h2>most common findings</h2>
<table>${rows(stats.top_findings, r => r.finding_type, r => r.occurrences)}</table>

<h2>attacks blocked — by type</h2>
<table>${rows(stats.top_blocks, r => r.block_type + (r.block_level ? "  (" + r.block_level + ")" : ""), r => r.count)}</table>

<h2>blocked commands — interpreter</h2>
<table>${rows(stats.top_interpreters, r => r.interpreter, r => r.count)}</table>

<h2>scan source</h2>
<table>${rows(stats.scan_sources, r => r.scan_source, r => r.count)}</table>

<h2>version distribution</h2>
<table>${rows(stats.versions, r => "v" + (r.version || "?"), r => r.devices)}</table>

<h2>daily active devices — last 14 days</h2>
<table>${dailyRows || '<tr><td class="empty" colspan="3">no data yet</td></tr>'}</table>

<p class="ts">generated ${stats.generated_at}</p>

</body>
</html>`;

  return new Response(html, {
    headers: { ...CORS, "Content-Type": "text/html; charset=utf-8", "Cache-Control": "public, max-age=300" },
  });
}

// ─── Public events (paginated) ────────────────────────────────────────────────

async function handleEvents(request, env) {
  const url = new URL(request.url);
  const page = Math.max(0, parseInt(url.searchParams.get("page") || "0"));
  const pageSize = 100;

  const { results } = await env.TELEMETRY_DB.prepare(`
    SELECT
      ts, event, version, os_version, node_version,
      findings_total, findings_critical, findings_high, findings_medium, finding_types,
      scan_source, skipped,
      block_level, block_type, tool, cmd_len, interpreter,
      daemon_installed, gemini_configured, ai_tools
    FROM events ORDER BY rowid DESC LIMIT ? OFFSET ?
  `).bind(pageSize, page * pageSize).all();

  const response = json({ page, page_size: pageSize, results });
  response.headers.set("Cache-Control", "public, max-age=60");
  return addCors(response);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status, headers: { ...CORS, "Content-Type": "application/json" },
  });
}
function addCors(response) {
  const r = new Response(response.body, response);
  for (const [k, v] of Object.entries(CORS)) r.headers.set(k, v);
  return r;
}
function esc(s) {
  return String(s ?? "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}
function sanitizeStr(v, maxLen) {
  if (typeof v !== "string") return null;
  return v.replace(/[^\w.\-/:+ ]/g, "").slice(0, maxLen) || null;
}
function safeInt(v) {
  const n = parseInt(v);
  return isNaN(n) || n < 0 || n > 10000 ? null : n;
}
function safeJsonArr(v, maxItems) {
  if (!Array.isArray(v)) return null;
  const clean = v.filter(s => typeof s === "string" && /^[\w_-]{1,60}$/.test(s)).slice(0, maxItems);
  return clean.length > 0 ? JSON.stringify(clean) : null;
}
function safeJsonObj(v) {
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  const clean = {};
  for (const [k, val] of Object.entries(v)) {
    if (/^[\w_]{1,40}$/.test(k) && typeof val === "boolean") clean[k] = val;
  }
  return Object.keys(clean).length > 0 ? JSON.stringify(clean) : null;
}
