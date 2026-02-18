#!/usr/bin/env node
/**
 * vibe-sec: Interactive Report Server
 *
 * Serves the HTML report locally with interactive risk management:
 *   - Accept Risk (with comment + expiry)
 *   - Mark as Fixed
 *   - Snooze 30 days
 *
 * State saved to vibe-sec-state.json
 *
 * Usage: node scripts/serve-report.mjs [report.md]
 */

import fs from "fs";
import path from "path";
import http from "http";
import { execSync } from "child_process";

const PORT = 7777;
const STATE_FILE = "vibe-sec-state.json";

// ─── Find latest report ───────────────────────────────────────────────────────

function findLatestReport() {
  const arg = process.argv[2];
  if (arg && fs.existsSync(arg)) return arg;

  const files = fs.readdirSync(".")
    .filter(f => f.match(/^vibe-sec-log-report-.*v2\.md$/) || f.match(/^vibe-sec-log-report-\d{4}-\d{2}-\d{2}\.md$/))
    .sort().reverse();
  if (!files.length) throw new Error("No report .md found. Run npm run scan-logs first.");
  return files[0];
}

// ─── State management ─────────────────────────────────────────────────────────

const VALID_STATUSES = new Set(["accepted", "fixed", "snoozed", "expired"]);

function loadState() {
  try {
    const raw = JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
    if (!raw || typeof raw !== "object" || typeof raw.risks !== "object") return { risks: {} };
    // Sanitize each entry — prevents state file tampering from injecting bad data
    const risks = {};
    for (const [key, val] of Object.entries(raw.risks)) {
      if (typeof key !== "string" || !/^[a-zа-я0-9\-]{1,100}$/i.test(key)) continue;
      if (!val || typeof val !== "object") continue;
      risks[key] = {
        status: VALID_STATUSES.has(val.status) ? val.status : "accepted",
        comment: typeof val.comment === "string" ? val.comment.slice(0, 2000) : undefined,
        expiresAt: typeof val.expiresAt === "string" ? val.expiresAt.slice(0, 30) : undefined,
        snoozedUntil: typeof val.snoozedUntil === "string" ? val.snoozedUntil.slice(0, 30) : undefined,
        updatedAt: typeof val.updatedAt === "string" ? val.updatedAt.slice(0, 30) : undefined,
      };
    }
    return { risks };
  } catch { return { risks: {} }; }
}

function saveState(state) {
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}

// ─── Markdown → HTML with interactive buttons ────────────────────────────────

// Severity rank for sorting (lower = higher priority)
const SORT_RANK = {
  '🚨': 0, '🔴': 0,  // CRITICAL / EXPOSED
  '⚠️': 1, '🟠': 1,  // HIGH / IN LOGS
  '💡': 2, '🟡': 2,  // MEDIUM / LOCAL
  '🔵': 3,            // PROVIDER / TRUSTED_SERVICE
  '⚙️': 4,            // KNOWN RISK
  '✅': 5,            // SAFE
};

function presortFindings(text) {
  // Find the first h4 finding
  const firstH4 = text.search(/^#### /m);
  if (firstH4 === -1) return text;

  const pre = text.slice(0, firstH4);
  const rest = text.slice(firstH4);

  // Split into individual h4 blocks (each starting with ####)
  const blocks = rest.split(/^(?=#### )/m).filter(Boolean);

  blocks.sort((a, b) => {
    const iconA = a.match(/^#### (\S+)/)?.[1] || '';
    const iconB = b.match(/^#### (\S+)/)?.[1] || '';
    return (SORT_RANK[iconA] ?? 3) - (SORT_RANK[iconB] ?? 3);
  });

  return pre + blocks.join('');
}

function mdToHtml(text, state) {
  const now = Date.now();

  // Strip legacy section dividers from old Gemini format (e.g. "## Раздел 1 — Credentials")
  text = text.replace(/^## (?:Раздел|Section) \d+[^\n]*$/gm, "");
  // Strip leftover "## Findings (chunk N/M)" sub-headers from multi-chunk reports
  text = text.replace(/^## Findings \(\d+\/\d+\)[^\n]*$/gm, "");

  // Sort all findings by criticality before rendering
  text = presortFindings(text);

  // Check expired acceptances
  for (const [id, risk] of Object.entries(state.risks)) {
    if (risk.status === "accepted" && risk.expiresAt && new Date(risk.expiresAt).getTime() < now) {
      risk.status = "expired";
    }
  }

  function esc(s) {
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function severityClass(icon) {
    if (["🔴", "🚨"].includes(icon)) return "sev-critical";
    if (["🟠", "⚠️"].includes(icon)) return "sev-high";
    if (["🟡", "💡"].includes(icon)) return "sev-medium";
    if (icon === "🔵") return "sev-info";
    if (icon === "⚙️") return "sev-known";
    if (icon === "✅") return "sev-safe";
    return "";
  }

  function slugify(title) {
    return title.toLowerCase().replace(/[^a-zа-я0-9]+/gi, "-").slice(0, 60);
  }

  function renderButtons(id, riskState) {
    if (!riskState || riskState.status === "expired") {
      const expiredNote = riskState?.status === "expired"
        ? `<div class="expired-note">⏰ Ранее принято до ${riskState.expiresAt?.slice(0,10)} — истекло, пересмотрите</div>`
        : "";
      return `${expiredNote}
        <div class="risk-actions">
          <button onclick="acceptRisk('${id}')">✅ Принять риск</button>
          <button onclick="markFixed('${id}')">🔧 Исправлено</button>
          <button onclick="snooze('${id}')">💤 Снузить на 30 дней</button>
        </div>`;
    }
    if (riskState.status === "fixed") {
      return `<div class="status-badge fixed">🔧 Исправлено ${riskState.updatedAt?.slice(0,10)}</div>`;
    }
    if (riskState.status === "snoozed") {
      return `<div class="status-badge snoozed">💤 Снузено до ${riskState.snoozedUntil?.slice(0,10)}
        <button class="small" onclick="clearState('${id}')">×</button></div>`;
    }
    if (riskState.status === "accepted") {
      const preview = riskState.comment
        ? `<div class="accepted-msg">"${esc(riskState.comment.slice(0,160))}${riskState.comment.length > 160 ? "…" : ""}"</div>`
        : "";
      return `<div class="status-badge accepted">
        ✅ Принято${riskState.expiresAt ? ` до ${riskState.expiresAt.slice(0,10)}` : " навсегда"}
        <button class="small" onclick="clearState('${id}')">×</button>
        ${preview}
      </div>`;
    }
    return "";
  }

  let html = text
    // code blocks
    .replace(/```(\w+)?\n([\s\S]*?)```/g, (_, lang, code) =>
      `<pre class="code ${lang||''}"><code>${esc(code.trim())}</code></pre>`)
    // inline code
    .replace(/`([^`]+)`/g, (_, c) => `<code class="inline">${esc(c)}</code>`)
    // hr
    .replace(/^---$/gm, "<hr>")
    // blockquotes
    .replace(/^> (.+)$/gm, (_, content) => `<blockquote>${content}</blockquote>`)
    // markdown links [text](url or #anchor)
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_, label, href) => {
      const isAnchor = href.startsWith("#");
      const attrs = isAnchor ? `href="${href}"` : `href="${href}" target="_blank" rel="noopener"`;
      return `<a ${attrs}>${label}</a>`;
    })
    // arrow links: → text (plain text lines starting with →)
    .replace(/^→ (.+)$/gm, (_, content) => `<p class="arrow-link">→ ${content}</p>`)
    // headings — with id for anchor scrolling
    .replace(/^# (.+)$/gm, "<h1>$1</h1>")
    .replace(/^## (.+)$/gm, (_, title) => {
      const id = title.toLowerCase().replace(/[^a-zа-я0-9]+/gi, "-").replace(/^-|-$/g, "");
      return `<h2 id="${id}">${title}</h2>`;
    })
    .replace(/^### (.+)$/gm, (_, title) => {
      const id = title.toLowerCase().replace(/[^a-zа-я0-9]+/gi, "-").replace(/^-|-$/g, "");
      return `<h3 id="${id}">${title}</h3>`;
    })
    // h4 findings with buttons
    .replace(/^#### (🔴|🟠|🟡|🔵|✅|🚨|⚠️|💡|⚙️) (.+)$/gm, (_, icon, title) => {
      const cls = severityClass(icon);
      const id = slugify(title);
      const riskState = state.risks[id];
      const isSnoozed = riskState?.status === "snoozed" &&
        new Date(riskState.snoozedUntil).getTime() > now;
      const isFixed = riskState?.status === "fixed";
      const dimClass = (isSnoozed || isFixed) ? " dimmed" : "";
      const buttons = renderButtons(id, isSnoozed ? riskState : (isFixed ? riskState : riskState));
      return `</div><div class="finding ${cls}${dimClass}" id="${id}">
        <h4>${icon} ${esc(title)}</h4>${buttons}`;
    })
    .replace(/^#### (.+)$/gm, (_, title) => {
      const id = slugify(title);
      return `</div><div class="finding" id="${id}"><h4>${esc(title)}</h4>`;
    })
    // paragraphs — must run before bold so lines starting with ** get wrapped in <p>
    .replace(/^(?!<|$|\s|-|\|)(.+)$/gm, "<p>$1</p>")
    // bold
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    // tables
    .replace(/^\|(.+)\|$/gm, (line) => {
      if (/^[\s|:-]+$/.test(line)) return "";
      const cells = line.split("|").slice(1, -1).map(c => c.trim());
      return `<tr>${cells.map(c => `<td>${c}</td>`).join("")}</tr>`;
    })
    // list items
    .replace(/^- (.+)$/gm, "<li>$1</li>")
    // wrap tables
    .replace(/(<tr>.*?<\/tr>\n?)+/gs, m => `<table>${m}</table>`)
    // wrap lists
    .replace(/(<li>.*?<\/li>\n?)+/gs, m => `<ul>${m}</ul>`);

  return html;
}

function buildPage(mdFile, state) {
  const md = fs.readFileSync(mdFile, "utf8");
  const body = mdToHtml(md, state);
  const stateJson = JSON.stringify(state);

  return `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>vibe-sec Report</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #0d0d0d; color: #e0e0e0; line-height: 1.6; padding: 40px 20px; }
  .container { max-width: 860px; margin: 0 auto; }

  h1 { font-size: 1.8rem; font-weight: 700; color: #fff; margin-bottom: 4px; }
  h2 { font-size: 1.1rem; font-weight: 600; color: #aaa; text-transform: uppercase; letter-spacing: .08em; margin: 36px 0 12px; padding-bottom: 6px; border-bottom: 1px solid #2a2a2a; }
  h3 { font-size: 1rem; color: #888; margin: 24px 0 8px; font-weight: 600; }
  h4 { font-size: 1rem; font-weight: 700; margin-bottom: 10px; }
  p { color: #bbb; margin: 6px 0; font-size: .95rem; }
  hr { border: none; border-top: 1px solid #222; margin: 28px 0; }

  .finding { border-radius: 8px; padding: 16px 20px; margin: 10px 0; border-left: 4px solid #333; background: #161616; }
  .finding ul { margin: 6px 0 6px 18px; }
  .finding li { color: #bbb; font-size: .9rem; margin: 4px 0; }
  .finding strong { color: #ddd; }
  .finding.dimmed { opacity: 0.4; }

  .sev-critical { border-left-color: #e03e3e; background: #1a0e0e; }
  .sev-critical h4 { color: #ff6b6b; }
  .sev-high { border-left-color: #d97706; background: #1a1208; }
  .sev-high h4 { color: #fbbf24; }
  .sev-medium { border-left-color: #b5a016; background: #181500; }
  .sev-medium h4 { color: #e8d44d; }
  .sev-info { border-left-color: #2d6fbd; background: #0c1520; }
  .sev-info h4 { color: #60a5fa; }
  .sev-known { border-left-color: #7c3aed; background: #130e1f; }
  .sev-known h4 { color: #a78bfa; }
  .sev-safe { border-left-color: #16a34a; background: #0b1a0e; }
  .sev-safe h4 { color: #4ade80; }

  table { width: 100%; border-collapse: collapse; margin: 12px 0; font-size: .9rem; }
  td { padding: 7px 12px; border: 1px solid #2a2a2a; color: #ccc; vertical-align: top; }
  tr:first-child td { background: #1c1c1c; font-weight: 600; color: #eee; }

  pre.code { background: #111; border: 1px solid #2a2a2a; border-radius: 6px; padding: 14px 16px; margin: 10px 0; overflow-x: auto; font-size: .82rem; line-height: 1.5; }
  pre.bash, pre.sh { border-left: 3px solid #4ade80; }
  pre.html { border-left: 3px solid #f97316; }
  code { font-family: "SF Mono", "Fira Code", monospace; }
  code.inline { background: #1e1e1e; color: #a8d8a8; padding: 1px 5px; border-radius: 3px; font-size: .85em; }

  ul { margin: 8px 0 8px 20px; }
  li { color: #bbb; margin: 3px 0; font-size: .93rem; }

  a { color: #60a5fa; text-decoration: none; }
  a:hover { text-decoration: underline; }
  .arrow-link { color: #888; font-size: .9rem; margin: 4px 0; }
  .arrow-link a { color: #60a5fa; }

  /* Risk action buttons */
  .risk-actions { display: flex; gap: 8px; flex-wrap: wrap; margin: 12px 0 4px; }
  .risk-actions button { padding: 5px 12px; border-radius: 5px; border: 1px solid #333; background: #1e1e1e; color: #ccc; font-size: .82rem; cursor: pointer; transition: all .15s; }
  .risk-actions button:hover { background: #2a2a2a; border-color: #555; color: #fff; }

  .status-badge { display: inline-block; padding: 6px 12px; border-radius: 5px; font-size: .82rem; margin: 8px 0 4px; }
  .status-badge.accepted { background: #0b1f0e; border: 1px solid #16a34a; color: #4ade80; }
  .status-badge.fixed { background: #0b1a1f; border: 1px solid #2d6fbd; color: #60a5fa; }
  .status-badge.snoozed { background: #1a1208; border: 1px solid #d97706; color: #fbbf24; }
  .expired-note { background: #1f1208; border: 1px solid #b45309; color: #fbbf24; padding: 6px 12px; border-radius: 5px; font-size: .82rem; margin-bottom: 8px; }
  button.small { background: none; border: none; color: inherit; cursor: pointer; padding: 0 4px; font-size: .9em; opacity: .7; }
  button.small:hover { opacity: 1; }

  /* Accept modal */
  .modal-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,.75); z-index: 100; align-items: center; justify-content: center; }
  .modal-overlay.open { display: flex; }
  .modal { background: #1a1a1a; border: 1px solid #2e2e2e; border-radius: 12px; padding: 24px; width: 500px; max-width: 96vw; }
  .modal-finding-ref { display: flex; align-items: flex-start; gap: 10px; margin-bottom: 16px; padding-bottom: 14px; border-bottom: 1px solid #252525; }
  .modal-finding-ref .mfr-icon { font-size: 1.1em; flex-shrink: 0; margin-top: 1px; }
  .modal-finding-ref .mfr-title { color: #999; font-size: .88rem; line-height: 1.4; }
  .modal-hint { color: #555; font-size: .8rem; margin-bottom: 7px; }
  #modal-message {
    width: 100%; min-height: 140px; background: #111; border: 1px solid #2e2e2e; border-radius: 7px;
    color: #e0e0e0; padding: 12px 14px; font-size: .92rem; font-family: inherit;
    line-height: 1.55; resize: vertical;
  }
  #modal-message:focus { outline: none; border-color: #3d6b3d; }
  .modal-footer { display: flex; align-items: center; justify-content: space-between; margin-top: 14px; gap: 12px; flex-wrap: wrap; }
  .modal-expiry-row { display: flex; align-items: center; gap: 7px; color: #666; font-size: .82rem; flex-shrink: 0; }
  .modal-expiry-row select {
    background: #161616; border: 1px solid #2a2a2a; border-radius: 5px;
    color: #999; padding: 4px 8px; font-size: .82rem; font-family: inherit;
  }
  .modal-btns { display: flex; gap: 8px; }
  .modal-btns button { padding: 7px 18px; border-radius: 6px; border: none; font-size: .9rem; cursor: pointer; }
  .btn-confirm { background: #1a5c2a; color: #4ade80; font-weight: 600; }
  .btn-confirm:hover { background: #1f6e33; }
  .btn-cancel { background: #222; color: #888; }
  .btn-cancel:hover { background: #2a2a2a; color: #aaa; }
  .accepted-msg { color: #3a8f52; font-size: .82rem; font-style: italic; margin-top: 4px; }

  /* Verdict / Итог sections */
  h2.verdict-h2 { color: #818cf8; border-bottom-color: #2a2a45; }
  h2.итог-h2 { color: #4ade80; border-bottom-color: #1a3a1a; }

  /* Blockquotes — used for verdict callouts */
  blockquote { border-left: 4px solid #e03e3e; background: #150c0c; padding: 12px 18px; border-radius: 0 7px 7px 0; margin: 10px 0; color: #ffb3b3; line-height: 1.6; }
  blockquote strong { color: #ff8080; }

  .generated { color: #555; font-size: .8rem; margin-top: 40px; text-align: center; }
</style>
</head>
<body>
<div class="container">
<div class="finding">
${body}
</div>
<p class="generated">vibe-sec • <a href="/refresh" style="color:#555">обновить</a> • <a href="/audit-log" style="color:#555">📋 audit log</a></p>
</div>

<!-- Accept modal -->
<div class="modal-overlay" id="modal">
  <div class="modal">
    <div class="modal-finding-ref">
      <span class="mfr-icon" id="modal-icon"></span>
      <span class="mfr-title" id="modal-title"></span>
    </div>
    <div class="modal-hint">📝 Заготовка — отредактируй под себя</div>
    <textarea id="modal-message"></textarea>
    <div class="modal-footer">
      <div class="modal-expiry-row">
        Напомнить через
        <select id="modal-expiry">
          <option value="30">30 дней</option>
          <option value="90" selected>3 месяца</option>
          <option value="180">6 месяцев</option>
          <option value="365">1 год</option>
          <option value="0">Не напоминать</option>
        </select>
      </div>
      <div class="modal-btns">
        <button class="btn-cancel" onclick="closeModal()">Отмена</button>
        <button class="btn-confirm" onclick="confirmAccept()">Отправить ✓</button>
      </div>
    </div>
  </div>
</div>

<script>
let _state = ${stateJson};
let _currentId = null;

function generateDefault(id, title, icon) {
  const t = (id + " " + title).toLowerCase();

  if (t.includes("bigquery") || t.includes("super admin") || t.includes("super-admin")) {
    return "Это стейджинговое окружение, реальных данных клиентов нет. Запиши это и держи в голове три месяца. Через три месяца, если я всё ещё использую — напомни: вдруг к тому моменту уже будет продакшн.";
  }
  if (t.includes("terminal") || t.includes("accessibility") || t.includes("доступ к terminal")) {
    return "Это мой личный рабочий Mac, я единственный пользователь. Риск для меня приемлем при текущей конфигурации. Напомни через 6 месяцев — пересмотрю если что-то изменится.";
  }
  if (t.includes("chrome") || t.includes("playwright") || t.includes("браузер")) {
    return "Доступ к браузеру нужен мне намеренно — это рабочая конфигурация для автоматизации. Я понимаю риски prompt injection. Напомни через 3 месяца.";
  }
  if (t.includes("in logs") || t.includes("leaked") || t.includes("ключ") || t.includes("key") || t.includes("token")) {
    return "Ключ уже был заменён / это тестовый ключ без реальных прав. Держи в голове. Напомни через 3 месяца — проверю что текущие ключи под контролем.";
  }
  if (icon && (icon.includes("⚙️") || t.includes("known risk"))) {
    return "Я в курсе этого и принимаю риск осознанно. Напомни через 3 месяца — пересмотрю если ситуация изменится.";
  }
  return "Я изучил этот риск и принимаю его. Напомни через 3 месяца для повторной оценки.";
}

function acceptRisk(id) {
  _currentId = id;

  const el = document.getElementById(id);
  const h4 = el ? el.querySelector("h4") : null;
  const fullTitle = h4 ? h4.textContent.trim() : id;
  const icon = fullTitle.match(/^(\S+)/)?.[1] || "";
  const titleText = fullTitle.replace(/^\S+\s*/, "");

  document.getElementById("modal-icon").textContent = icon;
  document.getElementById("modal-title").textContent = titleText;

  const defaultMsg = generateDefault(id, titleText, icon);
  document.getElementById("modal-message").value = defaultMsg;

  // Auto-set expiry based on message keywords
  const sel = document.getElementById("modal-expiry");
  if (defaultMsg.includes("6 месяц")) sel.value = "180";
  else if (defaultMsg.includes("год")) sel.value = "365";
  else if (defaultMsg.includes("Не напоминать") || defaultMsg.includes("навсегда")) sel.value = "0";
  else sel.value = "90";

  document.getElementById("modal").classList.add("open");
  setTimeout(() => {
    const ta = document.getElementById("modal-message");
    ta.focus();
    ta.setSelectionRange(ta.value.length, ta.value.length);
  }, 60);
}

function closeModal() {
  document.getElementById("modal").classList.remove("open");
  _currentId = null;
}

async function confirmAccept() {
  const comment = document.getElementById("modal-message").value.trim();
  const days = parseInt(document.getElementById("modal-expiry").value);
  const expiresAt = days > 0
    ? new Date(Date.now() + days * 86400000).toISOString()
    : null;
  await postState(_currentId, { status: "accepted", comment, expiresAt });
  closeModal();
}

async function markFixed(id) {
  await postState(id, { status: "fixed" });
}

async function snooze(id) {
  const snoozedUntil = new Date(Date.now() + 30 * 86400000).toISOString();
  await postState(id, { status: "snoozed", snoozedUntil });
}

async function clearState(id) {
  await postState(id, null);
}

async function postState(id, data) {
  await fetch("/state", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id, data }),
  });
  location.reload();
}

// Close modal on overlay click
document.getElementById("modal").addEventListener("click", e => {
  if (e.target === e.currentTarget) closeModal();
});
</script>
</body>
</html>`;
}

// ─── HTTP Server ──────────────────────────────────────────────────────────────

const reportFile = findLatestReport();
console.log(`📄 Report: ${reportFile}`);
console.log(`💾 State:  ${STATE_FILE}`);
console.log(`\n🚀 Starting server at http://localhost:${PORT}\n`);

const server = http.createServer((req, res) => {
  // Save state
  if (req.method === "POST" && req.url === "/state") {
    let body = "";
    const MAX_BODY = 50_000; // 50KB limit to prevent DoS
    req.on("data", c => {
      body += c;
      if (body.length > MAX_BODY) {
        req.destroy();
        res.writeHead(413).end("payload too large");
      }
    });
    req.on("end", () => {
      try {
        const { id, data } = JSON.parse(body);
        // Prevent prototype pollution attacks
        if (typeof id !== "string" || ["__proto__", "constructor", "prototype"].includes(id)) {
          res.writeHead(400).end("invalid id");
          return;
        }
        // Sanitize id to alphanumeric + dash (slugified finding IDs)
        if (!/^[a-zа-я0-9\-]{1,100}$/i.test(id)) {
          res.writeHead(400).end("invalid id");
          return;
        }
        const state = loadState();
        if (data === null) {
          delete state.risks[id];
        } else {
          // Only allow known safe properties — no prototype pollution via data spreading
          const safe = {
            status: String(data.status || "").slice(0, 20),
            comment: typeof data.comment === "string" ? data.comment.slice(0, 2000) : undefined,
            expiresAt: typeof data.expiresAt === "string" ? data.expiresAt.slice(0, 30) : undefined,
            snoozedUntil: typeof data.snoozedUntil === "string" ? data.snoozedUntil.slice(0, 30) : undefined,
            updatedAt: new Date().toISOString(),
          };
          state.risks[id] = safe;
        }
        saveState(state);
        res.writeHead(200).end("ok");
      } catch {
        res.writeHead(400).end("bad request");
      }
    });
    return;
  }

  // Audit log viewer
  if (req.url === "/audit-log") {
    const auditFile = "vibe-sec-audit.jsonl";
    let auditHtml = `<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8"><title>vibe-sec Audit Log</title>
<style>* { box-sizing:border-box; margin:0; padding:0 }
body { font-family: "SF Mono","Fira Code",monospace; background:#0d0d0d; color:#ccc; padding:30px 20px; font-size:.85rem; line-height:1.6 }
.container { max-width:900px; margin:0 auto }
h1 { color:#fff; font-size:1.3rem; margin-bottom:16px }
.entry { background:#161616; border:1px solid #2a2a2a; border-radius:6px; padding:10px 14px; margin:6px 0 }
.ts { color:#555; font-size:.78rem }
.event { color:#818cf8; font-weight:700; margin:0 6px }
.gemini { border-left:3px solid #818cf8 }
.static { border-left:3px solid #fbbf24 }
.scan { border-left:3px solid #4ade80 }
.props { color:#888; margin-top:4px }
.back { color:#555; text-decoration:none; font-size:.8rem; display:block; margin-bottom:20px }
.back:hover { color:#888 }
.empty { color:#444; margin-top:20px }
</style></head><body><div class="container">
<a href="/" class="back">← обратно к отчёту</a>
<h1>📋 Audit Log — vibe-sec</h1>
<p style="color:#555;font-size:.8rem;margin-bottom:16px">Все действия инструмента. Что отправлялось в Gemini — только метаданные (размер, кол-во токенов), не сам контент.</p>`;

    try {
      if (!fs.existsSync(auditFile)) throw new Error("no file");
      const lines = fs.readFileSync(auditFile, "utf8").trim().split("\n").filter(Boolean).reverse(); // newest first
      for (const line of lines.slice(0, 200)) {
        try {
          const entry = JSON.parse(line);
          const { ts, event, ...rest } = entry;
          const cls = event.includes("gemini") ? "gemini" : event.includes("static") ? "static" : "scan";
          const props = Object.entries(rest)
            .map(([k, v]) => `<span style="color:#555">${k}:</span> <span style="color:#ccc">${Array.isArray(v) ? v.join(", ") : v}</span>`)
            .join(" &nbsp;·&nbsp; ");
          auditHtml += `<div class="entry ${cls}"><span class="ts">${ts}</span><span class="event">${event}</span><div class="props">${props}</div></div>`;
        } catch {}
      }
    } catch {
      auditHtml += `<p class="empty">Лог пуст — запусти <code>npm run scan-logs:static</code> для первой записи.</p>`;
    }

    auditHtml += `</div></body></html>`;
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" }).end(auditHtml);
    return;
  }

  // Serve report
  const state = loadState();
  try {
    const html = buildPage(reportFile, state);
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" }).end(html);
  } catch (e) {
    res.writeHead(500).end(e.message);
  }
});

server.listen(PORT, "127.0.0.1", () => {
  // Open in browser
  try { execSync(`open http://localhost:${PORT}`); } catch {}
});
