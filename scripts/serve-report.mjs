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

  function severityBadge(icon) {
    const map = {
      "🔴": ["CRITICAL", "sev-critical"],
      "🚨": ["CRITICAL", "sev-critical"],
      "⚠️": ["HIGH",     "sev-high"],
      "🟠": ["HIGH",     "sev-high"],
      "💡": ["MEDIUM",   "sev-medium"],
      "🟡": ["MEDIUM",   "sev-medium"],
      "🔵": ["INFO",     "sev-info"],
      "⚙️": ["KNOWN",    "sev-known"],
      "✅": ["SAFE",     "sev-safe"],
    };
    const [label, cls] = map[icon] || ["", ""];
    return label ? `<span class="sev-badge ${cls}">${label}</span>` : "";
  }

  function slugify(title) {
    return title.toLowerCase().replace(/[^a-zа-я0-9]+/gi, "-").slice(0, 60);
  }

  function renderButtons(id, riskState) {
    if (!riskState || riskState.status === "expired") {
      const expiredNote = riskState?.status === "expired"
        ? `<div class="expired-note">Previously accepted until ${riskState.expiresAt?.slice(0,10)} — expired, please review</div>`
        : "";
      return `${expiredNote}
        <div class="risk-actions">
          <button onclick="acceptRisk('${id}')">Accept Risk</button>
          <button onclick="markFixed('${id}')">Mark Fixed</button>
          <button onclick="snooze('${id}')">Snooze 30 days</button>
        </div>`;
    }
    if (riskState.status === "fixed") {
      return `<div class="status-badge fixed">Fixed ${riskState.updatedAt?.slice(0,10)}</div>`;
    }
    if (riskState.status === "snoozed") {
      return `<div class="status-badge snoozed">Snoozed until ${riskState.snoozedUntil?.slice(0,10)}
        <button class="small" onclick="clearState('${id}')">×</button></div>`;
    }
    if (riskState.status === "accepted") {
      const preview = riskState.comment
        ? `<div class="accepted-msg">"${esc(riskState.comment.slice(0,160))}${riskState.comment.length > 160 ? "…" : ""}"</div>`
        : "";
      return `<div class="status-badge accepted">
        Accepted${riskState.expiresAt ? ` until ${riskState.expiresAt.slice(0,10)}` : " (permanent)"}
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
    // blockquotes — ✓ prefix = green (positive), ✗ prefix = red (negative), plain = default
    .replace(/^> (.+)$/gm, (_, content) => {
      if (content.startsWith('✓ ')) return `<blockquote class="bq-positive">${content.slice(2)}</blockquote>`;
      if (content.startsWith('✗ ')) return `<blockquote class="bq-negative">${content.slice(2)}</blockquote>`;
      return `<blockquote>${content}</blockquote>`;
    })
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
    // h4 findings with severity badge + buttons
    .replace(/^#### (🔴|🟠|🟡|🔵|✅|🚨|⚠️|💡|⚙️) (.+)$/gm, (_, icon, title) => {
      const cls = severityClass(icon);
      const badge = severityBadge(icon);
      const id = slugify(title);
      const riskState = state.risks[id];
      const isSnoozed = riskState?.status === "snoozed" &&
        new Date(riskState.snoozedUntil).getTime() > now;
      const isFixed = riskState?.status === "fixed";
      const dimClass = (isSnoozed || isFixed) ? " dimmed" : "";
      const buttons = renderButtons(id, isSnoozed ? riskState : (isFixed ? riskState : riskState));
      return `</div><div class="finding ${cls}${dimClass}" id="${id}">
        <h4>${badge} ${esc(title)}</h4>${buttons}`;
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
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>vibe-sec Security Report</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Inter", sans-serif;
    background: #111113;
    color: #c9c9cf;
    line-height: 1.65;
    padding: 48px 24px;
    font-size: 14px;
  }
  .container { max-width: 820px; margin: 0 auto; }

  h1 {
    font-size: 1.5rem;
    font-weight: 600;
    color: #f0f0f2;
    margin-bottom: 4px;
    letter-spacing: -.01em;
  }
  h2 {
    font-size: .72rem;
    font-weight: 600;
    color: #666;
    text-transform: uppercase;
    letter-spacing: .12em;
    margin: 40px 0 14px;
    padding-bottom: 8px;
    border-bottom: 1px solid #222;
  }
  h3 {
    font-size: .9rem;
    color: #888;
    margin: 24px 0 8px;
    font-weight: 600;
  }
  h4 {
    font-size: .92rem;
    font-weight: 600;
    color: #ddd;
    margin-bottom: 10px;
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }
  p { color: #999; margin: 6px 0; font-size: .9rem; }
  hr { border: none; border-top: 1px solid #1e1e1e; margin: 32px 0; }

  /* Severity badge pills */
  .sev-badge {
    display: inline-block;
    font-size: .65rem;
    font-weight: 700;
    letter-spacing: .08em;
    padding: 2px 7px;
    border-radius: 3px;
    font-family: "SF Mono", "Fira Code", "Cascadia Code", monospace;
    flex-shrink: 0;
  }
  .sev-badge.sev-critical { background: rgba(239,68,68,.15); color: #f87171; border: 1px solid rgba(239,68,68,.3); }
  .sev-badge.sev-high     { background: rgba(245,158,11,.12); color: #fbbf24; border: 1px solid rgba(245,158,11,.25); }
  .sev-badge.sev-medium   { background: rgba(234,179,8,.1);   color: #d4b84a; border: 1px solid rgba(234,179,8,.2); }
  .sev-badge.sev-info     { background: rgba(59,130,246,.12); color: #60a5fa; border: 1px solid rgba(59,130,246,.25); }
  .sev-badge.sev-known    { background: rgba(139,92,246,.1);  color: #a78bfa; border: 1px solid rgba(139,92,246,.2); }
  .sev-badge.sev-safe     { background: rgba(34,197,94,.1);   color: #4ade80; border: 1px solid rgba(34,197,94,.2); }

  /* Finding cards */
  .finding {
    border-radius: 6px;
    padding: 16px 20px;
    margin: 8px 0;
    border-left: 3px solid #2a2a2a;
    background: #18181b;
  }
  .finding ul { margin: 6px 0 6px 18px; }
  .finding li { color: #999; font-size: .88rem; margin: 4px 0; }
  .finding strong { color: #ccc; }
  .finding.dimmed { opacity: 0.35; }

  .sev-critical { border-left-color: #dc2626; }
  .sev-high     { border-left-color: #d97706; }
  .sev-medium   { border-left-color: #a16207; }
  .sev-info     { border-left-color: #2563eb; }
  .sev-known    { border-left-color: #7c3aed; }
  .sev-safe     { border-left-color: #16a34a; }

  /* Tables */
  table { width: 100%; border-collapse: collapse; margin: 12px 0; font-size: .88rem; }
  td { padding: 7px 12px; border: 1px solid #222; color: #aaa; vertical-align: top; }
  tr:first-child td { background: #1c1c1f; font-weight: 600; color: #ddd; font-size: .78rem; text-transform: uppercase; letter-spacing: .06em; }

  /* Code */
  pre.code {
    background: #0f0f11;
    border: 1px solid #222;
    border-radius: 5px;
    padding: 14px 16px;
    margin: 10px 0;
    overflow-x: auto;
    font-size: .8rem;
    line-height: 1.55;
  }
  pre.bash, pre.sh { border-left: 2px solid #22c55e; }
  pre.html { border-left: 2px solid #f97316; }
  code { font-family: "SF Mono", "Fira Code", "Cascadia Code", monospace; }
  code.inline {
    background: #1c1c1f;
    color: #94a3b8;
    padding: 1px 5px;
    border-radius: 3px;
    font-size: .82em;
  }

  ul { margin: 8px 0 8px 20px; }
  li { color: #999; margin: 3px 0; font-size: .9rem; }

  a { color: #6699cc; text-decoration: none; }
  a:hover { color: #88aadd; text-decoration: underline; }
  .arrow-link { color: #666; font-size: .88rem; margin: 4px 0; }
  .arrow-link a { color: #6699cc; }

  /* Risk action buttons */
  .risk-actions { display: flex; gap: 6px; flex-wrap: wrap; margin: 12px 0 4px; }
  .risk-actions button {
    padding: 4px 12px;
    border-radius: 4px;
    border: 1px solid #2e2e35;
    background: transparent;
    color: #888;
    font-size: .78rem;
    font-family: inherit;
    cursor: pointer;
    transition: border-color .15s, color .15s;
    letter-spacing: .02em;
  }
  .risk-actions button:hover { border-color: #555; color: #ccc; }

  /* Status badges */
  .status-badge {
    display: inline-block;
    padding: 4px 10px;
    border-radius: 4px;
    font-size: .78rem;
    margin: 8px 0 4px;
    font-family: "SF Mono", "Fira Code", monospace;
  }
  .status-badge.accepted { background: #0d1f10; border: 1px solid #1a3a1f; color: #4ade80; }
  .status-badge.fixed    { background: #0d1825; border: 1px solid #1a3050; color: #60a5fa; }
  .status-badge.snoozed  { background: #1a1508; border: 1px solid #2e2006; color: #ca8a04; }
  .expired-note {
    background: #1c1208;
    border: 1px solid #3a2008;
    color: #ca8a04;
    padding: 5px 10px;
    border-radius: 4px;
    font-size: .78rem;
    margin-bottom: 8px;
  }
  button.small {
    background: none;
    border: none;
    color: inherit;
    cursor: pointer;
    padding: 0 4px;
    font-size: .9em;
    opacity: .5;
  }
  button.small:hover { opacity: 1; }
  .accepted-msg { color: #3a7a52; font-size: .8rem; font-style: italic; margin-top: 4px; }

  /* Accept modal */
  .modal-overlay {
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,.8);
    z-index: 100;
    align-items: center;
    justify-content: center;
  }
  .modal-overlay.open { display: flex; }
  .modal {
    background: #18181b;
    border: 1px solid #2a2a2e;
    border-radius: 8px;
    padding: 24px;
    width: 500px;
    max-width: 96vw;
  }
  .modal-finding-ref {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    margin-bottom: 16px;
    padding-bottom: 14px;
    border-bottom: 1px solid #222;
  }
  .modal-finding-ref .mfr-badge { flex-shrink: 0; margin-top: 1px; }
  .modal-finding-ref .mfr-title { color: #888; font-size: .86rem; line-height: 1.4; }
  .modal-hint { color: #555; font-size: .78rem; margin-bottom: 6px; }
  #modal-message {
    width: 100%;
    min-height: 120px;
    background: #0f0f11;
    border: 1px solid #2a2a2e;
    border-radius: 5px;
    color: #d0d0d4;
    padding: 10px 12px;
    font-size: .88rem;
    font-family: inherit;
    line-height: 1.55;
    resize: vertical;
  }
  #modal-message:focus { outline: none; border-color: #2a4a2e; }
  .modal-footer {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-top: 14px;
    gap: 12px;
    flex-wrap: wrap;
  }
  .modal-expiry-row {
    display: flex;
    align-items: center;
    gap: 7px;
    color: #555;
    font-size: .78rem;
    flex-shrink: 0;
  }
  .modal-expiry-row select {
    background: #111113;
    border: 1px solid #2a2a2e;
    border-radius: 4px;
    color: #888;
    padding: 3px 8px;
    font-size: .78rem;
    font-family: inherit;
  }
  .modal-btns { display: flex; gap: 8px; }
  .modal-btns button {
    padding: 6px 16px;
    border-radius: 4px;
    border: none;
    font-size: .86rem;
    font-family: inherit;
    cursor: pointer;
  }
  .btn-confirm { background: #14422a; color: #4ade80; font-weight: 600; border: 1px solid #1a5c3a; }
  .btn-confirm:hover { background: #185534; }
  .btn-cancel { background: #1c1c1f; color: #777; border: 1px solid #2a2a2e; }
  .btn-cancel:hover { color: #aaa; }

  /* Blockquotes — verdict callouts */
  blockquote {
    border-left: 3px solid #dc2626;
    background: #150c0c;
    padding: 12px 18px;
    border-radius: 0 5px 5px 0;
    margin: 6px 0;
    color: #f87171;
    line-height: 1.6;
    font-size: .88rem;
    font-weight: 500;
  }
  blockquote strong { color: #fca5a5; }

  /* Split-color Claude note */
  blockquote.bq-positive {
    border-left-color: #16a34a;
    background: #091a0c;
    color: #6ee88a;
    border-radius: 0 5px 0 0;
    margin-bottom: 0;
  }
  blockquote.bq-positive strong { color: #86efac; }
  blockquote.bq-negative {
    border-left-color: #dc2626;
    background: #150c0c;
    color: #f87171;
    border-radius: 0 0 5px 5px;
    margin-top: 0;
    border-top: 1px solid #2a1010;
  }
  blockquote.bq-negative strong { color: #fca5a5; }

  .app-callout {
    display: flex;
    align-items: flex-start;
    gap: 14px;
    margin-top: 48px;
    padding: 14px 18px;
    background: #111;
    border: 1px solid #222;
    border-radius: 8px;
  }
  .app-callout-icon { font-size: 1.4rem; line-height: 1; margin-top: 2px; }
  .app-callout-body { font-size: .85rem; color: #aaa; }
  .app-callout-body strong { color: #e0e0e0; }
  .app-callout-links { display: flex; gap: 16px; margin-top: 6px; }
  .app-callout-links a { color: #60a5fa; text-decoration: none; font-size: .8rem; }
  .app-callout-links a:hover { text-decoration: underline; }

  .report-footer {
    color: #444;
    font-size: .75rem;
    margin-top: 12px;
    padding-top: 12px;
    border-top: 1px solid #1e1e1e;
    display: flex;
    gap: 16px;
  }
  .report-footer a { color: #444; }
  .report-footer a:hover { color: #666; text-decoration: none; }

  /* Quick-jump finding index */
  .quick-jump {
    margin: 16px 0 8px;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .jump-link {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 7px 12px;
    border-radius: 5px;
    text-decoration: none;
    font-size: .83rem;
    font-weight: 500;
    border: 1px solid transparent;
    cursor: pointer;
    transition: background .12s, border-color .12s, transform .1s;
    color: #bbb;
    line-height: 1.35;
  }
  .jump-link .jump-title {
    text-decoration: underline;
    text-decoration-color: rgba(255,255,255,.2);
    text-underline-offset: 3px;
    text-decoration-thickness: 1px;
    transition: text-decoration-color .12s;
  }
  .jump-link:hover { color: #f0f0f2; text-decoration: none; transform: translateX(2px); }
  .jump-link:hover .jump-title {
    text-decoration-color: rgba(255,255,255,.55);
  }
  .jump-link .jump-num {
    font-family: "SF Mono", "Fira Code", monospace;
    font-size: .72rem;
    font-weight: 700;
    min-width: 18px;
    text-align: right;
    flex-shrink: 0;
  }
  .jump-link .jump-arrow {
    margin-left: auto;
    font-size: .78rem;
    flex-shrink: 0;
    transition: opacity .12s, transform .12s;
    opacity: .35;
  }
  .jump-link:hover .jump-arrow { opacity: .8; transform: translateY(2px); }
  .jump-link.jl-critical { background: rgba(220,38,38,.07); border-color: rgba(220,38,38,.18); }
  .jump-link.jl-critical:hover { background: rgba(220,38,38,.13); border-color: rgba(220,38,38,.3); }
  .jump-link.jl-critical .jump-num { color: #f87171; }
  .jump-link.jl-high { background: rgba(217,119,6,.06); border-color: rgba(217,119,6,.15); }
  .jump-link.jl-high:hover { background: rgba(217,119,6,.12); border-color: rgba(217,119,6,.28); }
  .jump-link.jl-high .jump-num { color: #fbbf24; }
  .jump-link .jump-badge {
    font-size: .62rem;
    font-weight: 700;
    letter-spacing: .07em;
    padding: 1px 5px;
    border-radius: 3px;
    font-family: "SF Mono", monospace;
    flex-shrink: 0;
  }
  .jump-link.jl-critical .jump-badge { background: rgba(239,68,68,.15); color: #f87171; border: 1px solid rgba(239,68,68,.3); }
  .jump-link.jl-high .jump-badge { background: rgba(245,158,11,.12); color: #fbbf24; border: 1px solid rgba(245,158,11,.25); }

  /* Flash highlight when scrolling to a finding via anchor */
  @keyframes finding-flash {
    0%   { box-shadow: 0 0 0 3px rgba(99,153,220,.5); }
    60%  { box-shadow: 0 0 0 5px rgba(99,153,220,.2); }
    100% { box-shadow: 0 0 0 0px rgba(99,153,220,.0); }
  }
  .finding.flash { animation: finding-flash 1.1s ease-out; }

  /* Scroll offset so card isn't hidden under any sticky header */
  .finding { scroll-margin-top: 24px; }
</style>
</head>
<body>
<div class="container">
<div class="finding">
${body}
</div>
<div class="app-callout">
  <div class="app-callout-icon">📱</div>
  <div class="app-callout-body">
    <strong>Get the menubar app</strong> — always-visible security status, daily background scans, instant alerts.
    <div class="app-callout-links">
      <a href="https://github.com/kobzevvv/vibe-sec-app/releases/latest" target="_blank">→ Download .app</a>
      <a href="https://github.com/kobzevvv/vibe-sec-app" target="_blank">GitHub</a>
      <a href="https://github.com/kobzevvv/vibe-sec-app#build--run" target="_blank">Build from source</a>
    </div>
  </div>
</div>
<div class="report-footer">
  <span>vibe-sec</span>
  <a href="/refresh">Refresh</a>
  <a href="/audit-log">Audit Log</a>
</div>
</div>

<!-- Accept Risk modal -->
<div class="modal-overlay" id="modal">
  <div class="modal">
    <div class="modal-finding-ref">
      <span class="mfr-badge" id="modal-badge"></span>
      <span class="mfr-title" id="modal-title"></span>
    </div>
    <div class="modal-hint">Describe why this risk is accepted — saved with the finding</div>
    <textarea id="modal-message"></textarea>
    <div class="modal-footer">
      <div class="modal-expiry-row">
        Remind in
        <select id="modal-expiry">
          <option value="30">30 days</option>
          <option value="90" selected>3 months</option>
          <option value="180">6 months</option>
          <option value="365">1 year</option>
          <option value="0">Never</option>
        </select>
      </div>
      <div class="modal-btns">
        <button class="btn-cancel" onclick="closeModal()">Cancel</button>
        <button class="btn-confirm" onclick="confirmAccept()">Accept Risk</button>
      </div>
    </div>
  </div>
</div>

<script>
let _state = ${stateJson};
let _currentId = null;

function generateDefault(id, title, badge) {
  const t = (id + " " + title).toLowerCase();

  if (t.includes("bigquery") || t.includes("super admin") || t.includes("super-admin")) {
    return "Staging environment only — no real customer data. Acceptable for now. Remind me in 3 months to reassess if this reaches production.";
  }
  if (t.includes("terminal") || t.includes("accessibility")) {
    return "Personal work Mac, single user. Risk is acceptable under current configuration. Remind me in 6 months to revisit if anything changes.";
  }
  if (t.includes("chrome") || t.includes("playwright") || t.includes("browser")) {
    return "Browser access is intentional — required for automation workflows. Prompt injection risks are understood. Remind me in 3 months.";
  }
  if (t.includes("in logs") || t.includes("leaked") || t.includes("key") || t.includes("token")) {
    return "Key has been rotated / this is a test key with no real permissions. Remind me in 3 months to verify current keys are under control.";
  }
  if (badge && (badge.includes("KNOWN") || t.includes("known risk"))) {
    return "Known and accepted risk. Remind me in 3 months to reassess if the situation changes.";
  }
  return "Reviewed and accepted. Remind me in 3 months for re-evaluation.";
}

function acceptRisk(id) {
  _currentId = id;

  const el = document.getElementById(id);
  const h4 = el ? el.querySelector("h4") : null;
  const badge = h4 ? (h4.querySelector(".sev-badge")?.textContent || "") : "";
  const titleEl = h4 ? h4.cloneNode(true) : null;
  if (titleEl) titleEl.querySelector(".sev-badge")?.remove();
  const titleText = titleEl ? titleEl.textContent.trim() : id;

  document.getElementById("modal-badge").innerHTML = h4?.querySelector(".sev-badge")?.outerHTML || "";
  document.getElementById("modal-title").textContent = titleText;

  const defaultMsg = generateDefault(id, titleText, badge);
  document.getElementById("modal-message").value = defaultMsg;

  // Auto-set expiry based on message keywords
  const sel = document.getElementById("modal-expiry");
  if (defaultMsg.includes("6 months")) sel.value = "180";
  else if (defaultMsg.includes("1 year") || defaultMsg.includes("year")) sel.value = "365";
  else if (defaultMsg.includes("Never") || defaultMsg.includes("permanent")) sel.value = "0";
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

// ─── Quick-jump index ─────────────────────────────────────────────────────────
// Builds a clickable list of critical/high findings and injects it after the
// first <blockquote> in the page (the Risk Summary callout).

(function buildQuickJump() {
  const critical = Array.from(document.querySelectorAll('.finding.sev-critical')).filter(f => f.id && !f.classList.contains('dimmed'));
  const high     = Array.from(document.querySelectorAll('.finding.sev-high')).filter(f => f.id && !f.classList.contains('dimmed'));
  const all = [...critical, ...high];
  if (all.length === 0) return;

  // Anchor target: first blockquote (the "N critical/high issues found" callout)
  const blockquote = document.querySelector('blockquote');
  if (!blockquote) return;

  function getTitle(el) {
    const h4 = el.querySelector('h4');
    if (!h4) return el.id;
    const clone = h4.cloneNode(true);
    clone.querySelector('.sev-badge')?.remove();
    clone.querySelectorAll('.risk-actions, .status-badge').forEach(n => n.remove());
    return clone.textContent.trim();
  }

  const nav = document.createElement('div');
  nav.className = 'quick-jump';

  let html = '';
  let critIdx = 0, highIdx = 0;
  for (const f of all) {
    const isCritical = f.classList.contains('sev-critical');
    const cls = isCritical ? 'jl-critical' : 'jl-high';
    const badge = isCritical ? 'CRITICAL' : 'HIGH';
    const num = isCritical ? ++critIdx : ++highIdx;
    const title = getTitle(f);
    html += '<a href="#' + f.id + '" class="jump-link ' + cls + '">' +
      '<span class="jump-num">' + num + '</span>' +
      '<span class="jump-badge">' + badge + '</span>' +
      '<span class="jump-title">' + title + '</span>' +
      '<span class="jump-arrow">\u2193</span>' +
      '</a>';
  }
  nav.innerHTML = html;

  // Insert after the blockquote
  blockquote.insertAdjacentElement('afterend', nav);

  // Flash the target card when navigating via anchor
  nav.addEventListener('click', e => {
    const a = e.target.closest('a');
    if (!a) return;
    const id = a.getAttribute('href')?.slice(1);
    if (!id) return;
    const target = document.getElementById(id);
    if (!target) return;
    // Remove then re-add to re-trigger animation
    target.classList.remove('flash');
    requestAnimationFrame(() => requestAnimationFrame(() => target.classList.add('flash')));
    target.addEventListener('animationend', () => target.classList.remove('flash'), { once: true });
  });
})();
</script>
</body>
</html>`;
}

// ─── HTTP Server ──────────────────────────────────────────────────────────────

const reportFile = findLatestReport();
console.log(`Report: ${reportFile}`);
console.log(`State:  ${STATE_FILE}`);
console.log(`\nStarting server at http://localhost:${PORT}\n`);

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
    let auditHtml = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>vibe-sec Audit Log</title>
<style>* { box-sizing:border-box; margin:0; padding:0 }
body { font-family: "SF Mono","Fira Code","Cascadia Code",monospace; background:#111113; color:#ccc; padding:32px 24px; font-size:.82rem; line-height:1.6 }
.container { max-width:900px; margin:0 auto }
h1 { color:#e0e0e4; font-size:1.1rem; margin-bottom:4px; font-weight:600; letter-spacing:-.01em }
.subtitle { color:#555; font-size:.76rem; margin-bottom:20px }
.entry { background:#18181b; border:1px solid #222; border-radius:5px; padding:9px 14px; margin:5px 0 }
.ts { color:#444; font-size:.75rem }
.event { color:#7b8cde; font-weight:700; margin:0 8px }
.gemini { border-left:2px solid #7b8cde }
.static { border-left:2px solid #ca8a04 }
.scan { border-left:2px solid #22c55e }
.props { color:#666; margin-top:3px; font-size:.76rem }
.back { color:#555; text-decoration:none; font-size:.76rem; display:block; margin-bottom:20px }
.back:hover { color:#888 }
.empty { color:#444; margin-top:20px }
</style></head><body><div class="container">
<a href="/" class="back">← back to report</a>
<h1>Audit Log</h1>
<p class="subtitle">All tool activity. Gemini entries show only metadata (size, token count) — not the actual content.</p>`;

    try {
      if (!fs.existsSync(auditFile)) throw new Error("no file");
      const lines = fs.readFileSync(auditFile, "utf8").trim().split("\n").filter(Boolean).reverse(); // newest first
      for (const line of lines.slice(0, 200)) {
        try {
          const entry = JSON.parse(line);
          const { ts, event, ...rest } = entry;
          const cls = event.includes("gemini") ? "gemini" : event.includes("static") ? "static" : "scan";
          const props = Object.entries(rest)
            .map(([k, v]) => `<span style="color:#444">${k}:</span> <span style="color:#aaa">${Array.isArray(v) ? v.join(", ") : v}</span>`)
            .join(" &nbsp;·&nbsp; ");
          auditHtml += `<div class="entry ${cls}"><span class="ts">${ts}</span><span class="event">${event}</span><div class="props">${props}</div></div>`;
        } catch {}
      }
    } catch {
      auditHtml += `<p class="empty">No entries yet — run <code>npm run scan-logs:static</code> to generate the first record.</p>`;
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
