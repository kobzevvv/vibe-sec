#!/usr/bin/env node
/**
 * Converts a vibe-sec markdown report to a styled HTML file.
 * Usage: node scripts/render-report.mjs [report.md]
 */

import fs from "fs";
import path from "path";

const inputFile = process.argv[2] || (() => {
  const files = fs.readdirSync(".")
    .filter(f => f.match(/^vibe-sec-log-report-.*\.md$/) && !f.includes("example"))
    .sort().reverse();
  if (!files.length) throw new Error("No report file found");
  return files[0];
})();

const md = fs.readFileSync(inputFile, "utf8");

// Minimal markdown → HTML converter (no deps)
function mdToHtml(text) {
  return text
    // code blocks
    .replace(/```bash\n([\s\S]*?)```/g, (_, code) =>
      `<pre class="code bash"><code>${esc(code.trim())}</code></pre>`)
    .replace(/```\n([\s\S]*?)```/g, (_, code) =>
      `<pre class="code"><code>${esc(code.trim())}</code></pre>`)
    // inline code
    .replace(/`([^`]+)`/g, (_, c) => `<code class="inline">${esc(c)}</code>`)
    // horizontal rule
    .replace(/^---$/gm, "<hr>")
    // h1
    .replace(/^# (.+)$/gm, "<h1>$1</h1>")
    // h2
    .replace(/^## (.+)$/gm, "<h2>$1</h2>")
    // h3
    .replace(/^### (.+)$/gm, "<h3>$1</h3>")
    // h4 findings — add severity class
    .replace(/^#### (🔴|🟠|🟡|🔵|✅|🚨|⚠️|💡) (.+)$/gm, (_, icon, title) => {
      const cls = severityClass(icon);
      return `</div><div class="finding ${cls}"><h4>${icon} ${esc(title)}</h4>`;
    })
    .replace(/^#### (.+)$/gm, "</div><div class=\"finding\"><h4>$1</h4>")
    // bold
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    // tables
    .replace(/^\|(.+)\|$/gm, (line) => {
      if (/^[\s|:-]+$/.test(line)) return ""; // separator row
      const cells = line.split("|").slice(1, -1).map(c => c.trim());
      return `<tr>${cells.map(c => `<td>${c}</td>`).join("")}</tr>`;
    })
    // list items
    .replace(/^- (.+)$/gm, "<li>$1</li>")
    // paragraphs (non-empty lines not already tagged)
    .replace(/^(?!<|$|\s)(.+)$/gm, "<p>$1</p>")
    // wrap consecutive <tr> in <table>
    .replace(/(<tr>.*<\/tr>\n?)+/gs, match => `<table>${match}</table>`)
    // wrap consecutive <li> in <ul>
    .replace(/(<li>.*<\/li>\n?)+/gs, match => `<ul>${match}</ul>`);
}

function esc(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function severityClass(icon) {
  if (icon === "🔴" || icon === "🚨") return "sev-critical";
  if (icon === "🟠" || icon === "⚠️") return "sev-high";
  if (icon === "🟡" || icon === "💡") return "sev-medium";
  if (icon === "🔵") return "sev-info";
  if (icon === "✅") return "sev-safe";
  return "";
}

const body = mdToHtml(md);

const html = `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>vibe-sec Report</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    background: #0d0d0d;
    color: #e0e0e0;
    line-height: 1.6;
    padding: 40px 20px;
  }

  .container { max-width: 860px; margin: 0 auto; }

  h1 {
    font-size: 1.8rem;
    font-weight: 700;
    color: #fff;
    margin-bottom: 4px;
  }
  h2 {
    font-size: 1.2rem;
    font-weight: 600;
    color: #aaa;
    text-transform: uppercase;
    letter-spacing: .08em;
    margin: 36px 0 12px;
    padding-bottom: 6px;
    border-bottom: 1px solid #2a2a2a;
  }
  h3 {
    font-size: 1rem;
    color: #888;
    margin: 24px 0 8px;
    font-weight: 600;
  }
  h4 {
    font-size: 1rem;
    font-weight: 700;
    margin-bottom: 10px;
    color: inherit;
  }

  p { color: #bbb; margin: 6px 0; font-size: .95rem; }

  hr { border: none; border-top: 1px solid #222; margin: 28px 0; }

  /* Findings */
  .finding {
    border-radius: 8px;
    padding: 16px 20px;
    margin: 10px 0;
    border-left: 4px solid #333;
    background: #161616;
  }
  .finding ul { margin: 6px 0 6px 18px; }
  .finding li { color: #bbb; font-size: .9rem; margin: 4px 0; }
  .finding strong { color: #ddd; }

  .sev-critical { border-left-color: #e03e3e; background: #1a0e0e; }
  .sev-critical h4 { color: #ff6b6b; }

  .sev-high { border-left-color: #d97706; background: #1a1208; }
  .sev-high h4 { color: #fbbf24; }

  .sev-medium { border-left-color: #b5a016; background: #181500; }
  .sev-medium h4 { color: #e8d44d; }

  .sev-info { border-left-color: #2d6fbd; background: #0c1520; }
  .sev-info h4 { color: #60a5fa; }

  .sev-safe { border-left-color: #16a34a; background: #0b1a0e; }
  .sev-safe h4 { color: #4ade80; }

  /* Tables */
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 12px 0;
    font-size: .9rem;
  }
  td {
    padding: 7px 12px;
    border: 1px solid #2a2a2a;
    color: #ccc;
    vertical-align: top;
  }
  tr:first-child td { background: #1c1c1c; font-weight: 600; color: #eee; }

  /* Code */
  pre.code {
    background: #111;
    border: 1px solid #2a2a2a;
    border-radius: 6px;
    padding: 14px 16px;
    margin: 10px 0;
    overflow-x: auto;
    font-size: .82rem;
    line-height: 1.5;
  }
  pre.bash { border-left: 3px solid #4ade80; }
  code { font-family: "SF Mono", "Fira Code", monospace; }
  code.inline {
    background: #1e1e1e;
    color: #a8d8a8;
    padding: 1px 5px;
    border-radius: 3px;
    font-size: .85em;
  }

  ul { margin: 8px 0 8px 20px; }
  li { color: #bbb; margin: 3px 0; font-size: .93rem; }

  .generated { color: #555; font-size: .8rem; margin-top: 40px; text-align: center; }
</style>
</head>
<body>
<div class="container">
<div class="finding">
${body}
</div>
<p class="generated">Generated by vibe-sec</p>
</div>
</body>
</html>`;

const outFile = inputFile.replace(/\.md$/, ".html");
fs.writeFileSync(outFile, html);
console.log(`✅ ${outFile}`);
