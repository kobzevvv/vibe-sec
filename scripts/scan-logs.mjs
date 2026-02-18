#!/usr/bin/env node
/**
 * vibe-sec: Local Claude Code log scanner powered by Gemini 1.5 Flash (1M context).
 *
 * Scans ~/.claude/ logs for security threats:
 *   - Accidentally pasted API tokens/keys in prompts
 *   - Suspicious domains accessed during sessions
 *   - Exposed credentials in bash commands
 *   - Unusual auth activity
 *
 * Usage:
 *   GEMINI_API_KEY=your_key node scripts/scan-logs.mjs
 *   # or
 *   node scripts/scan-logs.mjs --key your_key
 *
 * Output: threat analysis WITHOUT actual secret values (just descriptions).
 */

import fs from "fs";
import path from "path";
import os from "os";
import readline from "readline";

// ─── Config ──────────────────────────────────────────────────────────────────

const GEMINI_API_KEY = process.env.GEMINI_API_KEY ||
  process.argv.find((a, i) => process.argv[i - 1] === "--key");

const CLAUDE_DIR = path.join(os.homedir(), ".claude");
const MAX_CHARS = 700_000; // ~175K tokens — fits Gemini free tier (250k/min limit)
const CHARS_PER_TOKEN = 4;

// Security-relevant patterns to extract from debug logs (skip noise)
const SECURITY_RELEVANT = [
  /token/i, /secret/i, /key/i, /password/i, /credential/i,
  /auth/i, /oauth/i, /bearer/i, /api\./, /curl/i,
  /https?:\/\//,        // any URL
  /\.env/i,             // env file references
  /github\.com/i,
  /sk-/, /AKIA/,        // known secret prefixes
  /process\.env/i,
  /Error/i, /Failed/i,  // errors might reveal context
  /remote-debugging/i,
  /mcp/i,               // MCP server activity
];

// ─── Log readers ─────────────────────────────────────────────────────────────

function readHistoryLog() {
  const file = path.join(CLAUDE_DIR, "history.jsonl");
  if (!fs.existsSync(file)) return "";

  const lines = fs.readFileSync(file, "utf8").trim().split("\n");
  const entries = lines
    .map(l => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean);

  const out = ["=== CLAUDE CODE PROMPT HISTORY (history.jsonl) ==="];
  for (const e of entries) {
    const ts = new Date(e.timestamp).toISOString().slice(0, 16);
    const project = (e.project || "").split("/").pop();
    const text = (e.display || "").slice(0, 500); // truncate very long prompts
    out.push(`[${ts}] [${project}] ${text}`);
  }
  return out.join("\n");
}

function readDebugLogs() {
  const dir = path.join(CLAUDE_DIR, "debug");
  if (!fs.existsSync(dir)) return "";

  const files = fs.readdirSync(dir)
    .filter(f => f.endsWith(".txt"))
    .map(f => ({ name: f, mtime: fs.statSync(path.join(dir, f)).mtime }))
    .sort((a, b) => b.mtime - a.mtime) // newest first
    .slice(0, 20); // last 20 sessions

  const out = ["=== CLAUDE CODE DEBUG LOGS (last 20 sessions) ==="];
  let totalChars = 0;
  const budget = MAX_CHARS * 0.5; // give half budget to debug logs

  for (const { name, mtime } of files) {
    if (totalChars > budget) break;
    const content = fs.readFileSync(path.join(dir, name), "utf8");
    const relevantLines = content
      .split("\n")
      .filter(line => SECURITY_RELEVANT.some(re => re.test(line)));

    if (relevantLines.length === 0) continue;

    out.push(`\n--- Session: ${name} (${mtime.toISOString().slice(0, 16)}) ---`);
    for (const line of relevantLines) {
      out.push(line.slice(0, 300)); // cap line length
      totalChars += line.length;
      if (totalChars > budget) break;
    }
  }

  return out.join("\n");
}

function readSessionBashCommands() {
  const projectsDir = path.join(CLAUDE_DIR, "projects");
  if (!fs.existsSync(projectsDir)) return "";

  const out = ["=== BASH COMMANDS FROM CLAUDE CODE SESSIONS ==="];
  let totalChars = 0;
  const budget = MAX_CHARS * 0.3;

  const allJsonl = fs.readdirSync(projectsDir, { withFileTypes: true })
    .flatMap(entry => {
      if (entry.isDirectory()) {
        const dir = path.join(projectsDir, entry.name);
        return fs.readdirSync(dir)
          .filter(f => f.endsWith(".jsonl"))
          .map(f => path.join(dir, f));
      }
      return entry.name.endsWith(".jsonl") ? [path.join(projectsDir, entry.name)] : [];
    })
    .map(f => ({ file: f, mtime: fs.statSync(f).mtime }))
    .sort((a, b) => b.mtime - a.mtime)
    .slice(0, 10); // last 10 sessions

  for (const { file } of allJsonl) {
    if (totalChars > budget) break;

    const lines = fs.readFileSync(file, "utf8").trim().split("\n");
    const commands = [];

    for (const line of lines) {
      try {
        const entry = JSON.parse(line);
        // Extract bash tool calls from session snapshots
        const snap = JSON.stringify(entry.snapshot || entry);
        const bashMatches = snap.match(/"command"\s*:\s*"([^"]{1,300})"/g) || [];
        for (const m of bashMatches) {
          const cmd = m.replace(/"command"\s*:\s*"/, "").replace(/"$/, "");
          if (cmd.length > 5) commands.push(cmd);
        }
      } catch { /* skip malformed */ }
    }

    if (commands.length > 0) {
      out.push(`\n--- ${path.basename(file)} ---`);
      for (const cmd of commands.slice(0, 50)) {
        out.push(cmd);
        totalChars += cmd.length;
      }
    }
  }

  return out.join("\n");
}

// ─── Gemini call ─────────────────────────────────────────────────────────────

async function analyzeWithGemini(logContent) {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${GEMINI_API_KEY}`;

  const prompt = `You are a security analyst reviewing AI coding tool logs for a developer.

Analyze the following Claude Code logs and identify potential security threats.

IMPORTANT RULES:
- DO NOT reproduce any actual secret values, API keys, tokens, or passwords in your response
- Describe threats by TYPE and LOCATION only (e.g. "OpenAI API key found in prompt from Feb 15, project tutors-arcanum")
- Group findings by severity: CRITICAL, HIGH, MEDIUM, LOW
- For each finding include: what it is, where it was found (session/date/project), and how to fix it
- If something is clearly NOT a threat (test values, example placeholders), skip it
- Focus on: leaked tokens/keys in prompts, suspicious external domains, exposed credentials in bash commands, unusual auth patterns, data that shouldn't be in logs

Respond in this format:
## Security Scan Report

### Summary
[N] findings: [X] critical, [X] high, [X] medium, [X] low

### Findings

#### [SEVERITY] [Short title]
- **Found in**: [session/date/file]
- **What happened**: [description without actual secret value]
- **Risk**: [what could happen]
- **Fix**: [concrete action to take]

---

### Clean Areas
[List things that looked fine]

--- LOGS START ---
${logContent}
--- LOGS END ---`;

  const estimatedTokens = Math.round(prompt.length / CHARS_PER_TOKEN);
  console.log(`\n📊 Sending ~${estimatedTokens.toLocaleString()} tokens to Gemini...`);

  let res;
  for (let attempt = 1; attempt <= 3; attempt++) {
    res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.1, maxOutputTokens: 65536 },
      }),
    });
    if (res.ok) break;
    const errBody = await res.json().catch(() => ({}));
    const retryDelay = errBody?.error?.details?.find(d => d.retryDelay)?.retryDelay;
    if (res.status === 429 && attempt < 3) {
      const wait = retryDelay ? parseInt(retryDelay) * 1000 : 15000;
      console.log(`⏳ Rate limit hit, retrying in ${wait/1000}s... (attempt ${attempt}/3)`);
      await new Promise(r => setTimeout(r, wait));
    } else {
      throw new Error(`Gemini API error ${res.status}: ${JSON.stringify(errBody).slice(0,300)}`);
    }
  }

  const data = await res.json();
  return data.candidates?.[0]?.content?.parts?.[0]?.text || "No response from Gemini";
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  console.log("🔍 vibe-sec: Local Claude Code log scanner\n");

  // Ask for API key if not provided
  if (!GEMINI_API_KEY) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    await new Promise(resolve => {
      rl.question("Enter your Gemini API key (get one at aistudio.google.com/apikey): ", key => {
        process.env.GEMINI_API_KEY = key.trim();
        rl.close();
        resolve();
      });
    });
    if (!process.env.GEMINI_API_KEY) {
      console.error("❌ No API key provided. Exiting.");
      process.exit(1);
    }
    // Re-run with the key set
    const { execSync } = await import("child_process");
    execSync(`GEMINI_API_KEY=${process.env.GEMINI_API_KEY} node ${process.argv[1]}`, {
      stdio: "inherit",
      env: { ...process.env, GEMINI_API_KEY: process.env.GEMINI_API_KEY },
    });
    return;
  }

  console.log("📂 Reading Claude Code logs...");

  const history = readHistoryLog();
  const debug = readDebugLogs();
  const commands = readSessionBashCommands();

  const combined = [history, debug, commands].join("\n\n");
  const totalChars = combined.length;
  const estimatedTokens = Math.round(totalChars / CHARS_PER_TOKEN);

  console.log(`   history.jsonl:    ${history.length.toLocaleString()} chars`);
  console.log(`   debug logs:       ${debug.length.toLocaleString()} chars`);
  console.log(`   session commands: ${commands.length.toLocaleString()} chars`);
  console.log(`   ─────────────────────────────`);
  console.log(`   Total:            ${totalChars.toLocaleString()} chars (~${estimatedTokens.toLocaleString()} tokens)`);

  if (estimatedTokens > 900_000) {
    console.warn("\n⚠️  Content exceeds 900K tokens. Trimming to fit Gemini 1M context...");
    // Already handled by MAX_CHARS limit above
  }

  console.log("\n⏳ Analyzing with Gemini 1.5 Flash...");

  const report = await analyzeWithGemini(combined.slice(0, MAX_CHARS));

  console.log("\n" + "═".repeat(60));
  console.log(report);
  console.log("═".repeat(60));

  // Save report to file
  const outFile = `vibe-sec-log-report-${new Date().toISOString().slice(0, 10)}.md`;
  fs.writeFileSync(outFile, `# vibe-sec Log Scan Report\nGenerated: ${new Date().toISOString()}\n\n${report}`);
  console.log(`\n✅ Report saved to ${outFile}`);
}

main().catch(err => {
  console.error("❌ Error:", err.message);
  process.exit(1);
});
