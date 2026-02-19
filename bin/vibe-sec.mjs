#!/usr/bin/env node
/**
 * vibe-sec CLI — entry point for `npx vibe-sec`
 *
 * Safety net for vibe coding.
 *
 * Usage:
 *   npx vibe-sec              # setup (first run) or show status
 *   npx vibe-sec setup        # install hooks + daemon
 *   npx vibe-sec scan         # run log scanner (static, fast)
 *   npx vibe-sec scan --full  # full scan with Gemini AI analysis
 *   npx vibe-sec report       # open HTML report at localhost:7777
 *   npx vibe-sec status       # show current security score
 *   npx vibe-sec allow        # manage allowlist exceptions
 *   npx vibe-sec uninstall    # remove vibe-sec
 */

import fs from "fs";
import path from "path";
import os from "os";
import { execFileSync, spawnSync } from "child_process";
import readline from "readline";

const home = os.homedir();
const CONFIG_DIR    = path.join(home, ".config", "vibe-sec");
const SCRIPTS_DIR   = path.join(CONFIG_DIR, "scripts");
const PKG_SCRIPTS   = path.resolve(import.meta.dirname, "..", "scripts");

const [, , cmd, ...args] = process.argv;

// ─── ANSI colors ─────────────────────────────────────────────────────────────

const c = {
  reset:  "\x1b[0m",
  bold:   "\x1b[1m",
  red:    "\x1b[31m",
  yellow: "\x1b[33m",
  green:  "\x1b[32m",
  cyan:   "\x1b[36m",
  grey:   "\x1b[90m",
  dim:    "\x1b[2m",
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

function isInstalled() {
  return fs.existsSync(path.join(SCRIPTS_DIR, "hook.mjs"));
}

function runScript(scriptName, scriptArgs = [], opts = {}) {
  const scriptPath = path.join(SCRIPTS_DIR, scriptName);
  return execFileSync(process.execPath, [scriptPath, ...scriptArgs], {
    stdio: "inherit",
    cwd: CONFIG_DIR,
    ...opts,
  });
}

function getVersion() {
  try {
    const pkgPath = path.resolve(import.meta.dirname, "..", "package.json");
    return JSON.parse(fs.readFileSync(pkgPath, "utf8")).version || "?";
  } catch { return "?"; }
}

async function ask(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(question, ans => { rl.close(); resolve(ans.trim()); }));
}

// For "Y/n" prompts (default yes): only n/no/nope/nah cancels
function isNo(s) { return /^n/i.test(s); }
// For "y/N" prompts (default no): only y/yes proceeds
function isYes(s) { return /^y/i.test(s); }

function requireInstalled() {
  if (!isInstalled()) {
    console.error(`${c.red}❌  vibe-sec is not installed. Run: npx vibe-sec setup${c.reset}`);
    process.exit(1);
  }
}

// Lazy telemetry import (works both from npm package and installed scripts)
let _telemetry = null;
async function getTelemetry() {
  if (_telemetry) return _telemetry;
  try {
    // Try installed scripts first (for when user has vibe-sec installed)
    const installedPath = path.join(SCRIPTS_DIR, "telemetry.mjs");
    if (fs.existsSync(installedPath)) {
      _telemetry = await import(installedPath);
    } else {
      // Fall back to package scripts (during first setup)
      const pkgPath = path.resolve(import.meta.dirname, "..", "scripts", "telemetry.mjs");
      _telemetry = await import(pkgPath);
    }
  } catch { _telemetry = null; }
  return _telemetry;
}

function installScripts() {
  fs.mkdirSync(SCRIPTS_DIR, { recursive: true });
  const files = fs.readdirSync(PKG_SCRIPTS).filter(f => f.endsWith(".mjs"));
  for (const f of files) {
    const src = path.join(PKG_SCRIPTS, f);
    const dst = path.join(SCRIPTS_DIR, f);
    fs.copyFileSync(src, dst);
    fs.chmodSync(dst, 0o755);
  }
  return files.length;
}

// ─── setup ───────────────────────────────────────────────────────────────────

async function setup() {
  const version = getVersion();

  if (isInstalled()) {
    console.log(`${c.green}✅  vibe-sec ${version} is already installed.${c.reset}\n`);
    await showStatus();
    console.log(`\nRun ${c.bold}npx vibe-sec scan${c.reset} to refresh, or ${c.bold}npx vibe-sec report${c.reset} to open the HTML report.`);
    return;
  }

  console.log(`
${c.bold}vibe-sec ${version}${c.reset}  Safety net for vibe coding

What will be installed:
  ${c.bold}🛡️  Hook Guard${c.reset}   Intercepts every command before it runs — blocks attacks instantly
  ${c.bold}🔍  Log Scanner${c.reset}  Scans session history for secrets that accidentally leaked
`);

  const go = await ask(`Install to ${CONFIG_DIR}? (Y/n): `);
  if (isNo(go)) {
    console.log("Cancelled.");
    process.exit(0);
  }

  // 1. Copy scripts
  process.stdout.write(`\n${c.cyan}[1/4]${c.reset} Copying scripts... `);
  const count = installScripts();
  console.log(`${c.green}${count} files${c.reset}`);

  // 2. Install hooks
  process.stdout.write(`${c.cyan}[2/4]${c.reset} Installing Claude Code hook guard...\n`);
  try {
    runScript("install-hooks.mjs");
  } catch (e) {
    console.error(`${c.red}     Failed: ${e.message}${c.reset}`);
  }

  // 3. Background daemon
  const daemonAns = await ask(`\n${c.cyan}[3/4]${c.reset} Install background daily scanner? (Y/n): `);
  if (!isNo(daemonAns)) {
    try {
      runScript("setup-daemon.mjs");
    } catch (e) {
      console.error(`${c.yellow}     Warning: daemon install failed: ${e.message}${c.reset}`);
    }
  } else {
    console.log(`     ${c.dim}Skipped. You can install later with: npx vibe-sec setup-daemon${c.reset}`);
  }

  // 4. Gemini API key (optional)
  console.log(`\n${c.cyan}[4/4]${c.reset} Gemini API key for deep log analysis ${c.dim}(optional)${c.reset}`);
  console.log(`     Get a free key at https://aistudio.google.com/apikey`);
  const geminiKey = await ask(`     API key (press Enter to skip): `);
  if (geminiKey) {
    const envFile = path.join(CONFIG_DIR, ".env");
    fs.writeFileSync(envFile, `GEMINI_API_KEY=${geminiKey}\n`, { mode: 0o600 });
    console.log(`     ${c.green}Saved to ${envFile}${c.reset}`);
  } else {
    console.log(`     ${c.dim}Skipped. Static analysis only (still catches most issues).${c.reset}`);
  }

  // First scan
  console.log(`\n${c.bold}Running first security scan...${c.reset}\n${"─".repeat(60)}`);
  const env = { ...process.env };
  if (geminiKey) env.GEMINI_API_KEY = geminiKey;
  try {
    runScript("scan-logs.mjs", ["--static-only"], { env });
  } catch { /* scan exits non-zero if findings — that's fine */ }
  console.log("─".repeat(60));

  console.log(`
${c.green}${c.bold}✅  vibe-sec is installed and active!${c.reset}

${c.bold}Next steps:${c.reset}
  ${c.bold}npx vibe-sec report${c.reset}   Open the full HTML report
  ${c.bold}npx vibe-sec scan${c.reset}     Re-scan at any time
  ${c.bold}npx vibe-sec allow${c.reset}    Manage allowlist exceptions

${c.dim}Hook guard is now active in every new Claude Code session.${c.reset}
`);

  // Telemetry: setup completed
  const tel = await getTelemetry();
  if (tel) {
    try {
      await tel.track("setup_complete", {
        daemon_installed:  !isNo(daemonAns),
        gemini_configured: !!geminiKey,
        ai_tools:         tel.detectAiTools(),
      });
      await tel.flushQueue();
    } catch {}
  }
}

// ─── scan ────────────────────────────────────────────────────────────────────

function scan() {
  requireInstalled();
  const isFull = args.includes("--full");
  const extraArgs = args.filter(a => a !== "--full");
  const scanArgs = isFull ? [...extraArgs] : ["--static-only", ...extraArgs];
  try {
    runScript("scan-logs.mjs", scanArgs);
  } catch { /* non-zero exit when findings exist — not an error */ }
}

// ─── report ──────────────────────────────────────────────────────────────────

async function report() {
  requireInstalled();
  const tel = await getTelemetry();
  if (tel) { try { await tel.track("report_opened"); } catch {} }
  runScript("serve-report.mjs");
}

// ─── status ──────────────────────────────────────────────────────────────────

async function showStatus() {
  if (!isInstalled()) {
    console.log(`${c.yellow}⚠   vibe-sec is not installed.${c.reset}`);
    console.log(`    Run: ${c.bold}npx vibe-sec setup${c.reset}`);
    return;
  }

  // Find latest report
  let reportFiles = [];
  try {
    reportFiles = fs.readdirSync(CONFIG_DIR)
      .filter(f => f.startsWith("vibe-sec-log-report-") && f.endsWith(".md"))
      .sort();
  } catch {}

  if (reportFiles.length === 0) {
    console.log(`${c.grey}No scan results yet.${c.reset}`);
    console.log(`Run: ${c.bold}npx vibe-sec scan${c.reset}`);
    return;
  }

  const latest = path.join(CONFIG_DIR, reportFiles[reportFiles.length - 1]);
  const content = fs.readFileSync(latest, "utf8");

  // Extract score
  // Primary: machine-readable comment added by scan-logs
  const hiddenM = content.match(/<!--\s*findings:\s*(\d+)\s*-->/i);
  // Fallback: "No static issues found" means 0
  const isClean = /no static issues found/i.test(content);
  // Fallback: count from verbose verdict note (adds critical + high)
  const verboseM = content.match(/\*\*(\d+)\s+critical[^*]*?(\d+)\s+high-severity/i);

  const score = hiddenM
    ? parseInt(hiddenM[1])
    : isClean
      ? 0
      : verboseM
        ? parseInt(verboseM[1]) + parseInt(verboseM[2])
        : null;

  const dot   = score === 0 ? `${c.green}●${c.reset}` : score !== null && score > 5 ? `${c.red}●${c.reset}` : `${c.yellow}●${c.reset}`;
  const label = score === 0 ? `${c.green}clean${c.reset}` : score !== null ? `${c.yellow}${score} findings${c.reset}` : `${c.grey}unknown${c.reset}`;

  const dateStr = reportFiles[reportFiles.length - 1]
    .replace("vibe-sec-log-report-", "")
    .replace(".md", "");

  console.log(`${dot}  Security: ${label}  ${c.dim}(last scan: ${dateStr})${c.reset}`);
}

// ─── allow ───────────────────────────────────────────────────────────────────

function allow() {
  requireInstalled();
  runScript("allow.mjs", args);
}

// ─── uninstall ───────────────────────────────────────────────────────────────

async function uninstall() {
  requireInstalled();
  const ans = await ask(`${c.yellow}Remove vibe-sec hooks, daemon, and config? (y/N): ${c.reset}`);
  if (!isYes(ans)) { console.log("Cancelled."); return; }

  const tel = await getTelemetry();
  if (tel) {
    try { await tel.track("uninstall"); await tel.flushQueue(); } catch {}
  }

  try { runScript("install-hooks.mjs", ["--remove"]); } catch {}
  try { runScript("setup-daemon.mjs",  ["--remove"]); } catch {}

  fs.rmSync(SCRIPTS_DIR, { recursive: true, force: true });

  console.log(`${c.green}✅  vibe-sec uninstalled.${c.reset}`);
  console.log(`    Config dir ${CONFIG_DIR} is kept (scan results, allowlist).`);
  console.log(`    Remove manually if not needed: ${c.dim}rm -rf ${CONFIG_DIR}${c.reset}`);
}

// ─── help ────────────────────────────────────────────────────────────────────

function help() {
  const v = getVersion();
  console.log(`
${c.bold}vibe-sec ${v}${c.reset}  Safety net for vibe coding

${c.bold}Usage:${c.reset}
  npx vibe-sec              Setup (first run) or show status
  npx vibe-sec setup        Install hook guard + background scanner
  npx vibe-sec scan         Run log scanner (fast, no API key needed)
  npx vibe-sec scan --full  Full scan with Gemini AI analysis
  npx vibe-sec report       Open HTML report at localhost:7777
  npx vibe-sec status       Show status and current score
  npx vibe-sec allow        Allow a previously blocked command
  npx vibe-sec uninstall    Remove vibe-sec
  npx vibe-sec telemetry        Show telemetry status
  npx vibe-sec telemetry off    Disable telemetry
  npx vibe-sec telemetry on     Enable telemetry

${c.bold}Environment:${c.reset}
  GEMINI_API_KEY=...        Enable deep log analysis
  VIBE_SEC_GUARD=off        Disable hook guard for current session

${c.bold}Config:${c.reset}
  ${CONFIG_DIR}
`);
}

// ─── Route ───────────────────────────────────────────────────────────────────

if (!cmd || cmd === "setup") {
  await setup();
} else if (cmd === "scan") {
  scan();
} else if (cmd === "report") {
  await report();
} else if (cmd === "status") {
  await showStatus();
} else if (cmd === "allow") {
  allow();
} else if (cmd === "uninstall") {
  await uninstall();
} else if (cmd === "--help" || cmd === "-h" || cmd === "help") {
  help();
} else if (cmd === "telemetry") {
  const tel = await getTelemetry();
  if (!tel) { console.error("vibe-sec not installed"); process.exit(1); }
  const subCmd = args[0];
  if (subCmd === "off") tel.setOptOut(true);
  else if (subCmd === "on") tel.setOptOut(false);
  else tel.showTelemetryStatus();
} else {
  console.error(`${c.red}Unknown command: ${cmd}${c.reset}\n`);
  help();
  process.exit(1);
}
