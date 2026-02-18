#!/usr/bin/env node
/**
 * vibe-sec Telemetry
 *
 * Sends anonymous usage events to help us understand how vibe-sec is used
 * and what it actually finds in the wild.
 *
 * ─── What we collect ──────────────────────────────────────────────────────────
 *
 *   device_id     — Random UUID generated once, stored in ~/.config/vibe-sec/device-id.
 *                   Never linked to your name, email, IP, or machine identifier.
 *
 *   event         — What happened: setup_complete, scan_complete, block_triggered,
 *                   report_opened, allow_added, uninstall.
 *
 *   version       — vibe-sec version (e.g. "0.1.0").
 *   os_version    — macOS version string (e.g. "14.4.1").
 *   node_version  — Node.js version (e.g. "v22.0.0").
 *
 *   For scan_complete events:
 *     findings_total    — Total number of findings (integer).
 *     findings_critical — Count of CRITICAL severity findings.
 *     findings_high     — Count of HIGH severity findings.
 *     findings_medium   — Count of MEDIUM severity findings.
 *     finding_types     — Array of category IDs that were triggered, e.g.:
 *                         ["skip_permission_prompt", "env_in_git", "shell_secrets"]
 *                         Never includes file contents, paths, keys, or command text.
 *
 *   For block_triggered events (queued by hook.mjs, flushed on next scan):
 *     block_level  — "L1", "L2", or "L3"
 *     block_type   — Category: "rm_rf", "curl_bash", "wget_sh", "base64_exec",
 *                    "fork_bomb", "sudo_destructive", "exfil", "gemini",
 *                    "protected_file", "shell_config_backdoor"
 *     tool         — Claude Code tool intercepted: "Bash", "Write", or "Edit"
 *     cmd_len      — Length bucket: "xs"(<50), "s"(50-200), "m"(200-500),
 *                    "l"(500-2000), "xl"(2000+). NOT the command itself.
 *     interpreter  — First word if a known interpreter (bash/python/node/etc),
 *                    or "other_cmd". NEVER the actual command.
 *
 *   For scan_complete events, additional fields:
 *     source       — What triggered the scan: "cli", "app", or "daemon"
 *     skipped      — Array of check categories skipped by user (e.g. ["browser"])
 *
 *   For setup_complete events:
 *     daemon_installed  — bool
 *     gemini_configured — bool
 *     ai_tools          — { claude_code, cursor, windsurf, zed, copilot_vscode,
 *                           continue_dev, aider, codeium, tabnine }
 *                         Targeted check against a fixed known list only.
 *                         NOT a full enumeration of /Applications.
 *
 * ─── What we do NOT collect ───────────────────────────────────────────────────
 *
 *   ✗ The actual commands that were blocked
 *   ✗ File paths or file contents
 *   ✗ API keys, tokens, or any credentials
 *   ✗ Full list of installed applications
 *   ✗ Repository names or code you're working on
 *   ✗ Your IP address (not logged server-side)
 *   ✗ Any personally identifiable information
 *
 * ─── Opt out ──────────────────────────────────────────────────────────────────
 *
 *   export VIBE_SEC_TELEMETRY=off        # per-session
 *   touch ~/.config/vibe-sec/.no-telemetry  # permanent
 *   npx vibe-sec telemetry off           # via CLI
 *
 * ─── Source ───────────────────────────────────────────────────────────────────
 *
 *   This file is the complete telemetry implementation. Everything collected
 *   is documented above. You can verify by reading this file.
 */

import fs from "fs";
import path from "path";
import os from "os";
import { spawnSync } from "child_process";

// ─── Configuration ────────────────────────────────────────────────────────────

const TELEMETRY_ENDPOINT = process.env.VIBE_SEC_TELEMETRY_ENDPOINT
  || "https://vibe-sec-telemetry.dev-a96.workers.dev/v1/event";

const home    = os.homedir();
const CONFIG  = path.join(home, ".config", "vibe-sec");
const ID_FILE = path.join(CONFIG, "device-id");
const OPT_OUT = path.join(CONFIG, ".no-telemetry");
const QUEUE   = path.join(CONFIG, "telemetry-queue.jsonl");

// ─── Opt-out ──────────────────────────────────────────────────────────────────

function isOptedOut() {
  if (process.env.VIBE_SEC_TELEMETRY === "off") return true;
  try { fs.accessSync(OPT_OUT); return true; } catch { return false; }
}

// ─── Device ID ────────────────────────────────────────────────────────────────

function getOrCreateDeviceId() {
  try {
    const existing = fs.readFileSync(ID_FILE, "utf8").trim();
    if (/^[0-9a-f-]{36}$/.test(existing)) return existing;
  } catch { /* create new */ }

  const id = crypto.randomUUID();
  try {
    fs.mkdirSync(CONFIG, { recursive: true });
    fs.writeFileSync(ID_FILE, id, { mode: 0o600 });
  } catch { /* non-critical */ }
  return id;
}

// ─── System info ─────────────────────────────────────────────────────────────

function getOsVersion() {
  try {
    return spawnSync("sw_vers", ["-productVersion"], { encoding: "utf8" }).stdout.trim();
  } catch { return os.release(); }
}

function getVibesecVersion() {
  try {
    const pkg = path.resolve(import.meta.dirname, "..", "package.json");
    return JSON.parse(fs.readFileSync(pkg, "utf8")).version || "unknown";
  } catch { return "unknown"; }
}

// ─── AI tools detection ──────────────────────────────────────────────────────
//
// Checks a fixed, explicitly maintained list of known AI coding / vibe-coding
// tools. Does NOT enumerate /Applications or any other directory.
//
// To add a new tool: add an entry to AI_TOOLS_REGISTRY below.
// Update this list as new vibe-coding tools emerge.
//
// Last updated: 2026-02-18

const AI_TOOLS_REGISTRY = [
  // ─── Standalone IDE / AI editors ─────────────────────────────────────────
  { key: "cursor",          type: "app",    value: "/Applications/Cursor.app" },
  { key: "windsurf",        type: "app",    value: "/Applications/Windsurf.app" },
  { key: "zed",             type: "app",    value: "/Applications/Zed.app" },
  { key: "positron",        type: "app",    value: "/Applications/Positron.app" },
  { key: "void_editor",     type: "app",    value: "/Applications/Void.app" },
  { key: "pearai",          type: "app",    value: "/Applications/PearAI.app" },
  { key: "trae",            type: "app",    value: "/Applications/Trae.app" },

  // ─── Claude / Anthropic ───────────────────────────────────────────────────
  { key: "claude_code",     type: "dir",    value: "~/.claude" },
  { key: "claude_desktop",  type: "app",    value: "/Applications/Claude.app" },

  // ─── Terminal AI coding agents ────────────────────────────────────────────
  { key: "aider",           type: "bin",    value: "aider" },
  { key: "goose",           type: "bin",    value: "goose" },
  { key: "amp",             type: "bin",    value: "amp" },
  { key: "devon",           type: "bin",    value: "devin" },
  { key: "codex_cli",       type: "bin",    value: "codex" },
  { key: "openai_swarm",    type: "dir",    value: "~/.openai-swarm" },

  // ─── VS Code extensions ───────────────────────────────────────────────────
  { key: "copilot_vscode",  type: "vsext",  value: "github.copilot" },
  { key: "continue_dev",    type: "vsext",  value: "continue." },
  { key: "codeium",         type: "vsext",  value: "codeium." },
  { key: "tabnine",         type: "vsext",  value: "tabnine." },
  { key: "supermaven",      type: "vsext",  value: "supermaven." },
  { key: "aws_codewhisperer",type:"vsext",  value: "amazonwebservices.aws-toolkit" },
  { key: "sourcegraph_cody",type: "vsext",  value: "sourcegraph.cody" },
  { key: "double",          type: "vsext",  value: "double-bot." },
  { key: "blackbox",        type: "vsext",  value: "blackboxapp." },

  // ─── JetBrains AI plugins ─────────────────────────────────────────────────
  { key: "jetbrains_ai",    type: "dir",    value: "~/Library/Application Support/JetBrains" },

  // ─── Replit / browser-based ───────────────────────────────────────────────
  { key: "replit_agent",    type: "dir",    value: "~/.replit" },
  { key: "bolt",            type: "dir",    value: "~/.bolt" },

  // ─── MCP-related tooling ─────────────────────────────────────────────────
  { key: "mcp_inspector",   type: "bin",    value: "mcp" },
];

export function detectAiTools() {
  function hasApp(p)    { try { return fs.existsSync(p); } catch { return false; } }
  function hasDir(p)    { return hasApp(p.replace(/^~/, home)); }
  function hasBin(cmd)  { return spawnSync("which", [cmd], { stdio: "ignore" }).status === 0; }
  function hasVsExt(prefix) {
    try {
      const extDir = path.join(home, ".vscode", "extensions");
      return fs.readdirSync(extDir).some(d => d.startsWith(prefix));
    } catch { return false; }
  }

  const result = {};
  for (const { key, type, value } of AI_TOOLS_REGISTRY) {
    try {
      result[key] = type === "app"   ? hasApp(value)
                  : type === "dir"   ? hasDir(value)
                  : type === "bin"   ? hasBin(value)
                  : type === "vsext" ? hasVsExt(value)
                  : false;
    } catch { result[key] = false; }
  }
  return result;
}

// ─── Finding category mapper ──────────────────────────────────────────────────
// Maps finding titles (from scan-logs.mjs) to stable category IDs.
// Adding new rules here is enough — no changes needed in scan-logs.mjs.

const FINDING_CATEGORY_MAP = [
  [/skipDangerousModePermissionPrompt/,   "skip_permission_prompt"],
  [/MCP token in plaintext/,              "mcp_token_plaintext"],
  [/MCP servers without pinned version/,  "mcp_unpinned_version"],
  [/Secrets in shell history/,            "shell_history_secrets"],
  [/Ports listening on all interfaces/,   "open_ports_all_interfaces"],
  [/\.env files tracked in git/,          "env_in_git"],
  [/Secrets in git history/,              "secrets_in_git_history"],
  [/Service Account key/,                 "service_account_key"],
  [/CLI token in config/,                 "cli_token_config"],
  [/Claude paste cache/,                  "claude_paste_cache"],
  [/Claude shell snapshots/,              "claude_snapshots"],
  [/Firewall disabled/,                   "firewall_disabled"],
  [/CLAUDE\.md has no prompt injection/,  "no_injection_guard"],
  [/CLAUDE\.md not found/,                "no_claude_md"],
  [/Prompt injection indicators/,         "injection_signs_in_logs"],
  [/suspicious tool name/i,               "suspicious_mcp_tool_name"],
  [/suspicious instructions/i,            "suspicious_mcp_instructions"],
  [/suspicious capabilities/i,            "suspicious_mcp_capabilities"],
  [/Telegram.*token/i,                    "clawdbot_telegram_token"],
  [/Gateway.*token/i,                     "clawdbot_gateway_token"],
  [/running as root/i,                    "running_as_root"],
  [/Time Machine/i,                       "no_time_machine_backup"],
  [/\.claudeignore/i,                     "claudeignore_cve"],
  [/AI artifacts.*git/i,                  "ai_artifacts_committed"],
  [/without remote/i,                     "repos_without_remote"],
];

export function categorizeFindings(findings) {
  const types = new Set();
  for (const f of findings) {
    const title = f.title || "";
    for (const [pattern, category] of FINDING_CATEGORY_MAP) {
      if (pattern.test(title)) {
        types.add(category);
        break;
      }
    }
  }
  return [...types];
}

// ─── Queue (for hook.mjs — sync, zero-latency) ────────────────────────────────

/**
 * Write an event to the local queue file synchronously.
 * Used by hook.mjs which must not make network calls.
 * The queue is flushed on the next scan or daemon run.
 */
export function queueEvent(event, properties = {}) {
  if (isOptedOut()) return;
  try {
    fs.mkdirSync(CONFIG, { recursive: true });
    const entry = JSON.stringify({ event, ...properties, _queued_at: new Date().toISOString() });
    fs.appendFileSync(QUEUE, entry + "\n");
  } catch { /* non-critical */ }
}

/**
 * Flush queued events to the telemetry endpoint.
 * Call this from long-running processes (scan, setup) where network I/O is fine.
 */
export async function flushQueue() {
  if (isOptedOut()) return;
  let entries = [];
  try {
    entries = fs.readFileSync(QUEUE, "utf8")
      .split("\n")
      .filter(Boolean)
      .map(l => { try { return JSON.parse(l); } catch { return null; } })
      .filter(Boolean);
    fs.writeFileSync(QUEUE, ""); // clear queue before sending (prevent duplicates on failure)
  } catch { return; } // no queue or empty

  const base = {
    device_id:    getOrCreateDeviceId(),
    version:      getVibesecVersion(),
    os_version:   getOsVersion(),
    node_version: process.version,
  };

  for (const entry of entries) {
    const { _queued_at, ...props } = entry;
    await send({ ...base, ts: _queued_at || new Date().toISOString(), ...props });
  }
}

// ─── Direct track ─────────────────────────────────────────────────────────────

/**
 * Send a telemetry event immediately. Fire-and-forget — never blocks, never throws.
 */
export async function track(event, properties = {}) {
  if (isOptedOut()) return;
  try {
    await send({
      event,
      device_id:    getOrCreateDeviceId(),
      version:      getVibesecVersion(),
      os_version:   getOsVersion(),
      node_version: process.version,
      ts:           new Date().toISOString(),
      ...properties,
    });
  } catch { /* silent */ }
}

async function send(payload) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);
    fetch(TELEMETRY_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal,
    }).finally(() => clearTimeout(timeout)).catch(() => { /* silent */ });
  } catch { /* silent */ }
}

// ─── Opt-out management ───────────────────────────────────────────────────────

export function setOptOut(value) {
  fs.mkdirSync(CONFIG, { recursive: true });
  if (value) {
    fs.writeFileSync(OPT_OUT, "");
    console.log("✅ Telemetry disabled. No data will be sent.");
    console.log(`   To re-enable: rm ${OPT_OUT}`);
  } else {
    try { fs.unlinkSync(OPT_OUT); } catch { /* ok */ }
    console.log("✅ Telemetry enabled. Thank you for helping improve vibe-sec.");
    console.log("   See scripts/telemetry.mjs for exactly what is collected.");
  }
}

export function showTelemetryStatus() {
  const opted = isOptedOut();
  const id = opted ? "N/A" : getOrCreateDeviceId();
  console.log(`
vibe-sec telemetry: ${opted ? "DISABLED ✗" : "ENABLED ✓"}

${opted ? "   No data is being sent.\n" : `Device ID:  ${id}
Endpoint:   ${TELEMETRY_ENDPOINT}
`}
What is collected (when enabled):
  ✓ Anonymous random UUID (never linked to identity)
  ✓ Event type: setup, scan, block, report, allow
  ✓ Scan: finding counts and category IDs (NOT content)
  ✓ Block: level, type, tool (NOT the command itself)
  ✓ OS version, Node version, vibe-sec version
  ✓ Presence of known AI tools (hardcoded list check only)

What is NOT collected:
  ✗ Blocked command content
  ✗ File paths or file contents
  ✗ API keys, tokens, or credentials
  ✗ Full list of installed applications
  ✗ Repository names or code

Source:  scripts/telemetry.mjs (read it to verify)
Opt out: npx vibe-sec telemetry off
         export VIBE_SEC_TELEMETRY=off
         touch ~/.config/vibe-sec/.no-telemetry
`);
}
