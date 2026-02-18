#!/usr/bin/env node
/**
 * vibe-sec: Install / Remove PreToolUse Guard Hook
 *
 * Usage:
 *   node scripts/install-hooks.mjs          # install
 *   node scripts/install-hooks.mjs --remove # remove
 */

import fs from "fs";
import path from "path";
import os from "os";

const REMOVE = process.argv.includes("--remove");
const HOOK_SCRIPT = path.resolve(import.meta.dirname, "hook.mjs");
const SETTINGS_FILE = path.join(os.homedir(), ".claude", "settings.json");

// ─── Read current settings ────────────────────────────────────────────────────

let settings = {};
try {
  settings = JSON.parse(fs.readFileSync(SETTINGS_FILE, "utf8"));
} catch {
  settings = {};
}

// ─── Remove mode ─────────────────────────────────────────────────────────────

if (REMOVE) {
  const hooks = settings?.hooks?.PreToolUse;
  if (!Array.isArray(hooks)) {
    console.log("ℹ️  vibe-sec guard hook not found in settings — nothing to remove.");
    process.exit(0);
  }

  settings.hooks.PreToolUse = hooks.filter(
    h => !h.hooks?.some(c => c.command?.includes("vibe-sec") || c.command?.includes("hook.mjs"))
  );
  if (settings.hooks.PreToolUse.length === 0) delete settings.hooks.PreToolUse;
  if (Object.keys(settings.hooks || {}).length === 0) delete settings.hooks;

  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2));
  console.log("✅ vibe-sec guard hook removed from ~/.claude/settings.json");
  process.exit(0);
}

// ─── Install mode ─────────────────────────────────────────────────────────────

if (!fs.existsSync(HOOK_SCRIPT)) {
  console.error(`❌ Hook script not found: ${HOOK_SCRIPT}`);
  process.exit(1);
}

// Check if already installed
const existingHooks = settings?.hooks?.PreToolUse || [];
const alreadyInstalled = existingHooks.some(
  h => h.hooks?.some(c => c.command?.includes("hook.mjs"))
);
if (alreadyInstalled) {
  console.log("ℹ️  vibe-sec guard hook already installed.");
  process.exit(0);
}

// Add hook entry
if (!settings.hooks) settings.hooks = {};
if (!settings.hooks.PreToolUse) settings.hooks.PreToolUse = [];

settings.hooks.PreToolUse.push({
  matcher: ".*",   // intercept ALL tools (Bash, Write, Edit, etc.)
  hooks: [
    {
      type: "command",
      command: `node ${HOOK_SCRIPT}`,
    },
  ],
});

fs.mkdirSync(path.dirname(SETTINGS_FILE), { recursive: true });
fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2));

console.log(`
✅ vibe-sec guard hook installed!

Hook script: ${HOOK_SCRIPT}
Settings:    ${SETTINGS_FILE}

What's protected:
  🛡️  Level 1 — Catastrophic commands (rm -rf ~, curl|bash, fork bombs)
  🛡️  Level 2 — Prompt injection: sensitive file + network exfiltration
  🛡️  Level 3 — Gemini semantic analysis (if GEMINI_API_KEY is set)

Emergency override (if hook blocks something legitimate):
  export VIBE_SEC_GUARD=off   # disables for current shell session

To remove:
  npm run remove-hooks
`);
