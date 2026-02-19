#!/usr/bin/env node
/**
 * vibe-sec: Manage the L2/L3 allowlist
 *
 * Usage:
 *   npm run allow -- 'regex-pattern'     # add pattern (allow matching commands)
 *   npm run allow-last                   # allow last blocked command
 *   npm run allowlist                    # show current allowlist
 *   npm run allowlist -- --clear         # remove all allowlist entries
 */

import fs from "fs";
import path from "path";
import os from "os";
import readline from "readline/promises";

const home = os.homedir();
const CONFIG_DIR   = path.join(home, ".config", "vibe-sec");
const ALLOWLIST    = path.join(CONFIG_DIR, "allowlist");
const BLOCKED_LOG  = path.join(CONFIG_DIR, "blocked.log");

fs.mkdirSync(CONFIG_DIR, { recursive: true });

// ─── Subcommands ──────────────────────────────────────────────────────────────

const args = process.argv.slice(2);

// npm run allowlist
if (process.argv[1].includes("allow.mjs") && !args.length && process.env.npm_lifecycle_event === "allowlist") {
  showAllowlist();
  process.exit(0);
}

// npm run allowlist -- --clear
if (args.includes("--clear")) {
  try { fs.writeFileSync(ALLOWLIST, ""); } catch { /* empty */ }
  console.log("✅ Allowlist cleared.");
  process.exit(0);
}

// npm run allow-last
if (process.env.npm_lifecycle_event === "allow-last" || args.includes("--last")) {
  await allowLast();
  process.exit(0);
}

// npm run allowlist (via lifecycle event)
if (process.env.npm_lifecycle_event === "allowlist") {
  showAllowlist();
  process.exit(0);
}

// npm run allow -- 'pattern'
const pattern = args[0];
if (!pattern) {
  printHelp();
  process.exit(1);
}

addPattern(pattern);

// ─── Functions ────────────────────────────────────────────────────────────────

function addPattern(pat) {
  // Validate regex
  try { new RegExp(pat); } catch (e) {
    console.error(`❌ Invalid regex: ${e.message}`);
    process.exit(1);
  }

  // Check for duplicates
  let existing = [];
  try { existing = fs.readFileSync(ALLOWLIST, "utf8").split("\n").map(l => l.trim()); } catch { /* ok */ }
  if (existing.includes(pat)) {
    console.log(`ℹ️  Pattern already in allowlist: ${pat}`);
    return;
  }

  fs.appendFileSync(ALLOWLIST, `${pat}\n`);

  console.log(`
✅ Added to allowlist: ${pat}
   File: ${ALLOWLIST}

Commands matching this pattern will no longer be blocked (L2/L3).
L1 (rm -rf ~/, curl|bash, fork bomb) — cannot be allowed, always blocked.

View all rules:   npm run allowlist
Remove a rule:    edit ${ALLOWLIST}
`);
}

function showAllowlist() {
  let lines = [];
  try {
    lines = fs.readFileSync(ALLOWLIST, "utf8")
      .split("\n")
      .map(l => l.trim())
      .filter(l => l && !l.startsWith("#"));
  } catch { /* empty */ }

  if (!lines.length) {
    console.log(`
📋 Allowlist is empty.
   File: ${ALLOWLIST}

Commands are blocked by default (L2: prompt injection heuristics).
To add an exception: npm run allow -- 'regex-pattern'
`);
    return;
  }

  console.log(`\n📋 vibe-sec allowlist (${lines.length} rule${lines.length === 1 ? "" : "s"}):`);
  console.log(`   File: ${ALLOWLIST}\n`);
  lines.forEach((l, i) => console.log(`  ${i + 1}. ${l}`));
  console.log(`
To remove a rule — edit the file above.
To clear everything:  npm run allowlist -- --clear
`);
}

async function allowLast() {
  // Read last blocked entry
  let entries = [];
  try {
    entries = fs.readFileSync(BLOCKED_LOG, "utf8")
      .split("\n")
      .filter(Boolean)
      .map(l => { try { return JSON.parse(l); } catch { return null; } })
      .filter(Boolean);
  } catch { /* empty */ }

  if (!entries.length) {
    console.log("ℹ️  No blocked commands in log.");
    return;
  }

  const last = entries[entries.length - 1];
  const subjectShort = String(last.subject).slice(0, 200);

  console.log(`
Last blocked command:

  Reason:   ${last.reason}
  Command:  ${subjectShort}
  Time:     ${new Date(last.ts).toLocaleString("en")}
`);

  if (last.suggestedPattern) {
    console.log(`Suggested allowlist pattern:\n  ${last.suggestedPattern}\n`);
  }

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const suggested = last.suggestedPattern || "";
  const answer = await rl.question(
    `Enter regex pattern for allowlist${suggested ? ` [${suggested}]` : ""}: `
  );
  rl.close();

  const pat = answer.trim() || suggested;
  if (!pat) {
    console.log("Cancelled.");
    return;
  }
  addPattern(pat);
}

function printHelp() {
  console.log(`
vibe-sec allowlist manager

  npm run allow -- 'curl.*api\\.myservice\\.com'   # add pattern
  npm run allow-last                               # allow last blocked command
  npm run allowlist                                # show all rules
  npm run allowlist -- --clear                     # clear everything

Patterns are JavaScript regular expressions.
L1 (rm -rf ~/, curl|bash, fork bomb) cannot be added to allowlist.
`);
}
