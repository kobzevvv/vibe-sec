#!/usr/bin/env node
/**
 * vibe-sec: Install / Remove background scan daemon (macOS launchd)
 *
 * Runs scan-logs every hour, sends macOS notification if score changes.
 *
 * Usage:
 *   npm run setup-daemon          # install
 *   npm run setup-daemon -- --remove  # remove
 */

import fs from "fs";
import path from "path";
import os from "os";
import { execSync, spawnSync } from "child_process";

const REMOVE = process.argv.includes("--remove");
const home = os.homedir();

const LABEL       = "ae.vibe-sec.scan";
const PLIST_PATH  = path.join(home, "Library", "LaunchAgents", `${LABEL}.plist`);
const SCRIPT_PATH = path.resolve(import.meta.dirname, "scan-daemon.mjs");
const PROJECT_DIR = path.resolve(import.meta.dirname, "..");
const LOG_DIR     = path.join(home, ".config", "vibe-sec");

// ─── Remove ───────────────────────────────────────────────────────────────────

if (REMOVE) {
  spawnSync("launchctl", ["unload", PLIST_PATH], { stdio: "inherit" });
  try { fs.unlinkSync(PLIST_PATH); } catch { /* ok */ }
  try { fs.unlinkSync(SCRIPT_PATH); } catch { /* ok */ }
  console.log("✅ vibe-sec daemon stopped and removed.");
  process.exit(0);
}

// ─── Install ──────────────────────────────────────────────────────────────────

// Find node path (works with nvm)
let nodePath = process.execPath;
console.log(`Node: ${nodePath}`);

// Create log dir
fs.mkdirSync(LOG_DIR, { recursive: true });

// Write the scan runner script (Node.js, not shell — avoids macOS permission issues)
const runnerScript = `#!/usr/bin/env node
/**
 * vibe-sec daemon runner — called by launchd every hour
 * Runs static scan, sends macOS notification if score changed.
 */
import { execFileSync, spawnSync } from "child_process";
import fs from "fs";
import path from "path";
import os from "os";

const home = os.homedir();
const LOG_DIR    = path.join(home, ".config", "vibe-sec");
const PREV_FILE  = path.join(LOG_DIR, "last-score.txt");
const LOG_FILE   = path.join(LOG_DIR, "daemon.log");
const SCAN_SCRIPT = path.resolve(import.meta.dirname, "scan-logs.mjs");

fs.mkdirSync(LOG_DIR, { recursive: true });
const log = msg => fs.appendFileSync(LOG_FILE, \`[\${new Date().toISOString()}] \${msg}\\n\`);

log("Scan started");
let output = "";
try {
  output = execFileSync(process.execPath, [SCAN_SCRIPT, "--static-only"], {
    cwd: path.resolve(import.meta.dirname, ".."),
    timeout: 60_000,
    encoding: "utf8",
  });
  log("Scan completed");
} catch (e) {
  log("Scan error: " + e.message);
  output = e.stdout || "";
}

// Extract issue count
const m = output.match(/(\\d+) issue/);
const score = m ? m[1] : "?";
const prev  = (() => { try { return fs.readFileSync(PREV_FILE, "utf8").trim(); } catch { return ""; } })();
fs.writeFileSync(PREV_FILE, score);

log(\`Score: \${score} (prev: \${prev})\`);

// macOS notification only if score changed or first run
if (score !== prev) {
  const title   = score === "0" ? "vibe-sec ✅" : "vibe-sec 🔍";
  const body    = score === "0"
    ? "All clear, no threats found"
    : \`Issues found: \${score} — run npm run report\`;
  const subtitle = "Daily security scan";
  spawnSync("osascript", ["-e",
    \`display notification \${JSON.stringify(body)} with title \${JSON.stringify(title)} subtitle \${JSON.stringify(subtitle)}\`
  ], { stdio: "ignore" });
  log("Notification sent");
}
`;

fs.writeFileSync(SCRIPT_PATH, runnerScript, { mode: 0o755 });

// Write launchd plist — call node directly (no shell wrapper)
const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LABEL}</string>

    <key>ProgramArguments</key>
    <array>
        <string>${nodePath}</string>
        <string>${SCRIPT_PATH}</string>
    </array>

    <!-- Run once at load, then every 24 hours -->
    <key>RunAtLoad</key>
    <true/>
    <key>StartInterval</key>
    <integer>86400</integer>

    <key>WorkingDirectory</key>
    <string>${PROJECT_DIR}</string>

    <key>StandardOutPath</key>
    <string>${LOG_DIR}/daemon.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/daemon-error.log</string>

    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>`;

fs.mkdirSync(path.dirname(PLIST_PATH), { recursive: true });
fs.writeFileSync(PLIST_PATH, plist);

// Load into launchd
const result = spawnSync("launchctl", ["load", PLIST_PATH], { stdio: "pipe" });
if (result.status !== 0) {
  console.error("⚠️  launchctl load failed:", result.stderr?.toString());
  console.log(`File created, try manually:\n  launchctl load ${PLIST_PATH}`);
  process.exit(1);
}

console.log(`
✅ vibe-sec background scanner installed!

Schedule: daily + on login
First run: in a few seconds
Logs:      ${LOG_DIR}/daemon.log
Report:    npm run report

Notifications: macOS notification when security score changes

Stop:      npm run remove-daemon
`);
