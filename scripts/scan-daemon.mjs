#!/usr/bin/env node
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
const log = msg => fs.appendFileSync(LOG_FILE, `[${new Date().toISOString()}] ${msg}\n`);

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
const m = output.match(/(\d+) issue/);
const score = m ? m[1] : "?";
const prev  = (() => { try { return fs.readFileSync(PREV_FILE, "utf8").trim(); } catch { return ""; } })();
fs.writeFileSync(PREV_FILE, score);

log(`Score: ${score} (prev: ${prev})`);

// macOS notification only if score changed or first run
if (score !== prev) {
  const title   = score === "0" ? "vibe-sec ✅" : "vibe-sec 🔍";
  const body    = score === "0"
    ? "Всё чисто, угроз не найдено"
    : `Найдено проблем: ${score} — запусти npm run report`;
  const subtitle = "Ежечасная проверка";
  spawnSync("osascript", ["-e",
    `display notification ${JSON.stringify(body)} with title ${JSON.stringify(title)} subtitle ${JSON.stringify(subtitle)}`
  ], { stdio: "ignore" });
  log("Notification sent");
}
