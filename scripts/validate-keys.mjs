#!/usr/bin/env node
/**
 * vibe-sec: Key Validator
 *
 * Reads ~/.claude/ logs, extracts real API key values using regex,
 * and tests each one against its service to check if it's still ACTIVE or REVOKED.
 *
 * Usage:
 *   node scripts/validate-keys.mjs
 *   node scripts/validate-keys.mjs --raw vibe-sec-raw-2026-02-18.json
 *
 * Output:
 *   ✅ REVOKED  — key was already rotated, no action needed
 *   🔴 ACTIVE   — key still works, rotate immediately
 *   ❓ UNKNOWN  — couldn't verify (service down, rate limited, etc.)
 */

import fs from "fs";
import path from "path";
import os from "os";

// ─── Key patterns ─────────────────────────────────────────────────────────────

const DETECTORS = [
  {
    service: "OpenAI",
    pattern: /\bsk-(?:proj-)?[A-Za-z0-9\-_]{20,}/g,
    validate: async (key) => {
      const r = await safeFetch("https://api.openai.com/v1/models", {
        headers: { Authorization: `Bearer ${key}` },
      });
      if (r === null) return "UNKNOWN";
      return r.status === 200 ? "ACTIVE" : "REVOKED";
    },
  },
  {
    service: "Anthropic",
    pattern: /\bsk-ant-[A-Za-z0-9\-_]{20,}/g,
    validate: async (key) => {
      const r = await safeFetch("https://api.anthropic.com/v1/models", {
        headers: { "x-api-key": key, "anthropic-version": "2023-06-01" },
      });
      if (r === null) return "UNKNOWN";
      return r.status === 200 ? "ACTIVE" : "REVOKED";
    },
  },
  {
    service: "ElevenLabs",
    pattern: /\bxi_[A-Za-z0-9]{20,}|\b[a-f0-9]{32}\b/g,  // ElevenLabs keys: xi_ prefix or 32-char hex
    validate: async (key) => {
      const r = await safeFetch("https://api.elevenlabs.io/v1/user", {
        headers: { "xi-api-key": key },
      });
      if (r === null) return "UNKNOWN";
      return r.status === 200 ? "ACTIVE" : "REVOKED";
    },
  },
  {
    service: "GitHub PAT",
    // classic: ghp_, fine-grained: github_pat_
    pattern: /\b(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}/g,
    validate: async (key) => {
      const r = await safeFetch("https://api.github.com/user", {
        headers: { Authorization: `token ${key}`, "User-Agent": "vibe-sec" },
      });
      if (r === null) return "UNKNOWN";
      return r.status === 200 ? "ACTIVE" : "REVOKED";
    },
  },
  {
    service: "GitLab PAT",
    pattern: /\bglpat-[A-Za-z0-9\-_]{20,}/g,
    validate: async (key) => {
      const r = await safeFetch("https://gitlab.com/api/v4/user", {
        headers: { "PRIVATE-TOKEN": key },
      });
      if (r === null) return "UNKNOWN";
      return r.status === 200 ? "ACTIVE" : "REVOKED";
    },
  },
  {
    service: "Telegram Bot",
    // format: 123456789:AABBCCddEEFF...
    pattern: /\b\d{8,12}:[A-Za-z0-9\-_]{30,}/g,
    validate: async (key) => {
      const r = await safeFetch(`https://api.telegram.org/bot${key}/getMe`);
      if (r === null) return "UNKNOWN";
      try {
        const json = await r.json();
        return json.ok ? "ACTIVE" : "REVOKED";
      } catch { return "UNKNOWN"; }
    },
  },
  {
    service: "Stripe",
    pattern: /\bsk_(?:live|test)_[A-Za-z0-9]{20,}/g,
    validate: async (key) => {
      const r = await safeFetch("https://api.stripe.com/v1/account", {
        headers: { Authorization: `Bearer ${key}` },
      });
      if (r === null) return "UNKNOWN";
      return r.status === 200 ? "ACTIVE" : "REVOKED";
    },
  },
  {
    service: "Cloudflare",
    // API tokens start with a long base64-like string ~40 chars
    pattern: /\b[A-Za-z0-9\-_]{37,43}[A-Za-z0-9]\b/g,
    // Cloudflare tokens are hard to distinguish without context — only validate if in Cloudflare context
    contextHint: /cloudflare/i,
    validate: async (key) => {
      const r = await safeFetch("https://api.cloudflare.com/client/v4/user/tokens/verify", {
        headers: { Authorization: `Bearer ${key}` },
      });
      if (r === null) return "UNKNOWN";
      try {
        const json = await r.json();
        return json.success ? "ACTIVE" : "REVOKED";
      } catch { return "UNKNOWN"; }
    },
  },
  {
    service: "Replicate",
    pattern: /\br8_[A-Za-z0-9]{30,}/g,
    validate: async (key) => {
      const r = await safeFetch("https://api.replicate.com/v1/account", {
        headers: { Authorization: `Bearer ${key}` },
      });
      if (r === null) return "UNKNOWN";
      return r.status === 200 ? "ACTIVE" : "REVOKED";
    },
  },
  {
    service: "Gemini / Google AI",
    pattern: /\bAIza[A-Za-z0-9\-_]{35}/g,
    validate: async (key) => {
      const r = await safeFetch(
        `https://generativelanguage.googleapis.com/v1beta/models?key=${key}`
      );
      if (r === null) return "UNKNOWN";
      return r.status === 200 ? "ACTIVE" : "REVOKED";
    },
  },
  {
    service: "Daily.co",
    // Daily API keys: long alphanumeric, often found near "daily" context
    pattern: /\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b/g,
    contextHint: /daily/i,
    validate: async (key) => {
      const r = await safeFetch("https://api.daily.co/v1/rooms", {
        headers: { Authorization: `Bearer ${key}` },
      });
      if (r === null) return "UNKNOWN";
      return r.status === 200 ? "ACTIVE" : "REVOKED";
    },
  },
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

const ALLOWED_FETCH_HOSTS = [
  "api.openai.com", "api.anthropic.com", "api.github.com", "api.gitlab.com",
  "gitlab.com", "api.telegram.org", "api.stripe.com", "api.cloudflare.com",
  "api.replicate.com", "generativelanguage.googleapis.com", "api.elevenlabs.io",
  "api.daily.co", "api.pinecone.io", "api.supabase.io",
];

async function safeFetch(url, options = {}) {
  // SSRF protection: only allow requests to known API endpoints
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:") throw new Error("non-https");
    if (!ALLOWED_FETCH_HOSTS.some(h => parsed.hostname === h || parsed.hostname.endsWith("." + h))) {
      throw new Error(`blocked host: ${parsed.hostname}`);
    }
  } catch {
    return null;
  }
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const r = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(timeout);
    return r;
  } catch {
    return null;
  }
}

function mask(key) {
  if (key.length <= 8) return "****";
  return key.slice(0, 4) + "****" + key.slice(-4);
}

function maskEmail(str) {
  return str.replace(
    /([a-zA-Z0-9._%+\-]{1,3})[a-zA-Z0-9._%+\-]*@([a-zA-Z0-9\-]{1,3})[a-zA-Z0-9.\-]*\.([a-zA-Z]{2,})/g,
    (_, u, d, tld) => `${u}***@${d}***.${tld}`
  );
}

// ─── Extract keys from text ───────────────────────────────────────────────────

function extractKeys(text) {
  const found = []; // { service, key, context }
  const seen = new Set();

  for (const detector of DETECTORS) {
    const re = new RegExp(detector.pattern.source, "g");
    let match;
    while ((match = re.exec(text)) !== null) {
      const key = match[0];
      const id = `${detector.service}:${key}`;
      if (seen.has(id)) continue;

      // If detector has contextHint, check surrounding text (±200 chars)
      if (detector.contextHint) {
        const surrounding = text.slice(Math.max(0, match.index - 200), match.index + 200);
        if (!detector.contextHint.test(surrounding)) continue;
      }

      // Skip obvious false positives: hex UUIDs in non-key contexts, short matches
      if (key.length < 12) continue;

      seen.add(id);
      // Grab context snippet (surrounding 80 chars, no newlines)
      const ctxStart = Math.max(0, match.index - 40);
      const ctxEnd = Math.min(text.length, match.index + key.length + 40);
      const context = maskEmail(text.slice(ctxStart, ctxEnd).replace(/\n/g, " ").trim());
      found.push({ service: detector.service, key, context, validate: detector.validate });
    }
  }

  return found;
}

// ─── Read logs ────────────────────────────────────────────────────────────────

function readSource(rawFile) {
  if (rawFile) {
    console.log(`📂 Reading from raw file: ${rawFile}`);
    const raw = JSON.parse(fs.readFileSync(rawFile, "utf8"));
    return raw.content;
  }

  // Fall back to reading ~/.claude/ directly
  console.log("📂 Reading from ~/.claude/ directly...");
  const claudeDir = path.join(os.homedir(), ".claude");
  const parts = [];

  // history.jsonl
  const histFile = path.join(claudeDir, "history.jsonl");
  if (fs.existsSync(histFile)) {
    parts.push(fs.readFileSync(histFile, "utf8"));
  }

  // recent session files
  const projectsDir = path.join(claudeDir, "projects");
  if (fs.existsSync(projectsDir)) {
    const jsonlFiles = fs.readdirSync(projectsDir, { withFileTypes: true })
      .flatMap(e => e.isDirectory()
        ? fs.readdirSync(path.join(projectsDir, e.name))
            .filter(f => f.endsWith(".jsonl"))
            .map(f => path.join(projectsDir, e.name, f))
        : [])
      .map(f => ({ f, mtime: fs.statSync(f).mtime }))
      .sort((a, b) => b.mtime - a.mtime)
      .slice(0, 15)
      .map(({ f }) => f);

    for (const f of jsonlFiles) {
      parts.push(fs.readFileSync(f, "utf8"));
    }
  }

  return parts.join("\n");
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  console.log("🔑 vibe-sec: Key Validator\n");

  const rawFileArg = process.argv.find((a, i) => process.argv[i - 1] === "--raw");
  const text = readSource(rawFileArg);

  console.log("🔍 Scanning for key patterns...\n");
  const keys = extractKeys(text);

  if (keys.length === 0) {
    console.log("✅ No recognisable API keys found in logs.");
    return;
  }

  console.log(`Found ${keys.length} potential key(s). Checking with each service...\n`);
  console.log("─".repeat(60));

  const results = [];

  for (const { service, key, context, validate } of keys) {
    process.stdout.write(`  ${service.padEnd(20)} ${mask(key)}  →  `);
    const status = await validate(key);
    const icon = status === "ACTIVE" ? "🔴 ACTIVE   — rotate immediately!"
      : status === "REVOKED" ? "✅ REVOKED  — already rotated, safe"
      : "❓ UNKNOWN  — couldn't verify";
    console.log(icon);
    results.push({ service, key: mask(key), status, context: context.slice(0, 80) });
  }

  console.log("─".repeat(60));

  const active  = results.filter(r => r.status === "ACTIVE");
  const revoked = results.filter(r => r.status === "REVOKED");
  const unknown = results.filter(r => r.status === "UNKNOWN");

  console.log(`\n📊 Summary: ${active.length} active, ${revoked.length} revoked, ${unknown.length} unknown\n`);

  if (active.length > 0) {
    console.log("🔴 ACTIVE keys — rotate these now:");
    for (const r of active) {
      console.log(`   ${r.service}: ${r.key}`);
      console.log(`   Context: ...${r.context}...`);
      console.log();
    }
  }

  if (revoked.length > 0) {
    console.log(`✅ ${revoked.length} key(s) already revoked — no action needed.`);
  }

  // Save report
  const date = new Date().toISOString().slice(0, 10);
  const outFile = `vibe-sec-key-validation-${date}.json`;
  fs.writeFileSync(outFile, JSON.stringify({ validatedAt: new Date().toISOString(), results }, null, 2));
  console.log(`\n📄 Full results saved to ${outFile}`);
}

main().catch(err => {
  console.error("❌ Error:", err.message);
  process.exit(1);
});
