import { scanGitHub } from "./scanners/github";
import { scanEndpoints } from "./scanners/endpoints";
import { scanAIInterfaces } from "./scanners/ai-interfaces";
import { scanDependencies } from "./scanners/dependencies";
import {
  buildSummary,
  formatMarkdown,
  formatTelegramMessage,
  sendTelegramAlert,
  sendWebhook,
} from "./reporters/report";
import { ScanResult, ScannerConfig } from "./types";

export interface Env {
  // Required
  GITHUB_TARGET: string;
  // Optional
  GITHUB_TOKEN?: string;
  REPORT_MODE?: "console" | "telegram" | "webhook";
  TELEGRAM_BOT_TOKEN?: string;
  TELEGRAM_CHAT_ID?: string;
  WEBHOOK_URL?: string;
  DOMAINS_TO_SCAN?: string;       // comma-separated
  AI_ENDPOINTS_TO_SCAN?: string;  // comma-separated
  // KV for storing results
  SCAN_RESULTS?: KVNamespace;
}

async function runScan(env: Env): Promise<ScanResult> {
  const start = Date.now();

  const config: ScannerConfig = {
    githubTarget: env.GITHUB_TARGET,
    githubToken: env.GITHUB_TOKEN,
    domainsToScan: env.DOMAINS_TO_SCAN?.split(",").map(d => d.trim()).filter(Boolean) || [],
    aiEndpointsToScan: env.AI_ENDPOINTS_TO_SCAN?.split(",").map(e => e.trim()).filter(Boolean) || [],
  };

  // Run all scanners in parallel
  const [githubFindings, endpointFindings, aiFindings, depFindings] = await Promise.all([
    scanGitHub(config),
    scanEndpoints(config),
    scanAIInterfaces(config),
    scanDependencies(config),
  ]);

  const allFindings = [
    ...githubFindings,
    ...endpointFindings,
    ...aiFindings,
    ...depFindings,
  ].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return order[a.severity] - order[b.severity];
  });

  const result: ScanResult = {
    target: env.GITHUB_TARGET,
    scannedAt: new Date().toISOString(),
    duration_ms: Date.now() - start,
    findings: allFindings,
    summary: buildSummary(allFindings),
  };

  return result;
}

async function deliverReport(result: ScanResult, env: Env): Promise<void> {
  const mode = env.REPORT_MODE || "console";

  // Always store in KV if available
  if (env.SCAN_RESULTS) {
    await env.SCAN_RESULTS.put("latest", JSON.stringify(result), {
      expirationTtl: 60 * 60 * 24 * 30, // 30 days
    });
  }

  if (mode === "telegram" && env.TELEGRAM_BOT_TOKEN && env.TELEGRAM_CHAT_ID) {
    const msg = formatTelegramMessage(result);
    await sendTelegramAlert(msg, env.TELEGRAM_BOT_TOKEN, env.TELEGRAM_CHAT_ID);
  } else if (mode === "webhook" && env.WEBHOOK_URL) {
    await sendWebhook(result, env.WEBHOOK_URL);
  } else {
    // Console mode — just log
    console.log(formatMarkdown(result));
  }
}

export default {
  // HTTP handler — trigger scan via GET /scan or view latest report at /
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // GET / — return latest scan result
    if (url.pathname === "/" || url.pathname === "/report") {
      if (env.SCAN_RESULTS) {
        const latest = await env.SCAN_RESULTS.get("latest");
        if (latest) {
          const result: ScanResult = JSON.parse(latest);
          const report = formatMarkdown(result);
          return new Response(report, {
            headers: { "Content-Type": "text/markdown; charset=utf-8" },
          });
        }
      }
      return new Response("No scan results yet. Trigger a scan at /scan", { status: 200 });
    }

    // POST /scan — run scan on demand
    if (url.pathname === "/scan" && request.method === "POST") {
      // Simple auth check via Bearer token (set SCAN_SECRET in wrangler.toml)
      const auth = request.headers.get("Authorization");
      const secret = (env as any).SCAN_SECRET;
      if (secret && auth !== `Bearer ${secret}`) {
        return new Response("Unauthorized", { status: 401 });
      }

      const result = await runScan(env);
      await deliverReport(result, env);
      const report = formatMarkdown(result);
      return new Response(report, {
        headers: { "Content-Type": "text/markdown; charset=utf-8" },
      });
    }

    // GET /scan — form to trigger scan from browser
    if (url.pathname === "/scan" && request.method === "GET") {
      const html = `<!DOCTYPE html>
<html>
<head><title>vibe-sec</title><meta charset="utf-8">
<style>body{font-family:monospace;max-width:600px;margin:60px auto;padding:20px;background:#0d1117;color:#c9d1d9;}
h1{color:#58a6ff;}button{background:#238636;color:#fff;border:none;padding:12px 24px;cursor:pointer;border-radius:6px;font-size:16px;}
button:hover{background:#2ea043;}p{color:#8b949e;}</style></head>
<body>
<h1>🔍 vibe-sec</h1>
<p>Security scanner for indie developers.</p>
<p>Target: <strong>${env.GITHUB_TARGET}</strong></p>
<form method="POST" action="/scan">
  <button type="submit">Run Scan Now</button>
</form>
<p><a href="/report" style="color:#58a6ff">View latest report →</a></p>
</body>
</html>`;
      return new Response(html, { headers: { "Content-Type": "text/html" } });
    }

    return new Response("Not found", { status: 404 });
  },

  // Cron trigger — runs on schedule defined in wrangler.toml
  async scheduled(_event: ScheduledEvent, env: Env, _ctx: ExecutionContext): Promise<void> {
    const result = await runScan(env);
    await deliverReport(result, env);
  },
} satisfies ExportedHandler<Env>;
