import { ScanResult, Finding, Severity } from "../types";

const SEVERITY_EMOJI: Record<Severity, string> = {
  critical: "🔴",
  high:     "🟠",
  medium:   "🟡",
  low:      "🔵",
  info:     "⚪",
};

export function buildSummary(findings: Finding[]): ScanResult["summary"] {
  return {
    critical: findings.filter(f => f.severity === "critical").length,
    high:     findings.filter(f => f.severity === "high").length,
    medium:   findings.filter(f => f.severity === "medium").length,
    low:      findings.filter(f => f.severity === "low").length,
    total:    findings.length,
  };
}

export function formatMarkdown(result: ScanResult): string {
  const { summary } = result;
  const lines: string[] = [];

  lines.push(`# 🔍 vibe-sec scan report`);
  lines.push(`**Target:** ${result.target}`);
  lines.push(`**Scanned at:** ${result.scannedAt}`);
  lines.push(`**Duration:** ${result.duration_ms}ms`);
  lines.push(``);

  if (summary.total === 0) {
    lines.push(`✅ **No issues found.** Your public surface looks clean.`);
    return lines.join("\n");
  }

  lines.push(`## Summary`);
  lines.push(`| Severity | Count |`);
  lines.push(`|----------|-------|`);
  if (summary.critical) lines.push(`| 🔴 Critical | ${summary.critical} |`);
  if (summary.high)     lines.push(`| 🟠 High     | ${summary.high} |`);
  if (summary.medium)   lines.push(`| 🟡 Medium   | ${summary.medium} |`);
  if (summary.low)      lines.push(`| 🔵 Low      | ${summary.low} |`);
  lines.push(``);

  // Group by severity
  const bySeverity: Record<Severity, Finding[]> = {
    critical: [], high: [], medium: [], low: [], info: [],
  };
  for (const f of result.findings) {
    bySeverity[f.severity].push(f);
  }

  for (const severity of ["critical", "high", "medium", "low", "info"] as Severity[]) {
    const group = bySeverity[severity];
    if (group.length === 0) continue;

    lines.push(`## ${SEVERITY_EMOJI[severity]} ${severity.toUpperCase()} (${group.length})`);

    for (const finding of group) {
      lines.push(`### ${finding.title}`);
      lines.push(`**Category:** ${finding.category}`);
      lines.push(`**Location:** ${finding.location}`);
      lines.push(``);
      lines.push(finding.description);
      if (finding.evidence) {
        lines.push(``);
        lines.push(`**Evidence:** \`${finding.evidence}\``);
      }
      lines.push(``);
      lines.push(`**Remediation:** ${finding.remediation}`);
      lines.push(``);
      lines.push(`---`);
      lines.push(``);
    }
  }

  return lines.join("\n");
}

export function formatTelegramMessage(result: ScanResult): string {
  const { summary } = result;
  const lines: string[] = [];

  lines.push(`🔍 *vibe-sec scan complete*`);
  lines.push(`Target: \`${result.target}\``);
  lines.push(``);

  if (summary.total === 0) {
    lines.push(`✅ All clean — no issues found`);
    return lines.join("\n");
  }

  lines.push(`Found *${summary.total}* issues:`);
  if (summary.critical) lines.push(`🔴 Critical: *${summary.critical}*`);
  if (summary.high)     lines.push(`🟠 High: *${summary.high}*`);
  if (summary.medium)   lines.push(`🟡 Medium: *${summary.medium}*`);
  if (summary.low)      lines.push(`🔵 Low: *${summary.low}*`);
  lines.push(``);

  // Show top 5 findings
  const topFindings = result.findings
    .filter(f => f.severity === "critical" || f.severity === "high")
    .slice(0, 5);

  for (const f of topFindings) {
    lines.push(`${SEVERITY_EMOJI[f.severity]} *${f.title}*`);
    lines.push(`  📍 ${f.location}`);
    lines.push(``);
  }

  if (result.findings.length > 5) {
    lines.push(`_...and ${result.findings.length - 5} more. See full report._`);
  }

  return lines.join("\n");
}

export async function sendTelegramAlert(message: string, botToken: string, chatId: string): Promise<void> {
  await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chat_id: chatId,
      text: message,
      parse_mode: "Markdown",
      disable_web_page_preview: true,
    }),
  });
}

export async function sendWebhook(result: ScanResult, webhookUrl: string): Promise<void> {
  await fetch(webhookUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(result),
  });
}
