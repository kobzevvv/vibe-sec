import { Finding, ScannerConfig } from "../types";

// Paths that should never be publicly accessible
const SENSITIVE_PATHS = [
  // Env files
  { path: "/.env",                    name: ".env file",              severity: "critical" as const },
  { path: "/.env.local",              name: ".env.local",             severity: "critical" as const },
  { path: "/.env.production",         name: ".env.production",        severity: "critical" as const },
  { path: "/.env.backup",             name: ".env backup",            severity: "critical" as const },
  // Git
  { path: "/.git/config",             name: "Git config",             severity: "high" as const },
  { path: "/.git/HEAD",               name: "Git repo exposed",       severity: "high" as const },
  { path: "/.gitignore",              name: ".gitignore (recon)",     severity: "low" as const },
  // Cloud credentials
  { path: "/.aws/credentials",        name: "AWS credentials",        severity: "critical" as const },
  { path: "/credentials.json",        name: "credentials.json",       severity: "critical" as const },
  { path: "/service-account.json",    name: "GCP service account",    severity: "critical" as const },
  // Config dumps
  { path: "/config.json",             name: "config.json",            severity: "medium" as const },
  { path: "/config.yml",              name: "config.yml",             severity: "medium" as const },
  { path: "/docker-compose.yml",      name: "docker-compose.yml",     severity: "medium" as const },
  // DB
  { path: "/backup.sql",              name: "SQL backup",             severity: "critical" as const },
  { path: "/dump.sql",                name: "SQL dump",               severity: "critical" as const },
  { path: "/database.sql",            name: "Database dump",          severity: "critical" as const },
  // Admin panels
  { path: "/admin",                   name: "Admin panel",            severity: "medium" as const },
  { path: "/phpMyAdmin",              name: "phpMyAdmin",             severity: "high" as const },
  { path: "/phpmyadmin",              name: "phpMyAdmin (lower)",     severity: "high" as const },
  // Debug endpoints
  { path: "/debug",                   name: "Debug endpoint",         severity: "medium" as const },
  { path: "/__debug__",               name: "Debug route",            severity: "medium" as const },
  { path: "/metrics",                 name: "Metrics endpoint",       severity: "low" as const },
  { path: "/health",                  name: "Health check",           severity: "info" as const },
  // Common framework exposures
  { path: "/wp-login.php",            name: "WordPress login",        severity: "low" as const },
  { path: "/wp-config.php.bak",       name: "WP config backup",       severity: "critical" as const },
  { path: "/.DS_Store",               name: ".DS_Store (recon)",      severity: "low" as const },
];

// Indicators that a path is actually exposing something (not just returning 200 for SPA)
const EXPOSURE_INDICATORS = [
  "DB_PASSWORD", "API_KEY", "SECRET", "TOKEN", "PRIVATE",
  "aws_access_key", "BEGIN RSA", "BEGIN EC PRIVATE",
  "[core]", "[remote", "gitdir",  // git config patterns
];

export async function scanEndpoints(config: ScannerConfig): Promise<Finding[]> {
  const findings: Finding[] = [];
  const domains = config.domainsToScan || [];

  if (domains.length === 0) return findings;

  for (const domain of domains) {
    const domainFindings = await scanDomain(domain);
    findings.push(...domainFindings);
  }

  return findings;
}

async function scanDomain(domain: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const base = domain.startsWith("http") ? domain : `https://${domain}`;

  for (const { path, name, severity } of SENSITIVE_PATHS) {
    const url = `${base}${path}`;
    try {
      const res = await fetch(url, {
        method: "GET",
        redirect: "follow",
        headers: { "User-Agent": "vibe-sec-scanner/1.0 (security audit)" },
        signal: AbortSignal.timeout(8000),
      });

      // Skip 404s and redirects to auth
      if (res.status === 404 || res.status === 401 || res.status === 403) continue;

      if (res.status === 200) {
        const body = await res.text();

        // Verify it's actually exposing something (not a SPA returning 200 for everything)
        const isActuallyExposed = EXPOSURE_INDICATORS.some(indicator =>
          body.toLowerCase().includes(indicator.toLowerCase())
        ) || severity === "info" || body.length < 5000; // small non-SPA responses

        if (isActuallyExposed || severity === "critical" || severity === "high") {
          findings.push({
            severity,
            category: "exposed-endpoint",
            title: `${name} publicly accessible`,
            description: `"${url}" returns HTTP 200 and appears to expose sensitive data.`,
            location: url,
            evidence: body.slice(0, 100).replace(/\n/g, " ") + "...",
            remediation: getEndpointRemediation(path),
          });
        }
      }
    } catch (_) {
      // Timeout or network error — skip
    }
  }

  // Check SSL certificate expiry
  const sslFinding = await checkSSL(base, domain);
  if (sslFinding) findings.push(sslFinding);

  // Check security headers
  const headerFindings = await checkSecurityHeaders(base, domain);
  findings.push(...headerFindings);

  return findings;
}

async function checkSSL(base: string, domain: string): Promise<Finding | null> {
  try {
    const res = await fetch(base, {
      headers: { "User-Agent": "vibe-sec-scanner/1.0" },
      signal: AbortSignal.timeout(5000),
    });
    // If we got here, SSL is valid (Workers would throw on cert error)
    return null;
  } catch (e: any) {
    if (e?.message?.includes("certificate") || e?.message?.includes("SSL")) {
      return {
        severity: "high",
        category: "ssl",
        title: "SSL certificate issue",
        description: `SSL certificate for ${domain} may be expired or invalid.`,
        location: base,
        remediation: "Renew the SSL certificate. Use Let's Encrypt (free) or your hosting provider.",
      };
    }
    return null;
  }
}

async function checkSecurityHeaders(base: string, domain: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  try {
    const res = await fetch(base, {
      headers: { "User-Agent": "vibe-sec-scanner/1.0" },
      signal: AbortSignal.timeout(8000),
    });

    const missingHeaders: string[] = [];
    if (!res.headers.get("X-Content-Type-Options")) missingHeaders.push("X-Content-Type-Options");
    if (!res.headers.get("X-Frame-Options") && !res.headers.get("Content-Security-Policy")) {
      missingHeaders.push("X-Frame-Options / CSP (clickjacking protection)");
    }
    if (!res.headers.get("Strict-Transport-Security")) {
      missingHeaders.push("Strict-Transport-Security (HSTS)");
    }

    if (missingHeaders.length >= 2) {
      findings.push({
        severity: "low",
        category: "security-headers",
        title: "Missing security headers",
        description: `${domain} is missing: ${missingHeaders.join(", ")}`,
        location: base,
        remediation: "Add security headers via your hosting platform (Cloudflare, Vercel, Netlify) or framework middleware.",
      });
    }
  } catch (_) {}

  return findings;
}

function getEndpointRemediation(path: string): string {
  if (path.includes(".env")) {
    return "Never deploy .env files. Add .env to .gitignore. Use platform environment variables (Vercel, Railway, Cloudflare).";
  }
  if (path.includes(".git")) {
    return "Block /.git/ access in your web server config or hosting platform. Ensure your web root doesn't serve the git directory.";
  }
  if (path.includes(".sql") || path.includes("backup")) {
    return "Remove database dumps from public directories. Store backups in private cloud storage with access controls.";
  }
  if (path.includes("admin")) {
    return "Protect admin panels with authentication. Consider IP allowlisting or moving to a non-standard path.";
  }
  return "Restrict access to this resource. Add authentication or block the path in your web server configuration.";
}
