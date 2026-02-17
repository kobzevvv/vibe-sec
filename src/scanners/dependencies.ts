import { Finding, ScannerConfig } from "../types";

/**
 * Dependency vulnerability scanner.
 *
 * Uses the OSV (Open Source Vulnerability) database — free, no API key required.
 * https://osv.dev/
 *
 * Context: In September 2025, chalk, debug, ansi-styles (2.6B+ weekly downloads)
 * were compromised via a phished npm maintainer account. Malicious versions
 * were live for ~2 hours. Solo devs had zero visibility into this.
 */

interface OsvVuln {
  id: string;
  summary: string;
  severity?: Array<{ type: string; score: string }>;
  affected: Array<{
    package: { name: string; ecosystem: string };
    ranges: Array<{ type: string; events: Array<{ introduced?: string; fixed?: string }> }>;
  }>;
  references: Array<{ type: string; url: string }>;
}

export async function scanDependencies(config: ScannerConfig): Promise<Finding[]> {
  const findings: Finding[] = [];
  const repoPath = config.githubTarget;
  const headers: Record<string, string> = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "vibe-sec-scanner/1.0",
  };
  if ((config as any).githubToken) {
    headers["Authorization"] = `Bearer ${(config as any).githubToken}`;
  }

  // Check for package.json (npm/Node.js)
  const npmFindings = await checkNpmDependencies(repoPath, headers, config.githubTarget);
  findings.push(...npmFindings);

  // Check for requirements.txt (Python)
  const pyFindings = await checkPythonDependencies(repoPath, headers, config.githubTarget);
  findings.push(...pyFindings);

  return findings;
}

async function checkNpmDependencies(
  repoPath: string,
  headers: Record<string, string>,
  target: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Get list of repos
  const reposRes = await fetch(
    `https://api.github.com/users/${target}/repos?type=public&per_page=100`,
    { headers }
  );
  if (!reposRes.ok) return findings;
  const repos = await reposRes.json() as any[];

  for (const repo of repos.filter((r: any) => !r.fork).slice(0, 10)) {
    const pkgRes = await fetch(
      `https://api.github.com/repos/${target}/${repo.name}/contents/package.json`,
      { headers }
    );
    if (!pkgRes.ok) continue;

    const pkgData = await pkgRes.json() as any;
    if (!pkgData.content) continue;

    let pkg: any;
    try {
      pkg = JSON.parse(atob(pkgData.content.replace(/\n/g, "")));
    } catch {
      continue;
    }

    const allDeps = {
      ...pkg.dependencies,
      ...pkg.devDependencies,
    };

    // Check a sample of dependencies against OSV
    const criticalDeps = Object.entries(allDeps).slice(0, 20); // limit to avoid rate limits

    for (const [name, version] of criticalDeps) {
      const cleanVersion = String(version).replace(/[\^~>=<]/g, "").split(" ")[0];
      if (!cleanVersion || cleanVersion === "*" || cleanVersion.startsWith("http")) continue;

      const vulns = await queryOSV(name, cleanVersion, "npm");
      for (const vuln of vulns) {
        findings.push({
          severity: getCvssSeverity(vuln),
          category: "dependency-vuln",
          title: `Vulnerable dependency: ${name}@${cleanVersion}`,
          description:
            `${vuln.summary || "Known vulnerability"} (${vuln.id}). ` +
            `Found in ${repo.name}/package.json.`,
          location: `github.com/${target}/${repo.name}/blob/HEAD/package.json`,
          evidence: vuln.id,
          remediation:
            getFixVersion(vuln, name) ||
            `Run: npm audit fix\n` +
            `Or update manually: npm install ${name}@latest\n` +
            `Details: https://osv.dev/vulnerability/${vuln.id}`,
        });
      }
    }

    // NEXT_PUBLIC_ secret check in package.json scripts / config
    const pkgStr = JSON.stringify(pkg);
    if (pkgStr.includes("NEXT_PUBLIC_") && (
      pkgStr.includes("SERVICE_ROLE") ||
      pkgStr.includes("SECRET") ||
      pkgStr.includes("PRIVATE") ||
      pkgStr.includes("DATABASE_URL")
    )) {
      findings.push({
        severity: "critical",
        category: "nextjs-misconfiguration",
        title: `Potential NEXT_PUBLIC_ secret exposure in ${repo.name}`,
        description:
          "Found suspicious NEXT_PUBLIC_ variable references that may expose secrets to the browser. " +
          "Variables prefixed NEXT_PUBLIC_ are bundled into client-side JavaScript and readable by anyone. " +
          "AI code generators (v0, Lovable, Bolt) frequently make this mistake.",
        location: `github.com/${target}/${repo.name}`,
        remediation:
          "Never use NEXT_PUBLIC_ for secrets. Only use it for truly public values (e.g. your site URL).\n" +
          "Keep secrets in API routes (pages/api/ or app/api/) where they run server-side only.\n" +
          "Rename NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY → SUPABASE_SERVICE_ROLE_KEY",
      });
    }
  }

  return findings;
}

async function checkPythonDependencies(
  repoPath: string,
  headers: Record<string, string>,
  target: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

  const reposRes = await fetch(
    `https://api.github.com/users/${target}/repos?type=public&per_page=100`,
    { headers }
  );
  if (!reposRes.ok) return findings;
  const repos = await reposRes.json() as any[];

  for (const repo of repos.filter((r: any) => !r.fork).slice(0, 5)) {
    const reqRes = await fetch(
      `https://api.github.com/repos/${target}/${repo.name}/contents/requirements.txt`,
      { headers }
    );
    if (!reqRes.ok) continue;

    const reqData = await reqRes.json() as any;
    if (!reqData.content) continue;

    const content = atob(reqData.content.replace(/\n/g, ""));
    const lines = content.split("\n")
      .map(l => l.trim())
      .filter(l => l && !l.startsWith("#"));

    for (const line of lines.slice(0, 15)) {
      const match = line.match(/^([A-Za-z0-9_\-]+)[==><]{1,2}(.+)$/);
      if (!match) continue;
      const [, name, version] = match;
      const cleanVersion = version.trim().split(",")[0].replace(/[\^~>=<]/g, "");

      const vulns = await queryOSV(name, cleanVersion, "PyPI");
      for (const vuln of vulns) {
        findings.push({
          severity: getCvssSeverity(vuln),
          category: "dependency-vuln",
          title: `Vulnerable Python package: ${name}==${cleanVersion}`,
          description: `${vuln.summary || "Known vulnerability"} (${vuln.id}). Found in ${repo.name}/requirements.txt.`,
          location: `github.com/${target}/${repo.name}/blob/HEAD/requirements.txt`,
          evidence: vuln.id,
          remediation:
            `Run: pip install --upgrade ${name}\n` +
            `Details: https://osv.dev/vulnerability/${vuln.id}`,
        });
      }
    }
  }

  return findings;
}

async function queryOSV(packageName: string, version: string, ecosystem: string): Promise<OsvVuln[]> {
  try {
    const res = await fetch("https://api.osv.dev/v1/query", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        version,
        package: { name: packageName, ecosystem },
      }),
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return [];
    const data = await res.json() as any;
    // Only return high/critical severity
    return (data.vulns || []).filter((v: OsvVuln) => {
      const score = v.severity?.[0]?.score;
      if (!score) return false;
      const num = parseFloat(score);
      return num >= 7.0; // high and critical only
    });
  } catch {
    return [];
  }
}

function getCvssSeverity(vuln: OsvVuln): "critical" | "high" | "medium" | "low" {
  const score = parseFloat(vuln.severity?.[0]?.score || "0");
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  return "low";
}

function getFixVersion(vuln: OsvVuln, packageName: string): string | null {
  for (const affected of vuln.affected || []) {
    for (const range of affected.ranges || []) {
      for (const event of range.events || []) {
        if (event.fixed) {
          return `Update to ${packageName}@${event.fixed} or later. Run: npm install ${packageName}@${event.fixed}`;
        }
      }
    }
  }
  return null;
}
