import { Finding, ScannerConfig } from "../types";

// Patterns that indicate leaked secrets
const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp; severity: "critical" | "high" | "medium" }> = [
  { name: "AWS Access Key",              pattern: /AKIA[0-9A-Z]{16}/,                                           severity: "critical" },
  { name: "AWS Secret Key",             pattern: /aws_secret_access_key\s*=\s*['""]?[A-Za-z0-9+/]{40}/i,      severity: "critical" },
  { name: "OpenAI API Key",             pattern: /sk-[a-zA-Z0-9]{20,60}/,                                      severity: "critical" },
  { name: "Anthropic API Key",          pattern: /sk-ant-[a-zA-Z0-9\-]{90,}/,                                  severity: "critical" },
  { name: "GitHub Token",               pattern: /gh[pousr]_[A-Za-z0-9]{36,255}/,                              severity: "critical" },
  { name: "Stripe Secret Key",          pattern: /sk_live_[0-9a-zA-Z]{24,}/,                                   severity: "critical" },
  { name: "Supabase Service Role Key",  pattern: /eyJ[A-Za-z0-9_-]{40,}\.eyJ[A-Za-z0-9_-]{40,}\.[A-Za-z0-9_-]{40,}/, severity: "critical" },
  { name: "Firebase Admin SDK Key",     pattern: /"private_key":\s*"-----BEGIN RSA PRIVATE KEY/,               severity: "critical" },
  { name: "Private Key Block",          pattern: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/,            severity: "critical" },
  { name: "DB Connection String",       pattern: /postgres:\/\/[^:]+:[^@]+@|mysql:\/\/[^:]+:[^@]+@/,          severity: "critical" },
  { name: "Supabase DB Connection",     pattern: /postgresql:\/\/postgres\.[a-z]+:[^@]+@/,                     severity: "critical" },
  { name: "Stripe Test Key",            pattern: /sk_test_[0-9a-zA-Z]{24,}/,                                   severity: "high" },
  { name: "Google API Key",             pattern: /AIza[0-9A-Za-z\-_]{35}/,                                     severity: "high" },
  { name: "Cloudflare API Token",       pattern: /[A-Za-z0-9_-]{37}cloudflare|cf_token/i,                      severity: "high" },
  { name: "Telegram Bot Token",         pattern: /\d{8,10}:[A-Za-z0-9_\-]{35}/,                               severity: "high" },
  { name: "Hardcoded Password",         pattern: /password\s*=\s*['"][^'"]{6,}['"]/i,                          severity: "high" },
  { name: "JWT Secret",                 pattern: /jwt[_-]?secret\s*=\s*['"][^'"]{8,}['"]/i,                    severity: "high" },
  { name: "Bearer Token",               pattern: /bearer\s+[A-Za-z0-9\-._~+/]+=*/i,                           severity: "medium" },
];

// NEXT_PUBLIC_ variables that should NEVER be prefixed public
// AI code generators (v0, Lovable, Bolt, Cursor) make this mistake constantly
const DANGEROUS_NEXT_PUBLIC_PATTERNS = [
  "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY",
  "NEXT_PUBLIC_DATABASE_URL",
  "NEXT_PUBLIC_DB_PASSWORD",
  "NEXT_PUBLIC_SECRET",
  "NEXT_PUBLIC_PRIVATE",
  "NEXT_PUBLIC_OPENAI",
  "NEXT_PUBLIC_ANTHROPIC",
  "NEXT_PUBLIC_STRIPE_SECRET",
  "NEXT_PUBLIC_AWS_SECRET",
  "NEXT_PUBLIC_FIREBASE_PRIVATE",
];

// Files that should never be public
const SENSITIVE_FILENAMES = [
  ".env", ".env.local", ".env.production", ".env.secret",
  "*.pem", "*.key", "id_rsa", "id_ed25519",
  "credentials.json", "service-account.json", "secrets.json",
  "database.yml", "config/secrets.yml",
];

// Dangerous exposed paths to check in repos
const SENSITIVE_PATHS_TO_CHECK = [
  ".env", ".env.example", "config/database.yml",
  "config/secrets.yml", ".aws/credentials",
];

export async function scanGitHub(config: ScannerConfig): Promise<Finding[]> {
  const findings: Finding[] = [];
  const headers: Record<string, string> = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "vibe-sec-scanner/1.0",
  };
  if (config.githubToken) {
    headers["Authorization"] = `Bearer ${config.githubToken}`;
  }

  // 1. Get all public repos for the target
  const reposUrl = `https://api.github.com/users/${config.githubTarget}/repos?type=public&per_page=100`;
  let repos: any[] = [];

  try {
    const res = await fetch(reposUrl, { headers });
    if (!res.ok) throw new Error(`GitHub API error: ${res.status}`);
    repos = await res.json() as any[];
  } catch (e) {
    findings.push({
      severity: "info",
      category: "scan-error",
      title: "Could not fetch repos",
      description: `Failed to list repos for ${config.githubTarget}`,
      location: `github.com/${config.githubTarget}`,
      remediation: "Check that the username is correct and the profile is public.",
    });
    return findings;
  }

  // 2. Scan each repo
  for (const repo of repos) {
    // Skip forks — they inherit upstream secrets, not the owner's
    if (repo.fork) continue;

    const repoFindings = await scanRepo(repo, headers, config);
    findings.push(...repoFindings);
  }

  return findings;
}

async function scanRepo(repo: any, headers: Record<string, string>, config: ScannerConfig): Promise<Finding[]> {
  const findings: Finding[] = [];
  const repoPath = `${config.githubTarget}/${repo.name}`;

  // 2a. Check for sensitive filenames in the root tree
  try {
    const treeRes = await fetch(
      `https://api.github.com/repos/${repoPath}/git/trees/HEAD?recursive=0`,
      { headers }
    );
    if (treeRes.ok) {
      const tree = await treeRes.json() as any;
      const files: string[] = (tree.tree || []).map((f: any) => f.path as string);

      for (const file of files) {
        const filename = file.split("/").pop() || "";
        for (const pattern of SENSITIVE_FILENAMES) {
          if (pattern.startsWith("*")) {
            if (filename.endsWith(pattern.slice(1))) {
              findings.push({
                severity: "high",
                category: "sensitive-file",
                title: `Sensitive file in repo: ${filename}`,
                description: `File "${file}" matches a sensitive filename pattern and is publicly accessible.`,
                location: `github.com/${repoPath}/blob/HEAD/${file}`,
                remediation: `Remove "${file}" from the repo, rotate any secrets it contained, add it to .gitignore.`,
              });
            }
          } else if (filename === pattern || file === pattern) {
            findings.push({
              severity: "critical",
              category: "sensitive-file",
              title: `Sensitive file exposed: ${filename}`,
              description: `"${file}" is publicly visible in the repository.`,
              location: `github.com/${repoPath}/blob/HEAD/${file}`,
              remediation: `Remove the file from git history (git filter-branch or BFG), rotate all secrets, add to .gitignore.`,
            });
          }
        }
      }

      // 2b. Scan content of small text files for secrets
      const textFiles = files.filter(f =>
        !f.includes("node_modules") &&
        !f.includes("vendor") &&
        !f.includes(".next/") &&
        (f.endsWith(".ts") || f.endsWith(".tsx") || f.endsWith(".js") || f.endsWith(".jsx") ||
         f.endsWith(".py") || f.endsWith(".env") || f.endsWith(".yml") || f.endsWith(".yaml") ||
         f.endsWith(".json") || f.endsWith(".sh") || f.endsWith(".toml") ||
         f.endsWith(".tf") || f.endsWith(".md"))
      ).slice(0, 40); // limit to avoid rate limits

      for (const file of textFiles) {
        const contentFindings = await scanFileContent(repoPath, file, headers, config);
        findings.push(...contentFindings);
      }

      // Check .env.example for accidentally real values
      if (files.includes(".env.example") || files.includes(".env.sample")) {
        const envExampleFile = files.find(f => f === ".env.example" || f === ".env.sample")!;
        const exampleFindings = await scanEnvExample(repoPath, envExampleFile, headers);
        findings.push(...exampleFindings);
      }
    }
  } catch (_) {
    // tree fetch failed — skip silently
  }

  // 2c. Check recent commits for accidental secret commits (last 5)
  try {
    const commitsRes = await fetch(
      `https://api.github.com/repos/${repoPath}/commits?per_page=5`,
      { headers }
    );
    if (commitsRes.ok) {
      const commits = await commitsRes.json() as any[];
      for (const commit of commits) {
        const msg = commit.commit?.message || "";
        if (/secret|token|password|credential|key|env/i.test(msg) &&
            /add|upload|push|accidentally/i.test(msg)) {
          findings.push({
            severity: "medium",
            category: "suspicious-commit",
            title: "Suspicious commit message suggesting accidental secret commit",
            description: `Commit "${commit.sha?.slice(0, 7)}" has message: "${msg.slice(0, 80)}"`,
            location: `github.com/${repoPath}/commit/${commit.sha}`,
            remediation: "Review this commit for exposed secrets. If found, rotate immediately and clean git history.",
          });
        }
      }
    }
  } catch (_) {}

  return findings;
}

async function scanFileContent(
  repoPath: string,
  filePath: string,
  headers: Record<string, string>,
  _config: ScannerConfig
): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const res = await fetch(
      `https://api.github.com/repos/${repoPath}/contents/${filePath}`,
      { headers }
    );
    if (!res.ok) return findings;

    const data = await res.json() as any;
    if (!data.content || data.size > 100_000) return findings; // skip large files

    const content = atob(data.content.replace(/\n/g, ""));

    for (const { name, pattern, severity } of SECRET_PATTERNS) {
      const match = content.match(pattern);
      if (match) {
        const evidence = match[0].slice(0, 8) + "..." + match[0].slice(-4); // redacted
        findings.push({
          severity,
          category: "secret-leak",
          title: `${name} found in ${filePath}`,
          description: `A ${name} was detected in file "${filePath}" in public repository "${repoPath}".`,
          location: `github.com/${repoPath}/blob/HEAD/${filePath}`,
          evidence: `[REDACTED: ${evidence}]`,
          remediation:
            `1) Rotate the credential immediately — assume it's already compromised.\n` +
            `2) Remove from git history: npx @bfg-repo-cleaner/bfg --delete-files ${filePath}\n` +
            `3) Use environment variables only. Never hardcode secrets.\n` +
            `Fix with AI: "Remove all hardcoded secrets from my codebase and replace with process.env variables"`,
        });
      }
    }

    // NEXT_PUBLIC_ misconfiguration check (Next.js / Vercel apps)
    // This is the #1 mistake in AI-generated Next.js code
    if (filePath.endsWith(".env") || filePath.endsWith(".env.local") ||
        filePath.endsWith(".env.example") || filePath.includes(".env.")) {
      for (const dangerousKey of DANGEROUS_NEXT_PUBLIC_PATTERNS) {
        if (content.includes(dangerousKey)) {
          findings.push({
            severity: "critical",
            category: "nextjs-misconfiguration",
            title: `NEXT_PUBLIC_ secret exposed in ${filePath}`,
            description:
              `"${dangerousKey}" found in ${filePath}. Variables prefixed with NEXT_PUBLIC_ are ` +
              `bundled into client-side JavaScript and readable by anyone who opens DevTools. ` +
              `This is the #1 mistake in AI-generated Next.js apps (v0, Lovable, Bolt, Cursor). ` +
              `A service role key or secret with this prefix gives anyone full database access.`,
            location: `github.com/${repoPath}/blob/HEAD/${filePath}`,
            remediation:
              `Remove NEXT_PUBLIC_ prefix from secret variables.\n` +
              `✓ SUPABASE_SERVICE_ROLE_KEY (server-side only, safe)\n` +
              `✗ NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY (exposed to browsers, catastrophic)\n` +
              `Move all secret logic to /app/api/ or /pages/api/ routes.\n` +
              `Fix with AI: "Move my Supabase service role key to a server-side API route and remove it from the frontend"`,
          });
        }
      }
    }
  } catch (_) {}

  return findings;
}

async function scanEnvExample(
  repoPath: string,
  filePath: string,
  headers: Record<string, string>
): Promise<Finding[]> {
  const findings: Finding[] = [];
  try {
    const res = await fetch(
      `https://api.github.com/repos/${repoPath}/contents/${filePath}`,
      { headers }
    );
    if (!res.ok) return findings;
    const data = await res.json() as any;
    if (!data.content) return findings;
    const content = atob(data.content.replace(/\n/g, ""));

    // Check if .env.example contains real values (not just placeholders)
    const lines = content.split("\n");
    for (const line of lines) {
      if (!line.includes("=")) continue;
      const value = line.split("=")[1]?.trim();
      if (!value || value.startsWith("your_") || value === "" || value === "xxx" ||
          value.startsWith("<") || value.toLowerCase().includes("placeholder")) continue;

      for (const { name, pattern, severity } of SECRET_PATTERNS) {
        if (pattern.test(value)) {
          findings.push({
            severity,
            category: "secret-in-example",
            title: `Real secret in ${filePath}: ${name}`,
            description:
              `.env.example files are meant to show variable names with fake placeholder values. ` +
              `A real ${name} was found in "${filePath}" — this file is public. ` +
              `The key is likely already compromised.`,
            location: `github.com/${repoPath}/blob/HEAD/${filePath}`,
            remediation:
              `Replace the real value with a placeholder like: ${line.split("=")[0]}=your_key_here\n` +
              `Rotate the exposed credential immediately.`,
          });
        }
      }
    }
  } catch (_) {}
  return findings;
}
