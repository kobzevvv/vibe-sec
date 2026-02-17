import { Finding, ScannerConfig } from "../types";

/**
 * Supabase RLS (Row Level Security) checker.
 *
 * The #1 data breach vector for vibe-coded apps:
 * - Supabase REST API is auto-generated from your PostgreSQL schema
 * - RLS is opt-in, NOT enabled by default on new tables
 * - The anon key is embedded in every frontend — anyone can query your DB
 *   if RLS is disabled, even without auth
 *
 * Real incident: 170+ Lovable-generated apps had full DB exposed (CVE-2025-48757)
 * Real incident: Researcher found 13,000 user records exposed in indie app
 * Real incident: DeepStrike mass-exploited thousands of misconfigured instances
 */
export async function scanSupabase(config: ScannerConfig): Promise<Finding[]> {
  const findings: Finding[] = [];

  // We need the Supabase URL and anon key to check — extracted from github scan results
  // passed via config or detected from repo files
  const { supabaseUrl, supabaseAnonKey } = config as any;
  if (!supabaseUrl || !supabaseAnonKey) return findings;

  // 1. Try to read tables without authentication (as anon)
  const tablesRes = await tryFetch(`${supabaseUrl}/rest/v1/`, {
    "apikey": supabaseAnonKey,
    "Authorization": `Bearer ${supabaseAnonKey}`,
  });

  if (tablesRes?.ok) {
    const tables = await tablesRes.json() as any[];
    const exposed: string[] = [];

    for (const table of (tables || [])) {
      // Try to read data from each table without auth
      const dataRes = await tryFetch(`${supabaseUrl}/rest/v1/${table.name}?limit=1`, {
        "apikey": supabaseAnonKey,
        "Authorization": `Bearer ${supabaseAnonKey}`,
      });

      if (dataRes?.ok) {
        const data = await dataRes.json() as any[];
        if (Array.isArray(data) && data.length >= 0) {
          exposed.push(table.name);
        }
      }
    }

    if (exposed.length > 0) {
      findings.push({
        severity: "critical",
        category: "supabase-rls",
        title: `Supabase RLS disabled: ${exposed.length} table(s) publicly readable`,
        description:
          `Tables [${exposed.join(", ")}] are readable by anyone on the internet without authentication. ` +
          `The anon key is embedded in your frontend — this means anyone can query your entire database. ` +
          `This is how 170+ Lovable-generated apps were compromised in 2025 (CVE-2025-48757).`,
        location: supabaseUrl,
        evidence: `Exposed tables: ${exposed.join(", ")}`,
        remediation:
          `Enable Row Level Security on every table:\n` +
          `  1. Go to Supabase Dashboard → Table Editor → your table → RLS\n` +
          `  2. Enable RLS (toggle)\n` +
          `  3. Add a policy: for authenticated users only\n` +
          `  Or run SQL: ALTER TABLE your_table ENABLE ROW LEVEL SECURITY;\n` +
          `  Then create policies for what authenticated users can see.\n` +
          `  Fix with AI: paste this into Cursor/Claude: "Enable RLS on all my Supabase tables and add policies so only authenticated users can read their own data."`,
      });
    } else {
      findings.push({
        severity: "info",
        category: "supabase-rls",
        title: "Supabase RLS appears to be enabled",
        description: "Could not read table data as anonymous user — RLS seems to be protecting your tables.",
        location: supabaseUrl,
        remediation: "Good. Keep RLS enabled and review your policies regularly.",
      });
    }
  }

  // 2. Check if service role key is exposed (catastrophic — full admin access)
  // This is caught by github.ts secret scanner — flag separately here for clarity
  if ((config as any).supabaseServiceRoleKeyFound) {
    findings.push({
      severity: "critical",
      category: "supabase-service-role",
      title: "Supabase service_role key exposed in public repo",
      description:
        "The service_role key bypasses ALL Row Level Security policies and gives full admin access to your database. " +
        "Anyone with this key can read, write, and delete ALL data in your Supabase project. " +
        "This key should NEVER appear in frontend code or public repositories.",
      location: (config as any).supabaseServiceRoleKeyLocation || "your repository",
      remediation:
        "1. Immediately rotate the key: Supabase Dashboard → Settings → API → Regenerate service_role key\n" +
        "2. Remove from git history: use BFG Repo-Cleaner or `git filter-branch`\n" +
        "3. This key should only be used in server-side code (API routes, Edge Functions, backend)\n" +
        "4. NEVER use NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY — the NEXT_PUBLIC_ prefix exposes it to browsers",
    });
  }

  return findings;
}

async function tryFetch(url: string, headers: Record<string, string>): Promise<Response | null> {
  try {
    return await fetch(url, {
      headers: { ...headers, "User-Agent": "vibe-sec-scanner/1.0" },
      signal: AbortSignal.timeout(8000),
    });
  } catch {
    return null;
  }
}
