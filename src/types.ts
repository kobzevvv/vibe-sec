export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  severity: Severity;
  category: string;
  title: string;
  description: string;
  location: string;  // repo name, URL, or file path
  evidence?: string; // snippet or example (redacted)
  remediation: string;
}

export interface ScanResult {
  target: string;
  scannedAt: string;
  duration_ms: number;
  findings: Finding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
}

export interface ScannerConfig {
  githubTarget: string;
  githubToken?: string;
  domainsToScan?: string[];
  aiEndpointsToScan?: string[];
}
