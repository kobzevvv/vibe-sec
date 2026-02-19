# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in vibe-sec, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, email: **security@aichill.space**

Or use [GitHub Security Advisories](https://github.com/kobzevvv/vibe-sec/security/advisories/new) to report privately.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 7 days
- **Fix timeline**: depends on severity, typically within 30 days

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Scope

The following are in scope:

- **hook.mjs** — PreToolUse guard (bypass, evasion, false negatives)
- **scan-logs.mjs** — scanner (false negatives, information leakage)
- **serve-report.mjs** — report server (XSS, injection)
- **telemetry.mjs** — data collection beyond documented scope
- **allowlist** — bypass mechanisms

The following are out of scope:

- Issues requiring physical access to the machine
- Issues in dependencies (report upstream)
- Social engineering attacks against maintainers
