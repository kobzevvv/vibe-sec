# 🔍 vibe-sec

**Security scanner for indie developers and vibe coders.**

You built something cool with AI. You deployed it fast. But do you know what's exposed?
`vibe-sec` scans your public GitHub repos and web endpoints from the outside — just like an attacker would.

Runs on **Cloudflare Workers** (free tier). No server, no setup, no $500/month enterprise plan.

---

## What it finds

| Check | What it catches |
|---|---|
| 🔑 **Secret scanner** | API keys, tokens, passwords accidentally committed to GitHub |
| 📁 **Sensitive files** | `.env`, `credentials.json`, private keys, SQL dumps exposed in repos |
| 🌐 **Endpoint scanner** | `/.env`, `/.git/config`, `/admin`, `/backup.sql` — paths that shouldn't be public |
| 🤖 **AI interface probe** | Prompt injection, system prompt leaks, token extraction on your public chatbots |
| 🔒 **Security headers** | Missing HSTS, CSP, X-Frame-Options |
| 📜 **Suspicious commits** | Commit messages suggesting accidental secret pushes |

Patterns it detects: AWS keys, OpenAI/Anthropic keys, GitHub tokens, Stripe keys, Telegram bot tokens, Google API keys, DB connection strings, private SSH/RSA keys, hardcoded passwords, JWT secrets, and more.

---

## Quick Start (5 minutes)

### 1. Clone and install

```bash
git clone https://github.com/kobzevvv/vibe-sec
cd vibe-sec
npm install
```

### 2. Configure

Edit `wrangler.toml`:

```toml
[vars]
GITHUB_TARGET = "your-github-username"   # Who to scan
REPORT_MODE = "telegram"                  # "console" | "telegram" | "webhook"
```

Add secrets (not in wrangler.toml — use wrangler secrets):

```bash
# Optional: scan private repos too
wrangler secret put GITHUB_TOKEN

# For Telegram alerts:
wrangler secret put TELEGRAM_BOT_TOKEN
wrangler secret put TELEGRAM_CHAT_ID

# Optional: protect /scan endpoint
wrangler secret put SCAN_SECRET
```

### 3. Create KV namespace

```bash
wrangler kv namespace create SCAN_RESULTS
# Copy the ID into wrangler.toml
```

### 4. Deploy

```bash
wrangler deploy
```

That's it. Your scanner is live at `https://vibe-sec.<your-subdomain>.workers.dev`

---

## Usage

| Action | How |
|---|---|
| Trigger scan | `POST /scan` (or open in browser) |
| View latest report | `GET /report` |
| Scheduled daily scan | Configured automatically via cron in `wrangler.toml` |

### Trigger via curl

```bash
curl -X POST https://vibe-sec.your-subdomain.workers.dev/scan \
  -H "Authorization: Bearer your-scan-secret"
```

### Scan additional domains

Add to `wrangler.toml`:

```toml
[vars]
DOMAINS_TO_SCAN = "yourdomain.com,api.yourdomain.com"
AI_ENDPOINTS_TO_SCAN = "https://your-chatbot.vercel.app/api/chat"
```

---

## Example output

```
# 🔍 vibe-sec scan report
Target: your-username
Scanned at: 2026-02-18T09:00:00Z

## Summary
| Severity | Count |
|----------|-------|
| 🔴 Critical | 2 |
| 🟠 High     | 1 |

## 🔴 CRITICAL (2)

### OpenAI API Key found in .env
Location: github.com/your-username/my-project/blob/HEAD/.env
Evidence: `sk-proj1...key`
Remediation: Rotate the key immediately at platform.openai.com/api-keys...

### AWS Access Key found in config.js
Location: github.com/your-username/old-project/blob/HEAD/config.js
...
```

---

## Roadmap

- [ ] Dependency vulnerability scan (package.json, requirements.txt)
- [ ] Misconfigured S3 / GCS bucket detection
- [ ] Vercel / Netlify / Railway environment variable audit
- [ ] Slack / Discord alerts
- [ ] HTML report with dashboard UI
- [ ] GitHub Actions integration

---

## Why Cloudflare Workers?

- **External perspective**: scans from Cloudflare's global network, not localhost
- **Free tier**: 100k requests/day, cron triggers included — costs $0
- **No server**: deploy in seconds, forget about it, get daily alerts
- **Fast**: global edge network, sub-100ms response times

---

## Cost

**Free.** Cloudflare Workers free tier covers everything for personal use:
- 100,000 requests/day
- Cron triggers
- KV storage (1GB)

---

## Contributing

PRs welcome. If you find a false positive or want to add a new detection pattern, open an issue.

---

## License

MIT

---

*Built for developers who ship fast and sleep well.*
