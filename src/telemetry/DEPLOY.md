# Telemetry Worker — Deploy Guide

30 minutes, free tier, DDoS-protected by Cloudflare.

## 1. Create D1 database

```bash
wrangler d1 create vibe-sec-telemetry
```

Copy the `database_id` from the output into `wrangler-telemetry.toml`.

## 2. Create KV namespace (rate limiting)

```bash
wrangler kv namespace create TELEMETRY_RL
```

Copy the `id` into `wrangler-telemetry.toml`.

## 3. Run the schema

```bash
wrangler d1 execute vibe-sec-telemetry \
  --file=src/telemetry/schema.sql \
  --config=wrangler-telemetry.toml
```

## 4. Deploy

```bash
wrangler deploy --config=wrangler-telemetry.toml
```

## 5. Update telemetry endpoint

In `scripts/telemetry.mjs`, replace:
```js
|| "https://telemetry.vibe-sec.dev/v1/event"
```
With your actual Worker URL:
```js
|| "https://vibe-sec-telemetry.<your-subdomain>.workers.dev/v1/event"
```

## 6. Test

```bash
# Health check
curl https://vibe-sec-telemetry.<subdomain>.workers.dev/health

# Send a test event
curl -X POST https://vibe-sec-telemetry.<subdomain>.workers.dev/v1/event \
  -H "Content-Type: application/json" \
  -d '{"event":"scan_complete","device_id":"00000000-0000-0000-0000-000000000001","version":"0.1.0","os_version":"14.4","node_version":"v22.0.0","findings_total":3,"findings_critical":1,"findings_high":1,"findings_medium":1,"finding_types":["env_in_git","open_ports_all_interfaces"]}'

# Check public stats
curl https://vibe-sec-telemetry.<subdomain>.workers.dev/public/stats | jq .

# Browse raw events (no device_id exposed)
curl https://vibe-sec-telemetry.<subdomain>.workers.dev/public/events | jq .
```

## Public data access

Anyone can read:
- `GET /public/stats` — aggregated stats, cached 1h
- `GET /public/events?page=N` — raw anonymized events, paginated by 100

No auth needed for reads. All fields that could identify a user (device_id) are
excluded from public endpoints.

## Query D1 directly

```bash
# Total installs
wrangler d1 execute vibe-sec-telemetry \
  --command="SELECT COUNT(DISTINCT device_id) FROM events WHERE event='setup_complete'" \
  --config=wrangler-telemetry.toml

# Most common findings
wrangler d1 execute vibe-sec-telemetry \
  --command="SELECT value, COUNT(*) c FROM events, json_each(finding_types) WHERE event='scan_complete' GROUP BY value ORDER BY c DESC LIMIT 20" \
  --config=wrangler-telemetry.toml

# Tool adoption
wrangler d1 execute vibe-sec-telemetry \
  --command="SELECT ai_tools FROM events WHERE event='setup_complete' LIMIT 100" \
  --config=wrangler-telemetry.toml
```

## Share read access

To give a collaborator SQL access to the D1 database:
1. Cloudflare Dashboard → Workers & Pages → D1 → vibe-sec-telemetry
2. Create a read-only API token scoped to this database only
3. They can then use: `wrangler d1 execute vibe-sec-telemetry --command="SELECT ..."` with their token
