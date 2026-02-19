#!/bin/bash
# ============================================================================
# vibe-sec dirty machine setup — macOS
#
# Creates a deliberately insecure developer environment for testing
# vibe-sec's static security scanner. All secrets are FAKE.
#
# Usage:  ./test/dirty-machine/setup-macos.sh
# Cleanup: ./test/dirty-machine/teardown.sh
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FIXTURES="$SCRIPT_DIR/fixtures"
BACKUP_DIR="$SCRIPT_DIR/.backup-$(date +%s)"
HOME_DIR="$HOME"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo ""
echo "======================================================"
echo "  vibe-sec: Dirty Machine Setup (macOS)"
echo "  All secrets are FAKE — safe to run locally"
echo "======================================================"
echo ""

# Track what we set up for teardown
MANIFEST="$SCRIPT_DIR/.setup-manifest"
: > "$MANIFEST"

# ─── Helper functions ─────────────────────────────────────────────────────────

backup_if_exists() {
  local target="$1"
  if [ -f "$target" ] || [ -d "$target" ]; then
    mkdir -p "$BACKUP_DIR"
    local rel_path="${target#$HOME_DIR/}"
    local backup_path="$BACKUP_DIR/$rel_path"
    mkdir -p "$(dirname "$backup_path")"
    cp -a "$target" "$backup_path"
    echo -e "  ${YELLOW}BACKED UP${NC}: $target → $BACKUP_DIR/$rel_path"
  fi
}

install_fixture() {
  local src="$1"
  local dest="$2"
  local desc="$3"

  backup_if_exists "$dest"
  mkdir -p "$(dirname "$dest")"
  cp "$src" "$dest"
  echo "$dest" >> "$MANIFEST"
  echo -e "  ${GREEN}INSTALLED${NC}: $dest ($desc)"
}

append_fixture() {
  local src="$1"
  local dest="$2"
  local desc="$3"

  backup_if_exists "$dest"
  mkdir -p "$(dirname "$dest")"
  # Add a marker so teardown can remove only our lines
  echo "" >> "$dest"
  echo "# --- vibe-sec dirty machine test data START ---" >> "$dest"
  cat "$src" >> "$dest"
  echo "# --- vibe-sec dirty machine test data END ---" >> "$dest"
  echo "$dest:appended" >> "$MANIFEST"
  echo -e "  ${GREEN}APPENDED${NC}: $dest ($desc)"
}

# ─── 1. Claude Code settings ─────────────────────────────────────────────────
echo "1/13 Claude Code settings (dangerousMode + MCP tokens + @latest)"
install_fixture "$FIXTURES/claude-settings.json" "$HOME_DIR/.claude/settings.json" \
  "skipDangerousModePermissionPrompt + plaintext MCP tokens + @latest"

# ─── 2. Claude history (prompt injection indicators) ──────────────────────────
echo "2/13 Claude prompt history (injection patterns)"
install_fixture "$FIXTURES/claude-history.jsonl" "$HOME_DIR/.claude/history.jsonl" \
  "prompt injection attempts in history"

# ─── 3. CLAUDE.md (no prompt injection protection) ───────────────────────────
echo "3/13 CLAUDE.md (no injection hardening)"
install_fixture "$FIXTURES/CLAUDE.md" "$HOME_DIR/.claude/CLAUDE.md" \
  "CLAUDE.md without prompt injection protection"

# ─── 4. Shell history with leaked secrets ─────────────────────────────────────
echo "4/13 Shell history secrets"
append_fixture "$FIXTURES/zsh_history" "$HOME_DIR/.zsh_history" \
  "API keys and tokens in zsh history"

# ─── 5. Google Service Account key in Downloads ──────────────────────────────
echo "5/13 Google Service Account key"
install_fixture "$FIXTURES/fake-sa-key.json" "$HOME_DIR/Downloads/fake-sa-key.json" \
  "GCP service account JSON key in Downloads"

# ─── 6. Fly.io CLI token ─────────────────────────────────────────────────────
echo "6/13 Fly.io CLI config"
install_fixture "$FIXTURES/fly-config.yml" "$HOME_DIR/.fly/config.yml" \
  "Fly.io access token in config"

# ─── 7. Paste cache with secrets ─────────────────────────────────────────────
echo "7/13 Claude paste cache (secrets in pasted content)"
mkdir -p "$HOME_DIR/.claude/paste-cache"
for f in "$FIXTURES/paste-cache/"*; do
  fname=$(basename "$f")
  install_fixture "$f" "$HOME_DIR/.claude/paste-cache/$fname" "paste cache file"
done

# ─── 8. Shell snapshots ──────────────────────────────────────────────────────
echo "8/13 Claude shell snapshots"
mkdir -p "$HOME_DIR/.claude/shell-snapshots"
for f in "$FIXTURES/shell-snapshots/"*; do
  fname=$(basename "$f")
  install_fixture "$f" "$HOME_DIR/.claude/shell-snapshots/$fname" "shell snapshot"
done

# ─── 9. Clawdbot config ──────────────────────────────────────────────────────
echo "9/13 Clawdbot config (Telegram bot token + gateway token)"
install_fixture "$FIXTURES/clawdbot-config.json" "$HOME_DIR/.clawdbot/clawdbot.json" \
  "Telegram bot token and gateway token in plaintext"

# ─── 10. SSH keys ─────────────────────────────────────────────────────────────
echo "10/13 SSH keys (unencrypted private key)"
install_fixture "$FIXTURES/ssh-key-no-passphrase" "$HOME_DIR/.ssh/id_rsa_test_insecure" \
  "SSH private key without passphrase"
chmod 600 "$HOME_DIR/.ssh/id_rsa_test_insecure"

# ─── 11. Git credential store ────────────────────────────────────────────────
echo "11/13 Git credential store (plaintext)"
install_fixture "$FIXTURES/git-credentials" "$HOME_DIR/.git-credentials" \
  "plaintext git credentials"

# ─── 12. Git repo with tracked .env ──────────────────────────────────────────
echo "12/13 Git repo with tracked .env"
REPO_DIR="/tmp/vibe-sec-test-repo"
rm -rf "$REPO_DIR"
mkdir -p "$REPO_DIR"
cp "$FIXTURES/git-repo-with-env/.env" "$REPO_DIR/.env"
(
  cd "$REPO_DIR"
  git init -q
  git add .env
  git commit -q -m "initial commit with .env (oops)"
)
echo "$REPO_DIR" >> "$MANIFEST"
echo -e "  ${GREEN}CREATED${NC}: $REPO_DIR (git repo with tracked .env)"

# ─── 13. Docker Compose + Terraform state ────────────────────────────────────
echo "13/13 Docker Compose + Terraform state"
COMPOSE_DIR="/tmp/vibe-sec-test-compose"
TF_DIR="/tmp/vibe-sec-test-terraform"
rm -rf "$COMPOSE_DIR" "$TF_DIR"
mkdir -p "$COMPOSE_DIR" "$TF_DIR"
cp "$FIXTURES/docker-compose.yml" "$COMPOSE_DIR/docker-compose.yml"
cp "$FIXTURES/terraform.tfstate" "$TF_DIR/terraform.tfstate"
echo "$COMPOSE_DIR" >> "$MANIFEST"
echo "$TF_DIR" >> "$MANIFEST"
echo -e "  ${GREEN}CREATED${NC}: $COMPOSE_DIR/docker-compose.yml (ports on 0.0.0.0)"
echo -e "  ${GREEN}CREATED${NC}: $TF_DIR/terraform.tfstate (secrets in state)"

# ─── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "======================================================"
echo -e "  ${GREEN}Setup complete!${NC}"
echo ""
echo "  Fixture locations:"
echo "    ~/.claude/settings.json        — dangerousMode, MCP tokens, @latest"
echo "    ~/.claude/history.jsonl        — prompt injection indicators"
echo "    ~/.claude/CLAUDE.md            — no injection hardening"
echo "    ~/.zsh_history                 — appended secrets"
echo "    ~/Downloads/fake-sa-key.json   — GCP service account key"
echo "    ~/.fly/config.yml              — Fly.io token"
echo "    ~/.claude/paste-cache/         — 11 files (with secrets)"
echo "    ~/.claude/shell-snapshots/     — env snapshot"
echo "    ~/.clawdbot/clawdbot.json      — Telegram + gateway tokens"
echo "    ~/.ssh/id_rsa_test_insecure    — unencrypted SSH key"
echo "    ~/.git-credentials             — plaintext git credentials"
echo "    /tmp/vibe-sec-test-repo/       — git repo with tracked .env"
echo "    /tmp/vibe-sec-test-compose/    — docker-compose on 0.0.0.0"
echo "    /tmp/vibe-sec-test-terraform/  — tfstate with secrets"
if [ -d "$BACKUP_DIR" ]; then
  echo ""
  echo -e "  ${YELLOW}Backups saved to: $BACKUP_DIR${NC}"
fi
echo ""
echo "  Run the scanner:"
echo "    node scripts/scan-logs.mjs --static-only"
echo ""
echo "  Clean up:"
echo "    ./test/dirty-machine/teardown.sh"
echo "======================================================"
echo ""
