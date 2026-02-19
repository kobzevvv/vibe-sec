#!/bin/bash
# ============================================================================
# vibe-sec dirty machine teardown — macOS / Linux
#
# Removes all test fixtures and restores backed-up files.
#
# Usage: ./test/dirty-machine/teardown.sh
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HOME_DIR="$HOME"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo ""
echo "======================================================"
echo "  vibe-sec: Dirty Machine Teardown"
echo "======================================================"
echo ""

MANIFEST="$SCRIPT_DIR/.setup-manifest"

# Find the most recent backup directory
BACKUP_DIR=$(ls -dt "$SCRIPT_DIR"/.backup-* 2>/dev/null | head -1 || true)

# ─── Remove installed fixtures ────────────────────────────────────────────────

if [ -f "$MANIFEST" ]; then
  while IFS= read -r line; do
    [ -z "$line" ] && continue

    if [[ "$line" == *":appended" ]]; then
      # Remove appended content
      target="${line%:appended}"
      if [ -f "$target" ]; then
        # Remove everything between our markers
        if grep -q "vibe-sec dirty machine test data START" "$target" 2>/dev/null; then
          LC_ALL=C sed -i '' '/# --- vibe-sec dirty machine test data START ---/,/# --- vibe-sec dirty machine test data END ---/d' "$target"
          echo -e "  ${GREEN}CLEANED${NC}: $target (removed appended test data)"
        fi
      fi
    elif [ -d "$line" ]; then
      rm -rf "$line"
      echo -e "  ${GREEN}REMOVED${NC}: $line/ (directory)"
    elif [ -f "$line" ]; then
      rm -f "$line"
      echo -e "  ${GREEN}REMOVED${NC}: $line"
    fi
  done < "$MANIFEST"
  rm -f "$MANIFEST"
else
  echo -e "  ${YELLOW}No manifest found${NC} — removing known test locations..."

  # Fallback: remove known fixture locations
  rm -f "$HOME_DIR/.claude/settings.json"
  rm -f "$HOME_DIR/.claude/history.jsonl"
  rm -f "$HOME_DIR/.claude/CLAUDE.md"
  rm -f "$HOME_DIR/Downloads/fake-sa-key.json"
  rm -f "$HOME_DIR/.fly/config.yml"
  rm -rf "$HOME_DIR/.claude/paste-cache"
  rm -rf "$HOME_DIR/.claude/shell-snapshots"
  rm -f "$HOME_DIR/.clawdbot/clawdbot.json"
  rm -f "$HOME_DIR/.ssh/id_rsa_test_insecure"
  rm -f "$HOME_DIR/.git-credentials"
  rm -rf /tmp/vibe-sec-test-repo
  rm -rf /tmp/vibe-sec-test-compose
  rm -rf /tmp/vibe-sec-test-terraform

  echo -e "  ${GREEN}Removed${NC} all known fixture locations"
fi

# ─── Restore backups ─────────────────────────────────────────────────────────

if [ -n "$BACKUP_DIR" ] && [ -d "$BACKUP_DIR" ]; then
  echo ""
  echo "Restoring backups from: $BACKUP_DIR"
  (
    cd "$BACKUP_DIR"
    find . -type f | while IFS= read -r file; do
      rel="${file#./}"
      dest="$HOME_DIR/$rel"
      mkdir -p "$(dirname "$dest")"
      cp "$file" "$dest"
      echo -e "  ${GREEN}RESTORED${NC}: $dest"
    done
  )
  rm -rf "$BACKUP_DIR"
  echo -e "  ${GREEN}Backup directory removed${NC}"
else
  echo ""
  echo -e "  ${YELLOW}No backup directory found${NC} — nothing to restore"
fi

# ─── Clean up empty directories ──────────────────────────────────────────────

rmdir "$HOME_DIR/.fly" 2>/dev/null || true
rmdir "$HOME_DIR/.clawdbot" 2>/dev/null || true

echo ""
echo "======================================================"
echo -e "  ${GREEN}Teardown complete!${NC}"
echo "  Your system has been restored to its previous state."
echo "======================================================"
echo ""
