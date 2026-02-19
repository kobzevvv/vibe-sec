# ============================================================================
# vibe-sec dirty machine setup — Windows
#
# Creates a deliberately insecure developer environment for testing
# vibe-sec's static security scanner. All secrets are FAKE.
#
# Usage:  .\test\dirty-machine\setup-windows.ps1
# Cleanup: .\test\dirty-machine\teardown.ps1
# ============================================================================

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$FixturesDir = Join-Path $ScriptDir "fixtures"
$BackupDir = Join-Path $ScriptDir ".backup-$(Get-Date -Format 'yyyyMMddHHmmss')"
$HomeDir = $env:USERPROFILE
$ManifestPath = Join-Path $ScriptDir ".setup-manifest"

Write-Host ""
Write-Host "======================================================"
Write-Host "  vibe-sec: Dirty Machine Setup (Windows)"
Write-Host "  All secrets are FAKE - safe to run locally"
Write-Host "======================================================"
Write-Host ""

# Clear manifest
Set-Content -Path $ManifestPath -Value ""

# ─── Helper functions ─────────────────────────────────────────────────────────

function Backup-IfExists {
    param([string]$Target)
    if (Test-Path $Target) {
        if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null }
        $RelPath = $Target.Replace($HomeDir, "").TrimStart("\")
        $BackupPath = Join-Path $BackupDir $RelPath
        $BackupParent = Split-Path -Parent $BackupPath
        if (-not (Test-Path $BackupParent)) { New-Item -ItemType Directory -Path $BackupParent -Force | Out-Null }
        Copy-Item -Path $Target -Destination $BackupPath -Force
        Write-Host "  BACKED UP: $Target -> $BackupPath" -ForegroundColor Yellow
    }
}

function Install-Fixture {
    param([string]$Source, [string]$Dest, [string]$Desc)
    Backup-IfExists -Target $Dest
    $DestParent = Split-Path -Parent $Dest
    if (-not (Test-Path $DestParent)) { New-Item -ItemType Directory -Path $DestParent -Force | Out-Null }
    Copy-Item -Path $Source -Destination $Dest -Force
    Add-Content -Path $ManifestPath -Value $Dest
    Write-Host "  INSTALLED: $Dest ($Desc)" -ForegroundColor Green
}

function Append-Fixture {
    param([string]$Source, [string]$Dest, [string]$Desc)
    Backup-IfExists -Target $Dest
    $DestParent = Split-Path -Parent $Dest
    if (-not (Test-Path $DestParent)) { New-Item -ItemType Directory -Path $DestParent -Force | Out-Null }
    Add-Content -Path $Dest -Value ""
    Add-Content -Path $Dest -Value "# --- vibe-sec dirty machine test data START ---"
    Get-Content -Path $Source | Add-Content -Path $Dest
    Add-Content -Path $Dest -Value "# --- vibe-sec dirty machine test data END ---"
    Add-Content -Path $ManifestPath -Value "${Dest}:appended"
    Write-Host "  APPENDED: $Dest ($Desc)" -ForegroundColor Green
}

# ─── 1. Claude Code settings ─────────────────────────────────────────────────
Write-Host "1/13 Claude Code settings (dangerousMode + MCP tokens + @latest)"
Install-Fixture -Source (Join-Path $FixturesDir "claude-settings.json") `
    -Dest (Join-Path $HomeDir ".claude\settings.json") `
    -Desc "skipDangerousModePermissionPrompt + plaintext MCP tokens + @latest"

# ─── 2. Claude history ───────────────────────────────────────────────────────
Write-Host "2/13 Claude prompt history (injection patterns)"
Install-Fixture -Source (Join-Path $FixturesDir "claude-history.jsonl") `
    -Dest (Join-Path $HomeDir ".claude\history.jsonl") `
    -Desc "prompt injection attempts in history"

# ─── 3. CLAUDE.md ────────────────────────────────────────────────────────────
Write-Host "3/13 CLAUDE.md (no injection hardening)"
Install-Fixture -Source (Join-Path $FixturesDir "CLAUDE.md") `
    -Dest (Join-Path $HomeDir ".claude\CLAUDE.md") `
    -Desc "CLAUDE.md without prompt injection protection"

# ─── 4. Shell history — skip on Windows (no .zsh_history) ────────────────────
Write-Host "4/13 Shell history — skipped (Windows uses PowerShell history)"

# ─── 5. Google Service Account key ───────────────────────────────────────────
Write-Host "5/13 Google Service Account key"
Install-Fixture -Source (Join-Path $FixturesDir "fake-sa-key.json") `
    -Dest (Join-Path $HomeDir "Downloads\fake-sa-key.json") `
    -Desc "GCP service account JSON key in Downloads"

# ─── 6. Fly.io CLI token ─────────────────────────────────────────────────────
Write-Host "6/13 Fly.io CLI config"
Install-Fixture -Source (Join-Path $FixturesDir "fly-config.yml") `
    -Dest (Join-Path $HomeDir ".fly\config.yml") `
    -Desc "Fly.io access token in config"

# ─── 7. Paste cache ──────────────────────────────────────────────────────────
Write-Host "7/13 Claude paste cache (secrets in pasted content)"
$PasteCacheDir = Join-Path $HomeDir ".claude\paste-cache"
if (-not (Test-Path $PasteCacheDir)) { New-Item -ItemType Directory -Path $PasteCacheDir -Force | Out-Null }
Get-ChildItem (Join-Path $FixturesDir "paste-cache") | ForEach-Object {
    Install-Fixture -Source $_.FullName -Dest (Join-Path $PasteCacheDir $_.Name) -Desc "paste cache file"
}

# ─── 8. Shell snapshots ──────────────────────────────────────────────────────
Write-Host "8/13 Claude shell snapshots"
$SnapshotsDir = Join-Path $HomeDir ".claude\shell-snapshots"
if (-not (Test-Path $SnapshotsDir)) { New-Item -ItemType Directory -Path $SnapshotsDir -Force | Out-Null }
Get-ChildItem (Join-Path $FixturesDir "shell-snapshots") | ForEach-Object {
    Install-Fixture -Source $_.FullName -Dest (Join-Path $SnapshotsDir $_.Name) -Desc "shell snapshot"
}

# ─── 9. Clawdbot config ──────────────────────────────────────────────────────
Write-Host "9/13 Clawdbot config (Telegram bot token + gateway token)"
Install-Fixture -Source (Join-Path $FixturesDir "clawdbot-config.json") `
    -Dest (Join-Path $HomeDir ".clawdbot\clawdbot.json") `
    -Desc "Telegram bot token and gateway token in plaintext"

# ─── 10. SSH keys ─────────────────────────────────────────────────────────────
Write-Host "10/13 SSH keys (unencrypted private key)"
Install-Fixture -Source (Join-Path $FixturesDir "ssh-key-no-passphrase") `
    -Dest (Join-Path $HomeDir ".ssh\id_rsa_test_insecure") `
    -Desc "SSH private key without passphrase"

# ─── 11. Git credential store ────────────────────────────────────────────────
Write-Host "11/13 Git credential store (plaintext)"
Install-Fixture -Source (Join-Path $FixturesDir "git-credentials") `
    -Dest (Join-Path $HomeDir ".git-credentials") `
    -Desc "plaintext git credentials"

# ─── 12. Git repo with tracked .env ──────────────────────────────────────────
Write-Host "12/13 Git repo with tracked .env"
$RepoDir = Join-Path $env:TEMP "vibe-sec-test-repo"
if (Test-Path $RepoDir) { Remove-Item -Recurse -Force $RepoDir }
New-Item -ItemType Directory -Path $RepoDir -Force | Out-Null
Copy-Item -Path (Join-Path $FixturesDir "git-repo-with-env\.env") -Destination (Join-Path $RepoDir ".env")
Push-Location $RepoDir
git init -q
git add .env
git commit -q -m "initial commit with .env (oops)"
Pop-Location
Add-Content -Path $ManifestPath -Value $RepoDir
Write-Host "  CREATED: $RepoDir (git repo with tracked .env)" -ForegroundColor Green

# ─── 13. Docker Compose + Terraform state ────────────────────────────────────
Write-Host "13/13 Docker Compose + Terraform state"
$ComposeDir = Join-Path $env:TEMP "vibe-sec-test-compose"
$TfDir = Join-Path $env:TEMP "vibe-sec-test-terraform"
if (Test-Path $ComposeDir) { Remove-Item -Recurse -Force $ComposeDir }
if (Test-Path $TfDir) { Remove-Item -Recurse -Force $TfDir }
New-Item -ItemType Directory -Path $ComposeDir -Force | Out-Null
New-Item -ItemType Directory -Path $TfDir -Force | Out-Null
Copy-Item -Path (Join-Path $FixturesDir "docker-compose.yml") -Destination (Join-Path $ComposeDir "docker-compose.yml")
Copy-Item -Path (Join-Path $FixturesDir "terraform.tfstate") -Destination (Join-Path $TfDir "terraform.tfstate")
Add-Content -Path $ManifestPath -Value $ComposeDir
Add-Content -Path $ManifestPath -Value $TfDir
Write-Host "  CREATED: $ComposeDir\docker-compose.yml (ports on 0.0.0.0)" -ForegroundColor Green
Write-Host "  CREATED: $TfDir\terraform.tfstate (secrets in state)" -ForegroundColor Green

# ─── Summary ──────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "======================================================"
Write-Host "  Setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "  Run the scanner:"
Write-Host "    node scripts/scan-logs.mjs --static-only"
Write-Host ""
Write-Host "  Clean up:"
Write-Host "    .\test\dirty-machine\teardown.ps1"
Write-Host "======================================================"
Write-Host ""
