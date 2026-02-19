# ============================================================================
# vibe-sec dirty machine teardown — Windows
#
# Removes all test fixtures and restores backed-up files.
#
# Usage: .\test\dirty-machine\teardown.ps1
# ============================================================================

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$HomeDir = $env:USERPROFILE
$ManifestPath = Join-Path $ScriptDir ".setup-manifest"

Write-Host ""
Write-Host "======================================================"
Write-Host "  vibe-sec: Dirty Machine Teardown (Windows)"
Write-Host "======================================================"
Write-Host ""

# Find the most recent backup directory
$BackupDir = Get-ChildItem -Path $ScriptDir -Filter ".backup-*" -Directory -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1

# ─── Remove installed fixtures ────────────────────────────────────────────────

if (Test-Path $ManifestPath) {
    Get-Content $ManifestPath | ForEach-Object {
        $line = $_.Trim()
        if (-not $line) { return }

        if ($line.EndsWith(":appended")) {
            $target = $line.Replace(":appended", "")
            if (Test-Path $target) {
                $content = Get-Content $target -Raw
                $pattern = "(?s)\r?\n?# --- vibe-sec dirty machine test data START ---.*?# --- vibe-sec dirty machine test data END ---\r?\n?"
                $cleaned = $content -replace $pattern, ""
                Set-Content -Path $target -Value $cleaned -NoNewline
                Write-Host "  CLEANED: $target (removed appended test data)" -ForegroundColor Green
            }
        }
        elseif (Test-Path $line -PathType Container) {
            Remove-Item -Recurse -Force $line
            Write-Host "  REMOVED: $line\ (directory)" -ForegroundColor Green
        }
        elseif (Test-Path $line) {
            Remove-Item -Force $line
            Write-Host "  REMOVED: $line" -ForegroundColor Green
        }
    }
    Remove-Item -Force $ManifestPath
}
else {
    Write-Host "  No manifest found - removing known test locations..." -ForegroundColor Yellow

    # Fallback: remove known fixture locations
    $KnownPaths = @(
        (Join-Path $HomeDir ".claude\settings.json"),
        (Join-Path $HomeDir ".claude\history.jsonl"),
        (Join-Path $HomeDir ".claude\CLAUDE.md"),
        (Join-Path $HomeDir "Downloads\fake-sa-key.json"),
        (Join-Path $HomeDir ".fly\config.yml"),
        (Join-Path $HomeDir ".clawdbot\clawdbot.json"),
        (Join-Path $HomeDir ".ssh\id_rsa_test_insecure"),
        (Join-Path $HomeDir ".git-credentials")
    )
    foreach ($p in $KnownPaths) {
        if (Test-Path $p) { Remove-Item -Force $p; Write-Host "  REMOVED: $p" -ForegroundColor Green }
    }

    $KnownDirs = @(
        (Join-Path $HomeDir ".claude\paste-cache"),
        (Join-Path $HomeDir ".claude\shell-snapshots"),
        (Join-Path $env:TEMP "vibe-sec-test-repo"),
        (Join-Path $env:TEMP "vibe-sec-test-compose"),
        (Join-Path $env:TEMP "vibe-sec-test-terraform")
    )
    foreach ($d in $KnownDirs) {
        if (Test-Path $d) { Remove-Item -Recurse -Force $d; Write-Host "  REMOVED: $d\" -ForegroundColor Green }
    }

    Write-Host "  Removed all known fixture locations" -ForegroundColor Green
}

# ─── Restore backups ─────────────────────────────────────────────────────────

if ($BackupDir) {
    Write-Host ""
    Write-Host "Restoring backups from: $($BackupDir.FullName)"

    Get-ChildItem -Path $BackupDir.FullName -Recurse -File | ForEach-Object {
        $RelPath = $_.FullName.Replace($BackupDir.FullName, "").TrimStart("\")
        $Dest = Join-Path $HomeDir $RelPath
        $DestParent = Split-Path -Parent $Dest
        if (-not (Test-Path $DestParent)) { New-Item -ItemType Directory -Path $DestParent -Force | Out-Null }
        Copy-Item -Path $_.FullName -Destination $Dest -Force
        Write-Host "  RESTORED: $Dest" -ForegroundColor Green
    }

    Remove-Item -Recurse -Force $BackupDir.FullName
    Write-Host "  Backup directory removed" -ForegroundColor Green
}
else {
    Write-Host ""
    Write-Host "  No backup directory found - nothing to restore" -ForegroundColor Yellow
}

# ─── Clean up empty directories ──────────────────────────────────────────────

foreach ($d in @((Join-Path $HomeDir ".fly"), (Join-Path $HomeDir ".clawdbot"))) {
    if ((Test-Path $d) -and ((Get-ChildItem $d -ErrorAction SilentlyContinue).Count -eq 0)) {
        Remove-Item $d -ErrorAction SilentlyContinue
    }
}

Write-Host ""
Write-Host "======================================================"
Write-Host "  Teardown complete!" -ForegroundColor Green
Write-Host "  Your system has been restored to its previous state."
Write-Host "======================================================"
Write-Host ""
