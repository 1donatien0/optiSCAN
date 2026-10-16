# SPDX-License-Identifier: GPL-3.0-or-later
# Liste les branches distantes (hors main/dev). Usage : .\scripts\list-remote-branches.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
git fetch origin --prune 2>&1 | Out-Host
Write-Host "`n=== Branches distantes ===" -ForegroundColor Cyan
git branch -r
$extra = git branch -r | ForEach-Object { $_.Trim() } |
    Where-Object { $_ -match '^origin/' -and $_ -notmatch '^origin/HEAD' -and $_ -notin @('origin/main', 'origin/dev') }
if ($extra) {
    Write-Host "`nBranches a supprimer sur origin (si obsolete) :" -ForegroundColor Yellow
    $extra | ForEach-Object { Write-Host "  git push origin --delete $($_.Replace('origin/',''))" }
} else {
    Write-Host "`nOK : seules origin/main et origin/dev (ou equivalent)." -ForegroundColor Green
}
Write-Host "`n=== Tips locaux ===" -ForegroundColor Cyan
git branch -vv
Write-Host "main : $(git rev-parse --short main)  dev : $(git rev-parse --short dev)"
