# Parcourt l'historique et retire Co-authored-by: Cursor de tous les messages.
# Usage : pwsh -File scripts/strip-cursor-coauthor-from-history.ps1 [-Branch win] [-Push]
param(
    [string]$Branch = 'win',
    [switch]$Push
)

$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)

$strip = Join-Path $PSScriptRoot 'strip-cursor-coauthor-msg.ps1'
$env:FILTER_BRANCH_SQUELCH_WARNING = '1'

git filter-branch -f --msg-filter "powershell -NoProfile -ExecutionPolicy Bypass -File `"$strip`"" $Branch

if ($Push) {
    & git push --force-with-lease origin $Branch
    Write-Host "Poussé sur origin/$Branch"
}
