# SPDX-License-Identifier: GPL-3.0-or-later
# Réécrit le commit HEAD sans ligne Co-authored-by: Cursor (contourne les hooks Cursor).
# Usage : pwsh -File scripts/rewrite-head-without-cursor-coauthor.ps1 [-Branch win] [-Push]
param(
    [string]$Branch = 'win',
    [switch]$Push
)

$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)

$current = git rev-parse $Branch
$parent = git rev-parse "$current^"
$tree = git rev-parse "$current^{tree}"

$subject = git log -1 --format=%s $current
$body = git log -1 --format=%b $current
$cleanBody = ($body -split "`r?`n" | Where-Object { $_ -notmatch '^\s*Co-authored-by:\s*Cursor\s*<' }) -join "`n"
$msg = if ([string]::IsNullOrWhiteSpace($cleanBody)) { $subject } else { "$subject`n`n$($cleanBody.Trim())" }

$msgFile = Join-Path (git rev-parse --git-dir) 'COMMIT_MSG_CLEAN'
[System.IO.File]::WriteAllText($msgFile, $msg)

$env:GIT_AUTHOR_NAME = '1donatien0'
$env:GIT_AUTHOR_EMAIL = '2742813@collegelacite.ca'
$env:GIT_COMMITTER_NAME = '1donatien0'
$env:GIT_COMMITTER_EMAIL = '2742813@collegelacite.ca'

$new = & git commit-tree $tree -p $parent -F $msgFile
& git update-ref "refs/heads/$Branch" $new $current

Write-Host "Ancien : $current"
Write-Host "Nouveau : $new"
git log -1 --format='Author: %an <%ae>%nCommitter: %cn <%ce>%n%b' $Branch

if ($Push) {
    & git push --force-with-lease origin $Branch
    Write-Host "Poussé sur origin/$Branch"
}
