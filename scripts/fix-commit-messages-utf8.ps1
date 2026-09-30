# Corrige les messages des commits 45a046e et 51bc2ca (UTF-8, sans Co-authored-by).
param(
    [switch]$Push
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

# Accents via code points (évite la corruption d'encodage du fichier .ps1)
$e = [char]0x00E9
$a = [char]0x00E0

$utf8 = New-Object System.Text.UTF8Encoding $false
function Write-CommitMsg([string]$path, [string]$text) {
    [System.IO.File]::WriteAllText($path, $text, $utf8)
}

$env:GIT_AUTHOR_NAME = '1donatien0'
$env:GIT_AUTHOR_EMAIL = '2742813@collegelacite.ca'
$env:GIT_COMMITTER_NAME = '1donatien0'
$env:GIT_COMMITTER_EMAIL = '2742813@collegelacite.ca'

$msgDir = git rev-parse --git-dir
$defenderMsg = "feat: exclusions Windows Defender automatiques ${a} l'install et au d${e}marrage"

$winuiMsg = @"
feat(winui): migration WinUI 3 avec couche Application partag${e}e

Ajoute optiSCAN.WinUI, optiSCAN.Application, abstractions UI (INavigationService, IUiThreadScheduler), et refactore le WPF existant pour le partage de logique m${e}tier.
"@

# 1) Réécrire le commit Defender (tip actuel de main / parent de win)
$oldDefender = git rev-parse main
$parentDefender = git rev-parse "$oldDefender^"
$treeDefender = git rev-parse "$oldDefender^{tree}"
$defenderFile = Join-Path $msgDir 'COMMIT_MSG_DEFENDER'
Write-CommitMsg $defenderFile $defenderMsg
$newDefender = git commit-tree $treeDefender -p $parentDefender -F $defenderFile
Write-Host "Defender: $oldDefender -> $newDefender"

# 2) Réécrire HEAD win (51bc2ca) au-dessus du nouveau parent
$oldWinui = git rev-parse win
$treeWinui = git rev-parse "$oldWinui^{tree}"
$winuiFile = Join-Path $msgDir 'COMMIT_MSG_WINUI'
Write-CommitMsg $winuiFile $winuiMsg
$newWinui = git commit-tree $treeWinui -p $newDefender -F $winuiFile
git update-ref refs/heads/win $newWinui $oldWinui
Write-Host "WinUI: $oldWinui -> $newWinui"

# 3) Mettre à jour main si elle pointe encore sur l'ancien defender
$mainTip = git rev-parse main 2>$null
if ($mainTip -eq $oldDefender) {
    git update-ref refs/heads/main $newDefender $oldDefender
    Write-Host "main: $oldDefender -> $newDefender"
}

Write-Host ''
git log win -2 --format='%h %s%nAuthor: %an <%ae>%n%b'

if ($Push) {
    git push --force-with-lease origin win
    if ($mainTip -eq $oldDefender) {
        git push --force-with-lease origin main
    }
    Write-Host 'Pousse sur origin (win' -NoNewline
    if ($mainTip -eq $oldDefender) { Write-Host ' + main)' } else { Write-Host ')' }
}
