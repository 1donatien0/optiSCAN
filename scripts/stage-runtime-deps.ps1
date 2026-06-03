<#
.SYNOPSIS
    Copie clamav / yara / rules / certificats du projet vers un dossier de publication.

.PARAMETER PublishDir
    Cible (ex. publish\win-x64 ou bin\...\publish\win-x64).

.PARAMETER SourceRoot
    Racine optiSCAN (défaut : optiSCAN\ sous le dépôt).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $PublishDir,
    [string] $SourceRoot
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$src = if ($SourceRoot) { $SourceRoot } else { Join-Path $repo 'optiSCAN' }
$pub = (Resolve-Path -LiteralPath $PublishDir).Path

function Copy-Tree([string] $rel) {
    $from = Join-Path $src $rel
    if (-not (Test-Path $from)) {
        Write-Warning "Source absente : $from"
        return
    }
    $to = Join-Path $pub $rel
    New-Item -ItemType Directory -Force -Path (Split-Path $to -Parent) | Out-Null
    Copy-Item -LiteralPath $from -Destination $to -Recurse -Force
    Write-Host "  Copie $rel" -ForegroundColor DarkGray
}

Write-Host "stage-runtime-deps -> $pub" -ForegroundColor Cyan
Copy-Tree 'clamav\x64'
Copy-Tree 'clamav\x86'
Copy-Tree 'clamav\database'
Copy-Tree 'clamav\certs'
Copy-Tree 'yara'
Copy-Tree 'rules'
