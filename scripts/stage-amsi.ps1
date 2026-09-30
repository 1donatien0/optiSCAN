<#
.SYNOPSIS
    Copie optiSCAN.AmsiProvider.dll et les fichiers du minifiltre (.inf, .sys, .cat) vers un dossier de publication.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $PublishDir,
    [string] $Configuration = 'Release',
    [string] $Platform = 'x64'
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$dll = Join-Path $repo "native\optiSCAN.AmsiProvider\$Platform\$Configuration\optiSCAN.AmsiProvider.dll"
$pub = (Resolve-Path -LiteralPath $PublishDir).Path

# DLL AMSI absente : avertir sans interrompre — le minifiltre doit être copié quand même.
if (Test-Path -LiteralPath $dll) {
    Copy-Item -LiteralPath $dll -Destination (Join-Path $pub 'optiSCAN.AmsiProvider.dll') -Force
    Write-Host "  Copie optiSCAN.AmsiProvider.dll -> $pub" -ForegroundColor DarkGray
}
else {
    Write-Warning "AMSI DLL absente — exécuter scripts/build-amsi.ps1 ($dll)"
}

$inf = Join-Path $repo 'native\optiSCAN.Minifilter\optiSCAN.Minifilter.inf'
if (Test-Path -LiteralPath $inf) {
    Copy-Item -LiteralPath $inf -Destination (Join-Path $pub 'optiSCAN.Minifilter.inf') -Force
    Write-Host "  Copie optiSCAN.Minifilter.inf -> $pub" -ForegroundColor DarkGray
}

$sys = Join-Path $repo "native\optiSCAN.Minifilter\$Platform\optiSCAN.Minifilter.sys"
if (Test-Path -LiteralPath $sys) {
    Copy-Item -LiteralPath $sys -Destination (Join-Path $pub 'optiSCAN.Minifilter.sys') -Force
    Write-Host "  Copie optiSCAN.Minifilter.sys -> $pub" -ForegroundColor DarkGray
}

# Catalogue signé (après signature du pilote) : permet l'installation via pnputil.
$cat = Join-Path $repo "native\optiSCAN.Minifilter\$Platform\optiSCAN.Minifilter.cat"
if (Test-Path -LiteralPath $cat) {
    Copy-Item -LiteralPath $cat -Destination (Join-Path $pub 'optiSCAN.Minifilter.cat') -Force
    Write-Host "  Copie optiSCAN.Minifilter.cat -> $pub" -ForegroundColor DarkGray
}
