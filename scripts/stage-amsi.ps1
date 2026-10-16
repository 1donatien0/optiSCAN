# SPDX-License-Identifier: GPL-3.0-or-later
<#
.SYNOPSIS
    Copie optiSCAN.AmsiProvider.dll vers un dossier de publication.
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

if (-not (Test-Path -LiteralPath $dll)) {
    Write-Warning "AMSI DLL absente — exécuter scripts/build-amsi.ps1 ($dll)"
    return
}

Copy-Item -LiteralPath $dll -Destination (Join-Path $pub 'optiSCAN.AmsiProvider.dll') -Force
Write-Host "  Copie optiSCAN.AmsiProvider.dll -> $pub" -ForegroundColor DarkGray
