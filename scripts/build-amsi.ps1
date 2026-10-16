<#
.SYNOPSIS
    Compile optiSCAN.AmsiProvider.dll (Release x64) via MSBuild / Visual Studio.

.PARAMETER Configuration
    MSBuild configuration (défaut : Release).

.PARAMETER Platform
    Plateforme MSBuild (défaut : x64).

.NOTES
    SPDX-License-Identifier: GPL-3.0-or-later
#>
[CmdletBinding()]
param(
    [string] $Configuration = 'Release',
    [string] $Platform = 'x64',
    # Release : échec si Visual Studio C++ manque (au lieu d'un simple avertissement).
    [switch] $Require
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$vcxproj = Join-Path $repo 'native\optiSCAN.AmsiProvider\optiSCAN.AmsiProvider.vcxproj'

if (-not (Test-Path -LiteralPath $vcxproj)) {
    throw "Projet introuvable : $vcxproj"
}

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) {
    if ($Require) { throw "vswhere absent : Visual Studio (C++) requis pour le fournisseur AMSI." }
    Write-Warning "vswhere absent — build AMSI ignoré (environnement sans Visual Studio)."
    exit 0
}

$msbuild = & $vswhere -latest -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe' | Select-Object -First 1
if (-not $msbuild) {
    if ($Require) { throw "MSBuild introuvable : Visual Studio (C++) requis pour le fournisseur AMSI." }
    Write-Warning "MSBuild introuvable — build AMSI ignoré."
    exit 0
}

Write-Host "Build AMSI : $vcxproj ($Configuration|$Platform)" -ForegroundColor Cyan
& $msbuild $vcxproj /p:Configuration=$Configuration /p:Platform=$Platform /m /v:minimal
if ($LASTEXITCODE -ne 0) {
    if ($Require) { throw "Compilation du fournisseur AMSI échouée (code $LASTEXITCODE)." }
    Write-Warning "Compilation du fournisseur AMSI échouée (code $LASTEXITCODE)."
    exit 0
}

$dll = Join-Path $repo "native\optiSCAN.AmsiProvider\$Platform\$Configuration\optiSCAN.AmsiProvider.dll"
if (-not (Test-Path -LiteralPath $dll)) {
    throw "DLL AMSI absente après build : $dll"
}

Write-Host "AMSI OK : $dll" -ForegroundColor Green
