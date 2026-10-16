# SPDX-License-Identifier: GPL-3.0-or-later
<#
.SYNOPSIS
    Chaîne de préparation des releases v3.x (dépôt -> installateur testé).

.EXAMPLE
    .\scripts\prepare-release-v3.ps1
    .\scripts\prepare-release-v3.ps1 -SkipFreshclam
    .\scripts\prepare-release-v3.ps1 -SkipInstaller -RunFreshclam
#>
[CmdletBinding()]
param(
    [switch] $SkipTests,
    [switch] $SkipFetch,
    [switch] $SkipFreshclam,
    [switch] $SkipInstaller,
    [switch] $SkipClean,
    [switch] $SelfContained,
    [switch] $IncludeInstallerOutput
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$tfm = 'net10.0-windows10.0.17763.0'
$pubDir = if ($SelfContained) {
    Join-Path $root 'publish\win-x64'
} else {
    Join-Path $root "optiSCAN\bin\Release\$tfm\publish\win-x64"
}

function Invoke-Step([string] $label, [scriptblock] $action) {
    Write-Host "`n=== $label ===" -ForegroundColor Cyan
    & $action
    if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) {
        throw "$label a échoué (code $LASTEXITCODE)."
    }
}

if (-not $SkipClean) {
    Invoke-Step 'Nettoyage' {
        $cleanArgs = @{ IncludeObj = $true; IncludeCiPublish = $true }
        if ($IncludeInstallerOutput) { $cleanArgs['IncludeInstallerOutput'] = $true }
        & (Join-Path $root 'scripts\clean-before-publish.ps1') @cleanArgs
    }
}

if (-not $SkipFetch) {
    # Une release exige la vérification GPG de l'archive ClamAV.
    $fetchArgs = @('-RequireSignature')
    if (-not $SkipFreshclam) { $fetchArgs += '-RunFreshclam' }
    Invoke-Step 'Dependances ClamAV + YARA' {
        & (Join-Path $root 'scripts\fetch-runtime-deps.ps1') @fetchArgs
    }
}

if (-not $SkipTests) {
    Invoke-Step 'Tests Release' {
        dotnet test (Join-Path $root 'optiSCAN.Tests\optiSCAN.Tests.csproj') -c Release
    }
}

Invoke-Step 'dotnet publish' {
    $csproj = Join-Path $root 'optiSCAN\optiSCAN.csproj'
    $svc = Join-Path $root 'optiSCAN.Service\optiSCAN.Service.csproj'
    $hostProj = Join-Path $root 'optiSCAN.Host\optiSCAN.Host.csproj'
    if ($SelfContained) {
        dotnet publish $csproj -p:OptiscanShipping=true -c Release -r win-x64 --self-contained true `
            -p:PublishSingleFile=false -o $pubDir
        if ($LASTEXITCODE -ne 0) { return }
        dotnet publish $svc -p:OptiscanShipping=true -c Release -r win-x64 --self-contained true `
            -p:PublishSingleFile=false -o $pubDir
        if ($LASTEXITCODE -ne 0) { return }
        dotnet publish $hostProj -p:OptiscanShipping=true -c Release -r win-x64 --self-contained true `
            -p:PublishSingleFile=false -o $pubDir
    } else {
        # Le profil FolderProfile publie l'application en autonome : le service est publié
        # dans le même dossier et le même mode, avec sa DLL et ses dépendances (l'exe seul
        # ne démarre pas).
        dotnet publish $csproj -p:OptiscanShipping=true -c Release /p:PublishProfile=FolderProfile
        if ($LASTEXITCODE -ne 0) { return }
        dotnet publish $svc -p:OptiscanShipping=true -c Release -r win-x64 --self-contained true `
            -p:PublishSingleFile=false -o $pubDir
        if ($LASTEXITCODE -ne 0) { return }
        dotnet publish $hostProj -p:OptiscanShipping=true -c Release -r win-x64 --self-contained true `
            -p:PublishSingleFile=false -o $pubDir
    }
}

Invoke-Step 'Verification publish' {
    $verify = Join-Path $root 'scripts\verify-runtime-deps.ps1'
    if ($SkipFreshclam) {
        & $verify -PublishDir $pubDir -AllowMissingSignatures
    } else {
        & $verify -PublishDir $pubDir
    }
}

if (-not $SkipInstaller) {
    Invoke-Step 'Installateur Inno' {
        $build = Join-Path $root 'installer\build-release-setup.ps1'
        if ($SelfContained) {
            & $build -SkipPublish -PublishDir $pubDir
        } else {
            & $build -SkipPublish
        }
    }
}

[xml]$propsXml = Get-Content -LiteralPath (Join-Path $root 'Directory.Build.props')
$appVersion = ($propsXml.Project.PropertyGroup.Version | Select-Object -First 1).'#text'
$appRelease = if ($appVersion -match '^(\d+)\.(\d+)') { "v$($Matches[1]).$($Matches[2])" } else { 'v3' }
Write-Host "`n=== Preparation $appRelease ===" -ForegroundColor Green
Write-Host "  Publish : $pubDir"
Write-Host "  Setup   : installer\output\optiSCAN_Setup_v$appVersion.exe"
