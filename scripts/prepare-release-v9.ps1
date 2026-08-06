<#
.SYNOPSIS
    Chaîne complète de publication v9.0 (dépôt -> installateur testé).

.EXAMPLE
    .\scripts\prepare-release-v9.ps1
    .\scripts\prepare-release-v9.ps1 -SkipFreshclam
    .\scripts\prepare-release-v9.ps1 -SkipInstaller -RunFreshclam
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

$tfm = 'net8.0-windows10.0.17763.0'
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
    $fetchArgs = @()
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
    if ($SelfContained) {
        dotnet publish $csproj -c Release -r win-x64 --self-contained true `
            -p:PublishSingleFile=false -o $pubDir
        dotnet publish $svc -c Release -r win-x64 --self-contained true `
            -p:PublishSingleFile=false -o $pubDir
    } else {
        dotnet publish $csproj -c Release /p:PublishProfile=FolderProfile
        dotnet publish $svc -c Release -r win-x64 --self-contained false `
            -o (Join-Path $root "optiSCAN.Service\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64")
        Copy-Item (Join-Path $root "optiSCAN.Service\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64\optiSCAN.Service.exe") `
            (Join-Path $pubDir 'optiSCAN.Service.exe') -ErrorAction SilentlyContinue
    }
}

Invoke-Step 'Verification publish' {
    & (Join-Path $root 'scripts\verify-runtime-deps.ps1') -PublishDir $pubDir
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

Write-Host "`n=== Publication v9 prete ===" -ForegroundColor Green
Write-Host "  Publish : $pubDir"
Write-Host "  Setup   : installer\output\optiSCAN_Setup_v9.0.1.exe"
