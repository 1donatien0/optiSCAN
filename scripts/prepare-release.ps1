<#
.SYNOPSIS
    Chaîne complète de publication v1.0 (dépôt -> installateur testé).

.EXAMPLE
    .\scripts\prepare-release.ps1
    .\scripts\prepare-release.ps1 -SkipFreshclam
    .\scripts\prepare-release.ps1 -SkipInstaller -RunFreshclam
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

$tfm = 'net10.0-windows10.0.19041.0'
# Sortie des deux profils de publication (FolderProfile / FolderProfile-SelfContained).
$pubDir = Join-Path $root "optiSCAN.WinUI\bin\Release\$tfm\publish\win-x64"

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
    $csproj = Join-Path $root 'optiSCAN.WinUI\optiSCAN.WinUI.csproj'
    $svc = Join-Path $root 'optiSCAN.Service\optiSCAN.Service.csproj'
    # Defaut : framework-dependent (installateur leger ; setup.iss installe .NET 10 Desktop +
    # Windows App Runtime si absents). -SelfContained : tout embarque (.NET + Windows App SDK).
    $profileName = if ($SelfContained) { 'FolderProfile-SelfContained' } else { 'FolderProfile' }
    $sc = if ($SelfContained) { 'true' } else { 'false' }
    dotnet publish $csproj -c Release /p:PublishProfile=$profileName
    if ($LASTEXITCODE -ne 0) { return }
    # Service publie dans le meme dossier (exe + dll + deps, comme la CI).
    dotnet publish $svc -c Release -r win-x64 --self-contained $sc -p:PublishSingleFile=false -o $pubDir
}

Invoke-Step 'Verification publish' {
    & (Join-Path $root 'scripts\verify-runtime-deps.ps1') -PublishDir $pubDir
}

if (-not $SkipInstaller) {
    Invoke-Step 'Installateur Inno' {
        $build = Join-Path $root 'installer\build-release-setup.ps1'
        & $build -SkipPublish -PublishDir $pubDir
    }
}

Write-Host "`n=== Publication v1.0 prete ===" -ForegroundColor Green
Write-Host "  Publish : $pubDir"
Write-Host "  Setup   : installer\output\optiSCAN_Setup_v1.0.0.exe"
