<#
.SYNOPSIS
    Vérifie que tous les binaires et fichiers critiques sont présents dans le dossier
    de publication avant de créer l'installateur Inno Setup.

.PARAMETER PublishDir
    Chemin du dossier de publication (ex. publish\win-x64).

.EXAMPLE
    pwsh -File scripts\verify-runtime-deps.ps1 -PublishDir publish\win-x64
#>

param (
    [string] $PublishDir,
    [switch] $AllowMissingSignatures
)

if ([string]::IsNullOrWhiteSpace($PublishDir)) {
    $repo = Split-Path -Parent $PSScriptRoot
    $PublishDir = Join-Path $repo 'optiSCAN\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64'
    if (-not (Test-Path (Join-Path $PublishDir 'optiSCAN.exe'))) {
        $PublishDir = Join-Path $repo 'publish\win-x64'
    }
}
$PublishDir = (Resolve-Path -LiteralPath $PublishDir).Path

$ErrorActionPreference = 'Stop'
$failed = @()

function Check {
    param([string]$RelPath, [string]$Description)
    $full = Join-Path $PublishDir $RelPath
    if (-not (Test-Path $full)) {
        Write-Host "  MANQUANT  $RelPath  ($Description)" -ForegroundColor Red
        $script:failed += $RelPath
    } else {
        Write-Host "  OK        $RelPath" -ForegroundColor Green
    }
}

Write-Host "`n=== verify-runtime-deps.ps1 - $PublishDir ===`n" -ForegroundColor Cyan

Write-Host "[ Executable ]"
Check "optiSCAN.exe" "Executable principal"

Write-Host "`n[ ClamAV x64 ]"
Check "clamav\x64\clamscan.exe"  "Scanner ClamAV"
Check "clamav\x64\freshclam.exe" "Mise a jour signatures"
Check "clamav\x64\clamd.exe"     "Daemon ClamAV (v9)"
$clambc = Join-Path $PublishDir "clamav\x64\clambc.exe"
if (Test-Path $clambc) {
    Write-Host "  OK        clamav\x64\clambc.exe" -ForegroundColor Green
} else {
    Write-Host "  SKIP      clamav\x64\clambc.exe (optionnel)" -ForegroundColor Yellow
}
Check "clamav\certs\clamav.crt"  "Certificat CA Cisco-Talos"

Write-Host "`n[ Signatures ClamAV ]"
$sigFiles = Get-ChildItem -Path (Join-Path $PublishDir "clamav\database") -Filter "*.cvd" -ErrorAction SilentlyContinue
if ($sigFiles.Count -eq 0) {
    $sigFiles = Get-ChildItem -Path (Join-Path $PublishDir "clamav\database") -Filter "*.cld" -ErrorAction SilentlyContinue
}
if ($sigFiles.Count -eq 0) {
    if ($AllowMissingSignatures) {
        Write-Host "  SKIP      clamav\database (AllowMissingSignatures)" -ForegroundColor Yellow
    } else {
        Write-Host "  MANQUANT  clamav\database\*.cvd / *.cld  (lancer freshclam ou prepare-release-v9 -RunFreshclam)" -ForegroundColor Red
        $failed += "clamav\database\*.cvd"
    }
} else {
    foreach ($f in $sigFiles) {
        Write-Host "  OK        clamav\database\$($f.Name)" -ForegroundColor Green
    }
}

Write-Host "`n[ YARA ]"
Check "yara\yara64.exe" "YARA engine x64"
$yara32 = Join-Path $PublishDir "yara\yara32.exe"
if (Test-Path $yara32) {
    Write-Host "  OK        yara\yara32.exe" -ForegroundColor Green
} else {
    Write-Host "  SKIP      yara\yara32.exe (optionnel si processus x64 uniquement)" -ForegroundColor Yellow
}

$yaraRules = Get-ChildItem -Path (Join-Path $PublishDir "rules") -Filter "*.yar" -Recurse -ErrorAction SilentlyContinue
if ($yaraRules.Count -eq 0) {
    Write-Host "  MANQUANT  rules\*.yar  (regles YARA)" -ForegroundColor Red
    $failed += "rules\*.yar"
} else {
    Write-Host "  OK        rules\ - $($yaraRules.Count) regle(s) .yar" -ForegroundColor Green
}

Write-Host "`n[ Ressources ]"
Check "optiSCAN.ico"      "Icone application"
Check "optiSCAN_hero.png" "Image hero bouclier"

Write-Host ""
if ($failed.Count -eq 0) {
    Write-Host "=== Toutes les dependances sont presentes. Publication OK. ===" -ForegroundColor Green
    exit 0
} else {
    Write-Host "=== ECHEC : $($failed.Count) dependance(s) manquante(s) ===" -ForegroundColor Red
    foreach ($f in $failed) { Write-Host "  - $f" -ForegroundColor Red }
    exit 1
}
