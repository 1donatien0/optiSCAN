# Vérifie les binaires ClamAV / YARA attendus à côté de optiSCAN (développement ou publish).
# Usage : depuis la racine du dépôt :
#   .\scripts\verify-runtime-deps.ps1
#   .\scripts\verify-runtime-deps.ps1 -PublishDir ".\optiSCAN\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64"

param(
    [string]$PublishDir = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
if ($PublishDir) {
    $base = (Resolve-Path $PublishDir).Path
} else {
    $base = Join-Path $repoRoot "optiSCAN"
}

$arch = if ([Environment]::Is64BitOperatingSystem) { "x64" } else { "x86" }
$yaraArch = if ([Environment]::Is64BitOperatingSystem) { "64" } else { "32" }

Write-Host "optiSCAN — vérification des dépendances runtime"
Write-Host "Base : $base"
Write-Host ""

$ok = $true

function Test-PathReport($label, $path, [switch]$Required) {
    $exists = Test-Path -LiteralPath $path
    $mark = if ($exists) { "[OK]" } else { "[--]" ; if ($Required) { $script:ok = $false } }
    Write-Host "$mark $label"
    Write-Host "     $path"
    return $exists
}

$clamscan = Join-Path $base "clamav\$arch\clamscan.exe"
$freshclam = Join-Path $base "clamav\$arch\freshclam.exe"
$yara = Join-Path $base "yara\yara$yaraArch.exe"
$yarac = Join-Path $base "yara\yarac$yaraArch.exe"
$rules = Join-Path $base "rules"

Test-PathReport "clamscan.exe" $clamscan -Required
Test-PathReport "freshclam.exe" $freshclam
Test-PathReport "yara$yaraArch.exe" $yara -Required
Test-PathReport "yarac$yaraArch.exe" $yarac

if (Test-Path -LiteralPath $rules) {
    $yarCount = (Get-ChildItem -LiteralPath $rules -Filter "*.yar" -File -ErrorAction SilentlyContinue).Count
    if ($yarCount -gt 0) {
        Write-Host "[OK] rules/*.yar ($yarCount fichier(s))"
    } else {
        Write-Host "[--] rules/*.yar (aucun fichier .yar)"
        $ok = $false
    }
    Write-Host "     $rules"
} else {
    Write-Host "[--] dossier rules/"
    Write-Host "     $rules"
    $ok = $false
}

Write-Host ""
if ($ok) {
    Write-Host "Toutes les dépendances obligatoires sont présentes."
    exit 0
}

Write-Host "Dépendances manquantes. Voir README.md section 3 (ClamAV) et structure optiSCAN/clamav, optiSCAN/yara, optiSCAN/rules."
Write-Host "Publication : dotnet publish -c Release puis freshclam sur le dossier publish."
exit 1
