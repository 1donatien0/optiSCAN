# Verifie que optiSCAN.exe est la ou Inno Setup (setup.iss) le cherche.
# Usage : .\scripts\verify-publish-for-inno.ps1

[CmdletBinding()]
param(
    [switch] $FailOnMissing
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$tfm = 'net10.0-windows10.0.19041.0'

$candidates = @(
    @{ Label = 'Release publish win-x64 (attendu)'; Path = "optiSCAN.WinUI\bin\Release\$tfm\publish\win-x64\optiSCAN.exe" },
    @{ Label = 'Release publish plat'; Path = "optiSCAN.WinUI\bin\Release\$tfm\publish\optiSCAN.exe" },
    @{ Label = 'Release win-x64 intermediaire (build, pas publish)'; Path = "optiSCAN.WinUI\bin\Release\$tfm\win-x64\optiSCAN.exe" },
    @{ Label = 'Debug publish win-x64 (mauvaise config pour Inno)'; Path = "optiSCAN.WinUI\bin\Debug\$tfm\publish\win-x64\optiSCAN.exe" },
    @{ Label = 'Ancien VS net8.0 publish win-x64'; Path = 'optiSCAN.WinUI\bin\Release\net8.0\publish\win-x64\optiSCAN.exe' },
    @{ Label = 'CI publish racine'; Path = 'publish\win-x64\optiSCAN.exe' }
)

Write-Host "`n=== verify-publish-for-inno ===`n" -ForegroundColor Cyan
$found = @()
foreach ($c in $candidates) {
    $full = Join-Path $root $c.Path
    if (Test-Path -LiteralPath $full) {
        $item = Get-Item -LiteralPath $full
        Write-Host "[OK] $($c.Label)" -ForegroundColor Green
        Write-Host "     $($item.FullName)  ($([math]::Round($item.Length/1KB)) Ko, $($item.LastWriteTime))`n"
        $found += $item
    }
    else {
        Write-Host "[--] $($c.Label)" -ForegroundColor DarkGray
        Write-Host "     $full`n"
    }
}

if ($found.Count -eq 0) {
    Write-Host "Aucun optiSCAN.exe trouve. Inno echouera." -ForegroundColor Red
    Write-Host @"

Publiez en Release avec le bon profil :
  dotnet publish .\optiSCAN.WinUI\optiSCAN.WinUI.csproj -c Release -p:PublishProfile=FolderProfile-SelfContained

VS : clic droit optiSCAN > Publier > FolderProfile-SelfContained (Configuration = Release).

Attention : un nettoyage (clean-before-publish) efface publish\ — republiez ensuite.
"@ -ForegroundColor Yellow
    if ($FailOnMissing) { exit 1 }
    exit 0
}

$preferred = $found | Where-Object {
    $_.FullName -like "*\bin\Release\$tfm\publish\win-x64\optiSCAN.exe"
} | Select-Object -First 1

if ($preferred) {
    Write-Host "Inno utilisera : $($preferred.FullName)" -ForegroundColor Green
}
else {
    Write-Host "optiSCAN.exe present mais PAS au chemin attendu par setup.iss (Release\...\publish\win-x64\)." -ForegroundColor Yellow
    Write-Host "Republiez avec FolderProfile-SelfContained en Release, ou compilez Inno via build-release-setup.ps1 -PublishDir ..." -ForegroundColor Yellow
    if ($FailOnMissing) { exit 2 }
}
