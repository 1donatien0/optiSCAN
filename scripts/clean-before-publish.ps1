# Vide les sorties Release avant publication / Inno Setup.
# Usage (racine du depot) :
#   .\scripts\clean-before-publish.ps1
#   .\scripts\clean-before-publish.ps1 -IncludeObj
#   .\scripts\clean-before-publish.ps1 -IncludeInstallerOutput

[CmdletBinding()]
param(
    [ValidateSet('Release', 'Debug')]
    [string] $Configuration = 'Release',
    [switch] $IncludeObj,
    [switch] $IncludeInstallerOutput
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$tfm = 'net8.0-windows10.0.17763.0'
$binDir = Join-Path $root "optiSCAN\bin\$Configuration\$tfm"
$objDir = Join-Path $root "optiSCAN\obj\$Configuration\$tfm"
$publishDir = Join-Path $binDir 'publish'
$testsBin = Join-Path $root 'optiSCAN.Tests\bin'
$testsObj = Join-Path $root 'optiSCAN.Tests\obj'
$installerOut = Join-Path $root 'installer\output'

function Remove-PathIfExists([string] $path, [string] $label) {
    if (-not (Test-Path -LiteralPath $path)) { return $false }
    Write-Host "  - $label" -ForegroundColor DarkGray
    Write-Host "    $path"
    try {
        Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
    }
    catch {
        Stop-ProcessesLockingPublish $binDir
        Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
    }
    return $true
}

function Remove-OptiscanExecutables([string] $searchRoot) {
    if (-not (Test-Path -LiteralPath $searchRoot)) { return 0 }
    $exes = Get-ChildItem -LiteralPath $searchRoot -Recurse -Filter 'optiSCAN.exe' -File -ErrorAction SilentlyContinue
    $count = 0
    foreach ($exe in $exes) {
        Write-Host "  - optiSCAN.exe" -ForegroundColor DarkGray
        Write-Host "    $($exe.FullName)"
        Remove-Item -LiteralPath $exe.FullName -Force -ErrorAction Stop
        $count++
    }
    return $count
}

function Stop-ProcessesLockingPublish([string] $binRoot) {
    $names = @('optiSCAN', 'yara64', 'clamscan', 'freshclam', 'clamd')
  foreach ($name in $names) {
    Get-Process -Name $name -ErrorAction SilentlyContinue | ForEach-Object {
      Write-Host "  - Arret $name (PID $($_.Id))" -ForegroundColor Yellow
      Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
  }
  if (Test-Path -LiteralPath $binRoot) {
    Get-Process -ErrorAction SilentlyContinue | Where-Object {
      $_.Path -and $_.Path.StartsWith($binRoot, [System.StringComparison]::OrdinalIgnoreCase)
    } | ForEach-Object {
      Write-Host "  - Arret $($_.ProcessName) (PID $($_.Id))" -ForegroundColor Yellow
      Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
  }
  Start-Sleep -Seconds 1
}

Write-Host "Nettoyage avant publication ($Configuration)..." -ForegroundColor Cyan
Stop-ProcessesLockingPublish $binDir

$removed = 0
if (Remove-PathIfExists $binDir "Dossier bin complet ($Configuration)") { $removed++ }
elseif (Remove-PathIfExists $publishDir "Ancien dossier publish (partiel)") { $removed++ }

if ($Configuration -eq 'Release') {
    if (Remove-PathIfExists $testsBin 'optiSCAN.Tests\bin') { $removed++ }
    if (Remove-PathIfExists $testsObj 'optiSCAN.Tests\obj') { $removed++ }
}

# Securite : exe residuels hors bin (publish partiel, ancien RID, etc.)
$extraDirs = @(
    (Join-Path $root "optiSCAN\bin\$Configuration"),
    (Join-Path $root 'optiSCAN\bin')
)
foreach ($dir in $extraDirs) {
    if (Test-Path -LiteralPath $dir) {
        $removed += Remove-OptiscanExecutables $dir
    }
}

if ($IncludeObj) {
    if (Remove-PathIfExists $objDir "Dossier obj ($Configuration)") { $removed++ }
}

if ($IncludeInstallerOutput) {
    if (Test-Path -LiteralPath $installerOut) {
        Get-ChildItem -LiteralPath $installerOut -Filter '*.exe' -File -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "  - installateur" -ForegroundColor DarkGray
            Write-Host "    $($_.FullName)"
            Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop
            $removed++
        }
    }
}

Write-Host ""
Write-Host "Nettoyage termine." -ForegroundColor Green
Write-Host "Etapes suivantes (manuel) :" -ForegroundColor Yellow
Write-Host "  1. dotnet publish .\optiSCAN\optiSCAN.csproj -c Release /p:PublishProfile=FolderProfile"
Write-Host "  2. ISCC.exe .\installer\setup.iss"
Write-Host ""
Write-Host "Ou tout-en-un : .\installer\build-release-setup.ps1"
