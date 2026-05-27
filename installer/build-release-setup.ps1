# Publie optiSCAN (Release, win-x64) puis compile l'installateur Inno.
# Usage (depuis la racine du dépôt) : .\installer\build-release-setup.ps1
# Uniquement Inno (publish déjà fait) : .\installer\build-release-setup.ps1 -SkipPublish

[CmdletBinding()]
param(
    [switch] $SkipPublish
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$csproj = Join-Path $root 'optiSCAN\optiSCAN.csproj'
$iss = Join-Path $PSScriptRoot 'setup.iss'
$publishDir = Join-Path $root 'optiSCAN\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64'
$cleanScript = Join-Path $root 'scripts\clean-before-publish.ps1'

if (-not (Test-Path -LiteralPath $csproj)) { throw "Introuvable : $csproj" }
if (-not (Test-Path -LiteralPath $iss)) { throw "Introuvable : $iss" }

if (-not $SkipPublish) {
  if (-not (Test-Path -LiteralPath $cleanScript)) { throw "Introuvable : $cleanScript" }
  & $cleanScript
  Write-Host 'dotnet publish (Release, FolderProfile -> publish\win-x64)...' -ForegroundColor Cyan
    dotnet publish $csproj -c Release /p:PublishProfile=FolderProfile
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish a échoué (code $LASTEXITCODE)." }

    if (-not (Test-Path -LiteralPath (Join-Path $publishDir 'optiSCAN.exe'))) {
        throw "Publication introuvable : $publishDir\optiSCAN.exe"
    }
}

$iscc = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles}\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $iscc) { throw 'ISCC.exe introuvable. Installez Inno Setup 6.' }
Write-Host "Inno Setup : $iscc" -ForegroundColor Cyan
& $iscc $iss
if ($LASTEXITCODE -ne 0) { throw "ISCC a échoué (code $LASTEXITCODE)." }

$outDir = Join-Path $PSScriptRoot 'output'
if (Test-Path $outDir) {
    Write-Host 'Sortie :' -ForegroundColor Green
    Get-ChildItem $outDir -Filter '*.exe' | Sort-Object LastWriteTime -Descending | Select-Object -First 3 | Format-Table Name, Length, LastWriteTime -AutoSize
}
