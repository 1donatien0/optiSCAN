# Publie optiSCAN (Release, win-x64) puis compile l'installateur Inno.
# Usage (depuis la racine du dépôt) : .\installer\build-release-setup.ps1
# Uniquement Inno (publish déjà fait) : .\installer\build-release-setup.ps1 -SkipPublish

[CmdletBinding()]
param(
    [switch] $SkipPublish,
    [string] $PublishDir
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$csproj = Join-Path $root 'optiSCAN\optiSCAN.csproj'
$iss = Join-Path $PSScriptRoot 'setup.iss'
$publishDir = Join-Path $root 'optiSCAN\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64'
$cleanScript = Join-Path $root 'scripts\clean-before-publish.ps1'

if (-not (Test-Path -LiteralPath $csproj)) { throw "Introuvable : $csproj" }
if (-not (Test-Path -LiteralPath $iss)) { throw "Introuvable : $iss" }

$publishExe = Join-Path $publishDir 'optiSCAN.exe'
$staleFlatPublish = Join-Path (Split-Path $publishDir -Parent) 'optiSCAN.exe'

if (-not $SkipPublish) {
    if (-not (Test-Path -LiteralPath $cleanScript)) { throw "Introuvable : $cleanScript" }
    & $cleanScript -Configuration Release -IncludeObj -IncludeCiPublish
    Write-Host 'dotnet publish (Release, FolderProfile -> publish\win-x64)...' -ForegroundColor Cyan
    dotnet publish $csproj -c Release /p:PublishProfile=FolderProfile
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish a échoué (code $LASTEXITCODE)." }
} else {
    # Inno seul : refuser un publish plat obsolete (setup.iss fallback dangereux).
    if ((Test-Path -LiteralPath $staleFlatPublish) -and -not (Test-Path -LiteralPath $publishExe)) {
        throw @"
Publication win-x64 absente mais ancien publish\optiSCAN.exe detecte.
Relancez d'abord :
  .\scripts\clean-before-publish.ps1 -IncludeObj -IncludeCiPublish
  dotnet publish $csproj -c Release /p:PublishProfile=FolderProfile
"@
    }
}

if (-not (Test-Path -LiteralPath $publishExe)) {
    throw "Publication introuvable : $publishExe (faites dotnet publish avant Inno)."
}

$iscc = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles}\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $iscc) { throw 'ISCC.exe introuvable. Installez Inno Setup 6.' }

$propsPath = Join-Path $root 'Directory.Build.props'
[xml]$propsXml = Get-Content -LiteralPath $propsPath
$appVersion = ($propsXml.Project.PropertyGroup.Version | Select-Object -First 1).'#text'
if ([string]::IsNullOrWhiteSpace($appVersion)) { $appVersion = '8.0.0' }
$parts = $appVersion.Split('.')
$appRelease = if ($parts.Length -ge 2) { "v$($parts[0]).$($parts[1])" } else { "v$appVersion" }

Write-Host "Inno Setup : $iscc (AppVersion=$appVersion, AppRelease=$appRelease)" -ForegroundColor Cyan
$resolvedPublish = if (-not [string]::IsNullOrWhiteSpace($PublishDir)) {
    (Resolve-Path -LiteralPath $PublishDir).Path.TrimEnd('\', '/')
} else {
    (Resolve-Path -LiteralPath $publishDir).Path.TrimEnd('\', '/')
}
$relative = [System.IO.Path]::GetRelativePath($PSScriptRoot, $resolvedPublish)
$publishGlob = ($relative -replace '/', '\') + '\*'
$isccArgs = @(
    "/DAppVersion=$appVersion",
    "/DAppRelease=$appRelease",
    "/DAppPublishSource=$publishGlob"
)
Write-Host "Publish source (force win-x64) : $publishGlob" -ForegroundColor DarkGray
Write-Host "  optiSCAN.exe : $(Get-Item -LiteralPath (Join-Path $resolvedPublish 'optiSCAN.exe') | ForEach-Object { $_.LastWriteTime.ToString('u') })" -ForegroundColor DarkGray
& $iscc @isccArgs $iss
if ($LASTEXITCODE -ne 0) { throw "ISCC a échoué (code $LASTEXITCODE)." }

$outDir = Join-Path $PSScriptRoot 'output'
if (Test-Path $outDir) {
    Write-Host 'Sortie :' -ForegroundColor Green
    Get-ChildItem $outDir -Filter '*.exe' | Sort-Object LastWriteTime -Descending | Select-Object -First 3 | Format-Table Name, Length, LastWriteTime -AutoSize
}
