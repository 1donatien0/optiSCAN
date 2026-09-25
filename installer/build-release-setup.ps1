# Publie optiSCAN (Release, win-x64) puis compile l'installateur Inno.
# Usage (depuis la racine du depot) : .\installer\build-release-setup.ps1
# Uniquement Inno (publish deja fait) : .\installer\build-release-setup.ps1 -SkipPublish
# CI : .\installer\build-release-setup.ps1 -SkipPublish -PublishDir publish\win-x64

[CmdletBinding()]
param(
    [switch] $SkipPublish,
    [string] $PublishDir,
    # Embarquer les bases ClamAV (~105 Mo). Défaut: non (téléchargement post-install).
    [switch] $EmbedClamAvDatabase,
    # Embarquer les règles YARA. Défaut: non (YARA-Forge post-install).
    [switch] $EmbedYaraRules,
    # Embarquer ClamAV DB + règles YARA (offline).
    [switch] $EmbedOfflineSignatures
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$csproj = Join-Path $root 'optiSCAN\optiSCAN.csproj'
$iss = Join-Path $PSScriptRoot 'setup.iss'
$defaultPublishDir = Join-Path $root 'optiSCAN\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64'
$cleanScript = Join-Path $root 'scripts\clean-before-publish.ps1'
$verifyScript = Join-Path $root 'scripts\verify-runtime-deps.ps1'

if (-not (Test-Path -LiteralPath $csproj)) { throw "Introuvable : $csproj" }
if (-not (Test-Path -LiteralPath $iss)) { throw "Introuvable : $iss" }

function Resolve-PublishRoot([string] $dir) {
    $p = if ([System.IO.Path]::IsPathRooted($dir)) { $dir } else { Join-Path $root $dir }
    if (-not (Test-Path -LiteralPath $p)) {
        throw "Dossier publish introuvable : $p"
    }
    return (Resolve-Path -LiteralPath $p).Path.TrimEnd('\', '/')
}

$targetPublishDir = if (-not [string]::IsNullOrWhiteSpace($PublishDir)) {
    Resolve-PublishRoot $PublishDir
} else {
    $defaultPublishDir
}

$publishExe = Join-Path $targetPublishDir 'optiSCAN.exe'
$staleFlatPublish = Join-Path (Split-Path $targetPublishDir -Parent) 'optiSCAN.exe'

if (-not $SkipPublish) {
    if (-not (Test-Path -LiteralPath $cleanScript)) { throw "Introuvable : $cleanScript" }
    & $cleanScript -Configuration Release -IncludeObj -IncludeCiPublish
    if ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        throw "clean-before-publish a echoue (code $LASTEXITCODE)."
    }
    Write-Host 'dotnet publish (Release, FolderProfile -> publish\win-x64)...' -ForegroundColor Cyan
    dotnet publish $csproj -c Release /p:PublishProfile=FolderProfile
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish a echoue (code $LASTEXITCODE)." }
    $targetPublishDir = Resolve-PublishRoot $defaultPublishDir
    $publishExe = Join-Path $targetPublishDir 'optiSCAN.exe'
} else {
    if ((Test-Path -LiteralPath $staleFlatPublish) -and -not (Test-Path -LiteralPath $publishExe)) {
        throw @"
Publication win-x64 absente mais ancien publish\optiSCAN.exe detecte ($staleFlatPublish).
Relancez d'abord :
  .\scripts\clean-before-publish.ps1 -IncludeObj -IncludeCiPublish
  dotnet publish $csproj -c Release /p:PublishProfile=FolderProfile
"@
    }
}

if (-not (Test-Path -LiteralPath $publishExe)) {
    throw "Publication introuvable : $publishExe (faites dotnet publish avant Inno)."
}

if (Test-Path -LiteralPath $verifyScript) {
    Write-Host 'verify-runtime-deps...' -ForegroundColor Cyan
    if ($EmbedOfflineSignatures -or $EmbedClamAvDatabase) {
        & $verifyScript -PublishDir $targetPublishDir
    } else {
        & $verifyScript -PublishDir $targetPublishDir -AllowMissingSignatures
    }
    if ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        throw "verify-runtime-deps a echoue (code $LASTEXITCODE)."
    }
}

$iscc = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles}\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $iscc) { throw 'ISCC.exe introuvable. Installez Inno Setup 6.' }

$outDir = Join-Path $PSScriptRoot 'output'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$propsPath = Join-Path $root 'Directory.Build.props'
$versionMatch = Select-String -LiteralPath $propsPath -Pattern '<Version>([^<]+)</Version>' | Select-Object -First 1
$appVersion = if ($versionMatch) { $versionMatch.Matches[0].Groups[1].Value.Trim() } else { '' }
if ([string]::IsNullOrWhiteSpace($appVersion)) { throw "Version introuvable dans $propsPath" }
$parts = $appVersion.Split('.')
$appRelease = if ($parts.Length -ge 2) { "v$($parts[0]).$($parts[1])" } else { "v$appVersion" }

Write-Host "Inno Setup : $iscc (AppVersion=$appVersion, AppRelease=$appRelease)" -ForegroundColor Cyan
$fromUri = New-Object System.Uri(($PSScriptRoot.TrimEnd('\') + '\'))
$toUri = New-Object System.Uri(($targetPublishDir.TrimEnd('\') + '\'))
$relative = [Uri]::UnescapeDataString($fromUri.MakeRelativeUri($toUri).ToString()).TrimEnd('/').Replace('/', '\')
$publishGlob = $relative + '\*'
$isccArgs = @(
    "/DAppVersion=$appVersion",
    "/DAppRelease=$appRelease",
    "/DAppPublishSource=$publishGlob"
)
if ($EmbedOfflineSignatures) {
    $isccArgs += '/DEmbedOfflineSignatures'
} else {
    if ($EmbedClamAvDatabase) { $isccArgs += '/DEmbedClamAvDatabase' }
    if ($EmbedYaraRules) { $isccArgs += '/DEmbedYaraRules' }
}
Write-Host "Publish source (force) : $publishGlob" -ForegroundColor DarkGray
Write-Host "  optiSCAN.exe : $((Get-Item -LiteralPath $publishExe).LastWriteTime.ToString('u'))" -ForegroundColor DarkGray
if ($EmbedOfflineSignatures -or $EmbedClamAvDatabase) {
    Write-Host '  Bases ClamAV : embarquees' -ForegroundColor DarkGray
} else {
    Write-Host '  Bases ClamAV : telechargement post-install (freshclam / MAJ)' -ForegroundColor DarkGray
}
if ($EmbedOfflineSignatures -or $EmbedYaraRules) {
    Write-Host '  Regles YARA : embarquees' -ForegroundColor DarkGray
} else {
    Write-Host '  Regles YARA : telechargement post-install (YARA-Forge / MAJ)' -ForegroundColor DarkGray
}
& $iscc @isccArgs $iss
if ($LASTEXITCODE -ne 0) { throw "ISCC a echoue (code $LASTEXITCODE)." }

if (Test-Path $outDir) {
    Write-Host 'Sortie :' -ForegroundColor Green
    Get-ChildItem $outDir -Filter '*.exe' | Sort-Object LastWriteTime -Descending | Select-Object -First 3 | Format-Table Name, Length, LastWriteTime -AutoSize
}
