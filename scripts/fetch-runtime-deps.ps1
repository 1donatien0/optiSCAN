<#
.SYNOPSIS
    Télécharge ClamAV (win x64) et YARA (win64) dans optiSCAN/ pour publish et CI.

.PARAMETER Force
    Re-télécharge même si les exécutables sont déjà présents.

.PARAMETER RunFreshclam
    Lance freshclam vers optiSCAN/clamav/database (long, ~200+ Mo).

.PARAMETER FreshclamTimeoutMinutes
    Délai max pour freshclam (défaut 45).

.EXAMPLE
    .\scripts\fetch-runtime-deps.ps1
    .\scripts\fetch-runtime-deps.ps1 -RunFreshclam -FreshclamTimeoutMinutes 60
#>
[CmdletBinding()]
param(
    [switch] $Force,
    [switch] $RunFreshclam,
    [int] $FreshclamTimeoutMinutes = 45
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$versionsPath = Join-Path $PSScriptRoot 'runtime-versions.json'
if (-not (Test-Path $versionsPath)) { throw "Introuvable : $versionsPath" }
$versions = Get-Content $versionsPath -Raw | ConvertFrom-Json

$clamX64 = Join-Path $root 'optiSCAN\clamav\x64'
$clamDb = Join-Path $root 'optiSCAN\clamav\database'
$yaraDir = Join-Path $root 'optiSCAN\yara'
$cacheDir = Join-Path $root 'artifacts\deps-cache'
New-Item -ItemType Directory -Force -Path $clamX64, $clamDb, $yaraDir, $cacheDir | Out-Null

function Test-ClamReady {
    @('clamscan.exe', 'freshclam.exe', 'clamd.exe', 'clambc.exe') |
        ForEach-Object { Test-Path (Join-Path $clamX64 $_) } | Where-Object { $_ -eq $false } | Measure-Object |
        Select-Object -ExpandProperty Count
}

function Test-YaraReady {
    (Test-Path (Join-Path $yaraDir 'yara64.exe')) -and (Test-Path (Join-Path $yaraDir 'yara32.exe'))
}

function Expand-ZipToTemp([string] $zipPath) {
    $temp = Join-Path $cacheDir ("extract-" + [Guid]::NewGuid().ToString('n'))
    Expand-Archive -LiteralPath $zipPath -DestinationPath $temp -Force
    return $temp
}

function Copy-IfExists([string] $srcDir, [string] $destDir, [string[]] $names) {
    foreach ($name in $names) {
        $src = Get-ChildItem -Path $srcDir -Filter $name -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($src) {
            Copy-Item -LiteralPath $src.FullName -Destination (Join-Path $destDir $name) -Force
            Write-Host "  OK $name" -ForegroundColor Green
        } else {
            Write-Warning "  Absent dans l'archive : $name"
        }
    }
}

# --- ClamAV ---
if ($Force -or (Test-ClamReady) -gt 0) {
    Write-Host "`n[ ClamAV $($versions.clamavVersion) win x64 ]" -ForegroundColor Cyan
    $zipName = "clamav-$($versions.clamavVersion).win.x64.zip"
    $zipPath = Join-Path $cacheDir $zipName
    if (-not (Test-Path $zipPath) -or $Force) {
        Write-Host "  Telechargement $($versions.clamavWinX64Url) ..."
        Invoke-WebRequest -Uri $versions.clamavWinX64Url -OutFile $zipPath -UseBasicParsing
    }
    $temp = Expand-ZipToTemp $zipPath
    try {
        Copy-IfExists $temp $clamX64 @(
            'clamscan.exe', 'freshclam.exe', 'clamd.exe', 'clambc.exe',
            'libclamunrar.dll', 'libclamunrar_iface.dll', 'libclammspack.dll'
        )
    } finally {
        Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
    }
} else {
    Write-Host "[ ClamAV ] deja present dans optiSCAN\clamav\x64" -ForegroundColor DarkGray
}

# --- YARA ---
if ($Force -or -not (Test-YaraReady)) {
    Write-Host "`n[ YARA $($versions.yaraVersion) win64 ]" -ForegroundColor Cyan
    $zipName = "yara-$($versions.yaraVersion)-win64.zip"
    $zipPath = Join-Path $cacheDir $zipName
    if (-not (Test-Path $zipPath) -or $Force) {
        Write-Host "  Telechargement $($versions.yaraWin64Url) ..."
        Invoke-WebRequest -Uri $versions.yaraWin64Url -OutFile $zipPath -UseBasicParsing
    }
    $temp = Expand-ZipToTemp $zipPath
    try {
        Copy-IfExists $temp $yaraDir @('yara64.exe', 'yara32.exe', 'yarac64.exe', 'yarac32.exe')
        if (-not (Test-Path (Join-Path $yaraDir 'yara32.exe')) -and (Test-Path (Join-Path $yaraDir 'yara64.exe'))) {
            Copy-Item (Join-Path $yaraDir 'yara64.exe') (Join-Path $yaraDir 'yara32.exe') -Force
            Write-Host "  OK yara32.exe (copie de yara64 pour verify)" -ForegroundColor Yellow
        }
    } finally {
        Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
    }
} else {
    Write-Host "[ YARA ] deja present dans optiSCAN\yara" -ForegroundColor DarkGray
}

# --- Signatures ---
if ($RunFreshclam) {
    $freshclam = Join-Path $clamX64 'freshclam.exe'
    if (-not (Test-Path $freshclam)) { throw "freshclam.exe introuvable : $freshclam" }
    Write-Host "`n[ freshclam ] database -> $clamDb (timeout ${FreshclamTimeoutMinutes} min)" -ForegroundColor Cyan
    $p = Start-Process -FilePath $freshclam -ArgumentList "--datadir=$clamDb" -PassThru -NoNewWindow
    $timeoutMs = $FreshclamTimeoutMinutes * 60 * 1000
    if (-not $p.WaitForExit($timeoutMs)) {
        try { $p.Kill($true) } catch { }
        throw "freshclam timeout apres $FreshclamTimeoutMinutes minutes."
    }
    if ($p.ExitCode -ne 0) {
        throw "freshclam a quitte avec le code $($p.ExitCode)."
    }
    Write-Host "  Signatures OK dans $clamDb" -ForegroundColor Green
}

$rules = Get-ChildItem (Join-Path $root 'optiSCAN\rules') -Filter '*.yar' -ErrorAction SilentlyContinue
if (-not $rules -or $rules.Count -eq 0) {
    Write-Warning "Aucune regle .yar dans optiSCAN\rules"
}

Write-Host "`nVerification projet (avant publish)..." -ForegroundColor Cyan
$pubDefault = Join-Path $root 'optiSCAN\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64'
if (Test-Path (Join-Path $pubDefault 'optiSCAN.exe')) {
    & (Join-Path $PSScriptRoot 'verify-runtime-deps.ps1') -PublishDir $pubDefault
} else {
    Write-Host "  (publish\win-x64 absent — normal avant dotnet publish)" -ForegroundColor DarkGray
}

Write-Host "`nTermine. Etape suivante : dotnet publish ou .\scripts\prepare-release-v8.ps1" -ForegroundColor Green
