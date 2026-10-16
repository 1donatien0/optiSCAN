# SPDX-License-Identifier: GPL-3.0-or-later
<#
.SYNOPSIS
    Télécharge ClamAV (win x64) et YARA (win64) dans optiSCAN/ pour publish et CI.

.PARAMETER Force
    Re-télécharge même si les exécutables sont déjà présents.
    Sans -Force, un moteur est quand même remplacé quand son marqueur .pinned-version
    ne correspond plus à la version et à l'empreinte de runtime-versions.json.

.PARAMETER RequireSignature
    Exige la vérification GPG de l'archive ClamAV (signature Talos, clé scripts/keys/cisco-talos.gpg,
    empreinte clamavSigningKeyFingerprint). Sans ce commutateur, la signature est vérifiée si gpg
    est disponible, et seul le SHA-256 épinglé fait foi sinon (avec un avertissement).

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
    [switch] $RequireSignature,
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

function Assert-PinnedSha256([string] $Path, $Expected, [string] $Label, [switch] $Keep) {
    $pinned = [string] $Expected
    if ([string]::IsNullOrWhiteSpace($pinned)) {
        throw "$Label : empreinte SHA-256 absente de runtime-versions.json"
    }
    $actual = (Get-FileHash -Algorithm SHA256 -Path $Path).Hash
    if ($actual -ne $pinned.ToUpperInvariant()) {
        # Un téléchargement corrompu est effacé ; un fichier du dépôt (-Keep) est laissé pour examen.
        if (-not $Keep) { Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue }
        throw "$Label : empreinte SHA-256 incorrecte ($actual)"
    }
}

# Marqueur écrit après une extraction vérifiée : sans lui, des binaires plus anciens
# déjà présents (ex. ClamAV 1.4.5) seraient gardés malgré un nouvel épinglage.
$pinMarkerName = '.pinned-version'
$clamPin = "clamav $($versions.clamavVersion) $(([string]$versions.clamavWinX64Sha256).ToUpperInvariant())"
$yaraPin = "yara $($versions.yaraVersion) $(([string]$versions.yaraWin64Sha256).ToUpperInvariant())"

function Test-PinMarker([string] $dir, [string] $expected) {
    $marker = Join-Path $dir $pinMarkerName
    if (-not (Test-Path -LiteralPath $marker)) { return $false }
    return ((Get-Content -LiteralPath $marker -Raw).Trim() -eq $expected)
}

function Write-PinMarker([string] $dir, [string] $value) {
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText((Join-Path $dir $pinMarkerName), $value + "`n", $utf8NoBom)
}

function Find-Gpg {
    $cmd = Get-Command gpg -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    # Git for Windows (présent sur les runners GitHub) embarque gpg.
    foreach ($candidate in @(
            (Join-Path $env:ProgramFiles 'Git\usr\bin\gpg.exe'),
            (Join-Path $env:ProgramFiles 'GnuPG\bin\gpg.exe'),
            (Join-Path ${env:ProgramFiles(x86)} 'GnuPG\bin\gpg.exe'))) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) { return $candidate }
    }
    return $null
}

# Chemin passé à gpg. Le gpg de Git pour Windows (MSYS) attend « /c/x/y » ; Gpg4win accepte
# « C:/x/y ». Un « C:\x » est lu par MSYS comme un chemin relatif.
function ConvertTo-GpgPath([string] $Gpg, [string] $Path) {
    $full = [System.IO.Path]::GetFullPath($Path)
    if ($Gpg -match '[\\/]usr[\\/]bin[\\/]gpg(\.exe)?$' -and $full -match '^([A-Za-z]):\\(.*)$') {
        return '/' + $Matches[1].ToLowerInvariant() + '/' + $Matches[2].Replace('\', '/')
    }
    return $full.Replace('\', '/')
}

# Vérifie la signature détachée Talos de l'archive ClamAV avec la clé versionnée dans le dépôt,
# dans un trousseau temporaire, et contrôle l'empreinte de la clé primaire qui a signé.
function Assert-TalosSignature([string] $ZipPath, [string] $ZipUrl) {
    $expected = ([string] $versions.clamavSigningKeyFingerprint).Replace(' ', '').ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($expected)) { throw "clamavSigningKeyFingerprint absent de runtime-versions.json" }
    $gpg = Find-Gpg
    if (-not $gpg) {
        if ($RequireSignature) { throw "gpg introuvable : vérification de signature ClamAV impossible (-RequireSignature)" }
        Write-Warning "  gpg introuvable : signature ClamAV non vérifiée, seul le SHA-256 épinglé fait foi."
        return
    }
    $keyFile = Join-Path $PSScriptRoot 'keys\cisco-talos.gpg'
    if (-not (Test-Path -LiteralPath $keyFile)) { throw "Clé Talos introuvable : $keyFile" }
    $sigPath = "$ZipPath.sig"
    Invoke-WebRequest -Uri "$ZipUrl.sig" -OutFile $sigPath -UseBasicParsing
    $gnupgHome = Join-Path $cacheDir ("gnupg-" + [Guid]::NewGuid().ToString('n'))
    New-Item -ItemType Directory -Force -Path $gnupgHome | Out-Null
    # Sous Windows PowerShell 5.1, une sortie d'erreur d'un programme natif devient une erreur
    # terminale avec ErrorActionPreference=Stop : gpg y écrit ses messages d'information, d'où
    # Continue le temps des appels. Sa sortie est gardée pour le diagnostic en cas d'échec.
    $gpgHomeArg = ConvertTo-GpgPath $gpg $gnupgHome
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $importOut = & $gpg --homedir $gpgHomeArg --batch --import (ConvertTo-GpgPath $gpg $keyFile) 2>&1 | ForEach-Object { "$_" }
        $verifyOut = & $gpg --homedir $gpgHomeArg --batch --status-fd 1 --verify (ConvertTo-GpgPath $gpg $sigPath) (ConvertTo-GpgPath $gpg $ZipPath) 2>&1 | ForEach-Object { "$_" }
        $ErrorActionPreference = $previousPreference
        $status = $verifyOut
        # StartsWith, pas -like : « [GNUPG:] » serait lu comme une classe de caractères.
        $valid = $status | Where-Object { ([string] $_).StartsWith('[GNUPG:] VALIDSIG ') } | Select-Object -First 1
        if (-not $valid) {
            Write-Warning ("gpg ($gpg) :`n  import : " + ($importOut -join "`n  ") + "`n  verify : " + ($verifyOut -join "`n  "))
            throw "Signature ClamAV invalide ($ZipPath)"
        }
        $primary = ($valid -split ' ')[-1].ToUpperInvariant()
        if ($primary -ne $expected) { throw "Signature ClamAV par une clé inattendue ($primary)" }
        Write-Host "  OK signature Talos ($primary)" -ForegroundColor Green
    } finally {
        $ErrorActionPreference = $previousPreference
        Remove-Item -LiteralPath $gnupgHome -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $sigPath -Force -ErrorAction SilentlyContinue
    }
}

function Test-ClamReady {
    $missing = @('clamscan.exe', 'freshclam.exe', 'clamd.exe', 'libclamav.dll', 'libfreshclam.dll') |
        ForEach-Object { Test-Path (Join-Path $clamX64 $_) } | Where-Object { $_ -eq $false } | Measure-Object |
        Select-Object -ExpandProperty Count
    if ($missing -gt 0) { return $missing }
    if (-not (Test-PinMarker $clamX64 $clamPin)) { return 1 }
    if (-not (Test-Path (Join-Path $clamX64 'licenses\COPYING.txt'))) { return 1 }
    return 0
}

function Test-YaraReady {
    (Test-Path (Join-Path $yaraDir 'yara64.exe')) -and (Test-Path (Join-Path $yaraDir 'yara32.exe')) -and
        (Test-PinMarker $yaraDir $yaraPin)
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

function Copy-ClamAvRuntime([string] $srcDir, [string] $destDir) {
    New-Item -ItemType Directory -Force -Path $destDir | Out-Null
    $copied = @{}
    $required = @(
        'clamscan.exe', 'freshclam.exe', 'clamd.exe',
        'libclamav.dll', 'libfreshclam.dll'
    )
    Get-ChildItem -Path $srcDir -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Extension -in '.exe', '.dll' -and
            $_.Name -notmatch '^(sigtool|clamdtop|clamsubmit|clamconf)\.exe$'
        } |
        ForEach-Object {
            if ($copied.ContainsKey($_.Name)) { return }
            Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $destDir $_.Name) -Force
            $copied[$_.Name] = $true
            Write-Host "  OK $($_.Name)" -ForegroundColor Green
        }
    foreach ($name in $required) {
        if (-not (Test-Path (Join-Path $destDir $name))) {
            throw "Binaire ClamAV manquant dans l'archive : $name"
        }
    }

    # Licences : la GPLv2 (COPYING.txt) et les avis des bibliothèques (COPYING\COPYING.*)
    # accompagnent obligatoirement les binaires livrés (audit V9).
    $licDir = Join-Path $destDir 'licenses'
    New-Item -ItemType Directory -Force -Path $licDir | Out-Null
    $licenses = @(Get-ChildItem -Path $srcDir -Recurse -File -Filter 'COPYING*' -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '[\\/]UserManual[\\/]' })
    foreach ($lic in $licenses) {
        Copy-Item -LiteralPath $lic.FullName -Destination (Join-Path $licDir $lic.Name) -Force
    }
    if (-not (Test-Path (Join-Path $licDir 'COPYING.txt'))) {
        throw "Licence ClamAV (COPYING.txt) absente de l'archive."
    }
    Write-Host "  OK licences ClamAV ($($licenses.Count) fichier(s))" -ForegroundColor Green
}

function Install-ClamCertsLayout {
    param([string] $SourceCertsDir)
    $crt = Join-Path $SourceCertsDir 'clamav.crt'
    if (-not (Test-Path -LiteralPath $crt)) {
        throw "Certificat ClamAV introuvable : $crt (requis pour freshclam / verification CVD)"
    }
    # Ancre de confiance de la signature des CVD : empreinte épinglée (tag clamav-1.5.0).
    Assert-PinnedSha256 $crt $versions.clamavRootCertSha256 'Certificat racine ClamAV' -Keep
    # freshclam 1.4 Windows cherche aussi clamav\x64\certs par defaut (erreur CI sinon).
    $x64Certs = Join-Path $clamX64 'certs'
    New-Item -ItemType Directory -Force -Path $x64Certs | Out-Null
    Copy-Item -LiteralPath $crt -Destination (Join-Path $x64Certs 'clamav.crt') -Force
    Write-Host "  certs -> $x64Certs\clamav.crt" -ForegroundColor DarkGray
    return (Resolve-Path -LiteralPath $x64Certs).Path
}

function Clear-PartialClamDatabases {
    param([string] $DatabaseDir)
    if (-not (Test-Path -LiteralPath $DatabaseDir)) { return }
    Get-ChildItem -LiteralPath $DatabaseDir -Directory -Filter 'tmp.*' -ErrorAction SilentlyContinue |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force }
}

function Write-FreshclamCiConf {
    param(
        [string] $ConfPath,
        [string] $DatabaseDir,
        [string] $CertsDirResolved
    )
    New-Item -ItemType Directory -Force -Path $DatabaseDir | Out-Null
    $db = (Resolve-Path -LiteralPath $DatabaseDir).Path.Replace('\', '/')
    $log = "$db/freshclam-ci.log"
    $cert = $CertsDirResolved.Replace('\', '/')
    $lines = @(
        '# freshclam.conf generated by optiSCAN v3'
        "DatabaseDirectory `"$db`""
    )
    $lines += @(
        "UpdateLogFile `"$log`""
        'LogTime yes'
        'LogVerbose no'
        'DatabaseMirror database.clamav.net'
        'MaxAttempts 3'
        'ConnectTimeout 30'
        'ReceiveTimeout 0'
        'TestDatabases no'
    )
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($ConfPath, ($lines -join "`n") + "`n", $utf8NoBom)
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
    Assert-PinnedSha256 $zipPath $versions.clamavWinX64Sha256 'ClamAV'
    Assert-TalosSignature $zipPath $versions.clamavWinX64Url
    $temp = Expand-ZipToTemp $zipPath
    try {
        # Les .exe/.dll d'une version précédente sont retirés : une DLL disparue de la
        # nouvelle archive ne doit pas rester chargée à côté des nouveaux binaires.
        Get-ChildItem -LiteralPath $clamX64 -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in '.exe', '.dll' -or $_.Name -eq $pinMarkerName } |
            Remove-Item -Force
        # freshclam/clamscan dynamiquement liés : libclamav, libfreshclam, OpenSSL, libcurl, etc.
        Copy-ClamAvRuntime $temp $clamX64
        Write-PinMarker $clamX64 $clamPin
    } finally {
        Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
    }
} else {
    Write-Host "[ ClamAV ] deja present dans optiSCAN\clamav\x64" -ForegroundColor DarkGray
}

$certsSource = Join-Path $root 'optiSCAN\clamav\certs'
if ((Test-Path (Join-Path $clamX64 'clamscan.exe')) -and (Test-Path (Join-Path $certsSource 'clamav.crt'))) {
    Install-ClamCertsLayout -SourceCertsDir $certsSource | Out-Null
}

# --- YARA ---
if ($Force -or -not (Test-YaraReady)) {
    Write-Host "`n[ YARA $($versions.yaraVersion) win64 ]" -ForegroundColor Cyan
    $zipName = [IO.Path]::GetFileName(([Uri]$versions.yaraWin64Url).AbsolutePath)
    $zipPath = Join-Path $cacheDir $zipName
    if (-not (Test-Path $zipPath) -or $Force) {
        Write-Host "  Telechargement $($versions.yaraWin64Url) ..."
        Invoke-WebRequest -Uri $versions.yaraWin64Url -OutFile $zipPath -UseBasicParsing
    }
    Assert-PinnedSha256 $zipPath $versions.yaraWin64Sha256 'YARA'
    $temp = Expand-ZipToTemp $zipPath
    try {
        # Les binaires d'une version précédente (yarac32.exe, etc.) sont retirés avant copie.
        Get-ChildItem -LiteralPath $yaraDir -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^yarac?(32|64)\.exe$' -or $_.Name -eq $pinMarkerName } |
            Remove-Item -Force
        Copy-IfExists $temp $yaraDir @('yara64.exe', 'yarac64.exe')
        if (-not (Test-Path (Join-Path $yaraDir 'yara64.exe'))) {
            throw "Binaire YARA manquant dans l'archive : yara64.exe"
        }
        # L'archive officielle ne contient que la version 64 bits : yara32.exe en est une copie.
        Copy-Item (Join-Path $yaraDir 'yara64.exe') (Join-Path $yaraDir 'yara32.exe') -Force
        Write-Host "  OK yara32.exe (copie de yara64 pour verify)" -ForegroundColor Yellow
        Write-PinMarker $yaraDir $yaraPin
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
    $confPath = Join-Path $clamX64 'freshclam.conf'
    $certsSource = Join-Path $root 'optiSCAN\clamav\certs'
    $certsResolved = Install-ClamCertsLayout -SourceCertsDir $certsSource
    Clear-PartialClamDatabases -DatabaseDir $clamDb
    if ($env:GITHUB_ACTIONS -eq 'true') {
        Write-Host "  CI : base signatures videe avant freshclam" -ForegroundColor DarkGray
        if (Test-Path -LiteralPath $clamDb) {
            Remove-Item -LiteralPath $clamDb -Recurse -Force -ErrorAction SilentlyContinue
        }
        New-Item -ItemType Directory -Force -Path $clamDb | Out-Null
    }
    Write-FreshclamCiConf -ConfPath $confPath -DatabaseDir $clamDb -CertsDirResolved $certsResolved
    Write-Host "  freshclam.conf CI -> $confPath (CVD_CERTS_DIR=$certsResolved)" -ForegroundColor DarkGray

    Write-Host "`n[ freshclam ] database -> $clamDb (timeout ${FreshclamTimeoutMinutes} min)" -ForegroundColor Cyan
    # freshclam exige --option=valeur (un token) ; conf absent du repo (genere par l'app en prod).
    $clamDbFull = (Resolve-Path -LiteralPath $clamDb).Path
    $freshclamArgs = @(
        '--show-progress',
        '--no-warnings',
        "--datadir=$clamDbFull",
        "--config-file=$confPath"
    )
    $prevCvdCertsDir = $env:CVD_CERTS_DIR
    $env:CVD_CERTS_DIR = $certsResolved
    try {
        $p = Start-Process -FilePath $freshclam -WorkingDirectory $clamX64 -ArgumentList $freshclamArgs -PassThru -NoNewWindow
    } finally {
        if ($null -eq $prevCvdCertsDir) {
            Remove-Item Env:CVD_CERTS_DIR -ErrorAction SilentlyContinue
        } else {
            $env:CVD_CERTS_DIR = $prevCvdCertsDir
        }
    }
    $timeoutMs = $FreshclamTimeoutMinutes * 60 * 1000
    if (-not $p.WaitForExit($timeoutMs)) {
        try { $p.Kill($true) } catch { }
        throw "freshclam timeout apres $FreshclamTimeoutMinutes minutes."
    }
    if ($p.ExitCode -ne 0) {
        $logPath = Join-Path $clamDb 'freshclam-ci.log'
        if (Test-Path -LiteralPath $logPath) {
            Write-Host "--- freshclam-ci.log (fin) ---" -ForegroundColor Red
            Get-Content -LiteralPath $logPath -Tail 40 | ForEach-Object { Write-Host $_ }
        }
        throw "freshclam a quitte avec le code $($p.ExitCode). Voir $logPath"
    }
    Write-Host "  Signatures OK dans $clamDb" -ForegroundColor Green
}

$rules = Get-ChildItem (Join-Path $root 'optiSCAN\rules') -Filter '*.yar' -ErrorAction SilentlyContinue
if (-not $rules -or $rules.Count -eq 0) {
    Write-Warning "Aucune regle .yar dans optiSCAN\rules"
}

Write-Host "`nVerification projet (avant publish)..." -ForegroundColor Cyan
$pubDefault = Join-Path $root 'optiSCAN\bin\Release\net10.0-windows10.0.17763.0\publish\win-x64'
if (Test-Path (Join-Path $pubDefault 'optiSCAN.exe')) {
    & (Join-Path $PSScriptRoot 'verify-runtime-deps.ps1') -PublishDir $pubDefault
} else {
    Write-Host "  (publish\win-x64 absent - normal avant dotnet publish)" -ForegroundColor DarkGray
}

Write-Host "`nTermine. Etape suivante : dotnet publish ou .\scripts\prepare-release-v3.ps1" -ForegroundColor Green
