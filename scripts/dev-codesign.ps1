<#
.SYNOPSIS
    Signature de code en DEV, a cout zero (certificat auto-signe).

.DESCRIPTION
    Monte la chaine de signature Authenticode complete SANS acheter de certificat.
    Objectif : ecrire, tester et valider tout le pipeline de signature en local ;
    le jour ou un vrai certificat OV/EV est achete, seul le -CertSubject change
    (publish-release.ps1 et installer/setup.iss consomment deja un sujet/thumbprint).

    ATTENTION : un certificat auto-signe n'est valide QUE sur les machines ou il a
    ete installe comme autorite de confiance. Il ne supprime pas les avertissements
    SmartScreen chez un utilisateur tiers. C'est un outil de DEV, pas de distribution.

.PARAMETER Subject
    Nom du sujet du certificat (CN). Defaut : "optiSCAN Dev Code Signing".

.PARAMETER Create
    Cree le certificat auto-signe s'il n'existe pas deja.

.PARAMETER Trust
    Installe le certificat dans Root + TrustedPublisher de la machine locale
    (requiert une console elevee). Sans cela, les signatures ne seront pas
    considerees comme valides par Windows.

.PARAMETER Path
    Fichier(s) a signer. Accepte les jokers. Ex : bin\Release\**\optiSCAN.exe

.PARAMETER SignToolPath
    Chemin complet vers signtool.exe. Si omis, recherche dans le PATH puis dans
    les emplacements standards du Windows SDK.

.PARAMETER ShowThumbprint
    Affiche le thumbprint du certificat (a reporter dans la CI / Inno Setup).

.EXAMPLE
    # 1. Creation du certificat (une seule fois)
    .\scripts\dev-codesign.ps1 -Create

.EXAMPLE
    # 2. Installation comme autorite de confiance (console ELEVEE, une seule fois)
    .\scripts\dev-codesign.ps1 -Trust

.EXAMPLE
    # 3. Signature des binaires
    .\scripts\dev-codesign.ps1 -Path "optiSCAN\bin\Release\net8.0-windows10.0.17763.0\win-x64\publish\optiSCAN.exe"

.EXAMPLE
    # 4. Signature du setup Inno
    .\scripts\dev-codesign.ps1 -Path "installer\output\optiSCAN_Setup_v9.0.1.exe"

.NOTES
    Cout : 0 EUR. Prerequis : Windows SDK (signtool.exe), inclus avec Visual Studio.
    Voir ROADMAP_GRATUIT.md - Chantier 1.
#>

[CmdletBinding(DefaultParameterSetName = 'Sign')]
param(
    [string] $Subject = 'optiSCAN Dev Code Signing',

    [Parameter(ParameterSetName = 'Create')]
    [switch] $Create,

    [Parameter(ParameterSetName = 'Trust')]
    [switch] $Trust,

    [Parameter(ParameterSetName = 'Sign', Position = 0)]
    [string[]] $Path,

    [string] $SignToolPath,

    [switch] $ShowThumbprint,

    # Horodatage : gratuit et public. Garantit que la signature reste valide
    # apres expiration du certificat.
    [string] $TimestampUrl = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'

function Write-Step { param([string]$m) Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Ok   { param([string]$m) Write-Host "    $m" -ForegroundColor Green }
function Write-Warn2{ param([string]$m) Write-Host "    $m" -ForegroundColor Yellow }

# ---------------------------------------------------------------------------
# Localisation de signtool.exe (Windows SDK - gratuit)
# ---------------------------------------------------------------------------
function Resolve-SignTool {
    param([string] $Explicit)

    if ($Explicit) {
        if (Test-Path $Explicit) { return $Explicit }
        throw "signtool.exe introuvable au chemin fourni : $Explicit"
    }

    $inPath = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($inPath) { return $inPath.Source }

    # Recherche dans les emplacements standards du Windows SDK, version la plus recente.
    $roots = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
        "${env:ProgramFiles}\Windows Kits\10\bin"
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($root in $roots) {
        $candidate = Get-ChildItem -Path $root -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\' } |
            Sort-Object FullName -Descending |
            Select-Object -First 1
        if ($candidate) { return $candidate.FullName }
    }

    throw @"
signtool.exe introuvable.
Installez le Windows SDK (gratuit) : https://developer.microsoft.com/windows/downloads/windows-sdk/
Ou fournissez -SignToolPath "C:\chemin\signtool.exe".
"@
}

# ---------------------------------------------------------------------------
# Recherche du certificat de dev dans le magasin utilisateur
# ---------------------------------------------------------------------------
function Get-DevCert {
    param([string] $CertSubject)

    Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -eq "CN=$CertSubject" -and $_.NotAfter -gt (Get-Date) } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1
}

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ===========================================================================
# MODE 1 : creation du certificat auto-signe
# ===========================================================================
if ($Create) {
    Write-Step "Creation du certificat de signature de code (auto-signe)"

    $existing = Get-DevCert -CertSubject $Subject
    if ($existing) {
        Write-Warn2 "Un certificat valide existe deja."
        Write-Ok "Thumbprint : $($existing.Thumbprint)"
        Write-Ok "Expire le  : $($existing.NotAfter.ToString('yyyy-MM-dd'))"
        return
    }

    # KeyUsage DigitalSignature + EKU Code Signing (1.3.6.1.5.5.7.3.3)
    $cert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject "CN=$Subject" `
        -KeyUsage DigitalSignature `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -CertStoreLocation Cert:\CurrentUser\My `
        -NotAfter (Get-Date).AddYears(3)

    Write-Ok "Certificat cree."
    Write-Ok "Sujet      : CN=$Subject"
    Write-Ok "Thumbprint : $($cert.Thumbprint)"
    Write-Ok "Expire le  : $($cert.NotAfter.ToString('yyyy-MM-dd'))"
    Write-Host ""
    Write-Warn2 "Etape suivante (console ELEVEE) : .\scripts\dev-codesign.ps1 -Trust"
    return
}

# ===========================================================================
# MODE 2 : installation comme autorite de confiance locale
# ===========================================================================
if ($Trust) {
    Write-Step "Installation du certificat comme autorite de confiance (machine locale)"

    if (-not (Test-Elevated)) {
        throw "Cette operation requiert une console PowerShell ELEVEE (Executer en tant qu'administrateur)."
    }

    $cert = Get-DevCert -CertSubject $Subject
    if (-not $cert) {
        throw "Aucun certificat '$Subject' trouve. Lancez d'abord : .\scripts\dev-codesign.ps1 -Create"
    }

    # Export du certificat public (sans cle privee) vers un fichier temporaire.
    $tmp = Join-Path $env:TEMP "optiscan-devcert-$($cert.Thumbprint).cer"
    Export-Certificate -Cert $cert -FilePath $tmp -Force | Out-Null

    try {
        # Root : la signature est reconnue comme emanant d'une AC de confiance.
        Import-Certificate -FilePath $tmp -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
        Write-Ok "Ajoute a LocalMachine\Root"

        # TrustedPublisher : supprime l'invite "editeur inconnu".
        Import-Certificate -FilePath $tmp -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
        Write-Ok "Ajoute a LocalMachine\TrustedPublisher"
    }
    finally {
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    }

    Write-Host ""
    Write-Warn2 "Rappel : valable UNIQUEMENT sur cette machine. Aucun effet chez un utilisateur tiers."
    return
}

# ===========================================================================
# MODE 3 : signature des fichiers
# ===========================================================================
if ($ShowThumbprint) {
    $cert = Get-DevCert -CertSubject $Subject
    if (-not $cert) { throw "Aucun certificat '$Subject'. Lancez : .\scripts\dev-codesign.ps1 -Create" }
    Write-Host $cert.Thumbprint
    return
}

if (-not $Path -or $Path.Count -eq 0) {
    Write-Host @"
Usage :
  .\scripts\dev-codesign.ps1 -Create                 # 1. creer le certificat
  .\scripts\dev-codesign.ps1 -Trust                  # 2. l'approuver (console elevee)
  .\scripts\dev-codesign.ps1 -Path <fichiers>        # 3. signer
  .\scripts\dev-codesign.ps1 -ShowThumbprint         # thumbprint pour la CI

Cout total : 0 EUR. Voir ROADMAP_GRATUIT.md - Chantier 1.
"@
    return
}

$cert = Get-DevCert -CertSubject $Subject
if (-not $cert) {
    throw "Aucun certificat '$Subject' trouve. Lancez d'abord : .\scripts\dev-codesign.ps1 -Create"
}

$signtool = Resolve-SignTool -Explicit $SignToolPath
Write-Step "Signature Authenticode (certificat de dev)"
Write-Ok "signtool   : $signtool"
Write-Ok "Thumbprint : $($cert.Thumbprint)"

# Expansion des jokers et filtrage des fichiers signables.
$files = @()
foreach ($p in $Path) {
    $resolved = Resolve-Path $p -ErrorAction SilentlyContinue
    if (-not $resolved) { Write-Warn2 "Introuvable, ignore : $p"; continue }
    $files += $resolved.Path
}

if ($files.Count -eq 0) { throw "Aucun fichier a signer." }

$failed = 0
foreach ($f in $files) {
    Write-Host "    -> $(Split-Path $f -Leaf)" -NoNewline

    # /fd SHA256      : algorithme d'empreinte du fichier
    # /sha1           : selection du certificat par thumbprint (sans ambiguite)
    # /tr + /td SHA256: horodatage RFC 3161 (gratuit, public)
    & $signtool sign `
        /fd SHA256 `
        /sha1 $cert.Thumbprint `
        /tr $TimestampUrl `
        /td SHA256 `
        /q `
        $f 2>&1 | Out-Null

    if ($LASTEXITCODE -eq 0) {
        Write-Host "  OK" -ForegroundColor Green
    } else {
        Write-Host "  ECHEC (code $LASTEXITCODE)" -ForegroundColor Red
        $failed++
    }
}

Write-Host ""
if ($failed -gt 0) {
    Write-Host "$failed fichier(s) non signe(s)." -ForegroundColor Red
    exit 1
}

Write-Ok "$($files.Count) fichier(s) signe(s)."
Write-Host ""
Write-Warn2 "Verification : signtool verify /pa /v <fichier>"
Write-Warn2 "Passage en production : remplacer le certificat de dev par un certificat OV/EV,"
Write-Warn2 "puis reutiliser exactement la meme commande (seul le thumbprint change)."
