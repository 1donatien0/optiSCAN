<#
.SYNOPSIS
    Publication Release fiable d'optiSCAN + compilation de l'installeur Inno.

.DESCRIPTION
    Contourne l'UI de publication de Visual Studio (peu fiable) en utilisant
    directement `dotnet publish`. Gère les causes classiques d'échec :
      - arrête la tâche planifiée optiSCAN_Watchdog (qui relance l'exe),
      - termine tout optiSCAN.exe / optiSCAN.Service.exe en cours (verrous de fichiers),
      - nettoie le dossier publish périmé,
      - publie en Release win-x64 (framework-dependent par defaut, profil FolderProfile),
      - (optionnel) signe l'exe si un certificat est fourni,
      - compile l'installeur Inno (ISCC) si disponible.

.PARAMETER Configuration
    Configuration de build (défaut: Release).

.PARAMETER Runtime
    RID cible (défaut: win-x64).

.PARAMETER SelfContained
    Publier en self-contained (profil FolderProfile-SelfContained : .NET 10 + Windows App SDK embarqués,
    installeur plus lourd, aucun prérequis).

.PARAMETER FrameworkDependent
    Comportement par défaut (profil FolderProfile) : installeur léger ; setup.iss télécharge et installe
    .NET 10 Desktop Runtime + Windows App Runtime 1.8 s'ils manquent. Conservé pour compatibilité.

.PARAMETER SignToolPath / CertSubject
    Si fournis, signe optiSCAN.exe avec signtool (certificat du magasin par sujet).

.PARAMETER SkipInstaller
    Ne pas compiler l'installeur Inno.

.EXAMPLE
    pwsh -File scripts\publish-release.ps1
    pwsh -File scripts\publish-release.ps1 -FrameworkDependent
    pwsh -File scripts\publish-release.ps1 -CertSubject "Dona By"
#>
[CmdletBinding()]
param(
    [string]$Configuration = 'Release',
    [string]$Runtime = 'win-x64',
    [switch]$SelfContained,
    [switch]$FrameworkDependent,
    [string]$SignToolPath,
    [string]$CertSubject,
    [switch]$SkipInstaller
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$proj = Join-Path $repo 'optiSCAN.WinUI\optiSCAN.WinUI.csproj'
$tfm  = 'net10.0-windows10.0.19041.0'
# Sortie fixée par les profils de publication (PublishDir = bin\Release\<tfm>\publish\win-x64\).
$publishDir = Join-Path $repo "optiSCAN.WinUI\bin\$Configuration\$tfm\publish\$Runtime"

function Write-Step($m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }

# schtasks écrit sur stderr (accès refusé, tâche absente). Avec ErrorActionPreference Stop,
# PowerShell transforme cette sortie en erreur terminale et interrompt la publication.
function Invoke-OptionalScheduledTask([string[]] $SchtasksArgs) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & schtasks.exe @SchtasksArgs 2>&1 | Out-Null
    }
    finally {
        $ErrorActionPreference = $previous
    }
}

# 1) Neutraliser le watchdog qui relance optiSCAN pendant le build
Write-Step 'Arrêt du watchdog anti-sabotage'
Invoke-OptionalScheduledTask @('/Change', '/TN', 'optiSCAN_Watchdog', '/DISABLE')
Invoke-OptionalScheduledTask @('/End', '/TN', 'optiSCAN_Watchdog')

# 2) Terminer les instances qui verrouillent les binaires
Write-Step 'Fermeture des instances optiSCAN'
foreach ($p in 'optiSCAN','optiSCAN.Service') {
    Get-Process -Name $p -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Milliseconds 500

# 3) Nettoyer le dossier publish périmé
Write-Step 'Nettoyage du dossier publish'
if (Test-Path $publishDir) { Remove-Item -Recurse -Force $publishDir }

# 4) Publier via les profils : --self-contained seul n'embarquerait PAS le Windows App SDK
#    (WindowsAppSDKSelfContained n'est defini que dans FolderProfile-SelfContained).
$publishSelfContained = $SelfContained -and -not $FrameworkDependent
$profileName = if ($publishSelfContained) { 'FolderProfile-SelfContained' } else { 'FolderProfile' }
Write-Step "dotnet publish ($Configuration / $Runtime / profil $profileName)"
dotnet publish $proj -c $Configuration /p:PublishProfile=$profileName -p:CleanPublishArtifactsBeforePublish=true
if ($LASTEXITCODE -ne 0) { throw "dotnet publish a échoué (code $LASTEXITCODE)." }

$exe = Join-Path $publishDir 'optiSCAN.exe'
if (-not (Test-Path $exe)) { throw "optiSCAN.exe introuvable après publish : $exe" }
Write-Host "Publié : $exe" -ForegroundColor Green

# 5) Signature optionnelle de l'exécutable
if ($CertSubject) {
    Write-Step 'Signature Authenticode de optiSCAN.exe'
    $st = if ($SignToolPath) { $SignToolPath } else { 'signtool.exe' }
    & $st sign /n $CertSubject /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $exe
    if ($LASTEXITCODE -ne 0) { throw "signtool a échoué (code $LASTEXITCODE)." }
}
else {
    Write-Warning "Pas de signature (paramètre -CertSubject non fourni). SmartScreen affichera « éditeur inconnu »."
}

# 6) Compiler l'installeur Inno
if (-not $SkipInstaller) {
    Write-Step 'Compilation de l''installeur Inno'
    $buildSetup = Join-Path $repo 'installer\build-release-setup.ps1'
    if (-not (Test-Path -LiteralPath $buildSetup)) { throw "Introuvable : $buildSetup" }
    & $buildSetup -SkipPublish -PublishDir $publishDir -AllowMissingSignatures
    if ($LASTEXITCODE -ne 0) { throw "build-release-setup a échoué (code $LASTEXITCODE)." }
}

# 7) Réactiver le watchdog
Write-Step 'Réactivation du watchdog'
Invoke-OptionalScheduledTask @('/Change', '/TN', 'optiSCAN_Watchdog', '/ENABLE')

Write-Host "`nTerminé." -ForegroundColor Green
