<#
.SYNOPSIS
    Publication Release fiable d'optiSCAN + compilation de l'installeur Inno.

.DESCRIPTION
    Contourne l'UI de publication de Visual Studio (peu fiable) en utilisant
    directement `dotnet publish`. Gère les causes classiques d'échec :
      - arrête la tâche planifiée optiSCAN_Watchdog (qui relance l'exe),
      - termine tout optiSCAN.exe / optiSCAN.Service.exe en cours (verrous de fichiers),
      - nettoie le dossier publish périmé,
      - publie en Release win-x64 avec le runtime .NET inclus,
      - (optionnel) signe l'exe si un certificat est fourni,
      - compile l'installeur Inno (ISCC) si disponible.

.PARAMETER Configuration
    Configuration de build (défaut: Release).

.PARAMETER Runtime
    RID cible (défaut: win-x64).

.PARAMETER SelfContained
    Paramètre conservé pour compatibilité. La publication est toujours self-contained.

.PARAMETER SignToolPath / CertSubject
    Si le sujet est fourni, signe l'application, le service et les DLL plateforme publiés
    avec signtool (certificat du magasin par sujet). L'installeur n'est pas signé ici.

.PARAMETER SkipInstaller
    Ne pas compiler l'installeur Inno.

.EXAMPLE
    pwsh -File scripts\publish-release.ps1
    pwsh -File scripts\publish-release.ps1 -CertSubject "Dona By"
#>
[CmdletBinding()]
param(
    [string]$Configuration = 'Release',
    [string]$Runtime = 'win-x64',
    [switch]$SelfContained,
    [string]$SignToolPath,
    [string]$CertSubject,
    [switch]$SkipInstaller,
    # Embarquer bases ClamAV + règles YARA dans l'installeur (offline).
    # Défaut: non — téléchargement post-install (freshclam + YARA-Forge).
    [switch]$EmbedOfflineSignatures,
    # Embarquer uniquement la base ClamAV (~105 Mo).
    [switch]$EmbedClamAvDatabase,
    # Embarquer uniquement les règles YARA (.yar).
    [switch]$EmbedYaraRules
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$proj = Join-Path $repo 'optiSCAN\optiSCAN.csproj'
$tfm  = 'net10.0-windows10.0.17763.0'
$publishDir = Join-Path $repo "optiSCAN\bin\$Configuration\$tfm\publish\$Runtime"

function Write-Step($m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }

# 1) Neutraliser le watchdog qui relance optiSCAN pendant le build
Write-Step 'Arrêt du watchdog anti-sabotage'
schtasks.exe /Change /TN 'optiSCAN_Watchdog' /DISABLE 2>$null | Out-Null
schtasks.exe /End    /TN 'optiSCAN_Watchdog' 2>$null | Out-Null

# 2) Terminer les instances qui verrouillent les binaires
Write-Step 'Fermeture des instances optiSCAN'
foreach ($p in 'optiSCAN','optiSCAN.Service') {
    Get-Process -Name $p -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Milliseconds 500

# 3) Nettoyer le dossier publish périmé
Write-Step 'Nettoyage du dossier publish'
if (Test-Path $publishDir) { Remove-Item -Recurse -Force $publishDir }

# 4) Publier
Write-Step "dotnet publish ($Configuration / $Runtime / self-contained=true)"
dotnet publish $proj -p:OptiscanShipping=true -c $Configuration -r $Runtime --self-contained true -p:CleanPublishArtifactsBeforePublish=true
if ($LASTEXITCODE -ne 0) { throw "dotnet publish a échoué (code $LASTEXITCODE)." }

$exe = Join-Path $publishDir 'optiSCAN.exe'
if (-not (Test-Path $exe)) { throw "optiSCAN.exe introuvable après publish : $exe" }

# Service de protection : même mode, même dossier, avec sa DLL et ses dépendances.
$svcProj = Join-Path $repo 'optiSCAN.Service\optiSCAN.Service.csproj'
dotnet publish $svcProj -p:OptiscanShipping=true -c $Configuration -r $Runtime --self-contained true -p:PublishSingleFile=false -o $publishDir
if ($LASTEXITCODE -ne 0) { throw "dotnet publish du service a échoué (code $LASTEXITCODE)." }
foreach ($f in 'optiSCAN.Service.exe', 'optiSCAN.Service.dll') {
    if (-not (Test-Path (Join-Path $publishDir $f))) { throw "$f introuvable après publish : $publishDir" }
}
Write-Host "Publié : $exe" -ForegroundColor Green

# 5) Signature optionnelle de l'exécutable
if ($CertSubject) {
    Write-Step 'Signature Authenticode des binaires optiSCAN'
    $st = if ($SignToolPath) { $SignToolPath } else { 'signtool.exe' }
    # Mêmes fichiers que la CI : le service tourne en SYSTEM, il doit être signé comme l'interface.
    $toSign = 'optiSCAN.exe', 'optiSCAN.dll', 'optiSCAN.Service.exe', 'optiSCAN.Service.dll', 'optiSCAN.Platform.dll' |
        ForEach-Object { Join-Path $publishDir $_ }
    & $st sign /n $CertSubject /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 @toSign
    if ($LASTEXITCODE -ne 0) { throw "signtool a échoué (code $LASTEXITCODE)." }
}
else {
    Write-Warning "Pas de signature (paramètre -CertSubject non fourni). SmartScreen affichera « éditeur inconnu »."
}

# 6) Compiler l'installeur Inno
if (-not $SkipInstaller) {
    Write-Step 'Compilation de l''installeur Inno'
    $iscc = Get-Command 'ISCC.exe' -ErrorAction SilentlyContinue
    if (-not $iscc) {
        foreach ($c in @(
            "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
            "$env:ProgramFiles\Inno Setup 6\ISCC.exe")) {
            if (Test-Path $c) { $iscc = $c; break }
        }
    }
    if ($iscc) {
        # Version lue depuis Directory.Build.props (source unique de vérité) :
        # évite que l'installeur reparte sur un numéro figé après un bump.
        [xml]$propsXml = Get-Content -LiteralPath (Join-Path $repo 'Directory.Build.props')
        $appVersion = ($propsXml.Project.PropertyGroup.Version | Select-Object -First 1).'#text'
        if ([string]::IsNullOrWhiteSpace($appVersion)) { $appVersion = '3.1.0' }
        $isccArgs = @((Join-Path $repo 'installer\setup.iss'), "/DAppVersion=$appVersion")
        if ($EmbedOfflineSignatures) { $isccArgs += '/DEmbedOfflineSignatures' }
        else {
            if ($EmbedClamAvDatabase) { $isccArgs += '/DEmbedClamAvDatabase' }
            if ($EmbedYaraRules) { $isccArgs += '/DEmbedYaraRules' }
        }
        & $iscc @isccArgs
        if ($LASTEXITCODE -ne 0) { throw "ISCC a échoué (code $LASTEXITCODE)." }
        Write-Host "Installeur généré dans installer\output\" -ForegroundColor Green
    }
    else {
        Write-Warning "ISCC.exe (Inno Setup) introuvable — installeur non compilé. Ouvre installer\setup.iss manuellement."
    }
}

# 7) Réactiver le watchdog
Write-Step 'Réactivation du watchdog'
schtasks.exe /Change /TN 'optiSCAN_Watchdog' /ENABLE 2>$null | Out-Null

Write-Host "`nTerminé." -ForegroundColor Green
