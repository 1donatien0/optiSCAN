# Signe optiSCAN.exe et l'installateur Inno (Authenticode) via le magasin certificats Windows.
# Nécessite un certificat de signature de code déjà installé (clé privée accessible à signtool).
#
# Local :
#   pwsh -File scripts/sign-publish-artifacts.ps1 -CertSubject "Nom exact du sujet"
#   pwsh -File scripts/publish-release.ps1 -CertSubject "Nom exact du sujet"
#
# CI GitHub (secret repository SIGN_CERT_SUBJECT = même nom de sujet) :
#   Fonctionne si le runner a le certificat dans Cert:\CurrentUser\My ou Cert:\LocalMachine\My
#   (runner self-hosted, ou import du certificat sur la machine de build).
#   Sans secret ou sans certificat : étape ignorée, publish inchangé (gratuit).
param(
    [string]$PublishDir = 'publish/win-x64',
    [string]$InstallerDir = 'installer/output',
    [string]$CertSubject = $env:SIGN_CERT_SUBJECT,
    [string]$SignToolPath = $env:SIGNTOOL_PATH
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($CertSubject)) {
    Write-Host 'SIGN_CERT_SUBJECT non défini — signature ignorée.'
    exit 0
}

function Test-SigningCertInStore([string]$Subject) {
    foreach ($store in 'Cert:\CurrentUser\My', 'Cert:\LocalMachine\My') {
        $match = Get-ChildItem $store -ErrorAction SilentlyContinue |
            Where-Object { $_.Subject -like "*$Subject*" } |
            Select-Object -First 1
        if ($match) { return $match }
    }
    return $null
}

$cert = Test-SigningCertInStore $CertSubject
if (-not $cert) {
    Write-Warning @"
Certificat introuvable pour le sujet « $CertSubject » dans CurrentUser\My ou LocalMachine\My.
- Local : installez votre certificat OV/EV (token USB ou import .pfx), puis relancez.
- CI : utilisez un runner self-hosted avec le certificat installé, ou laissez le secret vide.
Signature ignorée — les binaires restent non signés.
"@
    exit 0
}

Write-Host "Certificat trouvé : $($cert.Subject) (thumbprint $($cert.Thumbprint))"

$st = if ($SignToolPath) { $SignToolPath } else { 'signtool.exe' }
$ts = 'http://timestamp.digicert.com'
$signArgs = @('sign', '/n', $CertSubject, '/fd', 'SHA256', '/tr', $ts, '/td', 'SHA256')

$exe = Join-Path $PublishDir 'optiSCAN.exe'
if (Test-Path $exe) {
    & $st @signArgs $exe
    if ($LASTEXITCODE -ne 0) { throw "signtool a échoué pour $exe (code $LASTEXITCODE)." }
    Write-Host "Signé : $exe"
}

$setup = Get-ChildItem -Path $InstallerDir -Filter '*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($setup) {
    & $st @signArgs $setup.FullName
    if ($LASTEXITCODE -ne 0) { throw "signtool a échoué pour l'installateur (code $LASTEXITCODE)." }
    Write-Host "Signé : $($setup.FullName)"
}

Write-Host 'Signature Authenticode terminée.'
