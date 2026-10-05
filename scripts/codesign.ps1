# Signature Authenticode des binaires optiSCAN et de l'installateur, à partir d'un .pfx.
#
# CI (job publish) : secrets CODESIGN_PFX (contenu base64 du .pfx) et CODESIGN_PASSWORD.
# Sans secret, -Prepare écrit enabled=false et les étapes de signature sont sautées :
# la chaîne reste verte, les binaires sortent non signés comme avant.
#
#   pwsh -File scripts/codesign.ps1 -Prepare
#   pwsh -File scripts/codesign.ps1 -Sign -PfxPath <pfx> -Files a.exe,b.dll
#
# Local : -Sign -PfxPath C:\chemin\cert.pfx (mot de passe dans $env:CODESIGN_PASSWORD).
[CmdletBinding()]
param(
    [switch] $Prepare,
    [switch] $Sign,
    [string] $PfxPath,
    [string[]] $Files,
    # HTTP est la norme pour l'horodatage RFC 3161 : la réponse est signée par l'autorité
    # d'horodatage et vérifiée par signtool ; le transport n'apporte pas la confiance.
    [string] $TimestampUrl = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'

function Write-Output-Var([string] $Name, [string] $Value) {
    if ($env:GITHUB_OUTPUT) {
        Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value "$Name=$Value" -Encoding utf8
    }
    Write-Host "$Name=$Value"
}

function Find-SignTool {
    if ($env:SIGNTOOL_PATH -and (Test-Path -LiteralPath $env:SIGNTOOL_PATH)) {
        return $env:SIGNTOOL_PATH
    }
    $onPath = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    $found = Get-ChildItem -Path $kits -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
        Sort-Object FullName -Descending |
        Select-Object -First 1
    if ($found) { return $found.FullName }
    throw 'signtool.exe introuvable (Windows SDK requis).'
}

if ($Prepare) {
    if ([string]::IsNullOrWhiteSpace($env:CODESIGN_PFX)) {
        Write-Host 'CODESIGN_PFX absent : signature désactivée pour ce build.'
        Write-Output-Var 'enabled' 'false'
        exit 0
    }

    $temp = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
    $pfx = Join-Path $temp 'optiscan-codesign.pfx'
    [IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($env:CODESIGN_PFX))
    Write-Output-Var 'enabled' 'true'
    Write-Output-Var 'pfx' $pfx
    Write-Output-Var 'signtool' (Find-SignTool)
    exit 0
}

if ($Sign) {
    if ([string]::IsNullOrWhiteSpace($PfxPath) -or -not (Test-Path -LiteralPath $PfxPath)) {
        throw "Certificat .pfx introuvable : $PfxPath"
    }
    if ([string]::IsNullOrWhiteSpace($env:CODESIGN_PASSWORD)) {
        throw 'CODESIGN_PASSWORD absent.'
    }

    $signtool = Find-SignTool
    $targets = @($Files | ForEach-Object { $_ -split ',' } | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
    if ($targets.Count -eq 0) { throw 'Aucun fichier à signer.' }

    # Le mot de passe ne passe plus sur la ligne de commande de signtool (visible par les
    # autres processus et dans les journaux d'audit) : le .pfx est importé dans le magasin de
    # l'utilisateur, signtool désigne le certificat par son empreinte, puis il est retiré.
    $secure = ConvertTo-SecureString -String $env:CODESIGN_PASSWORD -AsPlainText -Force
    $cert = Import-PfxCertificate -FilePath $PfxPath -CertStoreLocation 'Cert:\CurrentUser\My' -Password $secure
    if (-not $cert) { throw 'Import du certificat de signature impossible.' }
    try {
        foreach ($file in $targets) {
            & $signtool sign /sha1 $cert.Thumbprint /s My /fd SHA256 /tr $TimestampUrl /td SHA256 $file
            if ($LASTEXITCODE -ne 0) { throw "signtool sign a échoué pour $file (code $LASTEXITCODE)." }
            & $signtool verify /pa $file
            if ($LASTEXITCODE -ne 0) { throw "Signature invalide pour $file (code $LASTEXITCODE)." }
            Write-Host "Signé : $file"
        }
    } finally {
        Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $cert.Thumbprint) -DeleteKey -ErrorAction SilentlyContinue
    }
    exit 0
}

throw 'Préciser -Prepare ou -Sign.'
