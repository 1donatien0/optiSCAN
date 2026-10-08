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
    [switch] $EmbedOfflineSignatures,
    # Signer l'installateur et son désinstalleur (.pfx ; mot de passe dans $env:CODESIGN_PASSWORD).
    [string] $SignPfxPath
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$csproj = Join-Path $root 'optiSCAN\optiSCAN.csproj'
$iss = Join-Path $PSScriptRoot 'setup.iss'
$defaultPublishDir = Join-Path $root 'optiSCAN\bin\Release\net10.0-windows10.0.17763.0\publish\win-x64'
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
    dotnet publish $csproj -c Release /p:PublishProfile=FolderProfile /p:OptiscanShipping=true
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish a echoue (code $LASTEXITCODE)." }
    $targetPublishDir = Resolve-PublishRoot $defaultPublishDir
    # Service de protection : meme dossier, meme mode (autonome, comme FolderProfile), avec sa DLL
    # et ses dependances. L'installeur refuse de se compiler sans optiSCAN.Service.dll.
    $svcCsproj = Join-Path $root 'optiSCAN.Service\optiSCAN.Service.csproj'
    Write-Host 'dotnet publish du service (meme dossier)...' -ForegroundColor Cyan
    dotnet publish $svcCsproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false -p:OptiscanShipping=true -o $targetPublishDir
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish du service a echoue (code $LASTEXITCODE)." }
    $publishExe = Join-Path $targetPublishDir 'optiSCAN.exe'
} else {
    if ((Test-Path -LiteralPath $staleFlatPublish) -and -not (Test-Path -LiteralPath $publishExe)) {
        throw @"
Publication win-x64 absente mais ancien publish\optiSCAN.exe detecte ($staleFlatPublish).
Relancez d'abord :
  .\scripts\clean-before-publish.ps1 -IncludeObj -IncludeCiPublish
  dotnet publish $csproj -c Release /p:PublishProfile=FolderProfile
  dotnet publish optiSCAN.Service\optiSCAN.Service.csproj -c Release -r win-x64 --self-contained true -o <dossier publish>
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
if (-not [string]::IsNullOrWhiteSpace($SignPfxPath)) {
    if (-not (Test-Path -LiteralPath $SignPfxPath)) { throw "Certificat introuvable : $SignPfxPath" }
    if ([string]::IsNullOrWhiteSpace($env:CODESIGN_PASSWORD)) { throw 'CODESIGN_PASSWORD absent.' }
    $signtool = $env:SIGNTOOL_PATH
    if ([string]::IsNullOrWhiteSpace($signtool)) {
        $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
        $signtool = (Get-ChildItem -Path $kits -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
            Sort-Object FullName -Descending | Select-Object -First 1).FullName
    }
    if ([string]::IsNullOrWhiteSpace($signtool)) { throw 'signtool.exe introuvable (Windows SDK requis).' }
    # Le mot de passe ne figure plus dans la commande passée à ISCC puis à signtool : le .pfx
    # est importé dans le magasin de l'utilisateur et désigné par son empreinte, puis retiré
    # après la compilation. $q = guillemet, $f = fichier à signer (placeholders Inno Setup).
    $securePwd = ConvertTo-SecureString -String $env:CODESIGN_PASSWORD -AsPlainText -Force
    $signCert = Import-PfxCertificate -FilePath $SignPfxPath -CertStoreLocation 'Cert:\CurrentUser\My' -Password $securePwd
    if (-not $signCert) { throw 'Import du certificat de signature impossible.' }
    $importedThumbprint = $signCert.Thumbprint
    $signCommand = '$q' + $signtool + '$q sign /sha1 ' + $importedThumbprint +
        ' /s My /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $f'
    $isccArgs += "/Ssigntool=$signCommand"
    $isccArgs += '/DSignInstaller'
    Write-Host '  Signature : installateur et désinstalleur signés' -ForegroundColor DarkGray
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
try {
    & $iscc @isccArgs $iss
    if ($LASTEXITCODE -ne 0) { throw "ISCC a echoue (code $LASTEXITCODE)." }
} finally {
    if ($importedThumbprint) {
        Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $importedThumbprint) -DeleteKey -ErrorAction SilentlyContinue
    }
}

if (Test-Path $outDir) {
    Write-Host 'Sortie :' -ForegroundColor Green
    Get-ChildItem $outDir -Filter '*.exe' | Sort-Object LastWriteTime -Descending | Select-Object -First 3 | Format-Table Name, Length, LastWriteTime -AutoSize
}
