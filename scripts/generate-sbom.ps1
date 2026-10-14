# Génère des SBOM CycloneDX JSON pour les projets publishables.
param(
    [string]$OutputDir = "sbom",
    [string[]]$Projects = @(
        "optiSCAN/optiSCAN.csproj",
        "optiSCAN.Service/optiSCAN.Service.csproj",
        "optiSCAN.Platform/optiSCAN.Platform.csproj"
    )
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$toolName = "CycloneDX"
# Version épinglée : un outil de la chaîne de build ne change pas sans revue.
$toolVersion = "6.2.0"
$installed = dotnet tool list -g 2>$null | Select-String -Pattern "cyclonedx\s+$([regex]::Escape($toolVersion))" -Quiet
if (-not $installed) {
    Write-Host "Installing global tool $toolName $toolVersion..."
    dotnet tool uninstall --global $toolName 2>$null | Out-Null
    dotnet tool install --global $toolName --version $toolVersion
    if ($LASTEXITCODE -ne 0) { throw "Installation de $toolName $toolVersion impossible." }
}

foreach ($proj in $Projects) {
    if (-not (Test-Path $proj)) {
        Write-Warning "Project not found: $proj"
        continue
    }

    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($proj)
    Write-Host "SBOM: $proj -> $OutputDir\$baseName-bom.json"
    dotnet-CycloneDX $proj -o $OutputDir -json --filename "$baseName-bom"
    if ($LASTEXITCODE -ne 0) {
        throw "CycloneDX failed for $proj (exit $LASTEXITCODE)"
    }
}

# Composants natifs livrés à côté des projets .NET (audit V12) : moteurs épinglés dans
# runtime-versions.json et bibliothèques fournies par l'archive ClamAV. CycloneDX ne les voit
# pas : ils ne viennent pas de NuGet.
$versionsPath = Join-Path $PSScriptRoot 'runtime-versions.json'
$versions = Get-Content -LiteralPath $versionsPath -Raw | ConvertFrom-Json
function New-Lib([string] $name, [string] $license) {
    [ordered]@{ type = 'library'; name = $name; licenses = @(@{ license = @{ id = $license } }) }
}
$clamLibs = @(
    (New-Lib 'openssl' 'Apache-2.0'), (New-Lib 'libcurl' 'curl'), (New-Lib 'libxml2' 'MIT'),
    (New-Lib 'pcre2' 'BSD-3-Clause'), (New-Lib 'json-c' 'MIT'), (New-Lib 'bzip2' 'bzip2-1.0.6'),
    (New-Lib 'libssh2' 'BSD-3-Clause'), (New-Lib 'nghttp2' 'MIT'), (New-Lib 'zlib' 'Zlib'),
    (New-Lib 'unrar' 'LicenseRef-UnRAR'), (New-Lib 'pthreads4w' 'Apache-2.0')
)
$native = [ordered]@{
    bomFormat    = 'CycloneDX'
    specVersion  = '1.5'
    version      = 1
    metadata     = [ordered]@{ component = [ordered]@{ type = 'application'; name = 'optiSCAN native runtime' } }
    components   = @(
        [ordered]@{
            type = 'application'; name = 'clamav'; version = $versions.clamavVersion
            purl = "pkg:generic/clamav@$($versions.clamavVersion)?download_url=$($versions.clamavWinX64Url)"
            hashes = @(@{ alg = 'SHA-256'; content = $versions.clamavWinX64Sha256.ToLowerInvariant() })
            licenses = @(@{ license = @{ id = 'GPL-2.0-only' } })
            components = $clamLibs
        },
        [ordered]@{
            type = 'application'; name = 'yara'; version = $versions.yaraVersion
            purl = "pkg:github/virustotal/yara@v$($versions.yaraVersion)"
            hashes = @(@{ alg = 'SHA-256'; content = $versions.yaraWin64Sha256.ToLowerInvariant() })
            licenses = @(@{ license = @{ id = 'BSD-3-Clause' } })
        }
    )
}
$nativePath = Join-Path $OutputDir 'optiSCAN-native-bom.json'
$native | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $nativePath -Encoding utf8
Write-Host "SBOM: composants natifs -> $nativePath"

Write-Host "SBOM generation complete ($OutputDir)"
