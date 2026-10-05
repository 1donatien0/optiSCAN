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

Write-Host "SBOM generation complete ($OutputDir)"
