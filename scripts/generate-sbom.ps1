# Génère des SBOM CycloneDX JSON pour les projets publishables.
param(
    [string]$OutputDir = "sbom",
    [string[]]$Projects = @(
        "optiSCAN.WinUI/optiSCAN.WinUI.csproj",
        "optiSCAN.Service/optiSCAN.Service.csproj",
        "optiSCAN.IPC/optiSCAN.IPC.csproj"
    )
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$toolName = "CycloneDX"
$installed = dotnet tool list -g 2>$null | Select-String -Pattern $toolName -Quiet
if (-not $installed) {
    Write-Host "Installing global tool $toolName..."
    dotnet tool install --global $toolName
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
