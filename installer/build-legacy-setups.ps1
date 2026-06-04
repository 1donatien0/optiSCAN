# Recompile les installateurs v1–v6 depuis l'historique Git.
# v1–v5 : français seul (pas de choix English dans Inno).
# v6    : bilingue (FR + EN, comme à l'époque).
# Usage : .\installer\build-legacy-setups.ps1
#         .\installer\build-legacy-setups.ps1 -Versions 4,5,6

[CmdletBinding()]
param(
    [int[]] $Versions = @(1, 2, 3, 4, 5, 6)
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$outDir = Join-Path $PSScriptRoot 'output'
$iscc = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles}\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw 'ISCC.exe introuvable (Inno Setup 6).' }

$legacy = @(
    @{ Ver = 1; Sha = 'c5f3ed0'; FrenchOnly = $true;  Tfm = 'net8.0-windows';              SelfContained = $true }
    @{ Ver = 2; Sha = 'c5f3ed0'; FrenchOnly = $true;  Tfm = 'net8.0-windows';              SelfContained = $true; UseV1SetupTemplate = $true; ApplyV2UiFix = $true }
    @{ Ver = 3; Sha = '83a8d9b'; FrenchOnly = $true;  Tfm = 'net8.0-windows10.0.17763.0'; SelfContained = $false }
    @{ Ver = 4; Sha = '2c90e23'; FrenchOnly = $true;  Tfm = 'net8.0-windows10.0.17763.0'; SelfContained = $false }
    @{ Ver = 5; Sha = '84c6a05'; FrenchOnly = $true;  Tfm = 'net8.0-windows10.0.17763.0'; SelfContained = $false }
    @{ Ver = 6; Sha = 'dbe0c07'; FrenchOnly = $false; Tfm = 'net8.0-windows10.0.17763.0'; SelfContained = $false }
)

function Remove-EnglishInstallerLanguage {
    param([string] $IssPath)
    $lines = Get-Content -LiteralPath $IssPath -Encoding UTF8
    $filtered = $lines | Where-Object { $_ -notmatch '^\s*Name:\s*"english"' }
    Set-Content -LiteralPath $IssPath -Value $filtered -Encoding UTF8
}

function Remove-MissingLicenseDirective {
    param([string] $IssPath)
    $license = Join-Path (Split-Path -Parent $IssPath) '..\LICENSE.txt' | Resolve-Path -ErrorAction SilentlyContinue
    if ($license) { return }
    $lines = Get-Content -LiteralPath $IssPath -Encoding UTF8
    $filtered = $lines | Where-Object { $_ -notmatch '^\s*LicenseFile\s*=' }
    Set-Content -LiteralPath $IssPath -Value $filtered -Encoding UTF8
}

function Ensure-LegacySetupIcon {
    param([string] $WtRoot)
    $modernIcon = Join-Path $repoRoot 'optiSCAN\optiSCAN.ico'
    if (-not (Test-Path $modernIcon)) { return }
    Copy-Item -LiteralPath $modernIcon -Destination (Join-Path $WtRoot 'optiSCAN\ico.ico') -Force
}

function Apply-V2SetupTemplate {
    param(
        [string] $IssPath,
        [string] $RepoRoot
    )
    $template = git -C $RepoRoot show 'c5f3ed0:installer/setup.iss'
    if (-not $template) { throw 'Modèle setup v1 (c5f3ed0) introuvable.' }
    $content = ($template -join "`n") -replace '#define AppVersion\s+"1\.0\.0"', '#define AppVersion   "2.0.0"'
    $enc = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($IssPath, $content, $enc)
}

function Sync-PublishLayout {
    param(
        [string] $Root,
        [string] $Tfm
    )
    $base = Join-Path $Root "optiSCAN\bin\Release\$Tfm"
    $ridPublish = Join-Path $base 'win-x64\publish'
    $flatPublish = Join-Path $base 'publish'
    $nestedPublish = Join-Path $flatPublish 'win-x64'

    if (-not (Test-Path (Join-Path $ridPublish 'optiSCAN.exe'))) { return }

    foreach ($dest in @($nestedPublish, $flatPublish)) {
        New-Item -ItemType Directory -Force -Path $dest | Out-Null
        Copy-Item -Path (Join-Path $ridPublish '*') -Destination $dest -Recurse -Force
    }
}

function Build-LegacySetup {
    param($Cfg)

    $wt = Join-Path (Split-Path -Parent $repoRoot) "optiSCAN-build-v$($Cfg.Ver)"
    Push-Location $repoRoot
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    git worktree remove $wt --force 2>$null | Out-Null
    $ErrorActionPreference = $prevEap
    Pop-Location
    if (Test-Path $wt) {
        Start-Sleep -Seconds 1
        Remove-Item -LiteralPath $wt -Recurse -Force -ErrorAction SilentlyContinue
    }

    Push-Location $repoRoot
    git worktree add $wt $Cfg.Sha | Out-Null
    Pop-Location

    try {
        $iss = Join-Path $wt 'installer\setup.iss'
        if ($Cfg.UseV1SetupTemplate) { Apply-V2SetupTemplate -IssPath $iss -RepoRoot $repoRoot }
        if ($Cfg.FrenchOnly) { Remove-EnglishInstallerLanguage $iss }
        Remove-MissingLicenseDirective $iss

        if ($Cfg.ApplyV2UiFix) {
            . (Join-Path $PSScriptRoot 'Apply-V2LegacyUiFix.ps1')
            Apply-V2LegacyUiFix -WtRoot $wt
        }

        if ($Cfg.Ver -le 2) { Ensure-LegacySetupIcon -WtRoot $wt }

        $csproj = Join-Path $wt 'optiSCAN\optiSCAN.csproj'
        $sc = if ($Cfg.SelfContained) { 'true' } else { 'false' }
        Write-Host "v$($Cfg.Ver) ($($Cfg.Sha)) : dotnet publish (self-contained=$sc)..." -ForegroundColor Cyan
        dotnet publish $csproj -c Release -r win-x64 --self-contained $sc
        if ($LASTEXITCODE -ne 0) { throw "dotnet publish v$($Cfg.Ver) a échoué." }

        Sync-PublishLayout -Root $wt -Tfm $Cfg.Tfm

        $exe = Join-Path $wt "optiSCAN\bin\Release\$($Cfg.Tfm)\publish\optiSCAN.exe"
        $exeAlt = Join-Path $wt "optiSCAN\bin\Release\$($Cfg.Tfm)\publish\win-x64\optiSCAN.exe"
        $exeRid = Join-Path $wt "optiSCAN\bin\Release\$($Cfg.Tfm)\win-x64\publish\optiSCAN.exe"
        if (-not (Test-Path $exe) -and (Test-Path $exeAlt)) { $exe = $exeAlt }
        if (-not (Test-Path $exe) -and (Test-Path $exeRid)) {
            Sync-PublishLayout -Root $wt -Tfm $Cfg.Tfm
        }
        if (-not (Test-Path $exe) -and -not (Test-Path $exeAlt) -and -not (Test-Path $exeRid)) {
            throw "optiSCAN.exe introuvable après publish v$($Cfg.Ver)."
        }

        $installerDir = Join-Path $wt 'installer'
        & $iscc (Join-Path $installerDir 'setup.iss')
        if ($LASTEXITCODE -ne 0) { throw "ISCC v$($Cfg.Ver) a échoué." }

        $built = Get-ChildItem (Join-Path $wt 'installer\output\*.exe') | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if (-not $built) { throw "Aucun setup généré pour v$($Cfg.Ver)." }

        New-Item -ItemType Directory -Force -Path $outDir | Out-Null
        Copy-Item -LiteralPath $built.FullName -Destination (Join-Path $outDir $built.Name) -Force
        Write-Host "OK v$($Cfg.Ver) -> $($built.Name) ($([math]::Round($built.Length/1MB,1)) Mo)" -ForegroundColor Green
    }
    finally {
        Push-Location $repoRoot
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        git worktree remove $wt --force 2>$null | Out-Null
        $ErrorActionPreference = $prevEap
        Pop-Location
        if (Test-Path $wt) { Remove-Item -LiteralPath $wt -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

New-Item -ItemType Directory -Force -Path $outDir | Out-Null

foreach ($cfg in $legacy) {
    if ($cfg.Ver -notin $Versions) { continue }
    Build-LegacySetup $cfg
}

Write-Host "`nSortie finale ($outDir) :" -ForegroundColor Green
Get-ChildItem $outDir -Filter 'optiSCAN_Setup_v*.exe' | Sort-Object { [version]($_.BaseName -replace 'optiSCAN_Setup_v','') } |
    Format-Table Name, @{ N = 'Mo'; E = { [math]::Round($_.Length / 1MB, 1) } }, LastWriteTime -AutoSize
