# Ajoute optiSCAN aux exclusions Windows Defender (chemins + processus).
# Relance en administrateur si nécessaire.
# Usage :
#   .\scripts\add-defender-exclusions.ps1
#   .\scripts\add-defender-exclusions.ps1 -InstallDir "C:\Program Files\optiSCAN WinUI"

[CmdletBinding()]
param(
    [string] $InstallDir,
    [switch] $NoElevate
)

$ErrorActionPreference = 'Stop'

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not $NoElevate -and -not (Test-IsAdmin)) {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-NoElevate')
    if ($InstallDir) { $argList += @('-InstallDir', $InstallDir) }
    Write-Host 'Elevation UAC requise pour les exclusions Defender...' -ForegroundColor Yellow
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList -Wait
    exit $LASTEXITCODE
}

function Test-DefenderActive {
    try {
        $s = Get-MpComputerStatus -ErrorAction Stop
        return $s.AMServiceEnabled
    }
    catch {
        return $false
    }
}

function Ensure-ExclusionPath([string[]] $Existing, [string] $Path, [ref] $Denied) {
    if (-not (Test-Path -LiteralPath $Path)) {
        $parent = Split-Path -Parent $Path
        if ($parent -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Path $Path -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    $norm = (Resolve-Path -LiteralPath $Path).Path
    foreach ($e in $Existing) {
        if ($e.Equals($norm, [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
    }
    try {
        Add-MpPreference -ExclusionPath $norm -ErrorAction Stop
        return $true
    }
    catch {
        $Denied.Value = $true
        Write-Warning "Chemin refuse : $norm — $($_.Exception.Message)"
        return $false
    }
}

function Ensure-ExclusionProcess([string[]] $Existing, [string] $Name, [ref] $Denied) {
    foreach ($e in $Existing) {
        if ($e.Equals($Name, [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
    }
    try {
        Add-MpPreference -ExclusionProcess $Name -ErrorAction Stop
        return $true
    }
    catch {
        $Denied.Value = $true
        Write-Warning "Processus refuse : $Name — $($_.Exception.Message)"
        return $false
    }
}

if (-not (Test-DefenderActive)) {
    Write-Warning 'Windows Defender inactif ou indisponible — exclusions ignorees.'
    exit 2
}

$root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    # Script copie dans {app}\scripts par Inno : le dossier parent EST l'installation.
    $InstallDir = if (Test-Path -LiteralPath (Join-Path $root 'optiSCAN.exe')) { $root }
        else { Join-Path ${env:ProgramFiles} 'optiSCAN WinUI' }
    if (-not (Test-Path -LiteralPath $InstallDir)) {
        $InstallDir = $root
    }
}

$paths = @(
    $InstallDir
    (Join-Path $env:LOCALAPPDATA 'optiSCAN')
) | ForEach-Object {
    try { (Resolve-Path -LiteralPath $_ -ErrorAction SilentlyContinue).Path } catch { $_ }
} | Where-Object { $_ } | Select-Object -Unique

$processes = @(
    'optiSCAN.exe',
    'optiSCAN.Service.exe',
    'clamscan.exe',
    'freshclam.exe',
    'clamd.exe',
    'yara64.exe'
)

$pref = Get-MpPreference
$pathExisting = @($pref.ExclusionPath)
$procExisting = @($pref.ExclusionProcess)
$added = 0
$denied = $false

foreach ($p in $paths) {
    if (Ensure-ExclusionPath $pathExisting $p ([ref]$denied)) {
        Write-Host "  + chemin $p" -ForegroundColor Green
        if (Test-Path -LiteralPath $p) {
            $pathExisting += (Resolve-Path -LiteralPath $p).Path
        }
        $added++
    }
}

foreach ($proc in $processes) {
    if (Ensure-ExclusionProcess $procExisting $proc ([ref]$denied)) {
        Write-Host "  + processus $proc" -ForegroundColor Green
        $procExisting += $proc
        $added++
    }
}

if ($added -eq 0 -and -not $denied) {
    Write-Host 'Exclusions Defender deja en place.' -ForegroundColor Cyan
    exit 0
}

if ($denied) {
    Write-Host 'Certaines exclusions n''ont pas pu etre ajoutees (droits admin ou protection contre la falsification).' -ForegroundColor Yellow
    exit 4
}

Write-Host "Exclusions Defender ajoutees : $added" -ForegroundColor Green
exit 0
