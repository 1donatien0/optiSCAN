# SPDX-License-Identifier: GPL-3.0-or-later
# Ajoute optiSCAN aux exclusions Windows Defender : dossiers réservés aux administrateurs
# (installation, %ProgramData%\optiSCAN) et moteurs par chemin complet. Jamais optiSCAN.exe
# ni optiSCAN.Service.exe en exclusion de processus (audit A3) : ils sont retirés s'ils y sont.
# Relance en administrateur si nécessaire.
# Usage :
#   .\scripts\add-defender-exclusions.ps1
#   .\scripts\add-defender-exclusions.ps1 -InstallDir "C:\Program Files\optiSCAN"

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

# Même règle que InstallLocationTrust.IsAdminOnlyInstall : aucun droit d'écriture accordé
# à un autre compte que SYSTEM, Administrateurs, TrustedInstaller ou CREATOR OWNER.
function Test-AdminOnlyFolder([string] $Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return $false }
    $trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-3-0',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $write = [Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteExtendedAttributes, WriteAttributes, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
    try { $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop } catch { return $false }
    $owner = (New-Object Security.Principal.NTAccount($acl.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value
    if ($trusted -notcontains $owner) { return $false }
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        if (($rule.FileSystemRights -band $write) -eq 0) { continue }
        try { $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { return $false }
        if ($trusted -notcontains $sid) { return $false }
    }
    return $true
}

if (-not (Test-DefenderActive)) {
    Write-Warning 'Windows Defender inactif ou indisponible — exclusions ignorees.'
    exit 2
}

$root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    $InstallDir = Join-Path ${env:ProgramFiles} 'optiSCAN'
    if (-not (Test-Path -LiteralPath $InstallDir)) {
        $InstallDir = $root
    }
}

$installTrusted = Test-AdminOnlyFolder $InstallDir
if (-not $installTrusted) {
    Write-Warning "Dossier modifiable par d'autres comptes que les administrateurs : aucune exclusion pour $InstallDir"
}

$paths = @(
    $(if ($installTrusted) { $InstallDir }),
    (Join-Path ${env:ProgramData} 'optiSCAN')
) | Where-Object { $_ -and (Test-AdminOnlyFolder $_) } | ForEach-Object {
    (Resolve-Path -LiteralPath $_).Path
} | Select-Object -Unique

$processes = @(
    (Join-Path $InstallDir 'clamav\x64\clamscan.exe'),
    (Join-Path $InstallDir 'clamav\x64\freshclam.exe'),
    (Join-Path $InstallDir 'clamav\x64\clamd.exe'),
    (Join-Path $InstallDir 'yara\yara64.exe')
) | Where-Object { $installTrusted -and (Test-Path -LiteralPath $_) }

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

# Exclusions par nom nu de la 3.0.0. Les noms des moteurs peuvent appartenir à une autre
# installation (ClamAV, YARA) : ils ne sont retirés que si ceux d'optiSCAN l'étaient aussi.
$procNow = @((Get-MpPreference).ExclusionProcess)
$ours = @('optiSCAN.exe', 'optiSCAN.Service.exe') | Where-Object { $procNow -contains $_ }
$legacyTargets = @($ours)
if ($ours.Count -gt 0) {
    $legacyTargets += @('clamscan.exe', 'freshclam.exe', 'clamd.exe', 'yara64.exe') | Where-Object { $procNow -contains $_ }
}
foreach ($name in $legacyTargets) {
    try { Remove-MpPreference -ExclusionProcess $name -ErrorAction Stop } catch { }
}

# optiSCAN.exe / optiSCAN.Service.exe par chemin complet (jusqu'à la 3.1 candidate) : retirés.
foreach ($proc in @((Join-Path $InstallDir 'optiSCAN.exe'), (Join-Path $InstallDir 'optiSCAN.Service.exe'))) {
    if ($procNow -contains $proc) {
        try { Remove-MpPreference -ExclusionProcess $proc -ErrorAction Stop } catch { }
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
