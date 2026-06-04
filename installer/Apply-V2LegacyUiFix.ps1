# Corrections UI français + encodage UTF-8 pour l'installateur legacy v2.0.0.
# Appelé depuis build-legacy-setups.ps1 sur le worktree v2 avant publish.

function Write-Utf8BomFile {
    param([string] $Path, [string] $Content)
    $enc = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::WriteAllText($Path, $Content, $enc)
}

function Ensure-XmlUtf8Prologue {
    param([string] $Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $text = [System.IO.File]::ReadAllText($Path)
    if ($text -match '^\s*<\?xml') { return }
    Write-Utf8BomFile -Path $Path -Content ("<?xml version=`"1.0`" encoding=`"utf-8`"?>`r`n" + $text.TrimStart())
}

function Apply-Replacements {
    param(
        [string] $Path,
        [hashtable] $Map
    )
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $text = [System.IO.File]::ReadAllText($Path)
    foreach ($key in $Map.Keys) {
        $text = $text.Replace($key, $Map[$key])
    }
    Write-Utf8BomFile -Path $Path -Content $text
}

function Apply-V2LegacyUiFix {
    param([string] $WtRoot)

    $xaml = Join-Path $WtRoot 'optiSCAN\MainWindow.xaml'
    $code = Join-Path $WtRoot 'optiSCAN\MainWindow.xaml.cs'
    $result = Join-Path $WtRoot 'optiSCAN\Models\ScanResult.cs'
    $appXaml = Join-Path $WtRoot 'optiSCAN\App.xaml'

    $xamlMap = [ordered]@{
        'Version 1.0.0'                          = 'Version 2.0.0'
        '>optiSCAN v1.0.0<'                      = '>optiSCAN v2.0.0<'
        'optiSCAN v1.0 — Provided by Dona By'    = 'optiSCAN v2.0 — Proposé par Dona By'
        'Provided by Dona By'                    = 'Proposé par Dona By'
        'LANCER UN SCAN'                         = 'LANCER UNE ANALYSE'
        'Scan Rapide'                            = 'Analyse rapide'
        'Scan Complet'                           = 'Analyse complète'
        'Scanner un dossier'                     = 'Analyser un dossier'
        'Scanner un fichier'                     = 'Analyser un fichier'
        'Arrêter le scan'                        = "Arrêter l'analyse"
        'Prêt à scanner'                         = 'Prêt à analyser'
        'Dernier scan'                           = 'Dernière analyse'
        'Fichiers scannés :'                     = 'Fichiers analysés :'
        'Scan en cours'                          = 'Analyse en cours'
        'Header="Scans antivirus"'               = 'Header="Analyses antivirus"'
        'Temp Utilisateur'                       = 'Temp. utilisateur'
        'Temp Windows'                           = 'Temp. Windows'
        'Windows Temp + Temp utilisateur'        = 'Temp. Windows + temp. utilisateur'
        'Voir les scans'                         = 'Voir les analyses'
        'cardHistorySubtitle'                      = 'cardHistorySubtitle'
    }
    # Retirer la ligne noop ajoutée par erreur
    $xamlMap.Remove('cardHistorySubtitle')

    $codeMap = [ordered]@{
        'prêt à scanner'                         = 'prêt à analyser'
        'Scan annulé'                            = 'Analyse annulée'
        'Scan en cours'                          = 'Analyse en cours'
    }

    $resultMap = [ordered]@{
        'Scan en cours…'                         = 'Analyse en cours…'
        'Scan annulé'                            = 'Analyse annulée'
        'Scan rapide'                            = 'Analyse rapide'
        'Scan complet'                           = 'Analyse complète'
        'ScanType.QuickScan => "Scan rapide"'    = 'ScanType.QuickScan => "Analyse rapide"'
        'ScanType.FullScan  => "Scan complet"'   = 'ScanType.FullScan  => "Analyse complète"'
    }

    Apply-Replacements -Path $xaml -Map $xamlMap
    Apply-Replacements -Path $code -Map $codeMap
    Apply-Replacements -Path $result -Map $resultMap

    Ensure-XmlUtf8Prologue -Path $xaml
    Ensure-XmlUtf8Prologue -Path $appXaml
}
