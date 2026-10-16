# SPDX-License-Identifier: GPL-3.0-or-later
# Génère TOUT.md — export de tous les sources optiSCAN (cs, xaml).
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root 'TOUT.md'
$dirs = @(
    (Join-Path $root 'optiSCAN'),
    (Join-Path $root 'optiSCAN.Tests'),
    (Join-Path $root 'optiSCAN.Platform'),
    (Join-Path $root 'optiSCAN.Service')
)
$files = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
foreach ($d in $dirs) {
    if (-not (Test-Path $d)) { continue }
    foreach ($pat in @('*.cs', '*.xaml')) {
        Get-ChildItem $d -Recurse -Filter $pat -File |
            Where-Object { $_.FullName -notmatch '\\(bin|obj)\\' } |
            ForEach-Object { $files.Add($_) }
    }
}
$sorted = $files | Sort-Object FullName -Unique
$utf8 = New-Object System.Text.UTF8Encoding $false
$sw = New-Object System.IO.StreamWriter($out, $false, $utf8)
try {
    $sw.WriteLine('# optiSCAN - export code source complet')
    $sw.WriteLine('')
    $sw.WriteLine("> Fichier genere automatiquement le $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $sw.WriteLine("> Nombre de fichiers : $($sorted.Count)")
    $sw.WriteLine('')
    $sw.WriteLine('## Table des matieres')
    $sw.WriteLine('')
    foreach ($f in $sorted) {
        $rel = $f.FullName.Substring($root.Length).TrimStart('\').Replace('\', '/')
        $anchor = ($rel -replace '[^a-zA-Z0-9]+', '-').ToLower().Trim('-')
        $sw.WriteLine("- [$rel](#$anchor)")
    }
    $sw.WriteLine('')
    foreach ($f in $sorted) {
        $rel = $f.FullName.Substring($root.Length).TrimStart('\').Replace('\', '/')
        $lang = if ($f.Extension -eq '.cs') { 'csharp' } elseif ($f.Extension -eq '.xaml') { 'xml' } else { '' }
        $sw.WriteLine("## $rel")
        $sw.WriteLine('')
        $sw.WriteLine('```' + $lang)
        $sw.WriteLine([System.IO.File]::ReadAllText($f.FullName))
        $sw.WriteLine('```')
        $sw.WriteLine('')
    }
}
finally {
    $sw.Close()
}
Write-Host "TOUT.md : $($sorted.Count) fichiers -> $out ($(('{0:N0}' -f (Get-Item $out).Length)) octets)"
