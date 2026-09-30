<#
.SYNOPSIS
    Vérifie que les dictionnaires de thème WinUI (Light / Dark / HighContrast) déclarent
    exactement le même jeu de clés, avec le même type d'élément.

.DESCRIPTION
    Une clé absente d'un thème retombe silencieusement sur la valeur d'un autre thème
    (ex. accent violet en contraste renforcé). À lancer en local ou en CI :
        pwsh -File scripts/check-winui-theme-keys.ps1
    Code de sortie 1 en cas d'écart.
#>
[CmdletBinding()]
param(
    [string]$ThemesDir = (Join-Path $PSScriptRoot '..\optiSCAN.WinUI\Themes')
)

$ErrorActionPreference = 'Stop'
$files = 'Donaby.Light.xaml', 'Donaby.Dark.xaml', 'Donaby.HighContrast.xaml'
$xNs = 'http://schemas.microsoft.com/winfx/2006/xaml'

$maps = [ordered]@{}
foreach ($f in $files) {
    $path = Join-Path $ThemesDir $f
    [xml]$doc = Get-Content -LiteralPath $path -Raw -Encoding UTF8
    $map = @{}
    foreach ($node in $doc.DocumentElement.ChildNodes) {
        if ($node.NodeType -ne 'Element') { continue }
        $key = $node.GetAttribute('Key', $xNs)
        if ($key) { $map[$key] = $node.LocalName }
    }
    $maps[$f] = $map
}

$allKeys = $maps.Values | ForEach-Object { $_.Keys } | Sort-Object -Unique
$errors = 0
foreach ($key in $allKeys) {
    $types = foreach ($f in $files) { if ($maps[$f].ContainsKey($key)) { $maps[$f][$key] } else { '<absent>' } }
    if (($types | Sort-Object -Unique).Count -ne 1) {
        $errors++
        Write-Host ("  {0,-28} {1}" -f $key, (($files | ForEach-Object -Begin { $i = 0 } -Process { "$($_)=$($types[$i++])" }) -join '  ')) -ForegroundColor Red
    }
}

if ($errors -gt 0) {
    Write-Host "$errors clé(s) incohérente(s) entre les thèmes WinUI." -ForegroundColor Red
    exit 1
}
Write-Host "Thèmes WinUI cohérents : $($allKeys.Count) clés identiques dans $($files.Count) dictionnaires." -ForegroundColor Green
