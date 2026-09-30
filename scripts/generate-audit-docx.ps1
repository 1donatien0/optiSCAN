# Génère audit_optiSCAN_v1.docx à partir de la source unique AUDIT.md.
#
# Source d'audit UNIQUE : AUDIT.md (racine du dépôt). Ce script ne fait qu'en
# produire un rendu Word — il ne duplique aucun contenu et n'a pas à être tenu
# à jour manuellement quand l'audit évolue.
#
# Usage :
#   .\scripts\generate-audit-docx.ps1
#   .\scripts\generate-audit-docx.ps1 -SourcePath ..\AUDIT.md -OutputPath ..\audit_optiSCAN_v1.docx
param(
    [string]$SourcePath = (Join-Path (Split-Path $PSScriptRoot -Parent) "AUDIT.md"),
    [string]$OutputPath = (Join-Path (Split-Path $PSScriptRoot -Parent) "audit_optiSCAN_v1.docx")
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $SourcePath)) {
    throw "Source d'audit introuvable : $SourcePath (le fichier d'audit unique est AUDIT.md)."
}

# Lecture de la source unique, avec allègement Markdown léger pour un rendu Word lisible.
$lines = Get-Content -LiteralPath $SourcePath -Encoding UTF8
$sb = New-Object System.Text.StringBuilder
foreach ($line in $lines) {
    $t = $line
    $t = $t -replace '`', ''                    # code inline
    $t = $t -replace '\*\*', ''                 # gras
    $t = $t -replace '^\s{0,3}#{1,6}\s*', ''     # titres Markdown
    $t = $t -replace '^\s*>\s?', ''             # citations
    [void]$sb.AppendLine($t)
}
$content = $sb.ToString()

$word = New-Object -ComObject Word.Application
$word.Visible = $false
try {
    $doc = $word.Documents.Add()
    $doc.Content.Text = $content
    $wdFormatXMLDocument = 12
    if (Test-Path -LiteralPath $OutputPath) { Remove-Item -LiteralPath $OutputPath -Force }
    $doc.SaveAs([ref]$OutputPath, [ref]$wdFormatXMLDocument)
    $doc.Close([ref]$false)
    Write-Host "Written: $OutputPath (source unique : $SourcePath)"
}
finally {
    $word.Quit([ref]$false)
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($word) | Out-Null
}
