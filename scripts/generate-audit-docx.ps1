# Régénère audit_optiSCAN_v8.docx (révision post-refactor, 16 juin 2026).
param(
    [string]$OutputPath = (Join-Path (Split-Path $PSScriptRoot -Parent) "audit_optiSCAN_v8.docx")
)

$ErrorActionPreference = "Stop"

$content = @"
optiSCAN v8.0 — Antivirus Windows (C# WPF .NET 8)
Rapport d'audit technique — révision post-refactor

Auteur : Donatien Byakombe (Dona By)
Date : 16 juin 2026 (révision)
Dépôt : github.com/1donatien0/optiSCAN-stable
Tag : v8.0 (commit 5a7c194)

1. Résumé exécutif

optiSCAN v8.0 est un antivirus Windows développé en solo : architecture C# WPF .NET 8, moteurs ClamAV (dual-mode) + YARA, couche plateforme (AMSI, IPC, service Windows) et protection avancée (RTP, USB, planificateur, quarantaine AES-GCM).

Depuis l'audit initial du 16 juin 2026, une vague de refactorings a été livrée : ~22 coordinateurs, prefs DI (IUserPreferencesAccessor / IExclusionSettingsAccessor), IViewServices / IHistoryServices, IPC shutdown token + ACL pipe, CI seuil 40 %, SBOM CycloneDX, dependency-review.

Score global révisé : 84/100 — prêt pour release v8.0 côté technique (hors signature Authenticode EV).

2. Scores par dimension (révisés)

Architecture        88/100  (+6)  Coordinateurs, DI prefs, IHistoryServices
Qualité code        84/100  (+5)  MainWindow 737 L (était 1 009)
Sécurité            82/100  (+5)  Path traversal quarantaine, IPC ACL
Tests               78/100  (+6)  279 tests xUnit
CI / DevOps         90/100  (+5)  Seuil 40 %, SBOM publish, dependency-review
Async safety        86/100  (=)   10 async void gardés, ConfigureAwait(false)

3. Métriques clés (état actuel)

279 tests xUnit | ~78 fichiers de test
737 L MainWindow (était 1 009) | ~594 L HistoryControl (IHistoryServices)
22 coordinateurs | 3 suppressions null!
Seuil couverture CI : 40 % (warning 50 %)
Tag git v8.0 sur main

4. Constats — statut

RÉSOLU — Path traversal QuarantineManager.RestoreTo()
  IsResolvedPathUnderDirectory + tests QuarantineManagerSecurityTests

RÉSOLU — AppInstallPaths._cachedRoot
  Lazy<string> thread-safe (commit 5a7c194)

RÉSOLU — DistractionFreeMonitor._lastCheckUtc
  Volatile.Read/Write sur ticks UTC

RÉSOLU — HistoryControl couplé ServiceContainer
  Bind(IHistoryServices) — plus de ServiceContainer direct

RÉSOLU — Seuil couverture CI
  ci.yml : floor 0.40, target 0.50

RÉSOLU — SBOM pipeline publish
  scripts/generate-sbom.ps1 + artefact optiSCAN-sbom

PARTIEL — ScheduledScanService
  Tests parsing XML/schtasks ; pas d'intégration schtasks mockée

RÉSOLU — ExportCoordinator sans tests
  IHistoryExportService + ExportCoordinatorTests

OUVERT — Signature code installer (certificat EV requis)
OUVERT — Minifilter kernel .sys (stub intentionnel, hors scope v8)

5. Complétude fonctionnelle v8.0

Verdict inchangé : fonctionnellement complet. 0 NotImplementedException bloquant.
Panneaux UI 5/5 | Moteurs 5/5 | Protection plateforme 6/7 (minifilter stub)

6. Recommandations release

FAIT — Correctifs sécurité P0/P1 (quarantaine, thread-safety)
FAIT — Tag git v8.0
À FAIRE — GitHub Release avec optiSCAN_Setup_v8.0.0.exe (job publish main)
À FAIRE — Signature Authenticode (certificat EV)
POST-RELEASE — Couverture cible 50–60 %, refactor HistoryControl restant (~594 L)

© 2026 Donatien Byakombe — Révision générée le 16 juin 2026
"@

$word = New-Object -ComObject Word.Application
$word.Visible = $false
try {
    $doc = $word.Documents.Add()
    $doc.Content.Text = $content
    $wdFormatXMLDocument = 12
    if (Test-Path $OutputPath) { Remove-Item $OutputPath -Force }
    $doc.SaveAs([ref]$OutputPath, [ref]$wdFormatXMLDocument)
    $doc.Close([ref]$false)
    Write-Host "Written: $OutputPath"
}
finally {
    $word.Quit([ref]$false)
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($word) | Out-Null
}
