# Audit optiSCAN v7.0 — état au juin 2026

**Version** : 7.0.0 / tag `v7.0`  
**Méthode** : revue code + tests Release automatisés

---

## Synthèse

| Domaine | Verdict | Note |
|---------|---------|------|
| Architecture | `MainWindow` allégé (systray, refresh, exports) | 8/10 |
| Sécurité locale | Quarantaine AES-GCM, exclusions signées | 8/10 |
| UI / thèmes | Donaby clair/sombre + **contraste renforcé** | 8/10 |
| Réactivité | Navigation fade ; schtasks **async** | 7/10 |
| i18n | ~380 clés FR/EN ; services antivirus localisés | 8/10 |
| Tests | **65+** unitaires (dont headless, schtasks apply) | 7/10 |
| CI | GitHub Actions `dev` / `main` / `develop` | 8/10 |
| Release | Inno FR/EN, `AutoUpdateSignatures` lu au 1er lancement | 8/10 |

**Verdict** : produit **publiable** ; surveiller publish ClamAV/YARA et tests manuels installateur.

---

## Réalisé récemment

- Scan planifié : `Task.Run` / `ScheduledScanApply` (pas de gel UI).
- UAC : bandeau Accueil, message analyse complète, hint Options scan planifié.
- `AntivirusActions` : messages FR/EN ; confirmations suppression dans `AntivirusView`.
- Exports historique : `HistoryExportService` (hors `MainWindow`).
- Onboarding premier lancement (`OnboardingService`).
- Thème `Donaby.HighContrast.xaml`.
- Désinstalleur Inno : dialogue données utilisateur **bilingue**.
- `UserPreferences` : lecture registre Inno `AutoUpdateSignatures`.
- CI : branche `dev` incluse dans les pushes.

---

## Dettes restantes (priorisées)

| Priorité | Sujet |
|----------|--------|
| P2 | MVVM étendu (plus de ViewModels) |
| P2 | Tests intégration `schtasks` réel (mockés en unitaire seulement) |
| P2 | `async void` résiduel dans quelques handlers |
| P3 | Threat model / doc sécurité formelle |

---

## Tests automatisés

```powershell
dotnet test optiSCAN.Tests\optiSCAN.Tests.csproj -c Release
```

Couverture : quarantaine, SecureStore, navigation refresh, scan planifié (parse/apply), headless args, logs, chemins ClamAV.

---

## Validation manuelle

Voir [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md).

---

## Documents

| Document | Contenu |
|----------|---------|
| [BUILD.md](BUILD.md) | Publish, Inno, dépannage |
| [LOCALIZATION.md](LOCALIZATION.md) | FR/EN, `.resx` |
| [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md) | Avant chaque release |

*Les anciens audits détaillés UI couleurs / réactivité sont fusionnés dans ce document.*
