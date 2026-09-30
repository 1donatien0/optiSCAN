# Documentation optiSCAN

**Guide unique** : [README.md](../README.md) à la racine (architecture, release §8, audit §12).

| Sujet | Section README |
|-------|----------------|
| Build, publish, Inno, CI, SBOM, checklist | [§8](../README.md#8-publication-installateur-et-checklist-release-v10) |
| Installateur léger : prérequis .NET 10 Desktop + Windows App Runtime 1.8 (téléchargés si absents) | [§8 Étape A](../README.md#étapes-manuelles-détaillées) · [GUIDE_DISTRIBUTION.md](GUIDE_DISTRIBUTION.md) §3 |
| Coordinateurs UI (`optiSCAN.Application/Coordinators/`, `optiSCAN.WinUI/Services/WinUi*`) | [§1](../README.md#structure-des-modules) · [§12.1](../README.md#121-maintenabilité-et-choix-volontaires-non-bloquants) |
| DI préférences (`IUserPreferencesAccessor`, …) | [§1](../README.md#structure-des-modules) |
| FR / EN (839 clés) | [§9](../README.md#9-langues-de-linterface-fr-fr--en-us) |
| Historique (`ActivityLogService`, 5 filtres) | [§4.9](../README.md#49-journaux-et-historique) |
| Accueil posture / recommandations | [§4.11](../README.md#411-accueil-dashboard) |
| Scan USB/SD | [§5](../README.md#5-services-avancés-modules-complémentaires) · `RemovableDriveScanService` |
| Thèmes, accent, contraste renforcé (`WinUiThemeManager`, `ThemeBrush`) | [§2.2](../README.md#22-winuithememanager) |
| Jetons de couleur, règle de contraste 4,5:1, styles partagés | [§2.3](../README.md#23-tokens-de-couleur-disponibles) |
| Audit visuel WinUI (thèmes, espacements, contrastes) | [audit-visuel-winui.md](audit-visuel-winui.md) |
| Évolution de la branche `win` (étude, octobre 2026) | [ETUDE_PROSPECTIVE_BRANCHE_WIN.md](ETUDE_PROSPECTIVE_BRANCHE_WIN.md) |
| Panneau Antivirus | [§4.3](../README.md#43-panneau-antivirus) |
| Exclusions / anti-autophagie (`OptiscanProtectedPaths`) | [§4.7](../README.md#47-système-dexclusions) |
| Mode complémentaire Windows Defender | [§5](../README.md#defendercoexistenceservice--mode-complémentaire-windows-defender) |
| Exclusions Windows Defender (auto, au démarrage) | [§4.7](../README.md#47-système-dexclusions) · [§7](../README.md#exclusion-windows-defender) · `scripts/add-defender-exclusions.ps1` |
| Audit, tests (**383**) | [§12](../README.md#12-audit-et-qualité) |
| Posture /100 de l’édition WinUI | [§13](../README.md#13-sécurité-de-lédition-winui) |
| Branches `main` / `dev` | [Branches Git](../README.md#branches-git) |

| Débogage Visual Studio (F5, projet de démarrage) | [DEBUG_VS.md](DEBUG_VS.md) |
| Distribution, cohabitation antivirus | [GUIDE_DISTRIBUTION.md](GUIDE_DISTRIBUTION.md) |
| Signature de code (exe, installeur, AMSI, pilote) | [SIGNATURE_PROCEDURE.md](SIGNATURE_PROCEDURE.md) |
| Vie privée / RGPD | [POLITIQUE_CONFIDENTIALITE.md](POLITIQUE_CONFIDENTIALITE.md) · [CONFORMITE_RGPD.md](CONFORMITE_RGPD.md) |

**Version** : release **v1.0**, assembly **1.0.0**. Scripts : `scripts/` (dont `add-defender-exclusions.ps1`, `generate-sbom.ps1`), `installer/`, `.github/workflows/`.
