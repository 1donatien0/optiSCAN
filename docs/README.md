# Documentation optiSCAN

**Guide unique** : [README.md](../README.md) à la racine (architecture, release §8, audit §12).

| Sujet | Section README |
|-------|----------------|
| Build, publish, Inno, CI, SBOM, checklist | [§8](../README.md#8-publication-installateur-et-checklist-release-v80) |
| Coordinateurs UI (`optiSCAN/Coordinators/`) | [§1](../README.md#structure-des-modules) · [§12.1](../README.md#121-maintenabilité-et-choix-volontaires-non-bloquants-v8) |
| DI préférences (`IUserPreferencesAccessor`, …) | [§1](../README.md#structure-des-modules) |
| FR / EN (621 clés) | [§9](../README.md#9-langues-de-linterface-fr-fr--en-us) |
| Historique (`ActivityLogService`, 5 filtres) | [§4.9](../README.md#49-journaux-et-historique) |
| Accueil stats / recommandations | [§4.11](../README.md#411-vue-densemble-dashboard) |
| Scan USB/SD | [§5](../README.md#5-services-avancés-modules-complémentaires) · `RemovableDriveScanService` |
| Thème Windows | [§2.2](../README.md#22-thememanager) |
| Exclusions / anti-autophagie (`OptiscanProtectedPaths`) | [§4.7](../README.md#47-système-dexclusions) |
| Exclusions Windows Defender (auto) | [§4.7](../README.md#47-système-dexclusions) · [§7](../README.md#exclusion-windows-defender) · `scripts/add-defender-exclusions.ps1` |
| Audit, tests (**289**) | [§12](../README.md#12-audit-et-qualité) |
| Posture /100, AMSI | [§13](../README.md#13-sécurité-posture-et-menaces) |
| Branches `main` / `dev` | [Branches Git](../README.md#branches-git) |

**Version** : release **v8.0**, assembly **8.0.0**. Scripts : `scripts/` (dont `add-defender-exclusions.ps1`, `generate-sbom.ps1`), `installer/`, `.github/workflows/`.
