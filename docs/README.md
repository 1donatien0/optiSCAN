# Documentation optiSCAN

**Guide produit** : [README.md](../README.md) à la racine (architecture, release §8, audit §12).

**Version** : release **v9.0**, assembly **9.0.1**. Scripts : `scripts/` · Installeur : `installer/` · CI : `.github/workflows/`.

---

## Documents de ce dossier

| Document | Rôle |
|----------|------|
| [GUIDE_DISTRIBUTION.md](GUIDE_DISTRIBUTION.md) | Signature, .NET auto, Embed CVD/YARA, publish / Inno, checklist |
| [DIAGNOSTIC_INTEGRATION_WINDOWS.md](DIAGNOSTIC_INTEGRATION_WINDOWS.md) | Friction SmartScreen / AV ; profil install allégé façon v8 (2 moteurs) |
| [POLITIQUE_CONFIDENTIALITE.md](POLITIQUE_CONFIDENTIALITE.md) | Politique de confidentialité utilisateur (v9.0) |
| [CONFORMITE_RGPD.md](CONFORMITE_RGPD.md) | Analyse traitements / RGPD (note interne, pas un avis juridique) |
| [README.md](README.md) | Cet index |

## Documents à la racine / annexes

| Document | Rôle |
|----------|------|
| [../README.md](../README.md) | Guide unique (architecture, modules, release, langues, sécurité) |
| [../SECURITY.md](../SECURITY.md) | Politique de sécurité, signalement, composants v9 |
| [../LICENSE.txt](../LICENSE.txt) | CLUF v9.0 |
| [../Audit.md](../Audit.md) | Audit statique v9.0 (sécurité, qualité, RGPD, CI) |
| [../installer/redist/LISEZMOI.md](../installer/redist/LISEZMOI.md) | Runtime .NET 8 embarqué optionnel dans l'installeur |

---

## Renvois rapides vers le README

| Sujet | Section README |
|-------|----------------|
| Build, publish, Inno, CI, SBOM, checklist | [§8](../README.md#8-publication-installateur-et-checklist-release-v90) |
| Coordinateurs UI (`optiSCAN/Coordinators/`) | [§1](../README.md#structure-des-modules) · [§12.1](../README.md#121-maintenabilité-et-choix-volontaires-non-bloquants-v9) |
| DI préférences (`IUserPreferencesAccessor`, …) | [§1](../README.md#structure-des-modules) |
| FR / EN | [§9](../README.md#9-langues-de-linterface-fr-fr--en-us) |
| Historique (`ActivityLogService`) | [§4.9](../README.md#49-journaux-et-historique) |
| Accueil stats / recommandations | [§4.11](../README.md#411-vue-densemble-dashboard) |
| Scan USB/SD | [§5](../README.md#5-services-avancés-modules-complémentaires) · `RemovableDriveScanService` |
| Thème Windows | [§2.2](../README.md#22-thememanager) |
| Exclusions / anti-autophagie (`OptiscanProtectedPaths`) | [§4.7](../README.md#47-système-dexclusions) |
| Exclusions Windows Defender | [§4.7](../README.md#47-système-dexclusions) · [§7](../README.md#exclusion-windows-defender) · `scripts/add-defender-exclusions.ps1` |
| Audit, tests | [§12](../README.md#12-audit-et-qualité) |
| Posture /100, AMSI | [§13](../README.md#13-sécurité-posture-et-menaces) |
| Branches `main` / `dev` | [Branches Git](../README.md#branches-git) |

**Distribution** : détails opérationnels dans [GUIDE_DISTRIBUTION.md](GUIDE_DISTRIBUTION.md) (complète le §8 du README).
