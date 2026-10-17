# Documentation optiSCAN

**Présentation** : [README.md](../README.md) à la racine (captures, téléchargement).
**Guide produit** : [GUIDE.md](GUIDE.md) (architecture, release §8, audit §12).

**Version visée** : candidate **v3.1**, assembly **3.1.0** ; non publiée. Scripts : `scripts/` · Installeur : `installer/` · CI : `.github/workflows/`.

---

## Documents de ce dossier

| Document | Rôle |
|----------|------|
| [GUIDE_DISTRIBUTION.md](GUIDE_DISTRIBUTION.md) | Signature, modes runtime .NET, Embed CVD/YARA, publish / Inno, checklist |
| [SIGNATURE_PROCEDURE.md](SIGNATURE_PROCEDURE.md) | Procédure de signature SignPath (seule chaîne) |
| [../ROADMAP.md](../ROADMAP.md) | Feuille de route produit de l’antivirus après la v3.1 |
| [../RELEASE_PLAN_v3.1.md](../RELEASE_PLAN_v3.1.md) | Étapes et critères de validation de la candidate v3.1 |
| [DIAGNOSTIC_INTEGRATION_WINDOWS.md](DIAGNOSTIC_INTEGRATION_WINDOWS.md) | Diagnostic historique de distribution Windows ; profil allégé façon version 2 (2 moteurs) |
| [POLITIQUE_CONFIDENTIALITE.md](POLITIQUE_CONFIDENTIALITE.md) | Politique de confidentialité utilisateur (candidate v3.1) |
| [CONFORMITE_RGPD.md](CONFORMITE_RGPD.md) | Analyse traitements / RGPD (note interne, pas un avis juridique) |
| [GUIDE.md](GUIDE.md) | Guide unique (architecture, modules, release, langues, sécurité) |
| [README.md](README.md) | Cet index |

## Documents à la racine / annexes

| Document | Rôle |
|----------|------|
| [../README.md](../README.md) | Présentation du projet (anglais), captures, téléchargement |
| [../SECURITY.md](../SECURITY.md) | Politique de sécurité, signalement, composants v3.1 candidate |
| [../LICENSE.txt](../LICENSE.txt) | Licence GNU GPL v3 |
| [CODE_SIGNING_POLICY.md](CODE_SIGNING_POLICY.md) | Politique de signature du code (SignPath) |
| [../AUDIT_optiSCAN_360.md](../AUDIT_optiSCAN_360.md) | Audit 360, révision du 15 octobre 2026 au soir (7,6/10 ; 8,0 exigé pour publier) : note, décision de release, registre des risques ouverts |
| [archive/AUDIT_optiSCAN_360_journal_2026-10.md](archive/AUDIT_optiSCAN_360_journal_2026-10.md) | Journal des audits du 2 au 13 octobre 2026 (séries N à D, traitement détaillé) |
| [archive/README_SOURCEFORGE_v3.0.md](archive/README_SOURCEFORGE_v3.0.md) | Guide de la v3.0 publié sur SourceForge, mis à jour pour sa republication sous GPL v3 |
| [../installer/redist/LISEZMOI.md](../installer/redist/LISEZMOI.md) | Modes runtime .NET et limite actuelle du dossier redist |

---

## Renvois rapides vers le guide

| Sujet | Section du guide |
|-------|----------------|
| Build, publish, Inno, CI, SBOM, checklist | [§8](GUIDE.md#8-publication-installateur-et-checklist-release-v31-candidate) |
| Coordinateurs UI (`optiSCAN/Coordinators/`) | [§1](GUIDE.md#structure-des-modules) · [§12.1](GUIDE.md#121-maintenabilité-et-choix-volontaires-non-bloquants-v30) |
| DI préférences (`IUserPreferencesAccessor`, …) | [§1](GUIDE.md#structure-des-modules) |
| FR / EN | [§9](GUIDE.md#9-langues-de-linterface-fr-fr--en-us) |
| Historique (`ActivityLogService`) | [§4.9](GUIDE.md#49-journaux-et-historique) |
| Accueil stats / recommandations | [§4.11](GUIDE.md#411-vue-densemble-dashboard) |
| Scan USB/SD | [§5](GUIDE.md#5-services-avancés-modules-complémentaires) · `RemovableDriveScanService` |
| Thème Windows | [§2.2](GUIDE.md#22-thememanager) |
| Exclusions / anti-autophagie (`OptiscanProtectedPaths`) | [§4.7](GUIDE.md#47-système-dexclusions) |
| Exclusions Windows Defender | [§4.7](GUIDE.md#47-système-dexclusions) · [§7](GUIDE.md#exclusion-windows-defender) · `scripts/add-defender-exclusions.ps1` |
| Audit, tests | [§12](GUIDE.md#12-audit-et-qualité) |
| Posture /100, AMSI | [§13](GUIDE.md#13-sécurité-posture-et-menaces) |
| Branches `main` / `dev` | [Branches Git](GUIDE.md#branches-git) |

**Distribution** : détails opérationnels dans [GUIDE_DISTRIBUTION.md](GUIDE_DISTRIBUTION.md) (complète le §8 du guide).
