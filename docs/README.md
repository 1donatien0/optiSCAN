# Documentation optiSCAN

Index de la documentation technique et release pour **optiSCAN v7.0** (build **7.0.0**).

| Document | Public | Contenu |
|----------|--------|---------|
| [../README.md](../README.md) | Développeurs, contributeurs | Architecture, ClamAV/YARA, panneaux, services |
| [AUDIT.md](AUDIT.md) | QA, release, direction | **Audit unique** synthétisé (v7.0, juin 2026) |
| [THREAT-MODEL.md](THREAT-MODEL.md) | Sécurité, release | Périmètre local v7 (synthèse) |
| [BUILD.md](BUILD.md) | Release, packaging | Publish, nettoyage, Inno Setup, dépannage |
| [LOCALIZATION.md](LOCALIZATION.md) | Traducteurs, dev UI | FR/EN, `.resx`, périmètre i18n |
| [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md) | Release | Checklist manuelle avant installateur |

## Fichiers associés (hors Markdown)

| Chemin | Rôle |
|--------|------|
| [../installer/setup.iss](../installer/setup.iss) | Installateur Inno (FR + EN) |
| [../installer/build-release-setup.ps1](../installer/build-release-setup.ps1) | clean + publish + ISCC |
| [../scripts/verify-runtime-deps.ps1](../scripts/verify-runtime-deps.ps1) | Vérifie ClamAV + YARA dans publish |
| [../scripts/clean-before-publish.ps1](../scripts/clean-before-publish.ps1) | Nettoyage bin/obj avant release |
| [../.github/workflows/ci.yml](../.github/workflows/ci.yml) | CI : build, tests, artefact publish |

## Commandes rapides

```powershell
# Depuis la racine du dépôt
dotnet build optiSCAN.sln -c Release
dotnet test optiSCAN.Tests\optiSCAN.Tests.csproj -c Release
.\scripts\verify-runtime-deps.ps1
```

Voir [BUILD.md](BUILD.md) pour la chaîne complète jusqu’à `optiSCAN_Setup_v7.0.0.exe`.
