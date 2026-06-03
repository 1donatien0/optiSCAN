# Publication optiSCAN v8.0 — calendrier J-10

> **Date cible** : dans **10 jours** · **Version** : 8.0.0 (`Directory.Build.props`) · **Branche** : `dev` → merge → `main` → artefacts CI / installateur.

## Prérequis machine de build

- Windows 10/11 x64, .NET 8 SDK, Inno Setup 6
- Réseau (téléchargement ClamAV, YARA, signatures freshclam)
- Binaires **non versionnés** dans Git : `.\scripts\fetch-runtime-deps.ps1`

## Chaîne automatique (recommandée)

```powershell
# Depuis la racine du dépôt
.\scripts\prepare-release-v8.ps1
```

Équivalent manuel : `clean-before-publish` → `fetch-runtime-deps -RunFreshclam` → `dotnet test` → `dotnet publish` → `verify-runtime-deps` → `build-release-setup.ps1`.

## Calendrier suggéré

| Jour | Objectif | Actions |
|------|----------|---------|
| **J-10** | Gel fonctionnel | `dotnet test` Release (134 tests) ; plus de feature majeure ; `dev` à jour |
| **J-9** | Dépendances | `.\scripts\fetch-runtime-deps.ps1` ; vérifier `clamav\x64` + `yara\` + `rules\` |
| **J-8** | Publish local | `prepare-release-v8.ps1 -SkipFreshclam` puis avec `-RunFreshclam` une fois |
| **J-7** | VM propre | Installer `optiSCAN_Setup_v8.0.0.exe` sur VM sans SDK ; scan, RTP, clamd, posture, FR/EN |
| **J-6** | CI verte | Push `dev` ; corriger CI si échec publish (logs `verify-runtime-deps`) |
| **J-5** | Merge `main` | `git checkout main` → `git merge dev` → `git push origin main` → job **Publish win-x64** |
| **J-4** | Artefacts | Télécharger depuis Actions : `optiSCAN-setup-<sha>.exe` ; test identique à J-7 |
| **J-3** | Signature (opt.) | Authenticode `.pfx` — voir `installer/setup.iss.signing.example` |
| **J-2** | Communication | README §11, release GitHub, capture accueil posture /100 |
| **J-1** | Tag | `git tag v8.0.0` sur `main` ; notes de version |
| **J0** | Publication | Installateur sur SourceForge / site ; annonce |

## Checklist binaire (bloquant)

- [ ] `dotnet test` — **134** tests OK
- [ ] `.\scripts\verify-runtime-deps.ps1` — vert sur dossier publish
- [ ] `clamscan.exe`, `freshclam.exe`, **`clamd.exe`**, `yara64.exe`, règles `.yar`
- [ ] `clamav\database\` — au moins un `main.cvd` / `daily.cvd` (via freshclam)
- [ ] Installateur FR/EN, sidebar **v8.0**, options clamd / VT / mode jeu
- [ ] Test post-install : scan fichier, quarantaine, historique, exports PDF/HTML

## CI GitHub (`main` uniquement)

1. `fetch-runtime-deps.ps1`
2. `fetch-runtime-deps.ps1 -RunFreshclam` (timeout 45 min)
3. `dotnet publish` → `verify-runtime-deps.ps1`
4. Inno Setup → artefact `optiSCAN_Setup_v8.0.0.exe`

Sur **`dev`** : build + tests + artefact binaire Release (sans installateur complet).

## Après publication

- Conserver `main` et `dev` alignées (même tip après merge release)
- Dettes documentées (non bloquantes v8) : `scan_history.json` clair, signtool optionnel, EDR/VSS hors périmètre v8

## Liens

- Guide complet : [README.md](../README.md) §8
- Branches : [README.md § Branches Git](../README.md#branches-git)
