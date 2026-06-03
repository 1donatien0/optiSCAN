# Checklist publication optiSCAN v8.0

> **Version** : 8.0.0 (`Directory.Build.props`) · **Branche** : `dev` → merge → `main` → artefacts CI / installateur (usage équipe).

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

## Ordre recommandé

1. Gel fonctionnel : `dotnet test` Release (134 tests).
2. Dépendances : `.\scripts\fetch-runtime-deps.ps1` (+ `-RunFreshclam` pour l’installateur).
3. Publish local : `.\scripts\prepare-release-v8.ps1`.
4. VM propre : installer `optiSCAN_Setup_v8.0.0.exe` ; scan, RTP, clamd, posture, FR/EN.
5. CI : push `main` → job **Publish win-x64** ; artefact `optiSCAN-setup-<sha>.exe`.
6. Signature (opt.) : Authenticode — `installer/setup.iss.signing.example`.
7. Tag / distribution : `git tag v8.0.0`, release GitHub, SourceForge ou site.

## Checklist binaire (bloquant)

- [ ] `dotnet test` — **134** tests OK
- [ ] `.\scripts\verify-runtime-deps.ps1` — vert sur dossier publish
- [ ] `clamscan.exe`, `freshclam.exe`, **`clamd.exe`**, `yara64.exe`, règles `.yar`
- [ ] `clamav\database\` — au moins un `main.cvd` / `daily.cvd` (via freshclam)
- [ ] Installateur FR/EN, sidebar **v8.0**, options clamd / VT / mode jeu
- [ ] Test post-install : scan fichier, quarantaine, historique, exports PDF/HTML

## CI GitHub (`main` uniquement)

1. `fetch-runtime-deps.ps1`
2. `fetch-runtime-deps.ps1 -RunFreshclam` (timeout 45 min) — génère un `freshclam.conf` minimal dans `clamav\x64\` (non versionné dans Git, comme en production via `FreshclamUpdater`)

**Erreur CI connue (corrigée)** : `Can't open/parse freshclam.conf` si freshclam est lancé sans `--config-file` — le dépôt n’embarque pas de `.conf` dans `clamav\x64\` (évite des chemins machine de dev).
3. `dotnet publish` → `verify-runtime-deps.ps1`
4. Inno Setup → artefact `optiSCAN_Setup_v8.0.0.exe`

Sur **`dev`** : build + tests + artefact binaire Release (sans installateur complet).

## Après publication

- Conserver `main` et `dev` alignées (même tip après merge release)
- Dettes documentées (non bloquantes v8) : `scan_history.json` clair, signtool optionnel, EDR/VSS hors périmètre v8

## Liens

- Guide complet : [README.md](../README.md) §8
- Branches : [README.md § Branches Git](../README.md#branches-git)
