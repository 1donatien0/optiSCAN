# Checklist release — optiSCAN v7.0

À exécuter avant chaque publication (installateur Inno ou artefact CI).

## Build automatisé

```powershell
.\scripts\verify-runtime-deps.ps1
dotnet build optiSCAN.sln -c Release
dotnet test optiSCAN.Tests\optiSCAN.Tests.csproj -c Release
dotnet publish optiSCAN\optiSCAN.csproj -c Release -r win-x64 --self-contained true -o publish\win-x64
.\scripts\verify-runtime-deps.ps1 -PublishDir publish\win-x64
```

## Installation

- [ ] Installateur **FR** : UI et raccourcis cohérents
- [ ] Installateur **EN** : même contrôle sur une machine propre
- [ ] Icône **barre des tâches** et **systray** (build installé, pas seulement F5 Debug)
- [ ] Version affichée en sidebar = v7.0 / semver assembly

## Navigation & UI

- [ ] Accueil ↔ Antivirus ↔ Historique ×10 : fade + pas de freeze > 1 s
- [ ] Footer : scan en cours (spinner), MAJ signatures (icône refresh)
- [ ] Tooltip bouton thème : « mode clair » en sombre, « mode sombre » en clair
- [ ] Historique : filtres (menaces / recherche) et états vides

## Fonctionnel

- [ ] Scan rapide (F5) + fin de scan → toast **Ouvrir Antivirus**
- [ ] Menace RTP → toast avec quarantaine + **Ouvrir Antivirus**
- [ ] Nettoyer : **Analyser** ne parcourt que les cases cochées
- [ ] Options : scan planifié (schtasks) sans gel prolongé ; hint UAC visible
- [ ] Options : contraste renforcé bascule correctement
- [ ] Premier lancement : assistant de bienvenue (une fois)
- [ ] Bandeau UAC Accueil + relance administrateur si besoin
- [ ] Quarantaine : ajout, restauration, refus chemins sensibles

## Fichiers embarqués

- [ ] `clamav\x64` (clamscan, freshclam, bases)
- [ ] `yara64.exe` + règles YARA
- [ ] `optiSCAN.ico`, hero/shield PNG si utilisés dans l’UI
