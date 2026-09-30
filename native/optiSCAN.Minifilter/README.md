# optiSCAN Minifilter (v1.0 — stub)

Driver noyau `optiSCAN.Minifilter.sys` pour interception des accès fichiers **avant** exécution.

## État v1.0

Le service tente `PlatformRegistration.TryLoadMinifilter()` (copie vers `System32\drivers`, `pnputil` si un catalogue signé `.cat` accompagne l'INF, création du service noyau et de son instance si besoin, puis `fltmc load`). Sur Windows x64, un `.sys` non signé **est refusé** : c'est attendu jusqu'à SignPath. Ne pas activer le test signing sur les machines utilisateurs.

Le dépôt fournit :

- `filter.c` — squelette `DriverEntry` / `FltRegisterFilter` (compilation avec `OPTISCAN_MINIFILTER_BUILD`)
- `optiSCAN.Minifilter.inf` — métadonnées d'installation
- `MinifilterUserBridge.cs` — pont user-mode côté C#
- Documentation WDK pour compilation hors CI

## Prérequis production

- Windows Driver Kit (WDK) 10
- Certificat **EV** pour signature du driver (Microsoft attestation)
- Mode test (`bcdedit /set testsigning on`) pour développement uniquement

## Installation (dev / test signing)

`fltmc load` exige un service noyau `optiSCANMinifilter` et sa clé `Instances` (instance par défaut + altitude). L'INF les déclare (`DefaultInstall.NTamd64`) ; l'installeur et `PlatformRegistration` les créent eux-mêmes s'ils manquent.

```powershell
# Invite administrateur
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall.NTamd64 132 native\optiSCAN.Minifilter\optiSCAN.Minifilter.inf
fltmc load optiSCANMinifilter
fltmc filters   # optiSCANMinifilter doit apparaître (altitude 385210)
```

Désinstallation : `fltmc unload optiSCANMinifilter` puis `sc delete optiSCANMinifilter`.

## Altitude

`385210` est **provisoire** (plage *FSFilter Activity Monitor* 360000–389999). Avant toute distribution signée, demander une altitude à Microsoft et la reporter à trois endroits : `optiSCAN.Minifilter.inf` (`Instance1.Altitude`), `PlatformRegistration.MinifilterAltitude` et `installer/setup.iss`. Le test `MinifilterRegistrationConsistencyTests` vérifie que les trois concordent.

Le service `optiSCAN.Service` tente le chargement via `PlatformRegistration.TryLoadMinifilter()`.

## Interface

Port de communication : `\optiSCANMinifilter` (à implémenter dans le driver complet).
