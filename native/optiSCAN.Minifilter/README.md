# optiSCAN Minifilter (v1.0 — stub)

Driver noyau `optiSCAN.Minifilter.sys` pour interception des accès fichiers **avant** exécution.

## État v1.0

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

```powershell
copy native\optiSCAN.Minifilter\x64\optiSCAN.Minifilter.sys %SystemRoot%\System32\drivers\
fltmc load optiSCANMinifilter
```

Le service `optiSCAN.Service` tente le chargement via `PlatformRegistration.TryLoadMinifilter()`.

## Interface

Port de communication : `\optiSCANMinifilter` (à implémenter dans le driver complet).
