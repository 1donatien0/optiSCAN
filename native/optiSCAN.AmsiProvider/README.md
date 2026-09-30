# optiSCAN AMSI Provider

Fournisseur AMSI natif (`optiSCAN.AmsiProvider.dll`) qui transmet les buffers script
à `optiSCAN.exe --service-host` via le pipe `\\.\pipe\optiSCAN_Protection`.

Le nom du pipe et la version du protocole IPC sont définis dans
`protection_identifiers.h`, miroir de `optiSCAN.Platform/ProtectionIdentifiers.cs`
(cohérence vérifiée par les tests unitaires). Ne pas y mettre de version produit.

## Build (Visual Studio 2022)

1. Ouvrir `native\optiSCAN.AmsiProvider\optiSCAN.AmsiProvider.vcxproj`
2. Configuration **Release | x64**
3. Copier la DLL vers le dossier publish à côté de `optiSCAN.exe`

## Enregistrement

Effectué par `PlatformRegistration.TryRegisterAmsiProvider()` au démarrage du
service plateforme (`--service-host` / `optiSCAN.Service`), si la protection
système est activée dans les Options (nécessite droits administrateur).

Désactivé par `TryUnregisterAmsiProvider()` quand la protection plateforme est
coupée : la DLL peut rester dans le dossier d'installation sans être chargée.

Clé : `HKLM\SOFTWARE\Microsoft\AMSI\Providers\{A8F4E2B1-9C3D-4E5F-8A7B-1C2D3E4F5A6B}`

## Limites

- Coexistence avec Defender : un seul fournisseur AMSI « actif » par processus hôte selon la politique Windows.
- Signature Authenticode recommandée pour la DLL en production.
