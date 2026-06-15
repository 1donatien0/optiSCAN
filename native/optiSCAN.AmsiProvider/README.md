# optiSCAN AMSI Provider (v8)

Fournisseur AMSI natif (`optiSCAN.AmsiProvider.dll`) qui transmet les buffers script
à `optiSCAN.exe --service-host` via le pipe `\\.\pipe\optiSCAN_Protection_v8`.

## Build (Visual Studio 2022)

1. Ouvrir `native\optiSCAN.AmsiProvider\optiSCAN.AmsiProvider.vcxproj`
2. Configuration **Release | x64**
3. Copier la DLL vers le dossier publish à côté de `optiSCAN.exe`

## Enregistrement

Effectué automatiquement par `PlatformRegistration.TryRegisterAmsiProvider()` au démarrage
du service (nécessite droits administrateur).

Clé : `HKLM\SOFTWARE\Microsoft\AMSI\Providers\{A8F4E2B1-9C3D-4E5F-8A7B-1C2D3E4F5A6B}`

## Limites

- Coexistence avec Defender : un seul fournisseur AMSI « actif » par processus hôte selon la politique Windows.
- Signature Authenticode recommandée pour la DLL en production.
