# Fournisseur AMSI — optiSCAN

Licence : GPL-3.0-or-later.

`optiSCAN.AmsiProvider.dll` est livré avec le service de protection (3.1). Windows le charge dans les processus qui exécutent des scripts ou du contenu dynamique (PowerShell, hôte de scripts JScript/VBScript, macros Office, chargement d'assemblages .NET) et lui soumet ce contenu avant exécution.

## Fonctionnement

1. Le fournisseur lit au plus 512 Kio du contenu et le nom de l'application.
2. Il vérifie que le serveur du tube `\\.\pipe\optiSCAN_Protection` est bien l'hôte du service : session 0, image `optiSCAN.Host.exe` ou `optiSCAN.Service.exe`, processus du service `optiSCANProtection` ou enfant direct créé après lui.
3. Il envoie `scan_buffer` ; l'hôte copie le contenu dans `scan-staging` et l'analyse avec ClamAV et YARA dans leur AppContainer. Les résultats sont gardés 10 minutes par empreinte SHA-256.
4. Menace : `AMSI_RESULT_DETECTED` ; Windows bloque l'exécution.

**Fail-open** : service arrêté, tube absent, délai dépassé (250 ms de connexion, 3 s d'analyse), limite de débit atteinte ou erreur : le contenu passe. Le fournisseur ne doit jamais bloquer une application à cause d'un défaut d'optiSCAN. Aucune exception C++ ne sort d'une méthode COM.

## Compilation et livraison

- `scripts/build-amsi.ps1` (Visual Studio 2022, outils C++ v143, x64) ; `-Require` en CI et en release.
- `scripts/stage-amsi.ps1` copie la DLL dans le dossier publié ; l'installeur l'enregistre (`regserver`) avec la tâche « service de protection » et la retire à la désinstallation.
- CRT statique (`/MT`), CFG et CET activés, avertissements traités en erreurs.
- Signée par SignPath avec les autres binaires (`.signpath/artifact-configurations/binaries.xml`). Windows peut exiger une signature Authenticode des fournisseurs (`HKLM\SOFTWARE\Microsoft\AMSI\FeatureBits` = 0x2) ; par défaut la vérification est désactivée.

## Tests

- `AmsiScanBufferTests` : côté service (désactivé par défaut, détection, cache, tailles, noms de copie).
- `AmsiProviderNativeTests` : charge la DLL compilée par la fabrique COM, vérifie le nom affiché, l'analyse d'un flux et le fail-open sans service.
