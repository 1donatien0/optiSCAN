# Audit débogage Visual Studio — optiSCAN.WinUI

> **Date** : 2026-07-06 · **Cible** : Visual Studio 2026 (18.x) · **Projet** : `optiSCAN.WinUI` (WinUI 3, non packagé)

## Symptômes rapportés

| Symptôme | Cause probable |
|---|---|
| *« A project with an Output Type of Class Library cannot be started directly »* | Projet de démarrage = `optiSCAN.Application` ou `optiSCAN.IPC` (DLL) |
| F5 ne lance rien / mauvais exécutable | Cache `.vs\` + profil `slnLaunch` non sélectionné |
| Build OK mais debug incohérent | Double sortie `bin\Debug\` vs `bin\x64\Debug\` selon plateforme solution |

## Architecture (rappel)

| Projet | OutputType | F5 direct ? |
|---|---|---|
| **optiSCAN.WinUI** | `WinExe` → `optiSCAN.exe` | **Oui — seul projet UI** |
| optiSCAN.Application | `Library` | Non |
| optiSCAN.IPC | `Library` | Non |
| optiSCAN.Service | `Exe` (service Windows) | Non (console service, pas l’UI) |
| optiSCAN.Tests | Test | Via Test Explorer uniquement |

## Problèmes identifiés et corrections

### 1. Plateforme solution « Any CPU » absente

Visual Studio ouvre presque toujours avec **Debug \| Any CPU**. La solution avait supprimé cette config → VS tombait sur un mauvais mapping ou conservait un cache `.suo` invalide.

**Correction** : rétablir `Debug|Any CPU` dans `optiSCAN.sln` et mapper **WinUI** :

```
Debug|Any CPU  →  projet Debug|x64
Debug|x64      →  projet Debug|x64
```

Les bibliothèques restent en `Any CPU`.

### 2. Ordre des projets dans la solution

`optiSCAN.Application` était listé **avant** WinUI dans l’ancienne solution → VS proposait souvent Application comme démarrage par défaut.

**Correction** : `optiSCAN.WinUI` en **premier** dans `optiSCAN.sln`.

### 3. Profil de lancement partagé (`optiSCAN.slnLaunch`)

Fichier à la racine, référencé par `optiSCAN.sln` (*Solution Items*) — **il doit être commité** : sans lui, un clone neuf n'a pas le profil. VS ne l’applique **pas automatiquement** au premier F5 — il faut le sélectionner une fois dans la liste à côté du bouton ▶.

**Correction** : profil `optiSCAN (WinUI x64)` → démarre uniquement `optiSCAN.WinUI` avec `optiSCAN (Unpackaged)`.

### 4. `launchSettings.json`

Profil WinUI standard renommé en **`optiSCAN (Unpackaged)`** (`commandName: Project`) — convention Windows App SDK pour apps non MSIX.

### 5. GUID projet explicites

Les `.csproj` SDK n’avaient pas de `ProjectGuid` → risque de décalage avec `optiSCAN.sln` après migration.

**Correction** : `ProjectGuid` ajouté dans `optiSCAN.Application` (aligné sur la solution). Les autres projets SDK s'en passent : VS les résout par chemin depuis `optiSCAN.sln`.

### 6. Cache Visual Studio local (`.vs\`)

Le projet de démarrage est stocké dans `.vs\optiSCAN\v18\*.suo` (non versionné). Un ancien cache peut **ignorer** `slnLaunch` et relancer Application.

**Action manuelle requise** (une fois) :

1. Fermer Visual Studio
2. Supprimer le dossier `.vs` à la racine du dépôt
3. Rouvrir `optiSCAN.sln`

### 7. Double dossier de sortie Debug

Deux chemins coexistent après builds mixtes :

```
optiSCAN.WinUI\bin\x64\Debug\net10.0-windows10.0.19041.0\optiSCAN.exe   ← cible F5 (x64)
optiSCAN.WinUI\bin\Debug\net10.0-windows10.0.19041.0\optiSCAN.exe        ← ancien Any CPU
```

Le mapping solution **Any CPU → x64** pour WinUI unifie la sortie vers `bin\x64\Debug\...`.

## Procédure F5 (Visual Studio 2026)

1. Fermer VS, supprimer `.vs\` si le problème persiste
2. Ouvrir `optiSCAN.sln`
3. Accepter l’installation des composants si `.vsconfig` le propose (Windows App SDK, .NET 10)
4. Barre d’outils : **Debug** + **Any CPU** ou **x64** (les deux mappent WinUI en x64)
5. Liste à côté de ▶ : sélectionner **`optiSCAN (WinUI x64)`**
6. **F5**

Vérification manuelle si F5 échoue encore :

```
optiSCAN.WinUI\bin\x64\Debug\net10.0-windows10.0.19041.0\optiSCAN.exe
```

Clic droit sur **optiSCAN.WinUI** → **Définir comme projet de démarrage** si le profil `slnLaunch` n’apparaît pas.

## Prérequis VS 2026

Fichier `.vsconfig` à la racine :

- Workload **.NET desktop**
- **Windows App SDK** (WinUI 3)
- Windows 11 SDK (26100+)
- Test tools (optionnel)

**Windows App Runtime 1.8** installé sur le poste de dev : depuis le passage en publication
*framework-dependent*, `optiSCAN.WinUI.csproj` ne définit plus `WindowsAppSDKSelfContained` ; l'exe
de debug s'appuie donc sur le runtime installé (sinon message « This application requires the Windows
App Runtime » au lancement). Installeur : <https://aka.ms/windowsappsdk/1.8/latest/windowsappruntimeinstall-x64.exe>.

Sans le workload WinUI, le débogueur ne peut pas attacher correctement l’app unpackaged.

## Ligne de commande (référence)

```powershell
dotnet build .\optiSCAN.sln -c Debug -p:Platform=x64
dotnet run --project .\optiSCAN.WinUI\optiSCAN.WinUI.csproj -c Debug -p:Platform=x64
```

## Fichiers de configuration débogage

| Fichier | Rôle |
|---|---|
| `optiSCAN.sln` | Ordre projets, mapping plateformes |
| `optiSCAN.slnLaunch` | Profil de démarrage partagé (équipe) |
| `optiSCAN.WinUI/Properties/launchSettings.json` | Profil MSBuild `Project` |
| `.vsconfig` | Composants VS requis |
| `.vscode/launch.json` | Cursor / VS Code (x64) |
