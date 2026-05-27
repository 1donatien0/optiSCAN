# Publication et installateur — optiSCAN v6.0

Guide opérationnel pour produire `optiSCAN_Setup_v6.0.0.exe` (ou la version courante dans `Directory.Build.props` / `installer/setup.iss`).

## Prérequis

| Outil | Rôle |
|-------|------|
| [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) | `dotnet publish` |
| [.NET 8 Desktop Runtime](https://dotnet.microsoft.com/download/dotnet/8.0) | Cible utilisateur (vérifié par l’installateur) |
| [Inno Setup 6](https://jrsoftware.org/isinfo.php) | `ISCC.exe` → `installer\output\` |
| Binaires **ClamAV** + **YARA** | Sous `optiSCAN\clamav\` et `optiSCAN\yara\` (non versionnés dans git) |

Vérifier les dépendances runtime avant publish :

```powershell
.\scripts\verify-runtime-deps.ps1
```

## Nettoyage avant compilation

Le script `scripts\clean-before-publish.ps1` arrête les processus qui verrouillent `optiSCAN.exe`, supprime les dossiers `bin` / `obj` Release, les sorties de tests et (optionnellement) l’obj ou les anciens installateurs.

```powershell
# Depuis la racine du dépôt
.\scripts\clean-before-publish.ps1

# Supprimer aussi obj\ et les .exe dans installer\output\
.\scripts\clean-before-publish.ps1 -IncludeObj -IncludeInstallerOutput

# Nettoyage Debug en plus
.\scripts\clean-before-publish.ps1 -Configuration Debug -IncludeObj
```

**Conseil :** fermer Visual Studio avant publish pour éviter que `.vs` ou `bin` se recréent et verrouillent des fichiers.

## Publication manuelle (étapes séparées)

```powershell
cd <racine-du-dépôt>

.\scripts\clean-before-publish.ps1 -IncludeObj

dotnet publish .\optiSCAN\optiSCAN.csproj -c Release /p:PublishProfile=FolderProfile
```

Sortie attendue :

```
optiSCAN\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64\
    optiSCAN.exe
    clamav\ ...
    yara\ ...
    rules\ ...
```

**Première base ClamAV** (optionnel si la base n’est pas déjà dans `clamav\database`) :

```powershell
$pub = ".\optiSCAN\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64"
& "$pub\clamav\x64\freshclam.exe" --datadir="$pub\clamav\x64\database"
```

**Compilateur Inno Setup :**

```powershell
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" .\installer\setup.iss
```

Installateur généré : `installer\output\optiSCAN_Setup_v6.0.0.exe`.

## Variante tout-en-un

```powershell
.\installer\build-release-setup.ps1
```

Enchaîne : `clean-before-publish.ps1` → `dotnet publish` (profil **FolderProfile**) → `ISCC.exe`.

Publish déjà fait :

```powershell
.\installer\build-release-setup.ps1 -SkipPublish
```

## Tests unitaires (avant release)

```powershell
dotnet test .\optiSCAN.Tests\optiSCAN.Tests.csproj -c Release
```

## Dépannage Inno

| Erreur | Cause fréquente |
|--------|------------------|
| `optiSCAN.exe introuvable` | Publish non exécuté ou mauvais dossier (`publish\win-x64\` requis) |
| Fichier verrouillé | `optiSCAN.exe` ou antivirus en cours — relancer `clean-before-publish.ps1` |
| Compile aborted (LZMA) | Antivirus sur `installer\output` — réessayer ou exclure temporairement |

`setup.iss` détecte automatiquement `publish\win-x64\` puis `publish\` à la racine du TFM.

## Fichiers ignorés par git (ne pas committer)

- `bin/`, `obj/`, `.vs/`
- `installer/output/*.exe`
- Logs `*.log`

Voir `.gitignore` à la racine.
