# Langues de l’interface — optiSCAN v6.0

optiSCAN propose une interface **française (fr-FR)** et **anglaise (en-US)**. Les deux langues sont **embarquées dans l’exécutable** (pas de pack de langue à télécharger séparément, contrairement à Microsoft Defender).

## Pour l’utilisateur final

### Installation

L’installateur Inno Setup affiche un **choix de langue** (français / English) au début de l’assistant.

- **English** → au premier lancement, l’application démarre en **en-US**.
- **Français** → démarrage en **fr-FR**.

La langue est enregistrée dans :

- `HKCU\Software\optiSCAN\UiCulture` (`fr-FR` ou `en-US`)
- `%AppData%\optiSCAN\preferences.dat` (après le premier lancement)

### Changer la langue après installation

1. Ouvrir **Options** (raccourci `Ctrl+5`).
2. Section **GÉNÉRAL** → **Langue de l’interface** : *Français* ou *English*.
3. Confirmer le message → **optiSCAN redémarre** pour appliquer la langue partout.

Sans redémarrage, une partie des textes XAML ne se met pas à jour.

### Menu contextuel Windows (Explorateur)

Clic droit sur un fichier :

- FR : **Scanner avec optiSCAN**
- EN : **Scan with optiSCAN**

Le libellé suit la langue de l’application (installateur ou changement dans Options).

### Réinstallation

Si une copie précédente avait déjà enregistré **fr-FR** dans les préférences, une **réinstallation en anglais** peut laisser l’interface en français tant que l’utilisateur n’a pas changé la langue dans Options (la préférence utilisateur prime sur la langue de l’installateur).

## Pour les développeurs et traducteurs

### Fichiers de ressources

| Fichier | Culture |
|---------|---------|
| `optiSCAN/Resources/UiStrings.resx` | Français (défaut) |
| `optiSCAN/Resources/UiStrings.en.resx` | Anglais (en-US) |

Les clés doivent être **identiques** dans les deux fichiers.

### Code

| Composant | Rôle |
|-----------|------|
| `Localization/LocalizationService.cs` | Culture courante, `GetString`, `Format`, persistance, redémarrage |
| `Localization/LocExtension.cs` | `{loc:Loc Key=...}` en XAML |
| `Strings/OptiscanStrings.cs` | Messages récurrents (confirmations, statuts MAJ) |
| `Localization/ShellContextMenuSupport.cs` | Menu contextuel Explorateur selon la culture |

Initialisation : tout début de `App.OnStartup` → `LocalizationService.Initialize()`.

### Ajouter ou modifier un libellé

1. Ajouter la clé et la valeur FR dans `UiStrings.resx`.
2. Ajouter la **même clé** et la traduction EN dans `UiStrings.en.resx`.
3. Utiliser en XAML : `Text="{loc:Loc Key=Ma_Cle}"`  
   ou en C# : `LocalizationService.GetString("Ma_Cle")` / `Format("Ma_Cle", arg0, ...)`.

### Tests

```powershell
dotnet test .\optiSCAN.Tests\optiSCAN.Tests.csproj --filter Localization
```

Fichier : `optiSCAN.Tests/LocalizationServiceTests.cs`.

### Périmètre non traduit (volontaire ou technique)

- Sorties **ClamAV** / **freshclam** / **YARA** (logs techniques, souvent en anglais).
- Noms de menaces, chemins de fichiers, versions de bases.
- Contenu détaillé des **rapports PDF/HTML** exportés (principalement FR aujourd’hui).
- Marques produit : **ClamAV**, **YARA**, touches **F5**.

### Installateur

- Messages .NET 8 manquant : bilingues dans `installer/setup.iss` (`InitializeSetup`).
- `WriteInstallerUiCulture()` : écrit `UiCulture` en `ssPostInstall`.
- `RegisterExplorerContextMenu()` : enregistre le menu contextuel selon `ActiveLanguage`.
