# Langues de l’interface — optiSCAN v7.0

optiSCAN propose une interface **française (fr-FR)** et **anglaise (en-US)**. Les deux langues sont **embarquées dans l’exécutable** (pas de pack de langue séparé).

## Pour l’utilisateur final

### Installation

L’installateur Inno Setup affiche un **choix de langue** (français / English) au début de l’assistant.

- **English** → au premier lancement, l’application démarre en **en-US** (si aucune préférence existante).
- **Français** → démarrage en **fr-FR**.

La langue est enregistrée dans :

- `HKCU\Software\optiSCAN\UiCulture` (`fr-FR` ou `en-US`)
- `%AppData%\optiSCAN\preferences.dat` (après le premier lancement)

### Changer la langue après installation

1. Ouvrir **Options** (`Ctrl+5`).
2. Section **GÉNÉRAL** → **Langue de l’interface** : *Français* ou *English*.
3. Confirmer → **optiSCAN redémarre** pour appliquer la langue partout.

Sans redémarrage, une partie des textes XAML ne se met pas à jour.

### Menu contextuel Windows (Explorateur)

- FR : **Scanner avec optiSCAN**
- EN : **Scan with optiSCAN**

### Réinstallation

Si une copie précédente avait déjà enregistré **fr-FR**, une réinstallation en anglais peut laisser l’interface en français tant que l’utilisateur n’a pas changé la langue dans Options.

### Premier lancement

Parcours **3 étapes** (`OnboardingService`) : accueil → proposition MAJ signatures → rappel analyse rapide (F5).

### Voix éditoriale (v7)

| Zone | Ton | Exemple |
|------|-----|---------|
| **Accueil** | Calme, rassurant | « Votre ordinateur est protégé » + dernière analyse uniquement sous le hero |
| **Cartes / sections** | Title Case, pas de MAJUSCULES criardes | « Nettoyer », « Antivirus » |
| **Options** | Technique mais clair | RTP, planification, UAC |
| **Logs Clean / moteurs** | Brut, monospace (Consolas) | `=== ANALYSE EN COURS ===` |
| **Exports PDF/HTML** | Neutre pro | Segoe UI, clés `Export_*` |

- **FR** : vouvoiement ; préférer *analyse* à *scan* dans l’UI.
- **EN** : *scan* / *analysis* selon le contexte utilisateur.

---

## Pour les développeurs et traducteurs

### Fichiers de ressources

| Fichier | Culture |
|---------|---------|
| `optiSCAN/Resources/UiStrings.resx` | Français (défaut) |
| `optiSCAN/Resources/UiStrings.en.resx` | Anglais (en-US) |

Les clés doivent être **identiques** dans les deux fichiers (parité FR/EN obligatoire).

Volume indicatif : **~530 clés** (juin 2026).

### Préfixes de clés (convention)

| Préfixe | Usage |
|---------|--------|
| `Overview_`, `Av_`, `Hist_`, `Clean_`, `Opt_` | Panneaux principaux (`Overview_` : hero + dernière analyse + carte État de protection) |
| `Main_`, `Nav_`, `Status_`, `Vm_` | Fenêtre, navigation, statut, ViewModel |
| `Freshclam_` | MAJ signatures (UI + logs utilisateur) |
| `Av_Action_`, `Confirm_`, `Notif_` | Actions antivirus, dialogues, toasts |
| `Risk_` | Sévérités, recommandations, raisons de score |
| `Onboarding_`, `Export_` | Premier lancement, filtres export |

### Code

| Composant | Rôle |
|-----------|------|
| `Localization/LocalizationService.cs` | Culture, `GetString`, `Format`, persistance, redémarrage |
| `Localization/LocExtension.cs` | `{loc:Loc Key=...}` en XAML |
| `Strings/OptiscanStrings.cs` | Panneaux, confirmations récurrentes |
| `Localization/ShellContextMenuSupport.cs` | Menu contextuel Explorateur |

Initialisation : `App.OnStartup` → `LocalizationService.Initialize()` (avant mode headless ou UI).

### Ajouter ou modifier un libellé

1. Clé + valeur FR dans `UiStrings.resx`.
2. **Même clé** + traduction EN dans `UiStrings.en.resx`.
3. XAML : `Text="{loc:Loc Key=Ma_Cle}"`  
   C# : `LocalizationService.GetString("Ma_Cle")` ou `Format("Ma_Cle", arg0, ...)`.

### Tests

```powershell
dotnet test optiSCAN.Tests\optiSCAN.Tests.csproj -c Release --filter Localization
```

Fichier : `optiSCAN.Tests/LocalizationServiceTests.cs`.

### Périmètre traduit (v7.0)

| Zone | État |
|------|------|
| XAML (panneaux, Options, sidebar tooltips) | FR/EN |
| `AntivirusActions` (statut barre via `ActionCompleted`) | FR/EN |
| `RiskScoringService` (badges, recommandations, raisons) | FR/EN |
| `ScanUserDisplay`, toasts, Freshclam messages UI | FR/EN |
| Logs navigateurs **Clean** (noms produits localisés) | FR/EN |
| Installateur (.NET 8, désinstallation données) | FR/EN |

### Périmètre non traduit (volontaire ou technique)

- Sorties brutes **clamscan** / **freshclam** / **YARA** (logs techniques).
- Noms de menaces, chemins de fichiers, versions de bases.
- Corps détaillé des rapports **PDF/HTML** exportés (titres partiels via UI).
- Marques : **ClamAV**, **YARA**, raccourci **F5**.

### Installateur

- Messages .NET 8 manquant : bilingues (`InitializeSetup` dans `installer/setup.iss`).
- `WriteInstallerUiCulture()` : écrit `UiCulture` en `ssPostInstall`.
- Suppression données utilisateur à la désinstallation : dialogue **FR + EN**.
- `RegisterExplorerContextMenu()` : libellé selon `ActiveLanguage`.

### Registre Inno → application

Au **premier lancement** (aucun `preferences.dat`), `UserPreferences` lit :

- `HKCU\Software\optiSCAN\AutoUpdateSignatures` (1/0) → `SignatureAutoUpdateEnabled`

Voir `UserPreferences.ApplyInnoSetupDefaults()`.
