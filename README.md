# Guide Complet — optiSCAN v8.0

> **Version de référence.** Architecture mono-fenêtre, services avancés + Donaby Design System.  
> **Nomenclature** — **v8.0** : nom de release (documentation, CLUF). **8.0.0** : assembly et installateur (`Directory.Build.props`, Inno Setup).
>
> **Design system : Donaby Design** — thème sombre/clair dynamique, tokens DynamicResource WPF.
> Développé par **© 2026 Donatien Byakombe (Dona By)**.

## Sommaire

| Chapitre | Contenu |
|:---:|:---|
| **1** | Architecture technique (stack, arborescence du dépôt) |
| **2** | Donaby Design (thèmes, tokens) |
| **3** | Installation et configuration ClamAV |
| **4** | Application mono-fenêtre (panneaux, antivirus, pipeline, persistance, exports, vue d’ensemble) |
| **5** | Services complémentaires (RTP, scan USB/SD, planificateur, notifications, scoring) |
| **6** | Workflow démarrage UI et ligne de commande |
| **7** | Bonnes pratiques (droits, perfs, faux positifs, Defender) |
| **8** | Publication, installateur Inno Setup et checklist release |
| **9** | Langues de l’interface (fr-FR / en-US) |
| **10** | Dépendances et licences |
| **11** | Historique des versions produit |
| **12** | Audit et qualité |
| **13** | Sécurité (posture /100, modèle de menace) |
| **14** | Crédits |
| — | [Branches Git](#branches-git) (main / dev uniquement) |

---

## Branches Git

Le dépôt **1donatien0/optiSCAN-stable** n’utilise que **deux** branches, partageant **le même historique Git linéaire** depuis l’origine du projet (aucune branche parallèle orpheline, pas de rebase qui efface l’historique public).

| Branche | Rôle |
|---------|------|
| **`main`** | Référence **publiée** : ce qui est sur GitHub pour les releases, CI publish + installateur Inno. |
| **`dev`** | **Intégration** : développement courant ; fusion vers `main` quand une release est prête. |

**Workflow habituel**

1. Travailler et committer sur **`dev`** (`git checkout dev`).
2. Quand une version est prête : `git checkout main` → `git merge dev` (souvent fast-forward) → `git push origin main`.
3. Repasser sur **`dev`** pour la suite.

Après une release, `main` et `dev` peuvent pointer sur le **même commit** (normal). Les prochains commits repartent sur `dev` jusqu’au prochain merge.

Branche par défaut GitHub : **`main`**. CI : uniquement `main` et `dev` (voir [`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

---

## 1. Architecture technique

### Choix du langage : C# WPF .NET 8

| Critère | WPF | MAUI | C++ natif |
|---|---|---|---|
| Compatibilité Windows | Oui — natif | Partiel — multi-plateforme (overhead) | Oui — natif |
| Intégration ClamAV | Oui — Process.Start / TCP clamd | Oui — Process.Start | Oui — libclamav directe |
| MVVM + Binding UI | Oui — excellent | Partiel — différent | Non — manuel |
| **Verdict** | **Retenu** | Non nécessaire | Non nécessaire |

---

### Structure des modules

```
(racine du dépôt optiSCAN)
├── README.md                          ← Ce fichier (guide complet)
├── docs/
│   └── README.md                      ← Index doc (renvoie vers ce README)
├── .github/workflows/ci.yml           ← Build, tests (185), publish (main)
├── scripts/
│   ├── fetch-runtime-deps.ps1         ← Télécharge ClamAV + YARA (CI / dev)
│   ├── prepare-release-v8.ps1         ← Chaîne complète release v8
│   ├── clean-before-publish.ps1       ← Nettoyage bin/obj avant release
│   ├── verify-runtime-deps.ps1        ← Vérifie clamav + clamd + yara + rules
│   └── runtime-versions.json          ← Versions URL ClamAV / YARA
├── optiSCAN.sln                       ← Solution Visual Studio
├── optiSCAN.Tests/                    ← Tests unitaires (xUnit)
├── installer/
│   ├── setup.iss                      ← Script Inno Setup (FR + EN)
│   └── build-release-setup.ps1        ← clean + publish + ISCC
└── optiSCAN/                          ← Projet C# WPF
    ├── Models/
    │   ├── ThreatInfo.cs              ← Menace détectée
    │   ├── ScanProgress.cs            ← Progression temps réel (IProgress<T>)
    │   ├── ScanResult.cs              ← Résultat global d'un scan (types dont RemovableDrive)
    │   ├── ScanSession.cs             ← Entrée d'historique scan (v8 : Threats[] ; v7 : type legacy)
    │   └── ActivityEntry.cs           ← Ligne timeline Historique (scan + nettoyage)
    │
    ├── ViewModels/                    ← ScanViewModel, RelayCommand
    ├── Views/                         ← Overview, Antivirus, Clean, History, Options
    │
    ├── Localization/
    │   ├── LocalizationService.cs     ← Culture fr-FR / en-US, persistance
    │   ├── LocExtension.cs            ← {loc:Loc Key=...} en XAML
    │   └── ShellContextMenuSupport.cs ← Menu « Scanner avec optiSCAN » / EN
    ├── Resources/
    │   ├── UiStrings.resx             ← Chaînes UI (français)
    │   └── UiStrings.en.resx          ← Chaînes UI (anglais)
    ├── Strings/
    │   └── OptiscanStrings.cs         ← URLs, confirmations, statuts MAJ
    │
    ├── Converters/
    │   └── ThreatRiskConverters.cs    ← Colonne « Risque » (RiskScoringService → UI)
    │
    ├── Services/
    │   ├── ClamAvEngine.cs            ← clamscan.exe (sonde --version mise en cache 60 s)
    │   ├── FreshclamUpdater.cs        ← Mise à jour signatures via freshclam.exe
    │   ├── ThemeManager.cs            ← Bascule Donaby + MaterialDesign (UserPreferences)
    │   ├── ExclusionSettings.cs       ← Exclusions DPAPI (exclusions.dat) + dossier d’installation
    │   ├── AppInstallPaths.cs         ← Racine install : auto-exclusion scan / RTP / YARA
    │   ├── YaraEngine.cs              ← YARA + cache _compiled.yarc / _compiled.stamp
    │   ├── YaraForgeUpdater.cs        ← Mise à jour automatique règles de détection
    │   ├── ServiceContainer.cs        ← Singleton partagé (orchestrateur, MAJ, quarantaine, planif…)
    │   ├── ScanOrchestrator.cs        ← Pipeline ClamAV + YARA en parallèle
    │   ├── ScanProgressRelay.cs       ← Progression monotone (multi-cibles / Clam+YARA)
    │   ├── ScanUserDisplay.cs         ← Libellés scan localisés
    │   ├── ScanThreatMerger.cs        ← Fusion menaces ClamAV + YARA
    │   ├── MultiTargetScanAggregator.cs ← Fusion multi-cibles avec déduplication des menaces
    │   ├── AntivirusActions.cs        ← Quarantaine / suppression / MAJ + ActionCompleted
    │   ├── NavigationService.cs       ← Panneaux + fondu 180 ms
    │   ├── NavigationRefreshCoordinator.cs ← Refresh ciblé après navigation
    │   ├── HistoryExportService.cs    ← Export HTML/PDF (depuis Historique)
    │   ├── SystemTrayHost.cs          ← Systray (hors MainWindow)
    │   ├── OnboardingService.cs       ← Message premier lancement
    │   ├── HeadlessScanArguments.cs   ← --fullscan / --quickscan / --quiet
    │   ├── ScheduledScanApply.cs      ← Logique enable/disable tâche (testable)
    │   ├── ElevationHelper.cs         ← Relance UAC (--scan, analyse complète)
    │   ├── QuarantineManager.cs       ← Quarantaine AES-GCM, manifeste signé
    │   ├── SecureStore.cs             ← Persistance DPAPI + HMAC (prefs, exclusions, historique)
    │   ├── OverviewRecommendationsBuilder.cs ← Recommandations accueil (hygiène + activité)
    │   ├── OverviewProtectionStatsFormatter.cs ← Stats protection 30 j. (accueil, sans doublon reco.)
    │   ├── ScanLogManager.cs          ← Historique chiffré (.dat), GetActivityFeed, optiSCAN.log
    │   ├── RealTimeProtection.cs      ← FileSystemWatcher (Options)
    │   ├── RemovableDriveScanService.cs ← Scan auto USB/SD à l'insertion (WMI + polling)
    │   ├── RiskyFileExtensions.cs     ← Extensions à risque (partagées RTP ; USB = tous fichiers en rapide)
    │   ├── ScheduledScanService.cs    ← schtasks (async côté Options)
    │   ├── IpcManager.cs              ← Instance unique : WM_SHOWME
    │   ├── HtmlExportService.cs       ← Rapport HTML
    │   ├── NotificationService.cs     ← Toasts Windows natifs
    │   ├── RiskScoringService.cs      ← Score, sévérités i18n, PDF
    │   └── PdfReportGenerator.cs      ← Export PDF (QuestPDF)
    │
    ├── Themes/
    │   ├── Donaby.Dark.xaml           ← Thème sombre
    │   ├── Donaby.Light.xaml          ← Thème clair
    │   └── Donaby.HighContrast.xaml   ← Contraste renforcé (Options)
    │
    ├── App.xaml                       ← Fusionne Donaby.Light + ThemeManager au démarrage
    ├── MainWindow.xaml                ← Fenêtre unique — 5 panneaux sidebar
    ├── MainWindow.xaml.cs             ← Composition, navigation, RTP, RefreshSignatures/Antivirus (reco. → builder)
    ├── optiSCAN.ico                   ← Icône app
    ├── yara/                          ← Binaires du moteur de détection
    ├── rules/                         ← Règles de détection (.yar) + cache _compiled.yarc
    └── clamav/                        ← Binaires et base ClamAV (x64 / x86 / database)
```

**Règle de séparation :**
- `Models/` — aucune dépendance UI
- `Services/` — aucune dépendance WPF ; injectables / résolus via `ServiceContainer`
- `ViewModels/` — logique de présentation (`ScanViewModel`, commandes)
- `Views/` — XAML + code-behind léger ; navigation via `INavigationService`
- `MainWindow.xaml.cs` — composition : navigation, RTP, affichage statut/signatures ; recommandations accueil déléguées à `OverviewRecommendationsBuilder`

---

## 2. Donaby Design — Système de thèmes

### 2.1 Vue d'ensemble

optiSCAN utilise le **Donaby Design**, un système de design propriétaire basé sur des tokens de couleur WPF (`DynamicResource`). Le thème peut être basculé à chaud (sans redémarrage) entre le mode sombre et le mode clair.

Fichiers de thème :

| Fichier | Rôle |
|---|---|
| `Themes/Donaby.Dark.xaml` | Palette sombre |
| `Themes/Donaby.Light.xaml` | Palette claire |
| `Themes/Donaby.HighContrast.xaml` | Bordures et textes renforcés (Options) |
| `Services/ThemeManager.cs` | Clair / sombre / contraste ; sync thème Windows |

### 2.2 ThemeManager

`ThemeManager` est un service `static` initialisé **avant** `InitializeComponent()` dans le constructeur de **`MainWindow`** (thème correct dès le premier rendu XAML) :

```csharp
// MainWindow() — avant InitializeComponent()
ThemeManager.Initialize(); // SyncWindowsTheme par défaut, sinon DarkTheme

// Options — thème opposé à Windows (décocher = resuivre Windows)
ThemeManager.SetAlternateThemeEnabled(true/false);

// Contraste renforcé (Options)
ThemeManager.SetHighContrast(true);

// S'abonner aux changements
ThemeManager.ThemeChanged += (_, isDark) => { /* ... */ };
```

Styles boutons (`Styles/Controls.xaml`) : `GradientPrimaryButton`, `DangerButton`, `WarningButton`, `SuccessButton`, `HubActionCardButton`, etc. — couleurs sémantiques via `TemplateBinding.Background`.

La préférence est persistée dans `%AppData%\optiSCAN\preferences.dat` (DPAPI + HMAC). Par défaut **optiSCAN suit le thème applications Windows** (`SyncWindowsTheme`). Dans **Options**, une seule case dynamique propose le thème **opposé** à Windows (libellé « Thème clair » si Windows est sombre, « Thème sombre » si Windows est clair). Propriétés : `DarkTheme`, `SyncWindowsTheme`, `HighContrastEnabled`.

### 2.3 Tokens de couleur disponibles

| Token DynamicResource | Rôle |
|---|---|
| `AppBg` / `CardBg` / `HeaderBg` | Fonds principaux |
| `TextDark` / `TextMedium` / `TextSecondary` | Hiérarchie typographique |
| `PrimaryBlue` / `AccentBlue` | Couleur d'accent principale |
| `SuccessGreen` / `AlertGold` / `WarningOrange` / `DangerRed` | Statuts |
| `BorderColor` / `BorderSubtle` / `BorderStrong` | Séparateurs |
| `ThemeToggleIcon` / `ThemeToggleLabel` | Libellés dynamiques pour le bouton de thème |

---

## 3. Installation et configuration de ClamAV

### 3.1 Télécharger ClamAV (version x86-64 obligatoire)

```
https://www.clamav.net/downloads#otherversions
→ Windows → clamav-X.Y.Z.win.x64.zip   ← ZIP, pas MSI, pas ARM64
```

> **Attention :** la version `win.arm64` cause l'erreur `0xc000007b` sur les machines Intel/AMD.

### 3.2 Placer les binaires dans le projet

> **Clone git seul** — les binaires ClamAV et YARA ne sont pas versionnés dans Git. Les récupérer automatiquement :
>
> ```powershell
> .\scripts\fetch-runtime-deps.ps1
> .\scripts\fetch-runtime-deps.ps1 -RunFreshclam   # bases signatures (~200+ Mo, long)
> .\scripts\verify-runtime-deps.ps1                # après dotnet publish
> ```
>
> Au démarrage, optiSCAN journalise aussi l’état via `RuntimeDependencies` (`optiscan-*.log`).

```
<racine du dépôt>/optiSCAN/clamav/x64/
    ├── clamscan.exe
    ├── clamd.exe              ← daemon ClamAV optionnel (TCP 127.0.0.1:3310 si « Moteur clamd » activé)
    ├── freshclam.exe
    ...
```

Dossiers attendus à côté de `optiSCAN.exe` (publish ou debug) :

| Dossier | Contenu minimal |
|---|---|
| `clamav/x64/` (ou `x86/`) | `clamscan.exe`, `freshclam.exe` recommandé |
| `yara/` | `yara64.exe`, `yarac64.exe` (ou `32` en processus x86) |
| `rules/` | Au moins un fichier `.yar` (paquet initial ou MAJ YARA-Forge) |

### 3.3 Première mise à jour des signatures

```powershell
.\clamav\x64\freshclam.exe --datadir=".\clamav\x64\database"
```

Télécharge : `main.cvd` (~170 Mo), `daily.cvd` (~60 Mo), `bytecode.cvd` (~200 Ko).

### 3.4 Lecture de la version locale des signatures

`FreshclamUpdater.GetLocalDatabaseVersion()` lit l'en-tête binaire des fichiers `.cvd` / `.cld` :

```
Format réel : ClamAV-VDB:{date texte}:{version}:{signatures}:...
Exemple     : ClamAV-VDB:01 May 2026 06-27 +0000:27988:355446:...
```

La regex utilisée est `ClamAV-VDB:[^:]+:(\d+):` — elle capture le numéro de version
après la date textuelle (le premier champ est une date lisible, pas un entier).

### 3.5 Codes de sortie clamscan

| Code | Signification |
|---|---|
| 0 | Aucune menace |
| 1 | Menace(s) détectée(s) |
| 2 | Erreur de scan |

---

## 4. Architecture mono-fenêtre (v8.0)

Les sous-sections **4.1** à **4.11** suivent une lecture « produit » : navigation et panneaux, détail du panneau Antivirus, menaces et pipeline, options techniques (MAJ, exclusions, quarantaine, logs), exports, puis contenu de la vue d’ensemble.

### 4.1 Les 5 panneaux de MainWindow

Les vues sont empilées dans un seul `Grid` (`MainWindow.xaml`) : une seule est `Visible`, les autres `Collapsed`. La navigation passe par `NavigationService.NavigateTo("…")` (clés insensibles à la casse), enregistrées dans `MainWindow.RegisterPanels()`.

| Clé `NavigateTo` | Panneau | Contrôle | Rôle principal |
|---|---|---|---|
| `Overview` | Vue d'ensemble | `OverviewControl` | Cartes d'action (boutons), bandeau UAC, statut protection, recommandations |
| `Antivirus` | Antivirus | `AntivirusView` | Scans ; onglets **Analyse en cours** / **Quarantaine** / **Historique** / **Signatures** (`ScanViewModel`) |
| `Clean` | Nettoyer | `CleanControl` | Analyse / nettoyage (caches navigateurs, temp, corbeille) + **historique local** (colonne **Libéré** = `BytesDisplay`) |
| `History` | Historique | `HistoryControl` | Timeline unifiée scans + nettoyages (`GetActivityFeed`) ; traitement menaces v8 ; exports **HTML** / **PDF** |
| `Options` | Options | `OptionsControl` | **Langue** (fr/en, redémarrage), thème / `SyncWindowsTheme`, scan favori, RTP, **scan USB/SD** (auto à l'insertion, mode complet, inclure dans analyse complète), quarantaine auto, planif. (`ServiceContainer.ScheduledScan`, prochaine exécution, **Lancer maintenant**), exclusions |

Raccourcis clavier : `Ctrl+1` … `Ctrl+5` (`KeyboardShortcuts`) — ordre des panneaux : **Vue d’ensemble**, **Antivirus**, **Nettoyer**, **Historique**, **Options**.

### 4.2 Fenêtre principale, barre système et icône

L'interface repose sur `MainWindow` et la barre latérale (90 px). Le **systray** est géré par `SystemTrayHost` (double-clic pour rouvrir, menu Ouvrir / Quitter). Réduire la fenêtre laisse optiSCAN actif en arrière-plan. Footer : statut dynamique (scan, MAJ) à gauche ; crédit Vanier à droite.

### 4.3 Panneau Antivirus (`NavigateTo("Antivirus")`)

Panneau divisé en deux colonnes :
- **Colonne gauche (210px)** : boutons de scan, **cibles récentes** (`RecentTargets` / `ScanRecentCommand`), statistiques temps réel
- **Colonne droite** : TabControl avec 4 onglets :
  - **Analyse en cours** — progression, fichier courant, grille menaces (colonne **Risque** + nom virus), actions par menace, quarantaine groupée
  - **Quarantaine** — entrées paginées, restauration / suppression, purge
  - **Historique** — aperçu des dernières sessions (détail et actions dans le panneau **Historique** `Ctrl+4`)
  - **Signatures** — version de la base ClamAV, mise à jour manuelle, journaux freshclam / règles

Après chaque analyse réussie, `StartScanAsync` met à jour les **cibles récentes** (fichier/dossier scanné, ou entrée « analyse rapide » / « analyse complète »).

### 4.4 Nettoyer une menace détectée

`clamscan.exe` est un moteur de **détection uniquement** — il ne répare pas les fichiers infectés. La désinfection passe par l'isolement ou la suppression du fichier source.

Chaque ligne du tableau des menaces (`antivirusThreatsGrid`) propose trois actions :

| Bouton | Handler (`AntivirusView`) | Comportement |
|---|---|---|
| **Quarantaine** | `AntivirusActions.QuarantineThreat` | AES-256-GCM ; nom de menace depuis la ligne |
| **Supprimer** | `AntivirusActions.DeleteThreatFile` | Confirmation utilisateur, puis suppression définitive |
| **Ignorer** | `AntivirusActions.IgnoreThreat` | Exclusion du fichier |

`AntivirusActions.ActionCompleted` met à jour la **barre de statut** (`MainWindow`).

En bas du tableau, le bouton **Tout mettre en quarantaine** (`BtnQuarantineAll_Click`) traite toutes les menaces listées en une seule opération.

> **Attention :** toujours préférer la quarantaine à la suppression directe — elle permet de restaurer le fichier en cas de faux positif.

### 4.5 Pipeline de détection en parallèle

Les scans interactifs passent par `ScanViewModel.StartScanAsync` → `ScanOrchestrator` : pour chaque cible, **ClamAV** (daemon **clamd** ou repli **clamscan.exe**) et **YARA** tournent en parallèle (`Task.WhenAll`), puis fusion. Les scans **multi-dossiers** passent par `MultiTargetScanAggregator`. Le **dossier d’installation** est exclu (`AppInstallPaths` + `ExclusionSettings`). **`RiskScoringService`** alimente la colonne **Risque**, les toasts et le PDF.

> **clamd** — si `clamd.exe` est présent et l’option **Moteur clamd** est activée (Options), les scans utilisent le daemon TCP (`127.0.0.1:3310`) ; sinon repli sur **`clamscan.exe`**. Note posture Accueil : [§13 Sécurité](#13-sécurité-posture-et-menaces).

```
ScanViewModel → ScanOrchestrator
    │   ├─→ CompositeClamAvBackend (clamd → clamscan)  ─┐
    │   └─→ YaraEngine (.yarc + stamp)                 ├── Task.WhenAll → fusion
    └─→ Progress<ScanProgress> → UI
```

**v8.0** ajoute aussi : note de **posture sécurité** (Accueil), **réputation VirusTotal** (hash SHA-256, clé API Options), **mode jeu** (toasts / scans headless atténués).

**Identifiant menace** — `ThreatInfo.Id` : hash **SHA-256** déterministe (`FilePath|VirusName|DetectedAt`) — stable entre redémarrages (pas `string.GetHashCode()`).

### 4.6 Mise à jour des signatures

**Manuel** — `BtnManualUpdateSignatures_Click` enchaîne `FreshclamUpdater.UpdateAsync()` puis `YaraForgeUpdater.UpdateAsync()` (journal dans l’onglet Signatures).

**Automatique** — À l’instanciation de `ServiceContainer.Default`, les minuteries sont armées : **ClamAV toutes les 4 h**, **paquet YARA-Forge toutes les 24 h**. La case **Mise à jour automatique des signatures** dans **Options** coupe ou réactive **les deux** services (`DisableAutoUpdate` / `EnableAutoUpdate`).

### 4.7 Système d'exclusions

`ExclusionSettings.Current` (singleton) persiste dans :
```
%LOCALAPPDATA%\optiSCAN\exclusions.dat
```
(chiffrement **DPAPI** + **HMAC** ; migration automatique depuis l’ancien `exclusions.json` en clair).

- **Dossiers exclus** : listés par l’utilisateur + **dossier d’installation** d’optiSCAN (implicite, sans faux positifs sur les binaires/règles embarqués)
- **Règles exclues** : matches YARA filtrés (ex. `SuspiciousDownloads` — exclu par défaut)
- **RTP** : mêmes exclusions avant scan temps réel
- **Scan USB/SD** : mêmes exclusions ; lecteur entier exclu si son chemin racine est listé

Configurable depuis **Options → EXCLUSIONS**.

### 4.8 QuarantineManager — sécurité des fichiers infectés

Les fichiers en quarantaine sont stockés en **AES-256-GCM** (format binaire `OPTQ`, nonce et tag d’authentification).

- Clé maîtresse 256 bits, **DPAPI CurrentUser** (fichier `.key`).
- Manifeste `manifest.json` signé **HMAC-SHA256** (intégrité).

Stockage : `%LOCALAPPDATA%\optiSCAN\Quarantine\` — `{guid}.quar` + `manifest.json`. Restauration par défaut ou vers un dossier choisi : `IThreatStore.RestoreTo(quarantineId, destinationFolder)`.

### 4.9 Journaux et historique

| Fichier / service | Rôle |
|---|---|
| `ScanLogManager` → `scan_history.dat` / `clean_history.dat` | Historique chiffré **DPAPI + HMAC** (`SecureStore`) ; rotation implicite : à **100** entrées, les **50** plus anciennes sont retirées (reste **50**, regrossit jusqu'à 100) ; **v8** : `Threats[]` ; migration `.json` → `.legacy` |
| `ScanLogManager` → `optiSCAN.log` | Journal texte volontairement **non chiffré** (diagnostic) ; `FormatScanDetailCore` applique `PathRedaction` sur cible et chemins de menaces — noms de virus, dates et compteurs restent lisibles ; résumé dans **Historique → Scan Antivirus** |
| `AppLogger` → `optiscan-YYYY-MM-DD.log` | Logs applicatifs (composants, erreurs) ; purge **> 30 jours**, au plus **1×/jour** (marqueur `.lastcleanup` persisté) |

**Panneau Historique** (`HistoryControl`, `Ctrl+4`) :

- **Timeline** : `ScanLogManager.GetActivityFeed()` fusionne scans et nettoyages (`ActivityEntry`), tri date décroissante ; filtres **Scans** / **Nettoyages** / **Tout** ; recherche sur type ou cible.
- Détail d’une session **scan** : grille **Détections** (chemin, menace, risque) ; **Quarantaine** / **Ignorer** / **Supprimer** ; **Tout mettre en quarantaine** ; **Traiter dans Analyse** (`RequestReviewHistorySession`). Succès → `TryRemoveThreatFromSession` met à jour `scan_history.dat`.
- Sessions **v7** : badge menaces possible sans chemins (`Hist_DetailThreatsLegacy`) — relancer une analyse pour traiter.
- Types affichés : analyse rapide/complète, fichier, dossier, **lecteur amovible** (`ScanType.RemovableDrive`), nettoyage système.

### 4.10 Exports PDF et HTML

- **PDF** — `PdfReportGenerator` : déclenché via `ServiceContainer` (`ExportScanSessionPdfRequested` → `MainWindow.TryExportScanSessionPdf`). Bouton **Historique** : **PDF (sélection)** sur la ligne choisie dans Scan Antivirus.
- **HTML** — `HtmlExportService` : `RequestExportScanHistoryHtml()` depuis **Historique**.

### 4.11 Vue d'ensemble (dashboard)

Le panneau **Vue d'ensemble** (`OverviewControl`, clé `Overview`) regroupe :

- **Hero** : titre de protection (« Votre ordinateur est protégé » ou « Protection incomplète » selon les moteurs) et **dernière analyse** uniquement ; pas de détail ClamAV/YARA sur cet écran (voir onglet **Antivirus**).
- **Quatre cartes d'action** : Nettoyer, Antivirus, Historique, mise à jour des signatures (navigation via `ServiceContainer` / `INavigationService`).
- **Deux colonnes** sous les cartes :
  - **Statistiques de protection** : `OverviewProtectionStatsFormatter` (30 j., analyses / fichiers / menaces depuis l’historique) — distinct des recommandations pour éviter le doublon « activité ».
  - **Recommandations** : `OverviewRecommendationsBuilder` (hygiène signatures, suggestion nettoyage) ; `MainWindow` collecte le contexte et met à jour `OverviewControl`.

---

## 5. Services avancés (modules complémentaires)

### RealTimeProtection — surveillance temps réel

`RealTimeProtection.cs` : `FileSystemWatcher` sur dossiers sensibles (profil utilisateur, `ProgramData`, `Temp`, etc.), filtre sur extensions à risque (`RiskyFileExtensions`), délai de stabilisation, déduplication et **SemaphoreSlim(3)** parallèle. Une instance est créée dans **`ServiceContainer`** ; **Options** active ou coupe la surveillance et persiste le réglage. Les menaces détectées remontent vers l’UI (badge / liste) via événements consommés par **`MainWindow`**.

### RemovableDriveScanService — clés USB et cartes SD

`RemovableDriveScanService.cs` : à l’**insertion** d’un volume (WMI `Win32_VolumeChangeEvent` + polling de secours), analyse automatique en arrière-plan si l’option est activée (**Options → Analyser les clés USB et cartes SD**, activée par défaut).

| Aspect | Comportement |
|---|---|
| Détection | `DriveType.Removable` **ou** lecteur `Fixed` reconnu USB via WMI (`InterfaceType`, `PNPDeviceID`, `MediaType`) |
| Déjà branché au démarrage | Enregistré sans scan (évite une vague au lancement) |
| Mode rapide (défaut) | Tous les fichiers du volume (plafond **4 000**), analyse fichier par fichier |
| Mode complet (option) | `ScanOrchestrator.ScanFolderAsync` récursif (ClamAV + YARA) |
| Taille max. | **64 Go** par défaut (`RemovableDriveMaxSizeGb` ; `0` = illimité) |
| Analyse complète manuelle | Option **Inclure les lecteurs amovibles** → `ScanTargets.FullScanTargets(includeRemovable: true)` |
| Menace détectée | Historique (`ScanType.RemovableDrive`), toasts, quarantaine auto si activée, liste **Analyser** via `ThreatDetected` (même handler que la RTP) |

Un seul scan USB à la fois (**SemaphoreSlim(1)**). `ServiceContainer.ApplyRemovableDriveScan` / `ApplyPreferencesOnStartup` démarrent ou arrêtent le service.

### ScheduledScanService — tâche planifiée Windows

Instance unique : **`ServiceContainer.Default.ScheduledScan`** (partagée avec **Options**, pas d’instance locale isolée). Enveloppe **`schtasks.exe`** pour **`optiSCAN_DailyScan`** (`optiSCAN.exe --fullscan --quiet`, **`/RL LIMITED`**, heure configurable). **Options** : case planification, sélecteur d’heure, libellé **prochaine exécution** (`GetNextRunTime`), bouton **Lancer maintenant** (`RunNow`). **`App.xaml.cs`** : `--fullscan` / `--quickscan` / `--quiet` en headless (quarantaine auto si activée) — les résultats ne remontent pas dans la grille menaces de la session UI ouverte.

### NotificationService — toasts Windows natifs

`NotificationService.cs` utilise `Microsoft.Toolkit.Uwp.Notifications` pour envoyer des toasts système Windows :

| Méthode | Contenu |
|---|---|
| `ShowThreatDetected(threat)` | Alerte longue avec boutons Quarantaine / Ignorer / Ouvrir |
| `ShowQuarantined(threat)` | Confirmation de mise en quarantaine |
| `ShowScanCompleted(files, threats)` | Résumé de fin de scan |
| `ShowUpdateAvailable(version)` | Nouvelle mise à jour disponible |
| `ShowRealTimeProtectionStarted()` | Confirmation d'activation de la RTP |

### RiskScoringService — score de risque par menace

`RiskScoringService.cs` attribue un score numérique (0–100+) à chaque menace. Affichage : colonne **Risque** dans la grille Antivirus (`ThreatRiskConverters`), toasts, rapport PDF. Critères cumulatifs :

**Critère 1 — Nom du virus (mots-clés)**

| Niveau | Mots-clés |
|---|---|
| CRITIQUE | ransom, rootkit, bootkit, backdoor, worm.win32, wannacry, notpetya… |
| MAJEUR | trojan, worm, spyware, keylogger, dropper, banker, infostealer… |
| MINEUR | adware, pup, pua, hacktool, riskware… |
| INFORMATIONNEL | suspicious, detected |

**Critère 2 — Chemin du fichier**

| Condition | Niveau |
|---|---|
| `\Windows\System32\` ou `\SysWOW64\` | CRITIQUE |
| Extension exécutable (`.exe`, `.dll`, `.ps1`…) | MAJEUR |
| Document avec macro (`.docm`, `.xlsm`…) | MAJEUR |
| Dossier `\Temp\` | MINEUR |

**Critère 3 — Bonus/malus**

- Double détection ClamAV + YARA : **+20 pts**
- Fichier < 1 Mo (payload potentiel) : **+10 pts**
- Fichier > 50 Mo (risque plus faible) : **-10 pts**

**Table de décision finale**

| Score | Niveau | Couleur | Recommandation |
|---|---|---|---|
| ≥ 80 | CRITIQUE | `#C0392B` | Quarantaine/suppression immédiate |
| ≥ 50 | MAJEUR | `#E67E22` | Quarantaine dès que possible |
| ≥ 25 | MINEUR | `#F1C40F` | Surveillance ou quarantaine préventive |
| < 25 | INFORMATIONNEL | `#27AE60` | Aucune action immédiate |

---

## 6. Workflow utilisateur optiSCAN v8.0

```
DÉMARRAGE (UI)
    │
    ├─→ Mutex single-instance (2e instance → IPC « afficher » la fenêtre existante)
    ├─→ `App.OnStartup` → `LocalizationService.Initialize()` (fr-FR / en-US : prefs, registre installateur)
    ├─→ `ThemeManager.Initialize()` (préférence `UserPreferences`)
    ├─→ `MainWindow` + `ServiceContainer.Default` (ClamAV, YARA, orchestrateur, MAJ, quarantaine, planif., logs, `AntivirusActions`, `ThreatLookup` → VM)
    ├─→ Minuteries MAJ : freshclam **4 h**, règles YARA **24 h** (désactivables via Options)
    ├─→ `ScanViewModel.InitializeAsync` : versions, base, YARA, historique, quarantaine
    ├─→ Protection temps réel : état selon **Options** (`ServiceContainer.RealTimeProtection`)
    ├─→ Scan USB/SD : `ServiceContainer.RemovableDriveScan` si option activée
    └─→ Fenêtre principale + icône zone de notification (réduction possible sans quitter)
            │
            ├─→ [VUE D'ENSEMBLE] — hero (protection + dernière analyse), cartes d’action, statistiques 30 j., recommandations
            ├─→ [NETTOYER] — temporaires, caches navigateurs (Edge, Chrome, Firefox, Brave, **Opera**, **Vivaldi**, **Arc**), corbeille, journaux Windows
            ├─→ [ANTIVIRUS] — scans rapide/complet/dossier/fichier, quarantaine, historique de session, signatures
            ├─→ [HISTORIQUE] — sessions v8 : grille détections (chemin + menace), quarantaine / ignorer / supprimer, **Traiter dans Analyse** ; exports **HTML** / **PDF**
            └─→ [OPTIONS] — langue FR/EN, thème (sync Windows par défaut), scan favori, démarrage auto, MAJ auto, RTP, scan USB/SD, quarantaine auto, planification, exclusions

FERMETURE
    └─→ `MainWindow.OnWindowClosing` → `PerformCleanShutdown` → `ServiceContainer.Shutdown()` (RTP, scan USB, minuteries MAJ, moteurs)

DÉMARRAGE (ligne de commande)
    `--fullscan` / `--quickscan` [+ `--quiet` ] → `App.RunHeadlessAsync` : orchestrateur, journal, quarantaine auto si `ExclusionSettings.Current.AutoQuarantineEnabled`, notification fin si menaces et non quiet.
```

---

## 7. Bonnes pratiques

### Permissions et droits

L’application est publiée en **`asInvoker`** (`app.manifest`) : exécution avec les droits de l’utilisateur connecté. Les opérations sur chemins protégés (ex. analyse large sous `C:\Windows`) peuvent demander une **élévation UAC ponctuelle** (`ElevationHelper`) plutôt qu’un administrateur permanent.

### Performance

| Technique | Impact |
|---|---|
| `IsClamAvInstalled()` cache 60 s | Évite un `clamscan --version` à chaque changement d’onglet |
| Pipeline parallèle (Task.WhenAll) | ClamAV + YARA simultanés sur chaque cible |
| `MultiTargetScanAggregator` dédup | Pas de doublons si cibles qui se chevauchent |
| Règles pré-compilées (_compiled.yarc) | Scan comportemental accéléré |
| SemaphoreSlim(3) RTP | `RealTimeProtection` (activable depuis Options) |
| SemaphoreSlim(1) scan USB | `RemovableDriveScanService` (un lecteur à la fois) |
| Scan rapide limité aux dossiers critiques | `ScanTargets.QuickScanTargets()` |
| ExclusionSettings.Current (singleton lazy) | Pas de rechargement JSON par fichier |
| ServiceContainer (singleton services) | Une instance ClamAV/YARA/orchestrateur pour toute l’app |
| ThemeManager + UserPreferences | Bascule de thème sans redémarrage |

### Faux positifs

- `SuspiciousDownloads` exclue par défaut (trop agressive sur le dossier Downloads)
- Ne jamais supprimer automatiquement — toujours mettre en quarantaine en premier
- L'utilisateur confirme avant toute action destructrice (boîte de dialogue `MessageBoxButton.YesNo`)
- Le test EICAR est géré normalement par ClamAV (aucun traitement spécial dans le scoring)

### Exclusion Windows Defender

```powershell
Add-MpPreference -ExclusionPath "C:\Program Files\optiSCAN\clamav\database"
```

---

## 8. Publication, installateur et checklist release (v8.0)

> **Publication** : assembly **8.0.0** (`Directory.Build.props`, Inno Setup). **Branche** : `dev` → merge → `main` → artefacts CI / installateur — voir [Branches Git](#branches-git).

### Prérequis machine de build

- Windows 10/11 x64, .NET 8 SDK, Inno Setup 6
- Réseau (téléchargement ClamAV, YARA, signatures freshclam)
- Binaires **non versionnés** dans Git : `.\scripts\fetch-runtime-deps.ps1`

### Chaîne automatique (recommandée)

```powershell
# Depuis la racine du dépôt (dossier contenant optiSCAN.sln)
.\scripts\prepare-release-v8.ps1
```

Équivalent manuel : `clean-before-publish` → `fetch-runtime-deps -RunFreshclam` → `dotnet test` → `dotnet publish` → `verify-runtime-deps` → `build-release-setup.ps1`.

Sortie publish : `optiSCAN\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64\` (chemin attendu par `installer\setup.iss`). Installateur typique : `installer\output\optiSCAN_Setup_v8.0.0.exe`.

**Chaîne locale alternative** : `.\installer\build-release-setup.ps1` (nettoie, publie, lance ISCC).

### Ordre recommandé (équipe)

1. Gel fonctionnel : `dotnet test` Release (**185** tests).
2. Dépendances : `.\scripts\fetch-runtime-deps.ps1` (+ `-RunFreshclam` pour l’installateur).
3. Publish local : `.\scripts\prepare-release-v8.ps1` (ou étapes manuelles ci-dessous).
4. VM propre : installer `optiSCAN_Setup_v8.0.0.exe` ; scan, RTP, clamd, posture, FR/EN.
5. CI : push `main` → job **Publish win-x64** ; artefact `optiSCAN-setup-<sha>.exe`.
6. Signature (opt.) : Authenticode — `installer/setup.iss.signing.example`.
7. Tag / distribution : `git tag v8.0.0`, release GitHub, SourceForge ou site.

### Étapes manuelles détaillées

**Étape 0 — nettoyage (recommandé)**

```powershell
.\scripts\clean-before-publish.ps1 -IncludeObj -IncludeInstallerOutput -IncludeCiPublish
```

**Étape A — publication .NET**

```powershell
dotnet publish .\optiSCAN\optiSCAN.csproj -c Release /p:PublishProfile=FolderProfile
```

**Étape B — première base ClamAV** (adapter `$pub` si vous publiez ailleurs)

```powershell
$pub = ".\optiSCAN\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64"
& "$pub\clamav\x64\freshclam.exe" --datadir="$pub\clamav\database"
```

**Étape C — compilateur Inno Setup**

```powershell
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" .\installer\setup.iss
```

**Installateur** : assistant **bilingue** (français / English) ; langue choisie → `UiCulture` en registre pour le premier lancement de l’app.

**Contenu de l'installateur (~260 Mo avec signatures initiales) :**

```
optiSCAN_Setup_v8.0.0.exe
    ├── optiSCAN.exe
    ├── optiSCAN.ico
    ├── *.dll (runtime .NET 8)
    ├── clamav/x64/          ← Binaires x86-64 (clamscan + clamd) + base de signatures
    ├── yara/                ← Binaires du moteur de détection
    └── rules/               ← Règles de détection initiales
```

### Checklist binaire (bloquant)

- [ ] `dotnet test` Release — **185** tests OK
- [ ] `.\scripts\verify-runtime-deps.ps1` — vert sur dossier publish
- [ ] `clamscan.exe`, `freshclam.exe`, **`clamd.exe`**, `yara64.exe`, règles `.yar`
- [ ] `clamav\database\` — au moins un `main.cvd` / `daily.cvd` (via freshclam)
- [ ] Installateur FR/EN, sidebar **v8.0**, options clamd / VT / mode jeu, accueil posture /100
- [ ] Test post-install : scan fichier, quarantaine, **historique → traiter une menace**, exports PDF/HTML ; **clé USB** (scan auto si option activée)
- [ ] Après upgrade depuis v7 : `scan_history.dat` présent (éventuellement `scan_history.json.legacy`)

### CI GitHub

Pipeline : [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

| Branche | Comportement |
|---------|----------------|
| **`main`** | `fetch-runtime-deps.ps1` → `fetch-runtime-deps.ps1 -RunFreshclam` (timeout 45 min) → `dotnet publish` → `verify-runtime-deps.ps1` → Inno → `optiSCAN_Setup_v8.0.0.exe` |
| **`dev`** | Build + tests + artefact binaire Release (sans installateur complet) |

**Freshclam en CI** : génère un `freshclam.conf` minimal dans `clamav\x64\` (non versionné dans Git, comme en production via `FreshclamUpdater`). **Erreur connue (corrigée)** : `Can't open/parse freshclam.conf` si freshclam est lancé sans `--config-file`.

**Repères de couverture tests (release, 185 au total — voir checklist)** :

| Module | Fichier de tests |
|--------|------------------|
| Recommandations accueil | `OverviewRecommendationsBuilderTests` |
| Stats accueil 30 j. | `OverviewProtectionStatsFormatterTests` |
| Posture /100 | `SecurityPostureServiceTests` |
| Historique / timeline | `ScanLogManagerTests` (`GetActivityFeed`, DPAPI, rotation) |
| Scan USB/SD | `RemovableDriveDiscoveryTests` |
| Thème Windows | `ThemeManagerPreferenceTests` |
| Persistance | `SecureStoreTests`, `UserPreferencesStorageTests`, `ExclusionSettingsTests` |

### Après publication

- Conserver `main` et `dev` alignées (même tip après merge release).
- **v7 → v8** : migration historique JSON → `scan_history.dat` (DPAPI) au premier lancement.
- Maintenabilité et choix volontaires : [§12.1](#121-maintenabilité-et-choix-volontaires-non-bloquants-v8).

### Signature Authenticode (optionnelle)

Windows affiche « Éditeur inconnu » sans certificat. Utile pour release publique ; nécessite un `.pfx` et des secrets CI (`CODESIGN_PFX`). Exemple : [`installer/setup.iss.signing.example`](installer/setup.iss.signing.example). Signer `optiSCAN.exe` + `optiSCAN_Setup_v8.0.0.exe` (`signtool`).

---

## 9. Langues de l’interface (fr-FR / en-US)

| Canal | Comportement |
|-------|----------------|
| **Installateur Inno** | Choix FR ou EN → `HKCU\Software\optiSCAN\UiCulture` |
| **Options → Langue** | Français / English → confirmation → **redémarrage** de l’app |
| **Ressources** | `UiStrings.resx` + `UiStrings.en.resx` (**621** clés FR/EN, parité vérifiée en CI) |
| **Menu contextuel** | « Scanner avec optiSCAN » ou « Scan with optiSCAN » |

Les deux langues sont **incluses dans le même binaire** (pas de pack de langue séparé). Les rapports PDF/HTML exportés et les journaux techniques ClamAV/YARA peuvent rester partiellement en français ou en anglais technique.

### Développeurs et traducteurs

| Fichier | Culture |
|---------|---------|
| `optiSCAN/Resources/UiStrings.resx` | Français (défaut) |
| `optiSCAN/Resources/UiStrings.en.resx` | Anglais (en-US) |

Ajouter une clé : même nom dans les deux `.resx` → XAML `{loc:Loc Key=...}` ou C# `LocalizationService.GetString` / `Format`.

```powershell
dotnet test optiSCAN.Tests\optiSCAN.Tests.csproj -c Release --filter Localization
```

Non traduit volontairement : sorties brutes clamscan/freshclam/YARA, noms de menaces, chemins, marques ClamAV/YARA. L’UI **Historique** n’affiche pas le libellé moteur (`DetectedBy`) — réservé au pipeline interne.

---

## 10. Dépendances et licences

| Composant | Version | Licence | Notes |
|---|---|---|---|
| ClamAV | Dernière stable | GPLv2 | Inclure la licence dans l'installateur |
| .NET 8 WPF | 8.x | MIT | Inclus dans le runtime Windows |
| MaterialDesignThemes | 5.3.1 | MIT | Bibliothèque UI (PackIcon, styles) |
| QuestPDF | 2024.12.2 | Community | Rapport PDF — licence gratuite projets open-source |
| Mise à jour binaire optiSCAN (`UpdateService`) | — | — | Canal OTA non configuré ; staging `%LocalAppData%\optiSCAN\Updates` ; signatures via Antivirus |
| Planificateur de tâches (`schtasks.exe`) | — | — | Natif Windows — voir `ScheduledScanService` |
| Microsoft.Toolkit.Uwp.Notifications | 7.1.3 | MIT | Toasts Windows natifs |
| Inno Setup | 6.x | Freeware | Gratuit pour projets commerciaux |
| Base de signatures ClamAV | — | ClamAV License | Mise à jour depuis database.clamav.net |
| Règles de détection | — | Diverses open-source | Récupérées depuis YARA-Forge |

---

## 11. Historique des versions produit

### v8.0 — Clamd, posture, historique unifié, scan USB

- **Historique** — timeline scans + nettoyages (`ActivityEntry`, `GetActivityFeed`) ; menaces traitables (**Traiter dans Analyse**) ; `scan_history.dat` / `clean_history.dat` chiffrés (DPAPI) ; rotation 100→50 ; compat v7 sans chemins
- **Accueil** — `OverviewRecommendationsBuilder` + `OverviewProtectionStatsFormatter` (stats 30 j. sans doublon dans les recommandations)
- **Scan USB/SD** — `RemovableDriveScanService` (WMI + polling) ; rapide = tous fichiers (plafond 4 000) ; clés `Fixed` détectées via WMI USB ; type `RemovableDrive` ; pipeline menaces identique à la RTP
- **Thème Windows** — `SyncWindowsTheme` par défaut ; case Options (thème opposé à Windows) ; `ThemeManager.Initialize()` dans `MainWindow` avant `InitializeComponent`
- **clamd** — `CompositeClamAvBackend`, TCP `127.0.0.1:3310`, repli `clamscan.exe`
- **Posture /100**, **VirusTotal**, **mode jeu** — voir [§13](#13-sécurité-posture-et-menaces) et Options
- **Tests** — **185** tests Release — [§12](#12-audit-et-qualité) ; i18n **621** clés FR/EN

### v7.0 — Lifting UI Donaby + identité visuelle

- **Lifting apparence** — glassmorphism, fond mesh, cartes métriques, en-têtes unifiés
- **Accueil** — hero `FontSize.Display`, dernière analyse détaillée, carte État de protection, stats/recommandations
- **Typo & écriture** — Title Case, token Display, voix éditoriale ([§9](#9-langues-de-linterface-fr-fr--en-us))
- **Onboarding** — parcours 3 étapes (MAJ signatures optionnelle)
- **Logo hero** — bouclier optiSCAN (accueil), sidebar compacte
- **Footer** — statut live + crédit Vanier (deux colonnes)
- **Thèmes** — clair / sombre / contraste renforcé ; boutons sémantiques + hover grilles
- **Services** — `SystemTrayHost`, `HistoryExportService`, `SignatureUpdateUiRunner`, `ScanLastScanDisplay`
- **i18n** — exports PDF/HTML, MAJ signatures, ViewModel, runtime (**568** clés FR/EN)
- **Options** — schtasks async, hints RTP/UAC honnêtes, limite nettoyage navigateurs documentée
- **CI** — GitHub Actions ; tests Release ; artefact publish + installateur Inno (main)
- **Doc** — guide unique `README.md` (sections 8–13)

### v6.0 — Version majeure (publication)

- **Versioning unifié** — nom **v6.0** + build **6.0.0** (`Directory.Build.props`, Inno Setup, **LICENSE.txt**, manifeste, rapports PDF/HTML)
- **Interface bilingue** — français et anglais embarqués (`LocalizationService`, `UiStrings` / `UiStrings.en`) ; installateur et Options avec redémarrage ; menu contextuel Explorateur localisé
- **Documentation** — `README.md` ; scripts `clean-before-publish.ps1` et `build-release-setup.ps1`
- **Expérience d’analyse** — libellés utilisateur unifiés (`ScanUserDisplay`) ; progression monotone (`ScanProgressRelay`) ; fusion menaces (`ScanThreatMerger`) ; tests unitaires étendus
- **Antivirus** — analyse par boutons (rapide, complète, fichier, dossier) ; suppression du glisser-déposer

### v5.0 — Version majeure (publication)

- **Versioning unifié** — nom **v5.0** + build **5.0.0** (`Directory.Build.props`, Inno Setup, **LICENSE.txt**, manifeste, rapports PDF/HTML)
- **Nettoyer** — historique des sessions dans `CleanControl` (colonne **Libéré** / `BytesDisplay`) + onglet Historique
- **Stabilité** — `ThreatInfo.Id` SHA-256 déterministe ; quarantaine avec nom de menace réel ; `ServiceContainer.Shutdown()` à la fermeture
- **UI / services** — cibles récentes, colonne **Risque**, planification partagée, journal des analyses, auto-exclusion du dossier d’installation
- **Documentation** — README et CLUF alignés sur le code (plus de référence à `ClamDaemon.cs`)

### v4.0 — Version majeure (alignement produit)

- **Versioning unifié** — nom **v4.0** + build **4.0.0** (`Directory.Build.props`, Inno Setup, **LICENSE.txt**, manifeste, rapports PDF/HTML)
- **Interface d’analyse** — progression, fichier courant, fusion ClamAV + YARA (`ScanOrchestrator`)
- **Vue d’ensemble** — statistiques sur 30 jours, recommandations et bannière de protection **branchées** sur les services et l’historique
- **Options** — thème, `SyncWindowsTheme`, scan favori, RTP, quarantaine auto, planif. (`ScheduledScan` partagé, prochaine exécution, lancement immédiat), exclusions **DPAPI** (`exclusions.dat`)
- **Auto-exclusion** — dossier d’installation optiSCAN (`AppInstallPaths`) pour éviter l’auto-détection
- **Historique** — export **HTML** / **PDF** (dernier ou session sélectionnée) ; onglet **Journal** (`optiSCAN.log`)
- **Antivirus** — cibles récentes, colonne **Risque**, actions via **`AntivirusActions`**
- **Identifiants** — `ThreatInfo.Id` SHA-256 stable ; quarantaine conserve le vrai nom de menace
- **Logs** — nettoyage `AppLogger` 30 j. avec marqueur `.lastcleanup` persisté
- **Fermeture** — `ServiceContainer.Shutdown()` depuis `MainWindow`
- **Quarantaine** — format stockage **AES-256-GCM** (`OPTQ`) ; alignement silencieux des fichiers au format attendu au démarrage
- **Instance unique** — seconde exécution : **IPC** (`IpcManager`, WM_SHOWME) pour réafficher la fenêtre existante
- **Manifeste** — **`asInvoker`** + élévation ponctuelle (`ElevationHelper`) pour réduire la surface d’attaque
- **Français** — libellés et documentation alignés sur le comportement réel de l’application

### v3.0 — Donaby Design System + Stabilisation

- **Donaby Design System complet** — refonte UI vers le thème clair Donaby Light par défaut
- **OverviewControl** — hero (titre + dernière analyse), 4 cartes d'action cliquables ; statistiques et recommandations (sans panneau ClamAV/YARA sur l'accueil)
- **AntivirusView** — boutons d’analyse (rapide, complète, fichier, dossier) ; liste **cibles récentes** reliée à `UserPreferences`
- **CleanControl** — Brave, **Opera**, **Vivaldi**, **Arc**, journaux Windows
- **FreshclamUpdater** — `EnsureConfExists()` : résolution automatique du conf manquant (`x64\` → parent → `x86` → génération) ; `ResolveDbDir()` : résolution intelligente du dossier de base de données selon la hiérarchie clamav
- Correction CS0104 `CheckBox`/`Button` ambiguous — aliases `WpfCheckBox`/`WpfButton` dans `OptionsControl.xaml.cs`
- **README aligné code** — navigation, quarantaine AES-GCM, pipeline clamscan + YARA, RTP / planificateur / packaging
- **MAJ auto** — `ServiceContainer` arme freshclam (4 h) + YARA-Forge (24 h) ; Options coupe/réactive les deux

### v2.0 — Phase 2 : Services Avancés + Donaby Design

- **Donaby Design** — thème sombre/clair dynamique (`ThemeManager`, tokens `DynamicResource`)
- Icône **system tray** (expérimental dans les versions précédentes ; l’UI actuelle reste fenêtre principale uniquement)
- **Nettoyer par menace** — boutons Quarantaine + Supprimer par ligne dans le tableau des menaces
- Correction affichage **version signatures ClamAV** (regex `ClamAV-VDB:[^:]+:(\d+):`)
- Binaire **clamd** livré sous `clamav/` — utilisé lorsque l’option **Moteur clamd** est activée (sinon repli `clamscan.exe`)
- **Protection en temps réel** (FileSystemWatcher, 3 workers simultanés)
- **Tâche planifiée Windows** — API `schtasks` (`ScheduledScanService`) ; case **Options** + headless `--fullscan` opérationnel
- **Notifications toast** Windows natives (`Microsoft.Toolkit.Uwp.Notifications`)
- **Score de risque** (`RiskScoringService`) — CRITIQUE / MAJEUR / MINEUR / INFORMATIONNEL
- **Rapport PDF** (`PdfReportGenerator`, QuestPDF Community)
- **Vue d'ensemble** — cartes d'action, encarts d'état / recommandations (évolution continue selon les versions)

### v1.0 — Phase 1 : Fondations

- Scanner ClamAV (rapide / complet / dossier / fichier)
- Moteur YARA comportemental + règles YARA-Forge
- Quarantaine locale chiffrée (`.quar` + `manifest.json`)
- Historique des scans (rotation 100→50 ; détail menaces et chiffrement **.dat** depuis **v8**)
- Mise à jour automatique signatures (4 h) et règles (24 h)
- Système d'exclusions (dossiers + règles)
- Nettoyage fichiers temporaires

---

## 12. Audit et qualité

**Verdict (v8.0)** : produit stable ; valider l’installateur sur une machine propre avant diffusion large.

| Domaine | Note | Commentaire |
|---------|:----:|-------------|
| Architecture | 8/10 | `CompositeClamAvBackend`, posture injectable ; recommandations accueil extraites |
| Sécurité locale | 8/10 | Quarantaine AES-GCM ; historique `.dat` DPAPI ; `optiSCAN.log` diagnostic (chemins redacted, pas de secret critique) |
| UI / Donaby | 8/10 | Accueil posture ; VT optionnel |
| Tests & CI | 9/10 | **185** tests (posture, accueil, historique/timeline, USB, `SecureStore`) ; coverage Cobertura |
| Release Inno | 7/10 | Pipeline CI OK |

**Dettes ouvertes (résumé)** : tests intégration clamd/schtasks réels ; signature Authenticode optionnelle. Voir §12.1 pour le reste (maintenabilité, choix volontaires).

```powershell
dotnet test optiSCAN.Tests\optiSCAN.Tests.csproj -c Release
```

### 12.1 Maintenabilité et choix volontaires (non bloquants v8)

**`MainWindow` encore central** — `OverviewRecommendationsBuilder` a extrait le calcul des recommandations accueil ; il reste dans la fenêtre : `RefreshSignaturesDisplayAsync`, `RefreshAntivirusStatus`, coordination RTP, navigation. **Prochain candidat** (non urgent) : un `SignatureStatusService` (TTL/cache des libellés signatures). Pure maintenabilité.

**`optiSCAN.log` non chiffré** — choix intentionnel pour le support et le mode headless. Les lignes produites par `FormatScanDetail` / `FormatScanDetailCore` passent par `PathRedaction.RedactPath` sur `TargetPath` et `FilePath` : pas de chemins complets dans le journal. Restent lisibles : noms de menace, horodatages, compteurs — acceptable pour un log de diagnostic.

**`PostureFix_Click` / `LaunchFixUri`** — repli `ms-settings:…` puis `control.exe` (séparateur `|` dans `FixUri`) ; logique dans `OverviewControl` (méthode statique privée). Test unitaire possible via `internal` + `InternalsVisibleTo`, **ROI faible** (deux branches triviales) ; la posture elle-même est couverte par `SecurityPostureServiceTests`.

---

## 13. Sécurité (posture et menaces)

### Note posture /100 (Accueil)

| Id | Poids | Source |
|----|-------|--------|
| `firewall` | 15 | Domain / Standard / Public (`EnableFirewall`) |
| `uac` | 10 | `EnableLUA` |
| `wupdate` | 15 | `IWindowsUpdateProbe` (registre, WMI, WUA) |
| `shares` | 10 | Partages SMB (`REG_MULTI_SZ`) |
| `optiscan` | 25 | ClamAV + YARA + RTP |
| `scan` | 15 | Dernière analyse &lt; 7 jours |
| `sigauto` | 10 | MAJ signatures auto |

Limite : les trois profils pare-feu sont lus au registre, pas le profil réseau « actif » en temps réel.

Liens **Corriger** (accueil) : `optiscan://panel/{id}` (antivirus, options, history, clean, overview) ; UAC → `UserAccountControlSettings.exe` (+ repli `control.exe`) ; pare-feu → `ms-settings:windowsdefender-firewall` (+ replis) ; partages → `advancedsharing|control.exe` (séparateur `|`).

### Modèle de menace (périmètre local)

**Actifs** : fichiers analysés, quarantaine, prefs/exclusions (`%LocalAppData%\optiSCAN`), clé VT optionnelle.

**Contrôles** : quarantaine AES-GCM + HMAC ; exclusions avec frontière `\` ; UAC pour scan complet ; RTP ; clamd sur `127.0.0.1`.

**Limites** : malware admin peut neutraliser l’AV local ; pas d’AMSI v8 ; VT envoie le hash ; `optiSCAN.log` non chiffré mais sans chemins complets (`PathRedaction` sur les lignes de scan).

---

## 14. Crédits

Développé par **© 2026 Donatien Byakombe**  
Design system : **Donaby Design**
