# Guide Complet — optiSCAN v6.0

> **Version de référence.** Ce guide décrit l'architecture, les modules et les procédures
> de la version **v6.0** du produit (build **6.0.0**, édition ClamAV). Architecture mono-fenêtre avec services avancés + Donaby Design System.
>
> **Nomenclature (comme v1.0 … v5.0)** — **v6.0** : nom de release (documentation, CLUF). **6.0.0** : identifiant d’assembly et d’installateur (`Directory.Build.props`, Inno Setup).
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
| **5** | Services complémentaires (RTP, planificateur, notifications, scoring, journalisation) |
| **6** | Workflow démarrage UI et ligne de commande |
| **7** | Bonnes pratiques (droits, perfs, faux positifs, Defender) |
| **8** | Publication et installateur Inno Setup |
| **9** | Dépendances et licences |
| **10** | Historique des versions produit |
| **11** | Crédits |

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
├── README.md                          ← Ce fichier
├── optiSCAN.sln                       ← Solution Visual Studio
├── installer/
│   └── setup.iss                      ← Script Inno Setup
└── optiSCAN/                          ← Projet C# WPF
    ├── Models/
    │   ├── ThreatInfo.cs              ← Menace détectée
    │   ├── ScanProgress.cs            ← Progression temps réel (IProgress<T>)
    │   ├── ScanResult.cs              ← Résultat global d'un scan
    │   └── ScanSession.cs             ← Entrée d'historique (persistable JSON)
    │
    ├── ViewModels/                    ← ScanViewModel, RelayCommand
    ├── Views/                         ← Overview, Antivirus, Clean, History, Options
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
    │   ├── MultiTargetScanAggregator.cs ← Fusion multi-cibles avec déduplication des menaces
    │   ├── AntivirusActions.cs        ← Quarantaine / suppression / MAJ (sans passer par MainWindow)
    │   ├── QuarantineManager.cs       ← Quarantaine AES-GCM, manifeste signé, RestoreTo(chemin)
    │   ├── ScanLogManager.cs          ← Historique JSON + optiSCAN.log
    │   ├── AppLogger.cs               ← Journal applicatif optiscan-*.log + nettoyage 30 j.
    │   ├── RealTimeProtection.cs      ← FileSystemWatcher (Options)
    │   ├── ScheduledScanService.cs    ← schtasks (instance ServiceContainer.ScheduledScan)
    │   ├── IpcManager.cs              ← Instance unique : message WM_SHOWME
    │   ├── HtmlExportService.cs       ← Rapport HTML (Historique)
    │   ├── SignatureUpdateCoordinator.cs
    │   ├── NotificationService.cs     ← Toasts Windows natifs
    │   ├── RiskScoringService.cs      ← Score 0-100 (grille, toasts, PDF)
    │   └── PdfReportGenerator.cs      ← Export rapport PDF (QuestPDF)
    │
    ├── Themes/
    │   ├── Donaby.Dark.xaml           ← Thème sombre (tokens DynamicResource)
    │   └── Donaby.Light.xaml          ← Thème clair (tokens DynamicResource)
    │
    ├── App.xaml                       ← Fusionne Donaby.Light + ThemeManager au démarrage
    ├── MainWindow.xaml                ← Fenêtre unique — 5 panneaux sidebar
    ├── MainWindow.xaml.cs             ← Navigation, services, raccourcis
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
- `MainWindow.xaml.cs` — composition : navigation, handlers globaux, pont avec le `ServiceContainer`

---

## 2. Donaby Design — Système de thèmes

### 2.1 Vue d'ensemble

optiSCAN utilise le **Donaby Design**, un système de design propriétaire basé sur des tokens de couleur WPF (`DynamicResource`). Le thème peut être basculé à chaud (sans redémarrage) entre le mode sombre et le mode clair.

Fichiers de thème :

| Fichier | Rôle |
|---|---|
| `Themes/Donaby.Dark.xaml` | Palette sombre (fond `#1A1917`, accents violets) |
| `Themes/Donaby.Light.xaml` | Palette claire (fond `#F8F5F0`, accents violets) |
| `Services/ThemeManager.cs` | Service statique de bascule, persistance `UserPreferences` (DPAPI) |

### 2.2 ThemeManager

`ThemeManager` est un service `static` appelé au démarrage depuis `App.xaml.cs` (après `OnStartup`) :

```csharp
// App.xaml.cs — branche interface graphique
ThemeManager.Initialize(); // applique DarkTheme depuis UserPreferences (clair par défaut)

// Bascule depuis le bouton de l'UI
ThemeManager.Toggle();

// S'abonner aux changements
ThemeManager.ThemeChanged += (_, isDark) => { /* ... */ };
```

La préférence est persistée avec les autres options dans `%AppData%\optiSCAN\preferences.dat` (chiffrement DPAPI + HMAC, voir `UserPreferences.cs`). La propriété `DarkTheme` vaut `true` pour le thème sombre Donaby.

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

> **Clone git seul** — les binaires ClamAV et YARA ne sont pas versionnés (`bin/` est ignoré). Sans eux, l’application démarre mais ne peut pas analyser. Vérification :
>
> ```powershell
> .\scripts\verify-runtime-deps.ps1
> ```
>
> Au démarrage, optiSCAN journalise aussi l’état via `RuntimeDependencies` (`optiscan-*.log`).

```
<racine du dépôt>/optiSCAN/clamav/x64/
    ├── clamscan.exe
    ├── clamd.exe              ← binaire optionnel (non utilisé par l’app UI ; scans = clamscan)
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

## 4. Architecture mono-fenêtre (v6.0)

Les sous-sections **4.1** à **4.11** suivent une lecture « produit » : navigation et panneaux, détail du panneau Antivirus, menaces et pipeline, options techniques (MAJ, exclusions, quarantaine, logs), exports, puis contenu de la vue d’ensemble.

### 4.1 Les 5 panneaux de MainWindow

Les vues sont empilées dans un seul `Grid` (`MainWindow.xaml`) : une seule est `Visible`, les autres `Collapsed`. La navigation passe par `NavigationService.NavigateTo("…")` (clés insensibles à la casse), enregistrées dans `MainWindow.RegisterPanels()`.

| Clé `NavigateTo` | Panneau | Contrôle | Rôle principal |
|---|---|---|---|
| `Overview` | Vue d'ensemble | `OverviewControl` | Cartes d'action, statistiques 30 j., recommandations dynamiques, état ClamAV/YARA et signatures |
| `Antivirus` | Antivirus | `AntivirusView` | Scans ; onglets **Analyse en cours** / **Quarantaine** / **Historique** / **Signatures** (`ScanViewModel`) |
| `Clean` | Nettoyer | `CleanControl` | Analyse / nettoyage (caches navigateurs, temp, corbeille) + **historique local** (colonne **Libéré** = `BytesDisplay`) |
| `History` | Historique | `HistoryControl` | Scans / nettoyages ; onglet **Journal** (`ReadLastLogLines`) ; export **HTML** / **PDF** (dernier ou ligne sélectionnée) |
| `Options` | Options | `OptionsControl` | Thème / `SyncWindowsTheme`, scan favori, RTP, quarantaine auto, planif. (`ServiceContainer.ScheduledScan`, prochaine exécution, **Lancer maintenant**), exclusions |

Raccourcis clavier : `Ctrl+1` … `Ctrl+5` (`KeyboardShortcuts`) — ordre des panneaux : **Vue d’ensemble**, **Antivirus**, **Nettoyer**, **Historique**, **Options**.

### 4.2 Fenêtre principale et icône

L'interface v6.0 repose sur la fenêtre principale (`MainWindow`) et la barre latérale de navigation ; il n'y a pas d'icône dédiée dans la zone de notification système dans cette branche. L'icône `optiSCAN.ico` sert à la fenêtre, à la barre des tâches et à l'installateur.

### 4.3 Panneau Antivirus (`NavigateTo("Antivirus")`)

Panneau divisé en deux colonnes :
- **Colonne gauche (210px)** : boutons de scan, **cibles récentes** (`RecentTargets` / `ScanRecentCommand`), statistiques temps réel
- **Colonne droite** : TabControl avec 4 onglets :
  - **Analyse en cours** — progression, fichier courant, grille menaces (colonne **Risque** + nom virus), actions par menace, quarantaine groupée
  - **Quarantaine** — entrées paginées, restauration / suppression, purge
  - **Historique** — sessions enregistrées (aperçu dans ce panneau ; détail complet dans le menu **Historique**)
  - **Signatures** — version de la base ClamAV, mise à jour manuelle, journaux freshclam / règles

Après chaque analyse réussie, `StartScanAsync` met à jour les **cibles récentes** (fichier/dossier scanné, ou entrée « analyse rapide » / « analyse complète »).

### 4.4 Nettoyer une menace détectée

`clamscan.exe` est un moteur de **détection uniquement** — il ne répare pas les fichiers infectés. La désinfection passe par l'isolement ou la suppression du fichier source.

Chaque ligne du tableau des menaces (`antivirusThreatsGrid`) propose deux actions :

| Bouton | Handler | Comportement |
|---|---|---|
| **Quarantaine** | `BtnQuarantineThreat_Click` → `AntivirusActions.QuarantineThreat` | Chiffrement **AES-256-GCM** ; le **nom de menace** est repris depuis la ligne du `ScanViewModel` (plus de libellé « Détecté » forcé) |
| **Supprimer** | `BtnDeleteThreat_Click` → `AntivirusActions.DeleteThreatFile` | Suppression définitive du fichier source — irréversible |

En bas du tableau, le bouton **Tout mettre en quarantaine** (`BtnQuarantineAll_Click`) traite toutes les menaces listées en une seule opération.

> **Attention :** toujours préférer la quarantaine à la suppression directe — elle permet de restaurer le fichier en cas de faux positif.

### 4.5 Pipeline de détection en parallèle

Les scans interactifs passent par `ScanViewModel.StartScanAsync` → `ScanOrchestrator` : pour chaque cible, **ClamAV** (`clamscan.exe`) et **YARA** tournent en parallèle (`Task.WhenAll`), puis fusion. Les scans **multi-dossiers** passent par `MultiTargetScanAggregator` (déduplication : même fichier + même nom de menace). Le **dossier d’installation** d’optiSCAN est exclu automatiquement (`AppInstallPaths` + `ExclusionSettings`). **`RiskScoringService`** alimente la colonne **Risque**, les toasts et le PDF (pas une étape de fusion dans l’orchestrateur).

> **clamd** — le binaire `clamd.exe` peut être livré sous `clamav/x64/`, mais **aucun client C#** n’est branché : tous les scans UI utilisent **`clamscan.exe`**.

```
ScanViewModel → ScanOrchestrator (+ ExclusionSettings + AppInstallPaths)
    │   ├─→ ClamAvEngine (clamscan.exe)  ─┐
    │   └─→ YaraEngine (.yarc + stamp)   ├── Task.WhenAll → fusion / dédup
    └─→ Progress<ScanProgress> → UI (AntivirusView)
```

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

Configurable depuis **Options → EXCLUSIONS**.

### 4.8 QuarantineManager — sécurité des fichiers infectés

Les fichiers en quarantaine sont stockés en **AES-256-GCM** (format binaire `OPTQ`, nonce et tag d’authentification).

- Clé maîtresse 256 bits, **DPAPI CurrentUser** (fichier `.key`).
- Manifeste `manifest.json` signé **HMAC-SHA256** (intégrité).

Stockage : `%LOCALAPPDATA%\optiSCAN\Quarantine\` — `{guid}.quar` + `manifest.json`. Restauration par défaut ou vers un dossier choisi : `IThreatStore.RestoreTo(quarantineId, destinationFolder)`.

### 4.9 Journaux et historique

| Fichier / service | Rôle |
|---|---|
| `ScanLogManager` → `scan_history.json` / `clean_history.json` | Historique des sessions (100 entrées max chacun) |
| `ScanLogManager` → `optiSCAN.log` | Journal texte des analyses ; lu dans **Historique → onglet Journal** |
| `AppLogger` → `optiscan-YYYY-MM-DD.log` | Logs applicatifs (composants, erreurs) ; purge **> 30 jours**, au plus **1×/jour** (marqueur `.lastcleanup` persisté) |

### 4.10 Exports PDF et HTML

- **PDF** — `PdfReportGenerator` : déclenché via `ServiceContainer` (`ExportLastScanPdfRequested`, `ExportScanSessionPdfRequested` → `MainWindow.TryExportScanSessionPdf`). Boutons **Historique** : dernier scan ou **PDF (sélection)** sur la ligne choisie.
- **HTML** — `HtmlExportService` : `RequestExportScanHistoryHtml()` depuis **Historique**.

### 4.11 Vue d'ensemble (dashboard)

Le panneau **Vue d'ensemble** (`OverviewControl`, clé `Overview`) regroupe :

- **Bannière** : état de protection (ClamAV / YARA / signatures) ; rafraîchie à chaque navigation **Overview** (`RefreshAntivirusStatus` + `UpdateAntivirusCardStatus`, signatures via `RefreshSignaturesDisplay`).
- **Quatre cartes d'action** : Nettoyer, Antivirus, Historique, mise à jour des signatures (navigation via `ServiceContainer` / `INavigationService`).
- **Trois colonnes** sous les cartes :
  - **Statistiques de protection** : synthèse textuelle sur **30 jours** (analyses, fichiers parcourus, menaces) à partir de l’historique persisté ; horodatage de dernière actualisation.
  - **Recommandations** : trois encarts (signatures / hygiène disque / activité analyses) mis à jour dynamiquement selon l’état réel des moteurs, du nettoyage et de l’historique.
  - **Cartes d'information** : état ClamAV et nombre de règles YARA, dernière analyse, résumé des versions de signatures (ClamAV + pack YARA).

---

## 5. Services avancés (modules complémentaires)

### RealTimeProtection — surveillance temps réel

`RealTimeProtection.cs` : `FileSystemWatcher` sur dossiers sensibles (profil utilisateur, `ProgramData`, `Temp`, etc.), filtre sur extensions à risque, délai de stabilisation, déduplication et **SemaphoreSlim(3)** parallèle. Une instance est créée dans **`ServiceContainer`** ; **Options** active ou coupe la surveillance et persiste le réglage. Les menaces détectées remontent vers l’UI (badge / liste) via événements consommés par **`MainWindow`**.

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

## 6. Workflow utilisateur optiSCAN v6.0

```
DÉMARRAGE (UI)
    │
    ├─→ Mutex single-instance (2e instance → IPC « afficher » la fenêtre existante)
    ├─→ `App.OnStartup` → `ThemeManager.Initialize()` (préférence `UserPreferences`)
    ├─→ `MainWindow` + `ServiceContainer.Default` (ClamAV, YARA, orchestrateur, MAJ, quarantaine, planif., logs, `AntivirusActions`, `ThreatLookup` → VM)
    ├─→ Minuteries MAJ : freshclam **4 h**, règles YARA **24 h** (désactivables via Options)
    ├─→ `ScanViewModel.InitializeAsync` : versions, base, YARA, historique, quarantaine
    ├─→ Protection temps réel : état selon **Options** (`ServiceContainer.RealTimeProtection`)
    └─→ Fenêtre principale — pas d’icône dédiée dans la zone de notification (réduction = fenêtre masquée)
            │
            ├─→ [VUE D'ENSEMBLE] — cartes d’action, statistiques 30 j., recommandations dynamiques, état antivirus / signatures
            ├─→ [NETTOYER] — temporaires, caches navigateurs (Edge, Chrome, Firefox, Brave, **Opera**, **Vivaldi**, **Arc**), corbeille, journaux Windows
            ├─→ [ANTIVIRUS] — scans rapide/complet/dossier/fichier, quarantaine, historique de session, signatures
            ├─→ [HISTORIQUE] — sessions enregistrées ; exports **HTML** / **PDF**
            └─→ [OPTIONS] — thème clair/sombre, sync thème Windows, scan favori, démarrage auto, MAJ auto, RTP, quarantaine auto, planification, exclusions

FERMETURE
    └─→ `MainWindow.OnWindowClosing` → `PerformCleanShutdown` → `ServiceContainer.Shutdown()` (RTP, minuteries MAJ, moteurs)

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

## 8. Packaging final (v6.0)

Exécuter depuis la **racine du dépôt** (dossier contenant `optiSCAN.sln`). La sortie du profil **FolderProfile** est `optiSCAN\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64\` (chemin attendu par `installer\setup.iss`).

**Étape A — publication .NET**

```powershell
dotnet publish .\optiSCAN\optiSCAN.csproj -c Release /p:PublishProfile=FolderProfile
```

**Étape B — première base ClamAV** (adapter `$pub` si vous publiez ailleurs)

```powershell
$pub = ".\optiSCAN\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64"
& "$pub\clamav\x64\freshclam.exe" --datadir="$pub\clamav\x64\database"
```

**Étape C — compilateur Inno Setup**

```powershell
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" .\installer\setup.iss
```

Sortie typique : `installer\output\optiSCAN_Setup_v6.0.0.exe` (versions dans `#define` de `setup.iss`).

**Variante** : `dotnet publish ... -c Release -r win-x64 -o <dossier>` avec le même dossier que **`PublishDir`** du profil **FolderProfile**, pour que **`setup.iss`** trouve `optiSCAN.exe`.

**Contenu de l'installateur (~260 Mo avec signatures initiales) :**

```
optiSCAN_Setup_v6.0.0.exe
    ├── optiSCAN.exe
    ├── optiSCAN.ico
    ├── *.dll (runtime .NET 8)
    ├── clamav/x64/          ← Binaires x86-64 (clamscan + clamd) + base de signatures
    ├── yara/                ← Binaires du moteur de détection
    └── rules/               ← Règles de détection initiales
```

---

## 9. Dépendances et licences

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

## 10. Historique des versions produit

### v6.0 — Version majeure (publication)

- **Versioning unifié** — nom **v6.0** + build **6.0.0** (`Directory.Build.props`, Inno Setup, **LICENSE.txt**, manifeste, rapports PDF/HTML)
- **Expérience d’analyse** — libellés utilisateur unifiés (`ScanUserDisplay`) ; progression multi-cibles cumulative ; rafraîchissement Vue d’ensemble via navigation et fin de scan
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
- **OverviewControl** — 4 cartes d'action cliquables (Border + `MouseLeftButtonUp`, sans ControlTemplate) ; cercles d'icônes neutres (`SurfaceBg`) ; carte "État Antivirus" enrichie (ClamAV + YARA en temps réel)
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
- Binaire **clamd** livré sous `clamav/` (non utilisé par le pipeline UI actuel)
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
- Historique des scans (JSON, 100 entrées)
- Mise à jour automatique signatures (4 h) et règles (24 h)
- Système d'exclusions (dossiers + règles)
- Nettoyage fichiers temporaires

---

## 11. Crédits

Développé par **© 2026 Donatien Byakombe**  
Design system : **Donaby Design**
