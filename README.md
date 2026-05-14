# Guide Complet — optiSCAN v4.0

> **Version de référence.** Ce guide décrit l'architecture, les modules et les procédures
> de la version **v4.0** du produit (build **4.0.0**, édition ClamAV). Architecture mono-fenêtre avec services avancés Phase 2 + Donaby Design System.
>
> **Nomenclature (comme v1.0 / v2.0 / v3.0)** — **v4.0** : nom de release (documentation, CLUF). **4.0.0** : identifiant d’assembly et d’installateur (`Directory.Build.props`, Inno Setup).
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
| **5** | Services complémentaires (clamd côté code, RTP, planificateur, notifications, scoring) |
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
| Compatibilité Windows | ✅ Natif | ⚠ Multi-plateforme (overhead) | ✅ Natif |
| Intégration ClamAV | ✅ Process.Start / TCP clamd | ✅ Process.Start | ✅ libclamav directe |
| MVVM + Binding UI | ✅ Excellent | ⚠ Différent | ❌ Manuel |
| **Verdict** | **✅ Retenu** | Non nécessaire | Non nécessaire |

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
    ├── Services/
    │   ├── ClamAvEngine.cs            ← Lance clamscan.exe, parse la sortie
    │   ├── ClamDaemon.cs              ← Client TCP clamd (prêt, non branché au pipeline scan)
    │   ├── FreshclamUpdater.cs        ← Mise à jour signatures via freshclam.exe
    │   ├── ThemeManager.cs            ← Bascule Donaby + MaterialDesign (UserPreferences)
    │   ├── ExclusionSettings.cs       ← Dossiers et règles exclus (singleton JSON)
    │   ├── YaraEngine.cs              ← Moteur de détection comportementale
    │   ├── YaraForgeUpdater.cs        ← Mise à jour automatique règles de détection
    │   ├── ServiceContainer.cs        ← Singleton : ClamAV, YARA, orchestrateur, MAJ, quarantaine, RTP, logs…
    │   ├── ScanOrchestrator.cs        ← Pipeline ClamAV + YARA en parallèle
    │   ├── QuarantineManager.cs       ← Quarantaine chiffrée (AES-GCM), manifeste signé
    │   ├── ScanLogManager.cs          ← Historique JSON + journal texte
    │   ├── RealTimeProtection.cs      ← Surveillance FileSystemWatcher (démarrage selon Options)
    │   ├── ScheduledScanService.cs    ← Tâche planifiée Windows (schtasks.exe)
    │   ├── IpcManager.cs              ← Instance unique : message WM_SHOWME
    │   ├── HtmlExportService.cs       ← Rapport HTML (export depuis l’onglet Historique)
    │   ├── SignatureUpdateCoordinator.cs ← Enchaînement freshclam + règles (hors code-behind lourd)
    │   ├── NotificationService.cs     ← Toasts Windows natifs
    │   ├── RiskScoringService.cs      ← Score 0-100 par menace
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

> ⚠ La version `win.arm64` cause l'erreur `0xc000007b` sur les machines Intel/AMD.

### 3.2 Placer les binaires dans le projet

```
<racine du dépôt>/optiSCAN/clamav/x64/
    ├── clamscan.exe
    ├── clamd.exe              ← mode démon TCP (binaire présent ; pipeline UI = clamscan)
    ├── freshclam.exe
    ...
```

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

## 4. Architecture mono-fenêtre (v4.0)

Les sous-sections **4.1** à **4.11** suivent une lecture « produit » : navigation et panneaux, détail du panneau Antivirus, menaces et pipeline, options techniques (MAJ, exclusions, quarantaine, logs), exports, puis contenu de la vue d’ensemble.

### 4.1 Les 5 panneaux de MainWindow

Les vues sont empilées dans un seul `Grid` (`MainWindow.xaml`) : une seule est `Visible`, les autres `Collapsed`. La navigation passe par `NavigationService.NavigateTo("…")` (clés insensibles à la casse), enregistrées dans `MainWindow.RegisterPanels()`.

| Clé `NavigateTo` | Panneau | Contrôle | Rôle principal |
|---|---|---|---|
| `Overview` | Vue d'ensemble | `OverviewControl` | Cartes d'action, statistiques 30 j., recommandations dynamiques, état ClamAV/YARA et signatures |
| `Antivirus` | Antivirus | `AntivirusView` | Scans ; onglets **Analyse en cours** / **Quarantaine** / **Historique** / **Signatures** (`ScanViewModel`) |
| `Clean` | Nettoyer | `CleanControl` | Analyse / suppression des fichiers temporaires et caches (ex. Brave, journaux Windows) |
| `History` | Historique | `HistoryControl` | Sessions de scan et nettoyages ; export rapport **HTML** / **PDF** (dernier scan) |
| `Options` | Options | `OptionsControl` | Démarrage Windows, MAJ auto signatures + règles, protection temps réel, quarantaine auto, **planification** (`schtasks`), exclusions |

Raccourcis clavier : `Ctrl+1` … `Ctrl+5` (`KeyboardShortcuts`) — ordre des panneaux : **Vue d’ensemble**, **Antivirus**, **Nettoyer**, **Historique**, **Options**.

### 4.2 Fenêtre principale et icône

L'interface v4.0 repose sur la fenêtre principale (`MainWindow`) et la barre latérale de navigation ; il n'y a pas d'icône dédiée dans la zone de notification système dans cette branche. L'icône `optiSCAN.ico` sert à la fenêtre, à la barre des tâches et à l'installateur.

### 4.3 Panneau Antivirus (`NavigateTo("Antivirus")`)

Panneau divisé en deux colonnes :
- **Colonne gauche (210px)** : boutons de scan + statistiques en temps réel
- **Colonne droite** : TabControl avec 4 onglets :
  - **Analyse en cours** — progression, fichier courant, liste des menaces, actions par menace, quarantaine groupée
  - **Quarantaine** — entrées paginées, restauration / suppression, purge
  - **Historique** — sessions enregistrées (aperçu dans ce panneau ; détail complet dans le menu **Historique**)
  - **Signatures** — version de la base ClamAV, mise à jour manuelle, journaux freshclam / règles

### 4.4 Nettoyer une menace détectée

`clamscan.exe` est un moteur de **détection uniquement** — il ne répare pas les fichiers infectés. La désinfection passe par l'isolement ou la suppression du fichier source.

Chaque ligne du tableau des menaces (`antivirusThreatsGrid`) propose deux actions :

| Bouton | Handler | Comportement |
|---|---|---|
| **Quarantaine** | `BtnQuarantineThreat_Click` | Chiffre le fichier (**AES-256-GCM** via `QuarantineManager`) et le déplace sous `%LOCALAPPDATA%\optiSCAN\Quarantine\` — réversible (restauration) |
| **Supprimer** | `BtnDeleteThreat_Click` | Demande confirmation, supprime définitivement le fichier — irréversible |

En bas du tableau, le bouton **Tout mettre en quarantaine** (`BtnQuarantineAll_Click`) traite toutes les menaces listées en une seule opération.

> ⚠ Toujours préférer la quarantaine à la suppression directe — elle permet de restaurer le fichier en cas de faux positif.

### 4.5 Pipeline de détection en parallèle

Les scans interactifs passent par `ScanViewModel.StartScanAsync` → `ScanOrchestrator` : pour chaque cible, **ClamAV** (`clamscan.exe` via `ClamAvEngine`) et **YARA** (`YaraEngine`) tournent en parallèle (`Task.WhenAll`), puis fusion des résultats. **`RiskScoringService`** est utilisé pour les **toasts** et le **rapport PDF**, pas comme étape interne obligatoire de fusion dans l’orchestrateur. Le fichier `ClamDaemon.cs` fournit un client **clamd** TCP (port 3310) prêt à l’emploi, mais **n’est pas encore branché** sur ce pipeline (les scans utilisent `clamscan`).

```
ScanViewModel → ScanOrchestrator (+ ExclusionSettings.Current)
    │   ├─→ ClamAvEngine (clamscan.exe)  ─┐
    │   └─→ YaraEngine                   ├── Task.WhenAll → fusion menaces
    │         (règles filtrées)            ┘
    └─→ Progress<ScanProgress> → UI (AntivirusView / bindings)
```

### 4.6 Mise à jour des signatures

**Manuel** — `BtnManualUpdateSignatures_Click` enchaîne `FreshclamUpdater.UpdateAsync()` puis `YaraForgeUpdater.UpdateAsync()` (journal dans l’onglet Signatures).

**Automatique** — À l’instanciation de `ServiceContainer.Default`, les minuteries sont armées : **ClamAV toutes les 4 h**, **paquet YARA-Forge toutes les 24 h**. La case **Mise à jour automatique des signatures** dans **Options** coupe ou réactive **les deux** services (`DisableAutoUpdate` / `EnableAutoUpdate`).

### 4.7 Système d'exclusions

`ExclusionSettings.Current` (singleton) persiste dans :
```
%LOCALAPPDATA%\optiSCAN\exclusions.json
```

- **Dossiers exclus** : fichiers dans ces dossiers sautés lors du scan YARA
- **Règles exclues** : matches filtrés (ex. `SuspiciousDownloads` — exclu par défaut)

Configurable depuis **Options → EXCLUSIONS**.

### 4.8 QuarantineManager — sécurité des fichiers infectés

Les fichiers en quarantaine sont stockés en **AES-256-GCM** (format binaire `OPTQ`, nonce et tag d’authentification).

- Clé maîtresse 256 bits, **DPAPI CurrentUser** (fichier `.key`).
- Manifeste `manifest.json` signé **HMAC-SHA256** (intégrité).

Stockage : `%LOCALAPPDATA%\optiSCAN\Quarantine\` — `{guid}.quar` + `manifest.json`.

### 4.9 ScanLogManager — persistance

- Historique : `%LOCALAPPDATA%\optiSCAN\Logs\scan_history.json` (100 entrées max)
- Journal : `%LOCALAPPDATA%\optiSCAN\Logs\optiSCAN.log`

### 4.10 Exports PDF et HTML

- **PDF** — `PdfReportGenerator` (QuestPDF) : rapport A4 (résumé, évaluation de risque si menaces, tableau des menaces, pied de page). Sortie typique : `%LOCALAPPDATA%\optiSCAN\Reports\SCAN_{Type}_{yyyyMMdd_HHmmss}.pdf` (`GenerateAndSave`).
- **HTML** — `HtmlExportService` : rapport depuis l’onglet **Historique** (sessions, quarantaine, préférences), enregistrement au chemin choisi par l’utilisateur.

### 4.11 Vue d'ensemble (dashboard)

Le panneau **Vue d'ensemble** (`OverviewControl`, clé `Overview`) regroupe :

- **Bannière** : état de protection (ClamAV / YARA / signatures) et libellé principal, rafraîchi au chargement et après les mises à jour.
- **Quatre cartes d'action** : Nettoyer, Antivirus, Historique, mise à jour des signatures (navigation via `ServiceContainer` / `INavigationService`).
- **Trois colonnes** sous les cartes :
  - **Statistiques de protection** : synthèse textuelle sur **30 jours** (analyses, fichiers parcourus, menaces) à partir de l’historique persisté ; horodatage de dernière actualisation.
  - **Recommandations** : trois encarts (signatures / hygiène disque / activité analyses) mis à jour dynamiquement selon l’état réel des moteurs, du nettoyage et de l’historique.
  - **Cartes d'information** : état ClamAV et nombre de règles YARA, dernière analyse, résumé des versions de signatures (ClamAV + pack YARA).

---

## 5. Services avancés (modules complémentaires)

> **Note** — **ClamDaemon** (TCP clamd) est présent dans le code mais **n’alimente pas** le pipeline de scan interactif (`clamscan` par défaut). Les autres blocs correspondent au comportement actuel de l’application.

### ClamDaemon — mode démon TCP (code prêt, non branché au pipeline)

`ClamDaemon.cs` implémente démarrage de `clamd.exe`, génération de `clamd.conf`, connexion **TCP 127.0.0.1:3310** et commandes `SCAN` / statistiques, avec garde-fous (vérification du PID à l’écoute). **Les scans utilisateur passent aujourd’hui uniquement par `clamscan.exe`** (`ClamAvEngine`) ; l’activation « Utiliser clamd » dans l’UI n’est pas câblée.

### RealTimeProtection — surveillance temps réel

`RealTimeProtection.cs` : `FileSystemWatcher` sur dossiers sensibles (profil utilisateur, `ProgramData`, `Temp`, etc.), filtre sur extensions à risque, délai de stabilisation, déduplication et **SemaphoreSlim(3)** parallèle. Une instance est créée dans **`ServiceContainer`** ; **Options** active ou coupe la surveillance et persiste le réglage. Les menaces détectées remontent vers l’UI (badge / liste) via événements consommés par **`MainWindow`**.

### ScheduledScanService — tâche planifiée Windows

`ScheduledScanService.cs` enveloppe **`schtasks.exe`** (`/Create`, `/Delete`, `/Query`, `/Run`) pour la tâche **`optiSCAN_DailyScan`** (`optiSCAN.exe --fullscan --quiet`, **`/RL LIMITED`**, quotidien à **02:00** par défaut). La case **Planifier une analyse quotidienne** dans **Options** crée ou supprime cette tâche. **`App.xaml.cs`** gère `--fullscan` / `--quickscan` / `--quiet` en **mode headless** (y compris quarantaine auto si l’option est activée).

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

`RiskScoringService.cs` attribue un score numérique (0–100+) à chaque menace selon trois critères cumulatifs :

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

## 6. Workflow utilisateur optiSCAN v4.0

```
DÉMARRAGE (UI)
    │
    ├─→ Mutex single-instance (2e instance → IPC « afficher » la fenêtre existante)
    ├─→ `App.OnStartup` → `ThemeManager.Initialize()` (préférence `UserPreferences`)
    ├─→ `MainWindow` + `ServiceContainer.Default` (services partagés : ClamAV, YARA, orchestrateur, MAJ, quarantaine, logs, notifications, `AntivirusActions`)
    ├─→ Minuteries MAJ : freshclam **4 h**, règles YARA **24 h** (désactivables via Options)
    ├─→ `ScanViewModel.InitializeAsync` : versions, base, YARA, historique, quarantaine
    ├─→ Protection temps réel : état selon **Options** (`ServiceContainer.RealTimeProtection`)
    └─→ Fenêtre principale — pas d’icône dédiée dans la zone de notification (réduction = fenêtre masquée)
            │
            ├─→ [VUE D'ENSEMBLE] — cartes d’action, statistiques 30 j., recommandations dynamiques, état antivirus / signatures
            ├─→ [NETTOYER] — analyse et suppression des temporaires (avec confirmation)
            ├─→ [ANTIVIRUS] — scans rapide/complet/dossier/fichier, quarantaine, historique de session, signatures
            ├─→ [HISTORIQUE] — sessions enregistrées ; exports **HTML** / **PDF**
            └─→ [OPTIONS] — démarrage auto, MAJ auto, RTP, quarantaine auto, planification, exclusions

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
| Mode clamd (TCP daemon) | ✅ Gain théorique majeur — **module présent, non utilisé par le pipeline actuel** |
| Pipeline parallèle (Task.WhenAll) | ✅ ClamAV + YARA simultanés sur chaque cible |
| Règles pré-compilées (_compiled.yarc) | ✅ Scan comportemental accéléré |
| SemaphoreSlim(3) RTP | ✅ `RealTimeProtection` (activable depuis Options) |
| Scan rapide limité aux dossiers critiques | ✅ `ScanTargets.QuickScanTargets()` |
| ExclusionSettings.Current (singleton lazy) | ✅ Pas de rechargement JSON par fichier |
| ServiceContainer (singleton services) | ✅ Une instance ClamAV/YARA/orchestrateur pour toute l’app |
| ThemeManager + UserPreferences | ✅ Bascule de thème sans redémarrage |

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

## 8. Packaging final (v4.0)

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

Sortie typique : `installer\output\optiSCAN_Setup_v4.0.0.exe` (versions dans `#define` de `setup.iss`).

**Variante** : `dotnet publish ... -c Release -r win-x64 -o <dossier>` avec le même dossier que **`PublishDir`** du profil **FolderProfile**, pour que **`setup.iss`** trouve `optiSCAN.exe`.

**Contenu de l'installateur (~260 Mo avec signatures initiales) :**

```
optiSCAN_Setup_v4.0.0.exe
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
| Planificateur de tâches (`schtasks.exe`) | — | — | Natif Windows — voir `ScheduledScanService` |
| Microsoft.Toolkit.Uwp.Notifications | 7.1.3 | MIT | Toasts Windows natifs |
| Inno Setup | 6.x | Freeware | Gratuit pour projets commerciaux |
| Base de signatures ClamAV | — | ClamAV License | Mise à jour depuis database.clamav.net |
| Règles de détection | — | Diverses open-source | Récupérées depuis YARA-Forge |

---

## 10. Historique des versions produit

### v4.0 — Version majeure (alignement produit)

- **Versioning unifié** — nom **v4.0** + build **4.0.0** (`Directory.Build.props`, Inno Setup, **LICENSE.txt**, manifeste, rapports PDF/HTML)
- **Interface d’analyse** — progression, fichier courant, fusion ClamAV + YARA (`ScanOrchestrator`)
- **Vue d’ensemble** — statistiques sur 30 jours, recommandations et bannière de protection **branchées** sur les services et l’historique
- **Options** — temps réel, quarantaine auto, MAJ signatures, planification `schtasks`, exclusions et démarrage Windows reliés au stockage et au **`ServiceContainer`**
- **Historique** — export rapport **HTML** (aperçu complet) et **PDF** (dernière session enregistrée)
- **Quarantaine** — format stockage **AES-256-GCM** (`OPTQ`) ; alignement silencieux des fichiers au format attendu au démarrage
- **Instance unique** — seconde exécution : **IPC** (`IpcManager`, WM_SHOWME) pour réafficher la fenêtre existante
- **Manifeste** — **`asInvoker`** + élévation ponctuelle (`ElevationHelper`) pour réduire la surface d’attaque
- **Français** — libellés et documentation alignés sur le comportement réel de l’application

### v3.0 — Donaby Design System + Stabilisation

- **Donaby Design System complet** — refonte UI vers le thème clair Donaby Light par défaut
- **OverviewControl** — 4 cartes d'action cliquables (Border + `MouseLeftButtonUp`, sans ControlTemplate) ; cercles d'icônes neutres (`SurfaceBg`) ; carte "État Antivirus" enrichie (ClamAV + YARA en temps réel)
- **AntivirusView** — zone drag & drop redessinée (Rectangle dashed border, `TrayArrowDown`, 62px) ; menu "Cibles récentes" (dead code) supprimé
- **CleanControl** — support complet `chkBrave` (cache Brave Browser) et `chkLogs` (journaux Windows) dans analyse et nettoyage
- **FreshclamUpdater** — `EnsureConfExists()` : résolution automatique du conf manquant (`x64\` → parent → `x86` → génération) ; `ResolveDbDir()` : résolution intelligente du dossier de base de données selon la hiérarchie clamav
- ✅ Correction CS0104 `CheckBox`/`Button` ambiguous — aliases `WpfCheckBox`/`WpfButton` dans `OptionsControl.xaml.cs`
- ✅ **README aligné code** — navigation, quarantaine AES-GCM, pipeline clamscan + YARA, RTP / planificateur / packaging
- ✅ **MAJ auto** — `ServiceContainer` arme freshclam (4 h) + YARA-Forge (24 h) ; Options coupe/réactive les deux

### v2.0 — Phase 2 : Services Avancés + Donaby Design

- **Donaby Design** — thème sombre/clair dynamique (`ThemeManager`, tokens `DynamicResource`)
- Icône **system tray** (expérimental dans les versions précédentes ; l’UI actuelle reste fenêtre principale uniquement)
- **Nettoyer par menace** — boutons Quarantaine + Supprimer par ligne dans le tableau des menaces
- Correction affichage **version signatures ClamAV** (regex `ClamAV-VDB:[^:]+:(\d+):`)
- Mode démon **clamd** (TCP 3310) — scan sans rechargement signatures
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
