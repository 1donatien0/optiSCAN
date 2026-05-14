# Guide Complet — optiSCAN v4.0

> **Version de référence.** Ce guide décrit l'architecture, les modules et les procédures
> de la version **v4.0** du produit (build **4.0.0**, édition ClamAV). Architecture mono-fenêtre avec services avancés Phase 2 + Donaby Design System.
>
> **Nomenclature (comme v1.0 / v2.0 / v3.0)** — **v4.0** : nom de release (documentation, CLUF). **4.0.0** : identifiant d’assembly et d’installateur (`Directory.Build.props`, Inno Setup).
>
> **Design system : Donaby Design** — thème sombre/clair dynamique, tokens DynamicResource WPF.
> Développé par **© 2026 Donatien Byakombe (Dona By)**.

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
    │   ├── ScanOrchestrator.cs        ← Pipeline ClamAV + détection en parallèle
    │   ├── QuarantineManager.cs       ← Déplace/restaure/supprime les fichiers infectés
    │   ├── ScanLogManager.cs          ← Historique JSON + journal texte
    │   ├── RealTimeProtection.cs      ← FileSystemWatcher sur dossiers critiques
    │   ├── ScheduledScanService.cs    ← Tâche planifiée via schtasks.exe
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

### 4.1 Les 5 panneaux de MainWindow

Les vues sont empilées dans un seul `Grid` (`MainWindow.xaml`) : une seule est `Visible`, les autres `Collapsed`. La navigation passe par `NavigationService.NavigateTo("…")` (clés insensibles à la casse), enregistrées dans `MainWindow.RegisterPanels()`.

| Clé `NavigateTo` | Panneau | Contrôle | Rôle principal |
|---|---|---|---|
| `Overview` | Vue d'ensemble | `OverviewControl` | Cartes d'action, graphique illustratif, recommandations, état ClamAV/YARA et versions |
| `Clean` | Nettoyer | `CleanControl` | Analyse / suppression des fichiers temporaires et caches (ex. Brave, journaux Windows) |
| `Antivirus` | Antivirus | `AntivirusView` | Scans, onglets Scan / Quarantaine / Historique / Signatures (`ScanViewModel`) |
| `History` | Historique | `HistoryControl` | Liste des sessions enregistrées |
| `Options` | Options | `OptionsControl` | Démarrage Windows, notifications, MAJ auto signatures+règles, cases antivirus (RTP / quarantaine auto — UI présente, branchement incomplet), exclusions |

Raccourcis clavier : `Ctrl+1` … `Ctrl+5` (`KeyboardShortcuts`) mappés sur cet ordre : Overview, Clean, Antivirus, History, Options.

### 4.2 Fenêtre principale et icône

L'interface v4.0 repose sur la fenêtre principale (`MainWindow`) et la barre latérale de navigation ; il n'y a pas d'icône dédiée dans la zone de notification système dans cette branche. L'icône `optiSCAN.ico` sert à la fenêtre, à la barre des tâches et à l'installateur.

### 4.3 Panneau Antivirus (`NavigateTo("Antivirus")`)

Panneau divisé en deux colonnes :
- **Colonne gauche (210px)** : boutons de scan + statistiques en temps réel
- **Colonne droite** : TabControl avec 4 onglets :
  - **Scan en cours** — progression, liste des menaces, actions par menace, quarantaine globale
  - **Quarantaine** — fichiers mis en quarantaine, restauration/suppression unitaire
  - **Historique** — tous les scans enregistrés (horodatés)
  - **Signatures** — version base ClamAV, MAJ manuelle, logs freshclam

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

Les fichiers en quarantaine sont chiffrés en **AES-256-GCM** (format binaire `OPTQ` v2, nonce + tag d’authentification). L’ancien format **XOR 0x5A** (v1) reste pris en charge en **lecture seule** pour migration.

- Clé maîtresse 256 bits, stockée chiffrée **DPAPI CurrentUser** (fichier `.key` à côté du manifeste).
- Manifeste `manifest.json` signé **HMAC-SHA256** (intégrité).

Stockage : `%LOCALAPPDATA%\optiSCAN\Quarantine\` — fichiers `{guid}.quar` + `manifest.json`.

### 4.9 ScanLogManager — persistance

- Historique : `%LOCALAPPDATA%\optiSCAN\Logs\scan_history.json` (100 entrées max)
- Journal : `%LOCALAPPDATA%\optiSCAN\Logs\optiSCAN.log`

---

## 5. Services avancés

> **Transparence code / README** — Les sections ci-dessous décrivent des **modules présents dans le dépôt**. Lorsque l’intégration UI ou le pipeline de scan n’est pas encore branché, c’est indiqué explicitement.

### 5.1 ClamDaemon — mode démon TCP (code prêt, non branché au pipeline)

`ClamDaemon.cs` implémente démarrage de `clamd.exe`, génération de `clamd.conf`, connexion **TCP 127.0.0.1:3310** et commandes `SCAN` / statistiques, avec garde-fous (vérification du PID à l’écoute). **Les scans utilisateur passent aujourd’hui uniquement par `clamscan.exe`** (`ClamAvEngine`) ; l’activation « Utiliser clamd » dans l’UI n’est pas câblée.

### 5.2 RealTimeProtection — surveillance temps réel (implémenté, non branché)

`RealTimeProtection.cs` décrit la surveillance `FileSystemWatcher` (dossiers utilisateur / `ProgramData` / `Temp`, extensions dangereuses), délai de stabilisation, déduplication et **SemaphoreSlim(3)**. La classe n’est **pas encore instanciée** depuis `ServiceContainer` ou `MainWindow` ; la case **Protection temps réel** dans Options n’appelle pas ce service (branchement à compléter).

### 5.3 ScheduledScanService — tâche planifiée Windows (API prête)

`ScheduledScanService.cs` enveloppe **`schtasks.exe`** (`/Create`, `/Delete`, `/Query`, `/Run`) pour la tâche **`optiSCAN_DailyScan`** (`optiSCAN.exe --fullscan --quiet`, `/RL HIGHEST`, quotidien à 02:00 par défaut). **Aucun écran Options ne crée encore la tâche** ; en revanche `App.xaml.cs` gère bien `--fullscan` / `--quickscan` / `--quiet` en **mode headless** pour l’automatisation ou une tâche créée manuellement.

### 5.4 NotificationService — toasts Windows natifs

`NotificationService.cs` utilise `Microsoft.Toolkit.Uwp.Notifications` pour envoyer des toasts système Windows :

| Méthode | Contenu |
|---|---|
| `ShowThreatDetected(threat)` | Alerte longue avec boutons Quarantaine / Ignorer / Ouvrir |
| `ShowQuarantined(threat)` | Confirmation de mise en quarantaine |
| `ShowScanCompleted(files, threats)` | Résumé de fin de scan |
| `ShowUpdateAvailable(version)` | Nouvelle mise à jour disponible |
| `ShowRealTimeProtectionStarted()` | Confirmation d'activation de la RTP |

### 5.5 RiskScoringService — score de risque par menace

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

### 5.6 PdfReportGenerator — rapport PDF

`PdfReportGenerator.cs` utilise **QuestPDF** (licence Community) pour générer un rapport A4 en PDF :

- En-tête : titre « optiSCAN », date, version
- Bloc résumé : fichiers scannés, menaces, durée
- Bloc évaluation risque (si menace critique détectée)
- Tableau des menaces : nom du fichier, virus, moteur, horodatage
- Pied de page : numéros de page

Sortie : `%LOCALAPPDATA%\optiSCAN\Reports\optiSCAN_Report_YYYYMMDD_HHmmss.pdf`

---

## 6. Dashboard Vue d'ensemble

Le panneau **Vue d'ensemble** (`OverviewControl`, entrée de menu **Vue d'ensemble**) comprend notamment :

- **Bannière** : message de protection et état des définitions.
- **Quatre cartes d'action** : raccourcis vers Nettoyer, Antivirus, Historique et la mise à jour des signatures.
- **Trois colonnes** sous les cartes :
  - **Statistiques de Protection** : graphique décoratif (polylignes statiques sur `Canvas`) avec légende « Menaces / Scans » — illustration visuelle, pas un historique dynamique branché sur les données réelles.
  - **Recommandations d'Action** : encarts d'état (ex. système à jour, nettoyage conseillé).
  - **Cartes d'information** : état ClamAV / YARA, dernière analyse, versions des signatures ClamAV et du pack YARA (alimentées par `MainWindow` / `ScanViewModel`).

---

## 7. Workflow utilisateur optiSCAN v4.0

```
DÉMARRAGE (UI)
    │
    ├─→ Mutex single-instance (2e instance → IPC « afficher » la fenêtre existante)
    ├─→ `App.OnStartup` → `ThemeManager.Initialize()` (préférence `UserPreferences`)
    ├─→ `MainWindow` + `ServiceContainer.Default` (services partagés : ClamAV, YARA, orchestrateur, MAJ, quarantaine, logs, notifications, `AntivirusActions`)
    ├─→ Minuteries MAJ : freshclam **4 h**, règles YARA **24 h** (désactivables via Options)
    ├─→ `ScanViewModel.InitializeAsync` : versions, base, YARA, historique, quarantaine
    └─→ Fenêtre principale — pas d’icône zone de notification dédiée
            │
            ├─→ [VUE D'ENSEMBLE] — cartes d’action, graphique illustratif, recommandations, état antivirus / signatures
            ├─→ [NETTOYER] — analyse et suppression des temporaires (avec confirmation)
            ├─→ [ANTIVIRUS] — scans rapide/complet/dossier/fichier, quarantaine, PDF, signatures
            ├─→ [HISTORIQUE] — sessions enregistrées
            └─→ [OPTIONS] — démarrage auto, notifications, MAJ auto, exclusions ; cases RTP / quarantaine auto (UI, câblage partiel)

DÉMARRAGE (ligne de commande)
    `--fullscan` / `--quickscan` [+ `--quiet` ] → `App.RunHeadlessAsync` : orchestrateur, journal, quarantaine auto si `ExclusionSettings.Current.AutoQuarantineEnabled`, notification fin si menaces et non quiet.
```

---

## 8. Bonnes pratiques

### 8.1 Permissions et droits

```xml
<!-- app.manifest — OBLIGATOIRE pour scanner C:\Windows -->
<requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
```

### 8.2 Performance

| Technique | Impact |
|---|---|
| Mode clamd (TCP daemon) | ✅ Gain théorique majeur — **module présent, non utilisé par le pipeline actuel** |
| Pipeline parallèle (Task.WhenAll) | ✅ ClamAV + YARA simultanés sur chaque cible |
| Règles pré-compilées (_compiled.yarc) | ✅ Scan comportemental accéléré |
| SemaphoreSlim(3) RTP | ✅ Prévu dans `RealTimeProtection` (non branché) |
| Scan rapide limité aux dossiers critiques | ✅ `ScanTargets.QuickScanTargets()` |
| ExclusionSettings.Current (singleton lazy) | ✅ Pas de rechargement JSON par fichier |
| ServiceContainer (singleton services) | ✅ Une instance ClamAV/YARA/orchestrateur pour toute l’app |
| ThemeManager + UserPreferences | ✅ Bascule de thème sans redémarrage |

### 8.3 Faux positifs

- `SuspiciousDownloads` exclue par défaut (trop agressive sur le dossier Downloads)
- Ne jamais supprimer automatiquement — toujours mettre en quarantaine en premier
- L'utilisateur confirme avant toute action destructrice (boîte de dialogue `MessageBoxButton.YesNo`)
- Le test EICAR est géré normalement par ClamAV (aucun traitement spécial dans le scoring)

### 8.4 Exclusion Windows Defender

```powershell
Add-MpPreference -ExclusionPath "C:\Program Files\optiSCAN\clamav\database"
```

---

## 9. Packaging final (v4.0)

```powershell
# 1. À la racine du dépôt (dossier contenant optiSCAN.sln)
dotnet publish .\optiSCAN\optiSCAN.csproj -c Release -r win-x64 --self-contained false -o .\build\app

# 2. Première base ClamAV (exemple)
.\build\app\clamav\x64\freshclam.exe --datadir=".\build\app\clamav\x64\database"

# 3. Inno Setup
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" .\installer\setup.iss
# → installer\output\optiSCAN_Setup_v4.0.0.exe (voir #define AppVersion dans setup.iss)
```

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

## 10. Dépendances et licences

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

## 11. Historique des versions

### v4.0 — Version majeure (alignement produit)

- **Versioning unifié** — même convention que les releases précédentes : nom **v4.0** + build **4.0.0** (`Directory.Build.props`, Inno `AppVersion` / `AppRelease`, CLUF **LICENSE.txt**, manifeste, rapports PDF/HTML, User-Agent réseau)
- **Interface d’analyse** — bannière « analyse en cours », progression, fichier courant (ClamAV / YARA / agrégateur multi-cibles)
- **Vue d’ensemble** — retrait du graphique décoratif trompeur ; textes et recommandations alignés sur l’état réel
- **Dernière analyse** — rafraîchissement depuis l’historique après scan et au chargement
- **Français** — ton et libellés (crédits Dona By, statuts, options) harmonisés

### v3.0 — Donaby Design System + Stabilisation

- **Donaby Design System complet** — refonte UI vers le thème clair Donaby Light par défaut
- **OverviewControl** — 4 cartes d'action cliquables (Border + `MouseLeftButtonUp`, sans ControlTemplate) ; cercles d'icônes neutres (`SurfaceBg`) ; carte "État Antivirus" enrichie (ClamAV + YARA en temps réel)
- **AntivirusView** — zone drag & drop redessinée (Rectangle dashed border, `TrayArrowDown`, 62px) ; menu "Cibles récentes" (dead code) supprimé
- **CleanControl** — support complet `chkBrave` (cache Brave Browser) et `chkLogs` (journaux Windows) dans analyse et nettoyage
- **FreshclamUpdater** — `EnsureConfExists()` : résolution automatique du conf manquant (`x64\` → parent → `x86` → génération) ; `ResolveDbDir()` : résolution intelligente du dossier de base de données selon la hiérarchie clamav
- ✅ Correction CS0104 `CheckBox`/`Button` ambiguous — aliases `WpfCheckBox`/`WpfButton` dans `OptionsControl.xaml.cs`
- ✅ **README aligné code** — navigation `NavigationService`, quarantaine AES-GCM, pipeline clamscan+YARA, état d’intégration clamd/RTP/planificateur, workflow et packaging
- ✅ **MAJ auto** — `ServiceContainer` arme freshclam (4 h) + YARA-Forge (24 h) ; Options coupe/réactive les deux

### v2.0 — Phase 2 : Services Avancés + Donaby Design

- **Donaby Design** — thème sombre/clair dynamique (`ThemeManager`, tokens `DynamicResource`)
- Icône **system tray** (expérimental dans les versions précédentes ; l’UI actuelle reste fenêtre principale uniquement)
- **Nettoyer par menace** — boutons Quarantaine + Supprimer par ligne dans le tableau des menaces
- Correction affichage **version signatures ClamAV** (regex `ClamAV-VDB:[^:]+:(\d+):`)
- Mode démon **clamd** (TCP 3310) — scan sans rechargement signatures
- **Protection en temps réel** (FileSystemWatcher, 3 workers simultanés)
- **Tâche planifiée Windows** — API `schtasks` (`ScheduledScanService`), création UI à venir ; headless `--fullscan` opérationnel
- **Notifications toast** Windows natives (`Microsoft.Toolkit.Uwp.Notifications`)
- **Score de risque** (`RiskScoringService`) — CRITIQUE / MAJEUR / MINEUR / INFORMATIONNEL
- **Rapport PDF** (`PdfReportGenerator`, QuestPDF Community)
- **Vue d'ensemble** — cartes d'action, graphique illustratif, recommandations, état antivirus (sans jauges CPU matérielles dans l'UI actuelle)

### v1.0 — Phase 1 : Fondations

- Scanner ClamAV (rapide / complet / dossier / fichier)
- Moteur YARA comportemental + règles YARA-Forge
- Quarantaine XOR (`.quar` + `manifest.json`)
- Historique des scans (JSON, 100 entrées)
- Mise à jour automatique signatures (4 h) et règles (24 h)
- Système d'exclusions (dossiers + règles)
- Nettoyage fichiers temporaires

---

## 👤 Crédits

Développé par **© 2026 Donatien Byakombe**
Design system : **Donaby Design**
