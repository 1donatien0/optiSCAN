# Guide Complet — optiSCAN v3.0

> **Version de référence.** Ce guide décrit l'architecture, les modules et les procédures
> de la version 3.0 du produit (ClamAV Edition). Architecture mono-fenêtre avec services avancés Phase 2 + Donaby Design System.
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
optiSCAN/
├── optiSCAN/                          ← Solution Visual Studio
│   ├── README.md                      ← Ce fichier
│   ├── installer/
│   │   └── setup.iss                  ← Script Inno Setup
│   └── optiSCAN/                      ← Projet C# WPF
│       ├── Models/
│       │   ├── ThreatInfo.cs          ← Menace détectée
│       │   ├── ScanProgress.cs        ← Progression temps réel (IProgress<T>)
│       │   ├── ScanResult.cs          ← Résultat global d'un scan
│       │   └── ScanSession.cs         ← Entrée d'historique (persistable JSON)
│       │
│       ├── Services/
│       │   ├── ClamAvEngine.cs        ← Lance clamscan.exe, parse la sortie
│       │   ├── ClamDaemon.cs          ← Client TCP clamd (port 3310)
│       │   ├── FreshclamUpdater.cs    ← Mise à jour signatures via freshclam.exe
│       │   ├── ThemeManager.cs        ← ★ Bascule thème Donaby Dark/Light (registre)
│       │   ├── ExclusionSettings.cs   ← Dossiers et règles exclus (singleton JSON)
│       │   ├── YaraEngine.cs          ← Moteur de détection comportementale
│       │   ├── YaraForgeUpdater.cs    ← Mise à jour automatique règles de détection
│       │   ├── ScanOrchestrator.cs    ← Pipeline ClamAV + détection en parallèle
│       │   ├── QuarantineManager.cs   ← Déplace/restaure/supprime les fichiers infectés
│       │   ├── ScanLogManager.cs      ← Historique JSON + journal texte
│       │   ├── RealTimeProtection.cs  ← FileSystemWatcher sur dossiers critiques
│       │   ├── ScheduledScanService.cs← Planificateur Windows (2h00 AM)
│       │   ├── NotificationService.cs ← Toasts Windows natifs
│       │   ├── RiskScoringService.cs  ← Score 0-100 par menace
│       │   └── PdfReportGenerator.cs  ← Export rapport PDF (QuestPDF)
│       │
│       ├── Themes/
│       │   ├── Donaby.Dark.xaml       ← ★ Thème sombre (tokens DynamicResource)
│       │   └── Donaby.Light.xaml      ← ★ Thème clair (tokens DynamicResource)
│       │
│       ├── NativeMethods.cs           ← P/Invoke kernel32 (CPU, RAM)
│       ├── App.xaml                   ← Charge Donaby.Dark.xaml par défaut
│       ├── MainWindow.xaml            ← Fenêtre unique — 5 panneaux sidebar + tray
│       ├── MainWindow.xaml.cs         ← Code-behind complet
│       ├── optiSCAN.ico               ← Icône app (6 résolutions : 16→256px)
│       ├── yara/                      ← Binaires du moteur de détection
│       │   ├── yara64.exe
│       │   ├── yara32.exe
│       │   ├── yarac64.exe
│       │   └── yarac32.exe
│       ├── rules/                     ← Règles de détection (.yar)
│       │   ├── malware_signatures.yar
│       │   ├── suspicious_strings.yar
│       │   └── _compiled.yarc         ← Cache compilé (regénéré automatiquement)
│       └── clamav/                    ← Binaires et base ClamAV
│           ├── x64/                   ← Binaires Windows x86-64 (pas ARM64 !)
│           ├── x86/
│           └── database/
```

**Règle de séparation :**
- `Models/` — aucune dépendance UI, testable en console
- `Services/` — aucune dépendance UI, injectables
- `MainWindow.xaml.cs` — orchestre tous les services, met à jour l'UI directement

---

## 2. Donaby Design — Système de thèmes

### 2.1 Vue d'ensemble

optiSCAN utilise le **Donaby Design**, un système de design propriétaire basé sur des tokens de couleur WPF (`DynamicResource`). Le thème peut être basculé à chaud (sans redémarrage) entre le mode sombre et le mode clair.

Fichiers de thème :

| Fichier | Rôle |
|---|---|
| `Themes/Donaby.Dark.xaml` | Palette sombre (fond `#1A1917`, accents violets) |
| `Themes/Donaby.Light.xaml` | Palette claire (fond `#F8F5F0`, accents violets) |
| `Services/ThemeManager.cs` | Service statique de bascule, persistance registre |

### 2.2 ThemeManager

`ThemeManager` est un service `static` appelé au démarrage depuis `App.xaml.cs` :

```csharp
// App.xaml.cs
ThemeManager.Initialize(); // charge le thème sauvegardé (sombre par défaut)

// Bascule depuis le bouton de l'UI
ThemeManager.Toggle();

// S'abonner aux changements
ThemeManager.ThemeChanged += (_, isDark) => { /* ... */ };
```

La préférence est persistée dans le registre Windows :
```
HKEY_CURRENT_USER\Software\optiSCAN\optiSCAN_IsDarkTheme  (1 = sombre, 0 = clair)
```

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
optiSCAN/optiSCAN/clamav/x64/
    ├── clamscan.exe
    ├── clamd.exe              ← mode démon TCP
    ├── freshclam.exe
    ├── libclamav.dll
    ├── libclammspack.dll      ← obligatoire
    ├── libclamunrar.dll
    ├── freshclam.conf         ← généré automatiquement par FreshclamUpdater
    └── database/              ← rempli par freshclam
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

## 4. Architecture mono-fenêtre (v3.0)

### 4.1 Les 5 panneaux de MainWindow

| Index | Panneau | Contenu |
|---|---|---|
| 0 | Vue d'ensemble | Dashboard dynamique (graphique, recommandations, jauges système) |
| 1 | Nettoyer | Analyse + suppression des fichiers temporaires |
| 2 | Historique | Liste des scans passés |
| 3 | Options | Général, ClamAV, Exclusions, À propos |
| 4 | Antivirus | Scan, Quarantaine, Historique, Signatures |

Navigation via `ShowPanel(index)` — visibilité XAML gérée par `Visibility="Collapsed"`.

### 4.2 Icône système (System Tray)

L'application se minimise dans la barre des tâches système via `Hardcodet.Wpf.TaskbarNotification` :

```xml
<!-- MainWindow.xaml -->
<tb:TaskbarIcon x:Name="TrayIcon"
                IconSource="/optiSCAN.ico"
                ToolTipText="optiSCAN — Protection active"
                TrayMouseDoubleClick="TrayIcon_TrayMouseDoubleClick">
    <tb:TaskbarIcon.ContextMenu>
        <ContextMenu>
            <MenuItem Header="Afficher optiSCAN"         Click="TrayMenuShow_Click"/>
            <Separator/>
            <MenuItem Header="Lancer un scan"            Click="TrayMenuScan_Click"/>
            <MenuItem x:Name="TrayMenuProtect"
                      Header="Protection temps réel : Active"
                      Click="TrayMenuProtect_Click"/>
            <MenuItem Header="Mettre à jour signatures"  Click="TrayMenuUpdate_Click"/>
            <Separator/>
            <MenuItem Header="Quitter"                   Click="TrayMenuQuit_Click"/>
        </ContextMenu>
    </tb:TaskbarIcon.ContextMenu>
</tb:TaskbarIcon>
```

L'icône `optiSCAN.ico` est utilisée à la fois pour la fenêtre principale et pour la zone de notification. Elle contient 6 résolutions (16 × 16 à 256 × 256 px).

### 4.3 Panneau Antivirus (index 4)

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
| **Quarantaine** | `BtnQuarantineThreat_Click` | Chiffre le fichier (XOR `0x5A`) et le déplace dans `%LOCALAPPDATA%\optiSCAN\Quarantine\` — réversible |
| **Supprimer** | `BtnDeleteThreat_Click` | Demande confirmation, supprime définitivement le fichier — irréversible |

En bas du tableau, le bouton **Tout mettre en quarantaine** (`BtnQuarantineAll_Click`) traite toutes les menaces listées en une seule opération.

> ⚠ Toujours préférer la quarantaine à la suppression directe — elle permet de restaurer le fichier en cas de faux positif.

### 4.5 Pipeline de détection en parallèle

```
StartAntivirusScanAsync(type, path?)
    │
    ├─→ ScanOrchestrator  ←→ filtre ExclusionSettings.Current
    │        ├─→ ClamAvEngine.ScanFolderAsync()    ┐
    │        │   ou ClamDaemon.ScanFileAsync()      ├── Task.WhenAll
    │        └─→ YaraEngine (RunYaraOnFolder)       ┘
    │                ↓ filtrage des règles exclues
    │                ↓ RiskScoringService.Assess() pour chaque menace
    └─→ MergeResults() → UI mise à jour (Progress<ScanProgress>)
```

### 4.6 Mise à jour des signatures

`BtnManualUpdateSignatures_Click` lance séquentiellement :
1. `FreshclamUpdater.UpdateAsync()` — signatures ClamAV
2. `YaraForgeUpdater.UpdateAsync()` — règles de détection comportementale

Auto-update silencieux en arrière-plan :
- Signatures ClamAV : toutes les **4h**
- Règles de détection : toutes les **24h**

### 4.7 Système d'exclusions

`ExclusionSettings.Current` (singleton) persiste dans :
```
%LOCALAPPDATA%\optiSCAN\exclusions.json
```

- **Dossiers exclus** : fichiers dans ces dossiers sautés lors du scan YARA
- **Règles exclues** : matches filtrés (ex. `SuspiciousDownloads` — exclu par défaut)

Configurable depuis **Options → EXCLUSIONS**.

### 4.8 QuarantineManager — sécurité des fichiers infectés

Les fichiers en quarantaine sont **chiffrés par XOR** (`0x5A`) :
- Empêche Windows Defender de les détecter comme actifs
- Réversible (restauration = re-XOR)

Stockage : `%LOCALAPPDATA%\optiSCAN\Quarantine\`
- Fichiers : `{guid}.quar`
- Index : `manifest.json`

### 4.9 ScanLogManager — persistance

- Historique : `%LOCALAPPDATA%\optiSCAN\Logs\scan_history.json` (100 entrées max)
- Journal : `%LOCALAPPDATA%\optiSCAN\Logs\optiSCAN.log`

---

## 5. Services avancés

### 5.1 ClamDaemon — mode démon TCP

`ClamDaemon.cs` remplace les appels `clamscan.exe` par une connexion TCP directe à `clamd` (port 3310). Le daemon reste en mémoire et ne recharge les signatures qu'une seule fois au démarrage, ce qui élimine la latence de 5–15 s par fichier en mode clamscan.

```
optiSCAN → TCP 127.0.0.1:3310 → clamd.exe
                                      └── clamd.conf (auto-généré si absent)
                                            ├── DatabaseDirectory
                                            ├── MaxThreads = 10
                                            └── ScanPE / OLE2 / HTML / PDF / Archive
```

Activation : **Options → Utiliser clamd (mode démon)**

### 5.2 RealTimeProtection — surveillance temps réel

`RealTimeProtection.cs` surveille en permanence les dossiers critiques via `FileSystemWatcher` :

| Dossier surveillé | Raison |
|---|---|
| `C:\Users` | Profils utilisateurs (téléchargements, bureau) |
| `C:\ProgramData` | Installateurs et données d'applications |
| `C:\Windows\Temp` | Dépôt fréquent de droppers |
| Desktop / Downloads | Zones d'atterrissage principales |

Extensions surveillées : `.exe`, `.dll`, `.scr`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.js`, `.jar`, `.msi`, `.docm`, `.xlsm`, `.pptm`

Mécanismes de robustesse :
- **SemaphoreSlim(3)** — 3 scans simultanés maximum
- **Délai de stabilisation 500 ms** — attend la fin d'écriture du fichier
- **Cache de déduplication 30 s** — évite de rescanner le même fichier

En cas de détection : mise en quarantaine automatique + toast de notification.

Activation : **Options → Protection en temps réel** ou bouton **Optimiser maintenant** du dashboard.

### 5.3 ScheduledScanService — tâche planifiée Windows

`ScheduledScanService.cs` crée via `Microsoft.Win32.TaskScheduler` une tâche Windows planifiée :

| Paramètre | Valeur |
|---|---|
| Nom | `optiSCAN_DailyScan` |
| Heure | 2 h 00 AM quotidien |
| Commande | `optiSCAN.exe --fullscan --quiet` |
| Niveau | `TaskRunLevel.Highest` (administrateur) |
| `WakeToRun` | `true` |

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

Le panneau **Vue d'ensemble** (index 0) affiche en temps réel trois modules côte à côte :

**Module 1 — Statistiques de Protection** : graphique linéaire (Canvas WPF natif) sur 30 jours — scans par jour (bleu) et menaces détectées (vert).

**Module 2 — Recommandations d'Action** : cases à cocher reflétant l'état réel des services (RTP, clamd, scan planifié…). Bouton **Optimiser maintenant** pour tout activer en un clic.

**Module 3 — État Système** : trois jauges (`DashBar`) rafraîchies toutes les 4 secondes.

| Jauge | Source | Couleur dynamique |
|---|---|---|
| CPU | `GetSystemTimes` (delta 250 ms, kernel32.dll) | Vert < 60 %, Orange < 80 %, Rouge ≥ 80 % |
| RAM | `GlobalMemoryStatusEx` (kernel32.dll) | Idem |
| Disque C: | `DriveInfo("C")` | Idem |

---

## 7. Workflow utilisateur optiSCAN v3.0

```
DÉMARRAGE
    │
    ├─→ Vérification ClamAV installé
    ├─→ Vérification base de signatures
    ├─→ Initialisation ThemeManager (Donaby Dark/Light)
    ├─→ Initialisation services (RTP, clamd, notifications, PDF)
    ├─→ Auto-update signatures       (toutes les 4 h,  silencieux)
    └─→ Auto-update règles détection (toutes les 24 h, silencieux)
             │
             └─→ Fenêtre principale unique + icône system tray
                     │
                     ├─→ [VUE D'ENSEMBLE]
                     │       ├─→ Graphique protection 30 j
                     │       ├─→ Recommandations d'action
                     │       ├─→ Jauges CPU / RAM / Disque
                     │       └─→ [Optimiser maintenant] → active RTP + scan planifié
                     │
                     ├─→ [NETTOYER]    → analyse Temp + suppression avec confirmation
                     │
                     ├─→ [ANTIVIRUS]
                     │       ├─→ [⚡ Scan Rapide]     → Temp, Downloads, Bureau
                     │       ├─→ [🔍 Scan Complet]    → Tous les disques (lent)
                     │       ├─→ [📁 Scanner dossier] → FolderBrowserDialog
                     │       ├─→ [📄 Scanner fichier] → OpenFileDialog
                     │       ├─→ Par menace : [Quarantaine] ou [Supprimer]
                     │       ├─→ [🛡️ Tout mettre en quarantaine]
                     │       └─→ [📄 Exporter PDF]    → Rapport complet
                     │
                     ├─→ [HISTORIQUE] → tous les scans
                     └─→ [OPTIONS]
                             ├─→ Thème Donaby Dark / Light (toggle)
                             ├─→ Exclusions dossiers/règles
                             ├─→ Protection en temps réel (toggle)
                             ├─→ Mode clamd démon (toggle)
                             ├─→ Scan planifié : créer / supprimer
                             └─→ Notifications toast (toggle)
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
| Mode clamd (TCP daemon) | ✅ Pas de rechargement signatures (~10× plus rapide) |
| Pipeline parallèle (Task.WhenAll) | ✅ ClamAV + YARA simultanés |
| Règles pré-compilées (_compiled.yarc) | ✅ Scan comportemental ~10× plus rapide |
| SemaphoreSlim(3) RTP | ✅ Pas de tempête d'I/O à la création de fichiers |
| Scan rapide limité aux dossiers critiques | ✅ ~30 s vs 1 h+ scan complet |
| ExclusionSettings.Current (singleton lazy) | ✅ Pas de rechargement JSON par fichier |
| GetSystemTimes delta 250 ms | ✅ CPU sans PerformanceCounter NuGet |
| Timer 4 s pour le dashboard | ✅ Faible impact CPU en arrière-plan |
| ThemeManager.IsDark (static, registre) | ✅ Bascule de thème sans redémarrage |

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

## 9. Packaging final (v3.0)

```powershell
# 1. Compilation Release x64
cd optiSCAN/optiSCAN
dotnet publish -c Release -r win-x64 --self-contained false -o ..\..\build\app

# 2. Télécharger base ClamAV initiale
.\build\app\clamav\x64\freshclam.exe --datadir=".\build\app\clamav\x64\database"

# 3. Compiler l'installateur Inno Setup
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" .\installer\setup.iss
# → installer\output\optiSCAN_Setup_v3.0.exe
```

**Contenu de l'installateur (~260 Mo avec signatures initiales) :**

```
optiSCAN_Setup_v3.0.exe
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
| Hardcodet.Wpf.TaskbarNotification | — | MIT | Icône system tray |
| QuestPDF | 2024.12.2 | Community | Rapport PDF — licence gratuite projets open-source |
| Microsoft.Win32.TaskScheduler | 2.2.0.3 | MIT | Planificateur Windows |
| Microsoft.Toolkit.Uwp.Notifications | 7.1.3 | MIT | Toasts Windows natifs |
| Inno Setup | 6.x | Freeware | Gratuit pour projets commerciaux |
| Base de signatures ClamAV | — | ClamAV License | Mise à jour depuis database.clamav.net |
| Règles de détection | — | Diverses open-source | Récupérées depuis YARA-Forge |

---

## 11. Historique des versions

### v3.0 — Donaby Design System + Stabilisation

- ★ **Donaby Design System complet** — refonte UI vers le thème clair Donaby Light par défaut
- ★ **OverviewControl** — 4 cartes d'action cliquables (Border + `MouseLeftButtonUp`, sans ControlTemplate) ; cercles d'icônes neutres (`SurfaceBg`) ; carte "État Antivirus" enrichie (ClamAV + YARA en temps réel)
- ★ **AntivirusView** — zone drag & drop redessinée (Rectangle dashed border, `TrayArrowDown`, 62px) ; menu "Cibles récentes" (dead code) supprimé
- ★ **CleanControl** — support complet `chkBrave` (cache Brave Browser) et `chkLogs` (journaux Windows) dans analyse et nettoyage
- ★ **FreshclamUpdater** — `EnsureConfExists()` : résolution automatique du conf manquant (`x64\` → parent → `x86` → génération) ; `ResolveDbDir()` : résolution intelligente du dossier de base de données selon la hiérarchie clamav
- ✅ Correction CS0104 `CheckBox`/`Button` ambiguous — aliases `WpfCheckBox`/`WpfButton` dans `OptionsControl.xaml.cs`
- ✅ Correction XDG0066 designer — `StaticResource` → `DynamicResource` pour `DgHeader`/`DgRow` dans `HistoryControl.xaml`

### v2.0 — Phase 2 : Services Avancés + Donaby Design

- ★ **Donaby Design** — thème sombre/clair dynamique (`ThemeManager`, tokens `DynamicResource`)
- ★ Icône **system tray** (`Hardcodet.Wpf.TaskbarNotification`) — menu contextuel complet
- ★ **Nettoyer par menace** — boutons Quarantaine + Supprimer par ligne dans le tableau des menaces
- ★ Correction affichage **version signatures ClamAV** (regex `ClamAV-VDB:[^:]+:(\d+):`)
- ★ Mode démon **clamd** (TCP 3310) — scan sans rechargement signatures
- ★ **Protection en temps réel** (FileSystemWatcher, 3 workers simultanés)
- ★ **Tâche planifiée Windows** (2 h 00 AM, `TaskRunLevel.Highest`)
- ★ **Notifications toast** Windows natives (boutons Quarantaine/Ignorer)
- ★ **Score de risque** par menace (CRITIQUE / MAJEUR / MINEUR / INFORMATIONNEL)
- ★ **Rapport PDF** exportable (QuestPDF, Community license)
- ★ **Dashboard Vue d'ensemble** redessiné : graphique 30 j, recommandations, jauges CPU/RAM/Disque
- Bouton **Optimiser maintenant** : configuration en un clic

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

Développé par **© 2026 Donatien Byakombe (Dona By)**
Design system : **Donaby Design**
