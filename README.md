# Guide Complet — optiSCAN v3.1 (candidate)

> **Version de référence.** Architecture mono-fenêtre, services avancés + Donaby Design System.  
> **État** — v3.1 / 3.1.0 est la version candidate en préparation ; elle n'est pas encore publiée. La release 3.0 reste la base publiée. Voir le [plan de release v3.1](RELEASE_PLAN_v3.1.md), la [feuille de route produit d’optiSCAN Antivirus après 3.1](ROADMAP.md) et les [suivis d'audit](AUDIT_optiSCAN_360.md).
>
> **Nomenclature** — **v3.1** : nom de release. **3.1.0** : assembly et installateur (`Directory.Build.props`, Inno Setup).
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
| — | [Branches Git](#branches-git) (`main`, `dev`, `win`) |

---

## Branches Git

`main` et `dev` ont le même historique : **version 1** (1 juin 2026, tag `v1`), **version 2** (23 juin 2026, tag `v2`) et **version 3** (30 septembre 2026, tag `v3`). `win` s’en sépare à la version 2 ; son commit `first commit` porte la même date que la version 3.

L’historique a été regroupé autour de ces trois publications, en conservant les dates majeures.

| Branche | Rôle |
|---------|------|
| **`main`** | Référence publiée de l’édition WPF. Même commit que `dev`. |
| **`dev`** | Même historique que `main`. |
| **`win`** | Édition WinUI 3, à partir de la version 2. |

Branche par défaut GitHub : **`main`**. CI : `main` et `dev` (voir [`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

---

## 1. Architecture technique

### Choix du langage : C# WPF .NET 10 (LTS)

| Critère | WPF | MAUI | C++ natif |
|---|---|---|---|
| Compatibilité Windows | Oui — natif | Partiel — multi-plateforme (overhead) | Oui — natif |
| Intégration ClamAV | Oui — Process.Start / TCP clamd | Oui — Process.Start | Oui — libclamav directe |
| MVVM + Binding UI | Oui — excellent | Partiel — différent | Non — manuel |
| **Verdict** | **Retenu** | Non nécessaire | Non nécessaire |

### Architecture plateforme (v3.1 candidate)

optiSCAN v3.1 candidate rapproche un antivirus « classique » via une couche plateforme Windows :

```
optiSCAN.exe (UI WPF)
    ↔ IPC (optiSCAN.Platform — pipe optiSCAN_Protection, protocole v1)
optiSCAN.Service.exe  →  optiSCAN.exe --service-host
    ├── RTP (dossiers des comptes interactifs) + ProcessStartMonitor + scan USB
    ├── ProtectionPipeServer (scan_path / set_policy admin ; scan_buffer fermé sans AMSI)
    └── clamd en AppContainer, alimenté en flux (zINSTREAM) par l'hôte
```

| Composant | Rôle |
|---|---|
| `optiSCAN.Platform` | Contrats JSON IPC (`ping`, `scan_path`, `scan_buffer` — fermé par le serveur tant qu’AMSI n’est pas livré —, `status`, `shutdown`, `set_policy`) |
| `optiSCAN.Service` | Service Windows qui supervise `optiSCAN.exe --service-host` |
| `--service-host` | Moteur sans UI : RTP, IPC. Refusé hors compte SYSTEM |
| `ThreatRepairService` | Quarantaine + recours Defender (`MpCmdRun`) |
| `WindowsDefenderExclusionService` | Exclusions Defender **opt-in** (Options → réappliquer ; script ; `--defender-exclusions` si UAC) — plus d’auto install/démarrage |
| `CloudThreatIntelService` | Enrichissement VirusTotal (cache local) |
| `native/optiSCAN.AmsiProvider` | Prototype **non livré** : non compilé par la CI, non publié et jamais enregistré |
| `native/optiSCAN.Minifilter` | Squelette **non livré** : ni copié, ni chargé |

**Prérequis** : droits administrateur pour installer le service. AMSI et minifiltre ne font pas partie de la v3.1 candidate : aucun fournisseur AMSI ni pilote n'est enregistré.

**Option UI** : *Service Windows de protection système* (Options → Protection). Si le service est injoignable, repli automatique sur la RTP locale.

**Identifiants techniques** — définis une seule fois dans `optiSCAN.Platform/ProtectionIdentifiers.cs`, avec deux miroirs : `native/optiSCAN.AmsiProvider/protection_identifiers.h` (prototype non livré) et `installer/protection_identifiers.iss` (Inno Setup). Le test `ProtectionIdentifiersTests` échoue si les trois divergent.

| Identifiant | Valeur |
|---|---|
| Service Windows (SCM) | `optiSCANProtection` (affiché « optiSCAN Protection v3 ») |
| Pipe nommé | `\\.\pipe\optiSCAN_Protection` |
| Source journal d’événements | `optiSCAN Protection v3` |
| Protocole IPC | champ JSON `proto` = `1` (absent = client historique v1) |

Le service v3 s’appelle `optiSCANProtection` et le pipe `optiSCAN_Protection` : ces noms ne portent pas le numéro d’assembly. Seul `ProtocolVersion` s’incrémente si le format JSON change de façon incompatible ; le serveur refuse alors explicitement un client plus récent que lui. Une mise à jour par-dessus une installation existante arrête le service `optiSCANProtection` et les processus optiSCAN, puis recopie les fichiers. Ce service n’est enregistré que si la case « protection avancée » est cochée. Une installation neuve laisse cette case décochée. La ligne v2 utilisait `optiSCANProtectionV2` et `optiSCAN_Protection_v2` ; l’installeur v3 ne les cite pas.

---

### Structure des modules

```
(racine du dépôt optiSCAN)
├── README.md                          ← Ce fichier (guide complet)
├── docs/
│   ├── README.md                      ← Index doc (guides + renvois vers ce README)
│   ├── GUIDE_DISTRIBUTION.md          ← Signature, .NET, publish / Inno, checklist
│   ├── DIAGNOSTIC_INTEGRATION_WINDOWS.md ← Profil install allégé façon version 2 (2 moteurs)
│   ├── POLITIQUE_CONFIDENTIALITE.md   ← Politique utilisateur v3.1 candidate
│   └── CONFORMITE_RGPD.md             ← Note traitements / RGPD
├── AUDIT_optiSCAN_360.md              ← Audit 360 unique du 2 octobre 2026 (constats, traitement, réserves)
├── ROADMAP.md                        ← Feuille de route produit de l’antivirus après la v3.1
├── RELEASE_PLAN_v3.1.md              ← Critères de validation de la candidate v3.1
├── SECURITY.md                        ← Signalement + architecture sécurité
├── LICENSE.txt                        ← CLUF v3.1
├── .editorconfig                      ← Sévérités analyse Roslyn (alignement IDE / MSBuild)
├── Directory.Build.props              ← Version candidate 3.1.0, NetAnalyzers, TreatWarningsAsErrors (Release)
├── .github/workflows/
│   ├── ci.yml                         ← Build, suite xUnit, publish + SBOM (main)
│   ├── codeql.yml                     ← Analyse CodeQL (C# + natif)
│   ├── dependency-review.yml          ← Revue dépendances (PR)
│   └── gitleaks.yml                   ← Détection fuites secrets
├── scripts/
│   ├── fetch-runtime-deps.ps1         ← Télécharge ClamAV + YARA (CI / dev)
│   ├── prepare-release-v3.ps1         ← Chaîne de préparation des releases v3.x
│   ├── clean-before-publish.ps1       ← Nettoyage bin/obj avant release
│   ├── add-defender-exclusions.ps1    ← Exclusions Defender (manuel / Options ; pas auto à l’install)
│   ├── generate-sbom.ps1              ← SBOM CycloneDX (CI publish)
│   ├── build-amsi.ps1 / stage-amsi.ps1← Prototype AMSI (hors CI, non livré)
│   ├── codesign.ps1                   ← Signature Authenticode (.pfx ; CI si secrets CODESIGN_*)
│   ├── verify-runtime-deps.ps1        ← Vérifie clamav + clamd + yara (+ rules optionnelles)
│   ├── publish-release.ps1            ← Publish + Inno (défaut sans CVD/.yar embarqués)
│   ├── validate-release-readiness.ps1 ← Tests Release (+ verify publish optionnel)
│   └── runtime-versions.json          ← Versions URL ClamAV / YARA
├── optiSCAN.sln                       ← Solution Visual Studio
├── optiSCAN.Platform/                 ← IPC protection système (ProtectionIdentifiers = noms service/pipe)
├── optiSCAN.Service/                  ← Service Windows (supervise --service-host)
├── optiSCAN.Tests/                    ← Tests unitaires (xUnit)
├── native/
│   ├── optiSCAN.AmsiProvider/         ← Prototype AMSI (non livré)
│   └── optiSCAN.Minifilter/           ← Squelette de pilote (non livré)
├── installer/
│   ├── setup.iss                      ← Inno Setup FR/EN (x64 ; bases/règles téléchargées après install par défaut)
│   ├── redist/LISEZMOI.md             ← Modes runtime .NET (redist Inno non pris en charge)
│   └── build-release-setup.ps1        ← clean + publish + ISCC
└── optiSCAN/                          ← Projet C# WPF
    ├── Models/
    │   ├── ThreatInfo.cs              ← Menace détectée
    │   ├── ScanProgress.cs            ← Progression temps réel (IProgress<T>)
    │   ├── ScanResult.cs              ← Résultat global d'un scan (types dont RemovableDrive)
    │   ├── ScanSession.cs             ← Entrée d'historique scan (v2 : Threats[] ; v1 : type legacy)
    │   ├── ActivityEntry.cs           ← Ligne timeline Historique (projection UI)
    │   └── ActivityEventRecord.cs     ← Événement immuable (activity_log.dat)
    │
    ├── ViewModels/                    ← ScanViewModel, HistoryViewModel, HistoryThreatRow, RelayCommand
    ├── Views/                         ← Overview, Antivirus, Clean (Optimiser : Nettoyage / Mises à jour / Tweaks), History, Options
    │                                    CleanControl.xaml(.cs) + CleanControl.Updates.cs + CleanControl.Tweaks.cs
    │
    ├── Coordinators/                  ← Orchestration UI (MainWindow, Historique) — classes static sans état
    │   ├── MainWindowStartupCoordinator.cs / MainWindowShutdownCoordinator.cs
    │   ├── TrayCoordinator.cs         ← Systray (wrap `SystemTrayHost`)
    │   ├── OverviewRefreshCoordinator.cs / SignatureRefreshCoordinator.cs
    │   ├── HistoryDetailCoordinator.cs / HistoryRefreshCoordinator.cs / HistoryThreatRemediationCoordinator.cs
    │   ├── ExportCoordinator.cs       ← Exports HTML/PDF (via `IHistoryExportService`)
    │   └── … (toast, RTP, USB, signatures manuelles, shell scan, etc.)
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
    │   ├── ThreatRiskConverters.cs    ← Colonne « Risque » (RiskScoringService → UI)
    │   └── QuarantinePathVisibilityConverter.cs ← Chemin quarantaine (Historique, lecture seule)
    │
    ├── Services/
    │   ├── ClamAvEngine.cs            ← clamscan.exe (sonde --version mise en cache 60 s)
    │   ├── FreshclamUpdater.cs        ← Mise à jour signatures via freshclam.exe
    │   ├── ThemeManager.cs            ← Bascule Donaby + MaterialDesign (UserPreferences)
    │   ├── ExclusionSettings.cs       ← Exclusions DPAPI (exclusions.dat) + dossiers protégés
    │   ├── OptiscanProtectedPaths.cs  ← Install (entière si réservée aux admins) + bases/règles/quarantaine de %LocalAppData%\optiSCAN : anti-autophagie scan/RTP
    │   ├── WindowsDefenderExclusionService.cs ← Exclusions Defender (opt-in Options / script)
    │   ├── AppInstallPaths.cs         ← Façade racine install + motifs clamscan --exclude
    │   ├── YaraEngine.cs              ← YARA + cache _compiled.yarc / _compiled.stamp
    │   ├── YaraForgeUpdater.cs        ← Mise à jour automatique règles de détection
    │   ├── ServiceContainer.cs        ← Singleton + DI (`IUserPreferencesAccessor`, `IExclusionSettingsAccessor`, `IViewServices`, `IHistoryServices`)
    │   ├── ScanOrchestrator.cs        ← Pipeline ClamAV + YARA en parallèle
    │   ├── ScanProgressRelay.cs       ← Progression monotone (multi-cibles / Clam+YARA)
    │   ├── ScanUserDisplay.cs         ← Libellés scan localisés
    │   ├── ScanThreatMerger.cs        ← Fusion menaces ClamAV + YARA
    │   ├── MultiTargetScanAggregator.cs ← Fusion multi-cibles avec déduplication des menaces
    │   ├── AntivirusActions.cs        ← Quarantaine / suppression / MAJ + ActionCompleted
    │   ├── NavigationService.cs       ← Panneaux + fondu 180 ms
    │   ├── NavigationRefreshCoordinator.cs ← Refresh ciblé après navigation (Services/)
    │   ├── HistoryExportService.cs    ← Export HTML/PDF (`IHistoryExportService`)
    │   ├── SystemTrayHost.cs          ← Icône zone de notification (bas niveau)
    │   ├── OnboardingService.cs       ← Message premier lancement
    │   ├── HeadlessScanArguments.cs   ← --fullscan / --quickscan / --defender-exclusions / --quiet
    │   ├── ScheduledScanApply.cs      ← Logique enable/disable tâche (testable)
    │   ├── ElevationHelper.cs         ← Relance UAC (--scan, analyse complète)
    │   ├── QuarantineManager.cs       ← Quarantaine AES-GCM, manifeste signé
    │   ├── SecureStore.cs             ← Persistance DPAPI + HMAC (prefs, exclusions, historique)
    │   ├── OverviewRecommendationsBuilder.cs ← Recommandations accueil (hygiène + activité)
    │   ├── OverviewProtectionStatsFormatter.cs ← Stats protection 30 j. (accueil, sans doublon reco.)
    │   ├── ActivityLogService.cs      ← Journal unifié activity_log.dat (timeline Historique)
    │   ├── ScanLogManager.cs          ← Sessions scan/nettoyage (.dat), ReconcileQuarantinedThreats, optiSCAN.log
    │   ├── SignatureStatusService.cs  ← Versions signatures ClamAV/YARA (cache TTL 30 s)
    │   ├── RealTimeProtection.cs      ← FileSystemWatcher (Options)
    │   ├── RemovableDriveScanService.cs ← Scan auto USB/SD à l'insertion (WMI + polling)
    │   ├── RiskyFileExtensions.cs     ← Extensions à risque + hôtes de scripts (RTP, processus, USB)
    │   ├── ExecutableSniffer.cs       ← Exécutable PE reconnu à son en-tête, quelle que soit l’extension
    │   ├── SafeDirectoryCleaner.cs    ← Mesure / vidage du panneau Nettoyer sans suivre de jonction
    │   ├── PipeServerAccount.cs       ← Tube clamd : serveur du même compte, client sans usurpation
    │   ├── SystemExecutables.cs       ← Chemins complets des outils Windows (System32, PowerShell, Explorateur)
    │   ├── ScheduledScanService.cs    ← schtasks (async côté Options)
    │   ├── IpcManager.cs              ← Instance unique : WM_SHOWME
    │   ├── HtmlExportService.cs       ← Rapport HTML
    │   ├── NotificationService.cs     ← Toasts Windows natifs
    │   ├── RiskScoringService.cs      ← Score, sévérités i18n, PDF
    │   ├── PdfReportGenerator.cs      ← Export PDF (QuestPDF)
    │   ├── WingetUpdateService.cs     ← Liste / mise à jour apps (winget) ; --uninstall-previous + nettoyage des versions empilées
    │   └── SystemTweaksService.cs     ← Tweaks perf / confidentialité / UI / DISM — onglet Optimiser → Tweaks
    │
    ├── Themes/
    │   ├── Donaby.Dark.xaml           ← Thème sombre
    │   ├── Donaby.Light.xaml          ← Thème clair
    │   └── Donaby.HighContrast.xaml   ← Contraste renforcé (Options)
    │
    ├── App.xaml                       ← Fusionne Donaby.Light + ThemeManager au démarrage
    ├── MainWindow.xaml                ← Fenêtre unique — 5 panneaux sidebar
    ├── MainWindow.xaml.cs             ← Composition légère (~730 L) : navigation, branchement coordinateurs, événements services
    ├── optiSCAN.ico                   ← Icône app
    ├── yara/                          ← Binaires du moteur de détection
    ├── rules/                         ← Règles de détection (.yar) + cache _compiled.yarc
    └── clamav/                        ← Binaires et base ClamAV (x64 / x86 / database)
```

**Règle de séparation :**
- `Models/` — aucune dépendance UI
- `Coordinators/` — orchestration WPF sans état (méthodes `static`, hôtes `Host` typés) ; extrait de `MainWindow` / `HistoryControl`
- `Services/` — aucune dépendance WPF ; injectables via `Microsoft.Extensions.DependencyInjection` + `ServiceContainer`
- `ViewModels/` — logique de présentation (`ScanViewModel`, commandes)
- `Views/` — XAML + code-behind léger ; `Bind(IHistoryServices)` / `IViewServices` pour éviter le couplage à `MainWindow`
- `MainWindow.xaml.cs` — câblage : navigation, systray (`TrayCoordinator`), coordinateurs startup/shutdown/RTP/exports

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
    ├── clamd.exe              ← daemon ClamAV optionnel (AppContainer, port local aléatoire, joint par tube nommé)
    ├── freshclam.exe
    ...
```

Dossiers attendus à côté de `optiSCAN.exe` (publish ou debug) :

| Dossier | Contenu minimal |
|---|---|
| `clamav/x64/` (ou `x86/`) | `clamscan.exe`, `freshclam.exe` recommandé |
| `yara/` | `yara64.exe`, `yarac64.exe` (ou `32` en processus x86) |
| `rules/` | Fichiers `.yar` (optionnels au publish ; l'updater n'accepte que la release YARA-Forge épinglée dans le code) |

### 3.3 Première mise à jour des signatures

```powershell
.\clamav\x64\freshclam.exe --datadir=".\clamav\x64\database"
```

Télécharge : `main.cvd` (~170 Mo), `daily.cvd` (~60 Mo), `bytecode.cvd` (~200 Ko).

### 3.4 Lecture de la version locale des signatures

`FreshclamUpdater.GetLocalDatabaseVersion()` lit l'en-tête binaire des fichiers `.cvd` / `.cld` :

```
Format réel : ClamAV-VDB:{date texte}:{version}:{signatures}:...
Exemple     : ClamAV-VDB:01 May 2026 06-27 +0000:22988:355446:...
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

## 4. Architecture mono-fenêtre (v3.1 candidate)

Les sous-sections **4.1** à **4.11** suivent une lecture « produit » : navigation et panneaux, détail du panneau Antivirus, menaces et pipeline, options techniques (MAJ, exclusions, quarantaine, logs), exports, puis contenu de la vue d’ensemble.

### 4.1 Les 5 panneaux de MainWindow

Les vues sont empilées dans un seul `Grid` (`MainWindow.xaml`) : une seule est `Visible`, les autres `Collapsed`. La navigation passe par `NavigationService.NavigateTo("…")` (clés insensibles à la casse), enregistrées dans `MainWindow.RegisterPanels()`.

| Clé `NavigateTo` | Panneau | Contrôle | Rôle principal |
|---|---|---|---|
| `Overview` | Vue d'ensemble | `OverviewControl` | Cartes d'action (boutons), bandeau UAC, statut protection, recommandations |
| `Antivirus` | Antivirus | `AntivirusView` | Scans ; onglets **Analyse en cours** / **Quarantaine** / **Historique** / **Signatures** (`ScanViewModel`) |
| `Clean` | Optimiser | `CleanControl` | Trois sous-onglets : **Nettoyage** (caches navigateurs, temp, corbeille, cache Windows Update, DNS), **Mises à jour** (applications via winget avec `--uninstall-previous` et retrait des versions empilées du même programme + lien Windows Update, `WingetUpdateService`), **Tweaks** (performance, confidentialité, interface, DISM — `SystemTweaksService`, actions admin regroupées en une invite UAC et exécutées par appel direct des outils système, sans `cmd /c`) + **historique local** du nettoyage (colonne **Libéré** = `BytesDisplay`). Le nettoyage ne suit ni jonction ni lien et supprime chaque fichier par une descente nom par nom (`SafeDirectoryCleaner`) |
| `History` | Historique | `HistoryControl` + `HistoryViewModel` | Timeline `ActivityLogService.GetActivityFeed` ; 5 filtres (puces) ; traitement menaces ; exports **HTML** / **PDF** |
| `Options` | Options | `OptionsControl` | **Langue** (fr/en, redémarrage), thème / `SyncWindowsTheme`, scan favori, RTP, **scan USB/SD** (auto à l'insertion, mode complet, inclure dans analyse complète), quarantaine auto, planif. (`ServiceContainer.ScheduledScan`, prochaine exécution, **Lancer maintenant**), exclusions |

Raccourcis clavier : `Ctrl+1` … `Ctrl+5` (`KeyboardShortcuts`) — ordre des panneaux : **Vue d’ensemble**, **Antivirus**, **Optimiser**, **Historique**, **Options**.

### 4.2 Fenêtre principale, barre système et icône

L'interface repose sur `MainWindow` et la barre latérale (90 px). Le **systray** est géré par `TrayCoordinator` → `SystemTrayHost` (double-clic pour rouvrir, menu Ouvrir / Quitter). Réduire la fenêtre laisse optiSCAN actif en arrière-plan. Footer : statut dynamique (scan, MAJ) à gauche ; crédit Vanier à droite.

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

Les scans interactifs passent par `ScanViewModel.StartScanAsync` → `ScanOrchestrator` : pour chaque cible, **ClamAV** (daemon **clamd** ou repli **clamscan.exe**) et **YARA** tournent en parallèle (`Task.WhenAll`), puis fusion. Les scans **multi-dossiers** passent par `MultiTargetScanAggregator`. Les **périmètres protégés** optiSCAN sont exclus (`OptiscanProtectedPaths` + `ExclusionSettings`) : le dossier d'installation entier s'il est réservé aux administrateurs (sinon ses seuls `clamav`, `rules` et `yara`), et dans `%LOCALAPPDATA%\optiSCAN` les seuls sous-dossiers `clamav`, `clamd`, `rules`, `Quarantine` et `SafetyBackups` ; le reste de ce dossier, inscriptible par la session, est analysé. **`RiskScoringService`** alimente la colonne **Risque**, les toasts et le PDF.

> **clamd** — si `clamd.exe` est présent et l’option **Moteur clamd** est activée (Options), clamd est lancé dans un **AppContainer** sans accès direct aux fichiers des utilisateurs. L’hôte ouvre chaque fichier avec ses propres droits et l’envoie en flux (`zINSTREAM`) : aucune ACL n’est modifiée. Le client optiSCAN utilise un tube nommé réservé au compte; le port TCP aléatoire écoute sur `127.0.0.1`. Le protocole TCP de clamd n’authentifie pas ses clients : selon les filtres AppContainer/loopback de Windows, un processus local peut potentiellement l’atteindre. Ce port ne constitue pas une frontière d’identité. Les commandes d’arrêt et de rechargement sont désactivées. Un fichier non lu par clamd repasse par **`clamscan.exe`** ; si clamd est indisponible, tout le scan passe par clamscan. Note posture Accueil : [§13 Sécurité](#13-sécurité-posture-et-menaces).

```
ScanViewModel → ScanOrchestrator
    │   ├─→ CompositeClamAvBackend (clamd → clamscan)  ─┐
    │   └─→ YaraEngine (.yarc + stamp)                 ├── Task.WhenAll → fusion
    └─→ Progress<ScanProgress> → UI
```

**Délais maximaux globaux** — fichier : **10 min** ; dossier ou lecteur amovible : **2 h** ; scan rapide : **4 h** ; scan complet : **12 h**. Le délai est transmis aux moteurs pour arrêter leurs processus. À l'échéance, le scan est signalé en erreur avec une couverture incomplète ; les détections déjà obtenues sont conservées. Le scan USB garde aussi ses limites plus courtes (10 min en mode rapide, 45 min en mode complet).

La **version 2** ajoute aussi : note de **posture sécurité** (Accueil), **réputation VirusTotal** (hash SHA-256, clé API Options), **mode jeu** (toasts / scans headless atténués).

**Identifiant menace** — `ThreatInfo.Id` : hash **SHA-256** déterministe (`FilePath|VirusName|DetectedAt`) — stable entre redémarrages (pas `string.GetHashCode()`).

### 4.6 Mise à jour des signatures

**Manuel** — `BtnManualUpdateSignatures_Click` enchaîne `FreshclamUpdater.UpdateAsync()` puis `YaraForgeUpdater.UpdateAsync()` (journal dans l’onglet Signatures).

**Automatique** — À l’instanciation de `ServiceContainer.Default`, les minuteries sont armées : **ClamAV toutes les 4 h**, **vérification/mise à jour YARA-Forge toutes les 24 h**. La case **Mise à jour automatique des signatures** dans **Options** coupe ou réactive **les deux** services (`DisableAutoUpdate` / `EnableAutoUpdate`). Pour YARA-Forge, l'updater n'accepte que l'asset `yara-forge-rules-core.zip` de la release `20261004`, avec la taille et le SHA-256 approuvés localement ; l'URL et le digest de l'API GitHub doivent correspondre aussi. Si la release « latest » change, l'updater refuse le nouvel asset jusqu'à l'ajout de son empreinte dans une mise à jour optiSCAN. L'échec est fermé : les règles précédentes restent installées.

### 4.7 Système d'exclusions

`ExclusionSettings` persiste dans :
```
%LOCALAPPDATA%\optiSCAN\exclusions.dat
```
(chiffrement **DPAPI** + **HMAC** ; migration automatique depuis l’ancien `exclusions.json` en clair).

**Périmètres protégés** (`OptiscanProtectedPaths`) — jamais analysés (scans, RTP, quarantaine auto) pour éviter l’**auto-détection** sur les propres fichiers optiSCAN :

| Périmètre | Contenu typique |
|-----------|-----------------|
| **Installation** | `{autopf}\optiSCAN` (Program Files), répertoire du processus, chemin registre Inno |
| **Données applicatives** | `%LOCALAPPDATA%\optiSCAN\` — bases ClamAV (`clamav\database`), règles YARA, quarantaine, logs, staging MAJ (`Updates`), config clamd |

- **Liste Options** : ajout automatique au chargement (`EnsureProtectedFoldersListed`) ; **non supprimables** par l’utilisateur
- **Dossiers utilisateur** : ajout manuel dans **Options → EXCLUSIONS**
- **Règles exclues** : matches YARA filtrés (ex. `SuspiciousDownloads` — exclu par défaut)
- **ClamAV / clamd** : plusieurs `--exclude` / lignes `ExcludePath` (une par racine protégée)
- **RTP** et **scan USB/SD** : mêmes exclusions ; lecteur entier exclu si son chemin racine est listé

**Exclusions Windows Defender** (`WindowsDefenderExclusionService`) — **opt-in** (évite le marqueur heuristique « tamper » d’un ajout silencieux) :

| Moment | Comportement |
|--------|----------------|
| **Installation** | Script copié dans `{app}\scripts\` — **non exécuté** par Inno |
| **Démarrage / onboarding** | **Pas** d’appel automatique |
| **Options** | Bouton « Réappliquer les exclusions Defender » |
| **Manuel** | `.\scripts\add-defender-exclusions.ps1` (élévation) ou `optiSCAN.exe --defender-exclusions` |

Chemins : dossier d’installation uniquement, et seulement s’il est réservé aux administrateurs (`InstallLocationTrust`) ; jamais `%LOCALAPPDATA%\optiSCAN`, inscriptible par l’utilisateur. Hors d’un tel dossier (build de développement, copie portable), aucune exclusion n’est ajoutée et celles d’une version antérieure sont retirées. Processus : **chemins complets** des binaires installés (`optiSCAN.exe`, `optiSCAN.Service.exe`, `clamav\x64\clamscan.exe`, `freshclam.exe`, `clamd.exe`, `yara\yara64.exe`), jamais un simple nom d’image. L’installeur retire à chaque mise à jour les exclusions posées par la 3.0.0, et toutes les exclusions à la désinstallation. Si la **protection contre la falsification** Defender est active, ajout manuel dans *Sécurité Windows → Exclusions* — voir [§7](#exclusion-windows-defender).

Configurable depuis **Options → EXCLUSIONS** (exclusions internes optiSCAN uniquement).

### 4.8 QuarantineManager — sécurité des fichiers infectés

Les fichiers en quarantaine sont stockés en **AES-256-GCM** (format binaire `OPTQ`, nonce et tag d’authentification).

- Clé maîtresse 256 bits, **DPAPI CurrentUser** (fichier `.key`).
- Manifeste `manifest.json` signé **HMAC-SHA256** (intégrité).

Stockage : `%LOCALAPPDATA%\optiSCAN\Quarantine\` — `{guid}.quar` + `manifest.json`. Restauration par défaut ou vers un dossier choisi : `IThreatStore.RestoreTo(quarantineId, destinationFolder)`.

- Si la **suppression du fichier original** échoue après écriture du blob `.quar`, le blob est **supprimé** (rollback) et la quarantaine est annulée.
- Si la **persistance du manifeste** échoue après écriture du blob, l’entrée est retirée et le blob est supprimé.

Pendant un **scan en cours**, `ScanViewModel.ActiveScanSessionId` lie les quarantaines à la session ; les chemins isolés pendant l’analyse sont exclus du résultat final (`RemoveAlreadyQuarantinedThreats`).

### 4.9 Journaux et historique

| Fichier / service | Rôle |
|---|---|
| `ActivityLogService` → `%LocalAppData%\optiSCAN\Logs\activity_log.dat` | Timeline **Historique** (DPAPI + HMAC) ; événements immuables : `ScanCompleted`, `CleanCompleted`, `ThreatQuarantined`, `ThreatRestored`, `QuarantineDeleted` ; rétention **150** événements les plus récents (`MaxActivityEvents`) ; **migration unique** au premier lancement depuis `scan_history.dat` / `clean_history.dat` + entrées quarantaine actuelles si le fichier est vide |
| `ScanLogManager` → `scan_history.dat` / `clean_history.dat` | Détail des sessions (menaces en attente, exports) ; rotation **100 → 50** (même règle qu’avant) ; **v2** : `Threats[]` ; migration `.json` → `.legacy` ; alimente `ActivityLogService` à chaque scan/nettoyage terminé |
| `ScanLogManager` → `optiSCAN.log` | Journal texte volontairement **non chiffré** (diagnostic) ; `FormatScanDetailCore` applique `PathRedaction` sur cible et chemins de menaces — noms de virus, dates et compteurs restent lisibles ; résumé dans **Historique → Scan Antivirus** |
| `AppLogger` → `optiscan-YYYY-MM-DD.log` | Logs applicatifs non chiffrés ; purge **> 30 jours**, au plus **1×/jour**. Le dossier suit le compte du processus : profil utilisateur en mode interface, profil SYSTEM pour le service |

**Panneau Historique** (`HistoryControl` + `HistoryViewModel`, `Ctrl+4`) :

- **Timeline** : `ActivityLogService.GetActivityFeed(quarantine)` → `ActivityEntry`, tri date décroissante ; **5 puces** : **Tout**, **Menaces** (scans avec détections en attente), **Scans sains**, **Nettoyages**, **Quarantaine** ; recherche sur type, résumé, cible ou chemins quarantaine.
- **Sélection stable** : clé `SelectionKey` — `SessionId` pour les scans, `EventId` pour quarantaine/restauration/suppression — conservée après `Refresh()`.
- **Refresh** : `ReconcileQuarantinedThreats` retire des sessions persistées les menaces déjà en quarantaine (même chemin d’origine).
- Détail **scan** : grille via `HistoryThreatRow` ; **Quarantaine** / **Ignorer** / **Supprimer** ; **Tout mettre en quarantaine** ; **Traiter dans Analyse**. Détail **quarantaine** : lecture seule ; chemin masqué selon contexte (`QuarantinePathVisibilityConverter`).
- Sessions **version 1** : badge menaces possible sans chemins (`Hist_DetailThreatsLegacy`) — relancer une analyse pour traiter.
- Types affichés : analyse rapide/complète, fichier, dossier, **lecteur amovible** (`ScanType.RemovableDrive`), nettoyage système, événements quarantaine.

### 4.10 Exports PDF et HTML

- **PDF** — `PdfReportGenerator` : déclenché via `ServiceContainer` (`ExportScanSessionPdfRequested` → `MainWindow.TryExportScanSessionPdf`). Bouton **Historique** : **PDF (sélection)** sur la ligne choisie dans Scan Antivirus.
- **HTML** — `HtmlExportService` : `RequestExportScanHistoryHtml()` depuis **Historique**.

### 4.11 Vue d'ensemble (dashboard)

Le panneau **Vue d'ensemble** (`OverviewControl`, clé `Overview`) regroupe :

- **Hero** : titre de protection (« Votre ordinateur est protégé » ou « Protection incomplète » selon les moteurs) et **dernière analyse** uniquement ; pas de détail ClamAV/YARA sur cet écran (voir onglet **Antivirus**).
- **Quatre cartes d'action** : Optimiser, Antivirus, Historique, mise à jour des signatures (navigation via `ServiceContainer` / `INavigationService`).
- **Deux colonnes** sous les cartes :
  - **Statistiques de protection** : `OverviewProtectionStatsFormatter` (30 j., analyses / fichiers / menaces depuis l’historique) — distinct des recommandations pour éviter le doublon « activité ».
  - **Recommandations** : `OverviewRecommendationsBuilder` (hygiène signatures, suggestion nettoyage) ; `MainWindow` collecte le contexte et met à jour `OverviewControl`.

---

## 5. Services avancés (modules complémentaires)

### RealTimeProtection — surveillance temps réel

`RealTimeProtection.cs` : `FileSystemWatcher` sur les dossiers configurés, filtrage par extension à risque (`RiskyFileExtensions` : exécutables, scripts, raccourcis `.lnk`, documents à macros anciens et récents, `.pdf`, `.rtf`, `.one`, `.chm`, archives, images disque) ou, pour toute autre extension, par contenu : un exécutable PE déposé en `.dat` ou `.tmp` est reconnu à son en-tête (`ExecutableSniffer`), lu une fois après le délai de stabilisation par une ouverture partagée qui ne gêne pas l’auteur du fichier ; délai de 500 ms, vérification de stabilité pendant au plus 20 s, **128 événements en attente au maximum** et **3 scans simultanés**. Le cache de déduplication est limité à 8 192 chemins. Une saturation de la file ou du cache est journalisée et déclenche un rattrapage du dossier, limité à un par dossier toutes les 30 s ; une lacune temporaire reste possible. Avant le scan, le fichier est ouvert sans suivre le dernier lien, son chemin réel est vérifié et le contenu complet est copié depuis cette poignée vers `ScanStaging` ; le scan ne rouvre pas le chemin d'origine. Le staging conserve une réserve disque de 128 Mio. Si une copie complète est impossible, le résultat est une erreur avec une lacune de couverture, sans repli par chemin. La quarantaine chiffrée a sa propre limite de 256 Mio par fichier : une détection plus grande est signalée mais ne peut pas être mise en quarantaine automatiquement. Après une perte d’événements, le watcher est recréé et un parcours de rattrapage analyse les fichiers à risque (extension listée ou en-tête PE) déjà présents. Les chemins via lien, les entrées inaccessibles et les fichiers cloud hors ligne ne sont pas suivis ou hydratés ; une analyse de dossier les signale comme incomplète. Si le rattrapage du temps réel échoue ou si un fichier ne se stabilise pas, l’état est écrit dans le journal local, sans indicateur de santé dédié dans l’interface.

En mode interface, une menace détectée remonte à l’UI et est inscrite dans l’historique. Les scans temps réel sans menace, y compris ceux incomplets, ne créent pas de session d’historique. En mode service SYSTEM, les menaces sont journalisées et peuvent être mises en quarantaine automatiquement selon la politique de l’hôte ; elles ne remontent pas à l’historique de la session interactive. La quarantaine de ce processus est rangée dans `%ProgramData%\optiSCAN\Quarantine` et chiffrée avec la clé DPAPI SYSTEM. L’onglet Quarantaine en affiche le résumé ; le bouton **Gérer (administrateur)** ouvre, après UAC, une fenêtre de restauration et de suppression servie par le service. Conservation : 90 jours.

### ProcessStartMonitor — scan au démarrage d’un processus

Le moniteur WMI examine au lancement l’image du processus (extension listée ou en-tête PE, quelle que soit l’extension) et, pour les hôtes de scripts ainsi que `rundll32` et `regsvr32`, les fichiers cités dans la ligne de commande (`x.dat,Entry` compris). Il ouvre le fichier avec le jeton du processus déclencheur et scanne une copie temporaire limitée à 256 Mio. Avant une quarantaine automatique, le contenu actuellement présent au chemin doit avoir le même SHA-256 que la copie analysée ; sinon l’action est refusée. Si le processus a déjà quitté, si le fichier est inaccessible avec son identité ou s’il dépasse la limite, ce scan de démarrage est sauté.

### RemovableDriveScanService — clés USB et cartes SD

`RemovableDriveScanService.cs` : à l’**insertion** d’un volume (WMI `Win32_VolumeChangeEvent` + polling de secours), analyse automatique en arrière-plan si l’option est activée (**Options → Analyser les clés USB et cartes SD**, activée par défaut).

| Aspect | Comportement |
|---|---|
| Détection | `DriveType.Removable` **ou** lecteur `Fixed` reconnu USB via WMI (`InterfaceType`, `PNPDeviceID`, `MediaType`) |
| Déjà branché au démarrage | Enregistré sans scan (évite une vague au lancement) |
| Mode rapide (défaut) | `CollectRiskyFiles` en **un seul parcours** sans suivre les jonctions : **extension à risque** (`RiskyFileExtensions`) ou **en-tête PE** (`ExecutableSniffer`), exécutables placés en premier (plafond **4 000**, délai énumération **90 s**) ; **ClamAV `--file-list`** puis **YARA par lots en série** (`scanEnginesSequentially: true`, évite verrous USB) ; **timeout 10 min** ; repli `ScanFolderBackgroundAsync` si erreur/annulation |
| Mode complet (option) | `ScanFolderBackgroundAsync` récursif (ClamAV + YARA en parallèle, **sans pré-dénombrement YARA**) ; **timeout 45 min** |
| Taille max. | **64 Go** par défaut (`RemovableDriveMaxSizeGb` ; `0` = illimité) |
| Analyse complète manuelle | Option **Inclure les lecteurs amovibles** → `ScanTargets.FullScanTargets(includeRemovable: true)` |
| UI / notifications | Toasts début/fin (`ShowRemovableDriveScanStarted` / `ShowRemovableDriveScanCompleted`) si notifications activées ; barre de statut **Démarré** / **Terminé** / **Échec** via `ScanStatusChanged` (`MainWindow`) |
| Menace détectée | Historique (`ScanType.RemovableDrive`), quarantaine auto si activée, liste **Analyser** via `ThreatDetected` (même handler que la RTP) ; RTP **suspendue** pendant le scan |

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

## 6. Workflow utilisateur optiSCAN v3.1 candidate

```
DÉMARRAGE (UI)
    │
    ├─→ Mutex single-instance (2e instance → IPC « afficher » la fenêtre existante)
    ├─→ `App.OnStartup` → `InstallGlobalCrashHandlers()` puis `LocalizationService.Initialize()` (fr-FR / en-US : prefs, registre installateur)
    ├─→ `ThemeManager.Initialize()` (préférence `UserPreferences`)
    ├─→ `MainWindow` : `BindAllViewPanels` avant navigation sidebar ; `ServiceContainer.Default` (ClamAV, YARA, orchestrateur, MAJ, quarantaine, planif., logs, `AntivirusActions`, `ThreatLookup` → VM)
    ├─→ Minuteries MAJ : freshclam **4 h**, règles YARA **24 h** (désactivables via Options)
    ├─→ `ScanViewModel.InitializeAsync` : versions, base, YARA, historique, quarantaine
    ├─→ Protection temps réel : état selon **Options** (`ServiceContainer.RealTimeProtection`)
    ├─→ Scan USB/SD : `ServiceContainer.RemovableDriveScan` si option activée
    └─→ Fenêtre principale + icône zone de notification (réduction possible sans quitter)
            │
            ├─→ [VUE D'ENSEMBLE] — hero (protection + dernière analyse), cartes d’action, statistiques 30 j., recommandations
            ├─→ [NETTOYER] — temporaires, caches navigateurs (Edge, Chrome, Firefox, Brave, **Opera**, **Vivaldi**, **Arc**), corbeille, journaux Windows
            ├─→ [ANTIVIRUS] — scans rapide/complet/dossier/fichier, quarantaine, historique de session, signatures
            ├─→ [HISTORIQUE] — timeline `activity_log.dat` (5 filtres) ; sessions version 2 : détections, quarantaine / ignorer / supprimer, **Traiter dans Analyse** ; exports **HTML** / **PDF**
            └─→ [OPTIONS] — langue FR/EN, thème (sync Windows par défaut), scan favori, démarrage auto, MAJ auto, RTP, scan USB/SD, quarantaine auto, planification, exclusions

FERMETURE
    └─→ `MainWindow.OnWindowClosing` → `MainWindowShutdownCoordinator.PerformCleanShutdown` → `ServiceContainer.Shutdown()` (RTP, scan USB, minuteries MAJ, moteurs)

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
- Le test EICAR est couvert par la règle YARA embarquée `rules/test_rules.yar` (`EICAR_Test`) ; ClamAV le détecte aussi si la base est à jour

### Exclusion Windows Defender

Voir aussi [§4.7](#47-système-dexclusions) (détail technique). Résumé :

- **Opt-in** : Options → « Réappliquer les exclusions Defender », ou script admin `.\scripts\add-defender-exclusions.ps1`.
- Chemin : `Program Files\optiSCAN` ; processus par **chemin complet** sous ce dossier (jamais par simple nom).
- L’installeur **ne lance plus** le script automatiquement (profil allégé façon version 2).

Si la **protection contre la falsification** de Defender est active, l’ajout peut échouer — ajoutez les chemins dans *Sécurité Windows → Protection contre les virus et menaces → Exclusions*.

---

## 8. Publication, installateur et checklist release (v3.1 candidate)

> **Version candidate** : assembly **3.1.0** (`Directory.Build.props`, Inno Setup), non publiée. **Branche de préparation** : `dev`; les validations et l'historique local précèdent toute publication distante — voir le [plan de release v3.1](RELEASE_PLAN_v3.1.md).

### Prérequis machine de build

- Windows 10/11 x64, .NET 10 SDK (version fixée par `global.json`), Inno Setup 6
- Réseau (téléchargement ClamAV, YARA, signatures freshclam)
- Binaires **non versionnés** dans Git : `.\scripts\fetch-runtime-deps.ps1`

### Chaîne automatique (recommandée)

```powershell
# Depuis la racine du dépôt (dossier contenant optiSCAN.sln)
# Tout-en-un local (clean → publish FolderProfile → verify → ISCC) :
.\installer\build-release-setup.ps1

# Variante release complète (prepare-release-v3) :
.\scripts\prepare-release-v3.ps1
```

Équivalent manuel : `clean-before-publish` → `dotnet publish` → `verify-runtime-deps` → `build-release-setup.ps1 -SkipPublish`.  
Détails distribution (modes runtime, Embed signatures) : [`docs/GUIDE_DISTRIBUTION.md`](docs/GUIDE_DISTRIBUTION.md).

Sortie publish : `optiSCAN\bin\Release\net10.0-windows10.0.17763.0\publish\win-x64\` (chemin attendu par `installer\setup.iss`). `publish-release.ps1` produit toujours une publication self-contained ; la taille varie surtout selon l'inclusion des signatures. L'estimation historique de ~26 Mo ne correspond pas au profil actuel.

Offline avec bases + règles : `.\scripts\publish-release.ps1 -EmbedOfflineSignatures`.

### Ordre recommandé (équipe)

1. Gel fonctionnel : `.\scripts\validate-release-readiness.ps1` (ou suite `dotnet test` Release sur le commit candidat).
2. Dépendances : `.\scripts\fetch-runtime-deps.ps1` (binaires ClamAV/YARA ; freshclam optionnel — les CVD/`.yar` se téléchargent aussi **après install** via MAJ signatures).
3. Publish local : `.\scripts\prepare-release-v3.ps1` ou `clean` → `dotnet publish` → `build-release-setup.ps1 -SkipPublish`.
4. VM propre : installer `optiSCAN_Setup_v3.1.0.exe` ; **MAJ signatures** (freshclam + asset YARA-Forge épinglé ; vérifier l'échec fermé si la release latest n'est plus `20261004`) ; scan, RTP optionnelle, FR/EN.
5. CI : push `main` → job **Publish win-x64** ; artefact `optiSCAN-setup-<sha>.exe`.
6. Signature : secrets `CODESIGN_PFX` (base64) et `CODESIGN_PASSWORD` → la CI signe binaires, installateur et désinstalleur (`scripts/codesign.ps1`). Local : `build-release-setup.ps1 -SignPfxPath cert.pfx`.
7. Après validation et accord de publication : `git tag v3.1.0`, puis release GitHub, SourceForge ou site.

### Étapes manuelles détaillées

**Étape 0 — nettoyage (recommandé)**

```powershell
.\scripts\clean-before-publish.ps1 -IncludeObj -IncludeInstallerOutput -IncludeCiPublish
```

**Étape A — publication .NET** (application puis service, dans le même dossier et le même mode : l’installeur refuse de se compiler sans `optiSCAN.Service.dll`, sauf `/DAllowMissingService` pour un build de développement)

```powershell
dotnet publish .\optiSCAN\optiSCAN.csproj -c Release /p:PublishProfile=FolderProfile
dotnet publish .\optiSCAN.Service\optiSCAN.Service.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false `
    -o .\optiSCAN\bin\Release\net10.0-windows10.0.17763.0\publish\win-x64
```

**Étape B — (optionnel) bases ClamAV dans le publish** — non requise pour l’installeur **par défaut** (téléchargement post-install). Utile pour tests locaux ou `-EmbedClamAvDatabase` :

```powershell
$pub = ".\optiSCAN\bin\Release\net10.0-windows10.0.17763.0\publish\win-x64"
& "$pub\clamav\x64\freshclam.exe" --datadir="$pub\clamav\database"
```

**Étape C — compilateur Inno Setup**

```powershell
.\installer\build-release-setup.ps1 -SkipPublish
# ou : & "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe" .\installer\setup.iss
```

**Installateur** : assistant **bilingue** (français / English) ; langue choisie → `UiCulture` en registre pour le premier lancement de l’app.  
**Profil release recommandé** : x64 only ; `prepare-release-v3.ps1` utilise `FolderProfile` (self-contained, runtime inclus) et `publish-release.ps1` inclut toujours le runtime .NET ; service plateforme **décoché** ; ni AMSI ni pilote ; **pas** d’exclusions Defender auto ; bases ClamAV via **MAJ signatures** après install, règles YARA dans `%LOCALAPPDATA%\optiSCAN\rules`.

**Contenu de l'installateur (taille dépend du mode de publication, hors CVD/.yar) :**

```
optiSCAN_Setup_v3.1.0.exe
    ├── optiSCAN.exe + dépendances .NET (runtime inclus)
    ├── optiSCAN.Service.exe + optiSCAN.Service.dll + dépendances (service de protection, enregistré seulement si la case est cochée)
    ├── optiSCAN.ico / hero / shield
    ├── clamav/x64/          ← Binaires (clamscan, clamd, freshclam) — sans database/
    ├── yara/                ← yara64 / yarac (moteur)
    ├── rules/               ← absent par défaut ; téléchargé si latest correspond à l'asset épinglé `20261004`
    ├── scripts/             ← add-defender-exclusions.ps1 (opt-in manuel / Options)
    └── (ni AMSI ni .sys : non livrés en v3.1 candidate)
```

Offline complet : `publish-release.ps1 -EmbedOfflineSignatures` (CVD + `.yar` dans le setup).

### Checklist binaire (bloquant)

- [ ] Suite `dotnet test` Release réussie sur le commit candidat
- [ ] `.\scripts\verify-runtime-deps.ps1` — vert sur dossier publish (exige aussi `optiSCAN.Service.exe`, `optiSCAN.Service.dll`, son `runtimeconfig.json` et `optiSCAN.Platform.dll`)
- [ ] `clamscan.exe`, `freshclam.exe`, **`clamd.exe`**, `yara64.exe` (rules `.yar` : OK si absentes — MAJ post-install)
- [ ] `clamav\database\` — optionnel dans le setup défaut ; après install : freshclam / MAJ signatures
- [ ] Installateur FR/EN, service plateforme décoché par défaut ; vérifier que le runtime est inclus dans la publication de release
- [ ] Test post-install : **MAJ signatures** → scan fichier, quarantaine, historique ; exclusions Defender via Options si souhaité
- [ ] Après upgrade depuis la version 1 : `scan_history.dat` présent (éventuellement `scan_history.json.legacy`)

### CI GitHub

Pipelines : [`.github/workflows/ci.yml`](.github/workflows/ci.yml), [`codeql.yml`](.github/workflows/codeql.yml), [`dependency-review.yml`](.github/workflows/dependency-review.yml), [`gitleaks.yml`](.github/workflows/gitleaks.yml).

| Branche | Comportement |
|---------|----------------|
| **`main`** | `fetch-runtime-deps.ps1` → `fetch-runtime-deps.ps1 -RunFreshclam` (timeout 45 min) → `dotnet publish` → signature (si secrets) → SBOM CycloneDX → Inno → installateur nommé depuis `Directory.Build.props` |
| **`dev`** | Build + tests + artefact binaire Release (sans installateur complet) |

**Couverture** : seuil minimal **40 %** lignes (échec CI si en dessous) ; avertissement si &lt; **50 %** (cible progressive).

**Freshclam en CI** : génère un `freshclam.conf` minimal dans `clamav\x64\` (non versionné dans Git, comme en production via `FreshclamUpdater`). **Erreur connue (corrigée)** : `Can't open/parse freshclam.conf` si freshclam est lancé sans `--config-file`.

**Repères historiques de couverture** : le chiffre de 289 cas correspondait à une ancienne release ; vérifier la suite et la couverture de la révision candidate dans CI.

| Module | Fichier de tests |
|--------|------------------|
| Recommandations accueil | `OverviewRecommendationsBuilderTests` |
| Stats accueil 30 j. | `OverviewProtectionStatsFormatterTests` |
| Posture /100 | `SecurityPostureServiceTests` |
| Historique / timeline | `ActivityLogServiceTests`, `ScanLogManagerTests` ; `HistoryDetailCoordinatorTests`, `HistoryThreatRemediationCoordinatorTests` |
| Coordinateurs MainWindow | `MainWindowStartupCoordinatorTests`, `WindowTrayBehaviorCoordinatorTests`, `ToastActivationCoordinatorTests`, `ExportCoordinatorTests`, … |
| Scan USB/SD | `RemovableDriveDiscoveryTests`, `RemovableDriveScanServiceTests` |
| Intégration EICAR (YARA) | `EicarIntegrationTests` — règle `EICAR_Test` dans `test_rules.yar` (no-op si `yara64.exe` absent) |
| Signatures (cache TTL) | `SignatureStatusServiceTests` |
| Thème Windows | `ThemeManagerPreferenceTests` |
| Persistance | `SecureStoreTests`, `UserPreferencesStorageTests`, `ExclusionSettingsTests`, `OptiscanProtectedPathsTests`, `WindowsDefenderExclusionServiceTests` |

### Après publication

- Conserver `main` et `dev` alignées (même tip après merge release).
- **Version 1 → version 2** : migration historique JSON → `scan_history.dat` (DPAPI) au premier lancement.
- Maintenabilité et choix volontaires : [§12.1](#121-maintenabilité-et-choix-volontaires-non-bloquants-v30).

### Signature Authenticode (optionnelle)

Sans PFX configuré, les artefacts restent non signés. La signature Authenticode facultative utilise `CODESIGN_PFX` (base64) et `CODESIGN_PASSWORD` dans la CI. Celle-ci signe les binaires de l'application, puis l'installateur et le désinstalleur ; localement, utiliser `scripts/codesign.ps1` puis `installer/build-release-setup.ps1 -SignPfxPath cert.pfx`. La signature ne garantit pas une réputation SmartScreen ni l'absence de blocage par un autre produit de sécurité. Voir [la procédure de signature](docs/SIGNATURE_PROCEDURE.md).

---

## 9. Langues de l’interface (fr-FR / en-US)

| Canal | Comportement |
|-------|----------------|
| **Installateur Inno** | Choix FR ou EN → `HKCU\Software\optiSCAN\UiCulture` |
| **Options → Langue** | Français / English → confirmation → **redémarrage** de l’app |
| **Ressources** | `UiStrings.resx` + `UiStrings.en.resx` (**621** clés FR/EN, parité vérifiée en CI) |
| **Menu contextuel** | « Scanner avec optiSCAN » ou « Scan with optiSCAN » sur **fichiers et dossiers** (`--scan`) |

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
| ClamAV | 1.4.6 épinglé | GPLv2 | Inclure la licence dans l'installateur ; archive vérifiée (signature Talos + SHA-256) le 4 octobre 2026 |
| YARA | 4.5.5 épinglé | BSD-3-Clause | Dernier binaire Windows officiel. Les versions 4.5.6 à 4.5.8 sont publiées en sources seulement ; les adopter suppose de compiler YARA en CI |
| .NET 10 WPF | 10.x (LTS) | MIT | Runtime publié avec l'application (self-contained) ; support Microsoft annoncé jusqu'au 14 novembre 2028 |
| MaterialDesignThemes | 5.3.1 | MIT | Bibliothèque UI (PackIcon, styles) |
| QuestPDF | 2024.12.2 | Community | Rapport PDF — licence gratuite projets open-source |
| Mise à jour binaire optiSCAN (`UpdateService`) | — | — | Canal OTA non configuré ; staging `%LocalAppData%\optiSCAN\Updates` ; signatures via Antivirus |
| Planificateur de tâches (`schtasks.exe`) | — | — | Natif Windows — voir `ScheduledScanService` |
| Microsoft.Toolkit.Uwp.Notifications | 7.1.3 | MIT | Toasts Windows natifs |
| Inno Setup | 6.x | Freeware | Gratuit pour projets commerciaux |
| Base de signatures ClamAV | — | ClamAV License | Mise à jour depuis database.clamav.net |
| Règles de détection | — | Diverses open-source | Récupérées depuis l'asset YARA-Forge explicitement épinglé dans optiSCAN |

---

## 11. Historique des versions produit

### v3.0 — 30 septembre 2026

- **Version produit** — assembly **3.0.0** ; service Windows `optiSCANProtection`, affiché « optiSCAN Protection v3 » ; pipe `optiSCAN_Protection`. L’installeur arrête ce service s’il existe déjà et ne le recrée que si la case « protection avancée » est cochée.
- **3.0.0** — mise à jour par-dessus une installation existante : l’installeur ferme optiSCAN et arrête le service, sans désinstallation. Accueil : « Corriger » applique l’action (protection, MAJ auto, analyse rapide, suppression des partages après confirmation) ; le rafraîchissement de l’accueil se fait en arrière-plan
- **Historique des détections** — les détections de la protection temps réel et de la surveillance des processus laissent une session « Protection temps réel » (`ScanType.RealTime`, `DetectionHistoryRecorder`) dans l’Historique ; écriture de `scan_history.dat` verrouillée (accès concurrents)
- **Indépendance vis-à-vis des autres produits** — le nettoyage du menu contextuel (`ShellContextMenuSupport`, `setup.iss`) ne supprime plus les entrées « Scan with optiCombat » ; optiSCAN garde l’`AppId` Inno historique `F3A2C1D0-…`, distinct d’optiCOMBAT et d’optiSCAN WinUI 3
- **18 septembre 2026** — Optimiser → Mises à jour : `winget upgrade --uninstall-previous` puis désinstallation des versions encore listées du même identifiant (hors runtimes côte à côte : VC++, .NET, DirectX), pour ne plus empiler v4, v5, v6… du même programme
- **Optimiser** (ex-Nettoyer) — panneau sidebar + 3 sous-onglets : **Nettoyage** (temp, navigateurs, corbeille, cache WU, DNS), **Mises à jour** (`WingetUpdateService` + lien Windows Update), **Tweaks** (`SystemTweaksService`, une invite UAC regroupée)
- **Mode complément Defender** — coexistence recommandée : Defender garde le RTP ; optiSCAN scans manuels/planifiés
- **Exclusions Defender** — **opt-in** (Options / script) ; plus d’exécution silencieuse à l’install ni au démarrage
- **Installateur** — x64 only ; publish autonome ; service plateforme décoché ; CVD ClamAV + règles YARA **post-install** (freshclam / YARA-Forge) ; ni AMSI ni pilote ; chaîne locale : `.\installer\build-release-setup.ps1`
- **ClamAV 1.4.x** — binaires x64 ; correction `freshclam.conf` (retrait `CVDCertsDirectory`, certificats via `CVD_CERTS_DIR`)
- **AMSI** — non livré en v3.0 (prototype natif non compilable) ; la désinstallation retire toute clé AMSI laissée par une version antérieure
- **Service v3** — `optiSCANProtection`, affiché « optiSCAN Protection v3 », n’est créé que si la case « protection avancée » est cochée

### v2.0 — 23 juin 2026 — Clamd, posture, historique unifié, scan USB, coordinateurs

- **Anti-autophagie** — `OptiscanProtectedPaths` : installation réservée aux administrateurs (sinon ses moteurs, bases et règles) et sous-dossiers `clamav`, `clamd`, `rules`, `Quarantine`, `SafetyBackups` de `%LOCALAPPDATA%\optiSCAN` exclus des scans / RTP / quarantaine auto ; dossiers obligatoires dans Options
- **Exclusions Defender** — `WindowsDefenderExclusionService` + `scripts/add-defender-exclusions.ps1` : chemins et processus optiSCAN enregistrés à l’install et au démarrage (`--defender-exclusions` si UAC)
- **Démarrage UI** — handlers globaux d’exceptions (`InstallGlobalCrashHandlers`) ; `BindAllViewPanels` avant navigation sidebar (course XAML / services)
- **Publish** — cible MSBuild `CleanStalePublishOutput` : nettoyage de `publish\` uniquement (évite publish cassé)
- **Refactor UI** — ~22 coordinateurs (`optiSCAN/Coordinators/`) : startup/shutdown, systray, exports, historique, RTP/USB/toasts ; `MainWindow` allégé (~730 L)
- **DI préférences** — `IUserPreferencesAccessor`, `IExclusionSettingsAccessor` ; vues via `IViewServices` / `IHistoryServices` / `IHistoryExportService`
- **Qualité** — `.editorconfig` ; NetAnalyzers `latest-recommended` ; **289** tests ; SBOM CycloneDX en publish CI
- **Historique** — `ActivityLogService` + `activity_log.dat` (150 événements, migration unique) ; `HistoryViewModel` (5 filtres, `SelectionKey`) ; menaces traitables (**Traiter dans Analyse**) ; `scan_history.dat` / `clean_history.dat` (rotation 100→50) ; compat version 1 sans chemins
- **Accueil** — `OverviewRecommendationsBuilder` + `OverviewProtectionStatsFormatter` (stats 30 j. sans doublon dans les recommandations)
- **Scan USB/SD** — rapide = extensions à risque (4 000 max), moteurs **en série**, timeouts 10/45 min, repli récursif ; complet = `ScanFolderBackgroundAsync` ; statut barre + toasts début/fin
- **Quarantaine** — rollback si suppression originale échoue ; `ReconcileQuarantinedThreats` ; session scan active (`ActiveScanSessionId`)
- **Thème Windows** — `SyncWindowsTheme` par défaut ; case Options (thème opposé à Windows) ; `ThemeManager.Initialize()` dans `MainWindow` avant `InitializeComponent`
- **clamd** — `CompositeClamAvBackend` ; clamd en AppContainer, flux `zINSTREAM` par tube nommé, repli `clamscan.exe` par fichier non lu
- **Posture /100**, **VirusTotal**, **mode jeu** — voir [§13](#13-sécurité-posture-et-menaces) et Options
- **Tests** — **289** tests Release — [§12](#12-audit-et-qualité) ; i18n **621** clés FR/EN ; coordinateurs + exports couverts par tests dédiés

### v1.0 — 1 juin 2026 — interface Donaby

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

### Version 1 — 26 mai 2026

- **Interface bilingue** — français et anglais embarqués (`LocalizationService`, `UiStrings` / `UiStrings.en`) ; installateur et Options avec redémarrage ; menu contextuel Explorateur localisé
- **Documentation** — `README.md` ; scripts `clean-before-publish.ps1` et `build-release-setup.ps1`
- **Expérience d’analyse** — libellés utilisateur unifiés (`ScanUserDisplay`) ; progression monotone (`ScanProgressRelay`) ; fusion menaces (`ScanThreatMerger`) ; tests unitaires étendus
- **Antivirus** — analyse par boutons (rapide, complète, fichier, dossier) ; suppression du glisser-déposer

### Version 1 — 22 mai 2026

- **Optimiser (Nettoyage)** — historique des sessions dans `CleanControl` (colonne **Libéré** / `BytesDisplay`) + onglet Historique
- **Stabilité** — `ThreatInfo.Id` SHA-256 déterministe ; quarantaine avec nom de menace réel ; `ServiceContainer.Shutdown()` à la fermeture
- **UI / services** — cibles récentes, colonne **Risque**, planification partagée, journal des analyses, périmètres protégés optiSCAN
- **Documentation** — README et CLUF alignés sur le code (plus de référence à `ClamDaemon.cs`)

### Version 1 — 14 mai 2026

- **Interface d’analyse** — progression, fichier courant, fusion ClamAV + YARA (`ScanOrchestrator`)
- **Vue d’ensemble** — statistiques sur 30 jours, recommandations et bannière de protection **branchées** sur les services et l’historique
- **Options** — thème, `SyncWindowsTheme`, scan favori, RTP, quarantaine auto, planif. (`ScheduledScan` partagé, prochaine exécution, lancement immédiat), exclusions **DPAPI** (`exclusions.dat`)
- **Auto-exclusion** — périmètres protégés (`OptiscanProtectedPaths` : installation, bases, règles, quarantaine) pour éviter l’auto-détection
- **Historique** — export **HTML** / **PDF** (dernier ou session sélectionnée) ; onglet **Journal** (`optiSCAN.log`)
- **Antivirus** — cibles récentes, colonne **Risque**, actions via **`AntivirusActions`**
- **Identifiants** — `ThreatInfo.Id` SHA-256 stable ; quarantaine conserve le vrai nom de menace
- **Logs** — nettoyage `AppLogger` 30 j. avec marqueur `.lastcleanup` persisté
- **Fermeture** — `ServiceContainer.Shutdown()` depuis `MainWindow`
- **Quarantaine** — format stockage **AES-256-GCM** (`OPTQ`) ; alignement silencieux des fichiers au format attendu au démarrage
- **Instance unique** — seconde exécution : **IPC** (`IpcManager`, WM_SHOWME) pour réafficher la fenêtre existante
- **Manifeste** — **`asInvoker`** + élévation ponctuelle (`ElevationHelper`) pour réduire la surface d’attaque
- **Français** — libellés et documentation alignés sur le comportement réel de l’application

### Version 1 — Donaby Design

- **Donaby Design System complet** — refonte UI vers le thème clair Donaby Light par défaut
- **OverviewControl** — hero (titre + dernière analyse), 4 cartes d'action cliquables ; statistiques et recommandations (sans panneau ClamAV/YARA sur l'accueil)
- **AntivirusView** — boutons d’analyse (rapide, complète, fichier, dossier) ; liste **cibles récentes** reliée à `UserPreferences`
- **CleanControl** — Brave, **Opera**, **Vivaldi**, **Arc**, journaux Windows
- **FreshclamUpdater** — `EnsureConfExists()` : résolution automatique du conf manquant (`x64\` → parent → `x86` → génération) ; `ResolveDbDir()` : résolution intelligente du dossier de base de données selon la hiérarchie clamav
- Correction CS0104 `CheckBox`/`Button` ambiguous — aliases `WpfCheckBox`/`WpfButton` dans `OptionsControl.xaml.cs`
- **README aligné code** — navigation, quarantaine AES-GCM, pipeline clamscan + YARA, RTP / planificateur / packaging
- **MAJ auto** — `ServiceContainer` arme freshclam (4 h) + YARA-Forge (24 h) ; Options coupe/réactive les deux

### Version 1 — services avancés

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

### Version 1 — 30 avril 2026, fondations

- Scanner ClamAV (rapide / complet / dossier / fichier)
- Moteur YARA comportemental + règles YARA-Forge
- Quarantaine locale chiffrée (`.quar` + `manifest.json`)
- Historique des scans (rotation 100→50 ; détail menaces et chiffrement **.dat** depuis la **version 2**)
- Mise à jour automatique signatures (4 h) et règles (24 h)
- Système d'exclusions (dossiers + règles)
- Nettoyage fichiers temporaires

---

## 12. Audit et qualité

### v3.1 — candidate en préparation

- Version de build préparée : **3.1.0** ; la candidate n'est ni publiée ni taguée.
- Les constats de l'[audit 360 du 2 octobre 2026](AUDIT_optiSCAN_360.md) et leur traitement sont suivis dans l'audit et dans le [plan de release v3.1](RELEASE_PLAN_v3.1.md).
- Validations de release encore requises : tests Windows, parcours service/quarantaine installé et premier succès CodeQL C/C++ sur GitHub.
- Relectures du 7 octobre 2026 : séries **Y1–Y5** et **Z1–Z9** (publication du service, nettoyeur et jonctions, noms de périphériques, tube clamd, couverture de détection…) et corrections de robustesse — [audit, sections 4.6, 4.7 et 12](AUDIT_optiSCAN_360.md#46-relecture-du-7-octobre-2026--y1-à-y5).

**Réévaluation du 2 octobre 2026** — base `main` (`0e8161f`, release 3.0.0) + branche `refactor/protection-identifiers`. Revue statique du dépôt, compilation Release de toute la solution (analyseurs actifs, avertissements = erreurs) et contrôles automatisés ; tests non exécutés ici (runtime WPF requis, voir Tests & CI).

**Portée de cette note** : résultats historiques de la revue du 2 octobre 2026 sur les sources indiquées ci-dessus. Ils ne décrivent pas l’arbre de travail corrigé depuis ; voir l'[audit 360](AUDIT_optiSCAN_360.md) et ses [réserves ouvertes](AUDIT_optiSCAN_360.md#9-réserves-ouvertes-et-conditions-de-clôture). Les vérifications de compilation et de test ci-dessous ne couvrent pas les modifications locales plus récentes.

| Domaine | Note | Évolution | Commentaire |
|---------|:----:|:---------:|-------------|
| Architecture | 8/10 | = | DI (`ServiceContainer`), coordinateurs, `CompositeClamAvBackend`. **Nouveau** : identifiants de protection centralisés (`ProtectionIdentifiers`) avec miroirs C++/Inno testés, protocole IPC versionné (`proto`). Reste : 6 fichiers > 700 lignes (`MainWindow.xaml.cs` 793, `OptionsControl.xaml.cs` 766, `QuarantineManager` 764…) |
| Qualité du code | 7/10 | *nouveau* | ~26 700 lignes C# (app) + 5 100 XAML ; 0 TODO, 0 `#pragma` ; mais 283 `catch` génériques dont 37 vides, 16 règles CA désactivées dans `.editorconfig`, 6 appels `GetAwaiter().GetResult()`. Bug de chemin `clamd --config-file` corrigé (test de non-régression `ClamdHostTests`) |
| Sécurité locale | 8/10 | = | Quarantaine AES-GCM + HMAC, clé DPAPI ; exclusions et `SecureStore` DPAPI + HMAC ; `optiSCAN.log` avec chemins masqués (`PathRedaction`) |
| Sécurité plateforme (service, IPC, AMSI) | 7/10 | *nouveau* | Pipe avec ACL, limitation de débit, jeton d’arrêt protégé, refus explicite des protocoles inconnus ; noms service/pipe du contrat v3 indépendants du numéro d’assembly (`optiSCANProtection`, `optiSCAN_Protection`). Limites : ni AMSI ni minifiltre livrés (prototypes hors produit) ; signature Authenticode dépendante des secrets `CODESIGN_*` |
| UI / accessibilité | 8/10 | = | `AutomationProperties` présents dans les 5 vues + `MainWindow` (audit de juillet : 4 vues sur 7) ; politique de confidentialité accessible depuis Options ; FR/EN |
| Tests & CI | 9/10 | = | **330** méthodes de test (312 `[Fact]`, 18 `[Theory]`, ≈ 380 cas) contre 289 documentés ; CodeQL, gitleaks, dependency-review, SBOM, seuil de couverture 40 % (cible 50 %). Build Release de la solution rétablie (CA1863 dans `OverviewControl.xaml.cs`, CA1711 et CS1998 dans les tests). Couverture non remesurée |
| Release Inno | 7/10 | = | Mise à jour sans désinstallation ; signature Authenticode toujours absente (SmartScreen) |

**Note globale : 7,7/10** (7 domaines, moyenne simple) contre 8,0/10 sur l’ancienne grille de 5 domaines. L’écart vient des deux domaines ajoutés, plus exigeants (qualité du code, sécurité plateforme). Avant correction de la build Release, la note était de 7,4/10.

**Dettes ouvertes, par priorité**

1. ✅ ~~**Build Release cassée**~~ — corrigé : `OverviewControl` utilise `LocalizationService.Format` (CA1863) ; projet de tests : CA1711 désactivée pour les classes `[CollectionDefinition]` (convention xUnit), méthode de test `async` sans `await` rendue synchrone (CS1998).
2. ✅ ~~**`clamd` ne démarrait pas si le profil Windows contient un espace**~~ — corrigé : `ClamdHost.BuildStartInfo` passe le chemin par `ProcessStartInfo.ArgumentList` ; test `ClamdHostTests`.
3. **🟠 Signature Authenticode** de l’installeur et des `.exe` : chaîne prête (`scripts/codesign.ps1`), reste à fournir le certificat (`CODESIGN_PFX`, `CODESIGN_PASSWORD`).
4. **🟡 37 `catch` vides** à journaliser au minimum (`AppLogger.Debug`), en priorité dans `Services/`.
5. **🟡 Découper les fichiers de plus de 700 lignes**, en commençant par `OptionsControl.xaml.cs` et `QuarantineManager`.
6. **🟡 Tests d’intégration** réels clamd / schtasks / service Windows ; remesurer la couverture et viser 50 %.

```powershell
dotnet build optiSCAN.sln -c Release
dotnet test optiSCAN.Tests\optiSCAN.Tests.csproj -c Release
```

### 12.1 Maintenabilité et choix volontaires (non bloquants, v3.0)

**`MainWindow` allégé (version 2)** — la logique événementielle est dans `optiSCAN/Coordinators/` (classes `static` + hôtes typés). Il reste dans la fenêtre : enregistrement des panneaux, branchement `ServiceContainer`, et raccourcis navigation.

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

**Actifs** : fichiers analysés, quarantaine, historique, préférences/exclusions (`%LocalAppData%\optiSCAN` de l’utilisateur interactif), données de l’hôte et copies de scan sous `%ProgramData%\optiSCAN`, ainsi que les données distinctes du processus SYSTEM.

**Contrôles** : quarantaine AES-GCM + HMAC ; exclusions avec frontière `\` ; périmètres protégés optiSCAN (`OptiscanProtectedPaths`) ; exclusions Defender **opt-in** (`WindowsDefenderExclusionService`) ; UAC pour scan complet ; RTP ; clamd sur `127.0.0.1`.

**Limites** : malware admin peut neutraliser l’AV local ; pas d’AMSI ni de minifiltre dans la candidate v3.1 (FileSystemWatcher agit après l’écriture) ; le temps réel peut manquer une écriture si sa récupération échoue ; les scans de démarrage de processus ont une limite de taille et de droits ; les détections du service SYSTEM ne sont pas visibles dans l’historique interactif ; la quarantaine SYSTEM n’est gérable que par un administrateur élevé. VirusTotal transmet le hash si l’utilisateur configure sa clé. Les journaux ne sont pas chiffrés. Les segments de profils Windows standard (`C:\Users\…`) sont masqués par `PathRedaction`, mais les chemins personnalisés et certaines données de diagnostic peuvent rester lisibles.

### Durcissements de sécurité (v3.1 candidate, relectures du 7 octobre 2026)

- **Publication** : le service est publié avec sa DLL et ses dépendances dans le dossier de l’application ; l’installeur refuse de se compiler sans `optiSCAN.Service.dll`.
- **Outils Windows** lancés par leur chemin complet, dans l’application et dans l’installeur (jamais par un nom nu, que Windows chercherait d’abord dans le dossier courant).
- **Nettoyer** : aucune jonction ni lien suivi ; un dossier remplacé par une jonction pendant le nettoyage est refusé.
- **Copies d’analyse** : un nom de périphérique DOS (`COM1.txt`, `NUL`…) ou un flux nommé est remplacé par `content` + extension.
- **Pipe du service** : `scan_buffer` fermé tant qu’AMSI n’est pas livré ; chemins `\\?\` normalisés et chemins de périphérique refusés ; contrôle et écriture de `set_policy` atomiques.
- **clamd** : le client n’accepte qu’un serveur du même compte et n’autorise pas l’usurpation ; clamd et son relais sont rattachés à un objet job et s’arrêtent avec l’hôte.
- **Détection** : extensions élargies, exécutables PE reconnus quelle que soit l’extension (temps réel, processus, USB), `rundll32` et `regsvr32` suivis.

### Robustesse (v3.1 candidate)

- **Gestionnaires `async void` de l'interface** (Nettoyer, Options) et `AsyncRelayCommand` : les exceptions sont journalisées au lieu de fermer l'application ; la suite des gestionnaires reste sur le thread de l'interface.
- **Arrêt de l'hôte du service** : la demande d'arrêt envoyée par le service Windows (jeton vérifié) arrête proprement temps réel, IPC et conteneur avant la fin du processus. Les processus auxiliaires (relais clamd) gardent une sortie immédiate.
- **Tâches de fond** supervisées et journalisées (migration de la quarantaine, nettoyage Defender, reprise des watchers, relais clamd).
- **Defender** : les exclusions que Defender refuse de retirer sont journalisées.
- **Quarantaine** : la migration des anciens fichiers ne bloque plus la quarantaine pendant toute sa durée ; chaque écriture reste sous verrou et vérifie que l'entrée existe encore.
- **Signatures ClamAV** : le dossier de la base est résolu une fois par moteur, et non à chaque lancement de clamscan (la résolution crée un dossier de test et vérifie les droits de ProgramData en SYSTEM).

---

## 14. Crédits

Développé par **© 2026 Donatien Byakombe**  
Design system : **Donaby Design**
