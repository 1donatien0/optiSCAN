# Guide Complet — optiSCAN v1.0 (édition WinUI 3)

> **Version de référence.** Édition WinUI 3 (branche `win`). Jusqu’à la v2, les commits sont **les mêmes** que sur `main` / `dev` (historique réécrit : courriel perso, etc.). Le `first commit` ouvre le shell WinUI 3 ; la v3 WPF reste sur `main` / `dev`. Architecture mono-fenêtre, services avancés + Donaby Design System.  
> **Nomenclature** — **v1.0** : nom de release de l’édition WinUI 3 (documentation, GNU GPL v3), propre à cette branche. **1.0.0** : assembly et installateur (`Directory.Build.props`, Inno Setup).
>
> **Design system : Donaby Design** — thème sombre/clair dynamique, tokens ThemeResource WinUI 3 (ThemeDictionaries).
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
| **8** | Édition WinUI 3 issue du commit `first commit`, puis son installeur |
| **9** | Langues de l’interface (fr-FR / en-US) |
| **10** | Dépendances et licences |
| **11** | Historique : v1 et v2 communes avec `main` / `dev`, puis la v1 WinUI |
| **12** | Audit et qualité de l’édition WinUI |
| **13** | Sécurité de l’édition WinUI (posture /100) |
| **14** | Crédits |
| — | [Branches Git](#branches-git) — édition WinUI 3 (`win`) | 

---

## Branches Git

`main` et `dev` portent l’édition WPF. `win` est l’édition WinUI 3. La **partie commune** (v1 et v2) est **le même historique** que `main` / `dev` : mêmes commits, mêmes auteurs, courriel perso (`byakombe@outlook.fr`) à la place de l’adresse étudiante. À partir du `first commit`, `win` n’est plus du WPF : c’est WinUI 3, aux antipodes des v2 / v3 WPF. Elle évolue **isolément** (licence GPL-3, runtime .NET 10) ; elle peut s’inspirer de `main` sans en reprendre la v3.

L’historique WPF a été regroupé autour de ses publications, en conservant les dates majeures. Ce README décrit seulement l’édition WinUI.

| Branche | Rôle |
|---------|------|
| **`main`** | Référence publiée de l’édition WPF (v3). |
| **`dev`** | Édition WPF en cours, en avance sur `main`. |
| **`win`** | Édition WinUI 3. Mêmes commits que `main` / `dev` jusqu’à `6a23313` (v2), puis `first commit`. |

Branche par défaut GitHub : **`main`**. CI : `main`, `dev` et `win` (voir [`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

---

## 1. Architecture technique

### Choix du langage : C# WinUI 3 (.NET 10, Windows App SDK)

> **Pile WinUI 3.** L'UI repose sur Windows App SDK 1.8, publié en **framework-dependent** par défaut
> (installateur léger : il télécharge et installe **.NET 10 Desktop Runtime** et **Windows App Runtime 1.8**
> s'ils manquent — voir [§8](#8-édition-winui-3-issue-du-commit-first-commit)) : `NavigationView`, `SelectorBar`, `TabView`, FontIcon Segoe Fluent,
> ThemeDictionaries Donaby, systray Win32 `Shell_NotifyIcon` (`WinUiTrayHost`, sans dépendance),
> toasts `Microsoft.Toolkit.Uwp.Notifications`. Comparatif des piles envisagées ci-dessous.

| Critère | WinUI 3 | MAUI | C++ natif |
|---|---|---|---|
| Compatibilité Windows | Oui — natif | Partiel — multi-plateforme (overhead) | Oui — natif |
| Intégration ClamAV | Oui — Process.Start / TCP clamd | Oui — Process.Start | Oui — libclamav directe |
| MVVM + Binding UI | Oui — excellent | Partiel — différent | Non — manuel |
| **Verdict** | **Retenu** | Non nécessaire | Non nécessaire |

### Architecture plateforme v1.0 (protection système)

> **Couche activable, active par défaut hors mode complémentaire Defender.**
> `PlatformProtectionFeatureGate.IsUserActivatable = true` : la tâche *Protection système* de
> l'installateur est cochée au premier install, et une nouvelle installation sans Defender actif
> active le service (`UsePlatformProtectionService`). Le service Windows et AMSI s'installent sans
> pilote signé. Le **minifiltre** est enregistré (service noyau `optiSCANMinifilter` + instance,
> altitude provisoire `385210`) puis tenté par `fltmc load` ; Windows x64 le refuse tant que le
> `.sys` n'est pas signé (SignPath plus tard — voir `docs/GUIDE_DISTRIBUTION.md`).
> **Repli** : si le service est injoignable, optiSCAN assure la protection temps réel en
> **user-mode (`FileSystemWatcher`)**, sans pilote ni signature.

optiSCAN v1.0 rapproche un antivirus « classique » via une couche plateforme Windows :

```
optiSCAN.exe (UI WinUI 3 — projet optiSCAN.WinUI)
    ↔ IPC (optiSCAN.IPC — pipe optiSCAN_Protection_v1)
optiSCAN.Service.exe  →  optiSCAN.exe --service-host
    ├── RTP + ProcessStartMonitor + scan USB
    ├── ProtectionPipeServer (scan path/buffer pour AMSI)
    ├── optiSCAN.AmsiProvider.dll (COM AMSI → IPC)     [build MSVC / WDK]
    └── optiSCAN.Minifilter.sys (noyau, stub — chargé seulement si signé)
```

| Composant | Rôle |
|---|---|
| `optiSCAN.IPC` | Contrats JSON IPC (`ping`, `scan_path`, `scan_buffer`, `status`, `shutdown`) |
| `optiSCAN.Application` | Moteurs scan/quarantaine, coordinateurs, ViewModels partagés, DI |
| `optiSCAN.WinUI` | Shell WinUI 3 (Pages, services `WinUi*`, thèmes) |
| `optiSCAN.Service` | Service Windows qui supervise `optiSCAN.exe --service-host` |
| `--service-host` | Moteur sans UI : RTP, IPC, enregistrement AMSI/minifilter |
| `ThreatRepairService` | Quarantaine + recours Defender (`MpCmdRun`) |
| `WindowsDefenderExclusionService` | Exclusions Defender (chemins + processus optiSCAN) — démarrage de l’app, `--defender-exclusions`, script manuel ; rien à l’installation |
| `CloudThreatIntelService` | Enrichissement VirusTotal (cache local) |
| `native/optiSCAN.AmsiProvider` | DLL C++ fournisseur AMSI (build VS 2022 x64) |
| `native/optiSCAN.Minifilter` | Driver noyau stub (WDK + certificat EV en production) |

**Prérequis** : droits administrateur pour le service, l'enregistrement AMSI et le chargement minifilter (`fltmc`). En développement : `bcdedit /set testsigning on` pour le driver.

**Option UI** : *Service Windows de protection système* (Options → Protection). Si le service est injoignable, repli automatique sur la RTP locale.

---

### Structure des modules

Solution `optiSCAN.sln` : **5 projets** — `optiSCAN.WinUI`, `optiSCAN.Application`, `optiSCAN.IPC`, `optiSCAN.Service`, `optiSCAN.Tests`.

```
(racine du dépôt optiSCAN)
├── README.md                          ← Ce fichier (guide complet)
├── SECURITY.md                        ← Politique de sécurité (EN)
├── docs/                              ← Index, audit visuel WinUI, RGPD, confidentialité, distribution, signature, débogage VS
├── .editorconfig                      ← Sévérités analyse Roslyn (alignement IDE / MSBuild)
├── Directory.Build.props              ← Version 1.0.0, NetAnalyzers, TreatWarningsAsErrors (Release)
├── .github/workflows/
│   ├── ci.yml                         ← Build, tests, publish + SBOM (déclencheurs main / dev / win)
│   ├── codeql.yml                     ← Analyse CodeQL (C# + natif)
│   ├── dependency-review.yml          ← Revue dépendances (PR)
│   └── gitleaks.yml                   ← Détection fuites secrets
├── scripts/
│   ├── fetch-runtime-deps.ps1         ← Télécharge / met à jour ClamAV + YARA
│   ├── stage-runtime-deps.ps1         ← Copie clamav / yara / rules vers le dossier publish
│   ├── prepare-release.ps1            ← Chaîne complète release v1.0
│   ├── publish-release.ps1            ← Publish Release + compilation Inno
│   ├── verify-publish-for-inno.ps1    ← Vérifie l’emplacement de optiSCAN.exe attendu par setup.iss
│   ├── sign-publish-artifacts.ps1     ← Signature Authenticode (exe + installateur)
│   ├── dev-codesign.ps1               ← Signature de dev (certificat auto-signé)
│   ├── restore-quarantine-admin.ps1   ← Restauration quarantaine vers un chemin protégé (admin)
│   ├── clean-before-publish.ps1       ← Nettoyage bin/obj avant release
│   ├── add-defender-exclusions.ps1    ← Exclusions Windows Defender (install / manuel)
│   ├── generate-sbom.ps1              ← SBOM CycloneDX (CI publish)
│   ├── build-amsi.ps1 / stage-amsi.ps1← DLL AMSI native + fichiers minifiltre .inf/.sys/.cat (publish)
│   ├── verify-runtime-deps.ps1        ← Vérifie clamav + clamd + yara + rules
│   ├── validate-release-readiness.ps1 ← Tests Release (+ verify publish optionnel)
│   ├── check-winui-theme-keys.ps1     ← Parité des clés Light / Dark / HighContrast
│   └── runtime-versions.json          ← Versions URL ClamAV / YARA
│
├── optiSCAN.WinUI/                    ← UI WinUI 3 — exécutable optiSCAN.exe (projet de démarrage)
│   ├── App.xaml(.cs)                  ← Fusion WinUiStyles + ThemeDictionaries Light/Dark ; OnLaunched, mode headless
│   ├── MainWindow.xaml(.cs)           ← NavigationView (5 entrées), barre de statut, raccourcis Ctrl+1…5
│   ├── Views/                         ← OverviewPage, CleanPage (+ UpdatesPanel, TweaksPanel), AntivirusPage,
│   │                                     HistoryPage, OptionsPage, PlaceholderPage
│   ├── ViewModels/                    ← AntivirusViewModel (+ .ScanRun / .QuarantineHistory), CleanViewModel,
│   │                                     OptionsViewModel, UpdatesViewModel, TweaksViewModel
│   ├── Services/                      ← WinUiThemeManager, WinUiThemePacks, WinUiTrayHost, WinUiNavigationService,
│   │                                     WinUiStartupCoordinator (mutex instance unique), WinUiServiceHost,
│   │                                     WinUiServiceEventCoordinator, WinUiStatusFooterCoordinator, WinUiShellScanCoordinator,
│   │                                     WinUiUserConfirmService, WinUiOnboardingService, WinUiHistoryExportService,
│   │                                     WinUiNativeDialogs, WinUiThreadScheduler, WinUiWindowMessageHook, LocalizedTip, ThemeBrush, …
│   ├── Converters/                    ← BooleanToVisibilityConverter
│   └── Themes/
│       ├── WinUiStyles.xaml           ← Échelle d'espacement, styles de texte, cartes, vignettes, puces
│       ├── Donaby.Light.xaml / Donaby.Dark.xaml
│       └── Donaby.HighContrast.xaml   ← Overlay « contraste renforcé » (Options)
│
├── optiSCAN.Application/              ← Couche applicative partagée (aucune dépendance XAML)
│   ├── Models/                        ← ThreatInfo, ThreatDisplayItem, ScanResult, ScanSession, ActivityEntry, …
│   ├── Services/                      ← Moteurs (ClamAvEngine, ClamdEngine, CompositeClamAvBackend, YaraEngine),
│   │                                     ScanOrchestrator, QuarantineManager, ScanLogManager (+ ScanLogSqliteStore),
│   │                                     ActivityLogService, RealTimeProtection, RemovableDriveScanService,
│   │                                     SecurityPostureService, ServiceContainer + DependencyInjection/, …
│   ├── Coordinators/                  ← Orchestration UI sans état (exports, signatures, RTP, USB, toasts, sidebar…)
│   ├── ViewModels/                    ← HistoryViewModel, HistoryThreatRow, RelayCommand
│   ├── Localization/                  ← LocalizationService (fr-FR / en-US), ShellContextMenuSupport
│   ├── Resources/                     ← UiStrings.resx (FR) + UiStrings.en.resx (EN)
│   └── Strings/                       ← OptiscanStrings (URLs, confirmations, statuts MAJ)
│
├── optiSCAN.IPC/                      ← Contrats et client du pipe de protection système
├── optiSCAN.Service/                  ← Service Windows (supervise optiSCAN.exe --service-host)
├── optiSCAN.Tests/                    ← Tests xUnit (Application + IPC) ; `Legacy/` : sources WPF historiques encore testées
├── native/
│   ├── optiSCAN.AmsiProvider/         ← DLL AMSI (C++, build MSVC)
│   └── optiSCAN.Minifilter/           ← Driver noyau stub (WDK)
├── installer/
│   ├── setup.iss                      ← Script Inno Setup (FR + EN)
│   └── build-release-setup.ps1        ← clean + publish + ISCC
└── optiSCAN/                          ← Hors solution : assets partagés uniquement (optiSCAN.ico,
                                          optiSCAN_hero.png, optiSCAN_shield.png, clamav/, yara/, rules/)
```

**Règle de séparation :**
- `optiSCAN.Application` — aucune dépendance XAML ; services injectables via `Microsoft.Extensions.DependencyInjection` + `ServiceContainer`
- `Coordinators/` — orchestration UI sans état (méthodes `static`, hôtes `Host` typés)
- `optiSCAN.WinUI/Services/WinUi*` — adaptateurs WinUI des abstractions applicatives (navigation, confirmation, thread UI, systray)
- `optiSCAN.WinUI/Views/` — XAML + code-behind léger (libellés via `LocalizationService`, état via le ViewModel)
- `MainWindow.xaml.cs` — câblage : navigation, systray, coordinateurs startup/shutdown, événements services

---

### Développement local (Visual Studio / VS Code)

| Projet | Rôle au débogage |
|---|---|
| **optiSCAN.WinUI** | **Projet de démarrage** — exécutable `optiSCAN.exe` (WinUI 3) |
| optiSCAN.Application | Bibliothèque — logique métier (pas de F5 direct) |
| optiSCAN.IPC | Bibliothèque — IPC protection système (pas de F5 direct) |
| optiSCAN.Tests | Tests xUnit (`dotnet test` ou Test Explorer) |
| optiSCAN.Service | Service Windows (`--service-host`) |

**Visual Studio 2026** (ou 2022+)

Guide détaillé : [`docs/DEBUG_VS.md`](docs/DEBUG_VS.md)

1. **Fermer VS**, supprimer le dossier `.vs\` à la racine (cache projet de démarrage obsolète), rouvrir `optiSCAN.sln`.
2. Accepter les composants manquants si proposé (`.vsconfig` : Windows App SDK, .NET 10).
3. Barre d’outils : **Debug** + **Any CPU** ou **x64** (WinUI compile toujours en x64).
4. À côté de ▶, choisir **`optiSCAN (WinUI x64)`** (`optiSCAN.slnLaunch`).
5. **F5** → `optiSCAN.WinUI\bin\x64\Debug\...\optiSCAN.exe`.

Erreur *Class Library* : mauvais projet de démarrage → clic droit **optiSCAN.WinUI** → **Définir comme projet de démarrage**.

**VS Code** : configuration *optiSCAN (WinUI Debug x64)* dans `.vscode/launch.json` (tâche de build par défaut sur WinUI x64).

**Ligne de commande**

```powershell
dotnet build .\optiSCAN.sln -c Debug -p:Platform=x64
dotnet run --project .\optiSCAN.WinUI\optiSCAN.WinUI.csproj -c Debug -p:Platform=x64
```

---

## 2. Donaby Design — Système de thèmes

### 2.1 Vue d'ensemble

optiSCAN utilise le **Donaby Design** : les textes reposent sur les ressources système WinUI 3 (`TextFillColor*`) ; les couleurs **de marque, sémantiques et de surface** (fond d'application, volet de navigation, cartes de l'Accueil) sont définies par thème (`ThemeResource` + `ThemeDictionaries`). Le thème bascule à chaud (sans redémarrage).

| Fichier | Rôle |
|---|---|
| `Themes/Donaby.Light.xaml` / `Donaby.Dark.xaml` | Palettes claire / sombre (dictionnaires de thème d'`App.xaml`) |
| `Themes/Donaby.HighContrast.xaml` | Contraste renforcé (Options) — fusionné en dernier dans le dictionnaire « Light » |
| `Themes/WinUiStyles.xaml` | Échelle d'espacement, gouttière de page, styles de texte, cartes, vignettes, puces |
| `Services/WinUiThemeManager.cs` | Clair / sombre / contraste ; sync thème Windows ; preset et couleur d'accent |
| `Services/WinUiThemePacks.cs` | Presets d'accent : Donaby, Midnight, Ocean, Ember |

Les trois fichiers de thème déclarent **exactement le même jeu de clés** : `pwsh -File scripts/check-winui-theme-keys.ps1`.

### 2.2 WinUiThemeManager

`WinUiThemeManager` (static) est initialisé dans `MainWindow.InitializeShell` :

```csharp
WinUiThemeManager.Initialize(preferences, dark => WinUiThemeManager.Apply(dark, root));

WinUiThemeManager.SetAlternateThemeEnabled(true/false); // thème opposé à Windows (décocher = resuivre)
WinUiThemeManager.SetHighContrast(true);                // contraste renforcé (force le thème clair)
WinUiThemeManager.SetThemePreset("ocean");              // preset d'accent
WinUiThemeManager.SetCustomAccentColor("#534AB7");      // couleur d'accent perso (vide = preset)

WinUiThemeManager.ThemeChanged += (_, isDark) => { /* ... */ };
ThemeBrush.SetForegroundKey(label, "SuccessGreen");     // code-behind : couleur qui SUIT les bascules de thème
```

- **Accent** : `SystemAccentColor` et ses variantes `Light1..3` / `Dark1..3` sont **injectées par code** dans chaque dictionnaire de thème (le compilateur XAML WinUI ne reconnaît pas `<Color>` — avertissement WMC0001, bloquant en Release). L'accent (preset ou couleur perso) est **ajusté jusqu'à 4,5:1** (WCAG AA) sur le fond du thème (`EnsureContrast` : assombri en clair, éclairci en sombre) et `AccentTintBrush` en est **dérivé** (il suit le preset). En contraste renforcé, l'accent navy et la teinte jaune sont imposés.
- **Code-behind** : jamais `Foreground = …Brush` figé. Utiliser `ThemeBrush.SetForegroundKey(element, key)` / `SetBackgroundKey` (ou en XAML `svc:ThemeBrush.BackgroundKey="{x:Bind RiskBrushKey}"`) : la clé est réappliquée à chaque changement de thème de l'élément et d'accent, selon le thème **de l'élément** (le volet de navigation suit le même thème que la fenêtre). `WinUiThemeManager.GetBrush(key[, theme])` reste disponible pour une lecture ponctuelle (ex. couleurs de la barre de titre).
- **Barre de titre** : alignée sur le thème de l'app (`MainWindow.UpdateTitleBarColors`) — sinon elle suivait Windows (barre claire au-dessus d'une app sombre en « thème opposé »).
- **Persistance** : `%AppData%\optiSCAN\preferences.dat` (DPAPI + HMAC). Par défaut optiSCAN **suit le thème applications Windows** (`SyncWindowsTheme`) ; Options propose le thème **opposé**. Propriétés : `DarkTheme`, `SyncWindowsTheme`, `HighContrastEnabled`, `ThemePresetId`, `ThemeAccentColor`.

### 2.3 Tokens de couleur disponibles

| Clé (`ThemeResource`) | Rôle |
|---|---|
| `AccentBrush` / `AccentTintBrush` | Accent canonique (surchargé par preset / couleur perso) et fond teinté |
| `TextAccent` | Alias d'accent (clé renvoyée par `ActivityEntry.IconBrushKey`) |
| `SuccessGreen` / `WarningBrush` / `DangerRed` / `InfoBrush` | Jeu sémantique |
| `AlertBg` | Fond d'avertissement (pastilles) |
| `TextMutedBrush` / `TextOnPrimary` | Texte atténué (≥ 4,5:1) / texte sur pastille de risque (blanc en clair, quasi-noir en sombre) |
| `AppBackgroundBrush` / `SidebarBackgroundBrush` | Fond de fenêtre (`RootGrid`) / volet `NavigationView` (blanc en thème clair, `#141414` en thème sombre) |
| `CardBackgroundBrush` / `CardAltBackgroundBrush` / `CardBorderBrush` | Surfaces de **toutes** les cartes (`AppCardStyle` et dérivés), encarts (`InsetPanelStyle`), journaux |
| `WarningTintBrush` / `DangerBrush` | Fond teinté d'avertissement / rouge de danger (alias visuel de `DangerRed`) |
| `RiskCritical` / `RiskMajor` / `RiskMinor` / `RiskInformational` | Niveaux de risque (`RiskScoringService`) : rouge → orange → ambre/jaune → vert, dans les deux thèmes |

**Règle de contraste** : toute couleur utilisée comme texte atteint **4,5:1** (WCAG AA) sur `AppBackgroundBrush`, `CardBackgroundBrush`, `CardAltBackgroundBrush`, `AccentTintBrush` et `AlertBg` du même thème ; texte des pastilles de risque ≥ 5:1. Éviter `TextFillColorTertiaryBrush` pour un texte à lire (≈ 3:1 en clair).

Styles partagés (`WinUiStyles.xaml`) : `Spacing{XXS,XS,S,M,L,XL}` (2 → 24), `PagePadding` (gouttière de **toutes** les pages, Accueil compris), `PageTitleStyle`, `SectionTitleStyle`, `MetricValueStyle`, `AppCardStyle` (carte unique) / `AppAccentCardStyle` / `OverviewCardStyle` / `ToolbarCardStyle`, `InsetPanelStyle`, `TileButtonStyle` (vignettes Accueil **et** Antivirus), `RiskPillStyle` / `RiskPillTextStyle`, `FilterChipStyle`, `LogConsoleBorderStyle`, etc. Écarts : 8 entre vignettes, 12 entre cartes et blocs, 4 entre cases à cocher d'une liste. Détail des choix : [`docs/audit-visuel-winui.md`](docs/audit-visuel-winui.md).

---

## 3. Installation et configuration de ClamAV

### 3.1 Télécharger ClamAV (version x86-64 obligatoire)

```
https://www.clamav.net/downloads#otherversions
→ Windows → clamav-X.Y.Z.win.x64.zip   ← ZIP, pas MSI, pas ARM64
```

> **Attention :** la version `win.arm64` cause l'erreur `0xc000007b` sur les machines Intel/AMD.

### 3.2 Placer les binaires dans le projet

> **Binaires dans le dépôt** — sur la branche `win`, les binaires ClamAV (`optiSCAN/clamav/x64/`), YARA (`optiSCAN/yara/`) et les règles (`optiSCAN/rules/`) sont présents dans Git (le `.gitignore` empêche seulement d’y ajouter de nouveaux binaires). Les bases de signatures ne le sont pas. Pour mettre à jour binaires et bases :
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

Un code **2** sans aucun fichier analysé ni menace (base absente, chemin illisible…) donne le statut **Erreur**, jamais « aucune menace » (`ClamAvEngine`). L'attente de fin de processus passe par `WaitForExitAsync` (arrêt de clamscan si l'analyse est annulée).

---

## 4. Architecture mono-fenêtre (v1.0)

Les sous-sections **4.1** à **4.11** suivent une lecture « produit » : navigation et panneaux, détail du panneau Antivirus, menaces et pipeline, options techniques (MAJ, exclusions, quarantaine, logs), exports, puis contenu de l’Accueil.

### 4.1 Les 5 panneaux de MainWindow

`MainWindow.xaml` héberge une `NavigationView` ; chaque entrée (`Tag`) affiche la page correspondante, mise en cache (une instance par page). La navigation programmatique passe par `INavigationService` (`WinUiNavigationService`).

| Tag | Entrée | Page | Rôle principal |
|---|---|---|---|
| `overview` | Accueil | `OverviewPage` | 4 vignettes d'action, bandeau UAC, posture /100, statut plateforme, recommandations |
| `clean` | Optimiser | `CleanPage` | Onglets **Nettoyage** (temporaires, caches navigateurs, corbeille), **Mises à jour** (`UpdatesPanel`, winget), **Tweaks** (`TweaksPanel`) |
| `antivirus` | Antivirus | `AntivirusPage` + `AntivirusViewModel` | Analyses, résultats, quarantaine, signatures — voir [§4.3](#43-panneau-antivirus) |
| `history` | Historique | `HistoryPage` + `HistoryViewModel` | Timeline `ActivityLogService.GetActivityFeed` ; 5 filtres (puces) ; traitement menaces ; exports **HTML** / **PDF** |
| `options` | Options | `OptionsPage` + `OptionsViewModel` | **Langue** (fr/en, redémarrage), thème / preset / accent, scan favori, RTP, **scan USB/SD**, quarantaine auto, planification, exclusions |

Raccourcis clavier : `Ctrl+1` … `Ctrl+5` — **Accueil**, **Optimiser**, **Antivirus**, **Historique**, **Options**.

### 4.2 Fenêtre principale, barre système et icône

Fenêtre unique (`MainWindow`) : volet `NavigationView` à gauche (logo + badge d'état ClamAV sous « Antivirus »), barre de statut en bas (`WinUiStatusFooterCoordinator` : scan, MAJ, erreurs). Le **systray** est géré par `WinUiTrayHost` (Win32 `Shell_NotifyIcon`) : double-clic pour rouvrir, menu Ouvrir / Quitter. Fermer ou réduire la fenêtre laisse optiSCAN actif en arrière-plan.

### 4.3 Panneau Antivirus

Page `AntivirusPage` (`Ctrl+3`), de haut en bas :

1. **En-tête** — état de protection (`ProtectionBadgeText`) · dernière analyse ; à droite, 3 statistiques : **Analysés**, **Menaces**, **Quarantaine**.
2. **Zone d'action** — au repos : 4 vignettes (**Analyse rapide** en accent, **Complète**, **Dossier**, **Fichier**) et les **cibles récentes** en puces (`RecentTargets` / `ScanRecentCommand`). Pendant une analyse, elle est remplacée par la **carte de progression** (barre, fichier courant, statut) avec le bouton **Interrompre**.
3. **Barre de sections** (`SelectorBar`) :
   - **Analyse** — liste des menaces (pastille de risque, nom, chemin, actions en icônes) ; **Tout mettre en quarantaine** ; écran « système propre » si rien n'est détecté.
   - **Quarantaine (N)** — entrées paginées, restauration / suppression, **Vider la quarantaine**, écran dédié si vide.
   - **Signatures** — cartes ClamAV et YARA (version, dernière MAJ), **Mettre à jour** / **Arrêter**, journal freshclam / règles.

Fenêtre étroite (< 760 px) : vignettes en 2×2, statistiques sous le titre, cartes Signatures empilées. L'aperçu des sessions passées est dans le panneau **Historique** (`Ctrl+4`).

Après chaque analyse réussie, `StartScanAsync` met à jour les **cibles récentes** (fichier/dossier scanné, ou entrée « analyse rapide » / « analyse complète »).

### 4.4 Nettoyer une menace détectée

`clamscan.exe` est un moteur de **détection uniquement** — il ne répare pas les fichiers infectés. La désinfection passe par l'isolement ou la suppression du fichier source.

Chaque ligne de la liste des menaces (`ThreatsList`, section **Analyse**) propose quatre actions en icônes (infobulles traduites via `LocalizedTip`) :

| Icône | Appel (`AntivirusPage`) | Comportement |
|---|---|---|
| **Réputation** (globe) | `ThreatReputation.LookupFileAsync` | Recherche VirusTotal par hash SHA-256 (optionnelle) |
| **Ignorer** | `AntivirusActions.IgnoreThreat` | Exclusion du fichier |
| **Quarantaine** | `AntivirusActions.QuarantineThreat` | AES-256-GCM ; nom de menace depuis la ligne |
| **Supprimer** (rouge) | `AntivirusActions.DeleteThreatFile` | Confirmation utilisateur, puis suppression définitive |

`AntivirusActions.ActionCompleted` met à jour la **barre de statut** (`MainWindow`).

Au-dessus de la liste, le bouton **Tout mettre en quarantaine** (`QuarantineAll_Click`) traite toutes les menaces listées en une seule opération.

> **Attention :** toujours préférer la quarantaine à la suppression directe — elle permet de restaurer le fichier en cas de faux positif.

### 4.5 Pipeline de détection en parallèle

Les scans interactifs passent par `AntivirusViewModel.StartScanAsync` → `ScanOrchestrator` : pour chaque cible, **ClamAV** (daemon **clamd** ou repli **clamscan.exe**) et **YARA** tournent en parallèle (`Task.WhenAll`), puis fusion. Les scans **multi-dossiers** passent par `MultiTargetScanAggregator`. Les **périmètres protégés** optiSCAN (installation + `%LOCALAPPDATA%\optiSCAN`) sont exclus (`OptiscanProtectedPaths` + `ExclusionSettings`). **`RiskScoringService`** alimente la colonne **Risque**, les toasts et le PDF.

> **clamd** — si `clamd.exe` est présent et l’option **Moteur clamd** est activée (Options), les scans utilisent le daemon TCP (`127.0.0.1:3310`) ; sinon repli sur **`clamscan.exe`**. `CompositeClamAvBackend` relance aussi l'analyse avec clamscan quand clamd échoue en cours de route : socket coupée, réponse incomplète, ou cible illisible pour clamd (lignes `… ERROR` sans aucun fichier analysé). Une annulation ne déclenche pas de repli. Les listes de fichiers (`--file-list`, scan USB rapide) passent directement par clamscan. Note posture Accueil : [§13 Sécurité](#13-sécurité-de-lédition-winui).

```
AntivirusViewModel → ScanOrchestrator
    │   ├─→ CompositeClamAvBackend (clamd → clamscan)  ─┐
    │   └─→ YaraEngine (.yarc + stamp)                 ├── Task.WhenAll → fusion
    └─→ Progress<ScanProgress> → UI
```

**v1.0** ajoute aussi : note de **posture sécurité** (Accueil), **réputation VirusTotal** (hash SHA-256, clé API Options), **mode jeu** (toasts / scans headless atténués).

**Identifiant menace** — `ThreatInfo.Id` : hash **SHA-256** déterministe (`FilePath|VirusName|DetectedAt`) — stable entre redémarrages (pas `string.GetHashCode()`).

### 4.6 Mise à jour des signatures

**Manuel** — `BtnManualUpdateSignatures_Click` enchaîne `FreshclamUpdater.UpdateAsync()` puis `YaraForgeUpdater.UpdateAsync()` (journal dans l’onglet Signatures).

**Automatique** — À l’instanciation de `ServiceContainer.Default`, les minuteries sont armées par `SignatureUpdatePolicy.ApplyAutoUpdateTimers` : **ClamAV toutes les 4 h**, **paquet YARA-Forge toutes les 24 h** ; option **Mises à jour signatures renforcées** (`AggressiveSignatureUpdates`) : **2 h / 12 h**. La case **Mise à jour automatique des signatures** dans **Options** coupe ou réactive **les deux** services (`DisableAutoUpdate` / `EnableAutoUpdate`).

**Au démarrage** — `SignatureUpdatePolicy.EvaluateStartupNeed` : bases ClamAV absentes, règles YARA absentes ou dernière MAJ ClamAV plus vieille que `SignatureStaleThresholdDays` (**7 j** par défaut) → toast puis téléchargement silencieux si la MAJ auto est active (sinon simple toast « MAJ nécessaire »).

### 4.7 Système d'exclusions

`ExclusionSettings` persiste dans :
```
%LOCALAPPDATA%\optiSCAN\exclusions.dat
```
(chiffrement **DPAPI** + **HMAC** ; un ancien `exclusions.json` en clair est migré une fois au premier chargement, `SecureStore.MigrateFromPlaintext`).

**Périmètres protégés** (`OptiscanProtectedPaths`) — jamais analysés (scans, RTP, quarantaine auto) pour éviter l’**auto-détection** sur les propres fichiers optiSCAN :

| Périmètre | Contenu typique |
|-----------|-----------------|
| **Installation** | `{autopf}\optiSCAN WinUI` (Program Files — `optiSCAN` accepté aussi), répertoire du processus, chemin registre Inno |
| **Données applicatives** | `%LOCALAPPDATA%\optiSCAN\` — bases ClamAV (`clamav\database`), règles YARA, quarantaine, logs, staging MAJ (`Updates`), config clamd |

- **Liste Options** : ajout automatique au chargement (`EnsureProtectedFoldersListed`) ; **non supprimables** par l’utilisateur
- **Dossiers utilisateur** : ajout manuel dans **Options → EXCLUSIONS**
- **Règles exclues** : matches YARA filtrés (ex. `SuspiciousDownloads` — exclu par défaut)
- **ClamAV / clamd** : plusieurs `--exclude` / lignes `ExcludePath` (une par racine protégée)
- **RTP** et **scan USB/SD** : mêmes exclusions ; lecteur entier exclu si son chemin racine est listé

**Exclusions Windows Defender** (`WindowsDefenderExclusionService`) — évite que Defender bloque optiSCAN, ClamAV ou YARA :

| Moment | Comportement |
|--------|----------------|
| **Installation** | Aucune exclusion posée par l'installateur (choix volontaire) ; le script est copié dans `{app}\scripts` |
| **Démarrage** | Vérification asynchrone ; relance UAC via `--defender-exclusions` si besoin (max 1× / 24 h) |
| **Manuel** | `.\scripts\add-defender-exclusions.ps1` (élévation auto) |

Chemins : mêmes racines que `OptiscanProtectedPaths`. Processus : `optiSCAN.exe`, `optiSCAN.Service.exe`, `clamscan.exe`, `freshclam.exe`, `clamd.exe`, `yara64.exe`. Si la **protection contre la falsification** Defender est active, ajout manuel dans *Sécurité Windows → Exclusions* — voir [§7](#exclusion-windows-defender).

Configurable depuis **Options → EXCLUSIONS** (exclusions internes optiSCAN uniquement).

### 4.8 QuarantineManager — sécurité des fichiers infectés

Les fichiers en quarantaine sont stockés en **AES-256-GCM** (format binaire `OPTQ`, nonce et tag d’authentification).

- Clé maîtresse 256 bits, **DPAPI CurrentUser** (fichier `.key`).
- Manifeste `manifest.json` signé **HMAC-SHA256** (intégrité).

Stockage : `%LOCALAPPDATA%\optiSCAN\Quarantine\` — `{guid}.quar` + `manifest.json`. Restauration par défaut ou vers un dossier choisi : `IThreatStore.RestoreTo(quarantineId, destinationFolder)`.

- Si la **suppression du fichier original** échoue après écriture du blob `.quar`, le blob est **supprimé** (rollback) et la quarantaine est annulée.
- Si la **persistance du manifeste** échoue après écriture du blob, l’entrée est retirée et le blob est supprimé.

Pendant un **scan en cours**, `AntivirusViewModel.ActiveScanSessionId` lie les quarantaines à la session ; les chemins isolés pendant l’analyse sont exclus du résultat final (`RemoveAlreadyQuarantinedThreats`).

### 4.9 Journaux et historique

| Fichier / service | Rôle |
|---|---|
| `ActivityLogService` → `%LocalAppData%\optiSCAN\Logs\activity_log.dat` | Timeline **Historique** (DPAPI + HMAC) ; événements immuables : `ScanCompleted`, `CleanCompleted`, `ThreatQuarantined`, `ThreatRestored`, `QuarantineDeleted` ; rétention **150** événements les plus récents (`MaxActivityEvents`) ; **migration unique** au premier lancement depuis `scan_history.dat` / `clean_history.dat` + entrées quarantaine actuelles si le fichier est vide |
| `ScanLogManager` → `scan_history.dat` / `clean_history.dat` | Détail des sessions (menaces en attente, exports) ; rotation **100 → 50** ; **v1.0** : `Threats[]` (format `.dat` chiffré unique) ; alimente `ActivityLogService` à chaque scan/nettoyage terminé |
| `ScanLogManager` → `optiSCAN.log` | Journal texte volontairement **non chiffré** (diagnostic) ; `FormatScanDetailCore` applique `PathRedaction` sur cible et chemins de menaces — noms de virus, dates et compteurs restent lisibles ; résumé dans **Historique → Scan Antivirus** |
| `AppLogger` → `optiscan-YYYY-MM-DD.log` | Logs applicatifs (composants, erreurs) ; purge **> 30 jours**, au plus **1×/jour** (marqueur `.lastcleanup` persisté) |
| `App.OnUnhandledException` → `Logs\winui-crash.log` | Exceptions UI non gérées (secours si `AppLogger` échoue) ; rotation à **1 Mo** → `winui-crash.log.old` |

**Panneau Historique** (`HistoryPage` + `HistoryViewModel`, `Ctrl+4`) :

- **Timeline** : `ActivityLogService.GetActivityFeed(quarantine)` → `ActivityEntry`, tri date décroissante ; **5 puces** : **Tout**, **Menaces** (scans avec détections en attente), **Scans sains**, **Nettoyages**, **Quarantaine** ; recherche sur type, résumé, cible ou chemins quarantaine.
- **Sélection stable** : clé `SelectionKey` — `SessionId` pour les scans, `EventId` pour quarantaine/restauration/suppression — conservée après `Refresh()`.
- **Refresh** : `ReconcileQuarantinedThreats` retire des sessions persistées les menaces déjà en quarantaine (même chemin d’origine).
- Détail **scan** : grille via `HistoryThreatRow` ; **Quarantaine** / **Ignorer** / **Supprimer** ; **Tout mettre en quarantaine** ; **Traiter dans Analyse**. Détail **quarantaine** : lecture seule ; chemin d’origine affiché (`Hist_DetailQuarantinePath`).
- Sessions **héritées** (ancien format) : badge menaces possible sans chemins (`Hist_DetailThreatsLegacy`) — relancer une analyse pour traiter.
- Types affichés : analyse rapide/complète, fichier, dossier, **lecteur amovible** (`ScanType.RemovableDrive`), nettoyage système, événements quarantaine.

### 4.10 Exports PDF et HTML

- **PDF** — `PdfReportGenerator` : déclenché via `ServiceContainer` (`ExportScanSessionPdfRequested` → `MainWindow.OnExportPdfRequested` → `ExportCoordinator.TryExportSessionPdf`). Bouton **Historique** : **PDF (sélection)** sur la ligne choisie dans Scan Antivirus.
- **HTML** — `HtmlExportService` : `RequestExportScanHistoryHtml()` depuis **Historique**.

### 4.11 Accueil (dashboard)

Le panneau **Accueil** (`OverviewPage`, tag `overview`) regroupe :

- **Hero** : titre de protection (« Votre ordinateur est protégé » ou « Protection incomplète » selon les moteurs) et **dernière analyse** uniquement ; pas de détail ClamAV/YARA sur cet écran (voir onglet **Antivirus**).
- **Quatre vignettes d'action** (`TileButtonStyle`) : Nettoyer, Scanner, Historique, mise à jour des signatures (navigation via `INavigationService` ; « Scanner » et « Mise à jour » ciblent la section Antivirus correspondante).
- **Posture de sécurité /100** avec corrections en un clic ([§13](#13-sécurité-de-lédition-winui)) et **statut plateforme** (service, AMSI, minifiltre) quand la couche plateforme est active.
- **Cartes** dernière analyse, signatures, et :
  - **Statistiques de protection** : `OverviewProtectionStatsFormatter` (30 j., analyses / fichiers / menaces depuis l’historique) — distinct des recommandations pour éviter le doublon « activité ».
  - **Recommandations** : `OverviewRecommendationsBuilder` (hygiène signatures, suggestion nettoyage) ; `MainWindow` collecte le contexte et met à jour `OverviewPage` (`IOverviewPanel`).

---

## 5. Services avancés (modules complémentaires)

### RealTimeProtection — surveillance temps réel

`RealTimeProtection.cs` : `FileSystemWatcher` sur dossiers sensibles (profil utilisateur, `ProgramData`, `Temp`, etc.), filtre sur extensions à risque (`RiskyFileExtensions`), délai de stabilisation, déduplication et **SemaphoreSlim(3)** parallèle. Une instance est créée dans **`ServiceContainer`** ; **Options** active ou coupe la surveillance et persiste le réglage. Les menaces détectées remontent vers l’UI (badge / liste) via événements consommés par **`MainWindow`**. Chaque détection (RTP et `ProcessStartMonitor`) est aussi **enregistrée dans l’Historique** par `DetectionHistoryRecorder` : session `ScanType.RealTime` (« Protection temps réel ») visible dans l’onglet **Menaces**, avec Quarantaine / Ignorer / Supprimer tant que le fichier n’est pas traité (le toast seul ne laissait aucune trace).

### DefenderCoexistenceService — mode complémentaire Windows Defender

Nouvelle installation avec **Windows Defender actif** (`WinDefend` en marche) : optiSCAN propose le **mode complémentaire** (`DefenderComplementModeEnabled`, défaut). Defender garde le **temps réel** ; optiSCAN se concentre sur les analyses à la demande / planifiées / USB (ClamAV + YARA) — RTP optiSCAN et surveillance des processus sont **coupées** pour éviter le double scan. L'utilisateur peut basculer en **protection optiSCAN complète** (`ApplyFullOptiscanMode`), qui réactive la RTP, la surveillance des processus et le service de protection système. En mode complémentaire, le temps réel est considéré **délégué** (`DefenderCoexistenceService.IsRealTimeDelegated`) : le badge Antivirus reste **Actif** et le critère posture `optiscan` n'est pas pénalisé.

### RemovableDriveScanService — clés USB et cartes SD

`RemovableDriveScanService.cs` : à l’**insertion** d’un volume (WMI `Win32_VolumeChangeEvent` + polling de secours), analyse automatique en arrière-plan si l’option est activée (**Options → Analyser les clés USB et cartes SD**, activée par défaut).

| Aspect | Comportement |
|---|---|
| Détection | `DriveType.Removable` **ou** lecteur `Fixed` reconnu USB via WMI (`InterfaceType`, `PNPDeviceID`, `MediaType`) |
| Déjà branché au démarrage | Enregistré sans scan (évite une vague au lancement) |
| Mode rapide (défaut) | `CollectRiskyFiles` par **extension à risque** (`RiskyFileExtensions`, plafond **4 000**, délai énumération **90 s**) ; **ClamAV `--file-list`** puis **YARA par lots en série** (`scanEnginesSequentially: true`, évite verrous USB) ; **timeout 10 min** ; repli `ScanFolderBackgroundAsync` si erreur/annulation |
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

`RiskScoringService.cs` attribue un score numérique (0–100+) à chaque menace. Affichage : colonne **Risque** dans la grille Antivirus (pastille `RiskPillStyle` + `ThemeBrush.BackgroundKey`), toasts, rapport PDF. Critères cumulatifs :

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

## 6. Workflow utilisateur optiSCAN v1.0

```
DÉMARRAGE (UI)
    │
    ├─→ `App.OnLaunched` → `LocalizationService.Initialize()` (fr-FR / en-US : prefs, registre installateur) ; arguments headless éventuels
    ├─→ `WinUiStartupCoordinator` : mutex instance unique (2e instance → message « afficher » la fenêtre existante)
    ├─→ `MainWindow.InitializeShell` : `WinUiServiceHost` / `ServiceContainer` (ClamAV, YARA, orchestrateur, MAJ, quarantaine, planif., logs, `AntivirusActions`) → `AntivirusViewModel`
    ├─→ `WinUiThemeManager.Initialize()` (préférences `UserPreferences` : thème, contraste, preset, accent)
    ├─→ Minuteries MAJ : freshclam **4 h**, règles YARA **24 h** (désactivables via Options)
    ├─→ `AntivirusViewModel` : initialisation moteurs (versions, base, YARA), historique, quarantaine
    ├─→ Protection temps réel : état selon **Options** (`ServiceContainer.RealTimeProtection`)
    ├─→ Scan USB/SD : `ServiceContainer.RemovableDriveScan` si option activée
    └─→ Fenêtre principale + icône zone de notification (réduction possible sans quitter)
            │
            ├─→ [ACCUEIL] — hero (protection + dernière analyse), vignettes d’action, posture /100, recommandations
            ├─→ [OPTIMISER] — nettoyage : temporaires, caches navigateurs (Edge, Chrome, Firefox, Brave, **Opera**, **Vivaldi**, **Arc**), corbeille, journaux Windows ; mises à jour (winget) ; tweaks
            ├─→ [ANTIVIRUS] — scans rapide/complet/dossier/fichier, résultats, quarantaine, signatures
            ├─→ [HISTORIQUE] — timeline `activity_log.dat` (5 filtres) ; sessions v1.0 : détections, quarantaine / ignorer / supprimer, **Traiter dans Analyse** ; exports **HTML** / **PDF**
            └─→ [OPTIONS] — langue FR/EN, thème (sync Windows par défaut), scan favori, démarrage auto, MAJ auto, RTP, scan USB/SD, quarantaine auto, planification, exclusions

FERMETURE
    └─→ `MainWindow` (fermeture réelle, pas la réduction en systray) → `ServiceContainer.Shutdown()` (RTP, scan USB, minuteries MAJ, moteurs)

DÉMARRAGE (ligne de commande)
    `--fullscan` / `--quickscan` [+ `--quiet` ] → `App.RunHeadlessAsync` (WinUI) : orchestrateur, journal, quarantaine auto si `ExclusionSettings.Current.AutoQuarantineEnabled`, notification fin si menaces et non quiet.
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
| WinUiThemeManager + UserPreferences | Bascule de thème sans redémarrage |

### Faux positifs

- `SuspiciousDownloads` exclue par défaut (trop agressive sur le dossier Downloads)
- Ne jamais supprimer automatiquement — toujours mettre en quarantaine en premier
- L'utilisateur confirme avant toute action destructrice (boîte `MessageBoxW` Win32 via `WinUiUserConfirmService`)
- Le test EICAR est couvert par la règle YARA embarquée `rules/test_rules.yar` (`EICAR_Test`) ; ClamAV le détecte aussi si la base est à jour

### Exclusion Windows Defender

Voir aussi [§4.7](#47-système-dexclusions) (détail technique). Résumé :

- **Au premier démarrage** (pas à l’installation) : chemins `Program Files\optiSCAN WinUI` et `%LOCALAPPDATA%\optiSCAN`, plus les processus `optiSCAN.exe`, `clamscan.exe`, `freshclam.exe`, `clamd.exe`, `yara64.exe`, etc.
- **À chaque démarrage** de l’application : même logique si une exclusion manque encore (relance UAC au plus 1× / 24 h).

Commande manuelle (console **administrateur**) :

```powershell
.\scripts\add-defender-exclusions.ps1
```

Si la **protection contre la falsification** de Defender est active, l’ajout peut échouer — ajoutez les chemins dans *Sécurité Windows → Protection contre les virus et menaces → Exclusions*.

---

## 8. Édition WinUI 3 issue du commit `first commit`

Cette édition commence au commit `2ab25cc` (`first commit`), sur la branche `win`. Son parent git est `6a23313` (`release: optiSCAN 2`, tag `v2`) : **les mêmes objets** que sur `main` et `dev` (historique réécrit). La v3 WPF n’est pas dans cette branche. C’est la **v1** WinUI : release **v1.0**, assembly **1.0.0** (`Directory.Build.props`).

`first commit` pose le shell WinUI 3 (`optiSCAN.WinUI`), donne à l’installeur un `AppId` propre (`8680BFF9-…`) et un dossier `{autopf}\optiSCAN WinUI`. La couche plateforme (service, AMSI, tentative de minifiltre) est en place ; Windows x64 refuse encore un `.sys` non signé. Le détail, après les publications **v1** et **v2**, est en [§11](#11-historique).

La CI lance le build et les tests sur `win`. Le job qui produit l’installeur ne part que sur `main`. Cette édition se publie donc en local, et `win` n’est pas fusionnée dans `main` — voir [Branches Git](#branches-git).

### Prérequis machine de build

- Windows 10/11 x64, .NET 10 SDK (`global.json`, bande 10.0.4xx), Inno Setup **6.1+** (page de téléchargement des prérequis)
- Réseau (téléchargement ClamAV, YARA, signatures freshclam)
- Binaires ClamAV / YARA présents dans le dépôt ; mise à jour et bases de signatures : `.\scripts\fetch-runtime-deps.ps1 -RunFreshclam`

### Chaîne automatique (recommandée)

```powershell
# Depuis la racine du dépôt (dossier contenant optiSCAN.sln)
.\scripts\prepare-release.ps1
```

Équivalent manuel : `clean-before-publish` → `fetch-runtime-deps -RunFreshclam` → `dotnet test` → `dotnet publish` → `verify-runtime-deps` → `build-release-setup.ps1`.

Sortie publish : `optiSCAN.WinUI\bin\Release\net10.0-windows10.0.19041.0\publish\win-x64\` (chemin attendu par `installer\setup.iss`). Installateur typique : `installer\output\optiSCAN_Setup_v1.0.0.exe`.

**Chaîne locale alternative** : `.\installer\build-release-setup.ps1` (nettoie, publie, lance ISCC).

### Ordre recommandé (équipe)

1. Gel fonctionnel : `.\scripts\validate-release-readiness.ps1` (ou `dotnet test` Release — **398** tests).
2. Dépendances : `.\scripts\fetch-runtime-deps.ps1` (+ `-RunFreshclam` pour l’installateur).
3. Publish local : `.\scripts\prepare-release.ps1` (ou étapes manuelles ci-dessous).
4. VM propre : installer `optiSCAN_Setup_v1.0.0.exe` ; scan, RTP, clamd, posture, FR/EN.
5. Signature (opt.) : Authenticode — `.\scripts\sign-publish-artifacts.ps1` ou `installer/setup.iss.signing.example`.
6. Tag / distribution : tag propre à l’édition (ex. `winui-v1.0.0`), release GitHub, SourceForge ou site.

### Étapes manuelles détaillées

**Étape 0 — nettoyage (recommandé)**

```powershell
.\scripts\clean-before-publish.ps1 -IncludeObj -IncludeInstallerOutput -IncludeCiPublish
```

**Étape A — publication .NET**

```powershell
# Défaut : framework-dependent (installateur léger)
dotnet publish .\optiSCAN.WinUI\optiSCAN.WinUI.csproj -c Release /p:PublishProfile=FolderProfile
# Option : tout embarqué (.NET 10 + Windows App SDK, aucun prérequis, installateur plus lourd)
dotnet publish .\optiSCAN.WinUI\optiSCAN.WinUI.csproj -c Release /p:PublishProfile=FolderProfile-SelfContained
```

> ⚠️ Ne pas publier avec `--self-contained true` seul : cela n'embarque **pas** le Windows App SDK
> (`WindowsAppSDKSelfContained` n'est défini que dans `FolderProfile-SelfContained`).

**Prérequis côté utilisateur (mode par défaut)** — `setup.iss` vérifie **.NET 10 Desktop Runtime** (version 10.x) et
**Windows App Runtime 1.8** (`Get-AppxPackage`). S'ils manquent, il propose de les télécharger (redistribuables
officiels Microsoft via `aka.ms`) et les installe silencieusement avant la copie des fichiers. `build-release-setup.ps1`
passe `/DSelfContainedPublish` et `/DWinAppSdkSelfContainedPublish` quand le dossier publish embarque ces runtimes.

**Étape B — première base ClamAV** (adapter `$pub` si vous publiez ailleurs)

```powershell
$pub = ".\optiSCAN.WinUI\bin\Release\net10.0-windows10.0.19041.0\publish\win-x64"
& "$pub\clamav\x64\freshclam.exe" --datadir="$pub\clamav\database"
```

**Étape C — compilateur Inno Setup**

```powershell
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" .\installer\setup.iss
```

**Installateur** : assistant **bilingue** (français / English), langue détectée d'après Windows (voir [§9](#9-langues-de-linterface-fr-fr-en-us)) ; langue retenue → `UiCulture` en registre pour le premier lancement de l’app.

**Contenu de l'installateur (léger, sans bases de signatures) :**

```
optiSCAN_Setup_v1.0.0.exe
    ├── optiSCAN.exe
    ├── optiSCAN.ico
    ├── *.dll + optiSCAN.pri    ← application (runtimes .NET / Windows App SDK non embarqués par défaut)
    ├── clamav/x64 et x86/      ← binaires (clamscan, freshclam, clamd) — pas les fichiers .cvd
    ├── yara/                   ← binaires du moteur de détection
    ├── rules/                  ← règles de détection initiales
    └── scripts/                ← add-defender-exclusions.ps1 (exclusions Defender post-install)
```

Les bases ClamAV sont téléchargées par freshclam au premier lancement.

### Checklist binaire (bloquant)

- [ ] `dotnet test` Release — **398** tests OK
- [ ] `.\scripts\verify-runtime-deps.ps1` — vert sur dossier publish (dont `optiSCAN.pri`)
- [ ] VM **sans** .NET 10 ni Windows App Runtime : l'installateur les propose, les installe, puis optiSCAN démarre
- [ ] `clamscan.exe`, `freshclam.exe`, **`clamd.exe`**, `yara64.exe`, règles `.yar`
- [ ] `clamav\database\` présent pour `verify-runtime-deps` (freshclam) — les `.cvd` ne sont pas copiés dans l'installeur
- [ ] Installateur FR/EN, sidebar **v1.0**, options clamd / VT / mode jeu, accueil posture /100
- [ ] Test post-install : scan fichier, quarantaine, **historique → traiter une menace**, exports PDF/HTML ; **clé USB** (scan auto si option activée) ; exclusions Defender (script ou démarrage app)
- [ ] Historique : `scan_history.dat` / `clean_history.dat` présents (chiffrés DPAPI + HMAC)

### CI GitHub

Pipelines : [`.github/workflows/ci.yml`](.github/workflows/ci.yml), [`codeql.yml`](.github/workflows/codeql.yml), [`dependency-review.yml`](.github/workflows/dependency-review.yml), [`gitleaks.yml`](.github/workflows/gitleaks.yml).

> **Branche `win` :** `ci.yml` se déclenche sur `main`, `dev` et `win` (push / pull request), ou manuellement (`workflow_dispatch`). Sur `win`, le job **build-test** tourne (build, tests, couverture). Le job **Publish win-x64** ne part que sur `refs/heads/main`. L’installeur de l’édition WinUI 3 se produit en local (`prepare-release.ps1`).

Contenu du workflow `ci.yml` : job **build-test** (build, tests, couverture) sur `main`, `dev` et `win` ; le job **Publish win-x64** est réservé à `refs/heads/main` : `fetch-runtime-deps.ps1 -RunFreshclam` → `dotnet publish` (`FolderProfile`, framework-dependent) + service de protection → `stage-runtime-deps.ps1` → SBOM CycloneDX → Inno → `optiSCAN_Setup_v1.0.0.exe`.

**Couverture** (définie dans `ci.yml`) : seuil minimal **40 %** lignes (échec si en dessous) ; avertissement si &lt; **50 %** (cible progressive).

**Freshclam en CI** : génère un `freshclam.conf` minimal dans `clamav\x64\` (non versionné dans Git, comme en production via `FreshclamUpdater`). **Erreur connue (corrigée)** : `Can't open/parse freshclam.conf` si freshclam est lancé sans `--config-file`.

**Repères de couverture tests (release, 398 au total — voir checklist)** :

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
| Thème Windows | `ThemeManagerPreferenceTests` (préférences) — parité des thèmes WinUI : `scripts/check-winui-theme-keys.ps1` |
| Persistance | `SecureStoreTests`, `UserPreferencesStorageTests`, `ExclusionSettingsTests`, `OptiscanProtectedPathsTests`, `WindowsDefenderExclusionServiceTests` |

### Après publication

- Ne pas fusionner `win` dans `main` / `dev` : éditions distinctes (WinUI 3 / WPF).
- **Format de persistance** : historiques en `scan_history.dat` / `clean_history.dat` (DPAPI + HMAC) ; sessions de l’ancien format lues sans chemins, migration unique vers `activity_log.dat` (voir [§4.9](#49-journaux-et-historique)).
- Maintenabilité et choix volontaires : [§12.1](#121-maintenabilité-et-choix-volontaires-non-bloquants).

### Signature Authenticode (optionnelle)

Windows affiche « Éditeur inconnu » sans certificat. Utile pour release publique ; nécessite un `.pfx` et des secrets CI (`CODESIGN_PFX`). Exemple : [`installer/setup.iss.signing.example`](installer/setup.iss.signing.example). Signer `optiSCAN.exe` + `optiSCAN_Setup_v1.0.0.exe` (`signtool`).

---

## 9. Langues de l’interface (fr-FR / en-US)

| Canal | Comportement |
|-------|----------------|
| **Installateur Inno** | Langue de Windows détectée (`ShowLanguageDialog=auto`) : FR ou EN directement, choix proposé seulement pour une autre langue (français présélectionné) ; mise à jour = langue précédente ; `/LANG=english` force. Résultat → `HKCU\Software\optiSCAN\UiCulture` |
| **Options → Langue** | Français / English → confirmation → **redémarrage** de l’app |
| **Ressources** | `UiStrings.resx` + `UiStrings.en.resx` (**839** clés FR/EN, parité vérifiée en CI) |
| **Menu contextuel** | « Scanner avec optiSCAN » ou « Scan with optiSCAN » sur **fichiers et dossiers** (`--scan`) |

Les deux langues sont **incluses dans le même binaire** (pas de pack de langue séparé). Les rapports PDF/HTML exportés et les journaux techniques ClamAV/YARA peuvent rester partiellement en français ou en anglais technique.

### Développeurs et traducteurs

| Fichier | Culture |
|---------|---------|
| `optiSCAN.Application/Resources/UiStrings.resx` | Français (défaut) |
| `optiSCAN.Application/Resources/UiStrings.en.resx` | Anglais (en-US) |

Ajouter une clé : même nom dans les deux `.resx` → C# `LocalizationService.GetString` / `Format` (les pages WinUI posent leurs libellés dans `ApplyLocalizedLabels`) ; pour une infobulle dans un `DataTemplate` : `svc:LocalizedTip.Key="…"` (infobulle + nom d'accessibilité).

```powershell
dotnet test optiSCAN.Tests\optiSCAN.Tests.csproj -c Release --filter Localization
```

Non traduit volontairement : sorties brutes clamscan/freshclam/YARA, noms de menaces, chemins, marques ClamAV/YARA. L’UI **Historique** n’affiche pas le libellé moteur (`DetectedBy`) — réservé au pipeline interne.

---

## 10. Dépendances et licences

| Composant | Version | Licence | Notes |
|---|---|---|---|
| optiSCAN (édition WinUI 3) | 1.0.0 | **GNU GPL v3 ou ultérieure** | `LICENSE.txt` (notice) + `COPYING` (texte complet) |
| ClamAV | Dernière stable | GPLv2 | Processus séparés (`clamscan` / `clamd`) — agrégation, pas de liaison |
| .NET 10 + WinUI 3 (Windows App SDK) | 1.8.x | MIT | Framework-dependent par défaut (runtimes installés par l'installateur si absents) ; self-contained en option ; systray en Win32 natif (`WinUiTrayHost`), sans paquet tiers |
| Microsoft.Data.Sqlite | 10.0.12 | MIT | Historique des scans paginé (`ScanLogSqliteStore`) |
| Microsoft.Extensions.DependencyInjection | 10.0.12 | MIT | Conteneur de services |
| QuestPDF | 2024.12.2 | Community | Rapport PDF — licence gratuite projets open-source |
| Mise à jour binaire optiSCAN (`UpdateService`) | — | — | Canal OTA non configuré ; staging `%LocalAppData%\optiSCAN\Updates` ; signatures via Antivirus |
| Planificateur de tâches (`schtasks.exe`) | — | — | Natif Windows — voir `ScheduledScanService` |
| Microsoft.Toolkit.Uwp.Notifications | 7.1.3 | MIT | Toasts Windows natifs |
| Inno Setup | 6.x | Freeware | Gratuit pour projets commerciaux |
| Base de signatures ClamAV | — | ClamAV License | Mise à jour depuis database.clamav.net |
| Règles de détection | — | Diverses open-source | Récupérées depuis YARA-Forge |

---

## 11. Historique

### v1 — 1 juin 2026

> Publication `release: optiSCAN 1` (`7092a34`, tag `v1`).

- **Dépôt** — initialisation du projet (30 avril 2026)
- **Moteurs** — ClamAV, YARA, installateur et services
- **Stabilité** — consolidation, puis traduction anglaise

### v2 — 23 juin 2026

> Publication `release: optiSCAN 2` (`6a23313`, tag `v2`). Dernier commit **commun** avec `main` / `dev` ; parent du `first commit` WinUI.

- **Interface** — i18n et suppression des fichiers détectés
- **Analyse** — clamd, scan USB, historique et quarantaine
- **Plateforme** — protection système et scan contextuel
- **Socle** — architecture, sécurité et coordinateurs

### v1 WinUI — `first commit`

> Commit `2ab25cc` (`first commit`) : c’est la **v1** avec WinUI — voir [§8](#8-édition-winui-3-issue-du-commit-first-commit). Release **v1.0**, assembly **1.0.0**. Moteurs ClamAV (dual-mode) + YARA, quarantaine chiffrée **AES-256-GCM**, protection temps réel, historique unifié, posture de sécurité /100, et couche plateforme (service, AMSI, tentative de minifiltre). La v3 WPF reste sur `main` / `dev`.

- **Installateur léger** — publication framework-dependent (`FolderProfile`) ; `setup.iss` installe .NET 10 Desktop Runtime et Windows App Runtime 1.8 s'ils manquent ; dossier par défaut `{autopf}\optiSCAN WinUI` ; mutex `Global\optiSCAN_WinUI_UniqueInstance`
- **Mode complémentaire Defender** — Defender garde le temps réel ; badge et posture ne pénalisent plus ce choix ([§5](#defendercoexistenceservice-mode-complémentaire-windows-defender))
- **Dépôt** — l’interface de cette édition est `optiSCAN.WinUI` ; `optiSCAN/` ne garde que les assets. Les 9 sources encore testées sont dans `optiSCAN.Tests/Legacy/`.
- **Historique des détections** — les détections de la protection temps réel et de la surveillance des processus laissent une session « Protection temps réel » (`ScanType.RealTime`, `DetectionHistoryRecorder`) dans l’Historique ; écriture de `scan_history.dat` verrouillée (accès concurrents)
- **Installeur propre à cette édition** — `AppId` Inno `8680BFF9-…` (`InnoUninstallGuid` aligné), distinct d’optiCOMBAT ; le nettoyage du menu contextuel ne supprime plus les entrées « Scan with optiCombat ».
- **Anti-autophagie** — `OptiscanProtectedPaths` : installation (Program Files + processus) et `%LOCALAPPDATA%\optiSCAN` (MAJ signatures, quarantaine, logs) exclus des scans / RTP / quarantaine auto ; dossiers obligatoires dans Options
- **Exclusions Defender** — `WindowsDefenderExclusionService` + `scripts/add-defender-exclusions.ps1` : chemins et processus optiSCAN enregistrés au démarrage de l’app (`--defender-exclusions` si UAC) ; l’installateur copie seulement le script
- **Démarrage UI** — handler global d’exceptions (`App.UnhandledException`) ; `WinUiStartupCoordinator` (instance unique, services) avant la navigation
- **Publish** — cible MSBuild `CleanStalePublishOutput` : nettoyage de `publish\` uniquement (évite publish cassé)
- **Refactor UI** — coordinateurs `optiSCAN.Application/Coordinators/` (14) + `optiSCAN.WinUI/Services/WinUi*Coordinator` : startup/shutdown, systray, exports, historique, RTP/USB/toasts ; `MainWindow` allégé (~720 L)
- **DI préférences** — `IUserPreferencesAccessor`, `IExclusionSettingsAccessor` ; vues via `IViewServices` / `IHistoryServices` / `IHistoryExportService`
- **Qualité** — `.editorconfig` ; NetAnalyzers `latest-recommended` ; tests Release ; SBOM CycloneDX en publish CI
- **Historique** — `ActivityLogService` + `activity_log.dat` (150 événements, migration unique) ; `HistoryViewModel` (5 filtres, `SelectionKey`) ; menaces traitables (**Traiter dans Analyse**) ; `scan_history.dat` / `clean_history.dat` (rotation 100→50) ; compat format hérité sans chemins
- **Accueil** — `OverviewRecommendationsBuilder` + `OverviewProtectionStatsFormatter` (stats 30 j. sans doublon dans les recommandations)
- **Scan USB/SD** — rapide = extensions à risque (4 000 max), moteurs **en série**, timeouts 10/45 min, repli récursif ; complet = `ScanFolderBackgroundAsync` ; statut barre + toasts début/fin
- **Quarantaine** — rollback si suppression originale échoue ; `ReconcileQuarantinedThreats` ; session scan active (`ActiveScanSessionId`)
- **Thème Windows** — `SyncWindowsTheme` par défaut ; case Options (thème opposé à Windows) ; `WinUiThemeManager` : presets d’accent, couleur perso, contraste renforcé ([§2](#2-donaby-design-système-de-thèmes))
- **clamd** — `CompositeClamAvBackend`, TCP `127.0.0.1:3310`, repli `clamscan.exe`
- **Posture /100**, **VirusTotal**, **mode jeu** — voir [§13](#13-sécurité-de-lédition-winui) et Options
- **Tests** — tests Release — [§12](#12-audit-et-qualité-de-lédition-winui) ; i18n **839** clés FR/EN ; coordinateurs + exports couverts par tests dédiés

---

## 12. Audit et qualité de l’édition WinUI

Ce chapitre porte sur la **v1 WinUI** (branche `win`, `optiSCAN.WinUI`). Le détail visuel et le câblage sont dans [`docs/audit-visuel-winui.md`](docs/audit-visuel-winui.md).

**Cotation actuelle (v1 WinUI, 1er octobre 2026) : 39/50.** Application installable, user-mode. L’installeur `optiSCAN_Setup_v1.0.0.exe` se produit en local. Le contrôle sur une machine sans .NET 10 ni Windows App Runtime reste à faire avant une diffusion large.

| Domaine | Note | État sur `win` |
|---------|:----:|----------------|
| Architecture | 8/10 | Shell WinUI 3, coordinateurs, ClamAV + YARA. Service et AMSI livrés ; minifiltre tenté, charge refusé sans signature |
| Sécurité locale | 8/10 | Quarantaine AES-GCM, historique DPAPI, périmètres protégés. Exclusion Defender encore large, scripts Tweaks dans `%TEMP%`, copie de sécurité non chiffrée |
| UI / Donaby | 8/10 | Thèmes clair, sombre, contraste ; volet au thème ; accueil adaptable ; onglet Antivirus marqué. Pas de passe visuelle sur machine vierge |
| Tests et CI | 8/10 | **398** tests ; build et tests sur `win`. Pas d’intégration réelle clamd / `schtasks`. Couverture au seuil **40 %** (cible 50 %) |
| Release | 7/10 | Installeur léger produit en local, sans bases `.cvd`. Non rejoué sur machine vierge, non signé |

**En place sur cette branche**

- **Shell** — cinq panneaux ; vignettes d’accueil câblées (Scanner → Analyse, Mise à jour → Signatures et lance la mise à jour). Hors Analyse, le hub de scan est masqué.
- **Thèmes** — clair, sombre, contraste renforcé ; accent tenu à 4,5:1 ; `ThemeBrush` suit le thème choisi. Le volet utilise le fond de la fenêtre (blanc en clair, `#141414` en sombre).
- **Fenêtre** — minimum 720×480 ; l’accueil défile et se réagence en dessous de 720 px.
- **Antivirus** — l’onglet cliqué est celui qui est marqué (fond teinté, texte accent, soulignement). `Ctrl+1`…`5` passent par `PreviewKeyDown`.
- **Protection** — temps réel de l’application en repli. Service `optiSCANProtection` et AMSI installables ; le minifiltre est enregistré (service noyau + altitude) puis tenté (`fltmc`) et Windows x64 le refuse tant qu’il n’est pas signé.
- **Installeur** — framework-dependent, sans bases `.cvd` ; freshclam au premier lancement ; `AppId` `8680BFF9-…` ; dossier `{autopf}\optiSCAN WinUI`.
- **Filet** — **398** tests Release, **839** clés FR/EN. Sur `win`, la CI lance le build et les tests. L’installeur de cette édition ne sort pas de ce job : il se construit ici.

**Encore ouvert sur cette branche**

- Installateur non rejoué sur une machine vierge (runtimes absents, première mise à jour des signatures, SmartScreen « éditeur inconnu »).
- Signature Authenticode non posée.
- Pas de test d’intégration réel pour clamd ni pour `schtasks`.
- Exclusion Defender de `%LocalAppData%\optiSCAN` encore large ; scripts élevés des Tweaks écrits dans `%TEMP%` avant l’UAC ; copie de sécurité avant quarantaine (option, coupée par défaut) non chiffrée — [SECURITY.md](SECURITY.md#hardening-backlog).
- Couverture de lignes au seuil CI (**40 %**, cible **50 %**) ; la cible cœur à 80 % n’est pas un échec de build.

```powershell
dotnet test optiSCAN.Tests\optiSCAN.Tests.csproj -c Release
```

### 12.1 Maintenabilité et choix volontaires (non bloquants)

**`MainWindow` allégé (v1 WinUI)** — la logique événementielle est dans `optiSCAN.Application/Coordinators/` et `optiSCAN.WinUI/Services/WinUi*Coordinator` (classes `static` + hôtes typés). Il reste dans la fenêtre : enregistrement des panneaux, branchement `ServiceContainer`, et raccourcis navigation (`Ctrl+1`…`5` par `PreviewKeyDown`, sans accélérateur WinUI).

**`optiSCAN.log` non chiffré** — choix intentionnel pour le support et le mode headless. Les lignes produites par `FormatScanDetail` / `FormatScanDetailCore` passent par `PathRedaction.RedactPath` sur `TargetPath` et `FilePath` : pas de chemins complets dans le journal. Restent lisibles : noms de menace, horodatages, compteurs — acceptable pour un log de diagnostic.

**`PostureFix_Click` / `LaunchFixUri`** — repli `ms-settings:…` puis `control.exe` (séparateur `|` dans `FixUri`) ; logique dans `PostureFixService` / `OverviewPage`. Test unitaire possible via `internal` + `InternalsVisibleTo`, **ROI faible** (deux branches triviales) ; la posture elle-même est couverte par `SecurityPostureServiceTests`.

---

## 13. Sécurité de l’édition WinUI

Périmètre de la **v1 WinUI** : ClamAV, YARA, quarantaine, protection temps réel de l’application, historique, service Windows et AMSI. Le minifiltre est tenté au chargement ; sans signature Authenticode / attestation Microsoft, Windows x64 le refuse. La note posture ne mesure pas le pilote noyau.

### Note posture /100 (Accueil)

| Id | Poids | Source |
|----|-------|--------|
| `firewall` | 15 | Domain / Standard / Public (`EnableFirewall`) |
| `uac` | 10 | `EnableLUA` |
| `wupdate` | 15 | `IWindowsUpdateProbe` (registre, WMI, WUA) |
| `shares` | 10 | Partages SMB (`REG_MULTI_SZ`) |
| `optiscan` | 25 | ClamAV + YARA + protection temps réel de l’application (ou temps réel laissé à Defender en mode complémentaire) |
| `scan` | 15 | Dernière analyse &lt; 7 jours |
| `sigauto` | 10 | MAJ signatures auto |

La note ne mesure pas le service noyau. En mode complémentaire, Defender garde le temps réel et le critère `optiscan` reste réussi.

Limite : les trois profils pare-feu sont lus au registre, pas le profil réseau actif.

Liens **Corriger** (accueil) : `optiscan://panel/{id}` (antivirus, options, history, clean, overview) ; UAC → `UserAccountControlSettings.exe` (+ repli `control.exe`) ; pare-feu → `ms-settings:windowsdefender-firewall` (+ replis) ; partages → `advancedsharing|control.exe` (séparateur `|`).

### Ce que cette version couvre

**Actifs** : fichiers analysés, quarantaine, préférences et exclusions (`%LocalAppData%\optiSCAN`), clé VirusTotal si l’utilisateur l’a saisie.

**Contrôles actifs** : quarantaine AES-GCM + HMAC ; exclusions avec frontière `\` ; périmètres protégés (`OptiscanProtectedPaths`) ; exclusions Defender posées au démarrage de l’application ; élévation pour l’analyse complète ; protection temps réel de l’application ; clamd sur `127.0.0.1`, repli `clamscan.exe`.

**Limite noyau** : le minifiltre ne se charge pas tant que le `.sys` n’est pas signé (SignPath prévu plus tard). Un logiciel qui tourne déjà en administrateur peut couper un antivirus local. VirusTotal, s’il est activé, envoie le condensat. `optiSCAN.log` reste un journal de diagnostic : chemins de scan réduits par `PathRedaction`, fichier non chiffré. Les dettes encore ouvertes sont au [§12](#12-audit-et-qualité-de-lédition-winui).

---

## 14. Crédits

Développé par **© 2026 Donatien Byakombe**  
Design system : **Donaby Design**  
Licence de l’édition WinUI 3 : **GNU GPL v3 ou ultérieure** (`LICENSE.txt`, `COPYING`).
