# Audit complet — optiSCAN v7.0

**Produit** : optiSCAN — ClamAV Edition  
**Version** : 7.0.0 / release v7.0  
**Date** : audit statique du dépôt (mai 2026)  
**Méthode** : revue code, documentation, installateur, tests unitaires Release

---

## Synthèse exécutive

| Domaine | Verdict | Note |
|---------|---------|------|
| **Architecture** | Solide pour une app desktop mono-scope ; `MainWindow` trop chargé | 7/10 |
| **Sécurité locale** | Quarantaine chiffrée, exclusions signées, `asInvoker` | 8/10 |
| **UI / thèmes** | Donaby clair/sombre globalement OK ; quelques hex fixes | 7/10 |
| **Réactivité perçue** | Navigation légère, refresh post-clic lourd | 5/10 |
| **i18n** | XAML ~100 clés FR/EN ; services/logs encore FR-only | 6/10 |
| **Release / Inno** | Mature si `verify-runtime-deps` + publish correct | 7/10 |
| **Tests** | 49 tests unitaires OK ; lacunes schtasks/freshclam/UI | 6/10 |
| **Documentation** | README + docs/ riches ; pas de CI ni threat model | 7/10 |

**Verdict global** : produit **publiable** avec vigilance sur dépendances runtime (ClamAV/YARA), réactivité navigation, et promesse « scan complet » sans élévation UAC.

---

## Tests automatisés (état au audit)

```powershell
dotnet test optiSCAN.Tests\optiSCAN.Tests.csproj -c Release
```

| Résultat | Valeur |
|----------|--------|
| Total | 49 |
| Réussis | 49 |
| Échecs | 0 |

Couverture indirecte : quarantaine, SecureStore, localisation, chemins ClamAV, merger menaces, logs.  
**Non couvert** : navigation UI, schtasks, freshclam process, RTP, mode headless, installateur.

---

## 1. Architecture et qualité du code

### 1.1 Points forts

- **Mono-fenêtre + panneaux** : `NavigationService` bascule `Visibility` — simple, prévisible.
- **ServiceContainer** : ClamAV, YARA, quarantaine, RTP, planificateur, notifications centralisés.
- **Abstractions** : `IScanEngine`, coordinateur MAJ signatures, cibles scan unifiées (`ScanTargets`).
- **Shutdown** : désabonnements événements, arrêt RTP, mutex instance unique.

### 1.2 Dettes techniques

| Problème | Fichier(s) | Gravité |
|----------|------------|---------|
| God object (~1070 lignes) | `MainWindow.xaml.cs` | P2 |
| Logique quarantaine dupliée | `MainWindow` vs `AntivirusActions` | P1 |
| Handlers legacy non migrés | `BtnQuarantineThreat_Click`, etc. | P1 |
| MVVM partiel (1 ViewModel) | `ScanViewModel` seul | P2 |
| `async void` (MAJ, clean, RTP) | Plusieurs vues/services | P2 |
| `ElevationHelper` **jamais appelé** | `ElevationHelper.cs` | P1 |

### 1.3 Recommandations

1. Finaliser migration vers `AntivirusActions` pour toutes les actions menaces.
2. Extraire refresh navigation dans un `NavigationRefreshCoordinator`.
3. Brancher `ElevationHelper` ou documenter clairement les limites du scan sans admin.

---

## 2. UI / UX

### 2.1 Thèmes et lisibilité

Détail : [AUDIT-UI-COULEURS.md](AUDIT-UI-COULEURS.md)

| État | Détail |
|------|--------|
| OK | Tokens Donaby, ComboBox thématisées, onglets Antivirus/Historique |
| Reste | Colonne Risque (hex fixes), PDF export, tooltips sidebar FR hardcodés |

### 2.2 Réactivité au clic

Détail : [AUDIT-UI-REACTIVITE.md](AUDIT-UI-REACTIVITE.md)

| Écran | Problème principal |
|-------|-------------------|
| Accueil / Antivirus | Refresh historique + signatures + reco en cascade |
| Options | `schtasks` synchrone (jusqu’à ~15 s) |
| Nettoyage | OK (Task.Run) |

### 2.3 Options — langue et scan favori

| Élément | État |
|---------|------|
| Ouverture ComboBox au 1er clic | Corrigé (`PreviewMouseLeftButtonDown` + `IsDropDownOpen = true`) |
| Ambiguïté WPF/WinForms `ComboBox` | Corrigé (`System.Windows.Controls.ComboBox`) |
| Langue active affichée avant changement | Initialisation via `UserPreferences.UiCulture` ; pas de reset dans `DropDownOpened` |
| Style | ComboBox système (`Style="{x:Null}"`) — lisibilité OK, rendu moins intégré au thème |

### 2.4 Icône barre des tâches

| Couche | Configuration |
|--------|---------------|
| Exécutable | `<ApplicationIcon>optiSCAN.ico</ApplicationIcon>` |
| Fenêtre | `MainWindow.xaml` → `Icon="optiSCAN.ico"` |
| Systray | `ResolveTrayIcon()` → exe puis `optiSCAN.ico` |

Si icône générique persiste : cache Windows — fermer app, désépingler, relancer, ré-épingler.

---

## 3. Internationalisation (i18n)

Détail : [LOCALIZATION.md](LOCALIZATION.md)

### 3.1 OK

- `UiStrings.resx` / `UiStrings.en.resx` : **100 clés** chacun (parité).
- `{loc:Loc Key=...}` largement adopté en XAML.
- Installateur : `UiCulture` registre + menu contextuel FR/EN.
- Options langue : confirmation + redémarrage.

### 3.2 Lacunes (FR hardcodé)

| Zone | Exemples |
|------|----------|
| Services MAJ | `FreshclamUpdater`, `SignatureUpdateCoordinator` |
| Actions menaces | `AntivirusActions` |
| Nettoyage | `CleanControl.xaml.cs` (logs) |
| ViewModel | `ScanViewModel` (« Vérification… », « Jamais ») |
| Dialogues système | Filtres export, `FolderBrowserDialog` |
| Installateur | Message désinstallation données utilisateur (FR only) |
| Systray | `NotifyIcon.Text = "optiSCAN"` |

### 3.3 Écart installateur / app

Registre `AutoUpdateSignatures` écrit par Inno (`setup.iss`) — **non lu** par l’app (seule `UserPreferences.SignatureAutoUpdateEnabled` compte).

---

## 4. Performance et réactivité

### P0

| ID | Action | Fichiers |
|----|--------|----------|
| R1 | Cache `GetLocalDatabaseVersion()` | `FreshclamUpdater.cs` |
| R2 | Alléger `RefreshAntivirusData` (pas d’historique complet systématique) | `MainWindow.xaml.cs` |
| R3 | `schtasks` en `Task.Run` + indicateur Options | `OptionsControl.xaml.cs`, `ScheduledScanService.cs` |

### P1

| ID | Action |
|----|--------|
| R4 | Fusionner appels `RefreshOverviewProtectionAndRecommendations` |
| R5 | Refresh conditionnel (panneau visible / TTL cache) |
| R6 | Remplacer `Dispatcher.Invoke` redondant dans `ScanViewModel` |

---

## 5. Sécurité

### 5.1 Solide

| Mécanisme | Détail |
|-----------|--------|
| **Quarantaine** | AES-256-GCM, clé DPAPI, manifest HMAC, refus chemins sensibles |
| **Exclusions** | DPAPI + HMAC, exclusion auto dossier install |
| **Exécution** | Manifest `asInvoker` — pas d’admin par défaut |
| **Préférences** | Chiffrement local (`SecureStore`) |

### 5.2 Risques

| ID | Risque | Gravité |
|----|--------|---------|
| S1 | Scan complet / planifié sans UAC → couverture limitée | **P0** |
| S2 | `ElevationHelper` implémenté mais non branché | **P1** |
| S3 | Suppression fichier menace sans confirmation | **P1** |
| S4 | Exclusion dossier sans avertissement utilisateur | P2 |
| S5 | Restauration quarantaine sans re-scan | P2 |

---

## 6. Build, publish et installateur

Détail : [BUILD.md](BUILD.md)

### Checklist release manuelle

```powershell
.\scripts\clean-before-publish.ps1 -IncludeObj -IncludeInstallerOutput
.\scripts\verify-runtime-deps.ps1          # clamav + yara + rules
dotnet publish .\optiSCAN\optiSCAN.csproj -c Release /p:PublishProfile=FolderProfile
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" .\installer\setup.iss
```

### Points clés

| Sujet | Détail |
|-------|--------|
| Runtime | Non self-contained → .NET 8 Desktop Runtime requis |
| Binaires | ClamAV/YARA **hors git** — publish incomplet sans copie manuelle |
| Clean publish | Cible MSBuild supprime `bin\Release\...` avant publish |
| Inno | Détection publish, UiCulture, vérif .NET 8 bilingue, clean install conf legacy |
| CI | **Absente** — pas de workflow GitHub Actions |

---

## 7. Matrice des risques (P0 / P1 / P2)

### P0 — Bloquants ou impact majeur

| ID | Risque | Référence |
|----|--------|-----------|
| P0-1 | Micro-freezes navigation (I/O + refresh cascade) | `MainWindow.xaml.cs`, `FreshclamUpdater.cs` |
| P0-2 | Publish sans deps → installateur incomplet | `optiSCAN.csproj`, `verify-runtime-deps.ps1` |
| P0-3 | « Full scan » / planifié sans élévation | `ScanTargets.cs`, `ElevationHelper.cs`, `ScheduledScanService.cs` |

### P1 — Importants

| ID | Risque | Référence |
|----|--------|-----------|
| P1-1 | `ElevationHelper` non câblé | `ElevationHelper.cs` |
| P1-2 | `schtasks` synchrone UI | `OptionsControl.xaml.cs` |
| P1-3 | i18n services/logs FR-only | `CleanControl`, `FreshclamUpdater`, `AntivirusActions` |
| P1-4 | Suppression menace sans confirmation | `MainWindow`, `AntivirusActions` |
| P1-5 | Duplication logique quarantaine | `MainWindow` vs `AntivirusActions` |
| P1-6 | Registre `AutoUpdateSignatures` ignoré | `setup.iss` vs `UserPreferences` |
| P1-7 | Tests absents schtasks/freshclam/headless | `optiSCAN.Tests` |

### P2 — Améliorations

| ID | Risque | Référence |
|----|--------|-----------|
| P2-1 | Tooltips sidebar non localisés | `MainWindow.xaml` |
| P2-2 | Couleurs risque hex fixes | `RiskScoringService` |
| P2-3 | MainWindow god object | `MainWindow.xaml.cs` |
| P2-4 | Pas de CI build+test | racine dépôt |
| P2-5 | `SetAutoStart` via `Assembly.Location` | `OptionsControl.xaml.cs` |
| P2-6 | Désinstallateur dialogue FR-only | `setup.iss` |

---

## 8. Plan d’action recommandé

### Avant prochaine release (priorité haute)

1. Exécuter `verify-runtime-deps.ps1` avant chaque publish.
2. Corriger réactivité P0 (cache signatures, schtasks async).
3. Clarifier UX scan complet (élévation ou message honnête sur limites).
4. Vérifier icône barre des tâches sur build Release installé (pas seulement F5 Debug).

### Court terme (1–2 sprints)

5. Internationaliser `CleanControl`, `AntivirusActions`, messages MAJ.
6. Migrer handlers menaces vers `AntivirusActions`.
7. Ajouter tests `ScheduledScanService`, `FreshclamConfSupport` étendu.
8. Lire ou supprimer registre `AutoUpdateSignatures`.

### Moyen terme

9. CI : build Release + `dotnet test` + artefact publish.
10. Refactor `MainWindow` (refresh coordinator, exports).
11. Brancher `ElevationHelper` ou retirer le code mort.

---

## 9. Documents associés

| Document | Contenu |
|----------|---------|
| [AUDIT-UI-COULEURS.md](AUDIT-UI-COULEURS.md) | Lisibilité clair/sombre, tokens |
| [AUDIT-UI-REACTIVITE.md](AUDIT-UI-REACTIVITE.md) | Latence navigation, schtasks, I/O |
| [LOCALIZATION.md](LOCALIZATION.md) | FR/EN utilisateur et dev |
| [BUILD.md](BUILD.md) | Publish, Inno, dépannage |
| [../README.md](../README.md) | Guide architecture v7.0 |

---

## 10. Validation manuelle suggérée (post-release)

- [ ] Installateur FR puis EN — UI et menu contextuel cohérents
- [ ] Options : langue active visible, changement avec redémarrage
- [ ] Navigation Accueil ↔ Antivirus × 10 — fluidité acceptable
- [ ] Scan planifié : case à cocher sans freeze > 1 s
- [ ] Icône barre des tâches + systray (pas d’icône générique)
- [ ] Quarantaine : ajout, restauration, refus chemins sensibles
- [ ] Publish sur machine vierge sans .NET → message installateur .NET 8

---

*Audit statique — aucune modification de code dans ce document. Dernière exécution tests : 49/49 Release.*
