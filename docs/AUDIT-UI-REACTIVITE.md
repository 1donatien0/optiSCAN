# Audit UI — réactivité au clic (navigation et interactions)

**optiSCAN v7.0** — analyse statique du code (`MainWindow`, `NavigationService`, vues, ViewModels)  
**Date** : audit statique du dépôt (pas de profilage ETW / WPR sur machine réelle).

---

## 1. Synthèse

| Verdict | Détail |
|---------|--------|
| **Changement de panneau (sidebar)** | **Immédiat** : `NavigationService.NavigateTo` ne fait que basculer `Visibility` — pas de création de contrôles. |
| **Ressenti après le clic** | **Variable** : les rafraîchissements post-navigation s’exécutent sur le thread UI (via `Dispatcher.BeginInvoke` en priorité `Background`) et peuvent provoquer **micro-freezes** (50–300 ms selon disque et taille de l’historique). |
| **Pire cas utilisateur** | Clic **Antivirus** ou retour **Accueil** : I/O disque signatures + rechargement historique/quarantaine + recommandations recalculées **plusieurs fois** dans la même chaîne. |
| **Options** | Ouverture de l’onglet : `IsTaskExists()` / `GetNextRunTime()` via `schtasks.exe` (jusqu’à ~15 s en timeout). Case **Scan planifié** : `CreateDailyScan` / `DeleteTask` **synchrones** sur le thread UI. |
| **Nettoyage / analyse** | Pattern correct (`Task.Run` + logs via dispatcher) — latence attendue pendant l’opération, pas au simple clic de navigation. |

**Objectif cible** : panneau visible en **&lt; 16 ms** (1 frame) ; travail lourd en **arrière-plan** avec mise à jour progressive des libellés.

---

## 2. Chaîne d’un clic sidebar

```
NavItem_Checked
  → SwitchPanel → NavigationService.NavigateTo
       → Visibility (instantané)
       → événement Navigated
  → SurNavigationNaviguee
       → Dispatcher.BeginInvoke(Background)
            → SyncSidebarSelection
            → ApplyNavigationSideEffects(panelName)
```

### 2.1 Ce qui est bien fait

| Mécanisme | Effet |
|-----------|--------|
| `NavigateTo` sans chargement lazy | Pas de coût de layout supplémentaire au changement d’onglet. |
| `BeginInvoke` + `Background` | Le handler `Checked` et l’affichage du panneau ne sont pas bloqués par la suite de la chaîne (en théorie). |
| Cache `ClamAvEngine.IsClamAvInstalled` (60 s) | Évite de relancer `clamscan` à chaque navigation. |
| `ScheduledScanService.RunSchtasksCapture` | Lecture stdout/stderr concurrente + timeout 15 s — limite les deadlocks `schtasks`. |

### 2.2 Travail déclenché par panneau

| Panneau | `ApplyNavigationSideEffects` | Charge estimée |
|---------|------------------------------|----------------|
| **Accueil** | `RefreshHistory` + `RefreshAntivirusStatus` + `RefreshSignaturesDisplay` | **Élevée** |
| **Antivirus** | `RefreshAntivirusData()` (= status + quarantaine + historique + signatures) | **Très élevée** |
| **Historique** | `RefreshHistory` seul | **Moyenne** (taille JSON historique) |
| **Nettoyage** | *(aucun)* | **Faible** |
| **Options** | *(aucun)* | **Faible** à la navigation ; **élevée** au premier affichage (`LoadPreferences`) |

Fichiers centraux : `MainWindow.xaml.cs` (`ApplyNavigationSideEffects`, `RefreshAntivirusData`, `RefreshSignaturesDisplay`, `RefreshHistory`).

---

## 3. Goulots d’étranglement détaillés

### 3.1 I/O disque — version base ClamAV (P0)

`FreshclamUpdater.GetLocalDatabaseVersion()` lit jusqu’à **4 fichiers** (`.cld` / `.cvd`) et parse l’en-tête (512 octets + regex) **à chaque** appel.

Appelé notamment depuis :

- `RefreshSignaturesDisplay()`
- `RefreshOverviewProtectionAndRecommendations()` (via `GetLocalDatabaseVersion` + dates associées)

**Sur un clic Accueil** : `RefreshSignaturesDisplay` appelle en fin de chaîne `RefreshOverviewProtectionAndRecommendations()` → **double lecture** des mêmes fichiers si l’historique a déjà déclenché `RefreshHistory` → `RefreshOverviewProtectionAndRecommendations()`.

**Sur un clic Antivirus** : jusqu’à **triple** travail redondant sur l’accueil (historique + signatures, chacun rappelant les recommandations).

| Priorité | Recommandation |
|----------|----------------|
| **P0** | Cache mémoire (version + horodatage fichier) invalidé après MAJ signatures ou toutes les 30–60 s. |
| **P1** | Exécuter la lecture sur `Task.Run` puis `Dispatcher.BeginInvoke` pour mettre à jour les `TextBlock`. |

### 3.2 Historique et quarantaine (P0–P1)

`RefreshHistory()` :

- `_logManager.GetHistory()` + `GetCleanHistory()` (désérialisation / lecture fichier selon implémentation `ScanLogManager`).
- Mise à jour des grilles Historique **même** si le panneau Historique n’est pas visible.
- `UpdateProtectionStatistics`, `ApplyLastScanSummary`, `RefreshOverviewProtectionAndRecommendations`.

`RefreshQuarantineList()` → `ScanViewModel.LoadQuarantine` utilise `Dispatcher.Invoke` (synchrone) : inutilement bloquant si déjà sur le thread UI.

| Priorité | Recommandation |
|----------|----------------|
| **P0** | Ne pas appeler `RefreshHistory` complet sur chaque entrée Antivirus ; rafraîchir seulement onglets visibles ou données « stale » (&gt; N secondes). |
| **P1** | Remplacer `Dispatcher.Invoke` par mise à jour directe ou `BeginInvoke` dans `LoadQuarantine` / `LoadHistory`. |
| **P2** | Pagination / cache de l’historique en mémoire avec invalidation explicite après scan. |

### 3.3 Duplication `RefreshOverviewProtectionAndRecommendations` (P1)

Chaîne actuelle (simplifiée) pour **Antivirus** :

```
RefreshAntivirusData
  → RefreshHistory → RefreshOverviewProtectionAndRecommendations  (1)
  → RefreshSignaturesDisplay → RefreshOverviewProtectionAndRecommendations  (2)
```

Chaque passage relit signatures, recompte menaces 30 j, reconstruit les 3 cartes recommandations.

| Priorité | Recommandation |
|----------|----------------|
| **P1** | Un seul point d’entrée `RefreshOverviewSummary(force: bool)` avec garde « déjà à jour » ou coalescing dans la même `BeginInvoke`. |

### 3.4 Cartes Accueil → navigation (P1)

`OverviewControl.ActionCard_Click` :

- Navigation classique : `NavigateTo` seul (effets ci-dessus).
- Carte **Mettre à jour** : `NavigateTo(Antivirus)` + focus onglet signatures + `TriggerSignatureUpdate()` → peut lancer réseau / processus **en plus** du refresh navigation.

| Priorité | Recommandation |
|----------|----------------|
| **P1** | Décaler `TriggerSignatureUpdate` après affichage du panneau (`BeginInvoke` `ApplicationIdle` ou bouton explicite). |

### 3.5 Options — `schtasks` sur le thread UI (P0)

| Action | Comportement | Risque |
|--------|--------------|--------|
| `LoadPreferences` | `ScheduledScan.IsTaskExists()` | Freeze au **premier** affichage Options |
| `RefreshScheduledStatus` | `IsTaskExists` + `GetNextRunTime` (XML ou LIST) | Jusqu’à plusieurs processus |
| `CheckOption_Changed` — `ScheduledScan` | `CreateDailyScan` / `DeleteTask` puis re-query | **100 ms – plusieurs s** |

| Priorité | Recommandation |
|----------|----------------|
| **P0** | `await Task.Run(() => ScheduledScan.CreateDailyScan(...))` + indicateur « en cours » sur la case. |
| **P1** | Cache booléen « tâche planifiée active » + refresh async à l’ouverture Options. |

### 3.6 Autres interactions

| Zone | Observation |
|------|-------------|
| **Scan en cours** | `ScanViewModel` utilise parfois `Dispatcher.Invoke` (bloquant) pendant le scan — acceptable hors navigation. |
| **Protection temps réel** | `SurMenaceTempsReelDetectee` en `BeginInvoke(Background)` — bon pattern. |
| **Exports PDF/HTML** | Déjà différés en `BeginInvoke(Background)` depuis les événements. |
| **ComboBox langue** | Redémarrage app — hors perf clic. |
| **Thème** | `ThemeManager.Apply` sur case à cocher — coût WPF modéré, acceptable. |

---

## 4. Matrice réactivité par écran

| Écran | Clic typique | Réactivité visuelle | Travail post-clic | Note |
|-------|--------------|---------------------|-------------------|------|
| Sidebar → Accueil | Radio `Checked` | Immédiate | Historique + AV + signatures + reco | Redondance signatures/reco |
| Sidebar → Antivirus | Idem | Immédiate | **Pack complet** AV | Le plus lourd |
| Sidebar → Historique | Idem | Immédiate | Recharge grilles | OK si historique modeste |
| Sidebar → Nettoyage | Idem | Immédiate | Aucun | Bon |
| Sidebar → Options | Idem | Immédiate | `LoadPreferences` (schtasks) au load contrôle | Premier affichage lent |
| Carte Accueil | `MouseLeftButtonUp` | Immédiate | Comme navigation cible | Carte MAJ = + update signatures |
| Onglets Antivirus | `TabItem` | Immédiate | Dépend du VM / binding | Pas de refresh global forcé |
| Cases Options planif. | `CheckBox` | Toggle visible puis freeze possible | `schtasks` sync | **P0** async |

---

## 5. Plan d’action recommandé

| Id | Priorité | Action | Effort |
|----|----------|--------|--------|
| R1 | P0 | Cache `GetLocalDatabaseVersion` + dates signatures YARA/ClamAV | Faible |
| R2 | P0 | `ScheduledScan` : création/suppression/query en `Task.Run` + retour UI | Moyen |
| R3 | P0 | Alléger `RefreshAntivirusData` (pas d’historique complet si onglet Analyse seul) | Moyen |
| R4 | P1 | Fusionner les appels `RefreshOverviewProtectionAndRecommendations` | Faible |
| R5 | P1 | `LoadQuarantine` / `LoadHistory` sans `Dispatcher.Invoke` redondant | Faible |
| R6 | P2 | Profilage réel : DiagnosticSource ou `dotnet-trace` sur clic Antivirus × 10 | Faible |

---

## 6. Tests automatisés (exécution Release)

Commande :

```powershell
dotnet test optiSCAN.Tests\optiSCAN.Tests.csproj -c Release --verbosity normal
```

**Dernier run réussi** : **49 tests, 49 réussis, 0 échec** (~2,6 s d’exécution des tests).

Couverture indirecte liée à la perf / robustesse :

| Suite | Lien réactivité |
|-------|-----------------|
| `LocalizationServiceTests` | Pas de blocage UI (ressources) |
| `ScanLogManagerTests` | Historique — taille influence `RefreshHistory` |
| `QuarantineManagerTests` | Pagination quarantaine |
| `ScanProgressRelayTests` / `MultiTargetScanAggregatorTests` | Progression scan (pas navigation) |
| `FreshclamConfSupportTests` / `YaraRulesCacheSupportTests` | Config / cache règles (aligné avec R1) |
| `NotificationServiceTests` | Toasts — chemins `HandleToastActivation` |

**Non couvert par les tests unitaires** : délais perçus au clic sidebar, `schtasks`, lecture `.cvd` sur thread UI — à valider manuellement ou par test UI (FlaUI / WinAppDriver) si besoin.

### Dépendance build

Si `MSB3027` / fichier verrouillé : fermer **optiSCAN.exe** (et le débogueur VS) puis relancer `dotnet test`.

---

## 7. Scénario de validation manuelle (checklist)

1. Lancer l’app Release, historique ≥ 50 scans simulés ou réels.
2. Enchaîner 10× : Accueil → Antivirus → Historique → Nettoyage → Options (chrono subjectif ou OBS).
3. Sur **Options**, cocher/décocher **Scan planifié** : le toggle doit rester fluide (objectif post-R2).
4. Sur **Accueil**, carte « Mettre à jour les signatures » : panneau Antivirus visible avant barre de progression réseau.
5. Répéter avec base ClamAV sur HDD lent vs SSD — écart attendu sur R1.

---

## 8. Références code

| Fichier | Rôle |
|---------|------|
| `Services/NavigationService.cs` | Bascule visibilité |
| `MainWindow.xaml.cs` | `SurNavigationNaviguee`, `ApplyNavigationSideEffects`, refreshs |
| `Services/FreshclamUpdater.cs` | `GetLocalDatabaseVersion` |
| `ViewModels/ScanViewModel.cs` | `LoadQuarantine`, `LoadHistory` |
| `Views/OptionsControl.xaml.cs` | `CheckOption_Changed`, `LoadPreferences` |
| `Views/OverviewControl.xaml.cs` | `ActionCard_Click` |
| `Services/ScheduledScanService.cs` | `schtasks` |
