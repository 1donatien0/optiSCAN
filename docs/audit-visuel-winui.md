# Audit visuel & câblage — optiSCAN.WinUI (branche `win`)

_Date : 2026-07-07, mis à jour le 2026-09-30 — portée : `optiSCAN.WinUI` (thèmes, styles, vues, câblage accueil)._

> Les sections 1 à 3 sont l'audit initial (historique). L'état actuel est décrit en §4 et dans la
> dernière section « Passe contraste & cohérence (septembre 2026) », qui prévaut en cas d'écart.

Ce document couvre deux volets : (1) les correctifs de câblage déjà appliqués, et
(2) un audit du rendu visuel avec des recommandations concrètes **à valider avant modification**.

---

## 1. Câblage de l'accueil — corrigé

### Bug principal : « Mise à jour » ne bascule pas sur l'onglet Signatures

`OverviewPage.ActionUpdateSig_Click` appelait `RequestFocusAntivirusSignaturesTab()`,
mais l'événement `FocusAntivirusSignaturesRequested` du bus UI **n'était abonné nulle part**
dans le shell WinUI (`WinUiServiceEventCoordinator.Attach` ne le branchait pas). Résultat :
navigation vers Antivirus OK, mise à jour déclenchée OK, mais l'onglet Signatures jamais
sélectionné. Le même événement sert à l'onboarding (`OnboardingService`) — donc lui aussi
était cassé sur la branche `win`, alors qu'il fonctionnait sur les branches WPF.

**Correctif** : ajout d'un handler `OnFocusAntivirusSignaturesRequested` dans `MainWindow`
(navigue vers Antivirus + `SelectSignaturesTab()`), abonné via le coordinateur.

### Vignette « Scan » sur page en cache

`AntivirusPage` est mise en cache (une seule instance). La vignette « Scan » ne faisait que
`NavigateTo(Antivirus)` sans cibler d'onglet : si la page était restée sur Signatures ou
Quarantaine, cliquer « Scan » n'y ramenait pas l'onglet Scan.

**Correctif** : nouvel événement `FocusAntivirusScanTabRequested` (symétrique à celui des
signatures), appelé par la vignette Scan et branché dans le shell (`SelectScanTab()`).

### Fichiers touchés

- `optiSCAN.Application/Services/IUiEventBus.cs` — nouvel événement + méthode.
- `optiSCAN.Application/Services/UiEventBus.cs` — implémentation + `ClearHandlers`.
- `optiSCAN.Application/Services/ServiceContainer.cs` — délégation.
- `optiSCAN.WinUI/Services/WinUiServiceEventCoordinator.cs` — abonnements (Attach/Detach).
- `optiSCAN.WinUI/MainWindow.xaml.cs` — 2 handlers + branchement.
- `optiSCAN.WinUI/Views/OverviewPage.xaml.cs` — vignette Scan.

### Comportement cible des vignettes (référence)

| Vignette | Navigation | Onglet ciblé |
|----------|-----------|--------------|
| Nettoyer | Clean | — |
| Scanner | Antivirus | Scan |
| Historique | History | — |
| Mise à jour | Antivirus | Signatures + déclenche la MAJ |

---

## 2. Audit du rendu visuel

### 2.1 Espacements & alignements

**Constat** — aucune échelle d'espacement partagée. Les valeurs de `Spacing` / `Padding`
sont saisies au cas par cas et divergent d'une vue à l'autre :

- `Spacing` mélange 2, 4, 6, 8, 10, 12, 16 sans logique. Overview/Antivirus privilégient 8 ;
  Clean/Options privilégient 10 → deux « rythmes » verticaux visibles selon la page.
- Le padding de page `48,36,48,32` est **codé en dur** dans `AntivirusPage.xaml` et
  `HistoryPage.xaml` au lieu de réutiliser `PageScrollViewerStyle`.
- Padding interne des cartes incohérent : `AppCardStyle` = 16, mais des bordures inline
  utilisent 12, `12,10`, `14,12`.

**Recommandation** — définir une échelle d'espacement (multiples de 4) en ressources et s'y
tenir :

```
SpacingXS = 4    SpacingS = 8    SpacingM = 12    SpacingL = 16    SpacingXL = 24
```

Utiliser `PageScrollViewerStyle` partout (supprimer les `48,36,48,32` inline), et n'autoriser
que `SpacingS`/`SpacingM`/`SpacingL` pour les `StackPanel`. Cible : deux valeurs de gouttière
maximum par page.

### 2.2 Typographie & styles

**Constat** — les styles de texte partagés existent (`PageTitleStyle`, `SectionTitleStyle`,
`MetricValueStyle`…) mais ne sont pas appliqués partout :

- Tailles de titres codées en dur et divergentes : `CleanPage` utilise `FontSize="32"` et
  `"30"`, `PlaceholderPage` `"24"`, alors que `PageTitleStyle` vaut 28 et `MetricValueStyle`
  28. Trois « tailles de titre » concurrentes.
- `FontSize="14"` / `"16"` dispersés au lieu de `BodyStrongTextBlockStyle` /
  `SubtitleTextBlockStyle`.
- Les boutons-vignettes de l'accueil utilisent un `Padding` inline sans style de bouton
  partagé → ils ne s'harmonisent pas avec les autres boutons.

**Recommandation** — bannir les `FontSize` inline dans les vues ; router chaque texte vers un
style nommé. Créer un `TileButtonStyle` (padding, coin, hover, taille de titre) pour les 4
vignettes. Aligner `MetricValueStyle` et `PageTitleStyle` sur une seule échelle typographique
(ex. Titre 28 / Section 20 / Corps 14 / Légende 12).

### 2.3 Couleurs & thèmes

**Constat le plus sérieux — thème HighContrast partiellement câblé :**

- `App.xaml` ne déclare que les `ThemeDictionaries` **Light** et **Dark**. Le HighContrast
  est ajouté manuellement en overlay par `WinUiThemeManager` (`Donaby.HighContrast.xaml`).
- `Donaby.HighContrast.xaml` **omet plusieurs clés** présentes en Light/Dark :
  `AppBg`, `ContentBg`, `SidebarBg`, `AppBackgroundBrush`, `SidebarBackgroundBrush`,
  ainsi que `SystemAccentColorLight1..3` / `SystemAccentColorDark1..3`.
- `AccentGradient` est un `LinearGradientBrush` en Light/Dark mais un `SolidColorBrush` en
  HighContrast → tout binding supposant un dégradé se comporte différemment.

En mode contraste élevé, les contrôles qui référencent ces clés manquantes retombent sur les
valeurs du thème sous-jacent (accent violet), ce qui casse la cohérence « navy » du HC.

**Autres points :**

- Redondance de brosses pour une même couleur : en Light, `PrimaryBlue`, `AccentBlue`,
  `AccentBrush`, `TextAccent` valent tous `#534AB7`. Quatre alias = risque de dérive.
- Plusieurs couleurs « avertissement » cohabitent : `WarningBrush`, `AlertGold`, `RiskMinor`.
- Couleur brute codée en dur dans le code-behind : `OverviewPage.UpdateRecommendations`
  utilise `Microsoft.UI.Colors.DodgerBlue` au lieu d'une brosse de thème.

**Recommandation** — (a) compléter `Donaby.HighContrast.xaml` avec **toutes** les clés des
autres thèmes (mêmes noms, mêmes types — garder `AccentGradient` en dégradé même si les
stops sont identiques) ; (b) réduire les alias d'accent à une seule clé canonique
(`AccentBrush`) + les variantes système ; (c) un seul jeu sémantique
`Success / Warning / Danger / Info` et remplacer `DodgerBlue` par la brosse `Info`.

### 2.4 Onglets & états

**Constat :**

- `MainTabs` (TabView) utilise le style WinUI par défaut, sans état sélectionné personnalisé —
  cohérent mais neutre. Le bug de focus d'onglet (§1) est désormais corrigé.
- `FilterChipStyle` (ToggleButton) définit un fond « non coché » mais **aucun visuel d'état
  coché explicite** → la puce sélectionnée dépend du rendu par défaut, contraste faible sur
  certains thèmes.
- Les clés `SidebarActiveItem` / `SidebarIndicator` / `SidebarTextActive` sont définies mais
  la `NavigationView` applique sa propre sélection par défaut : ces clés semblent **inutilisées**,
  donc l'état actif de la barre latérale n'est pas harmonisé avec l'accent du thème.

**Recommandation** — ajouter un visuel d'état `Checked` explicite à `FilterChipStyle` (fond =
`AccentTintBrush`, texte = `AccentBrush`, ou inverse). Décider : soit surcharger les
`ThemeResource` de sélection de la `NavigationView` avec `SidebarActiveItem`/`SidebarIndicator`,
soit supprimer ces clés mortes pour éviter la confusion.

---

## 3. Ordre de priorité proposé

1. **Fait** — câblage des vignettes (Signatures + Scan).
2. Compléter les clés manquantes du thème HighContrast (correction, faible risque).
3. Introduire l'échelle d'espacement + supprimer les paddings de page inline.
4. Router les `FontSize` inline vers les styles ; créer `TileButtonStyle`.
5. Rationaliser les brosses (accent unique, jeu sémantique) + retirer `DodgerBlue`.
6. État `Checked` des puces + décision sur les clés de sélection de la sidebar.

---

## 4. Mise en œuvre — 2026-09-25

Points 2 à 6 appliqués. Rien n'a été compilé côté Linux : **build + passe visuelle à faire sous
Windows** (clair, sombre, contraste renforcé, preset + couleur d'accent perso).

### Thèmes (§2.3)

- *(Septembre 2026 : jeu porté à **21 clés** — surfaces `AppBackgroundBrush`, `SidebarBackgroundBrush`,
  `CardBackgroundBrush`, `CardAltBackgroundBrush`, `CardBorderBrush`, `WarningTintBrush`, `DangerBrush`
  réintroduites pour l'Accueil puis généralisées à toutes les cartes.)*
- `Donaby.Light/Dark/HighContrast.xaml` réduits aux **14 brosses réellement utilisées** (WinUI +
  `optiSCAN.Application`), jeu identique dans les trois fichiers. `SystemAccentColor` et ses variantes
  `Light1..3` / `Dark1..3` ne sont plus en XAML (avertissement **WMC0001** « Unknown type 'Color' »,
  bloquant en Release) : `WinUiThemeManager` les injecte par code, dérivées de l'accent courant. Contrôle :
  `pwsh -File scripts/check-winui-theme-keys.ps1`.
- Clés mortes supprimées : `AppBg`, `SidebarBg`, `ContentBg`, `CardBg*`, `Border*`, `PrimaryBlue`,
  `AccentBlue`, `AccentBg`, `SuccessBg`, `AlertGold`, `Text{Dark,Medium,Muted,Secondary}`,
  `Sidebar*` (décision §2.4 : la `NavigationView` garde sa sélection native, qui suit
  `SystemAccentColor`), `AccentGradient`, `HeroHalo*`, `*BackgroundBrush`, `CardBorderBrush`.
- Accent canonique : `AccentBrush` (`TextAccent` conservé comme alias, utilisé par
  `ActivityEntry.IconBrushKey`). Jeu sémantique : `SuccessGreen` / `WarningBrush` / `DangerRed` /
  **`InfoBrush`** (nouveau). `DodgerBlue` remplacé par `InfoBrush` dans `OverviewPage`.

### Contraste renforcé & accent — bugs corrigés dans `WinUiThemeManager`

- L'overlay HC était fusionné à la racine d'`App.Resources`, où il pouvait être masqué par
  `ThemeDictionaries`. Il est désormais fusionné **en dernier dans le dictionnaire « Light »**, et le
  contraste renforcé force le thème clair (palette HC pensée sur fond blanc — avant, navy sur fond sombre).
- La couleur d'accent perso / preset était écrite à la racine et **écrasait le navy du HC**. Elle est
  maintenant écrite dans chaque dictionnaire de thème ; en HC, l'accent navy est imposé.
- Les surcharges étaient appliquées **après** le changement de thème (donc non prises en compte avant le
  changement suivant). Ordre corrigé + aller-retour de thème (`RefreshThemeResources`) après HC / preset /
  couleur perso.
- Nouveau `WinUiThemeManager.GetBrush(key)` : le code-behind (`OverviewPage`, `MainWindow`, pied de page,
  `ThreatRiskBrushConverter`) lisait `Application.Current.Resources[key]`, qui suit le thème **de
  Windows** et non celui choisi dans l'app. *(Septembre 2026 : insuffisant — le pinceau restait figé
  après une bascule ; remplacé par la propriété attachée `ThemeBrush`, convertisseur supprimé.)*

### Espacements & typographie (§2.1, §2.2)

- Échelle complétée (`SpacingXXS` = 2) ; tous les `Spacing` / `RowSpacing` / `ColumnSpacing` des vues
  passent par `{StaticResource Spacing*}`. Normalisation : 10 → 12 (piles verticales) ou 8 (horizontales),
  14 → 12, 6 → 8, 1 → 2.
- `PagePadding` (32,20,32,16) partagé par `PageScrollViewerStyle` et les grilles racines
  d'Antivirus / Historique / Placeholder ; `TabContentPadding` pour les `0,8,0,0` répétés.
- Plus aucun `FontSize` inline sur du texte : `PlaceholderPage` → `PageTitleStyle` /
  `PageSubtitleStyle`, en-tête du volet → `SectionTitleStyle`, badge ClamAV → `NavBadgeTextStyle`.
  *(Septembre 2026 : exceptions réapparues avec le « lifting » — hero de l'Accueil (26 / 36, identité
  de marque), textes 12–14 px des cartes de l'Accueil et libellés du volet (10–11 px). À router vers
  `MutedCaptionStyle` / `NavBadgeTextStyle` lors d'une prochaine passe.)*
- `TileButtonStyle` / `TileTitleStyle` / `TileSubtitleStyle` pour les 4 vignettes de l'accueil
  (coins 8 alignés sur les cartes, hauteur mini commune).

### Puces de filtre (§2.4)

- L'état coché de `FilterChipStyle` reste celui du template WinUI (fond accent + texte sur accent) :
  contraste garanti dans tous les thèmes, y compris HC. Documenté dans le style.

### Reste à faire

- ~~`Services/WinUiThemeColors.cs` non utilisé~~ — supprimé (passe de septembre 2026).
- `ActivityEntry.IconBrushKey` renvoie `WarningOrange`, clé inexistante en WinUI (non utilisée par les
  vues WinUI aujourd'hui).

---

## 5. Refonte du panneau Antivirus — 2026-09-25

Seul panneau jugé à réorganiser (Accueil, Optimiser, Historique et Options conservés).

**Avant** : colonne « Outils » fixe de 220 px (récents + statistiques en texte brut), rangée de 4 boutons
hétérogènes, `TabView` à onglets fermables, actions de ligne en lettres (`VT` / `Q` / `I` / `X`, `↩` / `X`).
**Bug** : le bouton *Interrompre* vivait dans la zone des lanceurs, masquée pendant l'analyse — impossible
d'arrêter un scan depuis ce panneau.

**Après** (`Views/AntivirusPage.xaml`) :

| Zone | Contenu |
|------|---------|
| En-tête | Pastille bouclier, titre, état de protection · dernière analyse ; 3 cartes statistiques (Analysés, Menaces, Quarantaine) |
| Action (repos) | 4 vignettes icône + sous-titre (Rapide en accent, Complète, Dossier, Fichier) ; cibles récentes en puces |
| Action (scan) | Carte de progression accent + bouton **Interrompre** (correctif du bug) |
| Sections | `SelectorBar` : Analyse · Quarantaine (N) · Signatures |
| Analyse | En-tête « Menaces (N) » + *Tout mettre en quarantaine* ; liste en carte ; état vide « système propre » |
| Quarantaine | Liste en carte, pagination, *Vider* ; état vide dédié |
| Signatures | Cartes ClamAV / YARA avec pastille, boutons à icône, journal `LogConsoleBorderStyle` sélectionnable |

- Actions de ligne en boutons-icônes (`RowIconButtonStyle`) ; infobulle **et** nom d'accessibilité traduits via
  la propriété attachée `LocalizedTip.Key` (`Services/LocalizedTip.cs`).
- Adaptatif (< 760 px) : vignettes 2×2, statistiques sous le titre, cartes Signatures empilées.
- 9 nouvelles chaînes FR/EN : `Av_QuickSub`, `Av_FullSub`, `Av_FolderTile`, `Av_FolderSub`, `Av_FileTile`,
  `Av_FileSub`, `Av_ResultsTitle`, `Av_QuarantineEmpty`, `Av_QuarantineEmptySub`.

---

## 6. Correctifs fonctionnels — 2026-09-30

Fonctions visibles mais inopérantes (ou qui plantaient) dans `optiSCAN.WinUI`. Rien n'a été compilé côté
Linux : **build Release + test manuel sous Windows** à faire.

| Zone | Symptôme | Correctif |
|------|----------|-----------|
| Historique → Exporter HTML / PDF | L'application se figeait (FileSavePicker attendu en synchrone sur le thread UI) | `WinUiNativeDialogs.PickSaveFile` (IFileDialog Win32, synchrone) |
| Antivirus → Dossier / Fichier, Options → Parcourir | Échec des pickers WinRT quand l'app est relancée en administrateur | `WinUiNativeDialogs.PickFolder` / `PickFile` |
| Options → Langue, Accueil → Exécuter en admin | L'app disparaissait : la nouvelle instance voyait le mutex encore pris et quittait | Argument `--restart` : la nouvelle instance attend le mutex ; fermeture propre (`MainWindow.ExitApplication`) |
| Accueil → note de sécurité « Corriger » | Toujours refusé (page créée avant les services, confirmation nulle) | Page d'accueil créée à la fin d'`InitializeShell` |
| Accueil → « Mettre à jour maintenant » | Naviguait seulement | Lance la mise à jour (comme la vignette) |
| Antivirus → onglet Analyse | Plus de bascule automatique après une première navigation (désabonnement à `Unloaded` sans réabonnement) | Réabonnement à `Loaded` ; journal des signatures conservé hors de la page |
| Antivirus → liste des menaces | Liste périmée (reconstruite sur le seul nombre d'éléments) ; « Tout mettre en quarantaine » laissait les lignes | Reconstruction sur `CollectionChanged` ; menaces isolées retirées |
| Antivirus → quarantaine / récents, Historique | Liaisons `{Binding}` par réflexion | `x:Bind` typé (`QuarantineEntry`, `RecentScanTarget`, `ActivityEntry`, `HistoryThreatRow`) |
| Historique → actions de ligne | Boutons « Q / Q / D / I / X » sans infobulle ; suppression sans confirmation | Boutons-icônes + infobulles ; confirmation avant suppression / quarantaine groupée |
| Options → heure de l'analyse planifiée | Choix ignoré (toujours 02:00) | `ScheduleTime_SelectionChanged` |
| Options → Retirer une exclusion | Libellé via ressource injectée au runtime (introuvable selon l'ordre) | Libellé posé au `Loaded` |
| Options → Ajouter une exclusion | Chemin invalide ignoré en silence, saisie jamais vidée | Avertissement + saisie vidée |
| Thème | Case « thème alternatif » désynchronisée du bouton du volet | `OptionsViewModel.RefreshThemeState` + abonnement `ThemeChanged` |
| Démarrage | VM « provisoires » en double (2ᵉ `AntivirusViewModel` abonnée aux MAJ) ; init hors thread UI | VM créées paresseusement ; plus de `ConfigureAwait(false)` dans l'init |
| Robustesse | Toute exception dans une commande async / un clic fermait l'app | Filet dans `AsyncRelayCommand` + `UnhandledException.Handled = true` (journalisé) |
| Ressources | `Rtp_ThreatToastTitle`, `Overview_ProtectedSub` absentes (clé brute affichée) | Ajoutées FR/EN |

Sauvegarde de l'état avant correctifs : `git show refs/backup/avant-correctifs-claude` (fichiers suivis).

---

## Passe contraste & cohérence (septembre 2026)

Après le « lifting » de l'Accueil, vérification systématique des couleurs de texte dans les deux thèmes
(ratios WCAG calculés sur chaque fond de carte) et des espacements.

**Lisibilité**

- Pastilles de risque en **sombre** : texte blanc sur fonds pastel (rose, jaune, vert clair) — ratio 1,3 à
  2:1, illisible. `TextOnPrimary` sombre = `#1B1B1B` (≥ 8:1). Ordre visuel des niveaux rétabli
  (rouge → orange → ambre/jaune → vert) dans les deux thèmes.
- Couleurs posées par code **figées** sur le thème du moment (`Foreground = GetBrush(...)`,
  `ThreatRiskBrushConverter` via `x:Bind`) : après une bascule clair ↔ sombre, recommandations,
  posture, statut plateforme, pied de page et pastilles gardaient les couleurs de l'autre thème.
  Nouvelle propriété attachée `ThemeBrush` (réapplication sur `ActualThemeChanged` et changement
  d'accent) ; le convertisseur est supprimé.
- Badge ClamAV du volet : il prenait la variante claire alors que le volet était forcé en sombre (vert foncé sur noir). `ThemeBrush` résout selon le thème de l'élément. Le volet suit désormais le thème de la fenêtre.
- Thème clair : `WarningBrush` / `RiskMinor` (#BA7517, 3,2:1), `TextMutedBrush` (#8A8A8A, 3,0:1) et
  `SuccessGreen` (4,4:1) remontés au-dessus de 4,5:1 ; dates et tailles en `TextFillColorTertiary` (≈ 3:1)
  passées en `MutedCaptionStyle`.
- Accents : preset Donaby sombre (#7B6FE8, 3,5:1) → #9F97F0 ; Midnight / Ocean sombres éclaircis ;
  couleur perso **ajustée automatiquement** à 4,5:1 ; `AccentTintBrush` dérivé du preset (restait violet
  avec Ocean / Ember).
- Icônes de l'Accueil en dur (#2563EB, #7C3AED) → jetons `InfoBrush` / `SuccessGreen` ; textes du volet
  en dur (#94A3B8) → `TextFillColorSecondaryBrush`.
- Barre de titre système alignée sur le thème de l'app.

**Proportions & espacements**

- Une seule carte (`AppCardStyle`, surfaces Donaby opaques) pour toutes les pages : les pages
  Antivirus / Optimiser / Historique / Options utilisaient les surfaces système semi-transparentes (bordure
  quasi invisible en sombre), l'Accueil les surfaces Donaby.
- Accueil : gouttière `PagePadding` comme les autres pages (au lieu de 24,14,24,10), écarts de 12,
  vignettes au gabarit `TileButtonStyle` (icône 20, titre + sous-titre) identique au panneau Antivirus,
  encarts `InsetPanelStyle` (rayon 6 dans une carte de rayon 8), titres en `SectionTitleStyle`.
- Pastilles de risque identiques dans Antivirus et Historique (`RiskPillStyle`).
- Listes de cases (Options, Tweaks) : écart de 4 entre cases, 12 sous le titre ; barres d'actions en
  `ToolbarCardStyle` ; puces de filtre non cochées visibles (fond de carte + bordure).
- Unité « j » des seuils traduite (`Opt_Days`).

