# Audit UI — lisibilité, mode sombre et uniformisation

**optiSCAN v7.0** — `Donaby.Light.xaml` / `Donaby.Dark.xaml` + styles `App.xaml` / `Controls.xaml`  
**Date** : audit statique du dépôt (XAML + thèmes + code-behind couleurs).

---

## 1. Lisibilité des textes par mode

### 1.1 Mécanisme global

| Couche | Rôle |
|--------|------|
| **Donaby.\*.xaml** | Tokens `TextDark`, `TextMuted`, fonds, accents |
| **ThemeManager** | Bascule clair/sombre + Material Design `BaseTheme` |
| **App.xaml** | Styles implicites `TextBox`, `ComboBox`, `TabItem`, `CheckBox` |
| **Controls.xaml** | `DonabyTabItem`, boutons, DataGrid |

**Corps de texte** : presque tout passe par `TextDark` (titre/corps) et `TextMuted` (sous-titres) → **bon contraste** sur `CardBg` / `ContentBg` dans les deux modes.

### 1.2 Éléments corrigés récemment (OK)

| Zone | Problème | État |
|------|----------|------|
| Options — ComboBox langue / scan favori | Texte noir sur fond sombre | Corrigé (`App.xaml` + `ItemTemplate`) |
| Antivirus — onglets Analyse / Quarantaine | `Foreground` local bloquait le blanc sur violet | Corrigé (`DonabyTabItem`) |
| Boutons Warning / Success / Danger | Texte peu visible | `TextOnPrimary` explicite |
| Historique — onglets | Style dédié souligné | `DonabyTabItemUnderline` |

### 1.3 Points encore sensibles

| Zone | Mode | Problème | Gravité |
|------|------|----------|---------|
| **Grille menaces — colonne Risque** | Les deux | Couleurs **hex fixes** (`RiskScoringService`, ex. `#F1C40F`) — pas de tokens thème | Moyen |
| **PDF export** | N/A | QuestPDF couleurs fixes (bleu/gris) | Faible (hors UI live) |
| **Reco Accueil — ligne neutre** | Les deux | Icône `SuccessGreen` + texte `TextMedium` (incohérent sémantiquement) | Faible |
| **CheckBox Material Design** | Sombre | `Foreground = TextSecondary` — en général OK ; surveiller cases sur `CardBg` très sombre | Faible |

### 1.4 Matrice lisibilité par écran

| Écran | Clair | Sombre | Commentaire |
|-------|-------|--------|-------------|
| Accueil | OK | OK | Recos : fond + `SuccessGreen` / `AlertGold` sur `SuccessBg` / `AlertBg` |
| Antivirus | OK | OK | Onglets + bandeau scan : préférer `AccentBlue` sur `AccentBg` (sombre) |
| Nettoyer | OK | OK | Carte violette : `TextOnPrimary` |
| Historique | OK | OK | Onglets soulignés + `TextDark` |
| Options | OK | OK | ComboBox thématisées |
| Navigation / footer | OK | OK | `SidebarTextActive`, `TextDark` statut |

---

## 2. Mode sombre — couleurs et textes

### 2.1 Tokens texte (référence)

| Token | Clair | Sombre | Usage |
|-------|-------|--------|--------|
| `TextDark` | `#1A1918` | `#F0EDE8` | Titres, corps principal |
| `TextMedium` | `#555550` | `#B0ADA6` | Libellés intermédiaires |
| `TextMuted` | `#999990` | `#8A8780` | Aide, sous-textes |
| `TextSecondary` | **= Medium** | **= Medium** | Alias (ComboBox, stats labels) |
| `TextOnPrimary` | `#FFFFFF` | `#FFFFFF` | Sur `PrimaryBlue` / boutons pleins |
| `TextAccent` | `#534AB7` | `#9F97F0` | Liens, YARA actif |

### 2.2 Accents (écart clair / sombre voulu)

| Token | Clair | Sombre | Note |
|-------|-------|--------|------|
| `PrimaryBlue` | `#534AB7` | `#534AB7` | Boutons, onglet sélectionné |
| `AccentBlue` | `#534AB7` | `#9F97F0` | **Plus clair en sombre** — icônes sur `AccentBg` |
| `AccentBg` | `#EEEDFE` | `#26215C` | Bandeaux, pastilles |
| `SuccessGreen` | `#1D9E75` | `#5DCAA5` | Statuts OK, sidebar ClamAV |
| `AlertGold` | `#BA7517` | `#EF9F27` | Alertes, texte sur fond clair |
| `AlertGoldLight` | `#EF9F27` | `#FAC775` | Titres de section (GÉNÉRAL…) |
| `WarningOrange` | `#854F0B` | `#EF9F27` | Bouton ambre — blanc lisible dans les deux cas |

### 2.3 Contraste mode sombre — verdict

- **Fonds + texte principal** : palette cohérente (gris chaud `#1A1917` / `#F0EDE8`).
- **Violet sur violet** : risque si `PrimaryBlue` est utilisé **sur** `AccentBg` → utiliser **`AccentBlue`** (correction appliquée sur bandeau scan + hub rapide).
- **Cartes recommandations** : `SuccessGreen` sur `SuccessBg` `#04342C` — bon contraste.
- **Sidebar** : `SuccessGreen` sur fond sombre — lisible ; pas confondre avec `AccentBlue` (lien actif).

---

## 3. Uniformisation des équivalents

### 3.1 Doublons de tokens (même rôle, deux noms)

| A | B | Recommandation |
|---|---|----------------|
| `TextSecondary` | `TextMedium` | **Même valeur** dans les deux thèmes. À terme : n’utiliser que `TextMedium` OU documenter `TextSecondary` comme alias (fait en commentaire dans les `.xaml` thème). |
| `PrimaryBlue` vs `AccentBlue` (clair) | Identiques `#534AB7` | Sur fond `AccentBg`, préférer **`AccentBlue`** partout (s’adapte en sombre). |
| `AlertGold` vs `AlertGoldLight` | Deux tons or | **Titres de section** : `AlertGoldLight` (Options, Nettoyer, Accueil cartes). **Texte dans encart alerte** : `AlertGold`. Antivirus `OUTILS` / `STATS` alignés sur `AlertGoldLight`. |

### 3.2 Patterns à suivre (charte)

| Contexte | Fond | Texte / icône |
|----------|------|----------------|
| Page / carte | `CardBg` | `TextDark` + `TextMuted` |
| Titre de section (GÉNÉRAL, OUTILS) | — | `AlertGoldLight` |
| Onglet sélectionné | `PrimaryBlue` | `TextOnPrimary` (+ `TabHeaderPackIcon`) |
| Onglet inactif | `HeaderBg` | `TextSecondary` / `TextMedium` |
| Bouton primaire | `PrimaryBlue` | `TextOnPrimary` |
| Bouton warning | `WarningOrange` | `TextOnPrimary` |
| Bandeau accent | `AccentBg` | `TextDark` + icônes **`AccentBlue`** |
| Champ saisi | `SurfaceBg` | `TextDark` |
| Liste déroulante | `SurfaceBg` | `TextDark` |

### 3.3 Écarts restants entre vues

| Élément | Vue A | Vue B | Action |
|---------|-------|-------|--------|
| Titre section | Options : `AlertGoldLight` | Antivirus OUTILS : était `AlertGold` | **Aligné → AlertGoldLight** |
| Icône sur `AccentBg` | — | Hub / scan : était `PrimaryBlue` | **Aligné → AccentBlue** |
| Stats antivirus labels | `TextSecondary` | Autres écrans : `TextMuted` | Acceptable (alias identique) |
| Valeurs stats | `PrimaryBlue` / `DangerRed` | — | OK (sémantique couleur) |

### 3.4 Hors thème Donaby (à traiter si uniformisation totale)

1. **`RiskScoringService.GetSeverityColor`** — hex WCAG non recalculés au changement de thème.  
   → Proposer tokens `RiskCritical`, `RiskMajor`, `RiskMinor`, `RiskInfo` dans les deux `.xaml` thème.

2. **`OverviewControl.xaml.cs`** — `ThemeUiBrushes` pour statuts dynamiques : **correct** (suit le thème).

3. **`MainWindow.xaml.cs`** — badge ClamAV `SuccessGreen` / `DangerRed` : **correct**.

---

## 4. Synthèse et priorités

| Priorité | Action |
|----------|--------|
| **P0** | Maintenir styles globaux TabItem + ComboBox (régressions fréquentes) |
| **P1** | Tokens risque dans les thèmes + converter vers `DynamicResource` |
| **P2** | Unifier `TextSecondary` → `TextMedium` dans le XAML (refactor large, faible gain) |
| **P2** | Reco Accueil neutre : icône `TextMedium` au lieu de `SuccessGreen` |
| **P3** | Rapports PDF bilingues / thème — hors scope UI live |

**Verdict global** : après les correctifs onglets/combos/boutons, l’UI est **globalement lisible** en clair et en sombre. Les principales **non-uniformités** sont sémantiques (`AlertGold` vs `AlertGoldLight`, `PrimaryBlue` vs `AccentBlue` sur fond accent) et la **colonne Risque** fixe.

---

## 5. Vérification manuelle recommandée

1. Basculer **Options → thème sombre / clair** (et redémarrer si changement de langue seulement).
2. Parcourir : Accueil → Antivirus (onglets + scan) → Options (combos) → Historique.
3. Vérifier : onglet **Analyse** (texte blanc sur violet), combos **Français / Analyse rapide**, bandeau scan en cours en **mode sombre**.

Fichiers de référence : `optiSCAN/Themes/Donaby.Light.xaml`, `Donaby.Dark.xaml`, `Styles/Controls.xaml`, `App.xaml`.
