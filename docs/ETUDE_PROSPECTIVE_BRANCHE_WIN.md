# Étude prospective — branche `win` (édition WinUI 3)

_1er octobre 2026, relu le 14 octobre 2026. Observation du dépôt et d’une session d’usage réelle (publication, installateur, navigation Accueil → Antivirus). La relecture aligne le texte sur la branche : CI, runtime .NET 10, script de publication._

Ce texte décrit ce que la branche fait déjà, où le comportement et le rendu divergent, et quelles évolutions sont possibles. Ce n’est pas un engagement de livraison.

---

## 1. Position de la branche

`win` est l’édition WinUI 3 d’optiSCAN. Jusqu’à la v2, les commits sont ceux de `main` / `dev` (historique réécrit, courriel perso). Le `first commit` ouvre WinUI 3 ; la v3 WPF reste sur `main` / `dev`. Le nom de release **v1.0** (assembly **1.0.0**) est propre à WinUI.

| Fait | Conséquence |
|------|-------------|
| UI WPF retirée de `optiSCAN/` (assets seulement) | Cette branche est le produit, pas un prototype à côté de WPF. |
| `AppId` Inno distinct de l’édition WPF et d’optiCOMBAT | Les deux éditions peuvent cohabiter. Un passage transparent depuis WPF demanderait de reprendre l’`AppId` WPF. |
| CI déclenchée sur `main`, `dev` et `win` | Build Release et tests (`ci.yml`), CodeQL, gitleaks et dependency-review couvrent `win`. Le publish, le SBOM et l’installeur ne partent que sur `main`. |
| Protection plateforme (service, AMSI) **activable** ; minifiltre tenté | Service et AMSI s’installent. Windows x64 refuse un `.sys` non signé. SignPath plus tard (~1 an) pour la réputation puis l’attestation noyau. Repli : `FileSystemWatcher`. |
| Publication **framework-dependent** par défaut | L’installeur est léger ; .NET 10 Desktop et Windows App Runtime 1.8 sont téléchargés s’ils manquent. |

Le produit est déjà une application installable : `optiSCAN.exe` publié, puis `installer\output\optiSCAN_Setup_v1.0.0.exe`. La suite de l’évolution est une question de clarté, de fiabilité de la chaîne locale, et de ce qu’on choisit d’activer — pas de « finir l’application ».

---

## 2. Comportements observés

### 2.1 Les cinq panneaux tiennent

`NavigationView` + pages en cache. Les vignettes de l’accueil vont au bon panneau :

| Vignette | Navigation | Cible dans le panneau |
|----------|------------|------------------------|
| Nettoyer | Optimiser | — |
| Scanner (menu : rapide / complète) | lance l’analyse | l’analyse en cours ramène l’onglet Analyse |
| Scanner (choix manuel) | Antivirus | onglet Analyse |
| Historique | Historique | — |
| Mise à jour | Antivirus | onglet Signatures, puis lance la mise à jour |

Le lien « Mettre à jour maintenant » de la note de sécurité suit le même chemin que la vignette. Le câblage corrigé en septembre 2026 (`RequestFocusAntivirusSignaturesTab` branché dans `MainWindow`) est en place. **Le clic n’est pas mal branché.**

### 2.2 Antivirus : l’onglet actif se voit, le hub suit la section

`AntivirusPage` est empilée en quatre bandes, de haut en bas :

1. En-tête (état, dernière analyse, statistiques) — toujours visible.
2. Zone d’action (`ScanHubPanel`) — les quatre vignettes d’analyse (Rapide, Complète, Dossier, Fichier), **sur l’onglet Analyse seulement** ; pendant un scan, remplacées par la carte de progression.
3. `SelectorBar` : Analyse · Quarantaine · Signatures.
4. Un seul panneau de contenu : liste des menaces, quarantaine, ou cartes ClamAV / YARA + journal.

`ApplySectionVisibility` change la bande 4 et transmet la section à `UiPhaseVisibility.ApplyAntivirusScanPhase`, qui masque la bande 2 hors de l’onglet Analyse (hors scan en cours).

Le style WinUI 1.8 par défaut (`DefaultSelectorBarItemStyle`) ne marquait presque pas la section active : texte sélectionné de la même couleur que les autres (`TextFillColorPrimaryBrush`), fond transparent, seul repère un trait d’accent de 16 × 3 px. Il est remplacé sur cette page par un style local, `AntivirusSectionTabStyle` (`AntivirusPage.xaml`) :

- fond de l’onglet sélectionné en `AccentTintBrush` ;
- texte et icône en `AccentBrush`, en semi-gras ;
- trait d’accent de 3 px sur toute la largeur de l’onglet ;
- même rendu au survol et à l’appui de l’onglet sélectionné (le template WinUI, lui, perdait le fond au survol) ;
- états écrits en `Storyboard` : un `SelectedItem` posé depuis le code (vignette « Mise à jour », lien de la note de sécurité) déplace bien le repère. `ApplyRequestedSection` repose aussi `IsSelected` sur chaque onglet et rejoue la section au `Loaded`, la page étant mise en cache.

Comportement attendu : « Mettre à jour » ouvre Signatures, l’onglet Signatures est teinté et en gras, et les vignettes d’analyse ne sont plus affichées au-dessus. Le constat initial (« la page ressemble encore à Analyse ») venait d’un exécutable antérieur à ces changements ; **à revérifier sur un build publié à partir de la branche actuelle**, dans les trois thèmes (clair, sombre, contraste renforcé).

Écart restant : Optimiser utilise un `TabView` (Nettoyage / Mises à jour / Tweaks) et Antivirus un `SelectorBar` stylé. Les deux pages marquent désormais clairement leur section, mais pas avec le même langage visuel.

### 2.3 Ce qui est déjà solide

- Moteurs : ClamAV (clamd ou repli `clamscan`) et YARA en parallèle sur les scans interactifs ; USB en série avec timeouts.
- Quarantaine AES-256-GCM, périmètres protégés (`OptiscanProtectedPaths`), exclusions Defender au démarrage.
- Mode complémentaire Defender : si Defender fait le temps réel, optiSCAN ne le double pas, et la posture ne compte pas ça comme une protection dégradée.
- Thèmes Donaby clair / sombre / contraste renforcé, accent ajusté à 4,5:1, `ThemeBrush` pour ne pas figer les couleurs au changement de thème.
- 398 tests, 839 clés FR/EN, coordinateurs qui ont allégé `MainWindow`.
- Installeur Inno : moteurs, règles YARA, script d’exclusions. Les bases `.cvd` peuvent être absentes au moment du build (`AllowMissingSignatures`) : la mise à jour se fait au premier lancement.

### 2.4 Frottements de la chaîne locale

Observé en générant l’installeur sur cette machine :

- `scripts\publish-release.ps1` s’arrêtait sur `schtasks` (tâche `optiSCAN_Watchdog`, accès refusé) parce que `$ErrorActionPreference = 'Stop'` traitait la sortie d’erreur native comme un échec. `Invoke-OptionalScheduledTask` abaisse cette préférence le temps de l’appel : une tâche absente ou inaccessible n’interrompt plus la publication.
- `dotnet publish` du profil `FolderProfile`, puis `installer\build-release-setup.ps1 -SkipPublish`, produit bien `optiSCAN_Setup_v1.0.0.exe`.
- L’exécutable publié n’est pas signé : SmartScreen affiche « éditeur inconnu ». C’est le choix documenté de la phase 1, pas un oubli de build.

---

## 3. Ce que nous pouvons faire

Trois familles, par coût et par effet. A est réalisée (voir 2.2). En B, le script de publication et le build CI sur `win` le sont aussi ; il reste les bases ClamAV et l’installeur, qui ne sort que de `main`. C reste une piste.

### A. Rendre l’endroit où l’on est évident — réalisé

Le câblage est resté ; seule la lecture visuelle a changé (détail en 2.2).

| Piste | Statut |
|-------|--------|
| Texte et fond de l’item sélectionné en accent / teinte | Fait : `AntivirusSectionTabStyle` (fond `AccentTintBrush`, texte et icône `AccentBrush`, semi-gras), y compris au survol de l’onglet sélectionné |
| Trait de sélection plus long et plus épais | Fait : 3 px sur toute la largeur de l’onglet, via le template local (le `ScaleX` du template WinUI n’est plus utilisé) |
| Masquer ou réduire le hub d’analyse hors de l’onglet Analyse | Fait : `ScanHubPanel` masqué sur Quarantaine et Signatures. Décision prise : les vignettes ne servent plus de raccourci depuis ces sections |
| Titre de section dans le panneau Signatures | Non fait : facultatif maintenant que l’onglet se lit |

Reste à vérifier sur un build publié, dans les trois thèmes.

### B. Fiabiliser la publication sur `win`

| Piste | Statut |
|-------|--------|
| Ne pas faire échouer `publish-release.ps1` quand le watchdog n’est pas modifiable (compte non élevé, tâche absente) | Fait : `Invoke-OptionalScheduledTask` |
| Build Release et tests sur `win` | Fait : `ci.yml`, CodeQL, gitleaks et dependency-review. Le publish, le SBOM et l’installeur restent réservés à `main` |
| Bases ClamAV dans l’installeur, ou message explicite « première mise à jour au lancement » | Ouvert. L’installé scanne mieux si les `.cvd` sont déjà là ; sinon le premier lancement doit le dire clairement |

La signature Authenticode reste optionnelle en phase 1. La poser maintenant améliorerait SmartScreen ; elle n’est pas requise pour que ClamAV et YARA, déjà signés par leurs éditeurs, fonctionnent.

### C. Phase plateforme : ouverte sans le pilote noyau

*Mise à jour d’octobre 2026 : cette piste a été tranchée autrement que prévu au départ.* Service Windows et AMSI sont **activables** (`PlatformProtectionFeatureGate.IsUserActivatable = true`) : tâche cochée dans l’installeur, case active dans Options, et activés par défaut hors mode complémentaire Defender. Le minifiltre est enregistré et tenté, mais ne se charge pas sans signature Microsoft. Ce qui reste exclu : forcer le pilote non signé (test signing) chez l’utilisateur.

---

## 4. Évolution possible

Horizons alignés sur la stratégie déjà écrite (`docs/GUIDE_DISTRIBUTION.md`), plus ce que l’usage de cette session a montré.

### Maintenant — clarté d’usage

Le produit s’installe. Le prochain gain n’est pas une fonction nouvelle.

1. ~~Onglet actif lisible sur Antivirus~~ — fait (2.2). Aligner éventuellement le langage visuel avec le `TabView` d’Optimiser.
2. ~~Décision sur le hub d’analyse au-dessus de Quarantaine et Signatures~~ — tranché : masqué hors de l’onglet Analyse.
3. ~~Script de publication qui aboutit sans élévation quand le watchdog n’est pas accessible~~ — fait (`Invoke-OptionalScheduledTask`).
4. Vérification manuelle de l’installeur sur le poste : SmartScreen, runtimes manquants, première mise à jour des signatures — et rendu de l’onglet actif dans les trois thèmes.

### Cette année — branche tenue comme une release

1. ~~CI sur `win` (build Release et tests)~~ — fait. L’installeur de cette édition se produit encore en local, ou via le job publish de `main`.
2. Installeur testé sur une machine sans .NET 10 ni Windows App Runtime.
3. Cohabitation documentée et retestée avec Defender (mode complémentaire) et, si possible, un antivirus tiers.
4. Dette déjà nommée dans le README, sans la traiter comme un chantier unique : tests clamd / tâches planifiées réels, copie de quarantaine non chiffrée, scripts Tweaks écrits dans `%TEMP%` avant l’UAC, couverture du cœur encore sous la cible.

### Plus tard — seulement si le produit user-mode est stable chez des tiers

1. Certificat Authenticode (OV) pour l’exe et l’installeur, si SmartScreen devient le frein principal.
2. Reprise éventuelle de l’`AppId` WPF le jour où l’édition WinUI remplace l’édition WPF chez les mêmes utilisateurs.
3. SignPath (~1 an) : Authenticode de l’exe, de l’installeur et d’AMSI, puis attestation du minifiltre. D’ici là, `fltmc load` est tenté et le refus Windows est attendu.

---

## 5. Ce qu’il vaut mieux ne pas faire

- Rebrancher « Mettre à jour » vers un autre panneau : la cible Signatures est la bonne.
- Remplacer le `SelectorBar` par un autre contrôle seulement pour « réparer » un clic qui fonctionne. Le défaut est le repère visuel du template (texte identique, fond transparent, trait de 16×3 px), plus le hub d’analyse qui ne change pas de section.
- Activer le test signing (`bcdedit`) sur les machines des utilisateurs pour forcer le minifiltre non signé.
- Publier en self-contained par défaut : l’installeur gonfle (~75 Mo) alors que le chemin léger est déjà celui du produit.
- Prendre un publish local pour seule preuve que `win` tient : le build Release et les tests partent déjà sur cette branche. L’installeur, lui, ne sort que de `main` ou d’une publication locale.

---

## 6. Lecture courte

La branche `win` est une v1.0 installable, avec une UI déjà câblée et la couche plateforme posée (service, AMSI, tentative de minifiltre). Le malentendu « Mise à jour m’envoie sur Analyse » venait de l’apparence ; l’onglet actif est désormais marqué et le hub d’analyse ne s’affiche plus hors de l’onglet Analyse (à confirmer sur un build publié). Le build, les tests et le script de publication tiennent. La suite utile est de vérifier l’installeur sur une machine sans runtime .NET 10. Windows refusera le `.sys` non signé jusqu’à SignPath.
