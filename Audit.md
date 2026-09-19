# Audit complet — optiSCAN v9.0

**Date :** 8 juillet 2026
**Périmètre :** sécurité · qualité du code · conformité RGPD/légale · gratuité & accessibilité · build/CI-CD
**Méthode :** revue statique du dépôt `optiSCAN-stable` (revue de code, pas de pentest dynamique). ~30 600 lignes C# (projet principal ~23 900), 4 projets managés + 2 composants natifs (AMSI en C++, minifiltre en C), 87 fichiers de tests.
**Base de code auditée :** commit `589c353` — *Release v9.0.0*.
**Build actuel :** assembly **9.0.3** (`Directory.Build.props`).

> Le code natif (`.dll` AMSI, `.sys` minifiltre) n'est pas compilé par la CI ; seuls les sources ont été examinés. Le minifiltre est aujourd'hui un **squelette** non fonctionnel (voir §2).

> **Mise à jour doc (2026-07-16)** : CLUF aligné v9.0 (*R2*) ; politique rédigée dans `docs/POLITIQUE_CONFIDENTIALITE.md` (*R1* partiel) ; installeur x64 only + auto-install .NET documentés dans `docs/GUIDE_DISTRIBUTION.md`.
>
> **Mise à jour doc (2026-09-18)** : assembly **9.0.3** — Optimiser → Mises à jour : `winget upgrade --uninstall-previous` et nettoyage des versions empilées du même programme.

---

## 1. Résumé exécutif

optiSCAN est un antivirus Windows (WPF/.NET 8) **de bon niveau d'ingénierie** : architecture en couches avec injection de dépendances, coordinateurs, cryptographie correcte pour la quarantaine, IPC authentifié, moindre privilège par défaut, et une chaîne DevSecOps réelle (analyzers, CodeQL, gitleaks, dependency-review, SBOM, seuil de couverture). Le socle est sain et cohérent avec la documentation (`SECURITY.md`, `docs/CONFORMITE_RGPD.md`, `docs/POLITIQUE_CONFIDENTIALITE.md`, `docs/GUIDE_DISTRIBUTION.md`).

Les risques ne sont **pas** dans la conception mais dans quelques **durcissements ciblés** et surtout dans la **finalisation « prêt-pour-distribution »** (signature de code, publication de la politique de confidentialité, accessibilité complète).

### Notation synthétique

| Domaine | Note | Verdict |
|---|:---:|---|
| Sécurité applicative | 🟢 B+ | Crypto/IPC solides ; 2 durcissements moyens à faire |
| Qualité du code | 🟢 A− | Analyzers + warnings-as-errors + tests ; dette structurelle mineure |
| Conformité RGPD / légale | 🟡 B | Design respectueux ; travail **documentaire** restant |
| Gratuité & accessibilité | 🟡 B− | Gratuit et redistribuable ; accessibilité partielle |
| Build & CI/CD | 🟡 B | DevSecOps réelle ; **signature de code absente** |

### Constats prioritaires

1. **🔴 Signature de code absente** (installeur, `.exe`, `.dll` AMSI, pilote) — bloquant pour une diffusion tierce (SmartScreen, alertes AV, pilote non chargeable).
2. **🟠 Jeton d'arrêt IPC en clair dans `ProgramData`** — lisible par tout utilisateur authentifié → un utilisateur local peut arrêter le service de protection (déni de service).
3. **🟠 Pas de limitation de débit sur le pipe IPC** (`ScanPath`/`ScanBuffer`) accessible aux utilisateurs authentifiés → DoS local (déjà dans le backlog de durcissement).
4. **🟡 Politique de confidentialité rédigée mais non exposée** (app / site) — seul travail RGPD réellement restant.
5. **🟡 Accessibilité partielle** — `AutomationProperties` présents dans 4 vues sur 7.

---

## 2. Sécurité

### Points forts

- **Quarantaine chiffrée** : AES-256-GCM par fichier (chiffrement authentifié, en-tête `OPTQ` + nonce aléatoire unique + tag), clé maîtresse 256 bits enveloppée par **DPAPI (CurrentUser)**, manifeste signé **HMAC-SHA256** (un manifeste falsifié est rejeté). Aléa via `RandomNumberGenerator`. Aucun usage de MD5/SHA1/`new Random`/ECB dans le code sensible.
- **Moindre privilège** : l'app tourne en `asInvoker` (utilisateur standard) et ne demande l'élévation UAC que ponctuellement (`ElevationHelper`, liste blanche System32/Windows/Program Files). Amélioration nette par rapport aux versions antérieures qui tournaient en administrateur permanent.
- **IPC durci** : pipe nommé avec ACL explicite (SYSTEM/Administrateurs = FullControl, utilisateurs authentifiés = ReadWrite), plafond anti-DoS sur le buffer (96 Mo base64), refus des chemins sensibles (`QuarantineManager.IsSensitivePath`), jeton d'arrêt comparé en temps constant (`CryptographicOperations.FixedTimeEquals`).
- **Anti-zip-slip** : l'extraction YARA-Forge itère sur `entry.Name` (nom de fichier seul, sans composant de chemin) et filtre les `.yar` → pas de traversée de répertoire.
- **Pas de secret en dur** dans les sources ; la clé API VirusTotal est saisie par l'utilisateur et stockée via `SecureStore` (DPAPI + HMAC).
- **Auto-exclusion** : les répertoires d'install et `%LocalAppData%\optiSCAN` ne sont jamais scannés/mis en quarantaine (`OptiscanProtectedPaths`).

### Constats

| # | Sévérité | Constat | Recommandation |
|---|:---:|---|---|
| S1 | 🔴 Élevée (org.) | Aucun binaire signé (installeur, `optiSCAN.exe`, `optiSCAN.AmsiProvider.dll`, minifiltre). | Signer en Authenticode (EV pour le pilote). Bloquant pour diffusion tierce. Déjà listé dans le *hardening backlog*. |
| S2 | 🟠 Moyenne | Jeton d'arrêt IPC persisté **en clair** dans `%ProgramData%\optiSCAN\ipc_shutdown.token`. `ProgramData` est lisible par les utilisateurs authentifiés → n'importe quel utilisateur local peut lire le jeton et envoyer `Shutdown` (arrêt de la protection). | Restreindre l'ACL du fichier à SYSTEM + Administrateurs, ou dériver le jeton d'un secret DPAPI machine, ou n'autoriser `Shutdown` que depuis un appelant SYSTEM/admin. |
| S3 | 🟠 Moyenne | Pas de *rate-limiting* sur `ScanPath`/`ScanBuffer` ; le pipe est ouvert aux utilisateurs authentifiés. Un client local peut saturer le moteur (DoS). | Limiter le débit par client/temps ; envisager de restreindre le pipe aux seuls appelants nécessaires quand l'AMSI est désactivé. Déjà au backlog. |
| S4 | 🟡 Faible | Téléchargement des règles YARA-Forge : aucune vérification d'intégrité (hash/signature) au-delà de HTTPS + source GitHub. | Vérifier un hash/somme publié ou une signature du paquet avant extraction. |
| S5 | 🟡 Faible | ~52 blocs `catch { }` vides côté app (hors tests). La plupart sont du nettoyage « best effort », mais certains peuvent masquer des erreurs. | Journaliser au minimum en `Debug` ; réserver le silence aux cas réellement inoffensifs. |
| S6 | 🟡 Faible | ~69 binaires (moteur ClamAV, DLL) **versionnés dans git** alors que `.gitignore` les exclut (ajoutés avant le gitignore). Provenance non vérifiable dans l'historique + dépôt alourdi. | Retirer du suivi (`git rm --cached`), s'appuyer sur `scripts/fetch-runtime-deps.ps1` avec vérification de hash. |
| S7 | ℹ️ Info | Le minifiltre (`filter.c`) est un **squelette** : `DriverEntry` enregistre un filtre sans callbacks réels (`IRP_MJ_CREATE` tout à NULL). Non fonctionnel. | Cohérent avec `SECURITY.md` (« ne pas activer sans pilote signé »). À implémenter + signer avant toute activation. |

Le point AMSI est correctement conçu en « présent mais inactif » (inerte tant que non enregistré sous `HKLM\...\AMSI\Providers`), ce qui limite la surface d'attaque par défaut.

---

## 3. Qualité du code

### Points forts

- **Discipline de compilation** : `Directory.Build.props` active `EnableNETAnalyzers`, `AnalysisLevel=latest-recommended`, `Nullable`, `ImplicitUsings`, et **`TreatWarningsAsErrors` en Release** avec `Microsoft.CodeAnalysis.NetAnalyzers`. Rare et très sain.
- **Architecture** : composition par DI (`Microsoft.Extensions.DependencyInjection`), ~22 coordinateurs qui sortent l'orchestration du code-behind (bon pour la testabilité), découplage vues↔fenêtre par bus d'événements.
- **Tests** : 87 fichiers de tests, couverture mesurée (cobertura) avec **plancher + cible progressive** appliqués en CI.
- **Hygiène** : 1 seul `TODO` dans tout le code applicatif ; commentaires en français qui expliquent le *pourquoi*.

### Constats

| # | Sévérité | Constat | Recommandation |
|---|:---:|---|---|
| Q1 | 🟡 Faible | `Services/` concentre ~107 fichiers dans un seul projet — surface large, frontières implicites. | Modulariser (moteurs / quarantaine / mises à jour / plateforme-RTP / IPC). |
| Q2 | 🟡 Faible | `ServiceContainer` cumule façade + bus + cycle de vie (tendance *god object*). | Surveiller ; scinder si le couplage augmente. |
| Q3 | 🟡 Faible | 16 `async void` (hors tests). Inévitable pour certains *handlers* WPF, mais chaque occurrence est un risque d'exception non observée. | Confirmer que chacun est bien un *event handler* et enveloppé d'un try/catch. |
| Q4 | 🟡 Faible | `TOUT.md` (~1,5 Mo, export automatique du code) et `README.md` (~65 Ko) versionnés → dépôt alourdi, README difficile à maintenir. | Sortir `TOUT.md` du suivi ; scinder le README (garder l'essentiel, déplacer le détail dans `docs/`). |

---

## 4. Conformité RGPD & légale

### Points forts

- **Local par défaut** : historique, quarantaine (chiffrée), préférences et journaux restent sur le poste. Journaux **caviardés** (`PathRedaction`) et **rétention 30 jours** (rotation auto).
- **Seul envoi externe = opt-in** : VirusTotal reçoit uniquement le **hash SHA-256** (jamais le fichier), et seulement si l'utilisateur a saisi **sa propre clé API**. `docs/CONFORMITE_RGPD.md` documente précisément les traitements.
- **Minimisation** et **droit à l'effacement** (purge à la désinstallation) déjà en place.

### Constats

| # | Sévérité | Constat | Recommandation |
|---|:---:|---|---|
| R1 | 🟡 Moyenne | Politique rédigée dans `docs/POLITIQUE_CONFIDENTIALITE.md`, mais **pas encore exposée** dans l'app ni sur le site de distribution. | Afficher / lier la politique (Options, setup, page SourceForge / release). |
| R2 | ✅ Corrigé | ~~`LICENSE.txt` en v8.0~~ — aligné sur **v9.0 — 2026**. | — |
| R3 | ℹ️ Info | Le transfert de hash vers VirusTotal (US) doit être mentionné explicitement si la fonction est activée. | Lien vers la politique VirusTotal + mention « désactivé par défaut ». |

Verdict RGPD : **design respectueux de la vie privée**, conforme dans l'esprit ; il manque la formalisation publiée.

---

## 5. Gratuité & accessibilité

### Gratuité

Le CLUF (`LICENSE.txt`) accorde une **licence gratuite d'utilisation** et autorise la **redistribution gratuite à des tiers** ; le logiciel est explicitement qualifié de « logiciel gratuit ». Il **interdit** en revanche la revente, la location, le sous-licenciement et l'intégration dans un produit commercial.

- ✅ **Gratuit pour l'utilisateur final** et redistribuable — l'objectif « appli gratuite et accessible » est rempli côté coût.
- ⚠️ **Freeware propriétaire, pas open-source** : les restrictions (usage commercial, modification/rétro-ingénierie probablement encadrées) empêchent de le qualifier de « libre ». À clarifier si l'ambition est une diffusion communautaire/open-source.

### Accessibilité

| # | Sévérité | Constat | Recommandation |
|---|:---:|---|---|
| A1 | 🟢 Fort | Thème **contraste élevé** présent (`Donaby.HighContrast.xaml`) en plus de clair/sombre ; service de raccourcis clavier (`KeyboardShortcuts`). | — |
| A2 | 🟡 Moyenne | `AutomationProperties` présents dans **4 vues sur 7** seulement → couverture lecteur d'écran incomplète. | Ajouter noms/descriptions d'automatisation à toutes les vues et contrôles interactifs. |
| A3 | 🟡 Faible | Ratios de contraste (WCAG AA), ordre de tabulation et visibilité du focus non vérifiés dans cet audit statique. | Vérifier avec Accessibility Insights / Narrateur ; viser WCAG 2.1 AA. |

---

## 6. Build & CI/CD

### Points forts

- **CI complète** (`ci.yml`) : restore → build Release (warnings-as-errors) → tests → couverture avec **plancher + cible**.
- **DevSecOps réelle** : CodeQL (C# **et** natif), Dependabot (NuGet + Actions, hebdo), `dependency-review` (échec en sévérité *high*), **gitleaks**, SBOM CycloneDX.
- Actions épinglées à des versions majeures récentes ; permissions GitHub restreintes (`contents: read`).

### Constats

| # | Sévérité | Constat | Recommandation |
|---|:---:|---|---|
| B1 | 🔴 Élevée (org.) | **Aucune étape de signature** dans la CI (voir S1). | Ajouter la signature Authenticode au packaging release. |
| B2 | 🟡 Faible | Le minifiltre et l'AMSI natifs ne sont **pas compilés en CI** (WDK/MSVC hors pipeline `dotnet`). | Ajouter un job MSBuild/WDK, au moins pour l'AMSI, avec CodeQL natif déjà présent. |
| B3 | 🟡 Faible | La publication finale dépend d'Inno Setup exécuté localement (`installer/`). | Automatiser la génération du setup en CI pour la reproductibilité. |
| B4 | ℹ️ Info | `PrivilegesRequired=admin` dans `setup.iss` — attendu pour un installeur AV (exclusions Defender, chemins Program Files). | RAS. |

---

## 7. Plan d'action recommandé (par priorité)

1. **Signer** installeur + exécutables + AMSI (Authenticode), pilote en EV avant toute activation — *S1/B1*.
2. **Protéger le jeton d'arrêt IPC** (ACL SYSTEM/Admins ou dérivation DPAPI machine) — *S2*.
3. **Limiter le débit** des opérations IPC exposées aux utilisateurs authentifiés — *S3*.
4. **Exposer** la politique de confidentialité (app + site) — *R1* (CLUF déjà en v9.0 — *R2* fait).
5. **Compléter l'accessibilité** (`AutomationProperties` sur toutes les vues, vérif. WCAG AA) — *A2/A3*.
6. **Hygiène du dépôt** : sortir binaires ClamAV et `TOUT.md` du suivi git, vérifier l'intégrité des téléchargements YARA — *S6/Q4/S4*.
7. **CI native** : compiler/signer AMSI (et minifiltre à terme) + génération automatisée du setup — *B2/B3*.

---

*Audit statique du dépôt à date du 8 juillet 2026. Une revue dynamique (pentest local, fuzzing du canal IPC, tests d'accessibilité au lecteur d'écran) est recommandée pour compléter avant une diffusion large.*
