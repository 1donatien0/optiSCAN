# Feuille de route — d'optiSCAN vers un OS libre

**Objectif final :** un système d'exploitation **libre**, dans l'esprit de Linux.
**Contrainte :** coût = 0 €. Tout l'outillage listé ici est gratuit et libre.
**Date :** 8 juillet 2026

---

## 0. La décision qui structure tout

« Faire un OS comme Linux » recouvre deux projets radicalement différents. Il faut trancher avant d'écrire une ligne de code.

| | **Voie A — Une distribution** | **Voie B — Un noyau from scratch** |
|---|---|---|
| Ce qu'on construit | Noyau Linux + userland GNU assemblés, configurés, marqués, avec une identité propre | Son propre noyau : amorçage, mémoire, ordonnanceur, pilotes, système de fichiers |
| Réalisable seul ? | **Oui** | Un noyau *jouet* oui ; un noyau *utilisable* non |
| Délai crédible | **2 à 6 mois** pour une distro qui tient la route | 6–12 mois pour « ça démarre et lance un shell » ; **des années** pour utilisable |
| Utilisable au quotidien | Oui, dès la v1 | Réalistement, jamais en solo |
| Exemples | Ubuntu, Mint, Kali, Tails, Qubes | Linux (1991, puis 20 000+ contributeurs) |
| Coût | 0 € | 0 € |

**Recommandation : voie A.** Ce n'est pas un renoncement — Kali, Tails et Qubes sont des distributions, et ce sont de vrais OS avec une vraie identité. Linux lui-même n'a de valeur que par son userland. Et surtout : la voie A capitalise directement sur ton expertise sécurité, là où la voie B repart de zéro dans un domaine (le noyau) sans rapport avec ce que tu as construit.

> La voie B reste excellente **comme projet d'apprentissage en parallèle** (osdev.org, écrire un noyau x86 minimal). Mais ce n'est pas le chemin vers un OS qu'on utilise.

---

## 1. Le point aveugle à régler tout de suite : la licence

**Il y a une contradiction dans le projet actuel.**

L'objectif est un OS **libre**. Or `LICENSE.txt` d'optiSCAN est un CLUF **propriétaire** : il accorde la gratuité d'usage, mais **interdit** la modification commerciale, l'intégration dans un produit commercial, la revente et le sous-licenciement.

**Gratuit ≠ libre.** Un logiciel libre garantit les 4 libertés (usage, étude, modification, redistribution y compris modifiée et commerciale). Le CLUF actuel en refuse plusieurs.

**Conséquence pratique :** une distribution Linux ne pourra **pas** intégrer optiSCAN dans ses dépôts principaux avec cette licence. Debian, Fedora et Arch rejetteraient le paquet.

**À faire :** relicencier optiSCAN en **GPLv3** (cohérent avec l'écosystème Linux et avec ClamAV, lui-même GPLv2) ou en **MIT/Apache-2.0** si tu veux une adoption plus large. Tu es l'unique auteur (« Dona By »), donc tu peux relicencier sans demander l'accord de contributeurs tiers — c'est le bon moment, avant d'en avoir.

Coût : 0 €. Effort : une heure. Impact : **bloquant** pour tout le reste.

---

## 2. L'escalier — 4 chantiers, chacun utile en soi

Chaque marche produit quelque chose d'exploitable immédiatement, et rapproche du but.

### Chantier 1 — Chaîne de signature en local (fait ✅)

**Pourquoi c'est la première marche :** ça débloque la distribution d'optiSCAN Windows *aujourd'hui*, et ça t'apprend la signature de code — compétence directement réutilisable pour signer les paquets `.deb`/`.rpm` et les images ISO de la future distro (avec GPG, gratuit).

- `scripts/dev-codesign.ps1` — certificat auto-signé + signature Authenticode complète, **0 €**.
- Le pipeline est écrit et testable ; le certificat payant ne devient nécessaire qu'à la diffusion tierce.

**Transposition Linux :** `gpg --gen-key` + `debsign`/`rpmsign` + `sha256sum` signés. Même logique, gratuit de bout en bout, et **sans le problème SmartScreen** — sous Linux, la confiance passe par les dépôts et GPG, pas par une AC payante. *C'est un vrai argument pour la voie Linux : le racket du certificat de signature n'existe pas.*

**Effort :** fait. **Coût :** 0 €.

---

### Chantier 2 — Environnement de développement Linux

**But :** savoir compiler et tester depuis Linux.

- Installer une distro de travail (Debian, Fedora ou Arch — gratuites).
- `dotnet` SDK existe nativement sous Linux : `optiSCAN.Platform` et une partie des 87 fichiers de tests compilent et tournent tels quels.
- Passer la CI GitHub Actions en `ubuntu-latest` pour les projets portables (déjà gratuit pour un dépôt public).

**Limite honnête :** le projet WPF (`optiSCAN`, ~23 900 lignes) **ne compilera pas** sous Linux. WPF est Windows-only. C'est attendu, pas un échec.

**Effort :** quelques jours. **Coût :** 0 €.

---

### Chantier 3 — Portage d'optiSCAN sous Linux

**C'est la marche décisive** : elle transforme un antivirus Windows en l'application phare de la future distro.

| Composant Windows | Remplacement Linux | Difficulté |
|---|---|---|
| **UI WPF** | **Avalonia UI** — XAML, très proche de WPF | 🟢 Faible : ta connaissance XAML se transfère presque directement |
| Moteur ClamAV | `libclamav` / `clamd` natif — déjà mieux supporté sous Linux que sous Windows | 🟢 Faible |
| YARA | `libyara` natif | 🟢 Faible |
| **DPAPI** (quarantaine, SecureStore) | Secret Service / `libsecret` (GNOME Keyring, KWallet), ou dérivation de clé par phrase de passe | 🟠 Moyenne : à reconcevoir, mais l'AES-256-GCM et le HMAC restent identiques |
| **Minifiltre noyau** | **fanotify** (temps réel, en espace utilisateur, dans le noyau standard) ou eBPF | 🟠 Moyenne — mais **bien plus simple que le minifiltre Windows** : pas de pilote à écrire, pas de certificat EV à acheter |
| **AMSI** | Pas d'équivalent direct ; fanotify couvre l'essentiel du besoin | 🟡 À repenser |
| Pipe nommé + ACL | Socket UNIX + permissions POSIX | 🟢 Faible |
| Coexistence Defender | Sans objet | ✅ Disparaît |

**Ce qui se transfère intact :** toute l'architecture (DI, coordinateurs), la logique d'orchestration des scans, le modèle de quarantaine chiffrée, la conception des exclusions, le design IPC, et les tests. C'est-à-dire **l'essentiel de la valeur** des 30 600 lignes.

**Bonus majeur :** sous Linux, le minifiltre — le composant le plus coûteux et le plus risqué du projet Windows (certificat EV, attestation Microsoft, pilote noyau à signer) — est remplacé par **fanotify, gratuit et intégré au noyau**. Le point le plus cher du plan d'action disparaît purement et simplement.

**Effort :** 3 à 6 mois à temps partiel. **Coût :** 0 €.

---

### Chantier 4 — La distribution

**But :** l'OS libre.

**Positionnement suggéré : une distribution axée sécurité**, avec optiSCAN-Linux préinstallé comme couche d'analyse. C'est cohérent avec tout ce que tu as construit, et c'est un créneau lisible (là où « une distro généraliste de plus » ne l'est pas).

**Outillage, tout gratuit :**

| Outil | Usage | Difficulté |
|---|---|---|
| **archiso** (Arch) | Construire une ISO live | 🟢 La plus simple pour démarrer |
| **live-build** (Debian) | Idem, base Debian — écosystème de paquets énorme | 🟢 |
| **Yocto / Buildroot** | Construction complète depuis les sources, contrôle total | 🔴 Complexe |
| **Linux From Scratch** | Pédagogique : comprendre chaque brique | 🟠 Long mais formateur |

**Étapes :**

1. Choisir la base (recommandé : **Debian live-build** — stabilité, paquets, documentation).
2. Empaqueter optiSCAN-Linux en `.deb`, signé GPG.
3. Composer l'image : sélection de paquets, thème, installateur (Calamares, libre).
4. Publier le dépôt de paquets (GitHub Pages ou GitLab, gratuits).
5. Licence : **GPLv3** sur l'ensemble, sources publiées → c'est ce qui rend l'OS réellement *libre*.

**Effort :** 2 à 6 mois après le chantier 3. **Coût :** 0 €.

---

## 3. Récapitulatif des coûts

| Chantier | Coût | Délai |
|---|:---:|---|
| 1 — Signature locale | **0 €** | Fait |
| 2 — Dev Linux | **0 €** | Quelques jours |
| 3 — Portage optiSCAN Linux | **0 €** | 3–6 mois |
| 4 — Distribution | **0 €** | 2–6 mois |
| **Total** | **0 €** | **~1 an à temps partiel** |

**À noter :** le certificat de signature Windows (200–700 €/an) **n'est jamais requis** sur ce chemin. Si l'avenir est Linux, l'unique dépense obligatoire du plan d'action initial disparaît. C'est l'argument économique le plus fort en faveur de cette direction.

---

## 4. Prochaine action concrète

Trois choses, dans cet ordre, toutes gratuites et rapides :

1. **Relicencier optiSCAN en GPLv3** — une heure, et ça débloque tout le reste (§1).
2. **Trancher voie A vs voie B** (§0) — recommandation : A.
3. **Prototyper l'UI en Avalonia** — reprendre une seule vue WPF existante et la porter. Ce test d'une journée dira si le portage est aussi fluide que prévu, avant d'engager des mois.

---

## 5. Ce que je ne te cacherai pas

- **Un OS libre solo, c'est réaliste en voie A, pas en voie B.** Kali et Tails sont partis de Debian, pas de zéro.
- **Le chantier 3 est le vrai test.** S'il aboutit, le chantier 4 est surtout de l'assemblage et de l'empaquetage. S'il cale, l'OS n'aura pas d'identité propre.
- **La licence est le point bloquant le plus sous-estimé.** Sans relicenciement, le projet ne peut pas être libre, quelle que soit la qualité du code.
- **Continuer à investir massivement dans le WPF Windows** est orthogonal à l'objectif. Il reste pertinent de finir la v9.0 pour la distribuer, mais chaque nouvelle fonctionnalité WPF est du code qui ne migrera pas.
