# Diagnostic — Intégration Windows (optiSCAN v3.0)

> Date : 2026-07-16 · **Mission :** alléger le profil d’installation **façon version 2** (friction basse), tout en **conservant les gains de la version 3** et les **deux moteurs ClamAV + YARA**. Ce n’est pas un alignement produit sur ClamWin.

> **Mise à jour d'état — 29 octobre 2026 :** ce diagnostic décrit la décision de juillet, pas l'état courant. Depuis la 3.1, le service de protection est **coché** à la première installation (R9) et le fournisseur **AMSI est livré** avec le service ; le minifiltre reste absent. Une mise à jour reconfigure le service existant. Les sections 3 à 5 ci-dessous sont historiques. Pour l'état courant de sécurité, de distribution et des données SYSTEM, voir [l'audit 360](../AUDIT_optiSCAN_360.md#5-registre-des-risques-ouverts) et le [guide de distribution](GUIDE_DISTRIBUTION.md).

---

## 1. Référence : setup de la version 2 (~86 Mo, non signé)

Le setup de la version 2 montrait qu’on pouvait diffuser **sans Authenticode** avec un package plus léger et moins de gestes « AV-like » à l’install. La signature reste absente en version 2 comme en version 3 — ce n’est donc pas le seul levier.

Ce qui a alourdi la friction après la version 2 :

| Régression | Effet |
|------------|--------|
| Exclusions Defender auto (`SW_HIDE`) à chaque install | Marqueur heuristique « tamper » |
| Service plateforme souvent coché par défaut | `sc.exe create` systématique |
| Livraison AMSI / `.sys` envisagée dans les builds antérieurs | Pénalité AV potentielle sans bénéfice en l'absence d'implémentation et de signature |
| Package ~134 Mo vs ~86 Mo | Plus d’abandons au téléchargement |

---

## 2. Ce qu’on conserve (gains de la version 3)

- **Deux moteurs** : ClamAV (clamd/clamscan + freshclam) **et** YARA (rules + binaire)
- x64 only (`ArchitecturesAllowed=x64compatible`)
- Publish autonome avec les scripts de release ; un publish manuel framework-dependent exige un runtime .NET déjà installé
- **Bases ClamAV et règles YARA non embarquées par défaut** — téléchargées après install via MAJ signatures (freshclam + asset YARA-Forge approuvé localement). Le téléchargement des règles échoue fermé si la release upstream `latest` ne correspond plus à la pin optiSCAN, jusqu'à publication d'une nouvelle empreinte approuvée. Offline : `/DEmbedOfflineSignatures` (ou `/DEmbedClamAvDatabase` / `/DEmbedYaraRules`)
- Binaire **yara64.exe** toujours dans le setup (moteur) ; seuls les `.yar` sont optionnels
- Exclusion des outils ClamAV développeur (~47 Mo)
- Même `AppId` / URL SourceForge (réputation continue)
- UI WPF, quarantaine, RTP locale user-mode, etc.

---

## 3. Profil d’install cible (allégé, façon version 2)

Défaut :

1. Application + moteurs ClamAV/YARA (binaires) + MAJ signatures (recommandé) — CVD / `.yar` en post-install
2. **Pas** de service plateforme (case décochée)
3. **Pas** d’exécution auto des exclusions Defender
4. AMSI / minifiltre : **absents** ; les prototypes ne sont pas compilés, livrés, enregistrés ou chargés

Optionnel (utilisateur coche) :

- Service Windows de protection (RTP, surveillance de processus, scan USB et IPC) si l'utilisateur coche la tâche
- Démarrage Windows, icône Bureau

---

## 4. État dans `installer/setup.iss`

| Point | Statut |
|-------|--------|
| `platformservice` → `unchecked` | Fait |
| Plus d’appel `RegisterDefenderExclusions` en post-install | Fait (script toujours copié pour opt-in app) |
| AMSI / `.sys` | Absents du produit et de l'installateur |
| Bases ClamAV / règles YARA post-install (défaut) | Fait |
| Publish .NET / x64 | Les scripts de release publient self-contained ; un publish manuel framework-dependent exige le runtime sur la machine et n'est pas vérifié par l'installeur |

---

## 5. Suite

- [x] Installeur : pas d’exclusions Defender auto ; service plateforme décoché ; AMSI/`.sys` absents
- [x] App : plus d’`EnsureOptiscanExclusions` au démarrage / onboarding — opt-in Options uniquement
- La signature passe uniquement par SignPath Foundation, sur un tag de release ; voir [`SIGNATURE_PROCEDURE.md`](SIGNATURE_PROCEDURE.md). Elle ne change pas le profil d'installation décrit ici.

---

**Conclusion historique :** la mission reste un profil x64 allégé avec deux moteurs et des signatures récupérées après installation. L'ancien objectif de livraison conditionnelle AMSI/`.sys` a été abandonné ; ces composants ne font pas partie de la version courante.
