# Diagnostic — Intégration Windows (optiSCAN v9.0)

> Date : 2026-07-16 · **Mission :** alléger le profil d’installation **façon v8** (friction basse), tout en **conservant les gains v9** et les **deux moteurs ClamAV + YARA**. Ce n’est pas un alignement produit sur ClamWin.

---

## 1. Référence : setup v8 (~86 Mo, non signé)

Le setup `optiSCAN_Setup_v8.0.0` montrait qu’on pouvait diffuser **sans Authenticode** avec un package plus léger et moins de gestes « AV-like » à l’install. La signature reste absente en v8 comme en v9 — ce n’est donc pas le seul levier.

Ce qui a alourdi la friction après v8 :

| Régression | Effet |
|------------|--------|
| Exclusions Defender auto (`SW_HIDE`) à chaque install | Marqueur heuristique « tamper » |
| Service plateforme souvent coché par défaut | `sc.exe create` systématique |
| Livraison AMSI / `.sys` non signés | Pénalité AV, zéro bénéfice (DSE / AMSI refuse) |
| Package ~134 Mo vs ~86 Mo | Plus d’abandons au téléchargement |

---

## 2. Ce qu’on conserve (gains v9)

- **Deux moteurs** : ClamAV (clamd/clamscan + freshclam) **et** YARA (rules + binaire)
- x64 only (`ArchitecturesAllowed=x64compatible`)
- Auto-install / redist optionnel du **.NET 8 Desktop Runtime**
- **Bases ClamAV et règles YARA non embarquées par défaut** — téléchargées après install via MAJ signatures (freshclam + YARA-Forge). Offline : `/DEmbedOfflineSignatures` (ou `/DEmbedClamAvDatabase` / `/DEmbedYaraRules`)
- Binaire **yara64.exe** toujours dans le setup (moteur) ; seuls les `.yar` sont optionnels
- Exclusion des outils ClamAV développeur (~47 Mo)
- Même `AppId` / URL SourceForge (réputation continue)
- UI WPF, quarantaine, RTP locale user-mode, etc.

---

## 3. Profil d’install cible (allégré v8)

Défaut :

1. Application + moteurs ClamAV/YARA (binaires) + MAJ signatures (recommandé) — CVD / `.yar` en post-install
2. **Pas** de service plateforme (case décochée)
3. **Pas** d’exécution auto des exclusions Defender
4. AMSI / minifiltre : **livrés s’ils existent** (comme v8, `skipifsourcedoesntexist`) — inopérants sans signature

Optionnel (utilisateur coche) :

- Service Windows de protection (RTP/AMSI/IPC) si `optiSCAN.Service.exe` est présent
- Démarrage Windows, icône Bureau

---

## 4. État dans `installer/setup.iss`

| Point | Statut |
|-------|--------|
| `platformservice` → `unchecked` | Fait |
| Plus d’appel `RegisterDefenderExclusions` en post-install | Fait (script toujours copié pour opt-in app) |
| AMSI / `.sys` si présents (comme v8) | Fait (`skipifsourcedoesntexist`) |
| Bases ClamAV / règles YARA post-install (défaut) | Fait |
| Auto-.NET / x64 | Conservé |

---

## 5. Suite

- [x] Installeur : pas d’exclusions Defender auto ; service plateforme décoché ; AMSI/`.sys` comme v8
- [x] App : plus d’`EnsureOptiscanExclusions` au démarrage / onboarding — opt-in Options uniquement
- SignPath / Authenticode quand éligible

---

**Conclusion :** la mission est **optiSCAN v9 allégé façon v8** — double moteur, signatures en MAJ, AMSI/`.sys` livrés s’ils existent — pas un clone ClamWin.
