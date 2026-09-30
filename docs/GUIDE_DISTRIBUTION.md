# Guide de distribution — optiSCAN

Ce guide couvre la mise en production d'optiSCAN chez des utilisateurs tiers : **signature de code**, **cohabitation avec d'autres antivirus** et **chaîne de publication**. Il complète la synthèse d'audit du [README §12](../README.md#12-audit-et-qualité-de-lédition-winui).

---

## 0. Stratégie de distribution par phases (petit éditeur → croissance)

Le pilote noyau est la partie la plus coûteuse à signer (certificat **EV** + compte **Partner Center**). Il n'est **pas nécessaire** pour distribuer optiSCAN : l'app fonctionne sans lui.

### Phase 1 — maintenant (service + AMSI, sans budget signature)
- **Couche plateforme activable** (`PlatformProtectionFeatureGate.IsUserActivatable = true`). L'installeur pose le service `optiSCANProtection` et enregistre AMSI si la tâche est cochée (défaut au premier install). Hors mode complémentaire Defender, les préférences activent le service.
- **Repli user-mode** via `FileSystemWatcher` si le service n'est pas joignable — aucun pilote requis.
- **Minifiltre** : embarqué ; l'installateur et le service enregistrent le service noyau `optiSCANMinifilter` et son instance (altitude provisoire `385210`), puis tentent `fltmc load`. `pnputil` n'est appelé que si un catalogue signé `.cat` accompagne l'INF. Windows x64 **refuse** un `.sys` non signé ; l'installateur n'échoue pas pour autant. Ne pas activer le test signing chez l'utilisateur.
- Le scan à la demande / planifié (ClamAV + YARA), la quarantaine et l'historique fonctionnent pleinement.
- **Publication framework-dependent** par défaut (`scripts\publish-release.ps1`, profil `FolderProfile`) : installateur léger ; `setup.iss` télécharge et installe .NET 10 Desktop Runtime + Windows App Runtime 1.8 s'ils manquent.
- **Moteurs ClamAV / YARA** : binaires officiels **déjà signés** par leurs éditeurs. optiSCAN ne les re-signe pas.
- **optiSCAN.exe / installeur / AMSI** : signature Authenticode **non posée** en phase 1 (SmartScreen « éditeur inconnu » ; voir §1). SignPath est prévu dans **environ un an**, le temps de bâtir une réputation.

### Phase 2 — SignPath (~1 an)
- Signer l'exe, l'installeur et `optiSCAN.AmsiProvider.dll` (Authenticode).
- Ensuite seulement : certificat **EV** + **Partner Center** pour attester le minifiltre (voir `SIGNATURE_PROCEDURE.md`).
- Une fois le `.sys` + `.cat` signés, `fltmc load` doit réussir sur x64.

> Conséquence concrète : le service et AMSI sont déjà dans le produit livré. Seul le chargement noyau attend SignPath. La protection temps réel de l'application reste le repli.

---

## 1. Signature : moteurs vs coquille optiSCAN

### 1.0 Ce qui est déjà signé (et suffit pour scanner)

| Composant | Signé par | Rôle |
|-----------|-----------|------|
| `clamscan.exe`, `freshclam.exe`, `clamd.exe` | **Cisco / Talos** | Moteur antivirus |
| `yara64.exe` | Builds YARA officiels | Moteur de règles |
| Bases `.cvd` / règles `.yar` | Intégrité TLS + contrôles optiSCAN | Données |

optiSCAN **orchestre** ces binaires. Leur signature prouve qu'ils viennent du fournisseur attendu. **Signer optiSCAN n'est pas requis** pour qu'ils s'exécutent.

Les exclusions Windows Defender servent à la **cohabitation** (perf, faux positifs sur bases/quarantaine), pas parce que les moteurs seraient illégitimes.

### 1.1 Exécutable & installeur optiSCAN — Authenticode **optionnel** (phase 1)

Signer `optiSCAN.exe` et l'installeur atteste **votre** éditeur (SmartScreen, politiques d'entreprise). Ce n'est **pas** obligatoire pour un produit gratuit dont les moteurs sont déjà signés.

Sans certificat : `scripts/sign-publish-artifacts.ps1` et la CI ignorent l'étape (`SIGN_CERT_SUBJECT` vide).

Si vous signez plus tard (OV ~200–350 $/an) :

- **Exe** — `scripts/publish-release.ps1 -CertSubject "Dona By"` ou `scripts/sign-publish-artifacts.ps1`
- **Installeur Inno** — *Sign Tool* `signtool` dans Inno Setup, puis dans `installer/setup.iss` :

  ```
  SignTool=signtool $f
  SignedUninstaller=yes
  ```

### 1.2 Pilote minifiltre — signature noyau (phase 2 uniquement)

Sur **Windows 10/11 x64**, un pilote non signé **ne se charge pas** (Driver Signature Enforcement). Ce n'est pas optionnel.

- Le pilote doit être signé via le **portail Microsoft Hardware Dev Center** (compte développeur matériel + certificat EV) :
  - soit **Attestation signing** (plus simple, pas de tests HLK) — suffisant pour un minifiltre,
  - soit **WHQL** (tests HLK complets) si certification complète souhaitée.
- Sans cela, `optiSCAN.Minifilter.sys` est rejeté au chargement → pas de protection temps réel au niveau noyau. L'installateur n'affiche pas d'avertissement : l'échec est seulement journalisé (`PlatformRegistration`), et le service + AMSI restent actifs.
- Avant la soumission : demander une **altitude** à Microsoft et la reporter dans l'INF, `PlatformRegistration.MinifilterAltitude` et `installer/setup.iss` (test `MinifilterRegistrationConsistencyTests`).

### 1.3 Fournisseur AMSI

`optiSCAN.AmsiProvider.dll` (chargé en-process par les applications analysées) doit aussi être **signé** pour être accepté par AMSI, et enregistré sous `HKLM\SOFTWARE\Microsoft\AMSI\Providers` (déjà géré par le code, nécessite l'élévation).

---

## 2. Cohabitation avec d'autres antivirus

optiSCAN (hooks de processus, RTP, minifiltre, quarantaine) a le profil comportemental d'un logiciel qu'un autre AV peut considérer comme suspect.

- **Risque concret** : un **Kaspersky / Bitdefender / Avast** (très répandus en Europe) peut **mettre en quarantaine ou terminer** `optiSCAN.exe` — symptôme « se lance quelques secondes puis disparaît ».
- **Mesures** :
  1. Documenter pour l'utilisateur comment **ajouter une exclusion** dans son AV existant (dossier d'installation + `optiSCAN.exe`, `optiSCAN.Service.exe`).
  2. Tester optiSCAN sur des postes équipés de Kaspersky/Bitdefender/Defender **avant** diffusion.
  3. Côté Defender, l'application ajoute ses exclusions **au démarrage** (`WindowsDefenderExclusionService`, UAC au plus 1× / 24 h) ; `scripts\add-defender-exclusions.ps1` pour le faire à la main. L'installeur ne les pose pas.
  4. Signature optiSCAN **facultative** — réduit SmartScreen, pas requise pour les moteurs Clam/YARA déjà signés.
- **Avertissement** : faire tourner **deux moteurs temps réel** simultanément peut dégrader les performances et provoquer des conflits de verrous. Le recommander uniquement en complément (scan à la demande), pas comme second RTP permanent.
- **Déjà en place avec Defender** : sur une nouvelle installation où Defender est actif, optiSCAN démarre en **mode complémentaire** (`DefenderCoexistenceService`) — Defender garde le temps réel, optiSCAN coupe sa RTP et la surveillance des processus ; l'utilisateur peut repasser en protection optiSCAN complète dans Options. Le badge et la posture ne comptent pas ce choix comme une protection dégradée ([README §5](../README.md#defendercoexistenceservice-mode-complémentaire-windows-defender)).

---

## 3. Dépendance au runtime .NET

Publication en **framework-dependent** (défaut) : l'application a besoin du **.NET 10 Desktop Runtime** et du **Windows App Runtime 1.8**. L'installeur les **détecte** (`IsDotNet10DesktopInstalled`, `IsWindowsAppRuntimeInstalled`) et, s'ils manquent, les **télécharge** (redistribuables officiels Microsoft, page de téléchargement Inno 6.1+) puis les installe silencieusement.

Pour une installation hors ligne sur poste vierge : publier en **self-contained** — `scripts\publish-release.ps1 -SelfContained` (profil `FolderProfile-SelfContained`, .NET + Windows App SDK embarqués, installeur plus lourd).

---

## 4. Chaîne de publication fiable

L'UI de publication de Visual Studio s'est révélée peu fiable ici. Utiliser le script :

```powershell
# Publication simple
pwsh -File scripts\publish-release.ps1

# Publication + signature + installeur
pwsh -File scripts\publish-release.ps1 -CertSubject "Dona By"
```

Le script : désactive le watchdog, ferme les instances qui verrouillent les fichiers, nettoie `publish\`, publie, signe (si certificat), puis compile l'installeur Inno.

---

## 5. Checklist avant release (phase 1 — service + AMSI, sans SignPath)

- [ ] Code committé et build CI vert (tests + CodeQL + gitleaks).
- [ ] Publication **framework-dependent** par défaut (`scripts\publish-release.ps1`) — installateur testé sur une VM **sans** .NET 10 ni Windows App Runtime.
- [ ] Installeur Inno compilé ; SHA-256 du setup publié sur la release GitHub / SourceForge.
- [ ] Section **Installation** : SmartScreen « éditeur inconnu » → Exécuter quand même ; FAQ exclusions antivirus.
- [ ] `docs/CONFORMITE_RGPD.md` à jour (VirusTotal = hash uniquement, opt-in clé API).
- [ ] Testé sur poste vierge + poste avec Defender (idéalement un AV tiers).
- [ ] Numéro de version cohérent (`Directory.Build.props`, Inno, README).
- [ ] Couche plateforme activable (`PlatformProtectionFeatureGate.IsUserActivatable = true`) — service `optiSCANProtection` + AMSI si la tâche est cochée ; `fltmc load` tenté, refus Windows attendu sans signature.

### Phase 2 (SignPath, ~1 an)

- [ ] `optiSCAN.exe` et installeur **signés** Authenticode.
- [ ] `optiSCAN.AmsiProvider.dll` **signé**.
- [ ] Plus tard : pilote minifiltre **signé** (attestation/WHQL) et `fltmc load` réussi sur x64.
