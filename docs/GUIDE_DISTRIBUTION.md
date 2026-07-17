# Guide de distribution — optiSCAN

Ce guide couvre la mise en production d'optiSCAN chez des utilisateurs tiers : **signature de code**, **cohabitation avec d'autres antivirus** et **chaîne de publication**. Il complète l'[audit v9.0](../Audit.md) et le [diagnostic d'intégration](DIAGNOSTIC_INTEGRATION_WINDOWS.md) (profil install **allégé façon v8**, deux moteurs ClamAV + YARA — pas un clone ClamWin).

---

## 1. Signature de code (obligatoire pour une diffusion sérieuse)

### 1.1 Exécutable & installeur — Authenticode

Sans signature, SmartScreen affiche « éditeur inconnu » et beaucoup de produits de sécurité bloquent l'installeur.

- **Certificat** : un certificat **Code Signing OV** suffit techniquement ; un **EV** (sur token matériel) supprime l'écran SmartScreen plus vite (réputation immédiate). Fournisseurs : DigiCert, Sectigo, GlobalSign. Piste gratuite OSS : SignPath Foundation (voir le diagnostic d'intégration).
- **Signer l'exe publié** (intégré au script `scripts/publish-release.ps1` via `-CertSubject`) :

  ```powershell
  signtool sign /n "Dona By" /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 optiSCAN.exe
  ```

- **Signer l'installeur Inno** : configurer un *Sign Tool* nommé `signtool` (Tools > Configure Sign Tools…) puis décommenter dans `installer/setup.iss` :

  ```
  SignTool=signtool $f
  SignedUninstaller=yes
  ```

### 1.2 Pilote minifiltre — signature noyau (non contournable)

Sur **Windows 10/11 x64**, un pilote non signé **ne se charge pas** (Driver Signature Enforcement). Ce n'est pas optionnel.

- Le pilote doit être signé via le **portail Microsoft Hardware Dev Center** (compte développeur matériel + certificat EV) :
  - soit **Attestation signing** (plus simple, pas de tests HLK) — suffisant pour un minifiltre,
  - soit **WHQL** (tests HLK complets) si certification complète souhaitée.
- L'installeur n'avertit plus systématiquement si le `.sys` est absent (profil allégé) ; sans signature, le pilote ne se charge pas sous Windows x64.

### 1.3 Fournisseur AMSI

`optiSCAN.AmsiProvider.dll` (chargé en-process par les applications analysées) doit aussi être **signé** pour être accepté par AMSI, et enregistré sous `HKLM\SOFTWARE\Microsoft\AMSI\Providers` (déjà géré par le code, nécessite l'élévation).

---

## 2. Cohabitation avec d'autres antivirus

optiSCAN (hooks de processus, RTP, minifiltre, quarantaine) a le profil comportemental d'un logiciel qu'un autre AV peut considérer comme suspect.

- **Risque concret** : un **Kaspersky / Bitdefender / Avast** (très répandus en Europe) peut **mettre en quarantaine ou terminer** `optiSCAN.exe` — symptôme « se lance quelques secondes puis disparaît ».
- **Mesures** :
  1. **Signer** tous les binaires (réduit fortement les faux positifs).
  2. Documenter pour l'utilisateur comment **ajouter une exclusion** dans son AV existant (dossier d'installation + `optiSCAN.exe`, `optiSCAN.Service.exe`).
  3. Tester optiSCAN sur des postes équipés de Kaspersky/Bitdefender/Defender **avant** diffusion.
  4. Côté Defender, le projet gère déjà l'ajout d'exclusions (`scripts/add-defender-exclusions.ps1`).
- **Avertissement** : faire tourner **deux moteurs temps réel** simultanément peut dégrader les performances et provoquer des conflits de verrous. Le recommander uniquement en complément (scan à la demande), pas comme second RTP permanent. Voir aussi [SECURITY.md](../SECURITY.md).

---

## 3. Dépendance au runtime .NET

Publication en **framework-dependent** **win-x64 uniquement** (`ArchitecturesAllowed=x64compatible` dans `setup.iss`). L'utilisateur doit avoir le **.NET 8 Desktop Runtime x64**.

Comportement de l'installeur (`installer/setup.iss`) si le runtime manque :

1. **Runtime embarqué** (optionnel) : si `installer/redist/windowsdesktop-runtime-win-x64.exe` est présent au build, il est extrait et installé en local (`/quiet /norestart`) — fonctionne hors-ligne. Voir [installer/redist/LISEZMOI.md](../installer/redist/LISEZMOI.md).
2. **Sinon** : téléchargement automatique depuis le lien officiel Microsoft `aka.ms/dotnet/8.0/windowsdesktop-runtime-win-x64.exe`, puis installation silencieuse.
3. **Secours** (hors-ligne / échec téléchargement) : proposition d'ouvrir la page de téléchargement manuelle.

Pour une expérience « zéro dépendance » ou un package plus léger :

| Option | Commande / mécanisme | Effet |
|--------|----------------------|--------|
| Self-contained | `scripts\publish-release.ps1 -SelfContained` | Runtime dans le publish (installeur plus lourd) |
| Redist Inno | Placer l'exe dans `installer/redist/` | Hors-ligne sans self-contained |
| Installeur léger (défaut) | `scripts\publish-release.ps1` | Sans bases ClamAV ni règles YARA ; MAJ au 1er lancement |
| Offline (tout) | `-EmbedOfflineSignatures` | CVD ClamAV + règles YARA embarqués |
| Offline ClamAV seul | `-EmbedClamAvDatabase` | ~105 Mo CVD |
| Offline YARA seul | `-EmbedYaraRules` | fichiers `.yar` |

---

## 4. Chaîne de publication fiable

L'UI de publication de Visual Studio s'est révélée peu fiable ici. Préférer les scripts :

```powershell
# Chaîne complète v9 (recommandé)
.\scripts\prepare-release-v9.ps1

# Ou : publish + signature + Inno
.\scripts\publish-release.ps1
.\scripts\publish-release.ps1 -CertSubject "Dona By"
.\scripts\publish-release.ps1 -EmbedOfflineSignatures   # bases ClamAV + règles YARA dans le setup

# Publish déjà fait → Inno seul
.\installer\build-release-setup.ps1 -SkipPublish
```

Le script `publish-release.ps1` : désactive le watchdog, ferme les instances qui verrouillent les fichiers, nettoie `publish\`, publie, signe (si certificat), puis compile l'installeur Inno. Sortie typique : `installer\output\optiSCAN_Setup_v9.0.0.exe`.

Le publish WPF recopie aussi les assets disque (`optiSCAN.ico`, hero, shield) via la cible MSBuild `CopyEmbeddedAssetsToPublish` — nécessaires au systray, à `verify-runtime-deps` et à Inno.

---

## 5. Checklist avant release

- [ ] Code committé et build CI vert (tests + CodeQL + gitleaks).
- [ ] Pilote minifiltre **signé** (attestation/WHQL) et présent — ou absent du setup si non signé (voir diagnostic).
- [ ] `optiSCAN.AmsiProvider.dll` **signé** et présent — ou absent du setup si non signé.
- [ ] `optiSCAN.exe` et installeur **signés** Authenticode.
- [ ] Runtime .NET 8 géré (auto-download, redist, ou self-contained).
- [ ] Assets publish présents (`optiSCAN.ico`, hero, shield) — `verify-runtime-deps.ps1`.
- [ ] Testé sur poste vierge + poste avec Kaspersky/Defender.
- [ ] Politique de confidentialité accessible ([POLITIQUE_CONFIDENTIALITE.md](POLITIQUE_CONFIDENTIALITE.md) ; à exposer aussi dans l'app / site).
- [ ] Numéro de version cohérent (`Directory.Build.props`, `LICENSE.txt`, Inno, README) — **v9.0 / 9.0.0**.
