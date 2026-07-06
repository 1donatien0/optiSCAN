# Guide de distribution — optiSCAN

Ce guide couvre la mise en production d'optiSCAN chez des utilisateurs tiers : **signature de code**, **cohabitation avec d'autres antivirus** et **chaîne de publication**. Il complète l'audit (`AUDIT_optiSCAN_360.md`).

---

## 1. Signature de code (obligatoire pour une diffusion sérieuse)

### 1.1 Exécutable & installeur — Authenticode

Sans signature, SmartScreen affiche « éditeur inconnu » et beaucoup de produits de sécurité bloquent l'installeur.

- **Certificat** : un certificat **Code Signing OV** suffit techniquement ; un **EV** (sur token matériel) supprime l'écran SmartScreen plus vite (réputation immédiate). Fournisseurs : DigiCert, Sectigo, GlobalSign.
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
- Sans cela, `optiSCAN.Minifilter.sys` est rejeté au chargement → pas de protection temps réel au niveau noyau. L'installeur avertit désormais l'utilisateur si le `.sys` est absent/non signé.

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
  4. Côté Defender, le projet gère déjà l'ajout d'exclusions (`add-defender-exclusions.ps1`).
- **Avertissement** : faire tourner **deux moteurs temps réel** simultanément peut dégrader les performances et provoquer des conflits de verrous. Le recommander uniquement en complément (scan à la demande), pas comme second RTP permanent.

---

## 3. Dépendance au runtime .NET

Publication en **framework-dependent** : l'utilisateur doit avoir le **.NET 8 Desktop Runtime x64**. L'installeur le **vérifie déjà** (`IsDotNet8Installed`) et redirige vers la page de téléchargement si absent.

Pour une expérience « zéro dépendance » sur poste vierge, deux options :

- publier en **self-contained** : `scripts\publish-release.ps1 -SelfContained` (installeur plus lourd, ~150 Mo) ;
- ou **bundler** le runtime dans l'installeur (téléchargement via Inno Download Plugin déjà présent sur la machine de build).

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

## 5. Checklist avant release

- [ ] Code committé et build CI vert (tests + CodeQL + gitleaks).
- [ ] Pilote minifiltre **signé** (attestation/WHQL) et présent.
- [ ] `optiSCAN.AmsiProvider.dll` **signé** et présent.
- [ ] `optiSCAN.exe` et installeur **signés** Authenticode.
- [ ] Runtime .NET 8 géré (vérif installeur ou self-contained).
- [ ] Testé sur poste vierge + poste avec Kaspersky/Defender.
- [ ] Politique de confidentialité publiée (voir `CONFORMITE_RGPD.md`).
- [ ] Numéro de version cohérent (`Directory.Build.props`, Inno, README).
