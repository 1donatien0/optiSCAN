# Procédure de signature de code — optiSCAN

**État : 15 octobre 2026 — v3.1 candidate.** optiSCAN est un logiciel libre (GNU GPL v3 ou ultérieure). Une seule chaîne de signature existe : **SignPath Foundation**, qui signe gratuitement les projets open source acceptés. L'ancienne chaîne par certificat PFX (`codesign.ps1`, `sign-publish-artifacts.ps1`, `dev-codesign.ps1`, secrets `CODESIGN_*`, option `-CertSubject`) est retirée.

## Licence et signature : deux choses distinctes

- La **licence GPL v3** dit ce que chacun a le droit de faire du code. Elle est en place (`LICENSE.txt`).
- La **signature Authenticode** prouve qu'un binaire vient bien du projet. Elle est apposée par un certificat délivré par une autorité, ici celui de SignPath Foundation, sur des binaires compilés par GitHub Actions.

Tant que SignPath n'a pas accepté le projet et qu'aucun tag de release n'a été poussé, **aucun binaire n'est signé**. La chaîne est prête ; elle produit sa première signature à la première release approuvée.

## Ce qui est signé

Voir la [politique de signature](CODE_SIGNING_POLICY.md) : `optiSCAN.exe`, `optiSCAN.Service.exe`, `optiSCAN.Host.exe` et leurs DLL (`optiSCAN.dll`, `optiSCAN.Service.dll`, `optiSCAN.Host.dll`, `optiSCAN.Engine.dll`, `optiSCAN.Platform.dll`), le fournisseur AMSI `optiSCAN.AmsiProvider.dll`, puis l'installeur `optiSCAN_Setup_vX.Y.Z.exe`. Le désinstalleur Inno, enfermé dans l'installeur à la compilation, n'est pas signé : Inno ne le signe que si `signtool` est disponible pendant la compilation, ce que la chaîne SignPath exclut.

Les moteurs tiers ne passent pas par cette chaîne : archive ClamAV vérifiée par signature GPG Talos et SHA-256, YARA par SHA-256 épinglé. Le fournisseur AMSI (C++, `native/optiSCAN.AmsiProvider`) est livré et signé avec les binaires ; `release.yml` refuse une release sans lui. **Le minifiltre n'est pas livré** (prototype sous `native/`, hors v3.1) : l'installeur se contente de décharger une ancienne instance.

## Mise en place (une seule fois)

### Étape 1 — Committer et pousser la candidate

Tout le travail de la v3.1 est dans l'arbre de travail : le committer sur `dev` (découpage du [plan de release](../RELEASE_PLAN_v3.1.md#1-préparer-lhistorique-git-local)), vérifier la CI, puis fusionner dans `main`.

### Étape 2 — Purger l'historique (303 Mo, audit R15)

L'historique contient d'anciens installeurs et les binaires ClamAV/YARA (dont UnRAR). Sur une copie fraîche, jamais sur le dossier de travail :

```powershell
git clone --mirror https://github.com/1donatien0/optiSCAN.git optiSCAN-sauvegarde.git   # sauvegarde intacte
pip install git-filter-repo
git clone https://github.com/1donatien0/optiSCAN.git optiSCAN-propre
cd optiSCAN-propre
git filter-repo --invert-paths --path installer/output `
  --path-glob 'optiSCAN/clamav/*/*.exe' --path-glob 'optiSCAN/clamav/*/*.dll' `
  --path-glob 'optiSCAN/yara/*.exe'
git count-objects -vH                                  # vérifier la taille
git remote add origin https://github.com/1donatien0/optiSCAN.git
git push --force --all origin; git push --force --tags origin
```

Puis recloner le dépôt sur chaque poste : les anciens clones ne doivent plus être poussés.

### Étape 3 — Rendre le dépôt public

GitHub > dépôt > *Settings* > *General* > *Danger Zone* > *Change repository visibility* > *Public*. Activer l'authentification à deux facteurs du compte GitHub (exigence SignPath). La GPL v3 impose aussi que le code source soit disponible dès qu'on distribue les binaires : le dépôt public le satisfait.

### Étape 4 — Publier une première version non signée

SignPath Foundation exige un projet déjà publié. Récupérer l'installeur produit par la CI (artefact `optiSCAN-win-x64-<sha>` ou installeur du job *Publish*), créer une release GitHub `v3.1.0-beta.1` marquée *pre-release*, et y mettre le lien vers la [politique de signature](CODE_SIGNING_POLICY.md) (la page de téléchargement doit la citer).

### Étape 5 — Candidater

Formulaire : <https://signpath.org/apply>. Indiquer : dépôt GitHub public, licence GPL-3.0-or-later, build GitHub Actions (`.github/workflows/release.yml`), lien de la politique de signature, mainteneur et approbateur (Dona By). Signaler d'emblée UnRAR (livré par ClamAV, licence non libre ; on peut livrer ClamAV sans `libclamunrar`) et les licences par règle de YARA-Forge (audit R16). Attendre la réponse. Fait le 15 octobre 2026 ; SignPath a demandé que tous les composants tiers respectent ses exigences de licence, UnRAR a donc été retiré le 16 octobre 2026.

### Étape 6 — Configurer SignPath après acceptation

Dans l'interface SignPath (connexion avec double authentification) :

1. Ajouter le système de build de confiance *GitHub.com* à l'organisation et le lier au projet.
2. Installer l'application GitHub de SignPath et lui donner accès au dépôt `optiSCAN`.
3. Projet `optiSCAN` : créer les configurations d'artefacts `binaries` et `installer` en collant le contenu de [`.signpath/artifact-configurations/`](../.signpath/artifact-configurations).
4. Politiques de signature `test-signing` puis `release-signing` (approbateur : Dona By).
5. Créer un utilisateur CI avec le rôle de soumetteur et générer son jeton d'API.

### Étape 7 — Renseigner GitHub

*Settings* > *Secrets and variables* > *Actions* :

| Type | Nom | Valeur |
|---|---|---|
| Secret | `SIGNPATH_API_TOKEN` | Jeton de l'utilisateur CI SignPath |
| Variable | `SIGNPATH_ORGANIZATION_ID` | Identifiant de l'organisation SignPath |
| Variable | `SIGNPATH_PROJECT_SLUG` | `optiSCAN` |
| Variable | `SIGNPATH_SIGNING_POLICY` | `test-signing` pour le premier essai, puis `release-signing` |

### Étape 8 — Essai avec la politique de test

Lancer *Actions* > *Release — Build, sign (SignPath) & draft* > *Run workflow* sur `main`, approuver la demande dans SignPath, vérifier que le brouillon contient un installeur signé (certificat de test). Supprimer ce brouillon.

## Publier une release signée

1. Passer `SIGNPATH_SIGNING_POLICY` à `release-signing`, mettre à jour `<Version>` dans `Directory.Build.props`.
2. Pousser le tag `vX.Y.Z` correspondant sur `main` (`git tag v3.1.0` puis `git push origin v3.1.0`).
3. [`release.yml`](../.github/workflows/release.yml) compile, teste, publie, envoie les binaires à SignPath, attend l'**approbation manuelle** de l'approbateur, vérifie les signatures, compile l'installeur, le fait signer, calcule les empreintes et crée un brouillon de release.
4. Relire le brouillon et le publier.
5. Soumettre les binaires signés à Microsoft comme faux positif (Defender détectait `optiSCAN.exe` non signé), puis retirer l'exclusion du dossier d'installation (audit R1, R6).

## Vérification manuelle

```powershell
Get-AuthenticodeSignature .\optiSCAN.exe | Format-List Status, SignerCertificate
signtool verify /v /pa .\optiSCAN_Setup_v3.1.0.exe
```

## Références

- [`docs/CODE_SIGNING_POLICY.md`](CODE_SIGNING_POLICY.md) — politique publiée (exigée par SignPath Foundation)
- [`.github/workflows/release.yml`](../.github/workflows/release.yml) — chaîne de release signée
- [`.signpath/artifact-configurations/`](../.signpath/artifact-configurations) — fichiers signés et noms de produit attendus
- [`SECURITY.md`](../SECURITY.md) — posture et chaîne d'approvisionnement
