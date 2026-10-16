# Politique de signature du code — optiSCAN

Free code signing provided by [SignPath.io](https://about.signpath.io/), certificate by [SignPath Foundation](https://signpath.org/).

*Signature de code gratuite fournie par SignPath.io, certificat de la SignPath Foundation.*

## Ce qui est signé

Seuls les fichiers produits par la compilation automatisée de ce dépôt sont signés, à partir de la branche `main` et d'un tag `vX.Y.Z` :

- `optiSCAN.exe`, `optiSCAN.Service.exe`, `optiSCAN.Host.exe`, `optiSCAN.dll`, `optiSCAN.Service.dll`, `optiSCAN.Host.dll`, `optiSCAN.Engine.dll`, `optiSCAN.Platform.dll`, `optiSCAN.AmsiProvider.dll` ;
- l'installeur `optiSCAN_Setup_vX.Y.Z.exe`.

Les binaires tiers livrés tels que publiés par leurs projets (ClamAV, YARA, runtime .NET) ne sont pas signés par optiSCAN ; leur origine est vérifiée par empreinte SHA-256 et, pour ClamAV, par la signature GPG de Cisco-Talos (voir [SECURITY.md](../SECURITY.md)).

La compilation est faite par GitHub Actions ([`.github/workflows/release.yml`](../.github/workflows/release.yml)). Chaque demande de signature est approuvée manuellement avant d'être exécutée. Les métadonnées de produit et de version sont fixées par [`Directory.Build.props`](../Directory.Build.props) pour tous les projets ; la configuration d'artefact ([`.signpath/`](../.signpath/artifact-configurations)) refuse un binaire dont le nom de produit diffère.

## Rôles

| Rôle | Personnes | Responsabilité |
|---|---|---|
| Auteurs (committers) | [Dona By (@1donatien0)](https://github.com/1donatien0) | Modifient le code sans relecture supplémentaire |
| Relecteurs (reviewers) | Dona By | Relisent toute contribution d'une personne qui n'est pas auteur avant fusion |
| Approbateurs (approvers) | Dona By | Approuvent chaque demande de signature d'une release |

Tous les membres utilisent l'authentification multifacteur pour GitHub et SignPath.

## Confidentialité

Ce programme ne transfère aucune information vers d'autres systèmes en réseau, sauf à la demande explicite de l'utilisateur ou de la personne qui l'installe ou l'exploite, avec ces exceptions documentées :

- téléchargement des bases de signatures ClamAV depuis les serveurs officiels de ClamAV (aucune donnée locale envoyée) ;
- téléchargement des règles YARA-Forge publiées sur GitHub (aucune donnée locale envoyée) ;
- si l'utilisateur saisit sa propre clé VirusTotal (désactivé par défaut) : envoi de l'empreinte SHA-256 d'un fichier, jamais du fichier.

Détail : [Politique de confidentialité](POLITIQUE_CONFIDENTIALITE.md).

## Modifications du système

L'installeur peut, selon les options choisies : installer le service Windows `optiSCANProtection`, ajouter le dossier d'installation et les moteurs aux exclusions de Microsoft Defender, créer une tâche planifiée d'analyse quotidienne et un lancement au démarrage. Toutes ces modifications sont retirées par la désinstallation (Paramètres Windows > Applications).
