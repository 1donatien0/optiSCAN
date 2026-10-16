# optiSCAN 3.1 — antivirus libre pour Windows

**optiSCAN** est un antivirus libre pour Windows 10 et 11 (x64). Il associe le moteur **ClamAV** et les règles **YARA**, avec :

- une protection en temps réel ;
- un service Windows de protection ;
- l'analyse des scripts avant exécution (AMSI) ;
- une quarantaine chiffrée.

Il complète Microsoft Defender sans le remplacer.

**optiSCAN est un logiciel libre** distribué sous la **GNU General Public License, version 3 ou toute version ultérieure** (`GPL-3.0-or-later`). Vous pouvez l'utiliser, l'étudier, le modifier et le redistribuer selon les termes de cette licence.

> *In English — optiSCAN is a free (GPL-3.0-or-later) antivirus for Windows 10/11 x64. It combines ClamAV and YARA with real-time protection, a SYSTEM protection service, AMSI script scanning and an encrypted quarantine, and works alongside Microsoft Defender. The interface is available in French and English. See [Licence](#licence) and [Code source](#code-source) below.*

---

## Fonctionnalités

**Analyse**
- Analyse rapide, complète, d'un dossier ou d'un fichier, et clic droit « Scanner avec optiSCAN » dans l'Explorateur.
- ClamAV et YARA tournent en parallèle, et leurs résultats sont fusionnés avec un score de risque par menace.
- Analyse quotidienne planifiée. Une analyse manquée pendant la veille est lancée au réveil.

**Protection**
- **Temps réel** : les fichiers à risque sont analysés dès leur écriture, y compris un exécutable déguisé sous une autre extension.
- **Démarrage des processus** : un programme est examiné juste après son lancement, avec les fichiers que lui passent les hôtes de scripts, `rundll32` et `regsvr32`.
- **Clés USB et cartes SD** : analyse automatique à l'insertion.
- **AMSI** : les scripts PowerShell, JavaScript, VBScript et les macros Office sont analysés avant exécution.
- **Service Windows `optiSCANProtection`** : il protège la machine même sans session ouverte. Les moteurs y tournent dans un bac à sable Windows (AppContainer), sans accès au réseau.

**Gestion des menaces**
- Quarantaine chiffrée (AES-256-GCM), avec restauration et suppression.
- Historique unifié des analyses, détections et nettoyages, exportable en **HTML** et **PDF**.
- Mise à jour automatique des signatures ClamAV (toutes les 4 h) et des règles YARA-Forge (toutes les 24 h).

**Outils**
- **Note de sécurité du PC sur 100**, avec liens « Corriger » : pare-feu, UAC, Windows Update, partages, protection.
- **Optimiser** :
  - nettoyage des fichiers temporaires, des caches de navigateurs et de la corbeille ;
  - mise à jour des applications via `winget` ;
  - réglages de Windows (performances, confidentialité, interface), réversibles.

**Interface**
- Français et anglais.
- Thèmes clair, sombre et contraste renforcé.
- Notifications Windows.

## Limites à connaître

- optiSCAN **n'installe pas de pilote noyau**. La surveillance des fichiers agit juste après l'écriture, pas avant. Un pilote minifiltre est étudié pour une version ultérieure.
- AMSI est **non bloquant en cas de panne** : si le service ne répond pas, le script s'exécute.
- Un logiciel malveillant qui a déjà les droits administrateur peut neutraliser un antivirus local, quel qu'il soit.
- Gardez **Microsoft Defender actif** : optiSCAN est conçu pour fonctionner à ses côtés.

## Configuration requise

- Windows 10 version 1809 ou ultérieure, ou Windows 11, en **64 bits (x64)**.
- Droits administrateur pour l'installation et le service de protection.
- Une connexion Internet pour télécharger les signatures après l'installation (environ 300 Mo pour ClamAV).
- Rien d'autre à installer : le runtime .NET 10 est inclus.

## Installation

1. Téléchargez `optiSCAN_Setup_v3.1.0.exe` depuis l'onglet **Files**.
2. Lancez-le et choisissez la langue et les options : service de protection (recommandé), mises à jour automatiques des signatures, lancement au démarrage, icône sur le Bureau.
3. Au premier lancement, laissez optiSCAN télécharger les signatures ClamAV et les règles YARA.

La désinstallation se fait dans **Paramètres Windows > Applications**. Elle retire le service, le fournisseur AMSI et, s'ils ont été activés, la tâche planifiée et les exclusions Defender ajoutées par optiSCAN.

### Signature du code

Les versions signées d'optiSCAN le sont par la **SignPath Foundation**. Les binaires sont compilés par GitHub Actions à partir du code source public, puis signés après approbation manuelle. Les règles sont décrites dans la [politique de signature](https://github.com/1donatien0/optiSCAN/blob/main/docs/CODE_SIGNING_POLICY.md).

> Free code signing provided by [SignPath.io](https://about.signpath.io/), certificate by [SignPath Foundation](https://signpath.org/).

Un fichier non signé (pré-version, compilation personnelle) déclenche l'avertissement SmartScreen de Windows. Vérifiez alors son empreinte SHA-256 avec celle publiée dans la release.

## Confidentialité

optiSCAN **n'envoie aucune télémétrie**. Il ne se connecte qu'aux services suivants :

- les serveurs officiels de ClamAV, pour les signatures (aucune donnée locale envoyée) ;
- GitHub, pour les règles YARA-Forge d'une publication épinglée (aucune donnée locale envoyée) ;
- **VirusTotal, seulement si vous saisissez votre propre clé API** (désactivé par défaut). Dans ce cas, seule l'empreinte SHA-256 du fichier est envoyée, jamais le fichier.

Détail : [politique de confidentialité](https://github.com/1donatien0/optiSCAN/blob/main/docs/POLITIQUE_CONFIDENTIALITE.md).

## Code source

Le code source complet d'optiSCAN se trouve sur **GitHub : <https://github.com/1donatien0/optiSCAN>**. Il comprend l'application, le service, le fournisseur AMSI en C++, l'installeur Inno Setup et les scripts de compilation et de publication. Chaque version publiée correspond à un tag `vX.Y.Z`, et une archive des sources est jointe à chaque release.

Pour compiler :

```powershell
# Prérequis : SDK .NET 10, Visual Studio avec « Développement Desktop en C++ », Inno Setup 6
git clone https://github.com/1donatien0/optiSCAN.git
cd optiSCAN
.\scripts\fetch-runtime-deps.ps1      # ClamAV et YARA, vérifiés par SHA-256 et signature GPG
dotnet test optiSCAN.sln -c Release
.\scripts\publish-release.ps1         # publication + installeur
```

## Licence

```
optiSCAN — antivirus libre pour Windows
Copyright (C) 2026 Dona By (Donatien Byakombe)

Ce programme est un logiciel libre : vous pouvez le redistribuer et/ou le modifier
selon les termes de la GNU General Public License telle que publiée par la
Free Software Foundation, soit la version 3 de la licence, soit (à votre choix)
toute version ultérieure.

Ce programme est distribué dans l'espoir qu'il sera utile, mais SANS AUCUNE
GARANTIE, sans même la garantie implicite de QUALITÉ MARCHANDE ou d'ADÉQUATION
À UN USAGE PARTICULIER. Voir la GNU General Public License pour plus de détails.

Vous devez avoir reçu une copie de la GNU General Public License avec ce
programme (fichier LICENSE.txt). Sinon, voir <https://www.gnu.org/licenses/>.
```

Le texte intégral de la licence est livré avec le logiciel (`LICENSE.txt`) et s'affiche pendant l'installation.

### Composants tiers

optiSCAN livre des composants libres qui gardent chacun leur propre licence. Leurs textes sont installés dans les dossiers `licenses\` et `clamav\x64\licenses\`.

| Composant | Licence |
|---|---|
| ClamAV 1.4.6 (`clamscan`, `clamd`, `freshclam`) | GNU GPL v2 |
| UnRAR (livré avec ClamAV) | Licence UnRAR |
| OpenSSL, libcurl, zlib, bzip2, PCRE2, libxml2 et autres bibliothèques de ClamAV | Licences libres respectives |
| YARA 4.5.5 | BSD-3-Clause |
| Runtime .NET 10, WPF | MIT |
| MaterialDesignThemes, PDFsharp/MigraDoc 6.2.4, Microsoft.Toolkit.Uwp.Notifications | MIT |

Les signatures ClamAV et les règles YARA-Forge sont téléchargées après l'installation et relèvent des conditions de leurs auteurs. Le code source de ClamAV est publié par Cisco-Talos : <https://github.com/Cisco-Talos/clamav>.

Liste complète : [THIRD-PARTY-NOTICES.md](https://github.com/1donatien0/optiSCAN/blob/main/installer/licenses/THIRD-PARTY-NOTICES.md).

## Nouveautés de la version 3.1

**Licence**
- optiSCAN devient un **logiciel libre sous GPL-3.0-or-later** et remplace l'ancien CLUF.
- Les versions 1.0.0, 2.0.0 et 3.0.0 de l'onglet **Files** sont republiées sous la même licence : seule la licence affichée à l'installation change.
- Tous les fichiers sources portent un en-tête `SPDX-License-Identifier`.
- Le générateur PDF QuestPDF, dont la licence n'est pas libre, est remplacé par PDFsharp/MigraDoc (MIT).

**Protection**
- **Fournisseur AMSI** livré avec le service : les scripts sont analysés avant exécution.
- **Moteur séparé de l'interface** : le service lance un hôte dédié (`optiSCAN.Host.exe`), sans WPF.
- **Moteurs confinés** : sous SYSTEM, `clamd`, `clamscan`, `yara` et `yarac` tournent dans un AppContainer, sans réseau ni processus enfant.
- Le service de protection est coché à la première installation. Ses détections apparaissent dans l'historique et les notifications.

**Détection**
- Couverture élargie : exécutables reconnus quelle que soit leur extension, `%APPDATA%` et dossier Public dans l'analyse rapide, corbeilles des clés USB, sept nouveaux hôtes de scripts surveillés.

**Distribution**
- Chaîne de signature SignPath Foundation, et moteurs ClamAV et YARA épinglés et vérifiés.

**Qualité**
- 764 tests automatisés, et un audit indépendant suivi dans le dépôt.

Historique complet : [README du dépôt](https://github.com/1donatien0/optiSCAN#11-historique-des-versions-produit).

## Signaler un problème

- **Bogues et suggestions** : onglet *Tickets* ou *Discussion* de cette page, ou *Issues* sur GitHub.
- **Vulnérabilités** : ne les publiez pas. Écrivez en privé à l'auteur via sa [page SourceForge](https://sourceforge.net/u/donaby) (voir [SECURITY.md](https://github.com/1donatien0/optiSCAN/blob/main/SECURITY.md)).
- **Faux positif** : utilisez la quarantaine plutôt que la suppression. Vous pourrez restaurer le fichier et l'exclure dans *Options*.

---

Développé par **Dona By (Donatien Byakombe)**, 2026, avec le système de design Donaby Design.
