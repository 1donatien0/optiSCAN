# Politique de confidentialité — optiSCAN v3.1 (candidate)

**Dernière mise à jour :** 5 octobre 2026

**Éditeur :** Dona By — optiSCAN (édition ClamAV)

Ce document décrit comment optiSCAN traite vos données. Il complète le contrat de licence ([LICENSE.txt](../LICENSE.txt)) et la note interne [CONFORMITE_RGPD.md](CONFORMITE_RGPD.md). Ce n'est pas un avis juridique.

---

## 1. Principe général

optiSCAN est conçu pour fonctionner **localement sur votre ordinateur**. Par défaut, **aucune donnée personnelle n'est collectée, vendue ou transmise** à l'éditeur.

---

## 2. Données stockées sur votre poste

| Donnée | Emplacement | Durée |
|--------|-------------|-------|
| Historique, préférences et exclusions de l'interface | `%LOCALAPPDATA%\optiSCAN` de votre compte Windows | Jusqu'à suppression par vous ou désinstallation avec purge choisie |
| Quarantaine de l'interface (AES-GCM) | `%LOCALAPPDATA%\optiSCAN\Quarantine` de votre compte Windows | Jusqu'à suppression/restauration ou purge choisie |
| Copies de sécurité avant quarantaine (option, désactivable) | `%LOCALAPPDATA%\optiSCAN\SafetyBackups` de votre compte Windows, chiffrées | **30 jours** au plus (256 Mo au total) ; supprimées avec l'élément de quarantaine |
| Journaux du processus interactif | `%LOCALAPPDATA%\optiSCAN\Logs` de votre compte Windows | Journaux applicatifs : rotation après **30 jours** |
| État et staging du service | `%ProgramData%\optiSCAN` | Gérés par le service ; supprimés par l'installeur à la désinstallation |
| Quarantaine du service avancé (AES-GCM) | `%ProgramData%\optiSCAN\Quarantine`, accessible à SYSTEM et aux administrateurs | Supprimée automatiquement après **90 jours**, ou plus tôt par un administrateur ; supprimée à la désinstallation |
| Détections du service avancé | `%ProgramData%\optiSCAN\detections.json`, accessible à SYSTEM et aux administrateurs | Les **200** dernières ; supprimées à la désinstallation. Votre session n'en voit le chemin complet que pour les fichiers de votre profil |
| Journaux du service avancé | `%LOCALAPPDATA%\optiSCAN` du compte **SYSTEM** (généralement sous `systemprofile`) | Supprimés à la désinstallation |

- Les journaux ne sont **pas chiffrés**. Les chemins sous les profils Windows standard (`C:\Users\…`) sont masqués, y compris dans les messages et traces d'exception ; d'autres chemins personnalisés ou données de diagnostic peuvent rester lisibles.
- Les quarantaines sont chiffrées ; les clés DPAPI sont propres à l'identité Windows qui exécute le processus. La quarantaine créée par SYSTEM ne se restaure donc pas depuis un compte ordinaire : l'onglet Quarantaine en montre le nombre et la taille, et le bouton « Gérer (administrateur) » ouvre, après confirmation UAC, la liste de ses éléments avec restauration et suppression.

Ces données restent sur votre machine, sauf si vous les exportez vous-même ou utilisez l'option VirusTotal décrite ci-dessous. L'activation du service avancé entraîne un traitement par SYSTEM, avec une quarantaine distincte réservée aux administrateurs et vidée de ses éléments de plus de 90 jours.

---

## 3. Connexions réseau

### 3.1 Mises à jour de signatures (par défaut)

- **ClamAV** : téléchargement des bases antivirus depuis les serveurs officiels.
- **Règles YARA** : consultation de l'API et téléchargement depuis GitHub (YARA-Forge), limité à la release et à l'empreinte approuvées dans optiSCAN. Aucune donnée locale ni fichier n'est envoyé ; si l'asset `latest` ne correspond pas à la pin, les règles ne sont pas mises à jour.

Aucune information personnelle identifiable n'est envoyée ; seuls des téléchargements de fichiers publics sont effectués.

### 3.2 VirusTotal — **désactivé par défaut (opt-in)**

Si vous saisissez **votre propre clé API VirusTotal** dans les options :

- optiSCAN envoie uniquement le **hash SHA-256** d'un fichier (jamais le fichier complet) à `virustotal.com`.
- Ce traitement est soumis à la [politique de confidentialité de VirusTotal](https://www.virustotal.com/gui/privacy-policy).
- Des transferts hors de l'Union européenne peuvent s'appliquer si vous utilisez cette fonction.

Sans clé API, **aucune requête VirusTotal** n'est émise.

---

## 4. Ce que optiSCAN ne fait pas

- Pas de télémétrie d'usage vers l'éditeur.
- Pas de publicité ni de profilage.
- Pas de compte utilisateur obligatoire.
- Pas de vente de données.

---

## 5. Vos droits et choix

Vous pouvez à tout moment :

- Supprimer les données de l'interface en désinstallant optiSCAN avec la purge choisie ou en supprimant `%LOCALAPPDATA%\optiSCAN` de votre compte.
- Les données machine sous `%ProgramData%\optiSCAN` sont retirées par l'installeur à la désinstallation. La quarantaine du service en fait partie. Les journaux du service dans le profil SYSTEM sont aussi supprimés par le désinstalleur.
- Retirer votre clé VirusTotal pour stopper tout envoi de hash.
- Désactiver les mises à jour automatiques dans les options.

Pour toute question : [page SourceForge de l'auteur](https://sourceforge.net/u/donaby).

---

## 6. Modifications

Cette politique peut être mise à jour lors des versions majeures du logiciel. La date en tête de document indique la dernière révision.
