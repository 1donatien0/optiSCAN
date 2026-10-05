# Conformité RGPD / vie privée — optiSCAN

Note d'analyse des traitements de données d'optiSCAN, destinée à préparer une politique de confidentialité pour une diffusion (notamment en Europe). Ce n'est pas un avis juridique.

---

## 1. Données traitées localement (jamais transmises)

| Donnée | Où | Rétention |
|---|---|---|
| Historique / préférences / exclusions de l'interface | `%LOCALAPPDATA%\optiSCAN` du compte connecté | Jusqu'à suppression ou purge choisie à la désinstallation |
| Quarantaine de l'interface | `%LOCALAPPDATA%\optiSCAN\Quarantine` du compte connecté, chiffrée AES-GCM avec clé DPAPI CurrentUser | Jusqu'à restauration, suppression ou purge choisie |
| Journaux interactifs | `%LOCALAPPDATA%\optiSCAN\Logs` du compte connecté | Rotation AppLogger après 30 jours |
| État et staging du service | `%ProgramData%\optiSCAN` | Supprimés par l'installeur à la désinstallation |
| Quarantaine du service SYSTEM | `%ProgramData%\optiSCAN\Quarantine` (SYSTEM et Administrateurs uniquement), chiffrée AES-GCM avec clé DPAPI SYSTEM | Suppression automatique après **90 jours** ; consultation, restauration et suppression par un administrateur depuis l'onglet Quarantaine ; supprimée à la désinstallation |
| Journaux du service SYSTEM | `%LOCALAPPDATA%\optiSCAN` résolu sous SYSTEM (généralement `systemprofile`) | Rotation AppLogger ; supprimés à la désinstallation |

- Les journaux ne sont **pas chiffrés**. `PathRedaction` masque les segments de profils Windows standard (`C:\Users\…`) dans les messages et exceptions ; les profils personnalisés et d'autres détails de diagnostic peuvent encore contenir des chemins.
- La quarantaine est **chiffrée** (AES-GCM, clé protégée par DPAPI de l'identité du processus). Le service SYSTEM a sa propre clé et son propre dossier. L'onglet Quarantaine en affiche le nombre et la taille à tout utilisateur ; la liste (qui contient des chemins de tous les comptes), la restauration et la suppression passent par le service et exigent un administrateur élevé. Une ancienne quarantaine du service (profil SYSTEM, versions 3.0.x) est déplacée vers ProgramData au premier démarrage du service.

Aucune de ces données ne quitte le poste.

## 2. Données transmises à des tiers

### VirusTotal (réputation de menaces) — **opt-in**

- **Ce qui est envoyé** : uniquement le **hash SHA‑256** d'un fichier (jamais le fichier lui‑même), via `GET https://www.virustotal.com/api/v3/files/{hash}`.
- **Condition** : uniquement si l'utilisateur a saisi **sa propre clé API VirusTotal**. Sans clé, aucune requête n'est émise.
- **Donnée personnelle ?** Un hash de fichier n'est normalement pas une donnée personnelle, mais il est transmis à un tiers (Google/VirusTotal) soumis à ses propres conditions.
- **Recommandation** : mentionner ce traitement dans la politique de confidentialité, indiquer qu'il est **désactivé par défaut**, et lier la politique de VirusTotal.

### Mises à jour de signatures (ClamAV/YARA)

- `freshclam` et l'API/téléchargement GitHub des règles contactent les serveurs de signatures (téléchargement de bases publiques). YARA-Forge n'installe que l'asset et l'empreinte autorisés localement par optiSCAN (release `20261004` dans l'état courant). Pas d'envoi de fichiers ou d'autres données locales ; échange réseau standard de mise à jour.

## 3. Points à formaliser pour le RGPD

1. **Politique de confidentialité** : texte rédigé dans [POLITIQUE_CONFIDENTIALITE.md](POLITIQUE_CONFIDENTIALITE.md) — reste à **exposer** dans l'app et sur le site / page de téléchargement.
2. **Base légale** : intérêt légitime (sécurité) pour le fonctionnement local ; **consentement** explicite pour l'envoi de hash à VirusTotal (déjà opt-in via saisie de clé).
3. **Minimisation** : confirmée (hash seul, pas de fichier ; logs caviardés ; rétention 30 j).
4. **Droits** : l'utilisateur peut supprimer ses données d'interface (purge proposée à la désinstallation ou suppression de `%LOCALAPPDATA%\optiSCAN`). L'installeur supprime l'état machine de `%ProgramData%\optiSCAN`, mais les données conservées sous le profil SYSTEM exigent un nettoyage administrateur et ne sont pas couvertes par la purge utilisateur.
5. **Transferts hors UE** : VirusTotal (États‑Unis) — déjà mentionné dans la politique ; à rappeler dans l'UI Options près du champ clé API.
6. **Pas de télémétrie** tierce intrusive — déclaré dans la politique (« pas de télémétrie d'usage vers l'éditeur »).

## 4. Verdict

Le traitement est local par défaut et l'envoi VirusTotal est **opt-in**. La quarantaine du service SYSTEM est désormais gérable par un administrateur et soumise à une conservation de 90 jours. La politique doit rester claire sur les chemins encore présents dans certains diagnostics.
