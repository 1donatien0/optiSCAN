# Modèle de menace — optiSCAN v7 (synthèse)

Document court pour la release v7.0 — périmètre **local**, poste Windows de l’utilisateur.

## Actifs protégés

- Fichiers analysés (disque local, quarantaine chiffrée AES-GCM)
- Préférences et exclusions (`%LocalAppData%\optiSCAN`, registre HKCU)
- Clé maîtresse quarantaine (DPAPI CurrentUser)

## Acteurs

| Acteur | Capacité |
|--------|----------|
| Utilisateur local | Lance scans, exclusions, restauration quarantaine |
| Processus malveillant local | Peut tenter de lire/altérer données optiSCAN si droits suffisants |
| Réseau (freshclam, YARA-Forge, SourceForge) | Téléchargement signatures / règles ; pas d’OTA binaire configuré |

## Contrôles v7

- Quarantaine chiffrée + manifeste HMAC
- Exclusions persistées ; confirmation avant suppression menace
- Élévation UAC à la demande (analyse complète, planifié)
- RTP limité à dossiers sensibles + extensions à risque
- Pas de télémétrie cloud intégrée

## Limites connues

- Un malware avec droits admin peut neutraliser ou supprimer optiSCAN comme tout AV local
- RTP ne couvre pas tout le profil utilisateur
- Logs et sorties moteurs peuvent contenir chemins sensibles sur disque

## Références

- [README.md](../README.md) — architecture
- [AUDIT.md](AUDIT.md) — synthèse QA v7
