# Prototype minifilter — non livré

Le dossier `native/optiSCAN.Minifilter` contient un squelette de pilote et des fichiers de conception. Il ne fait pas partie de la candidate v3.1 : il n'est pas construit par la CI, copié au publish ou livré dans l'installeur.

`PlatformRegistration.TryLoadMinifilter()` est volontairement un no-op qui journalise que le pilote n'est pas signé et n'est pas chargé. Le nettoyage du produit peut tenter de décharger une ancienne instance, mais aucune installation du pilote n'est effectuée.

Les fichiers `filter.c`, `.inf` et le pont C# ne constituent pas un filtre prêt à l'emploi. **Ne pas copier de `.sys` dans `System32\drivers` et ne pas le charger avec `fltmc`** : ces étapes de l'ancienne documentation ne sont pas prises en charge et ne permettent pas d'activer une protection avant exécution.

Une éventuelle reprise exige un pilote complet, une revue de sécurité, une validation WDK/Windows et sa chaîne de signature Microsoft avant toute intégration au produit. Voir aussi [`SECURITY.md`](../../SECURITY.md).

## Prérequis pour une reprise (chantier 3.2)

Le minifiltre est un pilote noyau : une erreur provoque un écran bleu, et Windows ne charge un pilote que s'il est signé par Microsoft. La chaîne SignPath ne s'applique pas aux pilotes.

1. **Compte Microsoft Partner Center** (programme Windows Hardware Developer) ; inscription gratuite, vérification de l'entreprise ou du développeur.
2. **Certificat EV de signature de code** (payant, environ 300 à 500 $ par an) pour signer le paquet soumis à Microsoft.
3. **WDK** (Windows Driver Kit) aligné sur Visual Studio 2022 ; projet *Filter Driver: Filesystem Mini-Filter*.
4. **Développement sur machine de test dédiée** en mode *test signing* (`bcdedit /set testsigning on`) avec Driver Verifier actif ; jamais sur un poste de travail.
5. **Signature d'attestation** par Microsoft (soumission du `.cab` signé EV dans Partner Center) ; pour une diffusion large, tests HLK et signature WHQL.
6. **Fonctionnement visé** : pré-création (`IRP_MJ_CREATE` en exécution) et post-écriture, communication avec l'hôte par `FltCreateCommunicationPort`, cache par fichier, délai borné et fail-open, altitude attribuée par Microsoft (demande d'altitude pour le groupe *FSFilter Anti-Virus*).

Licence : GPL-3.0-or-later. Le code noyau reste soumis aux exigences de signature ci-dessus, indépendantes de la licence.
