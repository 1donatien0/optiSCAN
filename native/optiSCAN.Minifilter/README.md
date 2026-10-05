# Prototype minifilter — non livré

Le dossier `native/optiSCAN.Minifilter` contient un squelette de pilote et des fichiers de conception. Il ne fait pas partie de la candidate v3.1 : il n'est pas construit par la CI, copié au publish ou livré dans l'installeur.

`PlatformRegistration.TryLoadMinifilter()` est volontairement un no-op qui journalise que le pilote n'est pas signé et n'est pas chargé. Le nettoyage du produit peut tenter de décharger une ancienne instance, mais aucune installation du pilote n'est effectuée.

Les fichiers `filter.c`, `.inf` et le pont C# ne constituent pas un filtre prêt à l'emploi. **Ne pas copier de `.sys` dans `System32\drivers` et ne pas le charger avec `fltmc`** : ces étapes de l'ancienne documentation ne sont pas prises en charge et ne permettent pas d'activer une protection avant exécution.

Une éventuelle reprise exige un pilote complet, une revue de sécurité, une validation WDK/Windows et sa chaîne de signature Microsoft avant toute intégration au produit. Voir aussi [`SECURITY.md`](../../SECURITY.md).
