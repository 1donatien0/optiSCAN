# Prototype AMSI — non livré

`optiSCAN.AmsiProvider` est un prototype natif conservé dans le dépôt. Il ne fait pas partie de la candidate v3.1 : le projet n'est pas compilé par la CI, la DLL n'est pas copiée au publish/installeur et Windows ne charge pas le fournisseur.

`PlatformRegistration.TryRegisterAmsiProvider()` est volontairement un no-op qui journalise que le fournisseur n'est pas signé et n'est pas chargé. `TryUnregisterAmsiProvider()` ne fait que nettoyer une éventuelle ancienne entrée AMSI laissée par une version antérieure.

Le fichier `protection_identifiers.h` est le miroir des identifiants définis dans `optiSCAN.Platform/ProtectionIdentifiers.cs`. Les tests vérifient qu'ils restent synchronisés ; ce partage de constantes ne signifie pas que le prototype fonctionne.

Ne pas copier ni enregistrer cette DLL pour une installation courante. Une éventuelle reprise exige une implémentation complète, une revue de sécurité, la chaîne de signature correspondante et une validation spécifique sous Windows avant toute intégration au produit.
