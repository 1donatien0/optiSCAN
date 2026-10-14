# Feuille de route produit — optiSCAN Antivirus

**Mise à jour :** 13 octobre 2026

**Horizon :** évolutions envisagées après la validation et la publication de la v3.1.

**Périmètre :** le produit antivirus optiSCAN pour Windows.

Cette feuille décrit des priorités et des critères de décision, sans calendrier ni promesse de livraison. Elle ne remplace pas le [plan de release v3.1](RELEASE_PLAN_v3.1.md) : la v3.1 est encore une candidate et doit franchir ses validations Windows et GitHub avant publication.

## Direction produit

Faire d’optiSCAN un antivirus Windows dont les résultats sont compréhensibles, dont les lacunes de couverture sont visibles, et dont les actions de quarantaine et les mises à jour des moteurs sont vérifiables. Les promesses de protection doivent correspondre exactement au comportement livré.

## Base actuelle et limites assumées

optiSCAN réunit une application WPF, un service Windows, les analyses à la demande et planifiées, la surveillance de fichiers après écriture, ClamAV et YARA, l’historique et une quarantaine chiffrée. Le code et les audits décrivent également des limites qui doivent guider la suite :

- AMSI et le minifiltre Windows sont des prototypes et ne sont pas livrés. La surveillance actuelle ne doit donc pas être présentée comme une interception préventive avant écriture ou exécution.
- Un scan peut se terminer avec des erreurs ou une couverture incomplète ; ces états doivent rester distincts d’un résultat sain.
- La release v3.1 et ses validations Windows restent régies par le [plan de release](RELEASE_PLAN_v3.1.md). L’[audit 360](AUDIT_optiSCAN_360.md) documente la base technique et ses [réserves](AUDIT_optiSCAN_360.md#5-registre-des-risques-ouverts).

## Priorités après la v3.1

### 1. Rendre l’état de protection et la couverture visibles

Améliorer l’information présentée à l’utilisateur lorsque la surveillance est arrêtée, dégradée, en reprise ou incapable de rattraper des événements. Consigner les détections temps réel et les scans incomplets dans un historique exploitable. Afficher les fichiers ignorés, inaccessibles ou non analysés et la raison correspondante.

**Critères de sortie :** les essais Windows distinguent sans ambiguïté les états sain, détection, erreur, annulation et couverture incomplète ; une erreur de moteur ou un rattrapage manqué ne peut pas apparaître comme une analyse propre.

### 2. Mesurer la qualité de détection et maintenir les règles

- Constituer une suite de vérification contrôlée pour ClamAV, YARA, leur orchestration, les mises à jour de signatures et les faux positifs.
- Suivre les faux positifs signalés, documenter leur triage et vérifier qu’une correction ne réduit pas la couverture ailleurs.
- Définir un mécanisme soutenable pour renouveler les règles YARA-Forge approuvées sans devoir intégrer chaque nouvelle empreinte dans une version du programme. Le mécanisme doit préserver la vérification cryptographique, permettre le retrait d’une publication compromise et refuser une mise à jour invalide ou incomplète.
- Montrer la date et l’état des dernières mises à jour de moteurs et de règles.

**Critères de sortie :** les mises à jour acceptées sont authentifiées et vérifiées de bout en bout ; les échecs laissent les règles précédentes intactes et signalent clairement le retard de protection.

### 3. Renforcer la fiabilité de la surveillance temps réel

Tester la création et la reprise des watchers, les débordements d’événements, les écritures répétées, les fichiers volumineux, le manque d’espace et le redémarrage du service. Rendre persistants les avertissements importants. Les détections du service SYSTEM sont notifiées et inscrites dans l'historique de la session depuis la candidate v3.1 (`recent_detections`) ; un dossier perdu par le temps réel passe désormais le badge de protection à « dégradé », avec notification (audit indépendant A15).

**Critères de sortie :** une perte de surveillance ou un rattrapage incomplet est signalé et inscrit dans l’historique ; les scénarios Windows d’installation, de mise à niveau, de restauration et de purge de quarantaine passent sur une machine de test.

Toute évolution vers AMSI ou un minifiltre est une décision distincte. Elle demande une architecture, une revue de sécurité et une validation de signature propres. Les coûts de certificats Authenticode/EV et de signature WHQL sont reportés par décision du projet ; aucun pilote ni calendrier de signature n’est promis dans cette feuille.

### 4. Pérenniser les moteurs et la chaîne de publication

Maintenir les versions prises en charge de .NET, ClamAV et YARA ; vérifier l’origine, les signatures et les empreintes des dépendances Windows avant intégration. Garder l’inventaire SBOM, les contrôles CI et l’analyse de code à jour. Documenter le support des versions de Windows, les procédures de mise à niveau et le retour à une configuration saine après échec.

**Critères de sortie :** chaque artefact de release a une provenance documentée, ses dépendances sont vérifiées, et l’installation, la mise à niveau, la désinstallation et la récupération sont validées sur Windows. Les validations restantes de la v3.1, dont CodeQL C/C++, demeurent des portes de release décrites dans son plan.

### 5. Améliorer le diagnostic et l’expérience d’utilisation

Rendre les erreurs compréhensibles sans exposer davantage de données privées. Définir les informations utiles à un rapport de diagnostic, vérifier leur masquage et documenter ce que les analyses transmettent ou conservent. Continuer à maintenir la parité française et anglaise ainsi que l’accessibilité des principaux parcours.

**Critères de sortie :** un utilisateur peut comprendre pourquoi une analyse n’a pas abouti, retrouver les actions proposées et partager un diagnostic avec une exposition maîtrisée des chemins et données locales.

### 6. Suites de l'audit indépendant du 13 octobre 2026

Corrigés dans la candidate : A3, A4, A5 (fermeture de `scan_path`), A6 (moteurs exigés en CI), A9, A10 et les points de la revue ligne à ligne ([audit, section 6](AUDIT_optiSCAN_360.md#6-relecture-des-corrections--défauts-trouvés-et-corrigés)). Restent à planifier :

- **A1, A2** — commiter la candidate, produire l'installateur depuis la CI seulement, rendre la signature Authenticode obligatoire au job de publication (avant toute diffusion publique) ;
- **A5 (suite)** — exécuter YARA et clamscan dans l'AppContainer de clamd, YARA 4.5.8 compilé en CI ;
- **A7, A8** — moteur dans une bibliothèque sans WPF, hébergé directement par `optiSCAN.Service` ; appels natifs centralisés, fin du singleton `ServiceContainer` ;
- **A12** — purger l'historique Git avant un passage du dépôt en public ;
- **A14** — scinder le README (utilisateur, développeur, CHANGELOG) ; remplacer l'audit-journal par un registre des risques ouverts ;
- **A13** — monter QuestPDF et xUnit sur un poste Windows, en comparant les PDF produits et en exécutant la suite.

A11 (retour arrière d'Optimiser, nom de la relance automatique) et A15 (santé du temps réel dans l'interface) sont corrigés dans la candidate.

## Périmètre et décisions futures

- Windows reste la plateforme prise en charge par cette feuille de route.
- Le développement d’un système d’exploitation ou d’une distribution n’est pas un objectif d’optiSCAN Antivirus.
- Une éventuelle édition pour une autre plateforme ne sera étudiée qu’après les priorités Windows, avec une décision séparée fondée sur un prototype, la compatibilité des moteurs, les licences et la capacité de maintenance.
- Les étapes commencent après leur décision d’engagement ; les coûts et échéances ne seront estimés qu’avec des essais et un périmètre établis.

## Références de pilotage

- [Plan de release v3.1](RELEASE_PLAN_v3.1.md) — validations de la candidate, avant toute publication.
- [Audit 360](AUDIT_optiSCAN_360.md) — constats, traitement, état du code et réserves Windows/GitHub.
