# Plan de release — optiSCAN v3.1

**État au 15 octobre 2026 (soir) :** candidate en préparation, assembly `3.1.0`. L'[audit 360](AUDIT_optiSCAN_360.md) note la candidate **7,4/10** (7,9 hors distribution ; 6,8 le matin) et maintient le refus d'une diffusion publique. **Seuil de publication fixé à 8,0/10.** Les contrôles en machine jetable, la signature SignPath et le premier passage CodeQL C/C++ mènent à 7,9 ; le seuil est atteint si la distribution passe ensuite à 8,0 ([section 2 de l'audit](AUDIT_optiSCAN_360.md#2-notation)). Cette version n'est pas publiée et aucun tag `v3.1.0` n'est créé.

Ce document ne décrit que les critères de la candidate v3.1. Il s'appuie sur l'[audit 360](AUDIT_optiSCAN_360.md) et son journal archivé, en particulier le [traitement des constats E, M et F](docs/archive/AUDIT_optiSCAN_360_journal_2026-10.md#4-constats-e-m-et-f) et les [réserves ouvertes et conditions de clôture](AUDIT_optiSCAN_360.md#5-registre-des-risques-ouverts). La projection produit qui commence après cette release est dans [`ROADMAP.md`](ROADMAP.md).

## 1. Préparer l'historique Git local

Avant toute publication distante, garder les corrections dans des commits locaux lisibles et cohérents. Découpage proposé :

1. **Sécurité et comportement** — chemins sûrs, quarantaine, IPC, scans, protections et tests associés.
2. **Build et chaîne d'approvisionnement** — SDK/runtime, vérification GPG et empreintes, CI/CodeQL, signature et scripts de publication.
3. **Version et documentation** — métadonnées `3.1.0`, audits, guides et cette feuille de route.

Pour chaque commit, relire le diff indexé et vérifier qu'aucun secret ou artefact temporaire n'est ajouté. Ne pas pousser ni créer le tag de release tant que les validations de la section 2 ne sont pas satisfaites et que la publication n'est pas décidée.

## 2. Validations requises avant release

| Priorité | Vérification | État / critère de sortie |
|---|---|---|
| Bloquant | Tests Release sur Windows : `dotnet test optiSCAN.Tests/optiSCAN.Tests.csproj -c Release` | **Validé le 15 octobre 2026** : 715 réussis, 0 échec, 0 ignoré, binaires Release, SDK 10.0.401. `dotnet test` n'a pas pu lancer l'hôte (accès refusé en surveillant le processus parent) ; les mêmes binaires ont été exécutés par le runner xUnit. Deux échecs de quarantaine ont révélé une course avec la migration de démarrage, corrigée avant ce passage (audit, L7). Le test de charge du `FileSystemWatcher` vérifie 480 fichiers sur deux vagues, la borne de file (128) et le rattrapage différé. |
| Bloquant | Service installé : détection/quarantaine SYSTEM, accès standard, gestion élevée, restauration/suppression et migration depuis une installation 3.0.x | À valider sur une VM Windows. Contrôles automatisés prêts : `artifacts\vm\optiSCAN-check.wsb` (Windows Sandbox), résultats dans `artifacts\vm\vm-results.txt`. |
| Bloquant | CodeQL C# et C/C++ | Exécuter après publication du workflow ; confirmer le succès du job `analyze-cpp` (`native/`, `build-mode: none`) sur GitHub. |
| Bloquant | Build et dépendances de release | Vérifier le publish win-x64, `scripts/verify-runtime-deps.ps1`, la signature GPG Talos et les versions ClamAV/YARA épinglées. |
| Bloquant | Installateur | Installer sur une VM propre, vérifier le parcours de mise à jour 3.0.x → 3.1, les options, les données de quarantaine et la désinstallation. |
| Bloquant | Authenticode (SignPath Foundation) | optiSCAN est sous GPL v3 ; la signature gratuite de SignPath Foundation est prévue ([politique](docs/CODE_SIGNING_POLICY.md), `.github/workflows/release.yml`, `.signpath/`). À faire par le mainteneur : purger l'historique (R15), rendre le dépôt public, publier une première version non signée, candidater sur signpath.org en exposant UnRAR et les règles YARA-Forge (audit, R16), renseigner `SIGNPATH_API_TOKEN` et les variables `SIGNPATH_*`, approuver la signature du tag. Soumettre ensuite les binaires signés à Microsoft comme faux positif (R1). |
| Bloquant | Cohérence de release | Vérifier `3.1.0` dans les propriétés, l'installeur et les artefacts ; exécuter `scripts/validate-release-readiness.ps1`. |
| Bloquant | Corrections du 13 octobre 2026 (audit 13) | **Exécutées sous Windows le 15 octobre** avec le reste de la suite (715/715), y compris `ResilienceFixesTests`, `ServiceDetectionAndAlertTests`, `ScheduledScanCatchUpTests`, `RemainingAuditFixesTests`, `ProtectionPipeJsonFramingTests`, `InstallerServiceRecoveryTests` et `FollowUpFixesTests`. **À valider sur VM** : `optiSCAN.exe` non détecté par Defender sans exclusion de processus (dossier d'installation toujours exclu) ; `sc qfailure optiSCANProtection` montre les trois relances ; EICAR détecté par le service puis notifié et inscrit dans l'historique de la session ; `schtasks /query /tn optiSCAN_DailyScan /xml` contient `StartWhenAvailable` ; scan manqué (PC en veille à l'heure prévue) lancé au réveil ; menace en mode jeu notifiée à la sortie ; « Exclure… » d'une notification sans effet si la confirmation est refusée ; `.exe` déposé dans `%LOCALAPPDATA%\optiSCAN\clamav` détecté ; fichier restauré non remis en quarantaine par le temps réel de la session ; dossier surveillé supprimé ou rendu inaccessible → badge « dégradé » et notification ; optiSCAN ouvert en administrateur → mise à jour des signatures et winget refusées avec message ; après installation, optiSCAN lancé non élevé ; « Rétablir l'origine » remet les réglages HKCU, le plan d'alimentation et la télémétrie (`FollowUpFixesTests` passé dans la suite du 15 octobre). |
| Bloquant | Corrections du 7 octobre 2026 (audit 4.6, 4.7, 12) | **Automatisé validé** dans la suite du 15 octobre : charge du watcher en deux vagues (480 fichiers), file bornée et rattrapage différé. **Encore à valider sur une VM Windows** : compilation ISCC et refus sans `optiSCAN.Service.dll`, démarrage du service installé, rendu du bouclier, « Analyser »/« Nettoyer » et jonction, `.exe` renommé en `.dat`, arrêt de `clamd.exe` après terminaison de l'hôte, arrêt du service et absence de repli clamscan systématique. |

M19 reste ouvert jusqu'au premier passage CodeQL C/C++ réussi sur GitHub. Les autres limites et réserves de validation sont consignées dans l'audit 360 ; toute nouvelle constatation de sécurité doit être triée avant le tag.

## 3. Décision de publication

**Bêta fermée** (testeurs informés, exclusion Defender du dossier d'installation documentée) : la suite d'avant la séparation du moteur est verte (715/715 le matin) ; celle d'après est encore à rejouer. Elle attend aussi les contrôles en machine jetable ci-dessus. **Release publique** : en plus, signature SignPath, faux positif levé auprès de Microsoft et premier passage CodeQL C/C++. Détail et risques : [audit 360, sections 3 et 5](AUDIT_optiSCAN_360.md#3-décision-de-release). Note en vigueur : **7,4/10** (7,9 hors distribution) ; seuil de publication : **8,0/10**.


La release `v3.1` ne sera prête qu'après les validations bloquantes, la relecture finale des commits locaux et la vérification des artefacts. Le tag `v3.1.0` et l'envoi vers le dépôt distant viendront ensuite, après décision explicite de publication. Jusqu'à cette étape, `3.1.0` désigne une candidate locale, pas une version distribuée.

## 4. Hors périmètre de cette candidate

AMSI et le minifiltre restent des prototypes non livrés. Leur intégration demanderait une implémentation, une revue de sécurité, une chaîne de signature et des validations Windows propres ; ils ne font pas partie des critères implicites de la v3.1.
