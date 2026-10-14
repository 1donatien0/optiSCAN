# Audit 360 — optiSCAN v3.1 candidate

**Révision du 13 octobre 2026, au soir.** Ce document remplace l'audit précédent. Il repart d'un examen complet de l'arbre de travail : relecture ligne à ligne de toutes les modifications non commitées, compilation, exécution de la suite de tests et mesures. L'ancien document, qui mêlait constats, corrections et journal de travail sur 950 lignes, est conservé dans [`docs/archive/AUDIT_optiSCAN_360_journal_2026-10.md`](docs/archive/AUDIT_optiSCAN_360_journal_2026-10.md). Le présent document ne garde que l'état actuel et un registre des risques ouverts.

## En bref

| Indicateur | Valeur |
|---|---|
| **Note globale** | **6,5 / 10** (6,4 à l'audit indépendant du matin) |
| Qualité technique (hors distribution) | **7,0 / 10** |
| Prêt à diffuser | **4 / 10** |
| **Décision** | **Pas de diffusion publique.** Bêta fermée possible dès que trois conditions sont remplies : commits, suite Windows verte, contrôles sur machine virtuelle. |

Le code a nettement progressé dans la journée : 37 défauts corrigés, dont deux plus graves que tous ceux de l'audit indépendant du matin (le service coupait son propre temps réel ; une lecture DPAPI ratée détruisait la quarantaine). La relecture de ces corrections en a trouvé six de plus, corrigés ici (section 6).

La note globale ne monte pourtant que d'un dixième, et c'est voulu. Ce qui la tire vers le bas n'est plus le code : la candidate n'est pas commitée, n'est pas signée, et Defender détecte `optiSCAN.exe` dès qu'il n'est plus exclu. Surtout, environ 3 400 lignes ont été ajoutées depuis la dernière exécution de la suite sous Windows (7 octobre). Ces trois points sont entre les mains du mainteneur ; une fois levés, la note atteint environ 7,4 (section 2).

## 1. Périmètre et méthode

L'examen porte sur la branche `dev` : commit `d18f333` plus l'arbre de travail du 13 octobre au soir (84 fichiers suivis modifiés, +3 370 / −673 lignes, plus 15 fichiers C# nouveaux et les licences de l'installeur).

| Contrôle | Résultat |
|---|---|
| Relecture ligne à ligne du diff du code non commité (5 100 lignes) et des 15 fichiers C# nouveaux | Six défauts trouvés et corrigés (section 6) |
| Compilation Release, Debug et publication (`OptiscanShipping=true`), SDK 10.0.401, avertissements traités en erreurs | 0 erreur, 0 avertissement |
| Suite de tests exécutée sous Linux (bibliothèques WPF de référence rendues chargeables, DPAPI remplacé par un substitut de test) | 714 cas, **638 réussis**, 76 échecs tous dus à l'absence de Windows (section 7) |
| Audit NuGet (vulnérables, dépréciés, obsolètes, transitifs compris) | Aucune vulnérabilité connue ; xUnit 2 « legacy » ; QuestPDF 2024.12 (2026.9 disponible) |
| Mesures sur le code de production | Section 8 |

**Non fait, faute de machine Windows :** exécution de la suite sous Windows, installation sur machine virtuelle, essais avec privilèges (jonctions, usurpation du tube, arrêt brutal du service), comportement de Defender. Ces points restent ouverts dans le registre (R2 à R4) et décident de la release.

## 2. Notation

| Domaine | Poids | Note | Justification |
|---|---:|---:|---|
| Sécurité du code privilégié (service, tube, quarantaine, chemins) | 25 % | 8,0 | Usurpation du client, parcours sans jonction, serveur identifié par le gestionnaire de services, `scan_path` fermé, compte du client lu sur son jeton, instance élevée qui ne lance plus d'outil configuré par l'utilisateur. Reste : YARA et clamscan non isolés sous SYSTEM (R5). |
| Efficacité de détection | 15 % | 6,5 | ClamAV et YARA, temps réel après écriture, surveillance des processus après lancement. Couverture élargie aujourd'hui (dossiers de données, corbeilles USB, `%APPDATA%`, détections du service visibles). Ni AMSI ni minifiltre (R7). |
| Robustesse et exploitation | 15 % | 7,0 | Relance automatique du service, clés mises de côté au lieu d'être écrasées, santé du temps réel visible, tâche planifiée rattrapée. Plafonnée tant que la suite Windows n'est pas rejouée (R3). |
| Qualité du code et maintenabilité | 10 % | 5,5 | Exécutable WPF unique à 20 modes, conteneur singleton, 503 blocs `catch` sans filtre, 78 déclarations P/Invoke (R10). |
| Tests et preuves | 10 % | 6,5 | 714 cas, la CI exige les moteurs pour EICAR ; 638 réussis sous Linux. Suite Windows à rejouer, CodeQL C/C++ jamais passé sur GitHub. |
| Distribution et confiance | 15 % | 4,0 | Non signé, non commité, détecté par Defender sans exclusion (R1, R2). Licences et actions de récupération désormais dans l'installeur. |
| Produit (expérience, mises à jour) | 5 % | 7,0 | Retour arrière d'Optimiser, alertes en mode jeu, confirmation avant exclusion. Pas de canal de mise à jour du produit (R8). |
| Dépendances et chaîne d'approvisionnement | 5 % | 7,0 | Archives épinglées, signature GPG Talos, SBOM. Pile de tests et QuestPDF en retard (R11). |
| **Total pondéré** | | **6,5** | Hors distribution, renormalisé : **7,0** |

**Ce qui fait monter la note**, sans autre changement de code :

| Étape | Effet | Note globale |
|---|---|---:|
| R2, R3, R4 : commits, suite Windows verte, contrôles VM | Tests 8, robustesse 8, distribution 5 | ≈ 7,0 |
| + R1 : binaires signés, faux positif levé auprès de Microsoft | Distribution 7,5 | ≈ 7,4 |
| + R5 : YARA et clamscan isolés (3.2) | Sécurité 9 | ≈ 7,6 |

Les audits internes (8,6 puis 7,9 puis 7,2) notaient surtout le code relu, sans séparer la distribution ni la maintenabilité. Ils ne sont pas comparables terme à terme.

## 3. Décision de release

La recommandation de l'audit du matin était de ne pas publier. Elle est maintenue pour une **diffusion publique**, et précisée pour une **bêta fermée**.

| Étape | Conditions | État |
|---|---|---|
| **Bêta fermée** (testeurs informés, exclusion Defender du dossier d'installation documentée) | R2 commits locaux propres (licences comprises) ; R3 `dotnet test` Release vert sous Windows ; R4 contrôles VM du [plan de release](RELEASE_PLAN_v3.1.md) | ⏳ |
| **Release publique 3.1.0** | Bêta fermée, plus R1 signature Authenticode et faux positif levé, premier passage CodeQL C/C++ sur GitHub | ⏳ |

Une bêta reste possible malgré R5 et R7 : ce sont des limites connues, documentées dans [SECURITY.md](SECURITY.md) et sans exploitation démontrée. R1 bloque en revanche toute diffusion large : un utilisateur sans l'exclusion verrait `optiSCAN.exe` mis en quarantaine par Defender.

## 4. Points forts

Six mécanismes tiennent à une relecture hostile ; toute refonte doit les préserver.

- **Suppression et quarantaine sans course** : descente du chemin nom par nom par `NtCreateFile` relatif au parent, refus des jonctions, liens symboliques et liens physiques ; lecture, chiffrement et suppression par la même poignée ; empreinte SHA-256 de la copie analysée exigée avant quarantaine.
- **Le service n'agit jamais avec ses propres droits sur un chemin fourni** : ouverture sous le jeton du client (`ImpersonateNamedPipeClient`), analyse d'une copie faite depuis cette poignée.
- **Tube authentifié dans les deux sens** : ACL explicite, première instance, clients distants refusés, quotas par compte ; côté client, serveur identifié par le PID que donne le gestionnaire de services.
- **Moindre privilège pour la politique** : un compte standard peut renforcer la protection, jamais l'affaiblir.
- **clamd confiné** : AppContainer, objet job « kill on close », port local aléatoire, commandes d'arrêt désactivées.
- **Chaîne d'approvisionnement vérifiée** : archives épinglées par SHA-256, signature GPG exigée en CI, actions GitHub épinglées par commit.

## 5. Registre des risques ouverts

Gravité : impact si le risque se réalise. **Bloquant** : empêche l'étape de release indiquée.

| # | Risque | Gravité | Bloquant pour | Action |
|---|---|---|---|---|
| R1 | Binaires et installateur non signés. Defender détecte `optiSCAN.exe` dès que le dossier d'installation n'est plus exclu (nom de détection à relever par `Get-MpThreatDetection`). | Élevée | Release publique | Certificat de signature (OV, EV ou service de signature en ligne) ; soumission des binaires à Microsoft comme faux positif ; retrait de l'exclusion de dossier une fois la signature reconnue. |
| R2 | Candidate non commitée : 84 fichiers modifiés, 15 fichiers C# nouveaux et `installer/licenses/`, exigé par `setup.iss`. | Élevée | Bêta | Commits locaux par thème (sécurité, détection, interface, installeur, documentation), `git add -A` pour le renommage du service de relance. |
| R3 | Suite Windows non rejouée depuis le 7 octobre (630/630 alors) ; environ 3 400 lignes ajoutées depuis. Les 76 cas qui ne peuvent pas tourner sous Linux couvrent la quarantaine, le tube et les API de sécurité. | Élevée | Bêta | `dotnet test optiSCAN.Tests -c Release` sous Windows, mode développeur activé pour les tests de liens. |
| R4 | Aucun contrôle sur machine virtuelle : service installé, migration 3.0.x, Defender, installeur, relance après plantage. | Élevée | Bêta | Liste du [plan de release](RELEASE_PLAN_v3.1.md). |
| R5 | `yara64`, `yarac64` et `clamscan` analysent sous SYSTEM des contenus fournis par n'importe quel compte, sans isolation ; YARA 4.5.5 n'a pas les corrections de bornes des versions 4.5.6 à 4.5.8. Une faille d'analyseur serait une exécution de code SYSTEM. | Élevée (défense en profondeur) | Non (3.2) | Exécuter YARA et clamscan dans l'AppContainer de clamd ; compiler YARA 4.5.8 en CI. |
| R6 | Le dossier d'installation reste exclu de Defender (nécessaire tant que R1 n'est pas levé). Il n'est exclu que s'il est réservé aux administrateurs (`InstallLocationTrust`). | Moyenne | Non | Retirer après R1. |
| R7 | Détection après écriture et après lancement ; ni AMSI ni minifiltre. La surveillance du noyau voit un processus très court, mais son image n'est plus lisible une fois terminé : il n'est pas analysé (désormais journalisé). | Moyenne (limite produit) | Non | Documenté ; décision séparée pour AMSI ou un pilote. |
| R8 | Pas de canal de mise à jour du produit signé ; règles YARA-Forge figées sur la publication approuvée. | Moyenne | Non | Décision produit (V7). |
| R9 | Protection par défaut limitée à la session : le service n'est pas coché à l'installation. | Moyenne | Non | Décision produit (V6). |
| R10 | Maintenabilité : un exécutable WPF à 20 modes héberge le service SYSTEM ; conteneur singleton ; 503 `catch` sans filtre ; 78 déclarations P/Invoke réparties. | Moyenne | Non | Moteur dans une bibliothèque sans WPF, hébergé par `optiSCAN.Service` ; appels natifs centralisés (3.2). |
| R11 | xUnit 2 (« legacy »), Microsoft.NET.Test.Sdk 17.11, QuestPDF 2024.12 ; correctifs 10.0.13 disponibles pour les paquets Microsoft.Extensions et System.*. | Faible | Non | Monter et rejouer la suite sous Windows, comparer un PDF produit. |
| R12 | `clamscan` (repli quand clamd est absent) exclut par motif les gros fichiers de données d'optiSCAN dans `%LOCALAPPDATA%\optiSCAN` (`.cvd`, `.cld`, `.yar`, `.quar`…). Un exécutable nommé ainsi n'est pas vu par clamscan seul ; YARA, clamd et le temps réel lisent l'en-tête et l'analysent. | Faible | Non | Accepté. |
| R13 | Le désinstalleur ne purge que les données du compte qui désinstalle (Inno ne fournit pas le jeton de l'utilisateur d'origine à la désinstallation). | Faible | Non | Documenté. |
| R14 | « Rétablir l'origine » rend la télémétrie aux réglages par défaut de Windows, pas à une stratégie d'entreprise préexistante. La confirmation le dit. | Faible | Non | Accepté. |
| R15 | Historique Git de 303 Mo. | Faible | Passage du dépôt en public | Purge de l'historique avant publication du dépôt. |

## 6. Relecture des corrections : défauts trouvés et corrigés

Toutes les corrections de la journée ont été relues dans le diff. Six défauts sont apparus ; ils sont corrigés et testés (`AuditReviewFixesTests`).

| # | Gravité | Défaut | Correction |
|---|---|---|---|
| L1 | Moyenne | Une détection du service relevée par un compte sans droit sur le chemin ne porte que le nom du fichier. Depuis l'historique, « Quarantaine », « Supprimer » ou « Exclure » sur `bad.exe` étaient résolus dans le dossier courant et pouvaient viser un autre fichier. | `AntivirusActions` n'agit que sur un chemin complet (`Path.IsPathFullyQualified`). |
| L2 | Moyenne | Même cause : une détection du service différée par le mode jeu réapparaissait avec les boutons d'action. | Origine conservée ; elle réapparaît sous sa notification propre, sans action. |
| L3 | Moyenne | Un exécutable renommé en fichier de données (`payload.dat`) dans les dossiers de `%LOCALAPPDATA%\optiSCAN`, modifiables par la session, restait exclu de toutes les analyses : CreateProcess et rundll32 le lancent quelle que soit son extension. | L'en-tête PE est lu pour ces fichiers ; un exécutable n'est jamais exclu. Motifs de clamscan réduits aux gros fichiers binaires d'optiSCAN (R12). |
| L4 | Faible | « Rétablir l'origine » aurait supprimé une valeur de registre d'origine qui n'était pas un DWORD. | Valeur d'un autre type laissée intacte. |
| L5 | Info | La surveillance du noyau était présentée comme voyant les processus courts ; elle les voit, mais ne peut pas lire leur image une fois terminés. | Journalisé ; limite décrite en R7. |
| L6 | Info | Deux commentaires de documentation mal placés (`ExclusionSettings`, `ServiceContainer`). | Replacés. |

### Corrections de la journée, vérifiées

| Lot | Contenu | Vérification |
|---|---|---|
| A3, A4, A5, A6, A9, A10 | Exclusions Defender par processus limitées aux moteurs ; récupération du service ; `scan_path` fermé ; moteurs exigés en CI ; chemins système par l'API ; fin de message JSON en un passage | Relu ; tests réussis sous Linux sauf ceux du tube (Windows) |
| B1 à B16 | Temps réel du service non coupé au démarrage ; clés et manifeste mis de côté ; pas de double quarantaine ; pas de double surveillance quand le service protège ; OneDrive et corbeilles USB analysés ; compilation YARA sérialisée ; purge des copies orphelines ; rotation du journal ; confirmation de restauration ; et neuf autres | Relu ; `ResilienceFixesTests` 7/7 avec substitut DPAPI |
| C1 à C8 | « Exclure… » avec confirmation ; dossiers de données analysés ; détections du service notifiées et inscrites ; clamd en parallèle ; tâche rattrapée au réveil ; alertes gardées en mode jeu ; copies de sécurité bornées et utiles ; winget toutes langues avec délais | Relu ; tests réussis, sauf quatre qui supposent Windows (chemins à barre oblique inverse, WPF) |
| D1 à D7 | Fichier restauré épargné ; santé du temps réel ; instance élevée sans freshclam ni winget ; compte du tube lu sur le jeton ; retour arrière d'Optimiser ; renommage du service de relance | Relu ; tests de `FollowUpFixesTests.cs` 8/8 |

## 7. Tests

Exécution du 13 octobre au soir sous Linux, binaires Release : **714 cas, 638 réussis.** Les 76 échecs ont été classés un par un ; aucun ne met en cause la logique testée.

| Cause | Cas |
|---|---:|
| Quarantaine : suppression par poignée NT (`NtCreateFile`) | 24 |
| WPF (`WindowsBase`) non exécutable hors Windows | 18 |
| Tubes nommés Windows (ACL, usurpation) | 13 |
| API de sécurité Windows (SID, jetons) | 9 |
| Chemins à barre oblique inverse, `schtasks`, WMI, épinglage NT | 8 |
| API natives (`ntdll`, `kernel32`) | 2 |
| Moteurs ClamAV et YARA absents du poste d'audit (EICAR) | 2 |

Les tests de la quarantaine ont été rejoués avec un substitut DPAPI (chiffrement réversible de test, même interface) : les échecs restants y viennent tous de la suppression NT. Ce substitut ne prouve rien sur DPAPI lui-même ; seule la suite Windows le peut (R3).

## 8. Mesures

Code de production (`optiSCAN`, `optiSCAN.Platform`, `optiSCAN.Service`), hors `obj` et `bin`.

| Mesure | Valeur |
|---|---:|
| Lignes C# de production / fichiers | 39 115 / 215 |
| Lignes de tests / attributs `[Fact]` et `[Theory]` / cas exécutés | 11 324 / 529 / 714 |
| `catch` sans type ni filtre / `catch (Exception)` sans `when` | 191 / 312 |
| Méthodes `async void` (gestionnaires d'interface pour l'essentiel) | 22 |
| Déclarations `DllImport` | 78 |
| Fichiers de plus de 500 lignes | 22 |

Les comptes de `catch` diffèrent de ceux des audits précédents (173) : ils comptent ici chaque bloc sans filtre, y compris les captures commentées et volontaires d'annulation ou de nettoyage.

## 9. Limites de cet audit

- Aucun essai sous Windows : les conclusions sur DPAPI, les ACL, les tubes, WMI, Defender et l'installeur reposent sur la lecture du code et sur la suite exécutée le 7 octobre sur un arbre antérieur.
- La relecture couvre l'arbre de travail du 13 octobre ; le code commité avant `d18f333` a été relu par l'audit indépendant du matin et n'a pas été relu une seconde fois en entier.
- La gravité repose sur des faits de code vérifiés ; la probabilité d'exploitation reste une appréciation.
- Les notes par domaine sont un jugement d'expert ; leur pondération est donnée pour qu'on puisse la discuter.
