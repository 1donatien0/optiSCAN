# Audit 360 — optiSCAN v3.1 candidate

**Révision du 15 octobre 2026 (soir).** Elle remplace la révision du matin (6,8/10), conservée dans le [journal archivé](docs/archive/AUDIT_optiSCAN_360_journal_2026-10.md). Entre les deux, quatre risques ont été traités dans le code : isolation des analyseurs (R5), passage en logiciel libre et chaîne de signature SignPath (R1, préparé), service coché à l'installation (R9), moteur et hôte SYSTEM sans WPF (R10). Les dépendances ont été montées (R11).

## En bref

| Indicateur | Valeur |
|---|---|
| **Note globale** | **7,6 / 10** (6,8 le matin du 15 octobre ; 6,5 le 13 octobre) |
| Qualité technique (hors distribution) | **8,2 / 10** |
| Prêt à diffuser | **4,5 / 10** |
| **Note visée pour publier** | **8,0 / 10** : atteinte quand les binaires sont signés (section 2) |
| **Décision** | **Pas de diffusion publique.** Bêta fermée possible après les contrôles en machine jetable (R4). |

**Licence et signature.** optiSCAN est sous GPL v3 depuis cette révision : c'est fait et vérifié (`LICENSE.txt`, installeur, interface, avis de tiers, et l'en-tête `SPDX-License-Identifier: GPL-3.0-or-later` dans chacun des fichiers sources, contrôlé par `LicenseHeaderTests`). La licence ne signe aucun fichier. Une signature Authenticode est apposée par un certificat d'autorité ; pour un projet libre, celui de SignPath Foundation, qui ne signe qu'après acceptation du projet et sur une release compilée par GitHub Actions. La chaîne est prête et c'est désormais la seule (l'ancienne chaîne par certificat PFX est retirée du dépôt) ; elle produira la première signature au premier tag approuvé.

La note de 8 est fixée comme condition de publication. Elle ne peut pas être obtenue par le code seul : la distribution pèse 15 % et reste à 4,5 tant que `optiSCAN.exe` n'est pas signé. Le code est désormais à 8,2 hors distribution. Les trois étapes restantes, toutes hors du dépôt, sont chiffrées en section 2.

## 1. Périmètre et méthode

Branche `dev` (`c50975c`) et arbre de travail du 15 octobre au soir.

| Contrôle | Résultat |
|---|---|
| Compilation Release de la solution (6 projets), avertissements traités en erreurs | 0 erreur, 0 avertissement (Windows et Linux) |
| Suite Release sous Windows, 15 octobre au soir, avant la séparation du moteur | **733 réussis sur 734** ; l'échec (police du rapport PDF) est corrigé |
| Suite Release sous Windows (moteur séparé, filtres d’exceptions, AMSI côté service, en-têtes GPL) | **764 réussis, 0 échec** (15 octobre, 20 h 16) ; le test de la DLL AMSI native attend sa compilation (outils C++ absents du poste, exigés par la CI) |
| Revue du code du 29 octobre 2026 (branche `fix/bugs-2026-10-29`) | 8 défauts corrigés : signature du manifeste de quarantaine dépendante de la langue (quarantaine vidée au changement de langue), fenêtre ouverte par le scan planifié, analyse en erreur sur un fichier exclu, gel de l'interface au dénombrement YARA, navigation vers Antivirus jamais faite, mise à jour avec service existant (`sc create` 1073), arrêt brutal de l'hôte, dates et tailles non localisées. Compilation sans avertissement ; 6 tests ajoutés ; **suite Windows à rejouer** (770 cas). Note inchangée en attendant. |
| Confinement des analyseurs, sous Windows | Prouvé par `ScannerSandboxTests` (19 cas) : lecture hors autorisations refusée, processus enfant refusé, copies d'analyse lisibles, arrêt immédiat |
| Audit NuGet (transitifs compris) | Aucune vulnérabilité ; `System.Security.Cryptography.Pkcs` 8.0.1 tiré par PDFsharp remplacé par 10.0.13 |
| Licences | GPL-3.0-or-later ; QuestPDF (licence non libre) retiré ; PDFsharp gardé en 6.2.4, dernière version MIT |

**Non fait :** installation en machine jetable (R4), premier passage CodeQL C/C++ sur GitHub, signature.

## 2. Notation

| Domaine | Poids | Matin | Soir | Justification du soir |
|---|---:|---:|---:|---|
| Sécurité du code privilégié | 25 % | 8,0 | **9,0** | R5 corrigé : `yara`, `yarac` et `clamscan` tournent sous SYSTEM dans l'AppContainer de clamd, sans réseau, sans processus enfant, avec les seules sorties standard héritées ; une cible hors du dossier des copies est copiée par le service ; échec du confinement = analyse incomplète, jamais de repli. L'hôte SYSTEM ne charge plus WPF. Reste : YARA 4.5.5 (corrections de bornes 4.5.6 à 4.5.8 absentes, désormais confinées). |
| Efficacité de détection | 15 % | 6,5 | **7,5** | Fournisseur AMSI livré avec le service : scripts PowerShell, JScript/VBScript, macros Office et contenus .NET analysés avant exécution (fail-open). Pas de minifiltre : les fichiers restent analysés après écriture (R7). À confirmer sous Windows et en machine jetable. |
| Robustesse et exploitation | 15 % | 8,0 | 8,0 | Inchangée ; l'hôte console garde les mêmes contrôles (SYSTEM, dossier réservé aux administrateurs, verrou unique) et la relance par le service. |
| Qualité du code et maintenabilité | 10 % | 5,5 | **7,5** | `optiSCAN.Engine` : 144 fichiers du moteur dans une bibliothèque sans aucune référence d'interface (test d'architecture). `optiSCAN.Host.exe` : hôte SYSTEM à deux modes au lieu de l'exécutable WPF à vingt modes. Conteneur propre à l'hôte, notifications par interface. Les 497 blocs `catch` généraux portent un filtre qui laisse passer les erreurs fatales (`ExceptionPolicy.IsFatal`), vérifié par un test qui parcourt le code. Reste : `ServiceContainer` singleton côté interface, P/Invoke répartis dans 16 fichiers. |
| Tests et preuves | 10 % | 8,0 | **8,5** | 748 cas sous Windows dont 19 sur le confinement, plus les tests AMSI (service et DLL native) ; xUnit v3, Test SDK 18.11. CodeQL C/C++ jamais passé sur GitHub. |
| Distribution et confiance | 15 % | 4,0 | **4,5** | Licence GPL v3, politique de signature publiée, chaîne SignPath unique (workflow, configurations d'artefacts ; ancienne chaîne PFX retirée). Aucune release n'a encore été signée et Defender détecte toujours `optiSCAN.exe` sans exclusion (R1). |
| Produit | 5 % | 7,0 | **7,5** | Service de protection coché à la première installation (R9). Pas de canal de mise à jour du produit (R8). |
| Dépendances | 5 % | 7,0 | **8,0** | xUnit v3 4.0.2, Test SDK 18.11, paquets Microsoft 10.0.13, MaterialDesign 5.3.2, QuestPDF retiré. YARA reste en 4.5.5. |
| **Total pondéré** | | **6,8** | **7,6** | Hors distribution : **8,2** |

Calcul : 9,0×25 % + 7,5×15 % + 8,0×15 % + 7,5×10 % + 8,5×10 % + 4,5×15 % + 7,5×5 % + 8,0×5 % = 7,625, arrondi à 7,6. Hors distribution (poids 85 %) : 6,95 / 0,85 = 8,2.

**Chemin vers 8,0**, sans autre changement de code :

| Étape | Qui | Effet | Note |
|---|---|---|---:|
| Contrôles en machine jetable réussis (R4, `artifacts\vm`) | Mainteneur, un double-clic | Distribution 5,5 | ≈ 7,8 |
| Dépôt public, historique purgé (R15), candidature SignPath Foundation acceptée, release signée, faux positif levé auprès de Microsoft (R1) | Mainteneur | Distribution 7,5 | **≈ 8,1** |
| Premier passage CodeQL C/C++ sur GitHub | Automatique au premier push | Tests 9,0 | ≈ 8,1 |

## 3. Décision de release

| Étape | Conditions | État |
|---|---|---|
| **Bêta fermée** (testeurs informés, exclusion Defender documentée) | Suite Windows verte après la séparation du moteur ; R4 en machine jetable | Suite verte (748/748) ; R4 prêt à lancer |
| **Release publique 3.1.0** | Bêta, plus R1 (signature SignPath, faux positif levé), CodeQL C/C++ réussi, note ≥ 8,0 | ⏳ |

## 4. Points forts

Les six mécanismes de la révision précédente tiennent toujours (suppression et quarantaine sans course, service qui n'agit jamais avec ses droits sur un chemin fourni, tube authentifié dans les deux sens, moindre privilège pour la politique, clamd confiné, chaîne d'approvisionnement vérifiée). Deux s'ajoutent :

- **Analyseurs confinés** : sous SYSTEM, aucun analyseur de contenu ne s'exécute avec les droits du service. Le confinement est vérifié sous Windows par des tests qui tentent de lire un fichier non autorisé et de créer un processus enfant.
- **Code SYSTEM sans interface** : `optiSCAN.Host.exe` ne référence ni WPF ni Windows Forms ; le tube n'accepte plus `optiSCAN.exe` comme serveur.

## 5. Registre des risques ouverts

| # | Risque | Gravité | Bloquant pour | État et action |
|---|---|---|---|---|
| R1 | Aucune release signée à ce jour ; Defender détecte `optiSCAN.exe` non signé sans exclusion. | Élevée | Release publique | **Préparé.** Licence GPL-3.0-or-later, [politique de signature](docs/CODE_SIGNING_POLICY.md), `.github/workflows/release.yml`, `.signpath/`. Reste : dépôt public, candidature sur signpath.org, première release signée, soumission du faux positif à Microsoft. |
| R4 | Aucun contrôle en machine jetable. | Élevée | Bêta | **Prêt.** `artifacts\vm\optiSCAN-check.wsb` (Windows Sandbox) installe, vérifie service, relances, EICAR, confinement, désinstallation, et écrit `vm-results.txt`. |
| R5 | Analyseurs non isolés sous SYSTEM. | — | — | **Clos.** Voir [SECURITY.md](SECURITY.md). YARA 4.5.8 en CI reste souhaitable (défense en profondeur). |
| R6 | Dossier d'installation exclu de Defender (tant que R1 n'est pas levé). | Moyenne | Non | Retirer après R1. |
| R7 | Pas de minifiltre : fichiers analysés après écriture et après lancement (AMSI couvre les scripts avant exécution depuis 3.1). | Moyenne | Non | Chantier 3.2 : pilote noyau, signature Microsoft (Partner Center, certificat EV) ; prérequis dans `native/optiSCAN.Minifilter/README.md`. |
| R8 | Pas de canal de mise à jour signé du produit. | Moyenne | Non | Décision produit. |
| R9 | Protection limitée à la session par défaut. | — | — | **Clos.** Service coché à la première installation (`checkedonce`) ; une mise à jour garde le choix précédent. |
| R10 | Maintenabilité. | Moyenne | Non | **Réduit.** Moteur et hôte sans WPF ; plus aucun `catch` général sans filtre. Reste : singleton `ServiceContainer` de l'interface, P/Invoke répartis. |
| R11 | Pile de tests et QuestPDF en retard. | — | — | **Clos.** xUnit v3, Test SDK 18.11, paquets 10.0.13 ; QuestPDF remplacé par PDFsharp/MigraDoc 6.2.4 (MIT). Dependabot n'en propose pas la 6.3+ (AGPL + licence commerciale). |
| R12 | `clamscan` exclut par motif certains fichiers de données d'optiSCAN. | Faible | Non | Accepté. |
| R13 | Le désinstalleur ne purge que le compte qui désinstalle. | Faible | Non | Documenté. |
| R14 | « Rétablir l'origine » ne restaure pas une stratégie d'entreprise préexistante. | Faible | Non | Accepté. |
| R15 | Historique Git de 303 Mo. | Faible | Dépôt public (donc R1) | Purge avant publication du dépôt. |
| R16 | Licences tierces à faire valider par SignPath : UnRAR (livré par ClamAV, non libre), règles YARA-Forge (licences par règle, dont DRL 1.1). | Moyenne | R1 | UnRAR retiré le 16 octobre 2026 après la réponse de SignPath (composants tiers sous licence acceptée) : `fetch-runtime-deps.ps1` ne copie plus `libclamunrar*`, `verify-runtime-deps.ps1` refuse une publication qui en contient, l'installeur les exclut et les supprime à la mise à jour. Reste : licences par règle de YARA-Forge (téléchargées après installation). |

## 6. Corrections du 15 octobre au soir

| Lot | Contenu | Vérification |
|---|---|---|
| R5 | `ScannerProcess` et `ClamdIsolation.StartScanner` : AppContainer de clamd sans capacité, objet job (un seul processus, arrêt sur exception, fin avec l'hôte), liste de poignées héritées limitée aux sorties ; `SandboxStaging` copie par lots les cibles hors du dossier des copies ; `yarac` écrit dans `scanner-work`, le résultat est recopié par le service. | Windows : `ScannerSandboxTests` 19/19 |
| R10 | `optiSCAN.Engine` (sans WPF), `optiSCAN.Host` (hôte SYSTEM), `INotificationSink`, `ProtectionHostContainer`, `EngineServiceRegistration` ; le service lance `optiSCAN.Host.exe` ; `PipeServerTrust` et `InstallLocationTrust` suivent. Appels Win32 isolés regroupés dans `Native/NativeMethods`. | Windows : suite 748/748, `EngineArchitectureTests` |
| R1 | GPL-3.0-or-later, politique de signature, workflow `release.yml`, configurations SignPath, métadonnées produit dans `Directory.Build.props`. Ancienne chaîne PFX supprimée (`codesign.ps1`, `sign-publish-artifacts.ps1`, `dev-codesign.ps1`, étapes `CODESIGN_*` de la CI, `-CertSubject`, `-SignPfxPath`) ; documentation alignée. | Relu ; s'exécutera au premier tag |
| R9 | Service coché à l'installation. | VM (R4) |
| R11 | Montée de version des dépendances ; PDF par MigraDoc et résolveur de polices Windows. | Windows : suite 733/734 puis correction de police |
| AMSI | Fournisseur natif réécrit (interface COM conforme, lecture de flux, nom affiché, enregistrement), serveur du tube authentifié comme côté .NET, `scan_buffer` ouvert par l'hôte avec débit, taille et cache bornés ; installeur (`regserver` avec le service), CI et release (`build-amsi.ps1 -Require`), SignPath. | `AmsiScanBufferTests` ; `AmsiProviderNativeTests` (Windows, DLL compilée) |
| R10 (suite) | `ExceptionPolicy.IsFatal` sur les 497 blocs `catch` généraux du code de production ; test qui refuse tout nouveau `catch` sans filtre. | Windows : `ExceptionPolicyTests` |
| Scripts | Seize scripts PowerShell réenregistrés en UTF-8 avec BOM (un tiret « — » cassait `publish-release.ps1` sous Windows PowerShell 5.1) ; `gpg` de Git pour Windows et sortie de publication corrigés ; test `ScriptEncodingTests`. Relais clamd : plantage au démarrage dans l'AppContainer introduit par la séparation, corrigé avant la suite verte. | Windows : suite 748/748 ; publication à rejouer |

## 7. Mesures

| Mesure | Matin | Soir |
|---|---:|---:|
| Projets de la solution | 4 | 6 (Engine, Host) |
| Fichiers du moteur sans référence d’interface | 0 | 144 |
| Modes de l'exécutable chargé sous SYSTEM | 20 | 2 |
| Cas de test exécutés sous Windows | 715 | 764 |
| `catch` sans type ni filtre / `catch (Exception)` sans `when` | 191 / 312 | 0 / 0 (497 filtrés par `IsFatal`) |
| Déclarations `DllImport` | 78 | 82 (tubes et job de l’analyseur, écran du mode jeu) |

## 8. Limites de cet audit

- La note est un jugement pondéré ; la pondération est donnée pour qu'on puisse la discuter. La révision du soir est rédigée par l'équipe qui a fait les corrections : une relecture indépendante est recommandée avant de s'appuyer sur la hausse de note.
- La séparation moteur / hôte passe la suite Windows (748/748) mais n'a pas encore été installée en machine jetable.
- La signature dépend d'un tiers (SignPath Foundation) et de son acceptation du projet.
