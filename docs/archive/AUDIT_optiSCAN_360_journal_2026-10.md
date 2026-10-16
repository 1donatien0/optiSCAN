# Audit 360 — optiSCAN v3 — 2 octobre 2026

Journal archivé. La note en vigueur est dans [`AUDIT_optiSCAN_360.md`](../../AUDIT_optiSCAN_360.md) : **7,4/10** au soir du 15 octobre 2026 (7,9 hors distribution ; 6,8 le matin ; 6,5 le 13 octobre ; 6,4 à l'audit indépendant).

Cet audit remplace l'audit précédent (`AUDIT_optiSCAN_360.md` au commit `43da273`, noté 8,6/10), repris sans en adopter les conclusions. Il couvre l'arbre `optiSCAN-stable` (branche `dev`, point de départ `43da273 release: optiSCAN 3`), puis l'arbre de travail au fil des corrections : chaque constat est donné avec son traitement et son état final. L'ensemble prépare la candidate **v3.1 / 3.1.0**, qui reste non publiée jusqu'aux contrôles Windows et GitHub du [plan de release](RELEASE_PLAN_v3.1.md). Les évolutions prévues après 3.1 figurent dans [ROADMAP.md](ROADMAP.md).

La **revue 360 du produit** ([série V](#48-revue-360-du-produit--v1-à-v13)) réexamine ensuite l'ensemble du produit sur l'arbre courant, sans reprendre les conclusions des séries précédentes. Ses treize constats révisent la note ([section 7](#7-notation)) et s'ajoutent aux [réserves](#9-réserves-ouvertes-et-conditions-de-clôture) ; neuf sont depuis corrigés dans le code, en attente de validation Windows.

Un **audit indépendant du 13 octobre 2026** ([section 13](#13-audit-indépendant-du-13-octobre-2026)) note le produit 6,4/10 ; ses constats et ceux de sa revue ligne à ligne sont pour la plupart corrigés dans l'arbre de travail, sans commit ni exécution des tests sous Windows.

## Méthode et niveau de preuve

- **Lecture statique** des quatre projets .NET (`optiSCAN`, `optiSCAN.Platform`, `optiSCAN.Service`, `optiSCAN.Tests`), du code natif, de l'installeur Inno, des scripts PowerShell et de la CI. Les chemins sensibles (quarantaine, suppression sûre, IPC, isolation clamd, politique de l'hôte, DACL) ont été relus ligne à ligne ; chaque constat cite un fichier et une ligne vérifiés dans l'état examiné.
- **Recherches quantitatives** : secrets, `TODO`/`FIXME`, captures vides, sync-over-async, `DateTime.Now`.
- **Compilation réelle** du fournisseur AMSI contre l'en-tête `amsi.h` du Windows SDK 10.0.16299, avec MinGW-w64 (`-fsyntax-only`).
- **Inspection binaire** de `installer/output/optiSCAN_Setup_v3.0.0.exe` : en-tête PE, répertoire de sécurité Authenticode. Le contenu n'a pas pu être listé (`innoextract` 1.9 ne lit pas Inno 6.7.0).
- **Mesures sur binaires réels** : clamd (INSTREAM direct et à travers un relais), YARA 4.5 (`-C`, `--scan-list`, fichiers illisibles), vérification GPG des archives ClamAV, empreintes des archives officielles retéléchargées.
- **Builds et tests sous Linux** (SDK .NET 10, `EnableWindowsTargeting`) après chaque lot de corrections.
- **Windows, 7 octobre 2026** : suite Release exécutée sur Windows, 630 réussis, 0 échec, 0 ignoré (SDK 10.0.401), dont le test de charge du watcher réel. Sorties intermédiaires isolées dans `%TEMP%` après un refus d'accès ACL dans `optiSCAN/obj`. **Non fait** : installation et validation du service sur une VM, vérification visuelle de l'interface/installeur et tests dynamiques avec privilèges (jonction dans `C:\Windows\Temp`, squat). Ces points restent en [section 9](#9-réserves-ouvertes-et-conditions-de-clôture).
- **Revue 360 du produit (série V)** sur l'arbre courant (`d18f333` et modifications non commitées) : relecture statique du service et de l'hôte, de la surveillance des processus, du temps réel, des moteurs, de l'installeur, de la publication, du canal de mise à jour et des licences tierces. Aucun build ni test relancé pour cette passe.

Échelle de confiance : **Prouvé** (compilation ou lecture sans ambiguïté), **Élevée** (le code ne laisse pas d'autre lecture raisonnable), **Probable** (dépend d'un comportement Windows ou d'une séquence à observer).

Les constats sont regroupés en séries, selon le moment de l'examen où ils sont apparus :


| Série       | Origine                                                                                                             | Nombre               |
| ----------- | ------------------------------------------------------------------------------------------------------------------- | -------------------- |
| **N1–N14**  | État initial (`43da273`), en plus des cinq constats de l'audit antérieur                                            | 14                   |
| **R1–R10**  | Révélés ou introduits par les premiers correctifs                                                                   | 10 (+ 2 sans numéro) |
| **E, M, F** | Relecture ligne à ligne des chemins sensibles : gravité élevée, moyenne, faible                                     | 12 + 21 + 23         |
| **X1–X11**  | Relevés en relecture des correctifs                                                                                 | 11                   |
| **Y1–Y5**   | Relecture du 7 octobre 2026 (publication, outils système, partages, ressource, logo)                                | 5                    |
| **Z1–Z9**   | Relecture approfondie du 7 octobre 2026 (frontières de privilège, clamd, couverture de détection)                   | 9                    |
| **V1–V13**  | Revue 360 du produit sur l'arbre courant (privilèges, couverture réelle, modèle par défaut, cycle de vie, licences) | 13, ouverts          |
| **A, B, C** | Audit indépendant du 13 octobre 2026 : constats A1–A15, revue ligne à ligne B1–B16, points restés ouverts C1–C8 ([section 13](#13-audit-indépendant-du-13-octobre-2026)) | 15 + 16 + 8          |




## Synthèse

**A ce jour :**

**État initial : 7,9/10.** Les 91 constats et les cinq points de l'audit antérieur sont traités : corrigés dans le code, retirés (AMSI, minifiltre, effacement de l'historique Defender), ou documentés quand il s'agit d'un choix de conception. Aucun constat de gravité critique ne reste ouvert. La relecture ligne à ligne n'a démontré aucune exécution de code à distance ni élévation directe et déterministe vers SYSTEM depuis un compte standard une fois les séries N et R corrigées, **sauf dans une installation hors** `Program Files` (X3) : le service SYSTEM s'y exécutait depuis un dossier modifiable par les utilisateurs, ce qui est désormais refusé. Les autres constats sont des affaiblissements de défense en profondeur et des ruptures de garanties annoncées, la plupart exploitables par un processus local de la même session.

**Revue 360 : 7,2/10, 7,7 attendu après validation Windows des corrections.** La revue du produit sur l'arbre courant relève treize constats ouverts, dont quatre de gravité élevée qu'aucune série précédente n'avait vus :

- avec le service, un compte standard peut faire se connecter la machine, sous le compte ordinateur, vers un partage de son choix, simplement en lançant une commande qui le cite (V1) ;
- tout scan manuel ou de clé USB **coupe** le temps réel et la surveillance des processus, sans rattrapage, jusqu'à 12 h (V2) ;
- la surveillance des processus interroge WMI une fois par seconde et ne voit pas les processus courts (V3) ;
- YARA 4.5.5 et clamscan analysent des contenus hostiles en SYSTEM, hors de l'isolation qui protège clamd (V4).

S'y ajoutent des limites de produit : protection par défaut limitée à la session de l'utilisateur (V6), aucun canal de mise à jour du produit (V7), licences tierces incomplètes (V9). Neuf constats sont corrigés dans le code et compilés, en attente de validation Windows ; V4 est documenté et reporté en 3.2 ; V6, V7 et V13 restent ouverts.

**Ce qui retient la note :**

- pas de signature Authenticode ni d'interception avant exécution (AMSI signé, minifiltre EV/WHQL) : coûts reportés de 3 à 5 ans par décision du projet ;
- aucune validation sur une vraie machine Windows des corrections, ni passage du workflow CodeQL C/C++ sur GitHub ;
- quelques limites de produit assumées, listées en [section 9](#9-réserves-ouvertes-et-conditions-de-clôture) ;
- les constats ouverts de la revue 360 (V1 à V13), en particulier V1 à V4.

---



## 1. Réexamen des cinq constats de l'audit antérieur


| #   | Constat d'origine                                           | Verdict                                                                                                                                                                                                                                                                                          | État final                                                                                                                                                              |
| --- | ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Scan IPC en LocalSystem pour tout utilisateur authentifié   | **Confirmé, mal hiérarchisé.** L'oracle de scan était un risque faible (il dit seulement si un fichier correspond à une signature). Les vrais risques du pipe étaient ailleurs : squat du nom, aucune authentification du serveur, clients distants acceptés, une seule instance bloquable (N4). | **Corrigé** (N4, R1, E4) : le service ouvre le fichier sous l'identité du client et scanne une copie privée ; quotas par compte.                                        |
| 2   | Fournisseur AMSI en échec ouvert                            | **Dépassé : AMSI n'existait pas.** La DLL ne compilait pas (N3) et n'aurait jamais été chargée (pas de clé COM `InprocServer32`). AMSI interroge tous les fournisseurs enregistrés : il n'y a pas de « fournisseur Microsoft prioritaire ».                                                      | **Retiré** de l'installeur, de la CI et de la documentation (N3).                                                                                                       |
| 3   | ClamAV et YARA ignorent le code de sortie                   | **Confirmé** (`ClamAvEngine.cs:253-255`), lignes `ERROR` ignorées aussi. Le défaut principal de détection était cependant N1.                                                                                                                                                                    | **Corrigé** : `ClassifyExit` pour clamscan, sortie YARA analysée avant le code de sortie (R10), troncature et échecs de lancement YARA remontés comme incomplets (E10). |
| 4   | Minifiltre squelette, chargement sans contrôle de signature | **Confirmé.** `FltStartFiltering` n'était jamais appelé et `fltmc load` échouait sans INF : du code mort qui écrivait dans `System32\drivers`.                                                                                                                                                   | **Neutralisé** : plus jamais copié ni chargé ; le code reste dans `native/`, hors livraison.                                                                            |
| 5   | Installeur non signé, contrôles lâches                      | **Confirmé, à recentrer.** Répertoire de sécurité PE à 0. Le « digest YARA-Forge facultatif » pesait peu à l'époque ; le vrai trou était N11 (binaires moteurs sans empreinte).                                                                                                                  | **Partiel** : empreintes, GPG et chaîne de signature en place (N11, E9, F12) ; certificat non fourni, signature reportée par décision.                                  |


Deux points de la liste « clos » de l'audit antérieur étaient aussi mal jugés : « clamd configuré sur `127.0.0.1` seulement » n'était pas un contrôle de sécurité (le loopback n'authentifie personne, N6), et l'alignement des identifiants C#/natif/Inno était sans portée puisque la DLL native ne se construisait pas.

---



## 2. État initial : constats N1 à N14



### N1 — Les scans de dossier via clamd perdent les détections · Critique · Confiance élevée

**Constat.** `UseClamdEngine = true` par défaut (`UserPreferences.cs:88`). Les scans rapide, complet et dossier passent par `RunPipelineAsync(recursive: true)`, `CompositeClamAvBackend.ScanFolderAsync`, `ClamdEngine.RunScanAsync`, puis `ClamdClient.ScanRecursiveAsync` (`CONTSCAN`). `ClamdClient.ReadResponseAsync` lisait la réponse avec une **attente maximale de 400 ms entre deux lignes** (`ClamdClient.cs:98`), alors que `CONTSCAN` n'écrit rien tant qu'il ne trouve ni menace ni erreur. Passé ce délai, la lecture était annulée et la sortie vide analysée comme « aucune menace », statut `Completed`, sans exception, donc sans repli clamscan. Sur un vrai dossier (Téléchargements, disque complet), une menace trouvée après 400 ms était silencieusement perdue.

**Traitement — corrigé.** Lecture de `nCONTSCAN` jusqu'à la fin de connexion ; une réponse incomplète ou une erreur sans résultat passe en `Error` et déclenche le repli clamscan. clamd isolé reçoit ensuite le contenu des fichiers en flux `zINSTREAM` (R4, R8), et tout fichier non lu par clamd est rescanné par clamscan (R9). Test avec un faux serveur lent.

### N2 — Exclusions Defender par nom de processus et sur un dossier inscriptible · Critique · Prouvé

**Constat.** `WindowsDefenderExclusionService.cs:16-24` et `scripts/add-defender-exclusions.ps1` excluaient `optiSCAN.exe`, `optiSCAN.Service.exe`, `clamscan.exe`, `freshclam.exe`, `clamd.exe` et `yara64.exe` **par simple nom d'image** : un malware renommé `clamd.exe` dans `%TEMP%` échappait à Defender. `%LOCALAPPDATA%\optiSCAN` (inscriptible par toute la session) était exclu de Defender et des scans d'optiSCAN : un dépôt invisible pour les deux antivirus. Aucun `Remove-MpPreference` à la désinstallation, et `SECURITY.md` ne disait pas qu'optiSCAN dégradait Defender.

**Traitement — corrigé.** Processus exclus par chemin complet sous `Program Files`, plus aucun dossier inscriptible exclu, retrait à la désinstallation. La relecture des correctifs a montré que ce n'était vrai que pour une installation sous `Program Files` (X3) et que `%LOCALAPPDATA%\optiSCAN` restait exclu des scans d'optiSCAN eux-mêmes (X7) : les deux points sont corrigés. Les exclusions héritées de 3.0.0 sont retirées à la mise à jour (R5), une fois par version, par le premier processus qui en a les droits ; les noms nus des moteurs ne sont retirés que si ceux d'optiSCAN l'étaient aussi (M21).

### N3 — Le fournisseur AMSI ne compile pas et serait mal enregistré · Élevée (fonction annoncée absente) · Prouvé

**Constat.** Compilation de `amsi_provider.cpp` contre `amsi.h` (SDK 10.0.16299) :

```
amsi_provider.cpp:112: error: 'HRESULT OptiscanAmsiProvider::CloseSession()' marked 'override', but does not override
amsi_provider.cpp:88:  error: no matching function for call to 'IAmsiStream::GetAttribute(AMSI_ATTRIBUTE, ULONGLONG*)'
amsi_provider.cpp:93:  error: no matching function for call to 'IAmsiStream::Read(unsigned char*, ULONG, ULONG*)'
amsi_provider.cpp:144: error: invalid new-expression of abstract class type 'OptiscanAmsiProvider'
```

L'échec était masqué à chaque étape : `continue-on-error: true` en CI, simple avertissement dans `stage-amsi.ps1`, `skipifsourcedoesntexist` dans `setup.iss`. Même compilée, la DLL n'aurait jamais été chargée : `PlatformRegistration.TryRegisterAmsiProvider` n'écrivait pas `HKLM\SOFTWARE\Classes\CLSID\{GUID}\InprocServer32`, `DllRegisterServer` ne faisait rien, et Windows 10 1903+ exige un fournisseur signé. Défauts secondaires : `DisableThreadLibraryCalls` sur l'EXE hôte, `DllCanUnloadNow` qui ignore les objets vivants, pipe ouvert sans SQOS et `ReadFile` synchrone sans délai. L'interface, elle, restait honnête (« AMSI : DLL absente »).

**Traitement — résolu par retrait.** Plus d'enregistrement, plus de build ni de livraison ; README et SECURITY décrivent AMSI comme non livré (R7). Le prototype reste dans `native/` : son client de pipe a quand même été durci (délais, plafond, serveur en session 0 : E4, M20) et il est couvert par le job CodeQL `c-cpp` (M19). Ses limites restantes sont listées dans SECURITY.md.

### N4 — Pipe de protection : squat, clients distants, blocage par un seul client · Élevée · Élevée

**Constat.** `ProtectionPipeAcl.cs:37` créait le pipe **sans** `FILE_FLAG_FIRST_PIPE_INSTANCE` **ni** `PIPE_REJECT_REMOTE_CLIENTS`, en lecture-écriture pour *Authenticated Users* (qui inclut les ouvertures réseau).

- **Squat du nom** pendant chaque relance de l'hôte (backoff jusqu'à 300 s), entre deux instances, et quand l'interface lançait un `--service-host` de secours sous l'identité de l'utilisateur. Aucun client ne vérifiait le serveur ; un faux serveur pouvait répondre « propre » et recevoir le jeton d'arrêt envoyé par le service. Le client .NET se connectait sans SQOS : un serveur doté de `SeImpersonatePrivilege` pouvait usurper le client SYSTEM.
- **Blocage** : une seule instance, aucun délai de lecture ; un client (y compris distant via le port 445) bloquait tous les scans et pouvait sonder l'existence de fichiers en SYSTEM.
- **Aucune usurpation au scan** : le service ouvrait le fichier en SYSTEM, avec un filtre `IsSensitivePath` purement textuel.

**Traitement — corrigé.** Première instance exigée, clients distants refusés, vérification de l'image du serveur côté client puis exigence de la session 0 (E4). Le service ouvre le fichier sous l'identité du client et scanne une copie dans `ScanStaging` (voir [3.3](#33-durcissements-complémentaires)). 16 places, au plus 2 par compte, délais de lecture (5 s entre deux octets, 10 s par requête) et d'écriture (10 s, M6), quotas de scan par compte, erreurs génériques, nouvelle tentative si le nom est pris. Repli `--service-host` utilisateur supprimé. L'opération `set_policy` ajoutée pendant ce lot était ouverte : voir R1.

### N5 — N'importe quel utilisateur peut empêcher l'hôte SYSTEM de démarrer · Élevée · Élevée

**Constat.** `App.xaml.cs:77` : l'hôte s'arrêtait si le mutex `Global\optiSCAN_ServiceHost` existait déjà. Un utilisateur standard pouvait le créer : l'hôte sortait, le superviseur relançait avec backoff et pause de 5 min toutes les 30 relances, et **la protection ne démarrait jamais**.

**Traitement — corrigé.** `--service-host` refusé hors SYSTEM, verrou sous forme de fichier dans `ProgramData\optiSCAN` (dossier repris par le service), repli utilisateur supprimé.

### N6 — clamd partagé sur 127.0.0.1:3310 entre toutes les sessions et tous les privilèges · Élevée · Élevée

**Constat.** `ClamdHost.EnsureRunningAsync` tenait clamd pour « prêt » dès que *quelque chose* répondait `PONG` sur 3310. L'hôte SYSTEM pouvait utiliser le clamd d'un utilisateur, avec une base modifiable par lui (un `.ign2` blanchit une signature) ; un utilisateur pouvait piloter le clamd SYSTEM (`SCAN`, `SHUTDOWN`) ; un processus pouvait écouter sur 3310 avant clamd et répondre `OK` à tout.

**Traitement — corrigé.** clamd tourne dans un AppContainer, sur un port aléatoire, derrière un tube nommé réservé au compte appelant ; il reçoit le contenu en flux et n'a plus besoin d'accès disque (R4, R8). Le nom du conteneur est aléatoire par installation, pour que son SID ne soit pas dérivable (M4).

### N7 — YARA sans règles sur l'installation par défaut · Élevée (détection) · Élevée

**Constat.** L'installeur n'embarquait pas de règles, `verify-runtime-deps.ps1` laissait passer leur absence, et `YaraForgeUpdater` écrivait dans `C:\Program Files\optiSCAN\rules` (`YaraForgeUpdater.cs:67`), non inscriptible par l'application `asInvoker`. Seul l'hôte SYSTEM, désactivé par défaut, pouvait y écrire : **YARA restait inopérant** chez la plupart des utilisateurs.

**Traitement — corrigé.** Règles dans `%LOCALAPPDATA%\optiSCAN\rules`, inscriptible par la session ; `RuntimeDependencies` consulte ce dossier avant celui de l'installation. La chaîne de mise à jour YARA-Forge a ensuite été épinglée et confinée (E6, E7).

### N8 — Le temps réel du service surveille le profil SYSTEM et supprime par chemin sous SYSTEM · Élevée · Élevée / Probable

**Constat.**

- `RealTimeWatchPaths` résolvait sous SYSTEM les dossiers de `systemprofile` : le service ne surveillait pas les dossiers des utilisateurs, alors que l'interface coupait son propre temps réel quand le service répondait (`ServiceContainer.cs:256-265`).
- Préférences et exclusions du service lues dans le profil SYSTEM : les réglages de l'utilisateur ne lui parvenaient jamais.
- Avec la quarantaine automatique (désactivée par défaut), `QuarantineManager.Quarantine` lisait puis supprimait **par chemin** (`File.Delete`, `:220`) dans `C:\ProgramData` et `C:\Windows\Temp` : schéma classique de suppression arbitraire par jonction menant à une élévation SYSTEM.
- `ProtectionServiceHost.Start` rejouait toute la logique de démarrage de l'interface depuis l'hôte (`sc start` sur lui-même, second `--service-host`, tâche `optiSCAN_Watchdog` créée par SYSTEM).
- Chaque menace était traitée deux fois, copie de sécurité comprise.

**Traitement — corrigé.** Mode hôte séparé de la logique de démarrage de l'interface ; dossiers des comptes surveillés ; politique machine dans `ProgramData\optiSCAN` (`HostPolicyStore`). La suppression sûre a été reprise en plusieurs étapes : parcours des dossiers parents sans traverser de jonction (R2), puis une seule poignée de la lecture à la suppression (`SafePathDelete.OpenForQuarantine`), refus des liens physiques, temps réel fermé aux jonctions (`RealTimePathGuard`) et analyse d'une copie privée (E5). Copie de sécurité faite une seule fois, à partir des octets déjà lus.

### N9 — Jeton d'arrêt écrit en SYSTEM dans un dossier potentiellement contrôlé par l'utilisateur · Moyenne · Probable

**Constat.** `ProtectionPipeShutdownToken.Persist` créait `%ProgramData%\optiSCAN\` sans ACL explicite, puis écrivait `ipc_shutdown.token` en suivant les liens. Un utilisateur qui créait le dossier avant le service pouvait lire le jeton, ou y poser une jonction pour faire tronquer et réécrire par SYSTEM un fichier arbitraire.

**Traitement — corrigé.** `[Dirs]` dans l'installeur ; `OptiScanProgramData` vérifie propriétaire et DACL, reprend le dossier (`SeTakeOwnership`/`SeRestore`) et parcourt tout son contenu sans suivre de lien. Toute entrée possédée ou autorisée pour un autre compte que SYSTEM, les Administrateurs ou le SID exact du conteneur clamd est **supprimée**, pas seulement remise à plat ; plafond de 200 000 entrées avec échec fermé.

### N10 — Tâches planifiées : chemin non cité · Moyenne (fonctionnel) · Probable

**Constat.** `TamperProtectionService.cs:55` et `ScheduledScanService.cs:49` passaient `/TR "C:\Program Files\optiSCAN\optiSCAN.exe --fullscan --quiet"` sans guillemets internes : schtasks coupait à `C:\Program`, et le scan planifié comme le watchdog échouaient. Le commentaire « ArgumentList échappe correctement pour schtasks » était faux.

**Traitement — corrigé.** Chemin cité dans les deux tâches.

### N11 — Chaîne d'approvisionnement des moteurs · Moyenne · Prouvé

**Constat.** `fetch-runtime-deps.ps1:146,171` téléchargeait ClamAV 1.4.5 et YARA 4.5.2 **sans empreinte épinglée** ni signature, pour des binaires livrés et exécutés en SYSTEM. Actions GitHub référencées par tag.

**Traitement — corrigé.** SHA-256 dans `runtime-versions.json` avec échec en cas d'écart (empreintes vérifiées contre les archives officielles retéléchargées) ; actions épinglées par SHA (concordance vérifiée par `git ls-remote`) ; signature GPG Talos vérifiée (E9) ; marqueur `.pinned-version` ; moteurs mis à jour (voir [section 5](#5-évolutions-structurantes)).

### N12 — Élévation d'un script `.cmd` écrit dans `%TEMP%` · Moyenne · Élevée

**Constat.** `SystemTweaksService.cs:374` écrivait `optiscan_admin_<guid>.cmd` dans `%TEMP%` puis le lançait via `runas` : tout code de la session pouvait le modifier avant le consentement UAC.

**Traitement — corrigé.** Relance élevée de `optiSCAN.exe` avec des identifiants d'action en liste blanche ; plus aucun script réinscriptible. Le même schéma sur un autre script est traité en R3.

### N13 — Installeur : effets de bord et contexte utilisateur · Moyenne · Élevée / Probable

**Constat.** Écritures `HKCU` et `{localappdata}` sous élévation (donc dans le profil de l'administrateur quand un utilisateur standard s'élève avec d'autres identifiants) ; `InitializeUninstall` démontait service, tâches et `ProgramData` avant la confirmation ; runtime .NET Desktop téléchargé et exécuté en admin sans empreinte, alors que le publish était autonome ; `IsDotNet8Installed` répondait vrai pour n'importe quel .NET.

**Traitement — corrigé, sauf signature.** HKCU écrit via `ExecAsOriginalUser`, plus rien de démonté avant confirmation, plus de téléchargement de runtime, profil de publication autonome. La chaîne de signature est prête mais inactive (voir orig. 5, F12).

### N14 — Mineurs


| Point                                                                               | Traitement                                                         |
| ----------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `ex.Message` renvoyé tel quel au client du pipe                                     | **Corrigé** : erreurs génériques.                                  |
| `TryCreateSafetyCopy` laissait une copie **en clair** du malware, parfois en double | **Corrigé** : copie chiffrée par DPAPI, faite une seule fois (F5). |
| Mutex d'interface `Global\optiSCAN_UniqueInstance` bloquant le second utilisateur   | **Corrigé** : `Local\`.                                            |
| SecureStore : HMAC peu utile dans un blob DPAPI, enveloppe sans HMAC acceptée       | **Corrigé** avec F3 (clé héritée refusée).                         |
| `TryLoadMinifilter` ne recopiait jamais un `.sys` plus récent                       | **Sans objet** : minifiltre plus chargé.                           |


---



## 3. Constats révélés par les premiers correctifs : R1 à R10



### 3.1 R1 à R7



#### R1 — `set_policy` non authentifiée : n'importe quel utilisateur coupe la protection SYSTEM · Critique · Prouvé

**Constat.** `ProtectionPipeServer.Dispatch` transmettait `set_policy` à `HostPolicyStore.TryApply` sans contrôle de l'appelant. Un programme d'un utilisateur standard pouvait envoyer `{"op":"set_policy","rt":false,"monitor":false,…}` : le service SYSTEM arrêtait temps réel, surveillance et mises à jour, et l'écrivait durablement. Aucun test ne couvrait `set_policy`.

**Traitement — corrigé.** Un compte standard peut seulement **renforcer** la protection (activer temps réel, surveillance, mises à jour, scan USB). **Réduire** la protection ou toucher à la quarantaine automatique exige SYSTEM ou un administrateur élevé, vérifié sur le jeton usurpé (`TokenElevation` et appartenance au groupe). L'interface se relance alors élevée (`--push-host-policy`, une invite UAC) ; un refus est journalisé. `host-policy.json` est écrit de façon atomique (M7) et n'est lu que s'il est fiable (voir [3.3](#33-durcissements-complémentaires)). Testé.

#### R2 — Suppression arbitraire en SYSTEM atteignable par un utilisateur standard · Élevée · Élevée

**Constat.** R1 permettait d'activer la quarantaine automatique SYSTEM ; l'hôte surveillait désormais `C:\Users\*\Downloads`, `Desktop`, `Temp` et `Startup` ; `QuarantineManager.Quarantine` lisait le fichier, puis `SafePathDelete.Delete` le rouvrait par chemin, avec `FILE_FLAG_OPEN_REPARSE_POINT` qui ne protège que le dernier composant. Remplacer un dossier **parent** par une jonction pendant le scan (plusieurs secondes) faisait supprimer par SYSTEM un fichier de même nom sous `System32`.

**Traitement — corrigé.** R1 fermé ; puis une seule poignée de la lecture à la suppression : parents parcourus nom par nom sans traverser de jonction, fichier ouvert en lecture et suppression avec partage en lecture seule (personne ne peut le renommer, le remplacer ni le modifier tant qu'elle est ouverte), lien refusé, liens physiques refusés (`IsSoleName`), suppression par `FileDispositionInfo` sur la même poignée, annulée si le manifeste ne peut pas être enregistré. Les points de réanalyse cloud (OneDrive) restent traversables : seuls les « substituts de nom » sont refusés. La quarantaine automatique revérifie l'empreinte du contenu analysé avant de supprimer.

#### R3 — Script lancé en SYSTEM au démarrage depuis un dossier que l'utilisateur peut préparer · Élevée (conditionnelle) · Probable

**Constat.** `SystemTweaksService.WriteDefenderHistoryHelper` écrivait `C:\ProgramData\optiSCAN\clear-wd-history.cmd`, exécuté par une tâche `ONSTART /RU SYSTEM`, sans reprendre le dossier ; `[Dirs] Permissions:` n'ajoute que des ACE. Un utilisateur pouvait créer le script d'avance et le modifier ensuite. Sur le fond, effacer l'historique de Defender n'a pas sa place dans un antivirus ; l'action vidait même sa quarantaine.

**Traitement — corrigé par retrait.** Un premier correctif remplaçait le script par l'exécutable installé (`optiSCAN.exe --clear-defender-history`), toujours lancé par une tâche `ONSTART /RU SYSTEM`, et ne vidait plus la quarantaine de Defender : il effaçait l'historique des détections (`Scans\History\Service`, `mpenginedb.db`*) et laissait les fichiers en quarantaine. Le vecteur du script préparé d'avance disparaissait, mais la fonction restait dans l'interface et un test en vérifiait l'existence (X4). L'action est maintenant réellement supprimée : case du panneau Optimiser, identifiant `defender-history` de `--apply-tweaks` (ignoré s'il est reçu), code d'effacement et chaînes FR/EN. `SystemTweaksService.RemoveDefenderHistoryTask` retire la tâche, le script et le compteur d'essais laissés par une version antérieure : au démarrage de l'hôte, au nettoyage unique par version (`DefenderLegacyCleanup`), et lorsque l'ancienne tâche lance encore `--clear-defender-history`, qui ne fait plus que la supprimer.

#### R4 — clamd isolé ne peut pas lire les fichiers à scanner · Moyenne (fonctionnel, performance) · Probable

**Constat.** Dans son AppContainer, clamd n'avait accès qu'à ses binaires, sa configuration et sa base. Il devait répondre `ERROR` sur presque tout fichier utilisateur, d'où un repli clamscan à chaque scan (rechargement complet de la base, plusieurs secondes et environ 1 Go par appel) et des fichiers sautés en silence avec le seuil `FilesScanned == 0`.

**Traitement — corrigé.** L'hôte ouvre le fichier avec ses propres droits et l'envoie à clamd en `zINSTREAM` (`ClamdClient.InstreamAsync`), testé contre un vrai clamd (EICAR détecté, fichier propre de 3 Mo, 20 envois de suite, limite de 100 Mo côté client). Toute ligne `ERROR` rend le scan incomplet (R9).

#### R5 — Anciennes exclusions Defender par simple nom conservées à la mise à jour · Moyenne · Élevée

**Constat.** `LegacyBareProcessNames` ne servait qu'à la désinstallation : une mise à jour gardait `clamd.exe`, `optiSCAN.exe`, etc. exclus par nom.

**Traitement — corrigé.** `--cleanup-legacy-defender-exclusions` lancé par l'installeur, puis `DefenderLegacyCleanup` exécuté **une fois par version** (marqueur `HKLM\SOFTWARE\optiSCAN`) par le premier processus qui en a les droits : installeur, service au démarrage ou instance élevée. Retire les noms nus de 3.0.0 et toute exclusion `…\AppData\Local\optiSCAN` de tous les profils. Pas de marqueur si Defender est absent (F16).

#### R6 — Faibles


| Point                                                                                                                                      | Traitement                                                                                                                                    |
| ------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Pipe : quatre clients envoyant un octet toutes les 4,9 s occupaient toutes les places ; `ListenLoopAsync` abandonnait si le nom était pris | **Corrigé** : délai global de 10 s par requête, quotas par compte, nouvelle tentative avec attente croissante (1 à 30 s).                     |
| `scan_path` : accès contrôlé sous l'identité du client, puis réouverture en SYSTEM                                                         | **Corrigé** : copie sous l'identité du client (voir [3.3](#33-durcissements-complémentaires)).                                                |
| Reprise de ProgramData : fichiers déjà présents laissés à l'utilisateur                                                                    | **Corrigé** : contenu étranger supprimé (N9).                                                                                                 |
| Mode `--clamd-stub` présent dans le binaire livré                                                                                          | **Corrigé** : compilé seulement hors publication (`OPTISCAN_TEST_HOOKS`) ; la CI échoue si le faux serveur réapparaît dans le binaire publié. |




#### R7 — Documentation en retard sur le code

**Constat.** `README.md` (16 mentions d'AMSI, clamd sur « TCP 127.0.0.1:3310 ») et `SECURITY.md` (« CodeQL native AMSI ») décrivaient l'architecture d'avant.

**Traitement — corrigé.** README, SECURITY, guide de distribution et documents de confidentialité distinguent les modes utilisateur et SYSTEM, les états de scan incomplets et les composants AMSI/minifiltre non livrés.

### 3.2 R8 à R10 et défauts découverts en corrigeant


| #      | Constat                                                                                                                                                                                                        | Traitement                                                                                                                                                                                                                                                                       |
| ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R8     | Pour laisser clamd lire les fichiers, l'hôte réécrivait la DACL de chaque dossier parent jusqu'à `C:\` pour chaque fichier scanné.                                                                             | **Supprimé.** INSTREAM (R4) : `ClamdIsolation` n'écrit plus d'ACL que sur ses propres dossiers, une seule fois.                                                                                                                                                                  |
| R8 bis | Les deux relais (`ExchangeAsync` côté hôte, `Pump` dans le conteneur) alternaient requête et réponse et auraient bloqué sur INSTREAM.                                                                          | **Corrigé.** `ClamdInstreamFramer` repère la fin de requête (bloc de longueur 0), complète un en-tête coupé et plafonne la taille relayée.                                                                                                                                       |
| R9     | Fichiers non lus par clamd sautés en silence.                                                                                                                                                                  | **Corrigé.** Chaque fichier non lu va dans `ScanResult.UnscannedFiles` et est rescanné par clamscan ; si ce repli échoue, le dossier passe en erreur. Dossiers exclus et protégés non envoyés, jonctions non suivies, fichiers OneDrive « en ligne uniquement » non téléchargés. |
| R10    | Un code de sortie YARA non nul faisait perdre les correspondances.                                                                                                                                             | **Corrigé.** Sortie analysée avant le code ; `YaraScanIncompleteException` transporte les correspondances et le scan est marqué incomplet.                                                                                                                                       |
| —      | **YARA sur une liste de fichiers ne fonctionnait pas du tout** : `yara -C règles f1 f2 …` est refusé (« can't accept multiple rules files »). Scans USB et par liste sans aucune correspondance YARA possible. | **Corrigé.** `--scan-list` avec une liste temporaire ; le repli sans règles compilées garde le vrai chemin de chaque correspondance.                                                                                                                                             |
| —      | **La fusion des résultats effaçait les erreurs** : `ScanThreatMerger` et `MultiTargetScanAggregator` rendaient toujours `Completed`.                                                                           | **Corrigé.** Un moteur qui n'a rien analysé met le scan en erreur ; une erreur partielle laisse le scan terminé avec son motif consigné ; un scan rapide ou complet n'est en erreur que si aucune zone n'a pu être analysée.                                                     |
| —      | Build Release cassé (CA1838 dans `PipeServerTrust.cs`) : le job CI aurait échoué.                                                                                                                              | **Corrigé.** Tampons `char[]` dans `PipeServerTrust` et `ClamdIsolation`.                                                                                                                                                                                                        |




### 3.3 Durcissements complémentaires


| Point                                                     | Avant                                                                                                                                                                                           | Après                                                                                                                                                                                                                                                                                                                                                                                                    |
| --------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan_path` **: fichier remplacé entre contrôle et scan** | Accès contrôlé avec les droits du client, puis chemin rouvert en SYSTEM.                                                                                                                        | Le service ne touche plus jamais le chemin avec ses propres droits. Il ouvre le fichier sous l'identité du client (`ImpersonateNamedPipeClient`) et copie le contenu de cette poignée dans `%ProgramData%\optiSCAN\scan-staging`, réservé à SYSTEM et aux Administrateurs (`ScanStaging`). C'est la copie qui est scannée puis supprimée. Plafond de 256 Mo ; `scan_buffer` passe par le même mécanisme. |
| `scan_path` **: réponses**                                | « Propre » quand le moteur était en erreur ; réponses distinctes pour un fichier inexistant ou inaccessible.                                                                                    | « Scan incomplet » en cas d'erreur ; même réponse « Chemin refusé » dans les deux cas : plus d'oracle d'existence.                                                                                                                                                                                                                                                                                       |
| **Pipe : places et débit**                                | 4 places partagées par tous.                                                                                                                                                                    | 16 places, au plus 2 par compte (compte lu sur le jeton du client avant toute lecture) ; 30 scans par minute et 2 simultanés par compte, en plus du plafond global ; SYSTEM non limité.                                                                                                                                                                                                                  |
| **Politique déposée d'avance**                            | Un `host-policy.json` déposé avant le premier démarrage du service voyait son propriétaire corrigé, mais son **contenu** était lu tel quel (temps réel coupé, quarantaine automatique activée). | Contenu étranger supprimé à la reprise ; `HostPolicyStore.TryRead` exige `OptiScanProgramData.IsTrustedFile` (pas de lien, propriétaire SYSTEM ou Administrateurs, aucun droit pour un autre compte) et vérifie aussi l'ACL du dossier parent, sinon politique par défaut (temps réel actif, pas de quarantaine automatique). L'hôte reprend le dossier avant de lire la politique.                      |
| **Temps réel SYSTEM et jonctions**                        | Une jonction créée dans un dossier surveillé faisait analyser des fichiers situés ailleurs ; un dossier déjà jonction au démarrage était accepté.                                               | `RealTimePathGuard` : dossier refusé si un élément de son chemin est un substitut de nom (contrôlé à la constitution de la liste et à la création du watcher ; OneDrive accepté) ; fichier ouvert sans suivre de lien, chemin réel (`GetFinalPathNameByHandle`) exigé sous le chemin réel du dossier ; poignée gardée sans partage de suppression pendant l'analyse. L'analyse porte sur une copie (E5). |
| **Quarantaine : lecture puis suppression**                | Second accès par chemin entre lecture et suppression.                                                                                                                                           | Une seule poignée (voir R2) ; l'original reste en place si le manifeste ne peut pas être enregistré.                                                                                                                                                                                                                                                                                                     |
| **Liens physiques**                                       | Non examinés.                                                                                                                                                                                   | Refusés pour la suppression et la quarantaine (`IsSoleName`, `NumberOfLinks == 1`).                                                                                                                                                                                                                                                                                                                      |
| **Publication**                                           | `FolderProfile.pubxml` publiait en mode dépendant du framework alors que l'installeur n'installe plus de runtime.                                                                               | Profil autonome ; tous les scripts de publication passent `OptiscanShipping=true`. Le script `publish-release.ps1` publie désormais toujours en self-contained ; son ancien paramètre `-SelfContained` reste accepté pour compatibilité. Publication Windows à valider avant release.                                                                                                                    |


**Point conservé : le pipe de scan reste ouvert aux utilisateurs authentifiés.** L'interface de chaque compte doit pouvoir demander un scan au service. Un client n'obtient rien qu'il ne pouvait déjà lire (ouverture sous son identité), et ce qu'il peut consommer est borné par compte : 2 connexions, 30 scans par minute, 2 simultanés, 256 Mo par fichier. Restreindre le pipe au compte de la console casserait les sessions multiples et le Bureau à distance.

**Effets visibles pour l'utilisateur :**

- un fichier atteint **uniquement** par une jonction placée dans un dossier surveillé n'est plus analysé en temps réel ; il reste couvert par les scans manuels et planifiés, et le refus est journalisé ;
- pendant son analyse en temps réel (quelques centaines de millisecondes), un fichier ne peut être ni renommé ni supprimé ; l'écriture reste possible ;
- une quarantaine échoue si un autre programme tient le fichier ouvert en écriture ; le motif est journalisé ;
- au premier démarrage du service, tout ce qu'un autre compte a déposé dans `ProgramData\optiSCAN` est supprimé ;
- optiSCAN s'installe uniquement sous `Program Files` ; une installation antérieure placée ailleurs doit être désinstallée avant la mise à jour (X3) ;
- dans un build de développement ou une copie portable, le service n'est pas enregistré et aucune exclusion Defender n'est ajoutée ; seuls les moteurs, bases et règles du dossier restent exclus des scans.

---



## 4. Constats E, M et F

Relecture ligne à ligne des chemins sensibles sur l'arbre de travail corrigé (commit `1203091` et modifications locales). Ces constats sont nouveaux ou résiduels par rapport aux séries N et R ; la relecture confirme par ailleurs dans le code les corrections de ces séries (`SafePathDelete`, `OptiScanProgramData`, AppContainer, quarantaine du service). Chaque correction de comportement a un test (`AuditFollowUpTests.cs`, `QuarantineManagerSecurityTests.cs`, `YaraForgePackageIntegrityTests.cs`, `ServiceQuarantineTests.cs`).

**Légende :** ✅ corrigé · 📄 documenté (choix ou limite assumée) · ◐ corrigé, validation distante en attente.

### 4.1 Gravité élevée



#### E1 — HMAC du manifeste de quarantaine contournable par rétrogradation de version · ✅

**Constat.** `QuarantineManager.cs:122-141` et `:788-792` : `LoadManifest` ne rejetait que les manifestes non signés de `Version >= 2`. Un manifeste `Version = 1` sans HMAC et avec des entrées était accepté puis re-signé silencieusement par `MigrateUnsignedManifestIfNeeded`. Tout processus capable d'écrire `manifest.json` (inscriptible par l'utilisateur pour la quarantaine de session) pouvait injecter des entrées et, avec E2, obtenir une écriture ou une suppression arbitraire dans la portée du compte.

**Correction.** Tout manifeste sans HMAC comportant des entrées est refusé, quelle que soit sa version ; un manifeste signé ancien voit seulement son numéro de version relevé, sans re-signature. Test : manifeste v1 injecté, toujours vide au rechargement.

#### E2 — Restauration et suppression hors quarantaine non résistantes aux jonctions · ✅

**Constat.** `RestoreToPath` écrivait par `File.WriteAllBytes` et `DeleteThreatFile` supprimait par `File.Delete` (`QuarantineManager.cs:393-428`, `AntivirusActions.cs:129-144`), deux API qui suivent les liens ; `IsSensitivePath` était purement lexical. La restauration du service était déjà durcie, pas la restauration interactive.

**Correction.** `RestoreFileWriter` : création **neuve** (`FILE_CREATE`) en parcourant le chemin sans traverser de jonction (`SafePathDelete.CreateNew`), relecture du chemin réel, suppression par la même poignée s'il diffère. Utilisé par la restauration interactive et par celle du service ; plus d'écrasement (F7). `DeleteThreatFile` passe par `SafePathDelete.Delete`.

#### E3 — Injection d'arguments dans l'invocation de MpCmdRun · ✅

**Constat.** `ThreatRepairService.cs:57` interpolait le chemin de la menace dans `-File "{filePath}"` : un nom contenant `"` pouvait ajouter des options à `MpCmdRun.exe`.

**Correction.** `ArgumentList` ; chemins avec guillemet, caractère de contrôle, tiret initial ou relatifs refusés ; arrêt de l'arbre au délai (F10).

#### E4 — Confiance du client pipe fondée sur nom et dossier · ✅

**Constat.** `PipeServerTrust.cs:23-33` identifiait le serveur par le nom d'image et le dossier, sans signature ni identité. En installation portable (dossier inscriptible), un faux `optiSCAN.exe` pouvait squatter le pipe et répondre « propre ».

**Correction.** Le serveur doit en plus tourner en **session 0** ; même contrôle dans le client AMSI natif. La session 0 ne suffisant pas à elle seule (X8), le client exige aussi que le serveur soit le processus du service optiSCAN ou l'hôte qu'il a lancé. Pas de vérification Authenticode tant que les binaires ne sont pas signés.

#### E5 — Temps réel : la poignée épinglée ne protège pas du renommage d'un dossier parent · ✅

**Constat.** `PinWithinRoot` vérifiait le chemin réel, mais le scan rouvrait ensuite le fichier **par chemin** (`ScanOrchestrator.cs:78`) ; l'absence de `FILE_SHARE_DELETE` empêche de renommer le fichier, pas un dossier parent, contrairement au commentaire de `RealTimePathGuard.cs:15-16`.

**Correction.** Le temps réel copie **toutes les tailles** depuis la poignée épinglée vers `ScanStaging` et scanne la copie ; la taille source est vérifiée et une réserve de 128 Mio est gardée sur le volume temporaire. Si l'espace ou la copie manque, le résultat est une erreur avec couverture incomplète ; il n'y a aucun repli par chemin. Les menaces sont rattachées au chemin d'origine, et la quarantaine automatique exige l'empreinte du contenu analysé (sa limite indépendante de 256 Mio reste applicable).

#### E6 — YARA-Forge : digest non épinglé, SHA-256 facultatif · ✅

**Constat.** Le digest attendu venait de la même réponse API GitHub que l'URL (`YaraForgePackageIntegrity.cs:26-61`) ; s'il manquait, la validation se réduisait à la signature `PK` et à la taille.

**Correction.** L'updater n'accepte que la release `20261004`, l'asset `yara-forge-rules-core.zip`, sa taille de 1 747 609 octets et le SHA-256 de l'allowlist locale de `YaraForgePackageIntegrity`. Le digest de l'API doit égaler cette allowlist, les octets téléchargés sont revalidés et l'URL doit viser exactement cette release et cet asset. Une nouvelle release exige qu'une mise à jour d'optiSCAN approuve son empreinte : les règles hebdomadaires restent bloquées jusque-là.

#### E7 — Extraction ZIP YARA-Forge non confinée et non plafonnée · ✅

**Constat.** `Path.Combine(rulesDirectory, entry.Name)` puis `ExtractToFile(overwrite: true)` (`YaraForgeUpdater.cs:342-372`), sans contrôle de chemin ni limite de taille (`GetByteArrayAsync` en mémoire) : traversée et bombe ZIP.

**Correction.** Téléchargement en flux plafonné à 64 Mio ; décompression plafonnée (32 Mio par règle, 256 Mio au total, 5 000 fichiers, octets réellement décompressés comptés) ; chemin confiné ; extraction en dossier temporaire puis remplacement ; un paquet refusé n'installe rien.

#### E8 — Certificat racine ClamAV téléchargé depuis `main` · ✅

**Constat.** L'ancre de confiance des CVD (`clamav.crt`) était téléchargée depuis la branche `main` de Cisco-Talos et validée seulement par sa taille (`FreshclamUpdater.cs:687-703`).

**Correction.** Certificat épinglé par SHA-256 (`60200E4B…940E9D`, tag `clamav-1.5.0`, identique à `main` et au fichier embarqué), **vérifié à chaque usage** quelle que soit sa provenance ; URL de secours sur le tag. Empreinte aussi dans `runtime-versions.json`, contrôlée par `fetch-runtime-deps.ps1`.

#### E9 — Clé GPG Talos déclarée mais jamais utilisée · ✅

**Constat.** `clamavSigningKeyFingerprint` figurait dans `runtime-versions.json:7` sans être lu : seul le SHA-256 était vérifié.

**Correction.** Vérification GPG dans `fetch-runtime-deps.ps1` : clé officielle versionnée (`scripts/keys/cisco-talos.gpg`), trousseau temporaire, contrôle de l'empreinte de la clé primaire (`VALIDSIG`). Obligatoire en CI et dans `prepare-release-v3.ps1` (`-RequireSignature`). Exécutée réellement : archive 1.4.6 acceptée, archive altérée refusée.

#### E10 — Troncature silencieuse de la sortie YARA · ✅

**Constat.** Capture plafonnée à 2 Mo (`YaraEngine.cs:35,160-178`) ; au-delà, un simple avertissement et un scan « terminé » : les correspondances suivantes étaient perdues.

**Correction.** Sortie tronquée → `YaraScanIncompleteException` ; scan marqué incomplet, correspondances déjà lues conservées. Un échec de lancement de YARA est aussi remonté comme incomplet.

#### E11 — BOM UTF-8 dans `--file-list` · ✅

**Constat.** `File.WriteAllLines(listPath, existing, Encoding.UTF8)` (`ClamAvEngine.cs:187`) préfixait le premier chemin d'un BOM, qui pouvait ne pas être scanné.

**Correction.** `new UTF8Encoding(false)`.

#### E12 — Compilation YARA : sortie jamais lue, blocage et processus orphelin · ✅

**Constat.** `CompileRulesAsync` redirigeait stdout sans le lire (`YaraEngine.cs:203-242`) : `yarac` pouvait bloquer indéfiniment, et n'était pas tué à l'annulation.

**Correction.** Les deux flux sont drainés ; arrêt de l'arbre à l'annulation et au délai (10 min). Scan YARA d'un fichier : délai de 5 min, puis incomplet.

### 4.2 Gravité moyenne


| #   | Constat                                                                                                                          | Statut | Correction                                                                                                                                                                                                                                                                                                                                                                             |
| --- | -------------------------------------------------------------------------------------------------------------------------------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| M1  | Format hérité « chiffré » par XOR à constante `0x5A`, sans MAC ni nonce, toujours déchiffré (`QuarantineManager.cs:34,591-597`). | ✅      | Plus déchiffré pour une restauration ; lu seulement par la migration, et seulement si l'empreinte du manifeste signé correspond.                                                                                                                                                                                                                                                       |
| M2  | Déchiffrement `.quar` sans plafond avant allocation (`File.ReadAllBytes`).                                                       | ✅      | Taille contrôlée **sur la poignée qui sert à la lecture** (une seule ouverture, sans partage d'écriture), lecture exacte, refus si le fichier a grossi. Un premier correctif contrôlait par `FileInfo` puis rouvrait le fichier : repris.                                                                                                                                              |
| M3  | Injection possible dans `freshclam.conf` (`"` et `\n` non traités).                                                              | ✅      | Guillemets et caractères de contrôle refusés dans les valeurs.                                                                                                                                                                                                                                                                                                                         |
| M4  | SID AppContainer dérivable du nom fixe `optiSCAN.clamd` : l'isolation loopback de clamd contournable.                            | ✅      | Nom de conteneur aléatoire par installation (128 bits), stocké en ProgramData (SYSTEM) ou dans le profil (interface), lecture stricte sans ACE d'AppContainer ; ACE de l'ancien conteneur retirées sans supprimer les bases.                                                                                                                                                           |
| M5  | Aucun garde-fou contre l'exclusion de `C:\`, `C:\Windows` ou d'un lecteur entier.                                                | ✅      | Exclusion refusée pour une racine de lecteur, `%WINDIR%` et son contenu, Program Files, ProgramData, `C:\Users`, le profil courant ou un de leurs parents ; une telle exclusion déjà enregistrée est ignorée.                                                                                                                                                                          |
| M6  | Écriture de la réponse IPC sans délai.                                                                                           | ✅      | Bornée à 10 s.                                                                                                                                                                                                                                                                                                                                                                         |
| M7  | `host-policy.json` écrit de façon non atomique.                                                                                  | ✅      | `AtomicFile`.                                                                                                                                                                                                                                                                                                                                                                          |
| M8  | Aucun délai sur les sous-processus clamscan, yara et freshclam.                                                                  | ✅      | Délais globaux dans l'orchestrateur : fichier 10 min, dossier ou lecteur amovible 2 h, scan rapide 4 h, scan complet 12 h. À l'échéance, les moteurs sont arrêtés et le résultat passe en erreur avec lacune de couverture, détections déjà obtenues conservées. Plafonds par processus maintenus (YARA fichier 5 min, yarac 10 min, Defender 60 s, MpCmdRun 2 min, `--version` 30 s). |
| M9  | Une exception d'une cible interrompait tout le scan multi-cibles.                                                                | ✅      | Cible en échec consignée en erreur, les autres continuent.                                                                                                                                                                                                                                                                                                                             |
| M10 | `ScanProgressRelay` partagé sans verrou.                                                                                         | ✅      | Verrouillé.                                                                                                                                                                                                                                                                                                                                                                            |
| M11 | Journal texte concurrent : lignes d'audit perdues.                                                                               | ✅      | Écritures sérialisées, partage en écriture, nouvel essai en cas de collision.                                                                                                                                                                                                                                                                                                          |
| M12 | `GetHistory`/`GetCleanHistory` rendaient une vue vivante.                                                                        | ✅      | Copie rendue ; les listes `Threats` des sessions ne sont plus jamais modifiées sur place (copie à l'écriture sous verrou). Un premier correctif ne copiait que la liste extérieure : repris.                                                                                                                                                                                           |
| M13 | Listes d'exclusions modifiées sans verrou pendant les lectures.                                                                  | ✅      | Copie à l'écriture, jamais modifiées une fois publiées.                                                                                                                                                                                                                                                                                                                                |
| M14 | Lecture PowerShell stdout puis stderr, sans délai (blocage possible).                                                            | ✅      | Flux lus en parallèle, délai réel avec arrêt.                                                                                                                                                                                                                                                                                                                                          |
| M15 | Conversion YARA → menaces dupliquée trois fois dans l'orchestrateur.                                                             | ✅      | Factorisée (`CollectYaraAsync`, `AddYaraThreats`, `FinishYaraResult`).                                                                                                                                                                                                                                                                                                                 |
| M16 | `RiskScoringService` dépendant de l'ordre d'un dictionnaire, repli « Mineur », pénalité de taille, System32 toujours critique.   | ✅      | Tous les mots-clés évalués, le plus grave l'emporte ; nom inconnu : Majeur pour ClamAV, Mineur pour YARA seul ; plus de pénalité de taille ; System32 → Majeur (une détection y est souvent un faux positif, la supprimer casserait Windows).                                                                                                                                          |
| M17 | Constante base64 IPC de 96 Mo inatteignable face au cadrage JSON de 1 Mo.                                                        | ✅      | Alignée sur `ProtectionPipeJsonFraming.DefaultMaxBytes`.                                                                                                                                                                                                                                                                                                                               |
| M18 | `freshclam.exe` absent → « à jour ».                                                                                             | ✅      | Échec.                                                                                                                                                                                                                                                                                                                                                                                 |
| M19 | Aucune analyse CodeQL du code C/C++.                                                                                             | ◐      | Job `analyze-cpp` (`c-cpp`, `build-mode: none`) pour `native/`, plus `workflow_dispatch`. Résultat réel à confirmer au premier passage sur GitHub.                                                                                                                                                                                                                                     |
| M20 | Client AMSI natif : lecture unique sans délai ni boucle.                                                                         | ✅      | E/S avec délai de 5 s, lecture jusqu'à fermeture, plafond 1 Mio, serveur exigé en session 0.                                                                                                                                                                                                                                                                                           |
| M21 | `add-defender-exclusions` retirait des exclusions par nom nu, au risque de toucher d'autres installations.                       | ✅      | Noms nus des moteurs retirés seulement si ceux d'optiSCAN l'étaient aussi (preuve du lot 3.0.0) ; même règle dans les trois scripts du service.                                                                                                                                                                                                                                        |




### 4.3 Gravité faible


| #   | Constat                                                                                  | Statut | Correction                                                                                                                                                                                                                                                 |
| --- | ---------------------------------------------------------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| F1  | DPAPI `CurrentUser` sans entropie additionnelle.                                         | 📄     | Documenté dans SECURITY.md : une entropie ne protège pas contre du code de la même session.                                                                                                                                                                |
| F2  | Clé maîtresse jamais effacée ; `QuarantineManager` non `IDisposable`.                    | ✅      | `IDisposable`, clé effacée.                                                                                                                                                                                                                                |
| F3  | SecureStore : signer puis chiffrer, clé héritée déterministe.                            | ✅ / 📄 | Clé héritée refusée. « Signer puis chiffrer » conservé : DPAPI authentifie déjà le contenu chiffré.                                                                                                                                                        |
| F4  | Migration depuis le clair : fichier sensible laissé en clair (`.legacy`).                | ✅      | `SecureStore.TrySave` rend l'échec ; le clair et les `.legacy` ne sont supprimés que si la version sécurisée a été écrite **et relue**, sinon la migration est retentée. Un premier correctif supprimait le clair même après un échec d'écriture : repris. |
| F5  | Copie de sécurité : écart entre contrôle de taille et lecture.                           | ✅      | Une seule ouverture, taille contrôlée sur la poignée.                                                                                                                                                                                                      |
| F6  | `ServiceQuarantineAdmin.List` matérialisait toutes les entrées.                          | ✅      | `GetNewestEntries` sous verrou ; `GetEntries` rend une copie.                                                                                                                                                                                              |
| F7  | Restauration non atomique, écrasement silencieux.                                        | ✅      | Voir E2.                                                                                                                                                                                                                                                   |
| F8  | Comparaison SHA-256 du manifeste non constante en temps.                                 | ✅      | `HashMatches` en temps constant.                                                                                                                                                                                                                           |
| F9  | `AtomicFile` : nom de `.tmp` déterministe.                                               | ✅      | Nom unique par écriture.                                                                                                                                                                                                                                   |
| F10 | MpCmdRun non tué au délai ; `int.Parse` non protégé dans le parseur clamscan.            | ✅      | Arrêt au délai ; `int.TryParse`.                                                                                                                                                                                                                           |
| F11 | Horodatage de signature en HTTP.                                                         | 📄     | Voulu pour RFC 3161 : le jeton est signé par l'autorité d'horodatage.                                                                                                                                                                                      |
| F12 | Mot de passe PFX en ligne de commande, PFX en clair sur le runner.                       | ✅      | PFX importé dans le magasin, signature par empreinte (`/sha1`) dans `codesign.ps1` et `build-release-setup.ps1`, certificat retiré ensuite.                                                                                                                |
| F13 | Outils non épinglés ; `rollForward: latestFeature`.                                      | ✅      | CycloneDX 6.2.0, Inno Setup 6.7.1, SDK 10.0.401 (`rollForward: latestPatch`, CI via `global-json-file`).                                                                                                                                                   |
| F14 | Code de sortie de `sc.exe` ignoré.                                                       | ✅      | Vérifié (création, démarrage).                                                                                                                                                                                                                             |
| F15 | Temps réel : `Dispose()` libère le sémaphore pendant que des gestionnaires l'utilisent.  | ✅      | `Dispose` attend la libération, sinon laisse le sémaphore au ramasse-miettes.                                                                                                                                                                              |
| F16 | Nettoyage Defender hérité marqué « fait » sans Defender.                                 | ✅      | Pas de marqueur, nouvel essai plus tard.                                                                                                                                                                                                                   |
| F17 | `LastExclusionResult` sans synchronisation.                                              | ✅      | Sous verrou.                                                                                                                                                                                                                                               |
| F18 | `_recentScans` non borné dans `ProcessStartMonitor`.                                     | ✅      | Purge des entrées expirées au-delà de 512, puis plafond absolu de 2 048 (retour à 1 024 en rafale) ; un fichier évincé peut être réanalysé à son prochain lancement. Un premier correctif ne bornait rien tant que les entrées étaient récentes : repris.  |
| F19 | Message diffusé Windows non authentifié, doublon `IpcManager`/`SingleInstanceMessaging`. | ✅      | Demande de scan acceptée seulement si déposée depuis moins de 60 s (chemin déjà validé) ; `SingleInstanceMessaging` supprimé.                                                                                                                              |
| F20 | stderr des moteurs journalisé sans masquage des chemins.                                 | ✅      | Passé par `PathRedaction` (clamscan, yara, yarac).                                                                                                                                                                                                         |
| F21 | `ThreatInfo.Id` non stable entre sessions malgré sa documentation.                       | ✅      | Documentation corrigée : identifiant d'une détection, pas d'un fichier.                                                                                                                                                                                    |
| F22 | Processus protégés (PPL) non scannés, sans trace.                                        | ✅      | Jeton inaccessible journalisé.                                                                                                                                                                                                                             |
| F23 | `Dispose()` vide côté client ; `FilePathOverride` contourne le contrôle ACL.             | ✅      | `FilePathOverride` limité aux builds de test (`OPTISCAN_TEST_HOOKS`) ; `Dispose` documenté.                                                                                                                                                                |




### 4.4 Notes et constats complémentaires

- **Déduplication du temps réel** sensible à la casse : rendue insensible. ✅
- `verifiedOn` de `runtime-versions.json` portait une date à venir : corrigé. ✅
- **Prototype AMSI** (échec ouvert, analyse JSON par sous-chaîne), temps réel limité aux extensions « à risque », `GetStatus` ouvert aux comptes authentifiés, `clamd.conf` de session écrit dans un dossier de l'utilisateur : 📄 limites listées dans SECURITY.md.
- **X1** : `SecurityPostureService.TryRemoveExposedShares` construisait une ligne `cmd.exe` élevée à partir de noms de partage. Les noms contenant un métacaractère de cmd sont refusés et signalés comme non traités. ✅
- **X2** : `ProcessStartMonitor.Dispose()` libérait le sémaphore sans attendre les tâches lancées par les événements WMI. Les tâches sont suivies ; `Dispose` annule celles qui attendent, attend jusqu'à 10 s celles qui scannent, et ne libère le sémaphore qu'une fois toutes terminées (sinon il est laissé au ramasse-miettes). Une tâche lancée pendant l'arrêt sort sans rien réserver. ✅
- **Mineurs** : `ProtectionPipeShutdownToken.IsTrustedDirectory` jamais appelé, supprimé ; réponse `nCONTSCAN` de clamd accumulée sans plafond, désormais bornée à 16 M caractères (au-delà, réponse incomplète et repli clamscan) ; commentaire d'en-tête de `SystemTweaksService` qui décrivait encore « UN script cmd », réécrit. ✅



### 4.5 Relecture des correctifs : X3 à X11



#### X3 — Installation hors `Program Files` : binaires exécutés en SYSTEM et exclus de Defender dans un dossier modifiable par les utilisateurs · Élevée (conditionnelle) · Élevée · ✅

**Constat.** `setup.iss` laissait choisir le dossier d'installation (`DisableDirPage=auto`) sans en restreindre les droits ; un dossier créé à la racine d'un volume (`C:\optiSCAN`, `D:\Apps\optiSCAN`) hérite d'un droit de modification pour les utilisateurs authentifiés. Le service LocalSystem y lançait `optiSCAN.Service.exe` puis `optiSCAN.exe --service-host`. `PlatformProtectionBootstrap.TryInstallWindowsService` enregistrait aussi le service depuis le dossier du processus, quel qu'il soit (build de développement, copie portable). Les exclusions Defender (`CollectProcessExclusionPaths`, `OptiscanProtectedPaths`) partaient de `AppContext.BaseDirectory` sans contrôle. Un utilisateur standard pouvait remplacer un binaire et obtenir une exécution SYSTEM dans un dossier que Defender ne regardait plus.

**Correction.** `InstallLocationTrust` (`optiSCAN.Platform`) vérifie le propriétaire et la DACL du dossier, de chacun de ses parents et des exécutables : seuls SYSTEM, Administrateurs et TrustedInstaller peuvent y écrire, renommer, supprimer ou changer les droits ; les points de réanalyse sont refusés. Sans ce contrôle : le service n'est pas enregistré, le service ne lance pas l'hôte (événement dans le journal Application), l'hôte refuse de démarrer, aucune exclusion Defender n'est ajoutée et celles d'une version antérieure sont retirées, et seuls `clamav`, `rules` et `yara` restent exclus des scans. L'installeur ferme le choix du dossier (`DisableDirPage=yes`) et `PrepareToInstall` refuse tout dossier hors `{autopf}`, y compris `/DIR=` et l'ancien dossier d'une installation antérieure. Tests : ACL d'un dossier réservé, hérité de la racine, possédé par un utilisateur, modèles « héritage seulement » et création de dossier sur un parent ; dossier temporaire refusé ; exclusions Defender jamais sur un dossier modifiable.

#### X4 — R3 retiré seulement en partie : tâche SYSTEM et effacement de l'historique Defender toujours présents · Élevée · Prouvé · ✅

La version reprise effaçait l'historique des détections de Defender et laissait les fichiers de sa quarantaine en place ; la tâche de démarrage SYSTEM et la fonction elle-même restaient. Voir [R3](#r3--script-lancé-en-system-au-démarrage-depuis-un-dossier-que-lutilisateur-peut-préparer--élevée-conditionnelle--probable) : la fonction est maintenant supprimée de l'interface, des arguments et du code, et la tâche des versions antérieures est retirée. Test : `defender-history` absent de la liste blanche et ignoré par `--apply-tweaks`.

#### X5 — Actions élevées du panneau Optimiser cassées par `cmd /c` · Moyenne (fonctionnel) · Élevée · ✅

**Constat.** `RunCommandLine` lançait `cmd.exe` avec `ArgumentList = ["/c", ligne]`. .NET échappait alors chaque `"` de la ligne en `\"`, que `cmd.exe` ne comprend pas : `reg add "HKLM\…\DataCollection"` recevait des guillemets dans le nom de clé, et la ligne `schtasks` de R3 un double échappement. `for /d %%d` n'est valide que dans un fichier batch : le vidage du cache Windows Update échouait. Les tests vérifiaient le texte des commandes, jamais leur exécution.

**Correction.** Plus de `cmd`. Chaque étape est un `ElevatedCommand` : outil de `System32` appelé par son chemin complet, arguments séparés, codes de sortie acceptés explicites (service déjà arrêté ou démarré, service absent, redémarrage requis par DISM). Le cache Windows Update est vidé en C# entre l'arrêt et le redémarrage du service, sans suivre les liens. Tests : aucun argument ne contient de guillemet ni de syntaxe `cmd`, clé de télémétrie passée en un argument, vidage d'un dossier contenant un lien symbolique sans toucher sa cible.

#### X6 — Angle mort du temps réel : `%TEMP%\optiscan_scan-staging` · Moyenne · Prouvé · ✅

**Constat.** Le temps réel ignorait tout fichier sous `%TEMP%\optiscan_scan-staging\` (`ScanStaging.IsStagingPath`), un dossier de la session qu'il surveille par ailleurs : un téléchargeur qui y écrivait sa charge échappait au temps réel en mode utilisateur, le mode par défaut.

**Correction.** Seules les copies créées par `ScanStaging.Stage` et encore ouvertes sont ignorées, ainsi que les événements tardifs d'une copie déjà supprimée (pendant 2 minutes, et seulement si le fichier n'existe plus). Tests : fichier déposé dans le dossier de copie analysé, fichier recréé à l'emplacement d'une copie supprimée analysé.

#### X7 — `%LOCALAPPDATA%\optiSCAN` exclu de tous les scans d'optiSCAN · Moyenne · Prouvé · ✅

**Constat.** N2 retirait ce dossier des exclusions Defender, mais il restait une racine protégée d'optiSCAN : temps réel, scans manuels, ClamAV et YARA l'ignoraient en entier, alors qu'il est inscriptible par la session.

**Correction.** Seuls les sous-dossiers `clamav`, `clamd`, `rules`, `Quarantine` et `SafetyBackups` sont protégés. L'ancienne exclusion du dossier entier est retirée de la liste enregistrée, et ce dossier ne peut plus être exclu. Tests : fichier déposé à la racine analysé, bases, règles et quarantaine exclues, ancienne entrée retirée.

#### X8 — Le client du pipe identifiait le serveur par la session 0 · Faible à moyenne (conditionnelle) · Probable · ✅

**Constat.** `PipeServerTrust` acceptait un `optiSCAN.exe` du dossier attendu tournant en session 0. Une tâche planifiée « exécuter même si l'utilisateur n'est pas connecté » tourne aussi en session 0, sous le compte de l'utilisateur ; en installation portable, un faux serveur lancé ainsi passait le contrôle.

**Correction.** Le serveur doit en plus être le processus du service `optiSCANProtection` (PID donné par `QueryServiceStatusEx`) ou un enfant direct de ce processus créé après lui (PID parent par instantané des processus, dates de création comparées). Le client AMSI natif n'est pas livré et garde l'ancien contrôle (SECURITY.md). Test Windows : un processus quelconque est refusé.

#### X9 — Reprise de `ProgramData` : parcours par chemin · Faible (défense en profondeur) · Probable · ✅

**Constat.** `OptiScanProgramData.NormalizeChildren` testait qu'une entrée n'était pas un lien, puis énumérait, réattribuait et supprimait par chemin. Un dossier remplacé par une jonction entre les deux aurait fait réattribuer et supprimer en SYSTEM des fichiers situés ailleurs. La fenêtre n'existait qu'à la première reprise d'un dossier préparé avant l'installation.

**Correction.** Parcours récursif où chaque dossier, de la racine à l'entrée traitée, reste ouvert sans partage de suppression (avec `SeBackupPrivilege` et `FILE_FLAG_OPEN_REPARSE_POINT`) : aucun ne peut être renommé ni remplacé pendant qu'on agit sur son contenu. Une entrée non fiable est épinglée de la même façon pendant la remise à plat de ses droits ; la suppression passe par une poignée sur l'entrée elle-même (`FileDispositionInfoEx`, lecture seule ignorée), jamais par la cible d'un lien. Profondeur bornée à 64 niveaux, échec fermé au-delà.

#### X10 — Installeur : codes de sortie de `sc.exe` ignorés · Faible · Prouvé · ✅

`InstallCurrentProtectionService` ne lisait pas `ResultCode`. Un échec de `sc create` est maintenant journalisé et signalé, sans démarrer le service ; un échec de `sc start` (hors « déjà démarré ») est signalé. F14 ne couvrait que le code C#.

#### X11 — Règles YARA-Forge figées sur la publication approuvée · Faible (sécurité), moyenne (détection) · Prouvé · 📄

L'épinglage d'E6 refuse toute publication YARA-Forge plus récente que `20261004` jusqu'à une nouvelle version d'optiSCAN : sans calendrier de publication, les règles vieillissent. Limite listée en section 9 ; le renouvellement des empreintes approuvées sans republier l'application, avec vérification cryptographique et retrait d'une publication compromise, est inscrit dans [ROADMAP.md](ROADMAP.md).

### 4.6 Relecture du 7 octobre 2026 : Y1 à Y5



#### Y1 — Installeur livré avec un service qui ne démarre pas · Élevée (fonctionnel) · Prouvé · ✅

`prepare-release-v3.ps1` (sans `-SelfContained`) publiait le service à part puis ne copiait que `optiSCAN.Service.exe` (`-ErrorAction SilentlyContinue`) ; `publish-release.ps1` ne publiait pas le service ; `setup.iss` reprenait l'exe seul, en `skipifsourcedoesntexist`. Sans `optiSCAN.Service.dll` ni ses dépendances, l'hôte d'application ne démarre pas. Seule la CI publiait correctement. **Correction** : les trois scripts de publication (`prepare-release-v3.ps1`, `publish-release.ps1`, puis `installer/build-release-setup.ps1`, relevé en alignant la documentation) publient le service dans le dossier de l'application, dans le même mode ; `setup.iss` ne prend le service que par `AppPublishSource` et refuse de compiler sans `optiSCAN.Service.dll` (`/DAllowMissingService` pour un build de développement) ; `verify-runtime-deps.ps1` exige l'exe, la DLL, le `runtimeconfig.json` du service et `optiSCAN.Platform.dll`. `publish-release.ps1 -CertSubject` signe les mêmes binaires que la CI.

#### Y2 — Outils Windows lancés par nom nu · Faible (défense en profondeur) · Élevée · ✅

`sc.exe`, `schtasks.exe`, `powershell.exe`, `cmd.exe`, `fltmc.exe`, `powercfg.exe`, `taskmgr.exe`, `shutdown.exe` et `explorer.exe` étaient lancés par leur nom : la recherche de `CreateProcess` passe par le dossier courant avant System32. Même chose dans l'installeur élevé (`sc`, `taskkill`, `schtasks`, `fltmc`, `reg`, `powershell`). **Correction** : `SystemExecutables` (chemins System32, PowerShell 5.1, Explorateur) dans l'application, `{sys}\…` dans `setup.iss` ; un test refuse tout nouveau lancement par nom nu.

#### Y3 — Suppression des partages : échec intermédiaire masqué · Faible · Prouvé · ✅

Les `net share … /delete` étaient chaînés par `&` : seul le code de la dernière commande comptait. **Correction** : `BuildRemoveSharesCommand` (`cmd /d /s /c`, `net.exe` par chemin complet, dossier de travail System32) tente chaque suppression et rend 1 si l'une échoue.

#### Y4 — Ressource `optiSCAN.png` déclarée avec une autre casse que le fichier · Faible (build) · Prouvé · ✅

Le fichier est `optiSCAN.PNG` : la compilation échouait hors Windows (`BG1002`). **Correction** : déclaration alignée ; un test compare les noms des ressources à ceux du disque, casse comprise.

#### Y5 — Logo battant de l'accueil rogné · Faible (interface) · Prouvé · ✅

La colonne du bouclier faisait 160 px de large pour un logo de 190 px et un halo de 240 px : WPF rognait les deux au rectangle de la colonne, et la pulsation montrait des bords coupés. Le halo (3 s) et le logo (2,5 s) battaient aussi à deux cadences. **Correction** : zone de 200 × 200 (la hauteur utile de la rangée), logo de 180 px, halo externe gardé à 240 px par une marge négative, un seul storyboard adouci (`SineEase`) pour le halo et le bouclier.

Vérification : build Release sans avertissement ; sous Linux, 499 tests dont 280 réussis, les 219 échecs identiques nom pour nom à ceux de `8a0ef28` (environnement) ; scripts PowerShell sans erreur d'analyse. À confirmer sur Windows : compilation de `setup.iss` (contrôle ISPP) et rendu du bouclier.

### 4.7 Relecture approfondie du 7 octobre 2026 : Z1 à Z9

Relecture des frontières de privilège : pipe et politique, quarantaine du service, copies d'analyse, clés USB, nettoyeur, installeur.

#### Z1 — Nettoyeur : suppression à travers une jonction · Élevée (conditionnelle) · Élevée · ✅

`CleanDir` parcourait `Directory.EnumerateFiles(…, AllDirectories)`, qui descend dans les jonctions, puis supprimait par chemin. Un compte standard peut créer un dossier dans `C:\Windows\Temp` : une jonction vers `C:\Windows\System32` ou le profil d'un autre compte faisait supprimer ces fichiers par l'administrateur qui lançait « Temp Windows ». Même risque, avec les droits du compte, dans `%TEMP%` et les caches de navigateurs. Les chemins système venaient en outre de la variable `SystemRoot`. **Correction** : `SafeDirectoryCleaner` refuse une racine qui est un lien, énumère sans point de réanalyse et supprime chaque fichier par `SafePathDelete` (descente nom par nom, refus d'un dossier remplacé par une jonction entre l'énumération et la suppression) ; chemins par `SpecialFolder.Windows`.

#### Z2 — Copie d'analyse nommée d'après un périphérique DOS · Moyenne · Élevée · ✅

`ScanStaging` gardait le nom d'origine. Sous Windows 10, `…\scan-staging\x\COM1.txt` désigne le port COM1 : le service SYSTEM y écrivait les octets fournis par un compte standard (`scan_path` sur un fichier créé par `\\?\`, `scan_buffer`, temps réel, USB), et `NUL` donnait une copie vide, donc « propre ». **Correction** : `SafeStagingName` remplace les noms réservés (avec ou sans extension, chiffres en exposant compris), les flux nommés, les caractères interdits et les noms réduits à des points par `content` + extension.

#### Z3 — Préfixe `\\?\` et noms courts devant les dossiers protégés · Faible (défense en profondeur) · Prouvé · ✅

`IsSensitivePath` comparait des préfixes de chaînes : `\\?\C:\Windows\…` ou `C:\PROGRA~1\…` n'étaient pas reconnus. Les écritures restaient bloquées plus loin (`SafePathDelete`, contrôle du chemin réel), mais pas la suppression d'une menace en processus élevé. **Correction** : préfixe `\\?\` retiré avant comparaison, autres chemins de périphérique (`\\.\`, `GLOBALROOT`, volume par GUID) refusés, noms 8.3 développés.

#### Z4 — `scan_buffer` ouvert sans client · Faible · Prouvé · ✅

L'opération ne servait qu'au fournisseur AMSI, non livré, et restait joignable par tout compte authentifié. **Correction** : fermée (`ScanBufferEnabled`) jusqu'à la réintégration d'AMSI.

#### Z5 — Clé USB : le service suivait les jonctions · Faible · Élevée · ✅

L'énumération SYSTEM d'un support amovible descendait dans les jonctions d'une clé NTFS (vers `C:\Windows`, un autre profil), et un dossier illisible arrêtait toute une extension. **Correction** : énumération sans point de réanalyse, dossiers illisibles ignorés.

#### Z6 — `set_policy` : contrôle et écriture non atomiques · Faible · Probable · ✅

Une requête « renforcer » d'un compte standard, contrôlée juste avant qu'un administrateur ne change la quarantaine automatique, pouvait réécrire l'ancien réglage. **Correction** : contrôle et écriture sous un même verrou.

#### Z7 — Tube clamd : reconnexion à un nom recréé par un autre compte · Élevée (conditionnelle) · Élevée · ✅

Le relais clamd écoute sur `optiSCAN_clamd_<GUID>`, nom écrit dans `clamd.pipe`. La liste des tubes est lisible par tout compte, et clamd, sans objet job, survit à l'hôte. Après un arrêt ou un plantage de l'hôte, le relais disparaît ; l'hôte suivant relit le nom et s'y reconnecte (`PingOwnedAsync` puis `ClamdClient`). Un compte standard qui a recréé ce nom entre-temps recevait les octets des fichiers analysés par le service SYSTEM (`INSTREAM`) et pouvait répondre « OK » : lecture de fichiers d'autres comptes et aveuglement du temps réel. Le client se connectait en outre au niveau d'usurpation par défaut ; un compte de service disposant de `SeImpersonatePrivilege` obtenait un jeton SYSTEM utilisable. **Correction** : le client clamd (et le pont interne) n'accorde que l'identification, et exige un serveur du même compte (`PipeServerAccount`) avant d'envoyer le premier octet.

#### Z8 — Détection limitée à une liste d'extensions · Élevée (détection) · Prouvé · ✅

Le temps réel, la surveillance des processus et l'analyse des clés USB ne regardaient qu'une liste d'extensions. `.lnk`, archives (`.zip`, `.rar`, `.7z`, `.cab`), `.xll`, `.one`, `.chm`, `.cpl`, `.vbe`, `.msix`/`.appx`, `.doc`/`.xls`/`.ppt` (macros anciennes), `.rtf`, `.pdf` ne déclenchaient rien, ni un exécutable déposé en `.dat` ou `.tmp`, lancé par `CreateProcess` ou chargé par `rundll32 x.dat,Entry` (`rundll32` et `regsvr32` n'étaient pas suivis). **Correction** :

- liste élargie (`RiskyFileExtensions`) ;
- `ExecutableSniffer` : un fichier hors liste est analysé si son contenu est un PE (`MZ`, puis `PE\0\0` à `e_lfanew`). Temps réel : l'en-tête est lu une fois, après le délai de stabilisation, par une ouverture partagée qui ne gêne pas l'auteur du fichier, sans suivre de lien et sous le dossier surveillé ; un fichier qui n'est pas un PE sort aussitôt du cache de dé-duplication ;
- processus : image et arguments des hôtes (dont `rundll32`, `regsvr32`) retenus sur extension ou en-tête PE ; cible `x.dat,Entry` séparée de son point d'entrée ; tout chemin absolu entre guillemets est candidat ;
- clés USB : un seul parcours au lieu d'un par extension, exécutables (extension ou en-tête) placés avant les autres fichiers dans la limite de fichiers.

Coût : une lecture de 68 octets par fichier hors liste écrit dans un dossier surveillé, une fois le fichier stabilisé.

#### Z9 — clamd et son relais survivaient à l'hôte · Moyenne · Prouvé · ✅

Sans objet job, un arrêt brutal de l'hôte laissait clamd et le relais tourner, et c'est ce qui rendait Z7 exploitable. **Correction** : processus créés suspendus, rattachés à un objet job `KILL_ON_JOB_CLOSE` propre à l'hôte, puis relancés. Windows ferme la poignée du job à la fin de l'hôte, même sur un plantage, et termine clamd et le relais.

#### Relevés sans correction (à décider)

- **Instance élevée et données du compte** : un optiSCAN élevé (relance UAC) régénère et utilise `freshclam.conf` dans `%LOCALAPPDATA%` (directives `OnUpdateExecute`…), et peut lancer `winget.exe` trouvé dans le `PATH` du compte. Un programme du même compte, non élevé, peut s'y glisser : contournement d'UAC, pas une frontière de sécurité Windows. Piste : ne pas lancer freshclam ni winget depuis une instance élevée, ou écrire la configuration dans un dossier réservé aux administrateurs.
- **Désinstalleur** : `{localappdata}` désigne le profil du compte administrateur qui désinstalle, pas forcément celui de l'utilisateur.
- **Quotas du pipe par compte** : le compte est lu sur le PID client ; un PID réutilisé pourrait faire compter une connexion comme SYSTEM (exempte de quota). Déni de service local seulement.

Vérification : build Release sans avertissement ; sous Linux, après Z9, 579 tests dont 359 réussis ; les échecs sont ceux d'environnement de `8a0ef28` (plus un nouveau test qui passe par `WindowsIdentity`) ; les tests de liens (nettoyeur, USB) s'exécutent réellement sous Linux. À confirmer sous Windows : nettoyage de `C:\Windows\Temp` avec une jonction (mode développeur), refus de `COM1.txt`.

### 4.8 Revue 360 du produit : V1 à V13

Réexamen complet du produit sur l'arbre courant (`d18f333` et deux modifications non commitées : `Directory.Build.props`, `installer/setup.iss`), sans reprendre les conclusions des séries précédentes. Cinq angles : frontières de privilège du service, couverture de détection en conditions réelles, modèle de protection livré par défaut, cycle de vie du produit (mises à jour, publication), conformité des composants tiers. Lecture statique : aucun build ni test n'a été relancé pour cette passe (voir [section 11](#11-limites)).

**Légende :** ✅ corrigé dans le code (compilé et testé sous Linux, à valider sous Windows) · 📄 documenté, correction reportée · ⏳ ouvert.


| #   | Constat                                                                                     | Gravité                        | Confiance | État               |
| --- | ------------------------------------------------------------------------------------------- | ------------------------------ | --------- | ------------------ |
| V1  | Surveillance des processus : connexion SYSTEM vers un partage choisi par un compte standard | Élevée (conditionnelle)        | Élevée    | ✅                  |
| V2  | Temps réel et surveillance des processus suspendus pendant tout scan manuel ou USB          | Élevée (détection)             | Prouvé    | ✅                  |
| V3  | Surveillance des processus par interrogation WMI : processus courts invisibles              | Élevée (détection)             | Élevée    | ✅ / 📄             |
| V4  | YARA et clamscan analysent des contenus hostiles sans isolation, en SYSTEM                  | Élevée (défense en profondeur) | Élevée    | 📄 (3.2)           |
| V5  | Hôte SYSTEM : une exception non gérée ouvre une boîte de dialogue en session 0              | Moyenne (disponibilité)        | Probable  | ✅                  |
| V6  | Protection par défaut limitée à la session de l'utilisateur                                 | Moyenne (produit)              | Prouvé    | ⏳ décision produit |
| V7  | Aucun canal de mise à jour du produit ; règles YARA figées                                  | Moyenne (produit)              | Prouvé    | ⏳ décision produit |
| V8  | Formats d'accès initial courants hors du temps réel                                         | Moyenne (détection)            | Prouvé    | ✅                  |
| V9  | Licences des composants tiers incomplètes ou inexactes                                      | Moyenne (conformité)           | Élevée    | ✅                  |
| V10 | `ExecutableSniffer` refuse des PE valides                                                   | Faible                         | Probable  | ✅                  |
| V11 | Service affiché « en cours d'exécution » sans hôte                                          | Faible                         | Élevée    | ✅                  |
| V12 | SBOM limité aux projets .NET                                                                | Faible                         | Prouvé    | ✅                  |
| V13 | Candidate non reproductible depuis un commit                                                | Faible (processus)             | Prouvé    | ⏳ commit           |




#### V1 — Surveillance des processus : connexion SYSTEM vers un partage choisi par un compte standard · Élevée (conditionnelle : poste joint à un domaine) · Élevée · ✅

**Constat.** Avec le service installé, `ProcessStartMonitor` tourne dans l'hôte SYSTEM ; il est actif par défaut (`ProcessMonitorEnabled = true`, `UserPreferences.cs:109`). Pour un hôte de scripts (`cmd.exe`, `powershell.exe`, `rundll32.exe`…), `ExtractCommandLineCandidates` retient tout chemin entre guillemets, UNC compris (`ProcessStartMonitor.cs:17`), et chaque jeton de la ligne de commande (`:163`). `ResolvePathsToScan` appelle ensuite `File.Exists(candidate)` puis `RiskyFileExtensions.IsRiskyOrExecutable`, qui ouvre le fichier pour lire son en-tête (`:146`). Ces deux accès se font **avec le jeton du service**, avant l'ouverture sous l'identité du processus (`OpenForProcess`, `:272`). L'image du processus suit le même chemin (`:139`).

Un compte standard qui lance `cmd /c echo \\hôte\x\y`, ou `\\hôte@80\x` (WebDAV, si le client WebClient tourne), fait donc se connecter la machine, **sous le compte ordinateur**, vers un hôte qu'il choisit. Dans un domaine, c'est une coercition d'authentification NTLM du compte machine, relayable vers LDAP ou ADCS selon la configuration (signature LDAP, EPA). Hors domaine, l'effet se limite à des connexions sortantes et à l'oracle d'existence d'un fichier distant. Sans le service, le même code tourne avec le jeton de l'utilisateur et n'a pas cet effet.

**Piste.** Ne retenir que des chemins locaux (lettre de lecteur sur un volume local) ; refuser UNC, `\\?\UNC\`, chemins de périphérique et noms WebDAV avant tout accès ; faire les contrôles d'existence et d'en-tête sous `OpenForProcess`, jamais sous le jeton du service. Test : candidat UNC jamais ouvert.

**Correction.** `ProcessStartMonitor.IsLocalCandidatePath` n'accepte que les chemins absolus dont la forme commence par une lettre de lecteur et refuse UNC, WebDAV, `\\?\`, `\\.\`, lecteurs réseau, flux nommés et jetons mal découpés, sans accès disque ni réseau. Le filtre lexical s'applique à l'image du processus et à chaque candidat de la ligne de commande. L'existence et la lecture de l'en-tête sont ensuite vérifiées depuis le flux ouvert sous le jeton du processus déclencheur, jamais sous SYSTEM ; une limite de 32 chemins par lancement borne les tâches. Tests : `Review360Tests` (onze formes refusées, extraction d'une ligne `cmd` qui cite des chemins UNC).

#### V2 — Temps réel et surveillance des processus suspendus pendant tout scan manuel ou USB · Élevée (détection) · Prouvé · ✅

**Constat.** Tout scan lancé depuis l'interface (rapide, complet, dossier, fichier) appelle `_realTimeProtection.Suspend()` au début et `Resume()` à la fin (`ScanViewModel.ScanRun.cs:48`, `:127`). Le scan d'un support amovible fait de même (`RemovableDriveScanService.cs:229`, `:286`), et il se déclenche seul à l'insertion (option active par défaut). Pendant la suspension :

- les gestionnaires du watcher sortent sans rien mettre en file (`RealTimeProtection.cs:283`, `:345`), et `Resume()` ne programme aucun rattrapage ;
- `ProcessStartMonitor` ignore tous les lancements (`ProcessStartMonitor.cs:109`, branché sur `IsPaused` par `ServiceRegistration.cs:68`).

Les délais maximaux sont de 4 h pour un scan rapide, 12 h pour un scan complet (`ScanOrchestrator.cs:22-23`), 10 ou 45 min pour une clé USB (`RemovableDriveScanService.cs:18-19`). Dans l'hôte SYSTEM, l'insertion d'une clé suspend le temps réel et la surveillance des processus **du service, pour toute la machine**. Un fichier déposé dans Téléchargements ou un exécutable lancé depuis la clé pendant ce temps n'est jamais vu par le temps réel. Le README le mentionne pour l'USB (« RTP suspendue pendant le scan ») sans en tirer la conséquence.

La suspension n'a pas de nécessité technique : une lecture ne déclenche pas d'événement `FileSystemWatcher`, et les copies d'analyse sont déjà écartées par `ScanStaging.IsStagingPath`.

**Piste.** Supprimer la suspension, ou à défaut garder les événements en file et rattraper au `Resume` ; ne jamais suspendre la surveillance des processus. Test : fichier créé pendant un scan, analysé.

**Correction.** Plus aucun appel à `Suspend()` dans `ScanViewModel.ScanRun` ni dans `RemovableDriveScanService` (le paramètre `RealTimeProtection` de ce dernier est retiré) : temps réel et surveillance des processus restent actifs pendant tous les scans. `Suspend`/`Resume` restent disponibles pour un arrêt bref explicite. README corrigé. Test : garde-fou sur le code source.

#### V3 — Surveillance des processus par interrogation WMI : processus courts invisibles · Élevée (détection) · Élevée · ✅ / 📄

**Constat.** `ProcessStartMonitor.cs:69` s'abonne à `__InstanceCreationEvent WITHIN 1 … ISA 'Win32_Process'`. Cet événement intrinsèque est produit par **interrogation** : WMI compare la liste des processus une fois par seconde, et un processus créé puis terminé entre deux passages n'est jamais signalé. S'ajoutent une seconde requête WMI pour lire l'image (`TryGetExecutablePath`), une attente de 400 ms (`HandlePathAsync`), puis l'ouverture du jeton du processus : s'il a déjà quitté, le scan est sauté (`NamedPipeClientAccess.OpenForProcess`, comportement documenté dans le README).

Un `rundll32 x.dat,Entry` ou un script qui s'exécute en moins d'une à deux secondes n'est donc pas analysé ; un processus plus long l'est pendant qu'il s'exécute déjà. L'interrogation impose aussi un coût CPU permanent à `WmiPrvSE`. Le README présente ce moniteur comme un « scan au démarrage d'un processus » : c'est une analyse a posteriori, et partielle.

**Piste.** Dans l'hôte SYSTEM, `Win32_ProcessStartTrace` (événement sans interrogation, réservé aux administrateurs) ou ETW `Microsoft-Windows-Kernel-Process` ; garder la trace des images vues même quand le processus a quitté, pour une analyse différée. Corriger la documentation : contrôle postérieur au lancement.

**Correction.** `ProcessStartMonitor.Start` s'abonne d'abord à `Win32_ProcessStartTrace` (événement du noyau, sans interrogation, disponible dans l'hôte SYSTEM et une interface élevée), puis se replie sur l'ancienne requête sans droits d'administrateur ; le mode retenu est journalisé. Image et ligne de commande sont lues en une seule requête. **Reste documenté** (README, SECURITY.md) : le contrôle est postérieur au lancement, et un processus déjà terminé quand l'analyse commence n'est pas analysé. À observer sur une VM.

#### V4 — YARA et clamscan analysent des contenus hostiles sans isolation, en SYSTEM · Élevée (défense en profondeur) · Élevée · 📄

**Constat.** clamd est isolé dans un AppContainer (N6), mais `YaraEngine` (`YaraEngine.cs:199`, `:446`, `:619`) et `ClamAvEngine` (`BuildStartInfo`, `ClamAvEngine.cs:390`) lancent `yara64.exe`, `yarac64.exe` et `clamscan.exe` **avec le jeton de l'hôte** : SYSTEM dans le service, administrateur dans une interface élevée. Ces moteurs analysent des octets fournis par n'importe quel compte : fichiers des dossiers surveillés, copies `scan_path`, clés USB.

- YARA applique ses modules (`pe`, `dotnet`, `elf`…) dès que les règles les importent. La version livrée, 4.5.5, n'a pas les corrections de bornes de 4.5.6 à 4.5.8 dans ces modules ([section 5.3](#53-moteurs)).
- clamscan sert de repli pour tout fichier que clamd n'a pas lu (R9) et quand clamd échoue : un fichier qui fait échouer clamd est réanalysé hors du conteneur.

Une corruption mémoire dans un analyseur deviendrait une exécution de code SYSTEM à partir d'un fichier déposé par un compte standard. C'est précisément le risque que l'isolation de clamd devait écarter.

**Piste.** Lancer YARA et clamscan dans le même AppContainer que clamd (ou sous un jeton restreint de faible intégrité, dans un objet job sans réseau), sur la copie d'analyse déjà privée ; compiler YARA 4.5.8 dans la CI Windows. En attendant, l'indiquer dans SECURITY.md.

**Traitement.** Documenté dans SECURITY.md (modèle de menace et durcissement restant à faire). Isolation de YARA et clamscan dans l'AppContainer de clamd et YARA 4.5.8 compilé en CI reportés en 3.2 : le changement touche le lancement des moteurs et doit être validé sous Windows.

#### V5 — Hôte SYSTEM : une exception non gérée ouvre une boîte de dialogue en session 0 · Moyenne (disponibilité) · Probable · ✅

**Constat.** `App.xaml.cs:82` installe les gestionnaires d'exceptions globales **avant** la branche `--service-host` (`:198`). `ShowCrashDialog` appelle `MessageBox.Show` (`:365`), par `dispatcher.Invoke` depuis un autre thread (`:377`). Dans l'hôte (session 0, bureau non interactif), personne ne peut fermer cette boîte :

- `UnobservedTaskException` est levée sur le thread du finaliseur, qui reste bloqué ;
- pour une exception fatale, le processus ne se termine pas tant que la boîte est ouverte.

`ProtectionWindowsService` ne relance l'hôte que si le processus a quitté (`HasExited`, `ProtectionWindowsService.cs:41-46`) : un hôte figé est tenu pour sain, et la protection reste arrêtée sans relance ni alerte.

**Piste.** Aucune interface dans les modes `--service-host` et sans fenêtre : journal puis code de sortie. Contrôle de vie du superviseur par `ping` sur le pipe, avec arrêt et relance de l'hôte qui ne répond plus.

**Correction.** `App.ShowCrashDialog` n'affiche plus rien dans les modes sans fenêtre (`--service-host`, scans planifiés, actions élevées) ni hors bureau interactif (`Environment.UserInteractive`) ; une exception fatale y termine le processus (`Environment.Exit(1)`). `ProtectionWindowsService` interroge l'hôte par `ping` toutes les 15 s après 2 min de démarrage ; quatre échecs consécutifs arrêtent l'hôte, que la boucle relance avec sa politique de relance. Test : garde-fous sur le code source.

#### V6 — Protection par défaut limitée à la session de l'utilisateur · Moyenne (produit) · Prouvé · ⏳

**Constat.** La tâche `platformservice` est décochée (`installer/setup.iss:126`) : une installation par défaut n'a pas de service. Temps réel, surveillance des processus et scan USB tournent alors dans `optiSCAN.exe` (`asInvoker`) :

- ils s'arrêtent à la fermeture de session ;
- tout programme du même compte peut fermer ou terminer ce processus ;
- le watchdog relance l'interface chaque minute (`TamperProtectionService.RunWatchdogCheck`), mais un programme qui détient `Local\optiSCAN_UniqueInstance` fait croire au watchdog comme à tout nouveau lancement qu'une instance tourne déjà (`TamperProtectionService.cs:113-122`).

La plupart des durcissements des sections 2 à 4 (pipe, ProgramData, quarantaine SYSTEM, AppContainer) ne s'appliquent qu'au mode service.

**Piste.** Cocher le service par défaut une fois validé en VM (section 9), ou afficher clairement dans l'accueil « protection limitée à votre session » quand il est absent.

#### V7 — Aucun canal de mise à jour du produit ; règles YARA figées · Moyenne (produit) · Prouvé · ⏳

**Constat.** `UpdateService.CheckForUpdatesAsync` ne contacte rien et renvoie `NotConfigured`, que `AppUpdateCheckResult.Success` compte comme un succès (`UpdateService.cs:25`, `:46-71`) ; l'utilisateur est renvoyé vers SourceForge. Les règles YARA-Forge sont épinglées sur la publication `20261004` (E6, X11) et ne changent qu'avec une nouvelle version d'optiSCAN. Ensemble, une installation ne reçoit **ni correctif de sécurité ni nouvelle règle YARA** sans téléchargement manuel d'un installeur non signé, que SmartScreen présente comme « éditeur inconnu ». Seules les signatures ClamAV se mettent à jour seules.

**Piste.** Manifeste de version signé (version, URL, SHA-256, signature par une clé embarquée), vérifié au démarrage, avec notification ; canal signé distinct pour approuver de nouvelles publications YARA-Forge sans nouvelle version.

#### V8 — Formats d'accès initial courants hors du temps réel · Moyenne (détection) · Prouvé · ✅

**Constat.** Le temps réel, le scan USB rapide et la surveillance des processus ne retiennent qu'une liste d'extensions (`RiskyFileExtensions.cs:8-27`) ou un en-tête PE. Restent hors liste, notamment : `.html`/`.htm`/`.svg` (contrebande HTML, pages d'hameçonnage), `.url`, `.iqy` et `.slk` (requêtes et formules Excel), `.xlsb`, `.inf`, et les archives `.gz`, `.tgz`, `.tar`, `.xz`, `.bz2`, que ClamAV sait ouvrir. Ces fichiers ne sont vus que par les scans manuels et planifiés.

**Piste.** Étendre la liste (ClamAV et YARA les traitent), avec un test par famille ; plus durablement, détection par contenu (en-têtes d'archives, balises HTML/SVG).

**Correction.** `RiskyFileExtensions` ajoute `.html`, `.htm`, `.xhtml`, `.shtml`, `.svg`, `.mht`, `.mhtml`, `.url`, `.inf`, `.xlsb`, `.iqy`, `.slk`, `.gz`, `.tgz`, `.tar`, `.xz`, `.bz2`, `.lzh`, `.arj`. README à jour. Test : un cas par famille.

#### V9 — Licences des composants tiers incomplètes ou inexactes · Moyenne (conformité) · Élevée · ✅

**Constat.**

- **YARA** (BSD-3-Clause) est livré (`yara64.exe`, `yarac64.exe`, copie `yara32.exe`) mais absent de l'article 4 du CLUF (`LICENSE.txt:66`). La licence BSD impose de reproduire l'avis de copyright et les conditions dans la documentation d'une distribution binaire.
- **ClamAV** (GPLv2) : `fetch-runtime-deps.ps1:161` ne garde que les `.exe` et `.dll` de l'archive, donc ni le texte de la GPL ni les avis des bibliothèques embarquées (OpenSSL 3, libcurl, libxml2, PCRE2, json-c, bzip2, libssh2, nghttp2, UnRAR, dont la licence est restrictive). L'installeur ne livre que le CLUF ; un lien GitHub ne remplace pas la copie de licence exigée par la GPLv2.
- **QuestPDF** : le CLUF le donne sous « MIT License » (`LICENSE.txt:86-87`) et le README parle de « licence gratuite projets open-source » (`README.md:860`). Depuis 2023, QuestPDF est sous sa propre licence, dont le niveau Community est gratuit sous conditions (dont un chiffre d'affaires annuel inférieur à 1 M USD). optiSCAN est distribué sous un CLUF propriétaire : la condition qui s'applique est celle du chiffre d'affaires, pas celle de l'open source.

**Piste.** Dossier `licenses\` dans l'installeur (GPLv2 et avis des bibliothèques de ClamAV, BSD de YARA, QuestPDF, MaterialDesign, .NET), CLUF article 4 corrigé, mention exacte de la licence QuestPDF retenue.

**Correction.** `fetch-runtime-deps.ps1` copie `COPYING.txt` (GPLv2) et les `COPYING.`* de l'archive ClamAV dans `clamav\x64\licenses` (le contenu de l'archive 1.4.6 a été vérifié : GPL, bzip2, curl, PCRE, UnRAR, YARA, zlib…) et retélécharge si ce dossier manque ; `verify-runtime-deps.ps1` et l'installeur (`#error`) refusent une publication sans la GPL. `installer/licenses/` apporte la licence officielle de YARA 4.5.5 et `THIRD-PARTY-NOTICES.md` (tous les composants, liens vers le code source de ClamAV, offre écrite de fourniture du source pendant trois ans). CLUF article 4 et README corrigés (YARA ajouté, QuestPDF sous sa propre licence Community). Les avis d'OpenSSL, libxml2, json-c, libssh2 et nghttp2 ne figurent pas dans l'archive ClamAV : ils sont référencés par lien.

#### V10 — `ExecutableSniffer` refuse des PE valides · Faible · Probable · ✅

**Constat.** `ExecutableSniffer.cs:83` exige `64 ≤ e_lfanew ≤ 64 Kio`. Le chargeur Windows accepte un en-tête PE qui chevauche l'en-tête DOS (`e_lfanew` inférieur à 64, technique connue des « tiny PE »). Un tel binaire renommé en `.dat` échappe au temps réel, au scan USB rapide et, pour son image, à la surveillance des processus (`IsRiskyOrExecutable`).

**Piste.** Accepter `e_lfanew` à partir de 4 (aligné sur 4), ou retenir tout fichier commençant par `MZ`. Test avec un en-tête chevauchant.

**Correction.** `ExecutableSniffer` accepte `e_lfanew` à partir de 4 (`MinPeHeaderOffset`). Test : en-tête PE chevauchant reconnu ; un offset dans la signature `MZ` reste refusé.

#### V11 — Service affiché « en cours d'exécution » sans hôte · Faible · Élevée · ✅

**Constat.** Si `optiSCAN.exe` manque ou si le dossier n'est pas réservé aux administrateurs, `ProtectionWindowsService.ExecuteAsync` écrit un événement et **retourne** (`ProtectionWindowsService.cs:21`, `:30`). L'hôte .NET garde alors le service dans l'état « En cours d'exécution » : `services.msc`, une supervision ou un script d'inventaire le voient actif alors qu'aucune protection ne tourne. L'interface, elle, détecte l'absence de réponse du pipe et repasse en protection locale. Les objets `Process` des hôtes précédents ne sont jamais libérés.

**Piste.** Arrêter l'application avec un code de sortie non nul (`IHostApplicationLifetime.StopApplication`, `Environment.ExitCode`) pour que le SCM affiche l'arrêt et applique ses actions de récupération ; libérer `_hostProcess` avant chaque relance.

**Correction.** Dossier non fiable ou `optiSCAN.exe` absent : le service journalise, fixe `Environment.ExitCode = 1` et appelle `IHostApplicationLifetime.StopApplication()` ; le gestionnaire de services le voit arrêté. L'objet `Process` de l'hôte précédent est libéré avant chaque relance.

#### V12 — SBOM limité aux projets .NET · Faible · Prouvé · ✅

**Constat.** `generate-sbom.ps1:4-8` ne décrit que les trois projets .NET (paquets NuGet). ClamAV 1.4.6 et ses bibliothèques natives, YARA 4.5.5 et le runtime .NET embarqué (publication autonome) n'y figurent pas. Ce sont pourtant les composants les plus exposés aux CVE.

**Piste.** Ajouter des composants CycloneDX pour les moteurs et leurs DLL (version, SHA-256 déjà épinglés dans `runtime-versions.json`) et pour le runtime publié.

**Correction.** `generate-sbom.ps1` produit aussi `optiSCAN-native-bom.json` (CycloneDX 1.5) : ClamAV et YARA avec version, empreinte SHA-256 épinglée et licence, et les bibliothèques livrées avec ClamAV. Exécuté et vérifié sous `pwsh` 7.4. Le runtime .NET embarqué n'y figure pas encore.

#### V13 — Candidate non reproductible depuis un commit · Faible (processus) · Prouvé · ⏳

**Constat.** Deux fichiers de publication sont modifiés sans être commités : `Directory.Build.props` (satellites limités à `en;fr` en publication) et `installer/setup.iss:133` (exclusion de `bin\`* et `*.pdb` du dossier publié). La CI construit depuis les commits ; la validation Windows du 7 octobre portait sur un autre état. L'exclusion `bin\*` n'est pas expliquée : si un dossier `bin` apparaît dans la publication, c'est le signe d'une sortie mal placée, que l'exclusion masquerait.

**Piste.** Commiter avec leur justification, puis refaire publication, `verify-runtime-deps.ps1` et compilation ISCC sur ce commit.

**Traitement.** Ouvert : les fichiers modifiés pendant cette revue s'ajoutent aux deux fichiers non commités. À commiter puis republier, comme indiqué.

#### Relevés mineurs de la revue

- `scan_path` **bloque un thread du pool** pendant tout le scan (`ProtectionPipeServer.cs:437`, `GetAwaiter().GetResult()`), jusqu'à 16 à la fois. Dans l'hôte, cela peut retarder les gestionnaires du temps réel qui partagent ce pool.
- **Politique machine poussée depuis les préférences de chaque compte** à chaque changement de réglage (`HostPolicyStore.PushToService`). Sur un poste partagé, un compte standard dont les réglages sont plus faibles reçoit une invite UAC qu'il ne peut pas satisfaire ; un administrateur qui valide impose son choix à tous les comptes. Comportement cohérent avec R1, à expliquer dans l'interface.
- `OverviewControl.LaunchFixUri` lance `control.exe` et les `.exe` des recommandations par nom nu via le shell (Y2 ne couvre pas ce chemin). Les URI sont internes ; risque faible.

---



## 5. Évolutions structurantes



### 5.1 Couverture des scans et surveillance


| Domaine                   | Changement                                                                                                                                                                                                                                                                                             | Effet                                                                                                                |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------- |
| Couverture                | L'énumération remonte les erreurs d'accès, fichiers hors ligne et points de réanalyse ignorés ; l'agrégateur ClamAV/YARA et les scans multi-cibles conservent erreurs et lacunes ; l'historique distingue erreur, annulation et résultat sain ; le pipe ne répond « propre » qu'après un scan terminé. | Une erreur connue ou une zone omise ne devient plus un résultat propre.                                              |
| Temps réel                | Les écritures repoussent le délai de 500 ms ; le fichier doit ensuite rester stable, dans une limite de 20 s. Une perte d'événements recrée le watcher et parcourt les fichiers à risque existants.                                                                                                    | Moins de scans pendant les écritures ; rattrapage après dépassement (un rattrapage échoué est seulement journalisé). |
| Surveillance au lancement | Le moniteur WMI ouvre le fichier sous le jeton du processus déclencheur, copie au plus 256 Mio en staging et calcule le SHA-256 de la copie ; la quarantaine automatique compare le contenu courant à ce hash avant toute suppression.                                                                 | Pas de scan d'octets inaccessibles au processus ; pas de quarantaine d'un contenu modifié depuis l'analyse.          |
| Journaux                  | `PathRedaction` masque les segments de profils Windows standard dans les messages, exceptions et traces d'`AppLogger`.                                                                                                                                                                                 | Exposition réduite des noms de profils usuels, sans garantie pour les chemins personnalisés.                         |




### 5.2 Quarantaine du service SYSTEM


| Avant                                                                                                                                                                                   | Après                                                                                                                                                                                                                                                                                                                     |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `%LOCALAPPDATA%` de `systemprofile`, avec une clé DPAPI SYSTEM distincte : invisible de l'interface, laissé à la désinstallation, détections absentes de l'historique de l'utilisateur. | `%ProgramData%\optiSCAN\Quarantine`, sous le dossier repris par `OptiScanProgramData`. `QuarantineManager.DefaultDirectory()` choisit ce dossier quand le processus est SYSTEM ; si ProgramData n'est pas fiable, l'ancien emplacement est gardé.                                                                         |
| Aucune migration.                                                                                                                                                                       | `ServiceQuarantineStore.MigrateLegacy` déplace l'ancien dossier au premier démarrage ; `RebaseRelocatedBlobs` rattache chaque entrée à son nouveau fichier et re-signe le manifeste.                                                                                                                                      |
| Aucune conservation.                                                                                                                                                                    | Éléments de plus de **90 jours** supprimés, 2 minutes après le démarrage puis toutes les 24 h.                                                                                                                                                                                                                            |
| Aucune gestion.                                                                                                                                                                         | Cinq opérations sur le pipe (`quarantine_summary`, `_list`, `_restore`, `_delete`, `_purge`), sans changer `ProtocolVersion`. Le résumé est ouvert à tout compte authentifié ; la liste (chemins de tous les comptes) et les actions exigent `IsElevatedAdministrator`. Liste bornée aux 2 000 éléments les plus récents. |
| —                                                                                                                                                                                       | **Restauration sans écriture SYSTEM** : le service déchiffre et vérifie le SHA-256 ; le fichier est créé sous le jeton usurpé de l'administrateur par `RestoreFileWriter` (jamais d'écrasement, sinon `nom_restored.ext`), puis son chemin réel est relu ; destinations relatives ou système refusées.                    |
| —                                                                                                                                                                                       | **Interface** : bandeau « Quarantaine du service : N élément(s)… » et bouton **Gérer (administrateur)** ; relance UAC avec `--service-quarantine`, qui n'ouvre que `ServiceQuarantineWindow`. Restaurer (à l'origine ou vers un dossier), supprimer, tout supprimer. Chaînes FR/EN à parité.                              |
| Désinstallation partielle.                                                                                                                                                              | `{commonappdata}\optiSCAN` (nouvelle quarantaine comprise) et `{sys}\config\systemprofile\AppData\Local\optiSCAN` supprimés.                                                                                                                                                                                              |




### 5.3 Moteurs

- **ClamAV 1.4.6** (au lieu de 1.4.5) : archives x64 et x86 de clamav.net, signatures `.sig` vérifiées (clé Talos `5BAD CA26 65EF 59DC F8A2 3D8B 707F 0DB4 8083 6771`, valide jusqu'au 13 mars 2027), SHA-256 épinglés : x64 `57B6FD1D…88295FD`, x86 `AE0FF986…CDEE5F00`.
- **YARA 4.5.5** (au lieu de 4.5.2). Les versions 4.5.6 à 4.5.8 (28 juillet 2026) sont publiées **en sources seulement** ; 4.5.5 est le dernier ZIP Windows officiel, épinglé avec l'empreinte publiée par GitHub (`352396C8…570163E4`). Les correctifs de 4.5.6–4.5.8 (bornes dans les modules `pe`, `dotnet`, `macho`, `dex`, chargement des règles compilées) ne sont donc pas livrés ; les adopter suppose de compiler YARA dans la CI Windows. L'archive 4.5.5 ne contient que la version 64 bits : `yara32.exe` en est une copie.
- `fetch-runtime-deps.ps1` écrit un marqueur `.pinned-version` (version et empreinte) après chaque extraction vérifiée ; un moteur dont le marqueur ne correspond plus est remplacé, ancienne version retirée.



### 5.4 Runtime .NET 10 LTS

- .NET 8 arrivait en fin de support le 10 novembre 2026. Tous les projets passent à `net10.0-windows*`, pris en charge jusqu'au **14 novembre 2028** ([politique Microsoft](https://dotnet.microsoft.com/en-us/platform/support/policy)) ; chemins de publication mis à jour dans les scripts, l'installeur, le profil de publication, la CI et la documentation. SDK épinglé par `global.json` (F13).
- Paquets `Microsoft.Extensions.DependencyInjection`, `Microsoft.Extensions.Hosting.WindowsServices`, `System.Management`, `System.ServiceProcess.ServiceController` en 10.0.12 ; `Microsoft.CodeAnalysis.NetAnalyzers` 9.0.0 retiré au profit des analyseurs du SDK.
- Seul changement de code : alias explicite vers `System.Windows.Controls.DataGrid`, ambigu avec le type WinForms de .NET 10.

---



## 6. Points solides

- **Suppression et quarantaine par poignée NT** : descente composant par composant sans traverser de jonction (`SafePathDelete.OpenParent`), refus des substituts de nom et des liens physiques, lecture et suppression par une poignée unique.
- **Cryptographie** : AES-256-GCM, nonce aléatoire de 96 bits, clé HMAC dérivée par HKDF d'un label distinct, comparaisons en temps constant ; SHA-256 vérifié à la restauration.
- **Écritures atomiques avec reprise** (`AtomicFile`) pour le manifeste, la clé, le SecureStore et la politique de l'hôte.
- **IPC** : clients distants refusés, ACL limitée (SYSTEM, Administrateurs, utilisateurs authentifiés en connexion seulement), usurpation qui **réduit** les droits du service, élévation réellement vérifiée, politique non affaiblissable par un compte standard, quotas par compte.
- `%ProgramData%\optiSCAN` : reprise DACL complète, contenu étranger supprimé, points de réanalyse purgés sans être suivis, parcours épinglé (aucun dossier renommable pendant la reprise), échec fermé.
- **Dossier d'installation** : service, hôte SYSTEM et exclusions Defender subordonnés à un dossier réservé aux administrateurs (`InstallLocationTrust`), installation imposée sous `Program Files`.
- **Isolation de clamd** : AppContainer au nom aléatoire, aucun accès disque, contenu reçu en flux.
- **Lancement de processus** : `ArgumentList` partout, arrêt propre de l'arbre à l'annulation et aux délais.
- **Chaîne d'approvisionnement** : moteurs épinglés par SHA-256 et signature GPG, certificat racine ClamAV épinglé, YARA-Forge sur liste d'autorisation, actions CI épinglées par SHA, permissions minimales, gitleaks, dependency-review, SBOM.
- **Code** : séparation Platform/Service/App, avertissements traités en erreurs, contrats IPC versionnés ; aucun secret dans le dépôt, aucun `TODO`/`FIXME`/`NotImplementedException`, captures vides quasi absentes en production.
- **Honnêteté de l'interface** : aucun état AMSI ou minifiltre mensonger ; scans incomplets signalés comme tels.

---



## 7. Notation

Même échelle et même moyenne simple que l'audit antérieur, pour pouvoir comparer. La colonne « Revue 360 » est la note retenue : elle part de l'état corrigé et tient compte des constats V ouverts. Une pondération orientée sécurité (détection et sécurité comptées double) aurait donné environ 4,8 pour l'état initial.


| Domaine                      | Audit antérieur | État initial | État corrigé | Revue 360 | Raison principale de l'écart                                                                                                                                                                                                                                                                                                                                                                       |
| ---------------------------- | --------------- | ------------ | ------------ | --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Architecture                 | 9,0             | 6,5          | 7,5          | **7,0**   | Hôte SYSTEM séparé de la logique de l'interface, politique machine centralisée, clamd réellement isolé sans modification d'ACL au fil des scans. Revue 360 : Parseurs YARA/clamscan hors isolation (V4) ; protection par défaut dans la session (V6).                                                                                                                                              |
| Sécurité applicative         | 8,5             | 4,5          | 9,0          | **8,0**   | Pipe, mutex, ProgramData, politique, `scan_path` et quarantaine durcis ; plus de fenêtre entre lecture et suppression ; HMAC non rétrogradable, restauration résistante aux jonctions ; service et hôte refusés hors d'un dossier réservé aux administrateurs ; serveur du pipe identifié par le service. Revue 360 : Coercition d'authentification SYSTEM par la surveillance des processus (V1). |
| Détection ClamAV / YARA      | 8,5             | 4,0          | 8,0          | **7,5**   | `CONTSCAN` réparé, YARA avec règles et par liste, erreurs et lacunes jamais rendues « propres », plus de zone inscriptible exclue des scans. YARA livré en 4.5.5, règles YARA-Forge figées sur la publication approuvée. Revue 360 : Formats courants hors temps réel (V8), PE chevauchants (V10), règles figées sans canal de mise à jour (V7).                                                   |
| Temps réel, AMSI, minifiltre | 8,5             | 3,0          | 7,0          | **5,5**   | AMSI et minifiltre retirés honnêtement ; temps réel SYSTEM sur les bons dossiers, fermé aux jonctions, analyse d'une copie. Pas d'interception avant exécution (signature reportée). Revue 360 : Suspension pendant les scans (V2), processus courts invisibles (V3), hôte figé non relancé (V5).                                                                                                  |
| Installateur                 | 8,5             | 5,5          | 7,5          | **7,0**   | Contexte utilisateur, désinstallation, runtime et exclusions héritées corrigés ; installation limitée à `Program Files` ; codes de `sc.exe` vérifiés. Non signé par décision. Revue 360 : Service décoché par défaut (V6), licences tierces non livrées (V9), modifications non commitées (V13).                                                                                                   |
| CI et chaîne                 | 9,0             | 5,5          | 8,5          | **7,5**   | Actions épinglées, empreintes et GPG des moteurs, build Release réparé, contrôle du binaire publié, signature conditionnelle prête. Revue 360 : SBOM sans moteurs ni runtime (V12), candidate non reproductible (V13).                                                                                                                                                                             |
| Journaux et secrets          | 8,5             | 7,0          | 7,5          | **7,5**   | Erreurs IPC génériques, motifs d'échec partiel consignés, masquage des profils usuels. Revue 360 : Sans changement.                                                                                                                                                                                                                                                                                |
| Tests                        | 8,5             | 6,0          | 8,0          | **7,5**   | Tests de non-régression pour les constats ; une partie ne vérifie quelque chose que sous Windows. Revue 360 : Aucun test sur les chemins UNC, la suspension du temps réel ni le mode hôte sans interface.                                                                                                                                                                                          |
| **Moyenne**                  | **8,6**         | **5,3**      | 7,9          | **7,2**   | 42,0 ÷ 8 = 5,25 → 63,0 ÷ 8 = 7,875 → 57,5 ÷ 8 = 7,19                                                                                                                                                                                                                                                                                                                                               |


La note a progressé par lots de corrections : 5,3 → 6,3 (séries N, avant R1) → 7,6 (R1 à R10) → 7,8 (`scan_path`, quotas, politique) → 7,9 (politique déposée d'avance, jonctions du temps réel, quarantaine à poignée unique). Les corrections des séries E, M, F et X et les évolutions de la section 5 n'ont pas encore été validées sur Windows : la note n'est pas relevée tant que ce n'est pas fait. La revue 360 la ramène à **7,2**. Les corrections de V1, V2, V3, V5, V8 à V12 la porteraient à environ **7,7** (sécurité 8,5, détection 8,0, temps réel 6,5, installateur 7,5, CI 8,0, tests 8,0) ; comme pour les séries précédentes, la note n'est relevée qu'après validation sous Windows. L'isolation des moteurs (V4) reste le principal levier suivant.

---



## 8. Tests

**État initial.** 330 tests xUnit (312 `[Fact]`, 18 `[Theory]`) sur 90 fichiers, plancher de couverture à 40 %. Aucun test sur `CONTSCAN`, les arguments schtasks, l'hôte de service, `set_policy`, `SafePathDelete` ou `PipeServerTrust`. À la relecture des chemins sensibles, plusieurs composants de sécurité n'avaient toujours pas de test dédié : `ProcessStartMonitor`, `ClamdIsolation`, `ClamdBroker`, `YaraEngine`, `ProtectionPipeAcl`, `ElevationHelper`, `ScanStaging`, `AtomicFile`, `ThreatRepairService`.

**Ajouts.**

- clamd et isolation : découpage INSTREAM, client, faux serveur lent, repli clamscan, relais concurrent, nom de conteneur ;
- fusion des statuts, YARA incomplet (code de sortie, troncature, orchestrateur), énumération, points de réanalyse ;
- copie de scan, quotas, politique « renforcer sans administrateur », ACL de ProgramData ;
- `LinkAndPolicyGuardTests` : politique possédée par l'utilisateur non fiable, comparaison de chemins réels, fichier atteint par un lien refusé, fichier ouvert impossible à renommer, quarantaine (lecture, verrouillage du nom, annulation puis suppression) et refus à travers un lien ;
- quarantaine du service (migration, conservation, liste, restauration sans écrasement, destinations refusées) ;
- `AtomicFile` (sauvegarde, reprise, écritures concurrentes), `ElevationHelper.NeedsElevation` (frontière de dossier, corrigée au passage : `C:\WindowsApps` était pris pour `C:\Windows`), ACL de `ProtectionPipeAcl`, `ThreatRepairService`, `ProcessStartMonitor`, rattachement des menaces du temps réel, certificat épinglé, `freshclam.conf`, exclusions interdites, risque, partages, parseur clamscan, paquets YARA-Forge (vrais ZIP, digest obligatoire, URL, plafonds) ;
- série X : ACL du dossier d'installation (`InstallLocationTrust`), exclusions Defender et périmètres protégés selon le dossier, copies d'analyse ignorées seulement pendant leur vie, `%LOCALAPPDATA%\optiSCAN` analysé hors bases et quarantaine, commandes élevées sans `cmd` et vidage sans suivre les liens, serveur du pipe identifié par le service.

Total au 5 octobre : 494 tests. Après les relectures du 7 octobre (séries Y et Z, robustesse) : 579, dont les nouveaux tests de liens (nettoyeur, clés USB), de noms de copie d'analyse, d'en-tête PE et de garde-fous sur le code source (lancements par nom nu, `ConfigureAwait(false)` dans les vues, niveau d'usurpation du tube clamd). Revue 360 : `Review360Tests` (chemins UNC et de périphérique refusés, aucune suspension du temps réel, abonnement sans interrogation, hôte sans boîte de dialogue, contrôle de vie) et `DetectionCoverageTests` (PE chevauchant, formats ajoutés) : 608 tests au total. Les tests qui créent des liens, passent par les API NT, les pipes ou les ACL ne vérifient quelque chose que sous Windows (`OperatingSystem.IsWindows()`) ; les tests de liens sont sautés silencieusement si la console ne peut pas créer de lien symbolique (activer le mode développeur).

---



## 9. Réserves ouvertes et conditions de clôture

**Non livrées / bloquantes pour la release signée :**

- signature Authenticode de l'installeur et des binaires : la chaîne est en place et inactive sans certificat ; aucun certificat n'est disponible, les artefacts sont non signés et `PipeServerTrust` ne peut pas vérifier de signature ;
- interception avant exécution : AMSI signé, minifiltre EV/WHQL, hors périmètre de cette candidate.

**Limites de produit assumées :**

- **santé du temps réel** : depuis le 13 octobre (D2), un dossier non surveillé, un watcher non rétabli ou un rattrapage en cours passent le badge de protection à « dégradé », avec la raison en infobulle et une notification à l'entrée dans cet état, pour la session comme pour le service. Un fichier qui ne se stabilise pas reste seulement journalisé ; les scans temps réel sans détection ne sont pas inscrits à l'historique ;
- **fichier restauré re-détecté** : le temps réel de la session épargne 15 minutes un fichier qu'on vient de restaurer, au même chemin et avec le même contenu (D1). Le temps réel du service SYSTEM n'en tient pas compte, volontairement : un compte standard ne doit pas pouvoir y soustraire un fichier ;
- **YARA 4.5.5** : les correctifs 4.5.6–4.5.8 exigent de compiler YARA dans la CI Windows ;
- **règles YARA-Forge bloquées** sur la release approuvée `20261004` jusqu'à ce qu'une mise à jour d'optiSCAN approuve la suivante ;
- **saturation des événements temps réel** : l'admission est limitée à 128 callbacks et le cache à 8 192 chemins. Une saturation déclenche un rattrapage coalescé par dossier ; si de nouveaux débordements arrivent pendant le délai de 30 s ou le rattrapage, un nouveau passage est planifié après ce délai. Un test Windows avec 480 créations sur deux vagues vérifie la borne, le nouveau passage et le traitement de tous les fichiers. La validation en VM de la charge réelle et un état de santé durable dans l'interface restent à faire ;
- **masquage des chemins** limité aux profils Windows standard ; le temps réel observe après écriture et ne remplace pas Defender ;
- **installation imposée sous** `Program Files` : une installation antérieure placée ailleurs doit être désinstallée avant la mise à jour ; un build de développement ou une copie portable fonctionne sans service ni exclusion Defender (X3).

**Revue 360 (série V) :**

- **corrigés dans le code, à valider sous Windows** : V1, V2, V3 (abonnement sans interrogation), V5, V8, V9, V10, V11, V12. Contrôles VM à ajouter : `cmd /c type \\hôte\x\y.js` sans connexion sortante de la machine (trace réseau) ; fichier EICAR créé pendant un scan complet, détecté ; journal `Surveillance des processus activée (événements de démarrage du noyau)` dans l'hôte ; exception provoquée dans l'hôte → processus terminé puis relancé ; installation dans un dossier non fiable → service arrêté ; `{app}\licenses` et `{app}\clamav\x64\licenses` présents après installation ;
- **avant le tag** : V13 (commiter l'ensemble, puis refaire publication et compilation ISCC) ; relancer `fetch-runtime-deps.ps1` pour obtenir `clamav\x64\licenses`, sans quoi ISCC refuse de compiler ;
- **documenté, reporté en 3.2** : V4 (YARA et clamscan hors isolation) ;
- **décisions produit** : V6 (service par défaut ou avertissement visible), V7 (canal de mise à jour signé).

**Conditions de clôture :**

1. **Validé le 7 octobre sur Windows** (SDK 10.0.401) : suite Release, 630 réussis, 0 échec, 0 ignoré, avec le test de charge réel du `FileSystemWatcher`. Le test a utilisé un `Directory.Build.props` temporaire sous `%TEMP%` pour isoler les sorties après refus d'accès ACL dans `optiSCAN/obj` ; les contrôles de la condition 5 ci-dessous restent séparément à faire en VM.
2. Service installé, compte standard puis administrateur :
  - scan par l'interface et scan d'un dossier utilisateur avec clamd actif (pas de repli clamscan systématique dans le journal `CompositeClamAv`) ;
  - réduire la protection en compte standard : l'invite UAC doit apparaître ;
  - provoquer une quarantaine automatique, vérifier le bandeau, puis liste, restauration (à l'origine et vers un dossier) et suppression après UAC ;
  - mise à jour depuis une 3.0.x : migration de la quarantaine SYSTEM et du conteneur clamd (nouvelles ACE, anciennes retirées) ;
  - `schtasks /query /tn optiSCAN_DailyScan /xml` : commande citée, `StartWhenAvailable` à `true` (C5) ;
  - installeur lancé avec `/DIR=C:\optiSCAN` : refus ; service lancé depuis une copie dans un dossier modifiable : hôte non démarré, événement dans le journal Application ;
  - fichier EICAR écrit dans `%TEMP%\optiscan_scan-staging\x\` puis dans `%LOCALAPPDATA%\optiSCAN\` : détecté par le temps réel ;
  - panneau Optimiser, en administrateur : télémétrie, DISM et cache Windows Update appliqués sans erreur dans le journal ; mise à jour depuis une version qui avait créé `optiSCAN-ClearDefenderHistory` : tâche absente ensuite.
3. `scripts\fetch-runtime-deps.ps1 -RequireSignature` puis `verify-runtime-deps.ps1` ; `clamscan --version` (1.4.6) et `yara64 --version` (4.5.5). Sur le poste de validation, les exécutables ClamAV x64 et x86 quittent avec NTSTATUS `0xC0000142` avant d'afficher leur version ; ce contrôle reste à refaire dans un environnement Windows où les binaires démarrent.
4. Après publication du workflow sur GitHub : premier passage réussi du job CodeQL `c-cpp` (M19) et de la CI avec `-RequireSignature`. La signature Authenticode reste un critère bloquant distinct : certificat requis, puis signatures des artefacts vérifiées.
5. **Partiellement validé** : la suite Windows (630/630) comprend le test de charge du watcher réel : borne de 128 événements, débordements, rattrapage différé et traitement de 480 fichiers. **À valider en VM** : `ISCC` échoue sans `optiSCAN.Service.dll` ; service installé démarré ; jonction dans `C:\Windows\Temp` non suivie par « Nettoyer » ; `COM1.txt` analysé sous le nom `content.txt` ; `.exe` renommé en `.dat` dans Téléchargements analysé ; `--service-host` tué → `clamd.exe` terminé ; arrêt du service → hôte fermé ; scans avec clamd actif sans repli clamscan systématique ; bouclier de l'accueil entier.

---



## 10. Vérification réalisée

- **Corrections de la revue 360** : build Release du service, de l'application et des tests sous Linux (SDK 10.0.401, `EnableWindowsTargeting`, avertissements traités en erreurs) sans avertissement. Suite sous Linux avec un faux framework WindowsDesktop : 608 tests, 388 réussis ; les 220 échecs sont ceux de l'environnement déjà connus (DPAPI `ProtectedData`, WPF, API NT), et aucun ne touche les classes modifiées hors de ces causes. `Review360Tests` et `DetectionCoverageTests` passent entièrement. Scripts PowerShell modifiés analysés sans erreur (`pwsh` 7.4) ; génération du SBOM natif et copie des licences exécutées sur données de test. **Non fait** : suite Windows, installeur, VM.
- **Compilation** : Debug, Release (sans build incrémental, avertissements traités en erreurs, comme en CI) et publication « shipping » réussies sous Linux avec le SDK .NET 10.0.401 et `EnableWindowsTargeting`, 0 avertissement. Le binaire publié ne contient pas le faux clamd.
- **Tests sous Linux**, avec un faux framework WindowsDesktop : 494 tests, 275 réussis. Les 219 échecs viennent tous de l'environnement (WPF et `ProtectedData` de référence non exécutables, API NT, pipes nommés, ACL Windows) ; à chaque lot, la liste des échecs a été comparée nom pour nom à la précédente, sans régression.
- **Binaires réels** : clamd INSTREAM (direct et à travers un relais), comportement de YARA 4.5, vérification GPG (archive valide acceptée, altérée refusée), empreintes des archives officielles.
- **Scripts et workflows** : scripts PowerShell sans erreur d'analyse (`pwsh` 7.6), y compris ceux embarqués dans `WindowsDefenderExclusionService` ; workflows YAML valides.
- **Suite Release Windows, 7 octobre** : 630 tests réussis, aucun échec ni test ignoré ; le test temps réel crée 480 fichiers sur deux vagues et vérifie que la file reste bornée, que le rattrapage reprend après débordement et que chaque fichier est traité. Les sorties ont été isolées sous `%TEMP%` à cause des ACL du `obj` du workspace. Cela ne couvre pas l'installation du service, l'installeur Inno, le parcours visuel de l'interface ni les contrôles privilégiés encore listés en section 9.

---



## 11. Limites

- L'analyse statique et les builds précédents ont été faits sous Linux ; la suite Release a aussi été exécutée sous Windows. L'installation du service, AppContainer/Defender en conditions installées, WMI, Inno Setup, la jonction privilégiée et les scénarios de verrouillage/suppression NTFS restent à vérifier sur VM. Les refus de renommer un dossier parent tant qu'un fichier y est ouvert et la suppression annulable ne sont pas observés ici.
- Contenu de l'installeur non extrait (Inno 6.7.0 non pris en charge par innoextract 1.9).
- Le modèle de menace de SECURITY.md exclut les attaques du même utilisateur contre DPAPI ; plusieurs constats E (E1, E2, E4) sont donc des affaiblissements de défense en profondeur bornés par les privilèges du compte attaquant.
- La gravité repose sur des faits de code vérifiés ; la probabilité d'exploitation reste une appréciation.
- La branche `win` (WinUI) n'a pas été examinée.
- La revue 360 (série V) est statique : ni build ni test sur l'arbre courant, modifications non commitées comprises. V3 et V5 reposent sur le comportement documenté de WMI et des bureaux non interactifs, à observer sur une VM.

---



## 12. Corrections de robustesse du 7 octobre 2026

Corrections de stabilité appliquées après les relectures Y et Z. Elles ne changent aucune frontière de sécurité ; la note n'en dépend pas.

- **Gestionnaires** `async void` : `btnAnalyze_Click`, `btnCleanNow_Click` (Nettoyer), `BtnScheduledRunNow_Click`, `BtnCheckAppUpdate_Click`, `BtnOpenSourceForge_Click` (Options) et `AsyncRelayCommand.Execute` journalisent leurs exceptions. Leur suite reprend sur le thread de l'interface : un `ConfigureAwait(false)` y ferait lever chaque accès à un contrôle, puis le `catch` lui-même, et `CommandManager.InvalidateRequerySuggested` hors de ce thread laisserait les boutons désactivés.
- **Arrêt de l'hôte** : `shutdown` (jeton vérifié) appelle désormais le gestionnaire fourni par `ProtectionServiceHost`, qui arrête temps réel, IPC et conteneur avant la fin du processus. Sans gestionnaire (tests), seule l'écoute IPC s'arrête. Le relais clamd (AppContainer) et le faux clamd gardent `Environment.Exit` : `Shutdown()` passerait par `OnExit`, qui instancie `ServiceContainer.Default`.
- **Tâches de fond** supervisées : `EnsureQuarantineBlobLayout`, `DefenderLegacyCleanup.RunAndMark`, `RecoverWatcherAsync`, pompe du relais clamd. Le préchauffage de clamd et `EnsureOptiscanExclusionsAsync` l'étaient déjà.
- **Captures vides** : commentées quand l'exception est attendue (annulation), journalisées sinon (`FreshclamConfSupport`, fermeture de `ClamdClient`).
- **Defender** : les retraits refusés écrivent `FAILED:<valeur>` ; `ParseResult` les journalise (chemins masqués) sans changer la ligne de résultat lue.
- **Quarantaine** : la migration des blobs sans MAC lit et chiffre hors verrou ; l'écriture se fait sous verrou et seulement si l'entrée est toujours au manifeste.
- **Base ClamAV** : `ClamAvEngine.DatabaseDir` est résolu une fois par instance (la résolution crée et supprime un dossier de test, et en SYSTEM vérifie ProgramData et retente la copie initiale des signatures) ; recalculé seulement si le dossier a disparu.

Vérification : build Release sans avertissement ; sous Linux, 579 tests ; les 220 échecs sont tous dus à l'environnement (WPF, API NT, `WindowsIdentity`, ACL), mêmes noms qu'à `8a0ef28` plus le nouveau test de `DatabaseDir`, qui passe par `WindowsIdentity` comme son voisin.

Mise à jour du 7 octobre : sur Windows / SDK 10.0.401, suite Release complète : **630 réussis, 0 échec, 0 ignoré**. Le nouveau test de charge du `FileSystemWatcher` crée 300 fichiers pendant le premier rattrapage puis 180 pendant le délai de récupération ; il confirme que les 480 fichiers sont traités et que la file reste sous son plafond de 128. Les contrôles manuels d'installation et de la condition 5 restent ouverts.

---



## 13. Audit indépendant du 13 octobre 2026

Un audit indépendant, mené sans reprendre les conclusions des sections précédentes, a porté sur l'arbre de travail du 13 octobre (`d18f333` et modifications non commitées). **Note indépendante : 6,4/10**, contre 7,2 en interne. L'écart vient surtout de la distribution (binaires non signés, candidate non commitée) et de la maintenabilité, que la notation interne ne sépare pas. Verdict : pas prêt pour une diffusion publique ; prêt pour une bêta fermée une fois A1 à A4 levés. Le rapport complet, avec ses preuves et son plan d'action, est tenu à part ; cette section en garde le suivi.

Toutes les corrections ci-dessous sont dans l'arbre de travail, sans commit. Release, Debug et publication (`OptiscanShipping=true`) compilent sous Linux (SDK 10.0.401, `EnableWindowsTargeting`) sans erreur ni avertissement. **Aucun des nouveaux tests n'a encore été exécuté sous Windows.**

### 13.1 Constats A1 à A15

| #   | Constat                                                                           | Gravité | État |
| --- | --------------------------------------------------------------------------------- | ------- | ---- |
| A1  | Candidate non commitée ; `installer/licenses/` non suivi mais exigé par `setup.iss` | Élevée  | ⏳ commits locaux à préparer |
| A2  | Binaires et installateur non signés pour un produit qui installe un service SYSTEM | Élevée  | ⏳ certificat requis |
| A3  | Exclusions Defender par processus sur `optiSCAN.exe` et `optiSCAN.Service.exe`    | Élevée  | ✅ |
| A4  | Aucune action de récupération du service ; le correctif V11 en dépend              | Moyenne | ✅ |
| A5  | YARA et clamscan non isolés en SYSTEM ; `scan_path` ouvert                         | Moyenne | ✅ `scan_path` fermé ; isolation des moteurs : 📄 3.2 |
| A6  | Tests de détection verts sans moteur ; la CI ne teste aucune vraie détection       | Moyenne | ✅ |
| A7  | Un seul exécutable WPF à 20 modes, dont l'hôte SYSTEM                              | Moyenne | 📄 feuille de route |
| A8  | Localisateur de services, P/Invoke dupliqués, 173 `catch` génériques               | Moyenne | 📄 feuille de route |
| A9  | Chemins `C:\` codés en dur ; Démarrage résolu dans le profil SYSTEM               | Faible  | ✅ |
| A10 | Cadrage JSON du pipe en coût quadratique                                          | Faible  | ✅ |
| A11 | Réglages « Optimiser » sans retour arrière                                        | Faible  | 📄 feuille de route |
| A12 | Historique Git de 303 Mo                                                          | Faible  | 📄 avant passage en public |
| A13 | QuestPDF et pile de tests en retard ; xUnit v2 déprécié                            | Faible  | 📄 feuille de route |
| A14 | README de 1 086 lignes ; audit devenu journal de travail                          | Faible  | 📄 feuille de route |
| A15 | Temps réel sans indicateur de santé dans l'interface                              | Info    | 📄 feuille de route |

- **A3** — Exclusions de processus limitées aux moteurs (`clamscan`, `freshclam`, `clamd`, `yara64`), par chemin complet. `optiSCAN.exe` et `optiSCAN.Service.exe` ne sont plus exclus comme processus : une telle exclusion aveugle Defender sur tout ce que le processus lit et écrit, et l'hôte SYSTEM manipule des fichiers hostiles. L'exclusion du **dossier** d'installation est conservée : sans elle, Defender détecte le binaire non signé par heuristique (signalé par le mainteneur ; noms de détection à confirmer par `Get-MpThreatDetection`). `%ProgramData%\optiSCAN` est exclu aux mêmes conditions d'ACL. Les anciennes exclusions de processus sont retirées par l'hôte SYSTEM une fois par version ; le script `add-defender-exclusions.ps1` applique le même contrôle d'ACL que le code.
- **A4** — `sc failure` (relances après 5 s, 60 s, 5 min ; remise à zéro après 24 h) et `sc failureflag 1`, posés par l'installeur et par l'application quand elle crée le service.
- **A5** — `scan_path` refusé par le serveur du service ; il n'est ouvert que par un paramètre explicite des tests.
- **A6** — La CI récupère ClamAV et YARA avant les tests ; avec `OPTISCAN_REQUIRE_ENGINES=1`, un moteur absent fait échouer le test EICAR au lieu de le faire passer en silence.
- **A9** — Dossiers système du temps réel résolus par l'API (`CommonApplicationData`, `Windows`).
- **A10** — Fin de message JSON repérée en un seul passage (`JsonEndScanner`) ; un message de 1 Mo est lu en 9 ms. Format inchangé.

### 13.2 Revue ligne à ligne : B1 à B16

| #   | Gravité | Défaut | Correction |
| --- | ------- | ------ | ---------- |
| B1  | Élevée  | L'hôte SYSTEM appliquait la règle « premier lancement avec Defender » de l'interface : temps réel du service coupé à chaque démarrage, alors que l'interface affichait « protégé » | Règle retirée de `ApplyHostPreferences` ; badge de l'interface fondé sur l'état du service |
| B2  | Élevée  | Clé de quarantaine ou clé HMAC illisible un instant : nouvelle clé écrite par-dessus, quarantaine et réglages perdus ; manifeste rejeté écrasé par un manifeste vide | Clé et manifeste mis de côté (`PreserveAside`, `.rejected-…`) avant toute nouvelle écriture |
| B3  | Moyenne | Seconde quarantaine sans empreinte dans `ServiceHostThreatHandler`, qui annulait le contrôle SHA-256 de la source | Le gestionnaire journalise l'état fixé par la source, sans requarantaine |
| B4  | Moyenne | Service actif : scan USB, surveillance des processus et clamd aussi lancés dans la session (double analyse, ~1 Go de RAM) | `ProtectionDelegatedToService` |
| B5  | Moyenne | Fichiers OneDrive présents sur le disque jamais analysés par clamd | Seuls les liens (symboliques, jonctions) sont écartés |
| B6  | Moyenne | `$RECYCLE.BIN` et `RECYCLER` ignorés sur les clés USB | Analysés ; seul `System Volume Information` est ignoré |
| B7  | Moyenne | Compilation YARA concurrente sur le même `_compiled.yarc` | Verrou unique, compilation vers un fichier temporaire puis remplacement |
| B8  | Moyenne | Copies d'analyse orphelines sans limite ; au-delà de 200 000 entrées, l'hôte refusait de démarrer | `ScanStaging.PurgeStale` au démarrage de l'hôte et de l'interface |
| B9  | Moyenne | Interface figée ~9 s au démarrage quand le service est injoignable | Pas de `sc create` sans élévation, pas d'attente après un refus |
| B10 | Moyenne | Fichier encore ouvert par son auteur jamais analysé par le temps réel | Trois nouveaux essais espacés de 1,5 s |
| B11 | Faible  | Service créé par l'application sans actions de récupération | Mêmes `sc failure` que l'installeur |
| B12 | Faible  | Suivi des lecteurs USB sans verrou | Lecteur réclamé sous verrou |
| B13 | Faible  | `optiSCAN.log` sans limite | Rotation à 10 Mo |
| B14 | Faible  | Restauration de la quarantaine en un clic | Confirmation avec le nom de la menace |
| B15 | Faible  | Anciennes exclusions de processus jamais retirées des installations existantes | Retrait automatique une fois par version ; `ProgramData\optiSCAN` toujours retiré à la désinstallation |
| B16 | Faible  | Divers : progression multi-cibles, 404 VirusTotal affiché en erreur, outils Windows lancés par nom nu, filtre UIPI, cache des exclusions interdites, stderr YARA sans limite, fin de lecture freshclam, sept hôtes de scripts absents de la surveillance des processus | Corrigés |

### 13.3 Points restés ouverts après la revue : C1 à C8

| #  | Défaut | Correction |
| -- | ------ | ---------- |
| C1 | Le bouton « Ignorer » d'une notification excluait le fichier de toutes les analyses, pour toujours, en un clic souvent pris pour « fermer » | Renommé « Exclure… » ; la fenêtre s'ouvre et une confirmation nomme le fichier, la menace et le chemin (« Non » par défaut). Sans confirmation, rien n'est exclu |
| C2 | Sous-dossiers `clamav`, `clamd`, `rules`, `Quarantine`, `SafetyBackups` de `%LOCALAPPDATA%\optiSCAN`, inscriptibles par la session, exclus en entier : une charge déposée là n'était jamais analysée | Seuls les fichiers de données connus y restent exclus (`IsDataFileName`, motifs `--exclude` par extension pour clamscan et clamd) ; un dossier d'exclusion obligatoire de ce type ne masque plus que ces fichiers |
| C3 | Détections du service SYSTEM invisibles pour l'utilisateur : ni notification, ni historique | `ServiceDetectionLog` (200 dernières, `%ProgramData%\optiSCAN\detections.json`) ; opération `recent_detections` ; `ServiceDetectionWatcher` relève toutes les 30 s, inscrit dans l'historique et notifie (3 alertes, au-delà un récapitulatif). Chemin complet rendu seulement à un administrateur élevé ou s'il est dans le profil de l'appelant ; un service plus ancien n'est plus interrogé |
| C4 | clamd analysait un fichier à la fois et gardait la liste complète du disque en mémoire | `Parallel.ForEachAsync`, jusqu'à 4 connexions (la moitié des cœurs, au moins 2) ; parcours consommé au fil de l'eau ; si clamd tombe en cours de dossier, repli complet sur clamscan |
| C5 | Tâche planifiée sans rattrapage : PC en veille à 2 h, scan sauté | Définition XML avec `StartWhenAvailable`, moindre privilège, session interactive ; tâches existantes mises à niveau au démarrage ; repli `/SC DAILY` si `/XML` échoue |
| C6 | Le mode jeu abandonnait les alertes de menace | Alertes gardées (50, plus le compte total), montrées ou résumées à la sortie du mode |
| C7 | `SafetyBackups` sans conservation ni usage ; analyse rapide sans `%APPDATA%` | Copies nommées d'après le SHA-256, gardées 30 jours et 256 Mo au total, supprimées avec l'entrée de quarantaine, et utilisées pour restaurer si le `.quar` est absent, illisible ou altéré. Analyse rapide étendue à `%APPDATA%` (Roaming) et au dossier Public ; temps réel du service aussi sur Roaming ; dossiers imbriqués analysés une seule fois (`RemoveNested`) |
| C8 | winget : aucun délai (une source bloquée figeait le panneau), annulation qui laissait winget tourner, tableau lu en français et en anglais seulement, liste arrêtée par un nom commençant par un chiffre (« 7-Zip ») | En-tête repéré par la ligne de tirets, colonnes déduites de l'en-tête (toutes langues), progression `\r` ignorée ; requêtes bornées à 2 min, mise à niveau à 30 min par paquet et 2 h pour « tout » ; winget et l'installateur arrêtés au délai ou à l'annulation ; délai dépassé affiché comme une erreur, pas comme « aucune mise à jour » |

### 13.4 Tests ajoutés

`ProtectionPipeJsonFramingTests`, `InstallerServiceRecoveryTests`, `ResilienceFixesTests`, `ServiceDetectionAndAlertTests` (journal des détections, filtrage des chemins, différé du mode jeu, « Exclure… » sans confirmation), `ScheduledScanCatchUpTests`, `RemainingAuditFixesTests` (winget en allemand et en espagnol, progression, copies de sécurité, analyse rapide), et des cas ajoutés à `OptiscanProtectedPathsTests`, `ProtectionPipeServerTests`, `WindowsDefenderExclusionServiceTests` et `RemovableDriveDiscoveryTests`. Ils compilent ; ils restent à exécuter avec la suite complète sous Windows.

### 13.5 Reste à faire

- Exécuter `dotnet test` sous Windows et les contrôles VM listés dans le [plan de release](RELEASE_PLAN_v3.1.md).
- Confirmer par `Get-MpThreatDetection` le nom de la détection Defender sur `optiSCAN.exe` : il dira si l'exclusion de dossier peut un jour être retirée (après signature Authenticode).
- A1 et A2 avant toute diffusion ; A5 (isolation de YARA et clamscan) et A7 en 3.2.

### 13.6 Corrections complémentaires : D1 à D7

| #  | Défaut | Correction |
| -- | ------ | ---------- |
| D1 | Un fichier restauré depuis la quarantaine était aussitôt remis en quarantaine par le temps réel (réserve de la section 9) | `RestoredContentGrace` : répit de 15 min, en mémoire seulement, lié au chemin exact et au SHA-256 du contenu restauré ; aucune alerte ni quarantaine pour ce fichier tant qu'il n'est pas modifié. Le service SYSTEM n'en tient pas compte |
| D2 | A15 : santé du temps réel invisible dans l'interface | `RealTimeProtection` suit les dossiers en défaut (watcher impossible à créer, non rétabli, événements perdus jusqu'à la fin du rattrapage) et lève `HealthChanged`. Le service expose leur nombre, sans chemin, dans `recent_detections` (`rt_degraded`). Badge « dégradé » avec la raison en infobulle, notification à l'entrée dans cet état, journal de l'hôte |
| D3 | Une instance élevée d'optiSCAN lançait freshclam (configuration, base et journal dans le profil) et winget (alias de `%LOCALAPPDATA%`, PATH du compte) : contournement d'UAC par un programme non élevé du même compte (relevé de la section 4.7) | `ElevatedSessionGuard` : refus dans une instance élevée, avec un message qui invite à rouvrir optiSCAN normalement. L'installeur lance désormais optiSCAN avec le jeton de l'utilisateur d'origine (`runasoriginaluser`) et non plus celui de l'installeur élevé |
| D4 | Quotas du pipe : compte lu sur le PID du client ; un PID réutilisé pouvait passer pour SYSTEM (exempté) ou pour un autre compte, et `recent_detections` aurait alors rendu les chemins du profil de ce compte | Exemption limitée à l'hôte lui-même ; pour la requête, compte relu sur le jeton usurpé (`GetImpersonatedClientSid`), qui décide du débit de scan et des chemins rendus |
| D5 | A11 : réglages « Optimiser » sans retour arrière | `TweakUndoStore` garde la valeur d'origine de chaque réglage à sa première modification (HKCU, plan d'alimentation, télémétrie). Bouton « Rétablir l'origine » : valeurs HKCU remises ou supprimées, plan d'alimentation d'origine, télémétrie rendue aux réglages par défaut de Windows (action élevée `telemetry-undo`). Ce qui échoue reste proposé. Le nettoyage DISM n'est pas réversible et la confirmation le dit |
| D6 | A11 : nom qui sur-promet | `TamperProtectionService` renommé `ProtectionWatchdogService` ; l'option devient « Relance automatique de la protection ». Le nom de la préférence enregistrée ne change pas |
| D7 | Bloc de documentation orphelin dans `PlatformProtectionBootstrap` | Remis sur `InvalidateReachabilityCache` |

Non corrigés, avec raison :

- **A1, A2** : commits locaux à préparer par le mainteneur ; certificat Authenticode à fournir.
- **A5 (isolation de YARA et clamscan), A7, A8** : refontes d'architecture prévues en 3.2, qui demandent une validation Windows à chaque étape.
- **A13** : QuestPDF 2026.9 et xUnit v3 (4.x) changent le moteur de rendu et le modèle d'exécution des tests. Les monter sans pouvoir exécuter la suite ni comparer un PDF produit n'aurait pas de garantie ; à faire sur un poste Windows.
- **Désinstalleur** : `{localappdata}` désigne le profil de l'administrateur qui désinstalle. Inno ne fournit pas le jeton de l'utilisateur d'origine pendant la désinstallation ; la purge reste celle du compte qui désinstalle.
- **V6, V7** : décisions produit (service par défaut, canal de mise à jour signé).

Vérification : Release, Debug et publication compilent sans erreur ni avertissement ; `FollowUpFixesTests` et le cas modifié de `HardeningFollowUpTests` restent à exécuter sous Windows.

---

## Révision du 15 octobre 2026 (matin) — 6,8/10

Texte de la révision remplacée le 15 octobre au soir, conservé tel quel ; ses liens internes renvoient au document de l'époque.


**Révision du 15 octobre 2026.** Elle reprend l'audit du 13 octobre au soir et le met à jour après la suite Release sous Windows. L'ancien document, qui mêlait constats, corrections et journal de travail, est conservé dans [`docs/archive/AUDIT_optiSCAN_360_journal_2026-10.md`](docs/archive/AUDIT_optiSCAN_360_journal_2026-10.md). Le présent document ne garde que l'état actuel et un registre des risques ouverts.

### En bref

| Indicateur | Valeur |
|---|---|
| **Note globale** | **6,8 / 10** (6,5 le 13 octobre ; 6,4 à l'audit indépendant du matin) |
| Qualité technique (hors distribution) | **7,3 / 10** |
| Prêt à diffuser | **4 / 10** |
| **Décision** | **Pas de diffusion publique.** La suite Windows est verte et la candidate est sur `dev`. La bêta fermée attend encore les contrôles sur machine virtuelle. |

Le 13 octobre, 37 défauts avaient été corrigés, dont deux plus graves que tous ceux de l'audit indépendant du matin (le service coupait son propre temps réel ; une lecture DPAPI ratée détruisait la quarantaine). La relecture de ces corrections en avait trouvé six de plus. La suite du 15 octobre en a trouvé un septième : la migration de démarrage tenait un fichier de quarantaine ouvert, et la purge échouait. Il est corrigé (section 6). La suite Release a ensuite donné 715 réussites, 0 échec, 0 ignoré.

Ce qui tire encore la note vers le bas n'est plus la suite : les binaires ne sont pas signés, Defender détecte `optiSCAN.exe` dès qu'il n'est plus exclu, et aucun contrôle n'a été fait sur machine virtuelle. Une fois ces points levés, la note atteint environ 7,4 (section 2).

### 1. Périmètre et méthode

L'examen porte sur la branche `dev` (commit `c50975c`, qui contient la candidate du 13 octobre) plus la correction de quarantaine du 15 octobre.

| Contrôle | Résultat |
|---|---|
| Relecture ligne à ligne du diff du code non commité (5 100 lignes) et des 15 fichiers C# nouveaux | Six défauts trouvés et corrigés le 13 octobre (section 6) |
| Compilation Release, Debug et publication (`OptiscanShipping=true`), SDK 10.0.401, avertissements traités en erreurs | 0 erreur, 0 avertissement (13 octobre) ; rebuild Release des tests le 15 octobre, 0 avertissement |
| Suite Release sous Windows, 15 octobre 2026 | **715 réussis, 0 échec, 0 ignoré** (section 7) |
| Audit NuGet (vulnérables, dépréciés, obsolètes, transitifs compris) | Aucune vulnérabilité connue ; xUnit 2 « legacy » ; QuestPDF 2024.12 (2026.9 disponible) |
| Mesures sur le code de production | Section 8 |

**Non fait :** installation sur machine virtuelle, essais avec privilèges (jonctions, usurpation du tube, arrêt brutal du service), comportement de Defender. R4 reste ouvert et décide de la bêta. R2 (candidate non commitée) et R3 (suite Windows) sont clos.

### 2. Notation

| Domaine | Poids | Note | Justification |
|---|---:|---:|---|
| Sécurité du code privilégié (service, tube, quarantaine, chemins) | 25 % | 8,0 | Usurpation du client, parcours sans jonction, serveur identifié par le gestionnaire de services, `scan_path` fermé, compte du client lu sur son jeton, instance élevée qui ne lance plus d'outil configuré par l'utilisateur. Reste : YARA et clamscan non isolés sous SYSTEM (R5). |
| Efficacité de détection | 15 % | 6,5 | ClamAV et YARA, temps réel après écriture, surveillance des processus après lancement. Couverture élargie aujourd'hui (dossiers de données, corbeilles USB, `%APPDATA%`, détections du service visibles). Ni AMSI ni minifiltre (R7). |
| Robustesse et exploitation | 15 % | 8,0 | Relance automatique du service, clés mises de côté au lieu d'être écrasées, santé du temps réel visible, tâche planifiée rattrapée. Suite Windows verte ; la purge n'est plus bloquée par la lecture de migration (L7). |
| Qualité du code et maintenabilité | 10 % | 5,5 | Exécutable WPF unique à 20 modes, conteneur singleton, 503 blocs `catch` sans filtre, 78 déclarations P/Invoke (R10). |
| Tests et preuves | 10 % | 8,0 | 715 cas exécutés sous Windows le 15 octobre, 0 échec. La CI exige les moteurs pour EICAR. CodeQL C/C++ jamais passé sur GitHub. |
| Distribution et confiance | 15 % | 4,0 | Non signé, détecté par Defender sans exclusion (R1). La candidate est commitée sur `dev` (R2 clos). Licences et actions de récupération dans l'installeur. |
| Produit (expérience, mises à jour) | 5 % | 7,0 | Retour arrière d'Optimiser, alertes en mode jeu, confirmation avant exclusion. Pas de canal de mise à jour du produit (R8). |
| Dépendances et chaîne d'approvisionnement | 5 % | 7,0 | Archives épinglées, signature GPG Talos, SBOM. Pile de tests et QuestPDF en retard (R11). |
| **Total pondéré** | | **6,8** | Hors distribution, renormalisé : **7,3** |

Le total est 8,0×25 % + 6,5×15 % + 8,0×15 % + 5,5×10 % + 8,0×10 % + 4,0×15 % + 7,0×5 % + 7,0×5 % = 6,825, arrondi à 6,8. Hors distribution (poids restant 85 %) : 7,3.

**Ce qui fait monter la note**, sans autre changement de code :

| Étape | Effet | Note globale |
|---|---|---:|
| R4 : contrôles sur machine virtuelle | Distribution 5 | ≈ 7,0 |
| + R1 : binaires signés, faux positif levé auprès de Microsoft | Distribution 7,5 | ≈ 7,4 |
| + R5 : YARA et clamscan isolés (3.2) | Sécurité 9 | ≈ 7,6 |

Les audits internes (8,6 puis 7,9 puis 7,2) notaient surtout le code relu, sans séparer la distribution ni la maintenabilité. Ils ne sont pas comparables terme à terme.

### 3. Décision de release

La recommandation de l'audit du matin était de ne pas publier. Elle est maintenue pour une **diffusion publique**, et précisée pour une **bêta fermée**.

| Étape | Conditions | État |
|---|---|---|
| **Bêta fermée** (testeurs informés, exclusion Defender du dossier d'installation documentée) | R2 commits locaux propres (licences comprises) ; R3 suite Release verte sous Windows ; R4 contrôles VM du [plan de release](RELEASE_PLAN_v3.1.md) | R2 et R3 clos ; R4 ouvert |
| **Release publique 3.1.0** | Bêta fermée, plus R1 signature Authenticode et faux positif levé, premier passage CodeQL C/C++ sur GitHub | ⏳ |

Une bêta reste possible malgré R5 et R7 : ce sont des limites connues, documentées dans [SECURITY.md](SECURITY.md) et sans exploitation démontrée. R1 bloque en revanche toute diffusion large : un utilisateur sans l'exclusion verrait `optiSCAN.exe` mis en quarantaine par Defender.

### 4. Points forts

Six mécanismes tiennent à une relecture hostile ; toute refonte doit les préserver.

- **Suppression et quarantaine sans course** : descente du chemin nom par nom par `NtCreateFile` relatif au parent, refus des jonctions, liens symboliques et liens physiques ; lecture, chiffrement et suppression par la même poignée ; empreinte SHA-256 de la copie analysée exigée avant quarantaine. La lecture de migration au démarrage partage la suppression, pour qu'une purge concurrente aboutisse (L7).
- **Le service n'agit jamais avec ses propres droits sur un chemin fourni** : ouverture sous le jeton du client (`ImpersonateNamedPipeClient`), analyse d'une copie faite depuis cette poignée.
- **Tube authentifié dans les deux sens** : ACL explicite, première instance, clients distants refusés, quotas par compte ; côté client, serveur identifié par le PID que donne le gestionnaire de services.
- **Moindre privilège pour la politique** : un compte standard peut renforcer la protection, jamais l'affaiblir.
- **clamd confiné** : AppContainer, objet job « kill on close », port local aléatoire, commandes d'arrêt désactivées.
- **Chaîne d'approvisionnement vérifiée** : archives épinglées par SHA-256, signature GPG exigée en CI, actions GitHub épinglées par commit.

### 5. Registre des risques ouverts

Gravité : impact si le risque se réalise. **Bloquant** : empêche l'étape de release indiquée.

| # | Risque | Gravité | Bloquant pour | Action |
|---|---|---|---|---|
| R1 | Binaires et installateur non signés. Defender détecte `optiSCAN.exe` dès que le dossier d'installation n'est plus exclu (nom de détection à relever par `Get-MpThreatDetection`). | Élevée | Release publique | Certificat de signature (OV, EV ou service de signature en ligne) ; soumission des binaires à Microsoft comme faux positif ; retrait de l'exclusion de dossier une fois la signature reconnue. |
| R2 | Candidate non commitée au soir du 13 octobre (84 fichiers, 15 fichiers C# nouveaux, `installer/licenses/`). | Élevée | Bêta | **Clos.** La candidate est sur `dev` (`c50975c`). La correction L7 du 15 octobre est dans l'arbre de travail, à committer avec cette révision. |
| R3 | Suite Windows non rejouée depuis le 7 octobre (630/630 alors) ; environ 3 400 lignes ajoutées depuis. Les 76 cas qui ne peuvent pas tourner sous Linux couvrent la quarantaine, le tube et les API de sécurité. | Élevée | Bêta | **Clos le 15 octobre 2026.** Binaires Release : 715 réussis, 0 échec, 0 ignoré. `dotnet test` n'a pas pu lancer l'hôte (accès refusé en surveillant le processus parent ; Test SDK 17.11, R11) ; les mêmes binaires ont été exécutés par le runner xUnit. Deux échecs de quarantaine ont révélé L7, corrigé avant la suite verte. |
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

### 6. Relecture des corrections : défauts trouvés et corrigés

Toutes les corrections de la journée ont été relues dans le diff. Six défauts sont apparus ; ils sont corrigés et testés (`AuditReviewFixesTests`).

| # | Gravité | Défaut | Correction |
|---|---|---|---|
| L1 | Moyenne | Une détection du service relevée par un compte sans droit sur le chemin ne porte que le nom du fichier. Depuis l'historique, « Quarantaine », « Supprimer » ou « Exclure » sur `bad.exe` étaient résolus dans le dossier courant et pouvaient viser un autre fichier. | `AntivirusActions` n'agit que sur un chemin complet (`Path.IsPathFullyQualified`). |
| L2 | Moyenne | Même cause : une détection du service différée par le mode jeu réapparaissait avec les boutons d'action. | Origine conservée ; elle réapparaît sous sa notification propre, sans action. |
| L3 | Moyenne | Un exécutable renommé en fichier de données (`payload.dat`) dans les dossiers de `%LOCALAPPDATA%\optiSCAN`, modifiables par la session, restait exclu de toutes les analyses : CreateProcess et rundll32 le lancent quelle que soit son extension. | L'en-tête PE est lu pour ces fichiers ; un exécutable n'est jamais exclu. Motifs de clamscan réduits aux gros fichiers binaires d'optiSCAN (R12). |
| L4 | Faible | « Rétablir l'origine » aurait supprimé une valeur de registre d'origine qui n'était pas un DWORD. | Valeur d'un autre type laissée intacte. |
| L5 | Info | La surveillance du noyau était présentée comme voyant les processus courts ; elle les voit, mais ne peut pas lire leur image une fois terminés. | Journalisé ; limite décrite en R7. |
| L6 | Info | Deux commentaires de documentation mal placés (`ExclusionSettings`, `ServiceContainer`). | Replacés. |
| L7 | Moyenne | La migration des fichiers de quarantaine au démarrage les ouvrait sans partage de suppression. Une purge ou une suppression pendant cette lecture échouait et laissait l'entrée en place (`PurgeOlderThan`, `PurgeAll`). | `ReadBlobBounded` partage la suppression. L'écriture reste exclusive. Suite Windows rejouée : 715/715. |

#### Corrections de la journée, vérifiées

| Lot | Contenu | Vérification |
|---|---|---|
| A3, A4, A5, A6, A9, A10 | Exclusions Defender par processus limitées aux moteurs ; récupération du service ; `scan_path` fermé ; moteurs exigés en CI ; chemins système par l'API ; fin de message JSON en un passage | Relu ; tests réussis sous Linux sauf ceux du tube (Windows) |
| B1 à B16 | Temps réel du service non coupé au démarrage ; clés et manifeste mis de côté ; pas de double quarantaine ; pas de double surveillance quand le service protège ; OneDrive et corbeilles USB analysés ; compilation YARA sérialisée ; purge des copies orphelines ; rotation du journal ; confirmation de restauration ; et neuf autres | Relu ; `ResilienceFixesTests` 7/7 avec substitut DPAPI |
| C1 à C8 | « Exclure… » avec confirmation ; dossiers de données analysés ; détections du service notifiées et inscrites ; clamd en parallèle ; tâche rattrapée au réveil ; alertes gardées en mode jeu ; copies de sécurité bornées et utiles ; winget toutes langues avec délais | Relu ; tests réussis, sauf quatre qui supposent Windows (chemins à barre oblique inverse, WPF) |
| D1 à D7 | Fichier restauré épargné ; santé du temps réel ; instance élevée sans freshclam ni winget ; compte du tube lu sur le jeton ; retour arrière d'Optimiser ; renommage du service de relance | Relu ; tests de `FollowUpFixesTests.cs` 8/8 |

Ces lots sont compris dans les 715 réussites du 15 octobre sous Windows.

### 7. Tests

Exécution du 15 octobre 2026 sous Windows, binaires Release : **715 réussis, 0 échec, 0 ignoré.** Elle couvre les cas qui échouaient sous Linux le 13 octobre (638/714), dont la quarantaine, les tubes et les API de sécurité. Le classement de ces 76 échecs d'environnement reste ci-dessous ; ils ne se reproduisent pas sous Windows.

Exécution du 13 octobre au soir sous Linux, binaires Release : **714 cas, 638 réussis.** Les 76 échecs avaient été classés un par un ; aucun ne mettait en cause la logique testée.

| Cause | Cas |
|---|---:|
| Quarantaine : suppression par poignée NT (`NtCreateFile`) | 24 |
| WPF (`WindowsBase`) non exécutable hors Windows | 18 |
| Tubes nommés Windows (ACL, usurpation) | 13 |
| API de sécurité Windows (SID, jetons) | 9 |
| Chemins à barre oblique inverse, `schtasks`, WMI, épinglage NT | 8 |
| API natives (`ntdll`, `kernel32`) | 2 |
| Moteurs ClamAV et YARA absents du poste d'audit (EICAR) | 2 |

Les tests de la quarantaine avaient été rejoués sous Linux avec un substitut DPAPI (chiffrement réversible de test, même interface) : les échecs restants y venaient tous de la suppression NT. La suite Windows du 15 octobre les exécute avec DPAPI et la suppression NT ; elle a aussi révélé L7, corrigé avant le passage vert.

### 8. Mesures

Code de production (`optiSCAN`, `optiSCAN.Platform`, `optiSCAN.Service`), hors `obj` et `bin`.

| Mesure | Valeur |
|---|---:|
| Lignes C# de production / fichiers | 39 115 / 215 |
| Lignes de tests / attributs `[Fact]` et `[Theory]` / cas exécutés sous Windows | 11 324 / 529 / 715 |
| `catch` sans type ni filtre / `catch (Exception)` sans `when` | 191 / 312 |
| Méthodes `async void` (gestionnaires d'interface pour l'essentiel) | 22 |
| Déclarations `DllImport` | 78 |
| Fichiers de plus de 500 lignes | 22 |

Les comptes de `catch` diffèrent de ceux des audits précédents (173) : ils comptent ici chaque bloc sans filtre, y compris les captures commentées et volontaires d'annulation ou de nettoyage.

### 9. Limites de cet audit

- La suite Release a été exécutée sous Windows le 15 octobre. L'installation du service, l'installeur, Defender et les essais privilégiés sur machine virtuelle n'ont pas été faits (R4).
- La relecture ligne à ligne couvre l'arbre du 13 octobre ; le code commité avant `d18f333` a été relu par l'audit indépendant du matin. La correction L7 a été relue et couverte par la suite du 15 octobre.
- La gravité repose sur des faits de code vérifiés ; la probabilité d'exploitation reste une appréciation.
- Les notes par domaine sont un jugement d'expert ; leur pondération est donnée pour qu'on puisse la discuter.

