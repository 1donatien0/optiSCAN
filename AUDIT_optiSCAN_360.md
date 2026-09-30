# Audit 360 — optiSCAN v3 — 2 octobre 2026 (contre-expertise indépendante)

Cette note remplace l’audit précédent (`AUDIT_optiSCAN_360.md` au commit `43da273`, noté 8,6/10), repris sans en adopter les conclusions. Chaque affirmation a été revérifiée dans le code de l'arbre `optiSCAN-stable` (branche `dev`, HEAD `43da273 release: optiSCAN 3`, arbre de travail propre). Les nouveaux constats sont cités au fichier et à la ligne.

## Méthode et niveau de preuve

- **Lecture statique** des quatre projets .NET, du code natif, de l'installeur Inno, des scripts et de la CI.
- **Compilation réelle** du fournisseur AMSI contre l'en-tête `amsi.h` du Windows SDK 10.0.16299, avec MinGW-w64 (`-fsyntax-only`). Résultat reproduit plus bas.
- **Inspection binaire** de `installer/output/optiSCAN_Setup_v3.0.0.exe` : en-tête PE, répertoire de sécurité Authenticode. Le contenu n'a pas pu être listé, car `innoextract` 1.9 ne lit pas le format Inno 6.7.0.
- **Non fait** : exécution de `dotnet test` (cible WPF Windows), installation sur une machine Windows, mesures dynamiques. Les constats marqués *probable* demandent une confirmation à l'exécution ; le test à faire est indiqué pour chacun.

Échelle de confiance : **Prouvé** (compilation ou lecture sans ambiguïté), **Élevée** (le code ne laisse pas d'autre lecture raisonnable), **Probable** (dépend d'un comportement Windows ou d'une séquence à observer).

## Verdict

L'audit d'origine décrit correctement beaucoup de mécanismes, mais sa note de **8,6/10 (A−)** ne tient pas. Trois raisons :

1. **Il a raté les défauts les plus graves.** Les voici :
   - le chemin de scan par défaut (clamd) perd les détections au bout de 400 ms d'attente ;
   - le produit affaiblit Windows Defender, l'antivirus principal de la machine, avec des exclusions par simple nom de processus et sur un dossier inscriptible par l'utilisateur ;
   - le fournisseur AMSI **ne compile pas** et serait de toute façon mal enregistré ;
   - n'importe quel utilisateur peut neutraliser le service de protection.
2. **Il juge comme « en place » des fonctions qui n'existent pas en pratique.** AMSI est noté comme « en échec ouvert » alors qu'il est absent. Le temps réel du service surveille le profil SYSTEM, pas celui de l'utilisateur. YARA n'a pas de règles sur une installation par défaut.
3. **Sa notation est ancrée sur la note précédente.** Il écrit : « ils ne ramènent pas la moyenne sous 8,4 ». C'est une conclusion posée avant l'analyse, pas un résultat. Plusieurs notes contredisent aussi les constats du même document : CI à 9,0 alors qu'un job natif échoue en silence, temps réel/AMSI à 8,5 alors qu'AMSI n'existe pas.

**Note indépendante : 5,3/10 (C−)**, détail plus bas. Les fondations sont saines : quarantaine AES-GCM, ArgumentList partout, DPAPI, CI large, 330 tests. Mais pour un logiciel dont le métier est de détecter et de protéger, la détection par défaut est défaillante et la surface d'attaque locale est sous-estimée.

---

## 1. Contre-vérification des cinq constats d'origine

| # | Constat d'origine | Verdict | Commentaire |
|---|---|---|---|
| 1 | Scan IPC en LocalSystem pour tout utilisateur authentifié | **Confirmé, mal hiérarchisé** | L'oracle de scan reste un risque faible : il ne dit que si un fichier correspond à une signature, et donne le nom de la menace. Les vrais risques du pipe sont ailleurs : squat du nom, aucune authentification du serveur par les clients, clients distants acceptés, une seule instance bloquable (voir N4). |
| 2 | Fournisseur AMSI en échec ouvert | **Dépassé : AMSI n'existe pas** | La DLL ne compile pas contre le SDK (N3). Même compilée, elle ne serait jamais chargée : l'enregistrement n'écrit pas la clé COM `InprocServer32`. L'affirmation « le fournisseur Microsoft reste en général prioritaire » est inexacte : AMSI interroge tous les fournisseurs enregistrés, il n'y a pas de priorité. |
| 3 | ClamAV et YARA ignorent le code de sortie | **Confirmé** | `ClamAvEngine.cs:253-255`. Les lignes `ERROR` de clamscan/clamd sont aussi ignorées par `ClamScanLineParser`. Mais le défaut principal de détection est N1, et l'audit ne le voit pas. |
| 4 | Minifiltre squelette, chargement sans contrôle de signature | **Confirmé** | À ajouter : `FltStartFiltering` n'est jamais appelé, et `fltmc load` échoue sans l'installation INF préalable (clé de service absente). C'est du code mort qui écrit dans `System32\drivers`. |
| 5 | Installeur non signé, contrôles lâches | **Confirmé, à recentrer** | L'absence de signature est prouvée : répertoire de sécurité PE à 0. En revanche, le « digest YARA-Forge facultatif » pèse peu : le digest arrive par la même réponse HTTPS GitHub que le fichier, il ne prouve rien de plus que TLS. Le vrai trou de chaîne d'approvisionnement est N11 (binaires ClamAV/YARA sans vérification d'empreinte). |

Sur la liste « Clos » : le point 7 (« clamd est configuré sur `127.0.0.1` seulement ») n'est pas un contrôle de sécurité clos. Le loopback n'authentifie personne, et tout utilisateur local parle à clamd (N6). Le point 6 (identifiants alignés C#/natif/Inno) est exact mais sans portée, puisque la DLL native ne se construit pas.

---

## 2. Nouveaux constats, du plus grave au moins grave

### N1 — Les scans de dossier via clamd perdent les détections · Critique · Confiance élevée

**Chemin par défaut.** `UseClamdEngine = true` (`UserPreferences.cs:88`). Les scans rapide, complet et dossier passent par `RunPipelineAsync(recursive: true)`, puis `CompositeClamAvBackend.ScanFolderAsync`, puis `ClamdEngine.RunScanAsync`, puis `ClamdClient.ScanRecursiveAsync` (commande `CONTSCAN`).

**Défaut.** `ClamdClient.ReadResponseAsync` lit la réponse avec une **attente maximale de 400 ms entre deux lignes** (`ClamdClient.cs:98`). Or `CONTSCAN` n'écrit rien tant qu'il ne trouve ni menace ni erreur. Dès qu'un dossier met plus de 400 ms à produire sa première ligne, la lecture est annulée, le socket fermé, et la sortie vide est analysée comme « aucune menace ». Le résultat est marqué `Completed`. Aucune exception n'est levée, donc le repli clamscan de `CompositeClamAvBackend` ne se déclenche pas. YARA tourne en parallèle, mais sans règles par défaut (N7).

**Effet.** Sur un vrai dossier (Téléchargements, Temp, disque complet), une menace trouvée après 400 ms est silencieusement perdue. L'utilisateur voit un scan « terminé, 0 menace ».

**Test de confirmation.** Créer un dossier avec 20 000 fichiers propres et un EICAR nommé pour être parcouru en dernier, puis lancer « Scanner un dossier » avec clamd actif.

**Correctif.** Lire jusqu'à la fin de connexion (clamd la ferme après `CONTSCAN`), avec un délai global et non un délai entre lignes. Utiliser `zCONTSCAN`/`nCONTSCAN`, traiter `ERROR` comme un échec, et tester avec un faux serveur lent (`ClamdClientTests` ne teste aujourd'hui que `PING`).

### N2 — Exclusions Defender par nom de processus et sur un dossier inscriptible · Critique · Prouvé

`WindowsDefenderExclusionService.cs:16-24` et `scripts/add-defender-exclusions.ps1` ajoutent `Add-MpPreference -ExclusionProcess` pour `optiSCAN.exe`, `optiSCAN.Service.exe`, `clamscan.exe`, `freshclam.exe`, `clamd.exe` et `yara64.exe`, **par simple nom d'image**. Defender exclut alors les fichiers ouverts par *n'importe quel* processus portant ce nom, quel que soit son emplacement. Un malware renommé `clamd.exe` dans `%TEMP%` écrit et lit sans être inspecté.

Les chemins exclus comprennent aussi `%LOCALAPPDATA%\optiSCAN` (`OptiscanProtectedPaths.cs:93`), un dossier inscriptible par l'utilisateur et par tout code de sa session. optiSCAN exclut aussi ce dossier de ses propres scans. On obtient donc un **dépôt invisible pour les deux antivirus**.

Rien ne retire ces exclusions à la désinstallation (aucun `Remove-MpPreference` dans le dépôt) : l'affaiblissement survit au produit. Le modèle de menace de `SECURITY.md` présente Defender comme « temps réel principal », sans mentionner qu'optiSCAN le dégrade.

**Correctif.** Exclure les processus **par chemin complet** sous `Program Files` (Defender accepte un chemin dans `-ExclusionProcess`). Ne jamais exclure un dossier inscriptible par l'utilisateur. Retirer les exclusions à la désinstallation.

### N3 — Le fournisseur AMSI ne compile pas et serait mal enregistré · Élevée (fonction annoncée absente) · Prouvé

Compilation de `amsi_provider.cpp` avec l'en-tête `amsi.h` du Windows SDK 10.0.16299 :

```
amsi_provider.cpp:112: error: 'HRESULT OptiscanAmsiProvider::CloseSession()' marked 'override', but does not override
amsi_provider.cpp:88:  error: no matching function for call to 'IAmsiStream::GetAttribute(AMSI_ATTRIBUTE, ULONGLONG*)'
amsi_provider.cpp:93:  error: no matching function for call to 'IAmsiStream::Read(unsigned char*, ULONG, ULONG*)'
amsi_provider.cpp:144: error: invalid new-expression of abstract class type 'OptiscanAmsiProvider'
```

Les signatures réelles sont `GetAttribute(attr, size, data, retSize)`, `Read(position, size, buffer, readSize)` et `void CloseSession(ULONGLONG)`. `DisplayName` n'est pas implémentée.

La chaîne masque l'échec à chaque étape :

- `ci.yml` construit avec `continue-on-error: true` ;
- `stage-amsi.ps1` ne fait qu'avertir quand la DLL manque ;
- `setup.iss` copie avec `skipifsourcedoesntexist`.

Le job CodeQL « Analyze C++ (AMSI) » ne peut pas réussir sa construction.

Même compilée, la DLL ne serait jamais chargée. `PlatformRegistration.TryRegisterAmsiProvider` (`:26-28`) écrit seulement `HKLM\SOFTWARE\Microsoft\AMSI\Providers\{GUID}` avec une valeur `Path`. Or amsi.dll instancie le fournisseur via COM, ce qui exige `HKLM\SOFTWARE\Classes\CLSID\{GUID}\InprocServer32`, et `DllRegisterServer` ne fait rien. Depuis Windows 10 1903, le fournisseur doit en plus être signé.

Défauts secondaires, inutiles à corriger avant une réécriture :

- `DisableThreadLibraryCalls(GetModuleHandleW(nullptr))` vise l'EXE hôte au lieu de la DLL (`:166`) ;
- `DllCanUnloadNow` ignore les objets vivants : déchargement prématuré possible, donc plantage de PowerShell ;
- `CreateFileW` sur le pipe se fait sans `SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION`, et `ReadFile` est synchrone sans délai : un serveur bloqué fige tous les hôtes AMSI.

Point positif : l'interface reste honnête (« AMSI : DLL absente »).

### N4 — Pipe de protection : squat, clients distants, blocage par un seul client · Élevée · Élevée

`ProtectionPipeAcl.cs:37` appelle `CreateNamedPipe` **sans `FILE_FLAG_FIRST_PIPE_INSTANCE` ni `PIPE_REJECT_REMOTE_CLIENTS`**, et donne `ReadWrite` à *Authenticated Users*, un groupe qui inclut les ouvertures de session réseau.

- **Squat du nom.** Le nom `optiSCAN_Protection` est libre :
  - pendant chaque relance de l'hôte (backoff jusqu'à 300 s, pause de 5 min après 30 relances) ;
  - entre deux instances, puisque `ListenLoopAsync` détruit l'instance avant d'en créer une autre ;
  - quand l'interface lance elle-même un `--service-host` de secours **sous l'identité de l'utilisateur** (`PlatformProtectionBootstrap.TryLaunchServiceHostProcess`).

  Aucun client ne vérifie l'identité du serveur (`GetNamedPipeServerProcessId` ou SID). Un faux serveur peut répondre « propre » à tout, et il reçoit le jeton d'arrêt que le service SYSTEM envoie à chaque arrêt (`ProtectionPipeClient.RequestShutdownAsync`). Le client .NET se connecte avec le niveau d'usurpation par défaut (`TokenImpersonationLevel.None`, donc sans SQOS) : un serveur doté de `SeImpersonatePrivilege` peut usurper le client SYSTEM.
- **Blocage.** Il n'y a qu'une instance à la fois, et aucun délai de lecture (`ProtectionPipeJsonFraming`). Un client qui garde la connexion ouverte bloque tous les scans IPC. Comme le pipe accepte les clients distants, n'importe quel compte de domaine qui atteint le port 445 peut le faire à distance, et sonder l'existence de fichiers en SYSTEM (« Chemin invalide »).
- **Au scan, aucune usurpation du client.** Le service ouvre le fichier avec ses propres droits SYSTEM. Le filtre `IsSensitivePath` est textuel (constat 1 d'origine) et n'exclut pas les profils des autres utilisateurs.

**Correctif.**

- Ajouter `FILE_FLAG_FIRST_PIPE_INSTANCE` et `PIPE_REJECT_REMOTE_CLIENTS`.
- Ouvrir plusieurs instances en avance.
- Fixer un délai de lecture (par exemple 5 s).
- Faire vérifier par les clients que le PID serveur appartient au service.
- Utiliser `ImpersonateNamedPipeClient` avant d'ouvrir `scan_path`.
- Supprimer le repli `--service-host` utilisateur.

### N5 — N'importe quel utilisateur peut empêcher l'hôte SYSTEM de démarrer · Élevée · Élevée

`App.xaml.cs:77` : l'hôte vérifie qu'il est seul avec `new Mutex(true, "Global\\optiSCAN_ServiceHost")` et s'arrête si le mutex existe déjà. Un utilisateur standard peut créer ce mutex dans `Global\`. L'hôte SYSTEM sort alors aussitôt, le superviseur relance avec backoff, puis se met en pause 5 min toutes les 30 relances : **la protection ne démarre jamais**. Le repli `--service-host` lancé par l'interface prend d'ailleurs ce même mutex en tant qu'utilisateur, avec le même effet sur le vrai service.

**Correctif.** Créer le mutex avec une DACL réservée à SYSTEM, et ne pas exiger un mutex global quand le processus est enfant du service.

### N6 — clamd partagé sur 127.0.0.1:3310 entre toutes les sessions et tous les niveaux de privilège · Élevée · Élevée

`ClamdHost.EnsureRunningAsync` considère clamd « prêt » dès que *quelque chose* répond `PONG` sur 3310. Conséquences :

- l'hôte SYSTEM peut utiliser le clamd lancé par l'interface d'un utilisateur, avec la base de signatures de ce profil, modifiable par cet utilisateur (par exemple un fichier `.ign2` qui blanchit une signature) ;
- inversement, un utilisateur peut piloter le clamd SYSTEM : `SCAN`/`CONTSCAN` sur des fichiers qu'il ne peut pas lire, `SHUTDOWN` pour couper le moteur ;
- un processus utilisateur peut écouter sur 3310 avant clamd et répondre `OK` à tout.

**Correctif.** Une instance clamd par contexte, sur un port aléatoire ou mieux un pipe nommé avec ACL. Vérifier le PID du serveur. `TCPAddr` ne suffit pas.

### N7 — YARA sans règles sur l'installation par défaut · Élevée (détection) · Élevée

L'installeur n'embarque pas les règles par défaut (`setup.iss`, `EmbedYaraRules` facultatif). `verify-runtime-deps.ps1` laisse passer leur absence. `YaraForgeUpdater` écrit dans `{app}\rules`, c'est-à-dire `C:\Program Files\optiSCAN\rules` (`YaraForgeUpdater.cs:67`). Or l'application tourne en `asInvoker` sans virtualisation : la mise à jour échoue faute de droits. Seul l'hôte SYSTEM peut écrire là, et il est désactivé par défaut (tâche `platformservice` décochée, mode complément Defender). **YARA reste donc inopérant** chez la plupart des utilisateurs.

**Test de confirmation.** Installation par défaut, compte standard, « Mettre à jour les signatures », puis vérifier `rules\*.yar`.

### N8 — Le temps réel du service surveille le profil SYSTEM, avec suppression par chemin sous SYSTEM · Élevée · Élevée / Probable

- `RealTimeWatchPaths` combine `C:\ProgramData`, `ScanTargets.QuickScanTargets()` et `C:\Windows\Temp`. Sous SYSTEM, les dossiers Téléchargements, Bureau, Temp et Démarrage résolus sont **ceux de `systemprofile`**. Le service ne surveille donc pas les dossiers des utilisateurs, alors qu'ApplyPreferencesOnStartup coupe le temps réel local quand le service répond (`ServiceContainer.cs:256-265`).
- Les préférences et exclusions du service sont celles du profil SYSTEM (`%LOCALAPPDATA%` de `systemprofile`). Les réglages de l'utilisateur, quarantaine auto comprise, ne lui parviennent jamais.
- Si la quarantaine auto est activée côté SYSTEM, `QuarantineManager.Quarantine` lit puis supprime **par chemin** (`File.Delete(threat.FilePath)`, `:220`), sans poignée ni contrôle de point de réanalyse. Cela se passe dans `C:\ProgramData` et `C:\Windows\Temp`, inscriptibles par les utilisateurs. C'est le schéma classique de suppression arbitraire par jonction (TOCTOU), menant à une élévation SYSTEM. Le risque est *conditionnel*, car `AutoQuarantineEnabled` vaut `false` par défaut.
- `ProtectionServiceHost.Start` appelle `ApplyPreferencesOnStartup`, qui relance la logique de démarrage de l'interface **depuis l'hôte lui-même** : `sc start` sur son propre service, ping pendant environ 5 s, lancement d'un second `--service-host` (refusé par le mutex), puis création par SYSTEM de la tâche `optiSCAN_Watchdog`.
- La menace est traitée deux fois : `RealTimeProtection` met en quarantaine, puis `ServiceHostThreatHandler` recommence, et la copie de sécurité est faite deux fois.

**Correctif.**

- Un mode hôte qui court-circuite toute la logique de démarrage de l'interface.
- Une configuration machine sous `ProgramData` avec ACL, ou bien un hôte par session.
- Une quarantaine fondée sur la poignée : ouverture avec `FILE_FLAG_OPEN_REPARSE_POINT`, contrôle du chemin final, suppression via `FileDispositionInfo` sur la même poignée.

### N9 — Jeton d'arrêt écrit en SYSTEM dans un dossier ProgramData potentiellement contrôlé par l'utilisateur · Moyenne · Probable

`ProtectionPipeShutdownToken.Persist` crée `%ProgramData%\optiSCAN\` sans ACL explicite, puis écrit et change la DACL d'`ipc_shutdown.token` en suivant les liens. Un utilisateur standard peut créer ce dossier avant le service, ou il est créé par le repli `--service-host` utilisateur. Il en est alors propriétaire et peut lire le jeton. Il peut aussi y poser une jonction ou un lien symbolique de l'espace objets : SYSTEM tronque alors un fichier arbitraire et en réécrit la DACL (déni de service, corruption).

**Correctif.** Créer le dossier dans l'installeur (`[Dirs]` avec `Permissions: system-full admins-full`), vérifier son propriétaire au démarrage, ouvrir sans suivre les points de réanalyse.

### N10 — Tâches planifiées : chemin non cité · Moyenne (fonctionnel) · Probable

`TamperProtectionService.cs:55` et `ScheduledScanService.cs:49` passent `/TR "C:\Program Files\optiSCAN\optiSCAN.exe --fullscan --quiet"` sans guillemets internes. Le commentaire « ArgumentList échappe correctement pour schtasks » est faux : `ArgumentList` protège l'argument entier, pas le chemin à l'intérieur de `/TR`. schtasks coupe alors au premier espace (`C:\Program`), et le scan planifié comme le watchdog échouent. En théorie, `C:\Program.exe` serait exécuté, mais seul un administrateur peut l'écrire.

**Test.** `schtasks /query /tn optiSCAN_DailyScan /xml`, puis lire `<Command>`.

**Correctif.** `$"\"{_exePath}\" --fullscan --quiet"`.

### N11 — Chaîne d'approvisionnement des moteurs · Moyenne · Prouvé

`fetch-runtime-deps.ps1:146,171` télécharge les ZIP ClamAV 1.4.5 et YARA 4.5.2 **sans empreinte SHA-256 épinglée** ni contrôle de signature. Ces binaires partent dans l'installeur et tournent en SYSTEM. Les actions GitHub sont référencées par tag, pas par SHA. Point positif : ClamAV 1.4 est la branche LTS actuelle.

**Correctif.** SHA-256 dans `runtime-versions.json` avec échec en cas de différence, vérification Authenticode des `.exe`, actions épinglées par SHA.

### N12 — Élévation d'un script `.cmd` écrit dans `%TEMP%` · Moyenne · Élevée

`SystemTweaksService.cs:374` écrit `optiscan_admin_<guid>.cmd` dans `%TEMP%`, puis le lance via `runas`. Entre l'écriture et le consentement UAC, tout code de la session peut modifier le script et obtenir une exécution administrateur.

**Correctif.** Passer les commandes en arguments du processus élevé (`optiSCAN.exe --tweak <id>`) au lieu d'un script réinscriptible.

### N13 — Installeur : effets de bord et contexte utilisateur · Moyenne · Élevée / Probable

- L'installeur exige les droits admin mais écrit dans `HKCU` et `{localappdata}` : menu contextuel, `UiCulture`, nettoyage de `freshclam.conf`. Avec une élévation par identifiants administrateur (utilisateur standard), ces écritures vont **dans le profil de l'administrateur**.
- `InitializeUninstall` (`setup.iss:483`) exécute `UnregisterOptiScanSystemArtifacts` : service, tâches, AMSI, `DelTree ProgramData`. Cette fonction est appelée avant la confirmation de désinstallation : annuler laisse donc le produit à moitié démonté (*probable*, à vérifier).
- Le runtime .NET Desktop est téléchargé puis exécuté en admin sans empreinte, alors que le publish est autonome. Ce téléchargement est inutile, et `IsDotNet8Installed` répond vrai pour n'importe quel .NET.

### N14 — Mineurs

- **Erreurs IPC.** `ex.Message` est renvoyé tel quel au client du pipe : chemins et détails internes.
- **Quarantaine.** `TryCreateSafetyCopy` laisse une copie **en clair** du malware (option `BackupBeforeQuarantine`), parfois en double.
- **Mutex de l'interface.** `Global\optiSCAN_UniqueInstance` : dans une session Bureau à distance ou après un changement rapide d'utilisateur, le second utilisateur ne peut pas lancer l'interface, et n'importe qui peut la bloquer.
- **SecureStore.** Le HMAC à l'intérieur d'un blob DPAPI n'ajoute presque rien : DPAPI est déjà intègre. Une enveloppe sans HMAC est encore acceptée (rétrocompatibilité), un affaiblissement surtout cosmétique au vu du modèle de menace.
- **Minifiltre.** `TryLoadMinifilter` ne recopie jamais un `.sys` plus récent (`if (!File.Exists(dest))`).

---

## 3. Ce qui est solide (confirmé)

- **Quarantaine.** AES-256-GCM, nonce aléatoire, manifeste HMAC comparé en temps constant, SHA-256 vérifié à la restauration, refus des destinations sensibles. Seule réserve : le format XOR historique reste lisible.
- **Lancement de processus.** `ArgumentList` est utilisé de façon systématique pour clamscan et YARA : pas d'injection de commande par nom de fichier.
- **Code .NET.** Séparation Platform/Service/App propre, avertissements traités en erreurs, contrats IPC versionnés, politique de relance testée.
- **Mises à jour.** freshclam est géré proprement (conf sans BOM, certificat CVD), et ClamAV vérifie lui-même la signature des bases.
- **CI.** Large : CodeQL C#, gitleaks, Dependabot, dependency-review, SBOM.
- **Tests.** 330 tests xUnit (312 `[Fact]`, 18 `[Theory]`) sur 90 fichiers.
- **Interface.** Elle n'affiche pas d'état AMSI ou minifiltre mensonger.

---

## 4. Notation indépendante

Même échelle et même moyenne simple que l'audit d'origine, pour pouvoir comparer. Une pondération orientée sécurité (détection et sécurité comptées double) donnerait une note plus basse, autour de 4,8.

| Domaine | Origine | Contre-expertise | Raison principale |
|---|---:|---:|---|
| Architecture | 9,0 | **6,5** | Bonne découpe, mais l'hôte SYSTEM réutilise toute l'application WPF et sa logique de démarrage ; configuration éclatée par profil ; clamd et mutex partagés entre contextes. |
| Sécurité applicative | 8,5 | **4,5** | N2, N4, N5, N9, N12 ; N8 conditionnel. La cryptographie de la quarantaine est bonne. |
| Détection ClamAV / YARA | 8,5 | **4,0** | N1 sur le chemin par défaut, N7, codes de sortie et lignes `ERROR` ignorés. |
| Temps réel, AMSI, minifiltre | 8,5 | **3,0** | AMSI ne compile pas et serait mal enregistré ; minifiltre factice ; temps réel du service sur le mauvais profil. Le temps réel local (FileSystemWatcher) fonctionne. |
| Installateur | 8,5 | **5,5** | Non signé, HKCU sous élévation, désinstallation à effet anticipé, runtime téléchargé sans empreinte, exclusions Defender persistantes. |
| CI et chaîne | 9,0 | **5,5** | Outillage large, mais échec natif masqué, binaires moteurs non vérifiés, actions non épinglées, pas de signature. |
| Journaux et secrets | 8,5 | **7,0** | Correct ; chemins complets dans les journaux et les erreurs IPC. |
| Tests | 8,5 | **6,0** | Volume réel, mais aucun test sur `CONTSCAN`, les arguments schtasks, l'hôte de service ou le natif ; plancher de couverture à 40 %. |
| **Moyenne** | **8,6** | **5,3** | 42,0 ÷ 8 = 5,25 |

---

## 5. Plan de remédiation priorisé

**Sous 48 h (bloquant pour toute diffusion) :**

1. N1 : corriger la lecture `CONTSCAN`, ou désactiver clamd pour les dossiers et repasser par clamscan avec le code de sortie, en attendant.
2. N2 : passer les exclusions Defender en chemins complets, retirer `%LOCALAPPDATA%\optiSCAN`, ajouter le retrait à la désinstallation.
3. N3 : soit réécrire le fournisseur AMSI (bonnes signatures, `DisplayName`, enregistrement `InprocServer32`, signature), soit **retirer AMSI** de l'installeur, de la CI (`continue-on-error`) et de la documentation.

**Sous 2 semaines :**

4. N4, N5, N6 : durcir le pipe (première instance, refus des clients distants, délai de lecture, vérification du PID, usurpation du client au scan), protéger le mutex par ACL, isoler clamd par contexte.
5. N7, N8 : règles YARA dans un dossier inscriptible par session ou embarquées ; mode hôte séparé de la logique de démarrage de l'interface ; quarantaine fondée sur la poignée.
6. Signature Authenticode de l'installeur et des binaires (`SignTool`), empreintes des moteurs (N11).

**Ensuite :** N9, N10, N12, N13, N14 ; remonter le plancher de couverture et ajouter des tests de non-régression pour chaque constat ci-dessus. Le minifiltre doit être soit développé pour de vrai (WDK, `FltStartFiltering`, port de communication, signature EV), soit retiré.

## 6. Limites

Pas d'exécution sur Windows, pas de `dotnet test`, pas d'extraction du contenu de l'installeur (Inno 6.7.0 non pris en charge par innoextract 1.9). N8 (TOCTOU), N9, N10 et le point « désinstallation » de N13 sont des lectures de code à confirmer par les tests indiqués. La branche `win` (WinUI) n'a pas été examinée.
