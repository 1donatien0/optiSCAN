# Audit technique 360° — optiSCAN v8.0

**Date :** 23 juin 2026
**Périmètre :** architecture, qualité de code, sécurité, robustesse, build & distribution, conformité (signature/RGPD), tests/CI.
**Méthode :** revue statique du dépôt `optiSCAN-stable` (≈ 35 700 lignes C# sur le projet principal, 4 projets, 82 fichiers de tests), compilation Release et exécution sous débogueur, comparaison avec la copie locale antérieure.
**Auditeur :** revue de spécialiste (lecture de code, pas de pentest dynamique).

> Avertissement : cet audit porte sur le code managé (.NET/WPF) du dépôt. Le pilote minifiltre et le fournisseur AMSI sont des composants natifs distincts dont seules les références ont été examinées (le `.sys`/`.dll` compilés ne sont pas dans le dépôt).

---

## 1. Résumé exécutif

optiSCAN est un antivirus Windows mûr et bien construit : architecture en couches avec injection de dépendances, cryptographie solide pour la quarantaine, IPC authentifié, et une chaîne DevSecOps réelle (analyzers, CodeQL, gitleaks, dependency-review, seuil de couverture). Le niveau d'ingénierie est nettement au-dessus de la moyenne d'un projet de cette taille.

Les problèmes ne sont **pas** dans la conception de fond mais dans **trois zones** :

1. **Démarrage fragile** — une exception au chargement de l'UI tuait le process en silence (cause du « ne se lance plus »). *Corrigé pendant cette session.*
2. **Chaîne de publication cassée** — une cible MSBuild supprimait toute la sortie de build avant le `publish`. *Corrigée pendant cette session ; un blocage résiduel côté UI de Visual Studio subsiste.*
3. **Prêt-pour-distribution incomplet** — signature du pilote et de l'exécutable, runtime .NET requis, cohabitation avec d'autres antivirus : ce sont les vrais risques pour un déploiement chez des tiers (notamment en Europe).

### Notation synthétique

| Domaine | Note | Commentaire |
|---|---|---|
| Architecture | 🟢 A− | Couches nettes, DI, coordinateurs, découplage par bus d'événements |
| Qualité de code | 🟢 A− | Analyzers + warnings-as-errors, nommage clair, commentaires utiles |
| Sécurité applicative | 🟢 B+ | Crypto et IPC bien faits ; quelques durcissements possibles |
| Robustesse / erreurs | 🟡 B− | Manquait un filet global d'exceptions (ajouté) ; chemins de démarrage à fiabiliser |
| Build & distribution | 🔴 C | Publish cassé (corrigé) ; signature/runtime non finalisés |
| Conformité (signature/RGPD) | 🟡 C+ | Pas de signature ; points RGPD à documenter |
| Tests & CI | 🟢 A− | 82 fichiers de tests, couverture mesurée avec seuil, SAST |

---

## 2. Architecture

**Constat.** Séparation claire :

- **Composition** : `ServiceContainer` (singleton paresseux, thread-safe) construit le graphe via `Microsoft.Extensions.DependencyInjection`. Bon choix.
- **UI** : WPF + MaterialDesign, vues (`Views/`), `ViewModels/`, et 22 **coordinateurs** (`Coordinators/`) qui sortent la logique d'orchestration du code-behind — excellent pour la testabilité.
- **Découplage** : `UiEventBus` / `IViewServices` permettent aux vues de naviguer et de réagir sans référencer `MainWindow`.
- **Modes d'exécution** multiples bien gérés dans `App.OnStartup` : UI normale, headless (`--fullscan`/`--quickscan`), service-host, watchdog, garde (`--guard`), scan depuis l'Explorateur (`--scan`), instance unique via mutex global.

**Points d'attention.**

- **`Services/` contient 107 fichiers.** C'est une surface importante dans un seul projet. À terme, envisager une modularisation (moteurs, quarantaine, mises à jour, plateforme/RTP, IPC) pour réduire le couplage implicite et clarifier les frontières.
- Le `ServiceContainer` expose beaucoup de responsabilités (façade + bus + cycle de vie). Acceptable, mais c'est un point de centralisation à surveiller.

---

## 3. Qualité de code

**Forces.**

- `Directory.Build.props` active **`EnableNETAnalyzers`**, `AnalysisLevel=latest-recommended`, **`TreatWarningsAsErrors` en Release**, et embarque `Microsoft.CodeAnalysis.NetAnalyzers`. C'est rare et très sain.
- `Nullable` activé, `ImplicitUsings` activé.
- Commentaires en français pertinents qui expliquent le *pourquoi* (ex. notes sur `async void`, ordre d'initialisation), pas seulement le *quoi*.
- Nommage cohérent, fichiers partiels pour séparer les responsabilités (`ScanViewModel.ScanRun.cs`).

**À améliorer.**

- **Fins de ligne incohérentes (CRLF vs LF).** La comparaison des deux copies a révélé qu'une douzaine de fichiers ne diffèrent *que* par les fins de ligne. Vérifier que `.gitattributes` impose bien `* text=auto eol=crlf` (ou LF) pour éviter le bruit de diff et les avertissements `git`.
- **`async void`** : présents (handlers d'événements, RTP). Ils sont enrobés de `try/catch`, ce qui est la bonne pratique, mais chaque `async void` reste un risque s'il évolue. À documenter/encadrer (déjà partiellement commenté).
- **Sync-over-async** : 4 occurrences de `.GetAwaiter().GetResult()` (chemin IPC/scan). Sur thread de pool aujourd'hui, donc OK, mais à proscrire sur le thread UI (risque d'inter-blocage).

---

## 4. Sécurité

### 4.1 Cryptographie — 🟢 très bon

- **Quarantaine** (`QuarantineManager`) : chiffrement **AES-GCM** (256 bits, tag d'authentification), **nonce aléatoire** par fichier via `RandomNumberGenerator`. La **clé maîtresse** est générée aléatoirement (32 octets) puis **enveloppée par DPAPI** (`ProtectedData`, portée `CurrentUser`). Conception conforme à l'état de l'art.
- **`SecureStore`** : DPAPI + **enveloppe HMAC** (détection d'altération), nettoyage mémoire via `CryptographicOperations.ZeroMemory`. Très propre.
- Aucun secret en dur détecté ; CI avec **gitleaks** pour le scan de secrets.

### 4.2 IPC (pipes nommés) — 🟢 bon, durcissement possible

- `ProtectionPipeAcl` crée le pipe avec une **ACL explicite** : SYSTEM et Administrateurs en *FullControl*, **utilisateurs authentifiés en ReadWrite**.
- L'opération **`Shutdown` exige un jeton** (`ProtectionPipeShutdownToken.Validate`) — bonne défense contre l'arrêt non autorisé.
- ⚠️ **Surface locale** : tout utilisateur authentifié peut envoyer `ScanPath`/`ScanBuffer`. C'est justifié par le fournisseur AMSI (qui s'exécute dans le contexte de l'application analysée), mais cela fait du service un *oracle de scan* et un vecteur de déni de service local. Recommandation : limiter le débit (rate-limit), borner la taille de `ScanBuffer`, et envisager de restreindre l'ACL si AMSI n'est pas activé.

### 4.3 Validation des chemins — 🟡 à corriger

`QuarantineManager.IsSensitivePath` protège les dossiers système, **mais compare avec `StartsWith` sans séparateur de fin** :

```csharp
if (fullPath.StartsWith(f, StringComparison.OrdinalIgnoreCase)) return true;
```

`C:\WindowsApps\…` correspond alors au préfixe `C:\Windows` → faux positif. Ce n'est **pas une faille** (cela sur-protège), mais c'est un bug de correction. Normaliser via `Path.GetFullPath` + comparer avec un séparateur de fin (`EndsWith(Path.DirectorySeparatorChar)` ou `Path.GetRelativePath`).

### 4.4 Exécution de processus externes — 🟢 maîtrisée

- `Process.Start` limité à des outils système attendus : `schtasks.exe`, `sc.exe`, `fltmc.exe`, `powershell.exe`.
- **PowerShell sans injection** : les exclusions Windows Defender passent les chemins via un **payload JSON encodé en Base64** décodé *dans* le script (`$data`), jamais concaténés dans la ligne de commande. Usage de `ArgumentList` (pas de chaîne unique). C'est la manière correcte — à souligner.
- `-ExecutionPolicy Bypass` est un *smell* mais acceptable et borné ici (gestion des exclusions Defender).

### 4.5 Élévation / privilèges — 🟡 par conception

- Manifeste **`asInvoker`** : exécution en utilisateur standard, élévation **à la demande** (`ElevationHelper.RelaunchElevated`). Bon principe de moindre privilège.
- Conséquence : les fonctions nécessitant l'admin (installation du pilote, écriture HKLM pour AMSI, tâches `schtasks /RL`) **échouent silencieusement sans élévation**. S'assurer que l'UX signale clairement ces dégradations.
- Écriture registre limitée à l'enregistrement du fournisseur AMSI sous `HKLM\SOFTWARE\Microsoft\AMSI\Providers` (attendu, nécessite admin).

### 4.6 Anti-sabotage / watchdog — 🟢 raisonnable

`TamperProtectionService` n'auto-termine pas l'application ; il (ré)installe une tâche planifiée `optiSCAN_Watchdog` (toutes les 15 min) qui relance la protection si absente. Effet de bord opérationnel important : **ce watchdog peut relancer `optiSCAN.exe` pendant un build/publish et verrouiller les binaires** (voir §6).

---

## 5. Robustesse & gestion d'erreurs

- **[Corrigé cette session] Absence de filet global d'exceptions.** Aucun gestionnaire `DispatcherUnhandledException` / `AppDomain.UnhandledException` / `TaskScheduler.UnobservedTaskException` → toute exception non gérée au démarrage tuait le process **sans trace** (« disparaît du gestionnaire des tâches »). Ajouté dans `App.xaml.cs` : journalisation (`%LOCALAPPDATA%\optiSCAN\Logs`) + boîte de dialogue.
- **[Corrigé cette session] Crash de démarrage `XamlParseException`.** Des `IsChecked` dans le XAML déclenchaient les handlers `Checked/Unchecked` *pendant* `InitializeComponent`, avant `Bind()`, → accès à `Services` qui levait une exception. Résolu par les gardes (`_suppressPreferenceEvents`, `_bound`, `_services==null`) et le `Bind()` déplacé avant l'activation des `RadioButton`.
- **Logging** : `AppLogger` maison (rolling quotidien, nettoyage 30 j, thread-safe, niveaux) + `PathRedaction` pour caviarder les chemins utilisateur. Bon compromis sans dépendance lourde.
- **Le chemin `Loaded` (`SurChargementFenetrePrincipale`)** est correctement enrobé de `try/catch`. Veiller à ce que tout nouveau code de démarrage le reste.

---

## 6. Build, packaging & distribution — 🔴 priorité

### 6.1 [Corrigé] Cible MSBuild destructrice

`optiSCAN.csproj` contenait une cible `CleanStalePublishOutput` (`BeforeTargets="BeforePublish"`) qui supprimait **tout** `bin\Release\<tfm>` — y compris l'`optiSCAN.dll`/`exe` fraîchement compilé que l'étape *publish* doit copier. Comme le build était « up-to-date », rien n'était régénéré → **publish en échec**. Corrigé : la cible ne supprime plus que le sous-dossier `publish\`.

### 6.2 [Résiduel] Échec de Publish via l'UI de Visual Studio

Même après correction, la **publication via l'interface VS 2026** échoue avec un message générique (« We were unable to determine the cause ») et un log temporaire, **sans erreur MSBuild** (le build, lui, réussit). Symptôme typique d'un souci de l'outillage de publication VS et/ou d'un **verrou de fichier** (instance `optiSCAN.exe` relancée par le watchdog). **Contournement fiable** : ligne de commande.

```powershell
# 1) Fermer optiSCAN (systray → Quitter) et désactiver la tâche optiSCAN_Watchdog
# 2) Vérifier qu'aucun optiSCAN.exe ne tourne (Gestionnaire des tâches)
# 3) Publier :
cd "C:\Users\BYAKOMBE\Documents\GitHub\optiSCAN-stable"
dotnet publish optiSCAN\optiSCAN.csproj -c Release -r win-x64 --self-contained false
```

### 6.3 Pilote minifiltre & fournisseur AMSI absents du dépôt

Le dépôt ne contient que `native\optiSCAN.Minifilter\optiSCAN.Minifilter.inf` — **pas** de `.sys` compilé, pas de `.cat`, pas de `.dll` AMSI. Le script Inno les copie avec `skipifsourcedoesntexist`, donc **l'installeur peut être généré silencieusement sans pilote**, livrant un AV sans protection temps réel noyau. À traiter explicitement (échec dur si absent, ou build natif intégré au pipeline).

### 6.4 Dépendance au runtime .NET

Le profil publie en **`SelfContained=false`** : l'utilisateur final doit avoir le **.NET 8 Desktop Runtime (x64)**. Sur une machine « vierge », l'app ne démarrera pas. Options : publier *self-contained*, ou faire vérifier/installer le runtime par l'installeur Inno.

### 6.5 Installeur Inno

`installer/setup.iss` est soigné (résolution du dossier publish par préprocesseur, exclusions clamav/rules/yara, copie depuis le dossier source). RAS majeur, hormis la dépendance au dossier `publish` (cf. 6.2/6.3).

---

## 7. Conformité : signature & RGPD

### 7.1 Signature de code — approche par phases

> **Stratégie retenue (petit éditeur).** La couche plateforme (service + minifiltre + AMSI) est **dormante par défaut** ; la protection temps réel tourne en **user-mode** (`FileSystemWatcher`), sans pilote ni signature. La signature du pilote (EV + Partner Center) est donc **reportée** à une phase ultérieure (~3 ans). Voir `docs/GUIDE_DISTRIBUTION.md` (§0) et `docs/SIGNATURE_PROCEDURE.md`.

- **Pilote — phase 2 (reporté)** : sur Windows 10/11 x64, un pilote non signé ne se charge pas (Driver Signature Enforcement). Tant qu'il n'est pas signé (attestation/WHQL Microsoft + EV), il **n'est pas embarqué** et la couche plateforme reste dormante. Aucun impact : le mode user-mode fonctionne sans lui.
- **Exécutable & installeur — phase 1 (maintenant)** : signature **optionnelle mais recommandée** via un certificat **OV** (l'EV n'apporte plus d'avantage SmartScreen depuis mars 2024). Sans signature, SmartScreen affiche « éditeur inconnu » et le risque de faux positifs AV augmente — acceptable en bêta.
- **Cohabitation antivirus** : optiSCAN (hooks de processus, RTP, minifiltre) correspond au profil qu'un **Kaspersky / Bitdefender / Avast** (très répandus en Europe) peut **détecter et terminer**. La signature réduit le risque mais ne l'élimine pas ; prévoir une documentation d'exclusion mutuelle et des tests sur postes équipés de ces AV.

### 7.2 RGPD / vie privée — 🟡 à documenter

- Les logs peuvent contenir des chemins de fichiers (donnée potentiellement personnelle) ; **`PathRedaction` atténue** déjà, et la rétention est bornée à 30 jours. Bon.
- ⚠️ **`CloudThreatIntelService` / `ThreatReputationService`** effectuent des requêtes externes (réputation de menaces). Vérifier précisément **ce qui est transmis** (hachages ? noms de fichiers ?) et documenter : finalité, base légale, possibilité de désactivation, et politique de confidentialité. C'est le principal point RGPD pour une diffusion en Europe.
- Aucune télémétrie tierce intrusive détectée par ailleurs.

---

## 8. Tests & CI — 🟢 bon

- **82 fichiers de tests / ~6 000 lignes** (xUnit + Moq), couvrant quarantaine, secure store, chemins d'installation, IDs de menaces, etc.
- **CI GitHub Actions** : `ci.yml` (build Release + tests + **couverture avec seuil progressif**), **`codeql.yml`** (SAST), **`dependency-review.yml`** (CVE des dépendances), **`gitleaks.yml`** (secrets). Chaîne DevSecOps complète et rare à ce niveau.
- À renforcer : tests d'intégration du **chemin de démarrage UI** (le crash trouvé n'aurait pas été attrapé par les tests unitaires) et de la **chaîne de publication**.

---

## 9. Dépendances

| Paquet | Version | Note |
|---|---|---|
| MaterialDesignThemes | 5.3.1 | OK |
| Microsoft.Extensions.DependencyInjection | 8.0.1 | OK |
| QuestPDF | 2024.12.2 | ⚠️ Licence *Community* gratuite sous un seuil de CA — vérifier l'éligibilité pour une distribution commerciale |
| Microsoft.Toolkit.Uwp.Notifications | 7.1.3 | ⚠️ Marqué « déprécié », **mais c'est la version supportée pour les apps WPF/Win32 NON empaquetées**. Le successeur (`CommunityToolkit.WinUI.Notifications` 8.x) s'oriente vers le Windows App SDK et peut casser les toasts en mode non empaqueté. **Ne pas migrer sans test approfondi** ; rester sur 7.1.3 est acceptable. |
| System.Management | 8.0.0 | OK (WMI) |
| xunit / Moq / coverlet | — | OK (tests) |

---

## 10. Recommandations priorisées

### P0 — bloquant (fait pendant la session)
1. ✅ Corriger le crash de démarrage `XamlParseException` (gardes + ordre `Bind`).
2. ✅ Ajouter le filet global d'exceptions (`App.xaml.cs`).
3. ✅ Corriger `CleanStalePublishOutput` (ne nettoyer que `publish\`).
4. ⏳ **Committer ces 6 fichiers** et **régénérer l'installeur** depuis le dépôt git (jamais depuis `D:\Projets`).

### P1 — avant toute distribution
5. **Phase 1 (maintenant)** : signer l'exe/installeur avec un **OV** (optionnel mais recommandé). **Phase 2 (~3 ans)** : EV + signature du pilote (attestation/WHQL Microsoft).
6. Régler la **dépendance runtime** : publier self-contained ou faire installer le .NET 8 Desktop Runtime par Inno.
7. **Phase 2** : garantir la présence du pilote/AMSI **signés** dans l'installeur et intégrer leur build au pipeline. En phase 1, la couche reste **dormante** (tâche installeur décochée, mode user-mode par défaut).
8. Fiabiliser la **publication** en CLI (`dotnet publish`) plutôt que l'UI VS ; arrêter le watchdog pendant les builds.
9. Documenter la **cohabitation antivirus** et tester sur postes Kaspersky/Defender.

### P2 — durcissement & qualité
10. Corriger `IsSensitivePath` (comparaison avec séparateur de fin).
11. Limiter/borner l'IPC `ScanPath`/`ScanBuffer` (rate-limit, taille max) ; revoir l'ACL si AMSI désactivé.
12. Documenter ce que transmet `CloudThreatIntelService` + politique de confidentialité (RGPD).
13. Normaliser les **fins de ligne** via `.gitattributes`.
14. **Ne PAS** migrer `Microsoft.Toolkit.Uwp.Notifications` à l'aveugle (risque de casser les toasts en non empaqueté — rester sur 7.1.3) ; vérifier l'éligibilité à la licence QuestPDF Community.
15. Ajouter des tests d'intégration du **démarrage UI** et de la **publication**.

---

## 11. Conclusion

optiSCAN est un projet **techniquement solide** : l'architecture, la cryptographie, l'IPC et l'outillage qualité sont au niveau d'un produit professionnel. Les défaillances rencontrées (« ne se lance plus », publish en échec) étaient des **régressions ponctuelles** — un ordre d'initialisation UI et une cible MSBuild trop agressive — désormais corrigées, et non des défauts d'architecture.

Le vrai chantier restant n'est pas le code mais la **mise en production**, désormais **abordée par phases**. En **phase 1** (maintenant, sans pilote) : protection user-mode par défaut, signature **OV optionnelle** de l'exe/installeur, **cohabitation antivirus** et **documentation RGPD**. La couche plateforme avancée (service + minifiltre + AMSI) reste **dormante mais en place**, à activer en **phase 2** (~3 ans) avec un **certificat EV** et la **signature du pilote** (Partner Center). Cette approche permet une diffusion immédiate sans le coût/la complexité du pilote signé.

*— Fin de l'audit.*
