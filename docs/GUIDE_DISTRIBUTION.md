# Guide de distribution — optiSCAN

Ce guide couvre la mise en production d'optiSCAN chez des utilisateurs tiers : **signature de code**, **cohabitation avec d'autres antivirus** et **chaîne de publication**. Il complète l'[audit 360](../AUDIT_optiSCAN_360.md) et le [diagnostic d'intégration](DIAGNOSTIC_INTEGRATION_WINDOWS.md). L'état courant du code et ses limites sont résumés dans les [réserves de l'audit](../AUDIT_optiSCAN_360.md#5-registre-des-risques-ouverts).

---

## 1. Signature de code

### 1.1 Exécutable & installeur — Authenticode

La signature Authenticode est facultative dans la chaîne actuelle. Sans `CODESIGN_PFX` et `CODESIGN_PASSWORD`, les artefacts restent non signés. Avec un certificat PFX configuré, la procédure courante signe les binaires publiés, l'installeur et son désinstalleur. La signature identifie l'éditeur ; elle ne garantit ni une réputation SmartScreen ni l'absence de blocage par un autre produit de sécurité.

- **Certificat** : fournir un PFX autorisé à signer et son mot de passe par la configuration locale ou les secrets CI ; voir la [procédure de signature](SIGNATURE_PROCEDURE.md). Le projet n'impose pas de classe OV/EV ni de fournisseur.
- **Signer les binaires publiés** avec le certificat PFX :

  ```powershell
  # Définir CODESIGN_PASSWORD dans l'environnement depuis un gestionnaire de secrets.
  pwsh -File scripts/codesign.ps1 -Sign -PfxPath cert.pfx `
    -Files publish/win-x64/optiSCAN.exe,publish/win-x64/optiSCAN.dll,publish/win-x64/optiSCAN.Service.exe,publish/win-x64/optiSCAN.Service.dll,publish/win-x64/optiSCAN.Platform.dll
  ```

- **Signer l'installeur et son désinstalleur** : après le publish, transmettre le même PFX au script Inno :

  ```powershell
  pwsh -File installer/build-release-setup.ps1 -SkipPublish `
    -PublishDir publish/win-x64 -SignPfxPath cert.pfx
  ```

### 1.2 AMSI et minifiltre

Ces deux composants **ne sont pas livrés ni actifs** dans la version courante. Les prototypes sous `native/` ne sont pas compilés par CI, inclus dans l'installateur, enregistrés ou chargés. La signature AMSI/noyau ne fait donc pas partie de la procédure de publication actuelle. Toute reprise de ces fonctions exige d'abord une implémentation, une revue de sécurité, une chaîne de signature et une validation Windows dédiées.

---

## 2. Cohabitation avec d'autres antivirus

optiSCAN analyse à la demande, surveille les changements de fichiers avec `FileSystemWatcher` et peut surveiller les créations de processus WMI lorsque le service avancé est activé. Il n'installe pas de hook noyau, d'AMSI ou de minifiltre dans la version courante.

- **Risque concret** : un **Kaspersky / Bitdefender / Avast** (très répandus en Europe) peut **mettre en quarantaine ou terminer** `optiSCAN.exe` — symptôme « se lance quelques secondes puis disparaît ».
- **Mesures** :
  1. **Signer** l'application et l'installeur (améliore l'identification de l'éditeur ; n'assure pas à lui seul l'absence de faux positifs).
  2. Documenter pour l'utilisateur comment **ajouter une exclusion** dans son AV existant (dossier d'installation ; éviter une exclusion de processus sur `optiSCAN.exe` ou `optiSCAN.Service.exe`, qui ferait ignorer par cet antivirus tout ce que ces processus lisent, y compris les fichiers analysés).
  3. Tester optiSCAN sur des postes équipés de Kaspersky/Bitdefender/Defender **avant** diffusion.
  4. Côté Defender, le projet gère déjà l'ajout d'exclusions (`scripts/add-defender-exclusions.ps1`).
- **Avertissement** : faire tourner **deux moteurs temps réel** simultanément peut dégrader les performances et provoquer des conflits de verrous. Le recommander uniquement en complément (scan à la demande), pas comme second RTP permanent. Voir aussi [SECURITY.md](../SECURITY.md).

---

## 3. Dépendance au runtime .NET

Publication **win-x64 uniquement** (`ArchitecturesAllowed=x64compatible`). Les scripts de release `prepare-release-v3.ps1` et `publish-release.ps1` publient en **self-contained** : le runtime .NET 10 est inclus. Le paramètre historique `-SelfContained` de `publish-release.ps1` est conservé pour compatibilité ; le script ne produit plus de publish dépendant du framework. Un publish manuel framework-dependent exige le **.NET 10 Desktop Runtime x64** sur le poste cible ; l'installeur ne le vérifie ni ne l'installe. Le code Inno contient des fonctions de téléchargement, mais elles ne sont pas raccordées au parcours actuel. Le projet cible **.NET 10 (LTS)**, pris en charge par Microsoft jusqu'au **14 novembre 2028** ; .NET 8 arrive en fin de support le 10 novembre 2026 ([politique de support .NET](https://dotnet.microsoft.com/en-us/platform/support/policy)). La version du SDK est fixée par `global.json`.

Pour éviter ce prérequis sur un poste neuf, utiliser le profil self-contained de la chaîne recommandée. Le dossier `installer/redist/` n'est pas consommé par le parcours Inno courant ; un redist y placé ne sera pas embarqué.

Pour une expérience « zéro dépendance » ou un package plus léger :

| Option | Commande / mécanisme | Effet |
|--------|----------------------|--------|
| Self-contained | `scripts\prepare-release-v3.ps1` ou `scripts\publish-release.ps1` (mode fixe) | Runtime dans le publish (installeur plus lourd) |
| Framework-dependent manuel | `dotnet publish ... --self-contained false` (hors chaîne release standard) | .NET 10 Desktop Runtime doit déjà être installé sur le poste cible |
| Redist Inno | Non pris en charge par le parcours courant | `installer/redist/` n'est pas lu par le script Inno |
| Installeur léger (défaut) | `scripts\publish-release.ps1` | Sans bases ClamAV ni règles YARA ; téléchargement au premier lancement si la release YARA-Forge `latest` correspond à l'asset, la taille et l'empreinte approuvés dans le code |
| Offline (tout) | `-EmbedOfflineSignatures` | CVD ClamAV + règles YARA embarqués |
| Offline ClamAV seul | `-EmbedClamAvDatabase` | ~105 Mo CVD |
| Offline YARA seul | `-EmbedYaraRules` | fichiers `.yar` |

---

## 4. Chaîne de publication fiable

L'UI de publication de Visual Studio s'est révélée peu fiable ici. Préférer les scripts :

```powershell
# Chaîne complète v3.1 candidate (recommandée)
.\scripts\prepare-release-v3.ps1

# Publish + compilation Inno (sans signature, sauf si le parcours PFX ci-dessous est utilisé)
.\scripts\publish-release.ps1
.\scripts\publish-release.ps1 -EmbedOfflineSignatures   # bases ClamAV + règles YARA dans le setup

# Publish déjà fait → Inno seul
.\installer\build-release-setup.ps1 -SkipPublish
```

Le script `publish-release.ps1` publie et compile l'installeur. Avec `-CertSubject`, il signe l'application, le service et les DLL plateforme publiés ; il ne signe pas l'installeur ni son désinstalleur. Pour une publication entièrement signée, utiliser la procédure de [`SIGNATURE_PROCEDURE.md`](SIGNATURE_PROCEDURE.md), qui signe aussi l'installeur et son désinstalleur. Sans certificat, la build reste non signée.

Le publish WPF recopie aussi les assets disque (`optiSCAN.ico`, hero, shield) via la cible MSBuild `CopyEmbeddedAssetsToPublish` — nécessaires au systray, à `verify-runtime-deps` et à Inno.

---

## 5. Checklist avant release

- [ ] Code committé et build CI vert (tests + CodeQL + gitleaks).
- [ ] Vérifier que le pilote minifiltre et le fournisseur AMSI restent absents du publish et de l'installateur tant que leur implémentation n'a pas été validée.
- [ ] Si le certificat est disponible, signer les binaires avec `scripts/codesign.ps1`, puis l'installeur et le désinstalleur avec `-SignPfxPath` ; sinon documenter que la build est non signée.
- [ ] Vérifier que le runtime est inclus dans le publish de release (`verify-runtime-deps.ps1`).
- [ ] Assets publish présents (`optiSCAN.ico`, hero, shield) — `verify-runtime-deps.ps1`.
- [ ] Testé sur poste vierge + poste avec Kaspersky/Defender.
- [ ] Politique de confidentialité accessible ([POLITIQUE_CONFIDENTIALITE.md](POLITIQUE_CONFIDENTIALITE.md) ; à exposer aussi dans l'app / site).
- [ ] Vérifier les moteurs épinglés avant publication (`scripts/runtime-versions.json`). Au 4 octobre 2026 : [ClamAV 1.4.6](https://www.clamav.net/downloads) (signature Talos et SHA-256 vérifiés) et YARA 4.5.5, dernier binaire Windows officiel. Les versions [YARA 4.5.6 à 4.5.8](https://github.com/VirusTotal/yara/releases) n'ont pas de binaire Windows. Relancer `fetch-runtime-deps.ps1` : le marqueur `.pinned-version` force le remplacement des binaires d'un ancien épinglage.
- [ ] Vérifier la pin YARA-Forge de `YaraForgePackageIntegrity` avant publication. L'état courant autorise seulement la release `20261004`, `yara-forge-rules-core.zip`, 1 747 609 octets, SHA-256 `0b548dff76139b7a041d20923ccfddfa614db6b6ee8710c181ff037a753ffe69`. Une nouvelle release upstream exige une revue du ZIP et une mise à jour optiSCAN avant d'être installable ; valider aussi que les règles ne sont pas embarquées par inadvertance dans le profil par défaut.
- [ ] Confirmer sur GitHub le succès des deux jobs CodeQL (C# et C/C++ `native/`) après publication du workflow ; `workflow_dispatch` permet une exécution manuelle.
- [ ] Numéro de version cohérent (`Directory.Build.props`, Inno, README) — **v3.1 / 3.1.0**.
