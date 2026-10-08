# Procédure de signature de code — optiSCAN

**État : 5 octobre 2026 — v3.1 candidate.** Cette procédure décrit la chaîne actuellement configurée. La signature Authenticode est facultative : sans certificat configuré, la publication continue et les artefacts optiSCAN restent non signés.

## Artefacts de la version courante

Quand le secret de signature est configuré, la CI signe les binaires applicatifs publiés (`optiSCAN.exe`, DLL de l'application, service et plateforme), puis l'installeur Inno et son désinstalleur. Le PFX est importé temporairement dans le magasin utilisateur et `signtool` sélectionne le certificat par empreinte. Le mot de passe ne passe pas en argument de processus ; le PFX temporaire et la clé importée sont retirés à la fin du job.

Les moteurs ne suivent pas cette chaîne Authenticode : l'archive ClamAV est vérifiée par signature GPG Talos et SHA-256 ; le moteur YARA par SHA-256 épinglé. **AMSI et le minifiltre ne sont pas livrés** : leurs prototypes sous `native/` ne sont ni compilés par la CI, ni inclus dans le publish/installeur, ni enregistrés/chargés. Il ne faut pas suivre les anciennes étapes de signature et d'installation de ces prototypes pour une release v3.1.

## Signature dans GitHub Actions

Dans les secrets du dépôt, configurer :

| Secret | Valeur |
|---|---|
| `CODESIGN_PFX` | Contenu base64 du certificat PFX |
| `CODESIGN_PASSWORD` | Mot de passe du PFX |

Le job `publish` de [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) appelle `scripts/codesign.ps1 -Prepare`. Si `CODESIGN_PFX` est absent, il saute les étapes de signature et poursuit le build. Sinon, le job signe les binaires de l'application, puis appelle `installer/build-release-setup.ps1 -SignPfxPath` pour l'installeur et le désinstalleur. L'étape de nettoyage retire le PFX temporaire.

Le timestamp RFC 3161 est demandé à `http://timestamp.digicert.com`. `scripts/codesign.ps1` vérifie ensuite la signature des fichiers signés.

## Signature locale

Prérequis : Windows, Windows SDK (`signtool.exe`), un PFX autorisé à signer les fichiers, et le publish Release win-x64. Fournir `CODESIGN_PASSWORD` dans l'environnement du processus PowerShell depuis un gestionnaire de secrets ; ne pas écrire le mot de passe dans la commande ou dans un fichier versionné.

```powershell
$publish = (Resolve-Path .\publish\win-x64).Path
$files = @(
    (Join-Path $publish 'optiSCAN.exe'),
    (Join-Path $publish 'optiSCAN.dll'),
    (Join-Path $publish 'optiSCAN.Service.exe'),
    (Join-Path $publish 'optiSCAN.Service.dll'),
    (Join-Path $publish 'optiSCAN.Platform.dll')
)

pwsh -File scripts\codesign.ps1 -Sign -PfxPath .\cert.pfx -Files $files
pwsh -File installer\build-release-setup.ps1 -SkipPublish `
    -PublishDir $publish -SignPfxPath .\cert.pfx
```

`codesign.ps1` importe le certificat dans `CurrentUser\My`, le sélectionne par empreinte, signe les binaires listés, les vérifie, puis retire la clé importée. `build-release-setup.ps1 -SignPfxPath` applique la même méthode à l'installeur et au désinstalleur Inno. Sans certificat, lancer la chaîne de publication sans ces options.

L'option `scripts/publish-release.ps1 -CertSubject` signe l'application, le service et les DLL plateforme publiés, mais pas l'installeur ni son désinstalleur. Utiliser la procédure ci-dessus pour une publication entièrement signée.

## Vérification manuelle

```powershell
signtool verify /v /pa .\publish\win-x64\optiSCAN.exe
signtool verify /v /pa .\installer\output\optiSCAN_Setup_v3.1.0.exe
```

## Références de la chaîne

- [`scripts/codesign.ps1`](../scripts/codesign.ps1) — signature des binaires applicatifs
- [`installer/build-release-setup.ps1`](../installer/build-release-setup.ps1) — signature Inno
- [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) — publication et nettoyage du certificat
- [`SECURITY.md`](../SECURITY.md) — posture et chaîne d'approvisionnement
