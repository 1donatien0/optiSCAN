# Avis de composants tiers — optiSCAN v3.1

optiSCAN est un logiciel libre distribué sous la GNU GPL v3 ou ultérieure (`LICENSE.txt`). Il livre les
composants ci-dessous, chacun sous sa licence d'origine.
Les textes de licence sont installés avec le logiciel :

- `licenses\` : ce fichier et la licence de YARA ;
- `clamav\x64\licenses\` : licence de ClamAV (GPLv2, `COPYING.txt`) et avis des bibliothèques
  fournis par l'archive officielle de ClamAV (`COPYING.*`).

## Moteurs livrés

| Composant | Version | Licence | Texte |
|---|---|---|---|
| ClamAV (`clamscan`, `clamd`, `freshclam`, `libclamav`, `libfreshclam`) | 1.4.6 | GNU GPL v2 | `clamav\x64\licenses\COPYING.txt` |
| UnRAR (`libclamunrar`) | livré avec ClamAV | Licence UnRAR (restrictive : interdit de recréer l'algorithme de compression RAR) | `clamav\x64\licenses\COPYING.unrar` |
| libcurl | livré avec ClamAV | Licence curl (type MIT) | `clamav\x64\licenses\COPYING.curl` |
| bzip2 | livré avec ClamAV | Licence bzip2 | `clamav\x64\licenses\COPYING.bzip2` |
| PCRE2 | livré avec ClamAV | BSD-3-Clause | `clamav\x64\licenses\COPYING.pcre` |
| zlib | livré avec ClamAV | Licence zlib | `clamav\x64\licenses\COPYING.zlib` |
| OpenSSL 3 (`libcrypto`, `libssl`) | livré avec ClamAV | Apache-2.0 | https://www.openssl.org/source/license.html |
| libxml2 | livré avec ClamAV | MIT | https://gitlab.gnome.org/GNOME/libxml2 |
| json-c | livré avec ClamAV | MIT | https://github.com/json-c/json-c |
| libssh2 | livré avec ClamAV | BSD-3-Clause | https://libssh2.org/license.html |
| nghttp2 | livré avec ClamAV | MIT | https://github.com/nghttp2/nghttp2 |
| pthreads4w (`pthreadVC3`) | livré avec ClamAV | Apache-2.0 | https://sourceforge.net/projects/pthreads4w/ |
| PDCurses | livré avec ClamAV | Domaine public | https://pdcurses.org/ |
| Redistribuable Visual C++ (`vcruntime140`, `msvcp140*`, `concrt140`) | livré avec ClamAV | Termes de licence Microsoft Visual C++ Redistributable | — |
| YARA (`yara64`, `yarac64`) | 4.5.5 | BSD-3-Clause | `licenses\YARA-COPYING.txt` |

Le code source de ClamAV 1.4.6 est publié par Cisco-Talos : https://github.com/Cisco-Talos/clamav/tree/clamav-1.4.6
(archive : https://www.clamav.net/downloads). Sur demande écrite à l'auteur d'optiSCAN (voir le dépôt du projet),
une copie du code source correspondant aux binaires ClamAV livrés est fournie pendant au moins trois ans,
conformément à la GPLv2 (article 3).

## Bibliothèques .NET

| Composant | Licence |
|---|---|
| Runtime .NET 10 et WPF / Windows Forms (publication autonome) | MIT |
| Microsoft.Extensions.DependencyInjection, Microsoft.Extensions.Hosting.WindowsServices, System.Management, System.ServiceProcess.ServiceController | MIT |
| MaterialDesignThemes, MaterialDesignColors | MIT |
| Microsoft.Toolkit.Uwp.Notifications | MIT |
| PDFsharp, MigraDoc 6.2.4 | MIT (https://github.com/empira/PDFsharp) |

## Données téléchargées après installation

- Bases de signatures ClamAV (database.clamav.net) : conditions de Cisco-Talos.
- Règles YARA-Forge (publication épinglée) : chaque règle porte sa propre licence dans ses métadonnées
  (https://github.com/YARAHQ/yara-forge).
