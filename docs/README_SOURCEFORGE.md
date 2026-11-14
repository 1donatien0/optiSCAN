# optiSCAN 3.1 — free antivirus for Windows

**optiSCAN** is a free antivirus for Windows 10 and 11 (x64). It combines the **ClamAV** engine and **YARA** rules with:

- real-time protection;
- a Windows protection service;
- script scanning before execution (AMSI);
- an encrypted quarantine.

It works alongside Microsoft Defender. It does not replace it.

**optiSCAN is free software**, released under the **GNU General Public License, version 3 or any later version** (`GPL-3.0-or-later`). You may use, study, modify, and redistribute it under the terms of that license.

> *En français — optiSCAN est un antivirus libre (GPL-3.0-or-later) pour Windows 10/11 x64. Il associe ClamAV et YARA, une protection en temps réel, un service de protection, l'analyse AMSI des scripts et une quarantaine chiffrée. Il complète Microsoft Defender. L'interface est en français et en anglais. Voir [Licence](#license) et [Code source](#source-code) ci-dessous.*

---

## Features

**Scanning**
- Quick, full, folder, and file scans, plus "Scan with optiSCAN" in the File Explorer right-click menu.
- ClamAV and YARA run in parallel. Their results are merged, with a risk score for each threat.
- A daily scan is scheduled. A scan missed while the computer was asleep starts when it wakes.

**Protection**
- **Real time:** risky files are scanned as soon as they are written, including an executable disguised with another extension.
- **Process start:** a program is examined just after it launches, along with the files passed to it by script hosts, `rundll32`, and `regsvr32`.
- **USB drives and SD cards:** scanned automatically when inserted.
- **AMSI:** PowerShell, JavaScript, VBScript, and Office macros are scanned before they run.
- **Windows service `optiSCANProtection`:** the computer stays protected even when nobody is signed in. The engines run in a Windows sandbox (AppContainer), with no network access.

**Threat handling**
- Encrypted quarantine (AES-256-GCM), with restore and delete.
- One history of scans, detections, and cleanups, exportable as **HTML** and **PDF**.
- Automatic updates of ClamAV signatures (every 4 hours) and YARA-Forge rules (every 24 hours).

**Tools**
- **PC security score out of 100**, with "Fix" links: firewall, UAC, Windows Update, shares, protection.
- **Optimize:**
  - cleanup of temporary files, browser caches, and the Recycle Bin;
  - application updates through `winget`;
  - reversible Windows settings (performance, privacy, interface).

**Interface**
- French and English.
- Light, dark, and high-contrast themes.
- Windows notifications.

## Limits to know

- optiSCAN **does not install a kernel driver**. File monitoring happens just after a write, not before it. A minifilter driver is being studied for a later version.
- AMSI **fails open**: if the service does not answer, the script runs.
- **RAR archive contents are not scanned.** ClamAV's UnRAR module is not shipped, because its license is not free. ZIP, 7z, CAB, and other archive formats are still scanned.
- Malware that already has administrator rights can disable a local antivirus, whichever product it is.
- Keep **Microsoft Defender turned on.** optiSCAN is built to run next to it.

## Requirements

- Windows 10 version 1809 or later, or Windows 11, **64-bit (x64)**.
- Administrator rights for installation and for the protection service.
- An Internet connection to download signatures after installation (about 300 MB for ClamAV).
- Nothing else to install: the .NET 10 runtime is included.

## Installation

1. Download `optiSCAN_Setup_v3.1.0.exe` from the **Files** tab.
2. Run it and choose the language and options: protection service (recommended), automatic signature updates, launch at startup, Desktop icon.
3. On first launch, let optiSCAN download the ClamAV signatures and the YARA rules.

Uninstall from **Windows Settings > Apps**. Uninstall removes the service, the AMSI provider, and, if they were enabled, the scheduled task and the Defender exclusions added by optiSCAN.

### Code signing

The **3.1.0 installer is not code-signed**. Windows may show "Windows protected your PC": click **More info → Run anyway**. Compare the SHA-256 of the file you downloaded with this value:

`D192B386B1FF6A668A973EBCB98F4E704DB7D3A104D45F087E09E62F00D16270`

The source code for this version is tag `v3.1.0` of the public repository: <https://github.com/1donatien0/optiSCAN>.

## Privacy

optiSCAN **sends no telemetry**. It connects only to the following services:

- the official ClamAV servers, for signatures (no local data is sent);
- GitHub, for the YARA-Forge rules of a pinned release (no local data is sent);
- **VirusTotal, only if you enter your own API key** (off by default). In that case only the file's SHA-256 is sent, never the file itself.

Details: [privacy policy](https://github.com/1donatien0/optiSCAN/blob/main/docs/POLITIQUE_CONFIDENTIALITE.md).

## Source code

The complete source code of optiSCAN is on **GitHub: <https://github.com/1donatien0/optiSCAN>**. It includes the application, the service, the C++ AMSI provider, the Inno Setup installer, and the build and release scripts. Each published version matches a `vX.Y.Z` tag, and a source archive is attached to each release.

To build:

```powershell
# Requirements: .NET 10 SDK, Visual Studio with "Desktop development with C++", Inno Setup 6
git clone https://github.com/1donatien0/optiSCAN.git
cd optiSCAN
.\scripts\fetch-runtime-deps.ps1      # ClamAV and YARA, checked by SHA-256 and GPG signature
dotnet test optiSCAN.sln -c Release
.\scripts\publish-release.ps1         # publish + installer
```

## License

```
optiSCAN — free antivirus for Windows
Copyright (C) 2026 Dona By (Donatien Byakombe)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program (file LICENSE.txt). If not, see
<https://www.gnu.org/licenses/>.
```

The full license text is shipped with the software (`LICENSE.txt`) and is shown during installation.

### Third-party components

optiSCAN ships free components that each keep their own license. Their texts are installed in the `licenses\` and `clamav\x64\licenses\` folders.

| Component | License |
|---|---|
| ClamAV 1.4.6 (`clamscan`, `clamd`, `freshclam`) | GNU GPL v2 |
| OpenSSL, libcurl, zlib, bzip2, PCRE2, libxml2, and the other ClamAV libraries | Their respective free licenses |
| YARA 4.5.5 | BSD-3-Clause |
| .NET 10 runtime, WPF | MIT |
| MaterialDesignThemes, PDFsharp/MigraDoc 6.2.4, Microsoft.Toolkit.Uwp.Notifications | MIT |

ClamAV signatures and YARA-Forge rules are downloaded after installation and remain under their authors' terms. ClamAV source code is published by Cisco-Talos: <https://github.com/Cisco-Talos/clamav>.

Full list: [THIRD-PARTY-NOTICES.md](https://github.com/1donatien0/optiSCAN/blob/main/installer/licenses/THIRD-PARTY-NOTICES.md).

## What is new in 3.1

**License**
- optiSCAN is now **free software under GPL-3.0-or-later**, replacing the old end-user license.
- Versions 1.0.0, 2.0.0, and 3.0.0 on the **Files** tab are republished under the same license: only the license shown at installation changes.
- Every source file carries an `SPDX-License-Identifier` header.
- The QuestPDF generator, whose license is not free, is replaced by PDFsharp/MigraDoc (MIT).

**Protection**
- An **AMSI provider** ships with the service: scripts are scanned before they run.
- **The engine is separate from the interface:** the service starts a dedicated host (`optiSCAN.Host.exe`), without WPF.
- **Confined engines:** under SYSTEM, `clamd`, `clamscan`, `yara`, and `yarac` run in an AppContainer, with no network and no child processes.
- The protection service is selected on a first installation. Its detections appear in the history and in notifications.

**Detection**
- Wider coverage: executables are recognized whatever their extension; `%APPDATA%` and the Public folder are part of the quick scan; USB Recycle Bins are scanned; seven additional script hosts are watched.

**Distribution**
- ClamAV and YARA are pinned and verified. This 3.1.0 installer is not code-signed. A signing setup is kept in the public repository for a later release.

**Quality**
- 771 automated tests, and an independent audit tracked in the repository.

Full history: [repository README](https://github.com/1donatien0/optiSCAN).

## Report a problem

- **Bugs and suggestions:** the *Tickets* or *Discussion* tab on this page, or *Issues* on GitHub.
- **Vulnerabilities:** do not post them publicly. Write privately to the author through his [SourceForge page](https://sourceforge.net/u/donaby) (see [SECURITY.md](https://github.com/1donatien0/optiSCAN/blob/main/SECURITY.md)).
- **False positive:** quarantine the file instead of deleting it. You can restore it and exclude it under *Options*.

---

Developed by **Dona By (Donatien Byakombe)**, 2026, with the Donaby Design system.
