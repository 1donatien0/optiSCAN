# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x (WinUI 3 edition) | Yes |

## Reporting a vulnerability

If you discover a security issue in optiSCAN, please report it privately:

1. **Do not** open a public GitHub issue for exploitable vulnerabilities.
2. Email the maintainer with: description, reproduction steps, impact, and affected version.
3. Allow up to **14 business days** for an initial response.

## Security architecture (summary)

> **Fallback protection is user-mode.** Real-time protection can run in-process via `FileSystemWatcher` with **no kernel driver**. Outside Defender complement mode, the Windows service and AMSI provider are user-activatable (`PlatformProtectionFeatureGate.IsUserActivatable = true`). The kernel minifilter is attempted at load time; **unsigned drivers do not load on Windows x64**. SignPath is planned later for Authenticode / attestation.

- **Self-scan exclusion**: install directory (Program Files / process base) and `%LocalAppData%\optiSCAN` (ClamAV DB, YARA rules, quarantine, update staging) are never scanned or auto-quarantined (`OptiscanProtectedPaths`); mandatory exclusion folders cannot be removed in Options.
- **Windows Defender coexistence**: when Defender is active, a new install defaults to **complement mode** (Defender keeps real-time protection; optiSCAN's own RTP and process monitor are off, on-demand/scheduled/USB scans remain) — see `DefenderCoexistenceService`. At **application startup** (not by the installer, which only ships the script), optiSCAN registers the same protected paths and its processes (`optiSCAN.exe`, ClamAV/YARA binaries) in Defender exclusions via `WindowsDefenderExclusionService` (UAC relaunch at most once per 24 h); `scripts/add-defender-exclusions.ps1` does the same manually. Tamper Protection may block automatic registration — manual exclusions may be required. Because `%LocalAppData%\optiSCAN` is user-writable, its ACL is hardened at startup (`DirectoryHardening`: owner + SYSTEM + Administrators, inheritance broken) to reduce the risk of a third party dropping a payload into the Defender-excluded directory — see audit item **S-1** (summary in [README §12](README.md#12-audit-et-qualité-de-lédition-winui)). Residual hardening (narrowing the exclusion to specific subfolders/processes) is still open.
- **Quarantine**: AES-256-GCM encryption, HMAC-signed manifest, DPAPI-protected master key; path traversal checks on restore.
- **Sensitive paths**: restore and IPC scan refuse System32, Windows, ProgramFiles, ProgramData, Startup.
- **Installer prerequisites**: the default (framework-dependent) installer downloads the **.NET 10 Desktop Runtime** and **Windows App Runtime 1.8** only if missing, from Microsoft's official `aka.ms` redirects, and runs them silently before copying files.
- **Platform layer**: user-activatable (`PlatformProtectionFeatureGate.IsUserActivatable = true`); installer task checked by default on first install. IPC pipe ACL; `shutdown` requires a token under `%ProgramData%\optiSCAN\` (admin-only ACL). The minifilter kernel service (`optiSCANMinifilter`) and its instance/altitude are registered before a best-effort `fltmc load`, which is expected to fail until the `.sys` is signed.
- **AMSI (v1.0)**: native `optiSCAN.AmsiProvider.dll` forwards script buffers to `--service-host` via the protection pipe (admin registration). Registered when the platform task is selected. Authenticode for the DLL comes later (SignPath).
- **Secrets**: user preferences (VirusTotal key) stored via DPAPI `SecureStore`; no credentials in the repository.
- **CI**: Release builds treat warnings as errors; CodeQL (C# and native AMSI); Dependabot; dependency review on PRs (high severity fails); gitleaks; SBOM CycloneDX artifact on `main` publish.

## Threat model notes

optiSCAN is a **desktop antivirus for Windows**. It assumes:

- Protection against typical user-space malware and misconfiguration.
- **Not** a guarantee against malware running with the same user privileges or kernel-level attackers.
- DPAPI `CurrentUser` protects local data from other users, not from same-session malware.

## Hardening backlog

- Code signing for **optiSCAN.exe / installer / AMSI** via SignPath in about a year (reputation first); EV + Microsoft attestation later for **minifilter** — see `docs/GUIDE_DISTRIBUTION.md`, `scripts/sign-publish-artifacts.ps1`
- Minifilter driver full implementation and build in CI (stub in repo today)
- Elevated batches of the *Optimize → Tweaks* panel are written to the user's `%TEMP%` before the UAC prompt (`SystemTweaksService.RunElevatedBatch`, Defender-history helper): same-user malware could alter them between write and elevation. Move to an inline command or a protected location.
- Optional *backup before quarantine* (`BackupBeforeQuarantine`, off by default) keeps an **unencrypted** copy of the detected file in `%LocalAppData%\optiSCAN\SafetyBackups`, a directory that is excluded from optiSCAN and Defender scans. Store it encrypted like the quarantine, or outside the excluded perimeter.
- Narrow the Defender exclusion on `%LocalAppData%\optiSCAN` to specific subfolders / processes (audit item S-1).
