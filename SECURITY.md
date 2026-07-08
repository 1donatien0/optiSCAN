# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 9.x (`main`, `dev`) | Yes |

## Reporting a vulnerability

If you discover a security issue in optiSCAN, please report it privately:

1. **Do not** open a public GitHub issue for exploitable vulnerabilities.
2. Email the maintainer with: description, reproduction steps, impact, and affected version.
3. Allow up to **14 business days** for an initial response.

## Security architecture (summary)

- **Self-scan exclusion**: install directory (Program Files / process base) and `%LocalAppData%\optiSCAN` (ClamAV DB, YARA rules, quarantine, update staging) are never scanned or auto-quarantined (`OptiscanProtectedPaths`); mandatory exclusion folders cannot be removed in Options.
- **Windows Defender coexistence (recommended on consumer PCs)**: Defender keeps real-time protection; optiSCAN runs as a **complement** (manual/scheduled ClamAV + YARA scans). `WindowsDefenderExclusionService` registers install paths and engine processes in Defender exclusions at install and startup. Tamper Protection may block automatic registration — add exclusions manually in Windows Security if needed.
- **Quarantine**: AES-256-GCM encryption, HMAC-signed manifest, DPAPI-protected master key; path traversal checks on restore.
- **Sensitive paths**: restore and IPC scan refuse System32, Windows, ProgramFiles, ProgramData, Startup.
- **IPC pipe**: ACL (SYSTEM / Administrators / authenticated users); `shutdown` requires a token under `%ProgramData%\optiSCAN\`; scan refuses sensitive paths; buffer size capped for AMSI/IPC.
- **AMSI (v9, optional)**: native `optiSCAN.AmsiProvider.dll` may be **shipped but inactive** — it is inert on disk until the platform protection service registers it under `HKLM\SOFTWARE\Microsoft\AMSI\Providers` (admin). With **platform protection disabled** or **Defender complement mode**, the DLL is not registered and is not loaded by Windows. When enabled, the provider forwards script buffers to `optiSCAN.Service` / `--service-host` via the protection pipe. With Windows Defender active, Microsoft’s AMSI provider typically takes priority in host processes.
- **Minifilter (v9, optional)**: kernel driver is optional and unsigned in current builds; not required for ClamAV/YARA scanning. Do not enable platform mode without a signed driver.
- **Secrets**: user preferences (VirusTotal key) stored via DPAPI `SecureStore`; no credentials in the repository.
- **CI**: Release builds treat warnings as errors; CodeQL (C# and native AMSI); Dependabot; dependency review on PRs (high severity fails); gitleaks; SBOM CycloneDX artifact on `main` publish.

## Threat model notes

optiSCAN is a **desktop antivirus for Windows**. It assumes:

- Protection against typical user-space malware and misconfiguration.
- **Not** a guarantee against malware running with the same user privileges or kernel-level attackers.
- DPAPI `CurrentUser` protects local data from other users, not from same-session malware.
- Running **two real-time engines** (Defender + optiSCAN RTP) increases disk I/O and false-positive risk; complement mode is the default when Defender is detected.

## Component states (v9)

| Component | Present on disk | Active |
|-----------|-----------------|--------|
| `optiSCAN.exe` + ClamAV/YARA | Yes (install) | On-demand / scheduled scans |
| `optiSCAN.AmsiProvider.dll` | Optional (installer) | Only if platform protection ON **and** HKLM AMSI registration succeeds |
| `optiSCAN.Minifilter.sys` | Optional | Only if signed and loaded (phase 2) |
| Windows Defender | OS | Primary RTP when enabled |

## Hardening backlog

- Code signing for installer and native binaries (Authenticode / EV for minifilter)
- Minifilter driver full implementation and build in CI (stub in repo today)
- Rate-limit IPC `ScanPath` / `ScanBuffer` when AMSI is disabled
