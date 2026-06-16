# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 8.x (`main`, `dev`) | Yes |

## Reporting a vulnerability

If you discover a security issue in optiSCAN, please report it privately:

1. **Do not** open a public GitHub issue for exploitable vulnerabilities.
2. Email the maintainer with: description, reproduction steps, impact, and affected version.
3. Allow up to **14 business days** for an initial response.

## Security architecture (summary)

- **Quarantine**: AES-256-GCM encryption, HMAC-signed manifest, DPAPI-protected master key; path traversal checks on restore.
- **Sensitive paths**: restore and IPC scan refuse System32, Windows, ProgramFiles, ProgramData, Startup.
- **IPC pipe**: ACL (SYSTEM / Administrators / authenticated users); `shutdown` requires a token under `%ProgramData%\optiSCAN\`; scan refuses sensitive paths.
- **AMSI (v8)**: native `optiSCAN.AmsiProvider.dll` forwards script buffers to `--service-host` via the protection pipe (admin registration).
- **Secrets**: user preferences (VirusTotal key) stored via DPAPI `SecureStore`; no credentials in the repository.
- **CI**: Release builds treat warnings as errors; CodeQL (C# and native AMSI); Dependabot; dependency review on PRs (high severity fails); gitleaks; SBOM CycloneDX artifact on `main` publish.

## Threat model notes

optiSCAN is a **desktop antivirus for Windows**. It assumes:

- Protection against typical user-space malware and misconfiguration.
- **Not** a guarantee against malware running with the same user privileges or kernel-level attackers.
- DPAPI `CurrentUser` protects local data from other users, not from same-session malware.

## Hardening backlog

- Code signing for installer and native binaries (Authenticode / EV for minifilter)
- Minifilter driver full implementation and build in CI (stub in repo today)
