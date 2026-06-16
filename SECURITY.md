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

- **Quarantine**: AES-256-GCM encryption, HMAC-signed manifest, DPAPI-protected master key.
- **Sensitive paths**: restore and IPC scan refuse System32, Windows, ProgramFiles, ProgramData, Startup.
- **IPC pipe**: ACL (SYSTEM / Administrateurs / utilisateurs authentifiés) ; `shutdown` exige un jeton sous `%ProgramData%\optiSCAN\` ; scan refuse les chemins sensibles.
- **Secrets**: user preferences (VirusTotal key) stored via DPAPI `SecureStore`; no credentials in the repository.
- **CI**: Release builds treat warnings as errors; CodeQL (C# and native AMSI); Dependabot for NuGet and GitHub Actions.

## Threat model notes

optiSCAN is a **desktop antivirus for Windows**. It assumes:

- Protection against typical user-space malware and misconfiguration.
- **Not** a guarantee against malware running with the same user privileges or kernel-level attackers.
- DPAPI `CurrentUser` protects local data from other users, not from same-session malware.

## Hardening backlog

- Code signing for installer binaries
- Minifilter driver build in CI
- Dependency review / SBOM in release pipeline
