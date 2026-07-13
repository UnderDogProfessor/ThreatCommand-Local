# Security Policy

ThreatCommand Local is designed to run on a single workstation and binds its web services to `127.0.0.1`. It is not a multi-user service, managed security platform, or replacement for an organization's incident-response process.

## Supported local security baseline

- Start with a unique `.env` database password and never commit that file.
- Create the required Local Access Protection passphrase on first launch.
- Local API requests have bounded in-memory limits; passphrase setup and unlock attempts are deliberately restricted more tightly.
- Keep Docker Desktop and the workstation patched.
- Enable only sources whose terms, rate limits, and data handling you accept.
- Treat feed content, import candidates, Copilot output, and learning detections as untrusted until a qualified human validates them.
- Run `health-check.bat` after upgrades and run `verify-backup-local.bat` against important backups.
- Before publishing or accepting a contribution, run `security-check-local.bat`; it validates Compose configuration, scans source files for common credential patterns, and checks the pinned frontend and backend dependencies without requiring a machine-wide PowerShell execution-policy change.

## Reporting a vulnerability

Do not post credentials, personal data, or an exploit proof of concept in a public issue. Until a repository owner publishes a private reporting channel, open a minimal issue that describes the affected version, the security impact, and safe reproduction boundaries. Repository owners should replace this section with a monitored private contact before public release.

## Scope and limitations

The local passphrase protects the API session in a browser. It does not encrypt the database at rest, protect an unlocked Windows account, or provide authorization for remote users. The optional external AI provider can transmit the submitted question and selected local evidence only after local configuration, provider selection, and per-request approval.
