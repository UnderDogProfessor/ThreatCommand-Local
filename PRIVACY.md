# Privacy, Network, and Safety Notice

## Local-first operation

ThreatCommand Local runs through localhost only. Docker port mappings explicitly bind the UI, API, and database to `127.0.0.1`. It does not create public links, cloud accounts, hosted databases, analytics, remote error reporting, cloud backups, email delivery, or public deployments.

The database, imports, reports, detections, digests, configuration, logs, and backup files remain on the user-controlled computer. Local-only storage does not protect information if the computer itself is compromised; protect the device and keep encrypted backups.

## Local access protection

Local Access Protection is optional and can be enabled from Settings for sensitive local work. It stores a salted PBKDF2 verifier rather than the passphrase itself, issues an HTTP-only local browser session, and requires a CSRF token for local write requests. It is a local access boundary, not protection against a fully compromised Windows account. Use device sign-in and disk encryption as well.

## Network policy

- Initial mode is **Manual Sync**; the local user may explicitly choose Scheduled Sync for enabled, parser-supported sources.
- **Offline Mode** blocks all connector requests.
- A connector starts disabled.
- Enabling a connector shows its destination and disclosure and requires acknowledgement.
- Syncing requires a distinct, immediate confirmation.
- The API writes a local request log for every attempted connector request.
- Scheduled Sync records each connector request locally and obeys the source interval. It is not enabled merely by installing the app.

Docker image and package downloads are setup-time downloads, not intelligence synchronization. They do not receive your local intelligence, notes, imports, prompts, or database contents.

## AI and browser-direct exceptions

Ollama is the private default and rejects non-local endpoints. It has no cloud-model fallback. An optional OpenAI or OpenAI-compatible provider is disabled by default and requires an explicit local `.env` configuration, in-product provider selection, and a fresh per-request confirmation. When used, the question and selected local evidence leave this device for that provider; Offline Mode blocks that call. The local audit trail records only a question fingerprint and citation IDs for these requests, not the question or answer. Every generated rule, query, action, or remediation item must be considered **DRAFT — HUMAN REVIEW REQUIRED**.

The optional Radware map is a browser-direct request, not a connector or Copilot call. It remains disconnected until the user confirms it and is blocked by the app while Offline Mode is active.

## Connector safety

Public feed providers can see the public IP address of the computer retrieving a feed. External enrichment can reveal interest in an indicator; it is not implemented by default. Follow all source terms, licenses, rate limits, and access controls. Never bypass authentication, a paywall, or a subscription requirement.

## Authorized defensive use

This project supports defensive intelligence aggregation, vulnerability prioritization, detection drafting, defensive hunt preparation, investigation notes, and local reporting. It does not implement exploitation, scanning, malware, credential theft, evasion, destructive activity, automated response, rule deployment, endpoint isolation, firewall changes, or account actions.
