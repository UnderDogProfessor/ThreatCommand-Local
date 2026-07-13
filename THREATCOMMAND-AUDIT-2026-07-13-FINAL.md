# ThreatCommand Local — final 9/10 readiness audit

**Audit date:** 2026-07-13

**Scope:** local Windows/Docker deployment at `G:\Projects\Threat--Command-Final`

## Verdict

- **Current evidence-based readiness:** **8.2/10**
- **Engineering progress:** the highest-value remaining code-level gaps—local semantic retrieval, parser-backed Sigma checks, dialog focus handling, clean build output, and clone-friendly security checks—have been addressed.
- **9/10 gate:** not yet claimable as an overall operational/public-release score. It requires the remaining owner-controlled actions: adding a private security contact, enabling and exercising the local semantic model with real reviewed knowledge, and confirming workstation/data-protection controls.

This deliberately distinguishes implemented capability from unperformed owner actions. Re-labeling an unconfigured model, an unselected license, or unverified device encryption as complete would be misleading.

## Verified evidence

| Check | Result |
|---|---|
| Local stack | Frontend, API, worker, and PostgreSQL/pgvector healthy on localhost. |
| Migrations | **18** applied; `knowledge_chunks` exists. |
| Backend tests | **13 passed**: feed parsing, Copilot approval, access/session handling, rate limits, Sigma parsing, KQL advisory behavior, and local semantic chunk/vector guards. |
| Frontend production build | Passed cleanly with type checking and no CSS compatibility warnings. |
| Dependency/security check | `security-check-local.bat` passed Compose validation, source secret-pattern scan, `npm audit` (**0 vulnerabilities**), and `pip check`. |
| Browser smoke test | `http://127.0.0.1:3000` rendered the intended Local Access unlock screen instead of a blank page. The passphrase was not entered or handled during the audit. |
| Local access state | The API reports access protection is configured and locked; protected routes remain unavailable without the owner’s passphrase. |

## Improvements completed in this pass

1. **True local semantic retrieval.** Migration 018 adds chunk storage and pgvector indexing. Reviewed knowledge is chunked locally and embedded only through a configured loopback Ollama endpoint. Cloud embedding providers are never used.
2. **Honest retrieval behavior.** The Knowledge Base shows indexing status, requires a typed `REINDEX` confirmation, detects stale/unindexed knowledge, caps a rebuild at 2,000 chunks, and labels PostgreSQL keyword search as a fallback when semantic retrieval is unavailable.
3. **Grounded Copilot evidence.** The Copilot now retrieves and cites local knowledge chunks alongside locally stored threat-feed evidence. Source content stays bounded and inside untrusted-data delimiters.
4. **Deletion integrity.** Deleting a reviewed knowledge item through its import record cascades to its semantic chunks, so deleted data cannot remain retrievable from the vector index.
5. **Parser-backed Sigma checks.** Sigma rules are parsed locally by `pySigma` 1.4.0. The UI/API still state clearly that parsing does not compile a SIEM query, execute a rule, run a fixture, or establish production coverage. KQL remains a non-executing structural advisory.
6. **Accessibility polish.** Detail dialogs now return focus on close and keep keyboard Tab navigation within the active dialog, in addition to the existing Escape, contrast, visible-focus, text-scale, and reduced-motion controls.
7. **Clone operability.** `security-check-local.bat` now runs the security script with a process-only execution-policy bypass, matching the existing backup/restore wrappers and avoiding a machine-wide PowerShell policy change.
8. **Release-quality build output.** Replaced the two CSS alignment values that emitted Autoprefixer compatibility warnings; the final Next.js production build is clean.

## What remains before calling the project 9/10

| Owner-controlled gate | Why it cannot be automated safely | Completion evidence |
|---|---|---|
| Add a private security contact | A monitored private reporting channel is an operational ownership decision. | Replace the placeholder contact in `SECURITY.md`. |
| Activate and exercise semantic retrieval | The audit must not invent an Ollama model or upload/import private knowledge. | Configure a 768-dimension local Ollama embedding model, rebuild the index from reviewed local knowledge, and verify a cited retrieval in the Knowledge Base. |
| Confirm workstation protection | Source code cannot enable or attest to your Windows sign-in, BitLocker/device encryption, backup passphrase, or physical-device controls. | Enable/confirm full-disk encryption and make/verify an encrypted backup with a passphrase you control. |
| Validate detections in an authorized platform | This installation has no SIEM workspace, telemetry, or harmless fixture corpus supplied by the owner. | Record benign fixture results for priority Sigma/KQL detections in the Detection Lifecycle workspace. |
| Add local operating context | Technology Profiles, IOCs, relevance decisions, and cases must describe real local operations, not fabricated data. | Populate the relevant local records and review the resulting prioritization. |

## Score movement

The earlier post-remediation audit scored **7.4/10**. This pass materially improves local RAG grounding, hallucination resistance, Sigma validation quality, accessibility, and clone usability. The new **8.2/10** reflects those verified code and build outcomes. A verified 9/10 becomes appropriate only when the owner-controlled gates above are completed and evidenced.
