# ThreatCommand Local — Post-remediation audit

## Executive verdict

- **Weighted overall score:** **7.4/10** (up from **5.9/10** in the July 13 reassessment; **+1.5**)
- **Verdict:** ThreatCommand Local is now a strong, local-first daily intelligence and defensive-learning dashboard with meaningful recovery, supply-chain, deletion, and first-run security controls. It is substantially more clone-ready for a public repository.
- **9/10 status:** **Not yet defensible.** A score must reflect demonstrated operation, not only code added. The required first-run passphrase has not been created by the local owner, no license/security contact has been chosen for public release, semantic retrieval is not implemented, and detection validation remains a safe structural advisory rather than a real Sigma/KQL platform test.

This report intentionally does not relabel the score as 9/10 just because the target is desirable.

## Verified evidence

- The stack was healthy on `127.0.0.1`: frontend, API, PostgreSQL, and worker all ran successfully.
- Migration **017** applied. The running database contained 17 migrations, 24 connectors (16 enabled), 631 live news records, 1,637 live KEVs, and 152 learning detections.
- The API now reported `configured: false`, `required: true`, and `unlocked: false`. Before setup, protected intelligence endpoints returned HTTP 428 while `/api/health` remained available.
- Browser smoke testing displayed the new **Protect your local workspace** screen with two passphrase fields and no browser console errors; it did not show a blank page.
- Ten backend unit tests passed: feed parsing, zero-day classification, Copilot default safety, access verifier/session behavior, detection lint behavior, and local rate limiting.
- A production frontend build completed successfully with locked dependencies. `npm audit --omit=dev --audit-level=high` found **0 vulnerabilities** after the PostCSS override; `pip check` found no broken backend requirements.
- `security-check-local.ps1` passed Compose validation, common secret-pattern scanning, the frontend dependency audit, and the backend dependency consistency check.
- A real non-destructive recovery drill completed: an encrypted test backup was restored into an isolated temporary database, verified **17 migrations**, **24 connectors**, and **1,639 vulnerabilities**, then the temporary database and all test backup artifacts were removed. The live database was not changed.
- `start-local.bat` was exercised after the Docker helper-path fix; it built and started the local stack. `health-check.bat` now waits up to 45 seconds for services rather than failing during normal startup.

## Scorecard

| # | Audit domain | Score | Evidence-based rationale |
|---:|---|---:|---|
| 1 | Product strategy and differentiation | 7 | Local-first intelligence, evidence, learning, and transparency workflow is clearly differentiated. |
| 2 | Target-user fit | 7 | Strong fit for a single analyst or learner; deliberately not multi-user. |
| 3 | Threat-intelligence usefulness | 7 | Live CISA KEV and public RSS sources, source health, and stored detail are useful daily. |
| 4 | Intelligence relevance scoring | 6 | Explainable local technology/relevance model exists but is still unpopulated. |
| 5 | Data quality, provenance, and freshness | 8 | Revision identity, timestamps, parser versioning, retention, and source governance are implemented. |
| 6 | Vulnerability prioritization | 8 | KEV, CVSS, freshness, technology criticality, and local relevance factors are transparent. |
| 7 | IOC intelligence lifecycle | 5 | Lifecycle is implemented but has no local IOC/sighting population. |
| 8 | Detection engineering workflow | 7 | Lifecycle, ownership, revisioning, evidence, and static advisory exist. |
| 9 | Detection quality and validation | 5 | Basic static lint is safe and tested, but is not a Sigma/KQL parser or benign fixture engine. |
| 10 | ATT&CK mapping and coverage integrity | 5 | Learning mappings are honest; platform/data-component feasibility is incomplete. |
| 11 | Threat-hunting workflow | 7 | Hypotheses, evidence labels, hashes, and findings are usable for authorized local work. |
| 12 | Incident response and case workflow | 7 | Case evidence, audit trail, and integrity-manifested handover export are implemented. |
| 13 | AI Copilot quality | 4 | Citations and provider controls exist; no configured local model or answer evaluation is evidenced. |
| 14 | RAG grounding and hallucination resistance | 2 | Bounded cited retrieval is present, but no chunks, embeddings, semantic search, or evaluation set exists. |
| 15 | AI safety and human-in-the-loop controls | 8 | Explicit external approval, offline blocking, untrusted-content delimiters, and privacy-preserving audit are strong. |
| 16 | Privacy and local-data protection | 8 | Mandatory setup gate, encrypted backups, raw purge, import/export deletion, and local-only binding are implemented. Disk encryption remains a workstation control. |
| 17 | Local-first architecture and network controls | 8 | Loopback binding, offline mode, safe redirects/DNS, allowlists, request logging, and backoff are verified. |
| 18 | Application security | 8 | CSP, trusted hosts, CSRF, non-root containers, capability drop, and bounded local request rates are present. |
| 19 | Authentication, authorization, and session security | 8 | First-run passphrase is enforced before intelligence access; the owner still needs to create the actual passphrase. |
| 20 | Data security, backup, retention, and deletion | 9 | Hash-verified encrypted backup, isolated restore verification, retention, and explicit erasure controls are verified. |
| 21 | Extensibility and connector architecture | 7 | Controlled connector lifecycle is strong; plugin manifests and parser isolation are not yet present. |
| 22 | Usability and UX | 8 | Clear first-run state, review queue, lifecycle workspaces, export erasure, and transparent source controls improve daily flow. |
| 23 | Dashboard clarity and operational value | 8 | Live news, KEVs, deep reading, detection learning, and global tracker provide practical daily value. |
| 24 | Accessibility | 6 | Focus indicators, Escape dismissal, contrast, text scale, and reduced motion exist; no formal accessibility suite/focus trap evidence. |
| 25 | Performance and resource efficiency | 6 | Bounded requests and retry hold help; no large-dataset benchmark or budget controls. |
| 26 | Reliability, resilience, and error handling | 8 | Retry behavior, startup wait, health checks, recovery drill, and connector failure reporting are verified. |
| 27 | Documentation and non-technical-user operability | 9 | Start, backup, restore, recovery verification, security, contribution, and public-clone guidance are materially improved. |
| 28 | Maintainability and upgrade path | 9 | Exact lockfile, digest-pinned Node/PostgreSQL images, CI, dependency audit, local security check, migrations, and tests are present. |
| 29 | Compliance and governance readiness | 7 | Source governance and evidence provenance exist; public license, private reporting contact, and formal policy remain owner decisions. |
| 30 | Overall readiness | 7 | Strong personal local workbench, not an enterprise CTI/SIEM or production detection deployment platform. |

## Improvements verified in this remediation

1. **Secure first run:** all intelligence API routes now require the user to create and unlock Local Access Protection. The UI guides setup instead of briefly rendering a blank or unprotected dashboard.
2. **Recovery that is actually exercised:** backup, restore, and verification now load DPAPI explicitly and use a passphrase-protected authenticated-encryption fallback when DPAPI is unavailable. The verifier restores into an isolated database and writes a local report without touching live data.
3. **Local erasure controls:** staged or approved imports, their derived knowledge entries, raw connector content, and handover exports can be removed with typed confirmation and audit events.
4. **Detection honesty:** the new built-in lint records only structural advice. It never executes a rule, query, fixture, or adversary behavior and labels its limitation in the UI and API.
5. **Supply-chain and release hygiene:** frontend versions are exact and locked, vulnerable PostCSS was overridden to 8.5.10, Node and PostgreSQL are digest pinned, dependency checks are clean, and GitHub CI now builds, tests, audits dependencies, starts the stack, and checks localhost health.
6. **Public-clone readiness:** `start-local.bat` creates a unique local database password on first run, Docker helper discovery works when Docker is found via its fallback location, and readiness checks tolerate normal container startup time.
7. **Security baseline:** local API request rates are bounded, and `security-check-local.ps1` gives maintainers a repeatable Compose, secret-pattern, and dependency audit.

## What still prevents a defensible 9/10

1. **Owner setup is intentionally outstanding.** Create the first-run passphrase in the browser, enable Windows sign-in/full-disk encryption, and make an encrypted backup using a passphrase you control. These cannot be completed safely by source code on the owner's behalf.
2. **Public-release authority is outstanding.** Choose a license and replace the placeholder private-security contact in `SECURITY.md`. A license is a material legal choice and was not guessed.
3. **RAG remains bounded retrieval, not semantic RAG.** A 9/10 claim needs opt-in local chunking/embedding retrieval, a configured local embedding model, citations, deletion handling, and evaluation evidence.
4. **Detection validation is not platform validation.** A 9/10 detection-quality score needs real parser-backed Sigma/KQL checks and benign, authorized fixture packs with expected results.
5. **Personalization has no operational evidence yet.** Technology Profiles, IOCs, relevance decisions, validation results, and case evidence remain mostly empty in the running workspace.
6. **Test depth remains limited.** Add API integration tests for migrations, access expiry/CSRF, import deletion, connector redirects/malformed feeds, recovery scripts, and export integrity before treating the project as release-complete.

## Conclusion

This remediation closes the previously unverified recovery, starter-password, dependency-locking, public-clone, deletion, rate-limit, and blank-page risks. It moves the application to a credible **7.4/10** evidence-backed overall readiness level today.

The route to 9/10 is now narrow and explicit rather than hidden: owner-controlled security/release decisions plus real semantic retrieval and parser-backed validation. Until those are demonstrated, reporting a 9/10 would be misleading.
