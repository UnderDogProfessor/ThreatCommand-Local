# ThreatCommand Local — Reassessment

## Executive verdict

- **Overall score:** **5.9/10** (up from **3.7/10** on July 12; **+2.2**)
- **Verdict:** ThreatCommand Local has moved from an attractive but weakly protected prototype to a credible, local-first personal intelligence and learning workbench. The remediation work materially improves data integrity, local security, connector governance, case evidence, and user transparency. It is still not an enterprise CTI, SIEM, or detection deployment platform.
- **Personal local use:** **Conditional but reasonable** for learning, CISA KEV/RSS review, and private non-sensitive case notes. Enable the optional local passphrase before storing sensitive investigation content.
- **External/public/enterprise use:** **No.** The product has no multi-user authorization model, enterprise identity, tested recovery drill, SBOM/vulnerability pipeline, complete detection test packs, or semantic RAG evaluation.

## Before and after

| Measure | July 12 | July 13 | Change |
|---|---:|---:|---:|
| Overall readiness | 3.7 | 5.9 | +2.2 |
| Personal local-use readiness | 5.5 | 6.7 | +1.2 |
| MVP readiness | 4.5 | 6.5 | +2.0 |
| Detection-engineer daily-use fit | 3.5 | 5.0 | +1.5 |
| Sensitive investigative-data trust | 3.0 | 5.0 | +2.0 |
| Enterprise readiness | 1.5 | 2.5 | +1.0 |

The sensitive-data score is deliberately capped because Local Access Protection is implemented but **not enabled in the running workspace**, and no clean-environment restore drill was evidenced.

## Evidence observed on July 13

- Frontend and API health check passed on `127.0.0.1`; PostgreSQL was healthy.
- UI, API, and database remained bound to loopback only.
- API ran as UID 10001 rather than root. The API container had `no-new-privileges` and all Linux capabilities dropped.
- Browser responses included CSP, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, and `X-Frame-Options: DENY`.
- A preflight from `https://evil.example` was rejected with HTTP 400.
- All 16 enabled connectors showed `success`, zero active failure counts, and no retry hold at the time inspected.
- Current local data: 24 connectors, 16 enabled; 631 non-demo news records; 1,637 live KEVs; 150 learning detections; 9 audit events.
- Migrations `011` through `016` were applied, covering source revision safety, unavailable-connector disablement, local access/audit, IOC/relevance, detection/case evidence, and source governance/backoff.
- Six targeted unit tests passed: feed text handling, zero-day classification, local access verifier/session, and external-AI approval defaults.

## Scorecard

| # | Audit domain | Score | Prior | Evidence status | Current rationale |
|---:|---|---:|---:|---|---|
| 1 | Product strategy and differentiation | 6 | 6 | Implemented | Local-first CTI, learning, and evidence workflow remains differentiated, though scope is broad. |
| 2 | Target-user fit | 6 | 6 | Implemented | Better suited to a personal analyst after the new review, evidence, and lifecycle screens. |
| 3 | Threat-intelligence usefulness | 6 | 5 | Implemented | CISA KEV plus public RSS are useful with source health and local reading; public feeds remain source-reported. |
| 4 | Intelligence relevance scoring | 6 | 2 | Implemented | Technology profiles, relevance states, and explainable vulnerability factors replaced the former opaque posture premise. No profiles are populated yet. |
| 5 | Data quality, provenance, and freshness | 7 | 3 | Implemented | Source-item keys, revisions, content timestamps, parser versions, and lifecycle views repair the old raw-content mismatch. |
| 6 | Vulnerability prioritization | 7 | 4 | Implemented | KEV, CVSS, recency, recorded technology, criticality, and validated exposure are explained without asserting affect. |
| 7 | IOC intelligence lifecycle | 5 | 1 | Implemented, unpopulated | Typed IOC schema and lifecycle states exist; no IOC records or sightings are present yet. |
| 8 | Detection engineering workflow | 6 | 3 | Implemented | Maturity, ownership, telemetry state, revisions, validation results, and local lifecycle UI exist. |
| 9 | Detection quality and validation | 3 | 1 | Partially implemented | Validation recording exists, but there is no Sigma/KQL parser or runnable benign fixture engine; zero validation results are recorded. |
| 10 | ATT&CK mapping and coverage integrity | 4 | 2 | Partially implemented | Learning templates are separated from operational claims; data-component feasibility remains incomplete. |
| 11 | Threat-hunting workflow | 6 | 3 | Implemented | Hypotheses, evidence labels/hashes, and finding taxonomy are available without executing queries. |
| 12 | Incident response and case workflow | 6 | 3 | Implemented | Evidence separation, audit events, and a local handover export with an integrity manifest are present. |
| 13 | AI Copilot quality | 4 | 3 | Partially implemented | Bounded cited evidence and provider controls improve it, but no local model is configured or live answer evaluation evidenced. |
| 14 | RAG grounding and hallucination resistance | 2 | 1 | Partially implemented | Citations and untrusted-source delimiters exist; embeddings, chunking, semantic retrieval, and answer validation do not. |
| 15 | AI safety and human-in-the-loop controls | 7 | 3 | Implemented | Untrusted source data is delimited, external AI needs a fresh opt-in, Offline Mode blocks it, and privacy-preserving audit events are written. |
| 16 | Privacy and local-data protection | 7 | 6 | Partially implemented | DPAPI backup, no secret backup copy, raw-content purge, and local access option improve protection. Disk encryption and enabled access protection remain user actions. |
| 17 | Local-first architecture and network controls | 8 | 6 | Implemented | Loopback ports, safe connector destinations, allowlists, request logging, backoff, and Offline map blocking are strong for a personal tool. |
| 18 | Application security | 7 | 3 | Implemented | Trusted-host protection, CSRF/session design, security headers, non-root runtime, and dropped capabilities were verified. Rate limits and scan automation remain absent. |
| 19 | Authentication/authorization/session security | 5 | 1 | Implemented but inactive | Optional PBKDF2 passphrase, HTTP-only session, and CSRF controls exist; the current workspace has not enabled them. |
| 20 | Data security, backup, retention, and deletion | 7 | 2 | Partially implemented | Encrypted DPAPI backups, integrity manifests, source retention, raw purge, and lifecycle view are present. Restore and full-erasure drills remain unverified. |
| 21 | Extensibility and connector architecture | 6 | 3 | Partially implemented | Parser availability, source governance, safe destination validation, revisions, and backoff improve controlled extensibility; manifests/isolation remain limited. |
| 22 | Usability and UX | 7 | 6 | Implemented | Review queue, lifecycle workspaces, evidence ledger, audit trail, and local handover improve the analyst path. |
| 23 | Dashboard clarity and operational value | 7 | 5 | Implemented | The active Command Center is intelligence/review focused, not based on the old static posture panel. Further layout presets would help. |
| 24 | Accessibility | 5 | 3 | Partially implemented | Focus indicator, Escape modal dismissal, high-contrast, large-text, and reduced-motion preferences exist. Focus trapping and formal accessibility testing remain absent. |
| 25 | Performance and resource efficiency | 5 | 4 | Partially implemented | Bounded requests and source backoff help; there is still no benchmark, quotas, or large-dataset profiling. |
| 26 | Reliability, resilience, and error handling | 6 | 3 | Partially implemented | Per-source failures, retry hold, scheduled checks, audit, and health verification are improved. No chaos/recovery or rate-limit fixture suite exists. |
| 27 | Documentation and non-technical-user operability | 7 | 3 | Implemented | Docs now explain encryption, external-AI disclosure, retention, and implemented local workflows. |
| 28 | Maintainability and upgrade path | 6 | 3 | Partially implemented | Sixteen migrations, tests, and hardened containers improve maintainability. A lockfile, SBOM, scans, and release process are still missing. |
| 29 | Compliance/governance readiness | 6 | 2 | Partially implemented | Source governance fields, local audit, evidence hashes, and handover provenance exist; policy, license review, and classification are incomplete. |
| 30 | Overall readiness | 6 | 3 | Implemented | A materially safer personal local workbench, not a trusted production security platform. |

## Improvements confirmed since the prior audit

1. **Source evidence integrity:** RSS/CISA/NVD paths now record source-item identity, revision, parser version, content-change time, and current raw content rather than silently leaving stale detail text.
2. **Controlled connector egress:** HTTPS-only public destinations, redirect/allowlist validation, parser availability status, disabled MITRE template, retry hold, and per-source failure counts were added.
3. **Actual local security baseline:** trusted host filtering, optional PBKDF2 local passphrase, HTTP-only session, CSRF checks, security headers, non-root API/frontend containers, and dropped capabilities were implemented.
4. **Sensitive local data controls:** DPAPI-encrypted backups and integrity manifests replace plaintext database backups; `.env` is excluded; the former known default database password was removed.
5. **Explainable analyst workflow:** technology profiles, relevance decisions, transparent vulnerability priority factors, IOC lifecycle, evidence ledger, hunt findings, incident evidence, audit trail, and handover provenance were added.
6. **Detection honesty and lifecycle:** learning templates remain explicitly non-operational, while maturity, ownership, telemetry state, revisions, and validation evidence can now be recorded locally.
7. **Safer AI boundary:** retrieval is bounded and delimited as untrusted data, citations are returned, cloud AI requires per-request approval, Offline Mode blocks it, and audit records avoid storing questions/answers.
8. **UX/accessibility:** visible focus, Escape dismissal, high-contrast, large-text, and reduced-motion preferences are present.

## Material gaps remaining

### Must do before using sensitive local case content

1. **Enable Local Access Protection.** It is implemented but currently disabled (`configured: false`).
2. **Perform and document a restore drill.** The backup scripts parse correctly and use DPAPI, but an actual clean-environment recovery was not run in this audit.
3. **Use device full-disk encryption and Windows sign-in protection.** Application-local controls do not protect against a compromised Windows account.

### Still needed for a stronger personal platform

- Populate Technology Profile and triage relevance; current counts are zero, so asset-aware priority is not yet personalized.
- Add validation evidence and benign fixture/parser checks before treating any detection as more than learning material.
- Build local semantic retrieval only after an appropriate local embedding model, chunking, citations, deletion, and evaluation set are in place.
- Add dependency, image, secret, and license scanning; generate an SBOM; expand automated tests to redirects, malformed feeds, imports, migrations, backups, access expiry, and export integrity.
- Add full deletion/retention execution reports, source-license verification, and formal accessibility testing/focus management.

## Audit conclusion

The system now earns a **5.9/10** rather than the previous **3.7/10** because the largest trust failures have been materially addressed in code and running configuration: content revision integrity, safe egress, local security controls, encrypted backups, honest detection lifecycle, evidence/case records, auditability, and documented behavior.

The score is intentionally not higher because several features are present but unused in the current workspace (local passphrase, technology profiles, IOC entries, validation results, case evidence), and because RAG, executable detection validation, recovery testing, supply-chain scanning, and enterprise controls are not yet evidenced.

**Recommended immediate user action:** enable Local Access Protection, record a small Technology Profile, review a few KEVs, and create a DPAPI backup. That will activate the parts of the new trust model that cannot be proven by code review alone.
