# Executive Verdict

- **Overall score:** 3.7/10
- **Verdict:** ThreatCommand Local is a promising, visually strong local intelligence workbench and learning tool, not yet a trustworthy threat-intelligence or detection-operations product. Its best qualities are local deployment, loopback-only published ports, explicit feed controls, CISA KEV ingestion, and a clear human-review stance. Its largest weaknesses are evidence integrity, provenance/freshness, lack of local access protection, placeholder detection content, absence of real RAG safeguards, weak lifecycle controls, no automated tests, and documentation that materially contradicts the running product.
- **Ready for local personal use?** Conditionally — for low-sensitivity learning, manually checked CISA KEV review, and non-authoritative personal note-taking. Not yet for sensitive investigation records or decisions that rely on the dashboard’s prioritization.
- **Ready for external/public/enterprise use?** No.
- **Top three reasons:**
  1. Feed content, source freshness, intelligence confidence, and relevance are not modeled well enough to support dependable operational conclusions.
  2. The local API has no authentication or session boundary, backups copy secrets in plaintext, containers run as root, and important web/container controls are absent.
  3. Detection Studio is a useful educational catalogue, but its rules are generic placeholders with no syntax, telemetry, test, version, deployment, or tuning evidence.

## Evidence boundary

This assessment examined the active Docker deployment, local API, browser UI, PostgreSQL state, migrations, FastAPI code, Next.js code, connector/worker code, scripts, and supplied documentation on July 12, 2026 (with database timestamps observed in UTC on July 13). The health check passed. The running database held 24 connectors, 16 enabled, 551 live news records, 1,637 live KEVs, 150 learning detections, six connectors currently marked failed, and no populated embeddings.

The following were **not provided or not verifiable from supplied evidence**: a threat model, architecture decision records, source-license review, SBOM, dependency/container vulnerability scan, automated test suite, security test report, backup/restore drill, AI evaluation set, prompt-injection test set, user research, performance benchmark, accessibility audit, model hardware sizing, or a tested data-erasure process. No score assumes any of those controls exist.

# Scorecard

| # | Audit domain | Score | Confidence | Evidence status | Rationale |
|---:|---|---:|---|---|---|
| 1 | Product strategy and differentiation | 6 | High | Implemented/claimed | Local-first CTI-to-learning workflow is differentiated, but scope has expanded beyond a coherent personal MVP. |
| 2 | Target-user fit | 6 | High | Implemented | Best fit is a security practitioner learning CTI/detection, not a production SOC. |
| 3 | Threat-intelligence usefulness | 5 | High | Implemented | CISA KEV and RSS ingestion work, but public-news aggregation is not enough to establish relevance. |
| 4 | Intelligence relevance scoring | 2 | High | Implemented | The dashboard returns a static posture score of 68; no transparent record-level formula or asset context exists. |
| 5 | Data quality, provenance, and freshness | 3 | High | Partially implemented | URL, hash, retrieval time, and raw text exist, but raw RSS content is not refreshed on update and source reliability/freshness are absent. |
| 6 | Vulnerability prioritization | 4 | High | Partially implemented | KEV/NVD paths exist and avoid claiming exposure, but no asset, exposure, criticality, remediation, or validation workflow exists. |
| 7 | IOC intelligence lifecycle | 1 | High | Missing | There is no normalized IOC entity, status, TTL, sighting, false-positive, or expiry model. |
| 8 | Detection engineering workflow | 3 | High | Partially implemented | Draft templates and educational detail exist; review, testing, ownership, change control, and export workflows do not. |
| 9 | Detection quality and validation | 1 | High | Implemented but inadequate | Generated Sigma/KQL is deliberately generic placeholder content and has no validator or test evidence. |
| 10 | ATT&CK mapping and coverage integrity | 2 | High | Partially implemented | Templates have ATT&CK labels, but no data-component feasibility, telemetry availability, test, deployment, or tuning evidence. |
| 11 | Threat-hunting workflow | 3 | High | Partially implemented | Hypothesis and scope capture exist; evidence, findings, query review, results, and closure learning do not. |
| 12 | Incident response and case workflow | 3 | High | Partially implemented | Basic cases/statuses/notes exist, without timeline integrity, evidence separation, handover, audit history, or reporting. |
| 13 | AI Copilot quality | 3 | High | Partially implemented | Local Ollama is a good default, but retrieval is limited to five threat summaries and is not a complete Copilot. |
| 14 | RAG grounding and hallucination resistance | 1 | High | Missing | pgvector/embedding columns exist but no embeddings, chunking, metadata retrieval, citations, or answer validation are implemented. |
| 15 | AI safety and human-in-the-loop controls | 3 | High | Partially implemented | Draft warnings and no autonomous tool execution are good; prompt injection and externally sent context are insufficiently controlled. |
| 16 | Privacy and local-data protection | 6 | High | Partially implemented | Published ports bind to loopback and no telemetry was found; encryption, local access protection, and secret/backup handling are weak. |
| 17 | Local-first architecture and network controls | 6 | High | Partially implemented | Loopback mappings, feed disclosures, request logs, and Offline Mode are strong starts; browser-based map traffic bypasses Offline Mode and no egress policy exists. |
| 18 | Application security | 3 | High | Partially implemented | Parameterized SQL and restrictive browser CORS are present; no auth, CSP/security headers, host validation, rate limits, scan pipeline, or hardened containers. |
| 19 | Authentication/authorization/session security | 1 | High | Missing | The local API exposes state-changing routes without an authentication or session mechanism. |
| 20 | Data security, backup, retention, and deletion | 2 | High | Partially implemented | Storage totals and raw-content pruning exist; backup encryption, restore proof, retention governance, erasure, and secret-safe backup handling do not. |
| 21 | Extensibility and connector architecture | 3 | High | Partially implemented | Connectors have database metadata and per-parser functions, not manifests, isolation, versioning, tests, or a permission model. |
| 22 | Usability and UX | 6 | Medium | Implemented | Navigation, detail modals, source controls, and review queue are understandable; density and operational prioritization need work. |
| 23 | Dashboard clarity and operational value | 5 | High | Implemented | It communicates “what is new,” but not “what requires action, why, and how fresh/credible it is.” |
| 24 | Accessibility | 3 | Medium | Partially implemented | Semantic buttons and labels help, but text is often 8–10px, modal focus is unmanaged, and no accessibility testing was provided. |
| 25 | Performance and resource efficiency | 4 | Medium | Partially implemented | Request timeouts and response bounds exist, but in-memory intelligence filtering, unbounded database growth, and no performance tests remain. |
| 26 | Reliability, resilience, and error handling | 3 | High | Partially implemented | Connector errors are logged and individual failures do not stop a batch; retries, backoff, stale status reset, test coverage, and recovery tests are absent. |
| 27 | Documentation and non-technical-user operability | 3 | High | Implemented but stale | Startup docs are useful, but they still say Phase 2/manual-only/Ollama-only while Scheduled Sync and external AI exist. |
| 28 | Maintainability and upgrade path | 3 | High | Partially implemented | Versioned migrations and pinned Python dependencies help; no tests, no lockfile, mutable image tags, duplicate legacy app, and no release process hurt maintainability. |
| 29 | Compliance/governance readiness | 2 | Medium | Partially implemented | Safe-use labels exist, but there is no data classification, evidence governance, license record, audit trail, or policy workflow. |
| 30 | Overall readiness | 3 | High | Implemented | Useful prototype/personal learning tool; insufficient evidence and controls for trusted operational use. |

Additional readiness scores:

| Measure | Score | Direct answer |
|---|---:|---|
| MVP readiness | 4.5/10 | A useful personal-learning MVP after the P0 trust work, not before. |
| Personal local-use readiness | 5.5/10 | Conditional: use for learning and source review, not sensitive cases or authoritative prioritization. |
| Production/enterprise readiness | 1.5/10 | No. |
| Would I use this daily as a detection engineer? | 3.5/10 | As a curated learning/reference shelf, yes; as a detection engineering system, no. |
| Would I trust this with sensitive investigative data? | 3.0/10 | No, until local access, encryption, backup handling, deletion, and audit controls exist. |

# What Is Strong

## Implemented and verified

- Docker publishes the UI, API, and PostgreSQL only on `127.0.0.1`; runtime inspection confirmed ports 3000, 8000, and 5432 are loopback-bound.
- CORS rejected an `https://evil.example` preflight and allowed only the local UI origin. It does not allow credentials.
- Connector enablement has a network disclosure, manual sync needs confirmation, and outbound connector attempts are logged locally.
- Offline Mode blocks connector/API AI calls; CISA KEV and RSS ingestion use timeouts and connector-specific failure logging.
- RSS content is converted to plain text before storage and React renders it as text, reducing ordinary feed-HTML XSS risk.
- CISA KEV ingestion stores local records and explicitly labels potential relevance rather than asserting local exposure or compromise.
- The UI makes source-reported news, original source links, local storage, and draft detection status reasonably visible.
- Import staging and human approval are a meaningful local-first safeguard. Uploads have a 15 MB limit and content-hash duplicate detection.
- Detection, hunt, incident, watchlist, digest, and source-management workspaces exist without auto-deploying, scanning, blocking, or remediating anything.
- The global attack map is disconnected by default and gives a browser-network warning before loading.

## Claimed/planned but not verified

- The documentation claims broad local-first privacy, but it does not reflect the optional external AI path or browser-direct map exception.
- pgvector is installed and an embedding column exists, but no embeddings or semantic retrieval were found.
- MITRE ATT&CK is registered as a connector but no parser exists.
- Backup/restore scripts exist, but no successful restore drill or backup-integrity test was supplied.

# Critical Gaps

## P0 — resolve before sensitive personal use

1. **Feed evidence can become internally inconsistent.** RSS deduplication hashes `connector|link|title`; on a repeat it only changes `retrieved_at`, not `raw_content`. The threat summary can change while the “full locally stored feed content” remains old. This makes the detail view non-authoritative. Fix with a source-item identity plus content revision/hash history, update raw content transactionally, and display “published / last retrieved / last changed.”
2. **The API has no local access boundary.** All state-changing endpoints are unauthenticated. Loopback reduces remote exposure but does not protect against another local user, malicious local process, browser compromise, or a DNS-rebinding/localhost attack path. Add an optional local passphrase that derives a session key, CSRF protection for browser writes, localhost host validation, idle lock, and a scoped API token for future automation.
3. **Offline Mode is not globally authoritative.** The Radware iframe/link is a browser-direct external request and can be loaded while the app reports Offline Mode; it is also absent from the connector request log. Either block it when offline or label Offline Mode precisely as “connector and AI offline; browser map is separate,” then provide a one-click browser privacy disconnect.
4. **Sensitive-data handling is inadequate.** First-run configuration contains a known development password, backups copy `.env` (including secrets) alongside plaintext SQL, and there is no encryption, restore verification, quota, or full erasure workflow. Make encrypted backup the default, exclude secrets by default, require an initial strong DB secret, document disk encryption, and add tested restore/erase operations.
5. **Detection coverage must never be inferred from the 150 templates.** Nearly all detections are draft learning templates. The generated Sigma body uses a literal review placeholder and every detection-format topic is forced to `process_creation`; KQL is a broad generic query. Do not show coverage counts as a capability metric; expose only “learning library” until rule feasibility and testing are evidenced.
6. **No automated regression/security test suite exists.** There are no test files, no connector fixtures, no malicious-input tests, no dependency/container scan, and no restore test. This is the main reason the app cannot safely evolve.
7. **AI is not safe enough to enable for untrusted intelligence.** Retrieved feed text is concatenated directly into the prompt. There are no untrusted-data boundaries, prompt-injection tests, citation validator, answer schema, content provenance in output, or external-AI request audit. The assistant has no tool execution — a strength — but its answers are still not demonstrably grounded.

## P1 — required for a genuinely valuable personal MVP

- Replace the static posture value with an explainable, per-record queue that exposes data age, source, confidence, relevance evidence, and unknowns.
- Add a technology/asset profile and a human-reviewed “potential relevance → confirmed relevance → not applicable” workflow. Never default unknown to affected.
- Introduce a normalized IOC and relationship model with first/last seen, validity, source reliability, analyst verdict, expired/stale states, and false-positive handling.
- Repair source management: set `next_sync_at` when enabling a connector in Scheduled Mode, prevent an unimplemented MITRE connector from being enabled, reset obsolete failure state when a URL changes, honour `CONNECTOR_ALLOWLIST`, and add per-source backoff/`Retry-After` handling.
- Version, validate, test, and lifecycle detections: Draft → Reviewed → Tested → Validated → Deployed → Tuned → Monitored → Retired. A personal tool can stop at Validated; it must not claim deployment.
- Add case timelines, immutable event/audit history, evidence references/hashes, findings, and a clear separation between analyst notes, source facts, and AI inference.
- Rewrite the documentation and in-product badges to match current behavior: Scheduled Sync, retention, external AI exception, and the browser-direct map.

# Dashboard and UX Findings

The current Command Center is aesthetically coherent and readable on a desktop. In a busy shift, though, it answers “what was ingested?” more clearly than “what needs attention now?” The three top cards are counts, not prioritization. “6 new KEVs” has no indication of whether they match a recorded technology, are fresh, are already triaged, or are merely newly dated by CISA. “10 live cybernews” makes volume look like value. The 150 learning detections card is safely worded, but still competes visually with operational intelligence.

The main visible hierarchy should be:

1. **Needs review now** — only records with a reason, source/date, confidence, stale status, and user-selected relevance evidence.
2. **New since last review** — separate from “last seven calendar days.”
3. **Source health** — compact, with failed/stale/overdue sources and a direct safe retry path.
4. **Learning / library** — a secondary workspace, not an operational metric.

Immediate changes:

- Remove the static posture score until it is calculated from documented inputs and shown with uncertainty.
- Replace count cards with review queue cards: “3 relevant KEVs awaiting validation,” “2 source items need corroboration,” “1 connector stale.”
- Show every card’s last refresh/retrieval time and age bucket. Avoid “live” when the last content is hours or days old.
- Keep the global map below the operational queue and label it decorative/contextual. It must not look like evidence about the user’s environment.
- Provide Analyst, Executive, and Learning layouts even for one user. Executive sees trends and decisions; Analyst sees queue/source evidence; Learning sees detections/hunts.
- In the first five minutes: select technologies, choose two high-signal feeds, set retention, review a sample KEV, create one action, and run a backup test. Do not ask users to enable 16 feeds.
- Accessibility is below the minimum expected for a professional console: 8–10px text is too small, color carries too much meaning, there is no visible skip navigation, and the modal has no focus trap, Escape behavior, or restoration of focus. Test keyboard-only and screen-reader flows before calling it usable.

# CTI and Data Findings

## Current state

The product has 24 connector records and 16 are enabled. Its strong source is CISA KEV. Most others are generic RSS/news feeds. This can create a compelling reading surface but not a trustworthy CTI system. Six connectors are currently marked failed; one enabled MITRE connector has no parser. One NVD failure shown in the UI was produced by an older source URL even though the database now points at the NVD API, so failure state can be misleading.

The implementation has basic provenance: connector key, source URL, content hash, retrieval time, raw content, and source-reported confidence. It does not have source reliability, license ID/version, item revision, source publication-versus-retrieval freshness, corroboration, analyst correction, data markings, canonical entities, or record supersession. Keyword severity makes `ransomware`, `remote code execution`, or `credential` “high”; that is not an intelligence severity model.

## Required minimum intelligence schema

- `source` (name, canonical URL, license/terms URL and version, reliability tier, feed policy)
- `source_item` (provider ID/link, source-published time, retrieved time, content hash, revision, raw body, parser version, status)
- `entity` and `relationship` (canonical CVE, IOC, malware, actor, technology, campaign; aliases; evidence links)
- `assertion` (what was claimed, by whom, confidence, corroboration, analyst assessment, contradiction state)
- `indicator` (type/value, first/last seen, valid from/until, state: observed/suspicious/malicious/stale/expired/sinkholed/false positive, source, evidence)
- `relevance assessment` (unknown/potential/confirmed/not applicable, evidence, owner, review date)
- `retention/deletion` (policy, expiration, tombstone, delete reason, purge completion)

Use four independent values instead of one overloaded confidence field: source reliability, evidence quality, corroboration count/quality, and analyst confidence. Freshness should be calculated per source/item: fresh, aging, stale, expired, and unknown — never silently inferred from sync success.

## Source policy

Start with CISA KEV, the NVD API after fixture tests, CISA advisories, and vendor advisories only for technologies the user records in their profile. Keep independent/vendor research as **news/context**, not a severity source. Delay podcasts, broad RSS mirrors, low-signal “zero day” feeds, and unimplemented STIX until terms, parser fixtures, failure recovery, retention, and a data model are ready. Do not scrape article pages to manufacture “full news”; feed-provided text plus a citation is the honest boundary.

# Detection and Hunting Findings

The library is a solid teaching concept, but it is not a detection-engineering workflow. It includes 150 educational drafts across On-Prem, Cloud, and Incident Response. The topic list is useful. The generated content is not production-grade: one generic Sigma log source is applied to unrelated topics, its match value is a placeholder, and the KQL query does not implement the stated behavior. No Sigma/KQL/SPL/Elastic/YARA/Suricata validation exists; only Sigma and KQL are generated. There are no rule owner, data component, source field mapping, ATT&CK version, test fixture, false-negative analysis, rule revision history, approval, or deployment state.

MITRE’s current guidance treats Data Components as the specific properties/values relevant to detecting a technique; a technique tag alone is not proof that telemetry can support a rule. The legacy ATT&CK data-source view is now deprecated in favor of the data-component approach. [MITRE ATT&CK Data Components](https://attack.mitre.org/datacomponents/) and [MITRE ATT&CK data-source notice](https://attack.mitre.org/datasources/)

Required rule metadata: stable rule ID, owner, platform/schema/version, ATT&CK technique/sub-technique and data components, telemetry prerequisites, field mappings, query logic, known false positives, expected blind spots, test fixture/results, confidence, maturity, reviewer, last validation, change history, and retirement reason.

Required maturity rule: a dashboard must show **Draft / Reviewed / Tested / Validated / Deployed / Tuned / Monitored / Retired**. “Coverage” can only count detections with present telemetry, a tested rule, a declared scope, and the matching maturity state. No current record meets that standard from supplied evidence.

Threat Hunting is a good bounded form, not a hunt system. Add lifecycle: Draft → Scoped → Approved → Collecting → Analyzing → Finding / No finding → Detection candidate → Closed. Require telemetry prerequisites before Active, collect timestamped evidence references, classify findings, support handover, and link a finding to a detection revision. Do not add query execution or endpoint access to this product.

Incident Notes should become a minimal evidence-led case workspace: immutable timeline events, separately tagged facts/claims/inference, evidence IDs/hashes, decision log, handover, and approved technical/executive export. Do not imitate a SOAR or automate containment.

# AI and RAG Findings

Local Ollama is the correct default. The code rejects nonlocal Ollama hosts and has no autonomous action/tool execution. Optional external AI is disabled by default, and Offline Mode blocks its API call. Those are meaningful safeguards.

It is not yet RAG. The Copilot retrieves up to five FTS-matched threat summaries only. It does not retrieve knowledge items, vulnerabilities, detections, hunt cases, source documents, chunks, vector embeddings, metadata, or source links. The `vector(768)` column and embedding settings are unused. A model response can therefore appear grounded without enough evidence.

The most material AI risk is prompt injection: untrusted source summaries are placed in the same prompt as instructions. A malicious RSS item can ask the model to ignore rules, fabricate a result, or manipulate the response. The model currently cannot call tools, delete data, alter connectors, change network mode, or deploy rules — retain that constraint.

Before enabling AI on non-demo data:

- Treat all retrieved/imported material as untrusted quoted data with explicit start/end boundaries.
- Use a strict system prompt that says retrieved text is never an instruction.
- Retrieve typed chunks with source ID, URL, date, content hash, trust tier, and freshness.
- Require citations for factual claims; refuse when relevant evidence is absent or conflicting.
- Return a structured answer: claim, evidence IDs, uncertainty, source age, and draft recommendations.
- Log local AI request metadata and, for external AI, show a per-request review of exactly what will leave the device and record the destination/data class locally.
- Add a red-team corpus for prompt injection, stale evidence, conflicting sources, fabricated CVEs/IOCs, attribution, unsafe actions, and invalid rules.

# Local Security and Privacy Findings

The loopback binding and restrictive CORS behavior are verified strengths. However, “localhost only” is not a complete security boundary. The API has no authentication/security scheme, state-changing requests need no anti-CSRF token, API docs remain reachable locally, and any local process can call the API. OWASP ASVS is a suitable verification basis because it covers the web/API controls that are currently incomplete, including architecture, access control, validation, data protection, files, logging, and configuration. [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)

Verified gaps:

- API, worker, and database containers run as root; root filesystems are writable; no capabilities are dropped.
- No CSP, `frame-ancestors`, `X-Content-Type-Options`, `Referrer-Policy`, or comparable application security headers were observed from the UI/API responses.
- Docker base images use mutable tags; frontend dependencies use version ranges and `npm install` without a lockfile. No SBOM, image scan, dependency scan, or signed release process was provided.
- `CONNECTOR_ALLOWLIST` is documented in `.env.example` but is not used by the connector implementation.
- Redirect handling permits HTTPS redirects but has no hostname/IP allowlist or private-address/DNS-rebinding control. NVD redirect handling lacks the RSS final-HTTPS check.
- RSS has an 8 MB cap, but CISA/NVD payloads have no equivalent response-size limit. Upload has a 15 MB cap but no malware scan, content-type verification, STIX/MISP validation, queue quota, or sandboxed parsing.
- Backups copy `.env` and a plaintext database dump. The backup script hardcodes the default database name/user instead of consistently using configured values.
- No deletion endpoint/workflow exists for intelligence, imports, source data, exports, AI data, or backups. Rejecting an import deliberately leaves its source file behind.

Minimum secure configuration: require a changed database secret at first start; use a local passphrase/idle lock; run non-root containers with read-only roots where feasible and explicit writable mounts; add CSP/security headers and trusted-host protection; keep database port unpublished unless the user explicitly needs it; enforce connector host allowlists and DNS/IP checks after redirects; implement rate/size/queue limits; generate SBOMs and scan pinned/digest-locked images; encrypt backups with a user-held key; and provide a verification/restore/erase checklist.

## NIST CSF 2.0 view

NIST CSF 2.0 organizes outcomes into Govern, Identify, Protect, Detect, Respond, and Recover; Govern explicitly emphasizes risk strategy, roles, policy, and legal obligations. [NIST CSF 2.0](https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20) and [NIST’s Govern explanation](https://www.nist.gov/cyberframework/faqs)

| Function | Current capability | Key gap / practical next step |
|---|---|---|
| Govern | Draft warnings, source disclosures, and local-only intent | Add risk statement, data classes, source/license register, AI/network policy, decision/audit records. |
| Identify | CVE/news records, manual watchlists, optional user profile field | Add asset/technology inventory, ownership, criticality, exposure evidence, and relevance review. |
| Protect | Loopback ports, CORS allowlist, Offline Mode | Add passphrase/session protection, secrets/backup encryption, container hardening, secure updates. |
| Detect | KEV/RSS ingestion and learning detection library | Add telemetry/data-component inventory, tested detection lifecycle, source freshness, and evidence queue. |
| Respond | Actions, hunt cases, incident notes | Add evidence timeline, finding/decision workflow, handover, and approved report templates. |
| Recover | Backup/restore scripts | Add encryption, retention, integrity check, restore drills, and recovery evidence. |

# Feature Request Backlog

The table uses **Build** for recommended work, **Defer** for valuable work after the prerequisite phase, and **Reject** for ideas that should not enter this product now. Complexity is implementation complexity for this local product.

| ID | Feature / user problem | Persona | Detailed requirement and acceptance criteria | Security/privacy | Dep. | Size | Value | Priority / phase | Recommendation |
|---|---|---|---|---|---|---|---|---|---|
| P0-01 | Source revision integrity | Analyst | Preserve source-item identity plus revision history; updated body/hash/date must appear together; test changed feed content. | Evidence integrity | Schema/migrations | M | Critical | P0 / Immediate | Build |
| P0-02 | Local access lock | Sensitive-data user | Optional passphrase-derived session, idle timeout, CSRF on writes, trusted hosts, API token policy. | Protects local records | Auth design | L | Critical | P0 / Immediate | Build |
| P0-03 | Secure backup/restore | Local operator | First-run secret change, encrypted backup, no `.env` copy by default, integrity check, restore drill. | Secrets/forensics | Crypto UX | M | Critical | P0 / Immediate | Build |
| P0-04 | Documentation truth pass | Non-technical user | Match UI/docs to Scheduled Sync, retention, external AI, external map, and current phases; acceptance: no contradicted claim. | Informed consent | Release notes | S | High | P0 / Immediate | Build |
| P0-05 | Detection truth model | Detection engineer | Separate learning drafts from operational rules; prohibit coverage claims without maturity evidence. | Prevents false assurance | Rule metadata | M | Critical | P0 / Immediate | Build |
| P0-06 | Automated quality/security tests | Maintainer | Unit/integration fixtures for feeds, APIs, migrations, imports, XSS, path traversal, CORS, redirects, and backups; run in CI/local. | Regression safety | Test framework | L | Critical | P0 / Immediate | Build |
| P0-07 | AI evidence boundary | AI user | Untrusted retrieval delimiters, source citations, structured answers, prompt-injection tests, external request review/audit. | AI data leakage/injection | Retrieval redesign | L | Critical | P0 / Immediate | Build |
| P0-08 | Global offline enforcement | Privacy-first user | Offline blocks or clearly scopes every external route, including browser map; record approved map connection separately. | Network integrity | UI/state model | S | High | P0 / Immediate | Build |
| P1-01 | Technology & relevance profile | Personal defender | Record technologies, versions, criticality, and evidence; workflow Unknown → Potential → Confirmed/Not applicable. | Do not infer exposure | Schema/UI | L | Critical | P1 / Useful MVP | Build |
| P1-02 | Evidence-led review queue | Analyst | Explain reason, source, age, reliability, relevance status, owner, and next review date for each item. | Decision traceability | P1-01 | M | High | P1 / Useful MVP | Build |
| P1-03 | Connector correctness manager | Operator | Initialize schedules on enable, disable unimplemented sources, reset obsolete failures, use allowlist, support backoff/Retry-After. | Controlled egress | Connector layer | M | High | P1 / Useful MVP | Build |
| P1-04 | IOC lifecycle | CTI analyst | Typed indicators, first/last seen, TTL, source/verdict/status, sightings, expiry, suppression, and false positives. | Sensitive indicators | New schema | L | High | P1 / Useful MVP | Build |
| P1-05 | Vulnerability priority explainer | Vulnerability owner | Transparent score with exploitation, verified tech match, criticality, exposure, CVSS, recency, unknown inputs; no default affected state. | Avoids false certainty | P1-01 | M | High | P1 / Useful MVP | Build |
| P1-06 | Detection lifecycle & validation | Detection engineer | Required metadata, Sigma/KQL parser validation, fixture results, reviewers, revision history, maturity state. | No unsafe deployment | Rule engine | XL | Critical | P1 / Useful MVP | Build |
| P1-07 | Hunt evidence workflow | Hunter | Scoped hypothesis, telemetry check, evidence records, findings taxonomy, detection candidate link, closure lesson. | Authorized use | Case schema | M | High | P1 / Useful MVP | Build |
| P1-08 | Incident timeline & handover | Responder | Immutable timeline, fact/claim/inference labels, evidence links/hashes, decision log, exportable handover. | Evidence integrity | Case schema | L | High | P1 / Useful MVP | Build |
| P1-09 | Data lifecycle controls | Privacy user | Per-source retention settings, delete/purge confirmation, source removal, export deletion, backup retention/erase report. | Right-to-delete/local privacy | Job queue | M | High | P1 / Useful MVP | Build |
| P1-10 | Source/license registry | Operator | Source owner, terms URL/version, allowed use, refresh policy, last verification, parser version, health. | License/compliance | Connector schema | M | High | P1 / Useful MVP | Build |
| P2-01 | Typed STIX/MISP importer | CTI analyst | Parse and validate supported STIX/MISP subset into typed entities; retain original file and provenance. | Malicious-file isolation | Parser sandbox | L | High | P2 / Power user | Build |
| P2-02 | Local semantic retrieval | AI user | Chunk, embed, filter by source/type/date/trust, display citations and rebuild/delete embeddings. | RAG privacy | P0-07 | L | High | P2 / Power user | Build |
| P2-03 | Local AI model/resource manager | Local AI user | Model availability, context/window estimate, CPU/RAM/disk warning, model selection, safe failure state. | Resource exhaustion | Ollama integration | M | Medium | P2 / Power user | Build |
| P2-04 | Source corroboration workflow | CTI analyst | Link claims from multiple sources; show agreement, conflict, and unresolved status. | Attribution restraint | Entity model | L | High | P2 / Power user | Build |
| P2-05 | Source freshness dashboard | Operator | Fresh/aging/stale/expired badges, last success, last content change, overdue action, historical health. | Avoids stale intelligence | P0-01 | M | High | P2 / Power user | Build |
| P2-06 | Detection data-component mapper | Detection engineer | Map each rule to ATT&CK data components, collection source, normalized fields, availability, and feasibility. | Honest coverage | P1-06 | L | High | P2 / Power user | Build |
| P2-07 | Detection test-pack runner | Detection engineer | Offline benign fixtures with expected result, parser test, revision evidence; no deployment. | Safe validation | P1-06 | XL | High | P2 / Power user | Build |
| P2-08 | Export with provenance manifest | Analyst | Export a selected case/digest with citations, hashes, source/license and generation metadata. | Data minimization | Case/source schema | M | High | P2 / Power user | Build |
| P2-09 | Dashboard layout presets | Solo operator | Analyst/Executive/Learning presets, saved locally, with first-review checklist. | Local preferences | UX design | M | Medium | P2 / Power user | Build |
| P2-10 | Manual connector test harness | Maintainer | Fixture replay, malformed XML/JSON, redirects, oversized responses, rate limits, and parser-version tests. | SSRF/resilience | Test framework | M | High | P2 / Power user | Build |
| P2-11 | Scheduled-sync policy engine | Operator | Jitter, per-source minimum interval, retry/backoff, circuit breaker, budget, source-specific conditional GET. | Provider/privacy load | Connector layer | L | High | P2 / Power user | Build |
| P2-12 | Local audit trail | Sensitive-data user | Append-only event log for imports, deletions, settings, source changes, AI external sends, and case decisions. | Accountability | P0-02 | M | High | P2 / Power user | Build |
| P2-13 | Backup recovery center | Operator | Encrypted backup schedule, restore sandbox/verification, retention, and recovery drill evidence. | Recoverability | P0-03 | L | High | P2 / Power user | Build |
| P2-14 | Evidence hashing/chain manifest | Responder | Hash evidence records and exports, record integrity check results, preserve original/revision relationship. | Forensic integrity | Case/source schema | M | Medium | P2 / Power user | Build |
| P2-15 | Personal operational profile onboarding | New user | Guided choice of assets, data sensitivity, feeds, retention, sync mode, and backup policy; safe defaults. | Consent/privacy | P1-01 | M | High | P2 / Power user | Build |
| P3-01 | Local entity graph | CTI learner | Optional graph of typed, cited relationships with freshness filtering. | Avoid visual certainty | Entity model | L | Medium | P3 / Advanced | Defer |
| P3-02 | Custom report templates | Analyst | Versioned local technical/executive templates with citation requirements. | Data minimization | Exports | M | Medium | P3 / Advanced | Build |
| P3-03 | ATT&CK release updater | Detection engineer | User-approved, versioned ATT&CK import with migration preview and rollback backup. | Supply-chain/version safety | Parser/versioning | L | Medium | P3 / Advanced | Defer |
| P3-04 | Offline asset CSV import | Personal defender | Validate a simple local asset inventory and map technologies without network discovery. | Sensitive asset data | P1-01 | M | Medium | P3 / Advanced | Build |
| P3-05 | Human-gated SIEM export | Detection engineer | Export reviewed rule packages only; never auto-deploy; show target assumptions. | Prevents unsafe actions | P1-06 | L | Medium | P3 / Advanced | Defer |
| P3-06 | Local feed quality analytics | Operator | Explain source signal/noise, duplicate rate, parse failures, and usage. | No telemetry export | P2-05 | M | Medium | P3 / Advanced | Build |
| P3-07 | Saved research queries | Analyst | Local saved filters, notes, and review reminders. | Local data only | Explorer | S | Medium | P3 / Advanced | Build |
| P3-08 | Incident checklist templates | Responder | Editable local containment/eradication/recovery checklists, not automated actions. | Clear human control | P1-08 | M | Medium | P3 / Advanced | Build |
| P3-09 | External AI provider adapters | Advanced user | Provider-specific data-class disclosure, response schema, local audit, opt-in per request. | Data egress | P0-07 | L | Medium | P3 / Advanced | Defer |
| P3-10 | Local accessibility preferences | All users | Font scale, contrast modes, reduced motion, keyboard shortcuts, persistent local settings. | Accessibility | UX refactor | M | Medium | P3 / Advanced | Build |

# Do Not Build Yet

| Idea | Why it should be deferred or rejected |
|---|---|
| Automatic IOC blocking/firewall changes | Creates unacceptable false-positive and authorization risk; no asset/telemetry/evidence model exists. |
| EDR isolation, account disablement, or patch deployment | This is a response platform scope and needs approvals, rollback, identity, and full audit trails. |
| Active scanning, exploit validation, or attack simulation | Changes the product’s safety boundary and requires explicit authorization controls. |
| A broad open connector marketplace | Unreviewed parsers introduce supply-chain, egress, licensing, and data-quality risk. Start with reviewed manifests and fixtures. |
| “Global threat score” or geographic attack attribution | It will overstate certainty and turn decorative telemetry into false operational evidence. |
| Autonomous AI agents that change settings/add feeds/delete data | Current trust, authentication, audit, and prompt-injection controls are insufficient. |
| Full SIEM/EDR ingestion and query execution | Scope and data volume would overwhelm a personal MVP before source/relevance/detection basics are trustworthy. |
| Multi-tenant cloud hosting | Contradicts the local-first differentiator and requires a complete identity, tenancy, encryption, support, and compliance program. |
| Social/community reputation scoring | High moderation, privacy, defamation, and low-signal burden without clear MVP value. |
| Mandatory commercial CTI integrations | Adds cost, licensing, secrets, support, and privacy complexity before the public-data workflow is reliable. |

# Roadmap

## Immediate critical fixes

**Objectives:** Restore truthfulness of data and controls before adding features.

- Fix RSS revision/raw-content consistency and connector status/schedule bugs.
- Disable or clearly mark unimplemented MITRE connector; enforce allowlisted connector hosts and safe redirect checks.
- Make Offline Mode cover or accurately exclude the browser map.
- Replace default database secret on first run; encrypt backups and stop copying `.env` by default.
- Add a local passphrase/session guard and baseline security headers.
- Remove static posture/coverage implications; label every learning draft clearly.
- Update all docs and badges.

**Security/tests:** fixture tests for changed RSS content, redirects, path traversal, oversized JSON, Offline Mode/map behavior, authentication, backups, and migrations.

**Success/exit:** every external path is inventoried; the UI accurately states all network/AI behavior; a feed update changes the stored detail atomically; encrypted backup restores in a clean test environment.

**Do not add:** more feeds, AI features, a graph, enterprise integrations, or any active response.

## Phase 1 — Trustworthy local prototype

**Objectives:** create defensible local evidence records and a safe personal access boundary.

- P0 backlog items; source revision/provenance/freshness, local lock, secure backup/restore, documentation, tests, AI boundaries.
- Structured source registry and data lifecycle model.
- Security hardening: non-root/read-only containers where practical, CSP/security headers, host validation, pinned releases and SBOM.

**Success/exit:** all critical user data can be backed up/restored/deleted intentionally; all connector parser paths have fixtures; no dashboard metric implies deployment/exposure; tests pass from a clean clone.

**Do not add:** additional external AI providers, automatic enrichment, source marketplace, or network actions.

## Phase 2 — Useful local MVP

**Objectives:** turn data into a small, explainable analyst queue.

- Technology/asset profile; potential/confirmed relevance; transparent vulnerability priority formula.
- Evidence-led review queue, source health, connector policy/backoff, IOC lifecycle.
- Detection lifecycle/metadata/validation and hunt/incident evidence workflow.
- Two or three high-signal sources only, selected by the user’s stack.

**Security/tests:** relevance edge cases, false certainty tests, detection fixture validation, source-license display, data deletion, and scheduled-sync rate-limit tests.

**Success/exit:** an analyst can explain why every queued item appears, what evidence supports it, what is unknown, and when it must be re-reviewed.

**Do not add:** SIEM control-plane access, deployment, endpoint actions, or multi-user collaboration.

## Phase 3 — Personal power-user platform

**Objectives:** deepen local analysis without expanding into an enterprise SOC.

- Typed STIX/MISP import, structured entity/relationship model, source corroboration, local semantic retrieval, rule test packs, backup recovery center, local audit trail, dashboard presets.

**Security/tests:** parser sandboxing, prompt-injection corpus, model resource limits, export redaction, integrity manifests, performance/storage limits.

**Success/exit:** large local data remains searchable and explainable; AI answers cite evidence and refuse unsupported claims; validated rules have reproducible fixtures.

**Do not add:** cloud tenancy, unreviewed plugins, autonomous agents, or auto-response.

## Phase 4 — Optional advanced integrations

**Objectives:** optional, human-gated interoperability for users who understand the privacy trade-offs.

- Approved external AI adapters with per-request review/audit.
- Human-gated reviewed-rule exports, ATT&CK updater, local entity graph, custom reports.

**Security/tests:** provider data-class policy, external request audit, export package validation, dependency/supply-chain checks, rollback/restore drills.

**Success/exit:** integrations are opt-in, scoped, auditable, reversible, and never silently change defensive systems.

# Test Plan

## Functional

- Clean startup/shutdown, repeated startup, migration upgrade, and data preservation.
- Offline Mode blocks connectors, external AI, and the map or explains its separate browser egress exactly.
- Manual Sync requires two disclosures; Scheduled Sync initializes newly enabled sources, honors schedule/jitter/backoff, and logs each attempt.
- Feed scenarios: 200 response, 301/302, HTTP downgrade, DNS/private-IP redirect, 429/Retry-After, timeout, malformed XML/JSON, duplicate, changed body with same URL/title, oversized body, source removal.
- Import scenarios: supported/unsupported extension, invalid STIX/MISP, 15 MB boundary, duplicate, malicious text, rejected/approved/delete/purge, queue quota.
- CISA/NVD fixture ingest, source revision, retraction/staleness, CVSS missing/conflicting, asset match unknown/potential/confirmed.
- Full-text and future semantic search; filters, pagination, empty/error states, source/detail citations.
- Detection: parser validation, fixture pass/fail, ATT&CK data-component prerequisites, maturity transitions, version/rollback, no deployment operation.
- Hunt/incident: evidence addition, timeline ordering, findings, handover/export, deletion/retention.
- Backup: encrypted backup, wrong-key failure, tamper detection, clean-environment restore, restore drill record.

## Security

- Verify all published ports remain loopback; test from another LAN host.
- Verify trusted-host, CORS, CSRF, session expiration, local API token scope, and DNS-rebinding resistance.
- Test URL scheme/host/IP allowlists before and after redirects; test SSRF to loopback, RFC1918, link-local, and metadata addresses.
- Test stored/reflected XSS through feeds, title, import preview, case notes, digest, and source URL; verify CSP.
- Test SQL injection, path traversal, malformed multipart, decompression/resource exhaustion, XML entity/DTD, poisoned STIX/MISP, and queue flooding.
- Verify no secret in logs, API response, UI, backup by default, or error detail; inspect external-AI payload audit.
- Run dependency vulnerability, SBOM, image/container, license, and secret scans on every release.
- Verify non-root container operation, read-only root behavior, data mount permissions, backup encryption, and data erase behavior.

## AI quality and safety

- Citation precision/recall: every factual statement must point to a current local source record.
- No-evidence, stale-evidence, conflicting-source, fabricated CVE/IOC, fabricated attribution, and fabricated incident tests.
- Prompt-injection corpus from RSS, STIX, MISP, Markdown, CSV, and user files; verify retrieved text cannot alter system policy.
- Unsafe-action prompts: ensure no connector/config/data action occurs and output remains draft/review-only.
- Detection generation: syntax, telemetry assumptions, ATT&CK data components, benign fixture behavior, false-positive/false-negative disclosure.
- Local-model unavailable, timeout, context overflow, low disk/RAM, external provider disabled, and external provider confirmation/audit tests.

## UX/accessibility

- First-time non-technical user can set a profile, choose sources, see privacy impact, and make an encrypted backup in five minutes.
- Experienced analyst can explain a queue item and open its evidence in 60 seconds.
- Keyboard-only: navigation, source switches, forms, modal open/close/focus return, Escape, and visible focus.
- Screen-reader landmarks, labels, live/error announcements, non-color status indicators, 200% zoom, mobile/tablet layout, contrast, reduced motion, empty/error/loading states.

# Final Recommendation

**Build next:** the Immediate Critical Fixes and Phase 1 trust layer — especially source revision integrity, local access protection, secure backups, true Offline Mode semantics, tests, and honest detection/relevance labeling.

**Delay:** more feeds, graphing, external AI expansion, SIEM integrations, a plugin marketplace, automated response, and all offensive/active capabilities.

**Validate before trusting the tool:** changed-feed preservation, provenance/freshness, local authentication/session behavior, encrypted backup/restore, deletion, redirect/SSRF controls, connector rate limits, prompt injection, detection fixture validity, and the absence of misleading “coverage” or “affected” claims.

**Smallest path to a high-value personal MVP:** a locally protected, tested CISA KEV + selected vendor advisory review queue tied to a small technology profile, with source/date/citation/freshness, a transparent “potential versus confirmed relevance” decision, secure backup/restore, and a clearly separate educational detection library. That is materially more useful — and more credible — than adding more dashboards or feeds.
