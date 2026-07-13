# Connector Extension Guide

## Phase 2 connector contract

Every connector must:

1. Be disabled by default.
2. Declare a human-readable name, source URL, data type, license/terms note, and credential requirement.
3. Show the exact destination and requested data before it can be enabled.
4. Require explicit acknowledgement when enabled.
5. Require explicit confirmation immediately before a Manual Sync request.
6. Respect HTTPS, source-host allowlists, public-IP-only destinations, rate limits, source terms, outages, malformed records, and unavailable sources.
7. Preserve source URL, retrieval time, raw content hash, record counts, and failures.
8. Never overwrite source-confirmed data with AI inference.

## Current connectors

| Connector | Status | Notes |
| --- | --- | --- |
| CISA KEV | Implemented | Parses the official JSON catalog after enable + Manual Sync confirmation |
| CISA Alerts RSS | Implemented, disabled | User-supplied public RSS URL; parser stores items as source-reported news |
| Zero Day Initiative RSS | Implemented, disabled | User-supplied public RSS URL; parser stores items as source-reported news |
| CIS Advisories Feed | Implemented, disabled | User-supplied public RSS URL; parser stores items as source-reported news |
| Cyber Alerts Public RSS | Implemented, disabled | User-supplied public RSS URL; parser stores items as source-reported news |
| 0dayfans RSS | Implemented, disabled | User-supplied public RSS URL; treat claims as unverified until corroborated |
| MITRE ATT&CK STIX | Registered template, unavailable | No parser is implemented; it cannot be enabled or scheduled |

The Feed Sources workspace also includes the user-supplied AWS Security Bulletins and Blog, Krebs on Security, BleepingComputer, The Hacker News, Graham Cluley, Schneier on Security, Troy Hunt, ESET, Sophos (two feeds), Securelist, Malwarebytes Labs, Cisco Talos, SANS ISC, Darknet Diaries, and NVD analyzed-CVE feeds. All are disabled by default and use the same source-reported RSS parser and confirmation controls.

## Adding a connector

Add its metadata through a new SQL migration, implement a parser in `backend/app/connectors.py`, and add regression tests before enabling it for use. Do not add a connector that requires bypassing a paywall, credential gate, robots rule, rate limit, or license.
