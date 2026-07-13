"""Safe, local detection-learning fixtures and a deliberately constrained evaluator.

The Detection Lab never starts a process, executes a query, contacts a SIEM, or
accepts arbitrary user-supplied code. It evaluates only bundled, benign events.
"""

from __future__ import annotations

import re
from typing import Any


def learning_level_for_rank(rank: int | None) -> str:
    """Give the curated 50-item segment library a repeatable learning path."""
    position = (rank or 1) % 25 or 25
    if position <= 7:
        return "beginner"
    if position <= 18:
        return "intermediate"
    return "advanced"


def topic_for(item: dict[str, Any]) -> str:
    title = str(item.get("title") or "Detection pattern")
    title = re.split(r"\s+(?:-|—)\s+", title, maxsplit=1)[-1]
    return re.sub(r"\s*\((?:Detection|Hunt & Tuning) Pattern\)\s*$", "", title).strip()


def _sigma_selection(item: dict[str, Any]) -> tuple[str, str] | None:
    """Read only a simple ``Field|contains: value`` learning predicate."""
    content = str(item.get("rule_content") or "")
    matched = re.search(r"(?mi)^\s*([A-Za-z][A-Za-z0-9_.-]*)\|contains\s*:\s*['\"]?([^'\"\n]+)", content)
    if not matched:
        return None
    return matched.group(1), matched.group(2).strip()


def _expected_event(item: dict[str, Any]) -> dict[str, str]:
    topic = topic_for(item)
    segment = item.get("segment") or "Foundational"
    event = {
        "TimeGenerated": "2026-07-12T14:08:00Z",
        "Host": "LAB-CLOUD-01" if segment == "Cloud" else "LAB-ENDPOINT-01",
        "Account": "lab.analyst",
        "Activity": f"Training signal for {topic}",
        "EventID": "1",
        "CommandLine": f"lab-simulator --review <review for {topic}>",
        "Source": "ThreatCommand Local Detection Lab",
    }
    selection = _sigma_selection(item)
    if selection:
        field, value = selection
        event[field] = f"lab-simulator --review {value}"
    return event


def fixture_catalog(item: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the bounded fixture set visible in the local learning lab."""
    topic = topic_for(item)
    expected = _expected_event(item)
    benign = {
        "TimeGenerated": "2026-07-12T14:12:00Z",
        "Host": expected["Host"],
        "Account": "lab.operator",
        "Activity": "Authorized inventory collection",
        "EventID": "1",
        "CommandLine": "lab-admin --collect-inventory",
        "Source": "ThreatCommand Local Detection Lab",
    }
    missing = {
        "TimeGenerated": "2026-07-12T14:16:00Z",
        "Host": expected["Host"],
        "Account": "",
        "Activity": "Incomplete training telemetry",
        "EventID": "",
        "CommandLine": "",
        "Source": "ThreatCommand Local Detection Lab",
    }
    if item.get("rule_format") == "Microsoft Sentinel KQL":
        benign_expected = True
        benign_purpose = "Shows why a broad training query needs a behavior-specific filter before production use."
    else:
        benign_expected = False
        benign_purpose = "A safe administrative look-alike that should not match the learning predicate."
    return [
        {"id": "expected-signal", "name": "Expected training signal", "purpose": f"A benign fixture carrying the review marker for {topic}.", "expected_match": True, "event": expected},
        {"id": "benign-look-alike", "name": "Benign administrative look-alike", "purpose": benign_purpose, "expected_match": benign_expected, "event": benign},
        {"id": "missing-telemetry", "name": "Missing required telemetry", "purpose": "Shows the effect of incomplete collection or normalization.", "expected_match": False, "event": missing},
    ]


def evaluate_fixture(item: dict[str, Any], fixture: dict[str, Any]) -> dict[str, Any]:
    """Evaluate a bundled fixture using a small, non-executing explanation model."""
    event = fixture["event"]
    rule_format = item.get("rule_format") or "Generic pseudocode"
    topic = topic_for(item)
    if rule_format == "Sigma":
        selection = _sigma_selection(item)
        if selection:
            field, value = selection
            observed = value.casefold() in str(event.get(field, "")).casefold()
            reasoning = f"The lab checked whether {field} contains the rule's literal learning marker. No process, query, or external system was used."
            matched_field = field
        else:
            observed = topic.casefold() in str(event.get("Activity", "")).casefold()
            reasoning = "This Sigma example has no supported simple contains predicate, so the lab used the fixture Activity field only as a learning approximation."
            matched_field = "Activity"
    elif rule_format == "Microsoft Sentinel KQL":
        observed = bool(str(event.get("Account", "")).strip())
        reasoning = "The lab modeled this educational KQL draft's isnotempty(Account) gate only. It did not interpret, run, or send KQL to Sentinel."
        matched_field = "Account"
    else:
        observed = topic.casefold() in str(event.get("Activity", "")).casefold()
        reasoning = "The lab compared the fixture Activity to the named learning topic because generic pseudocode has no executable parser."
        matched_field = "Activity"
    expected = bool(fixture["expected_match"])
    return {
        "fixture_id": fixture["id"], "fixture_name": fixture["name"], "expected_match": expected,
        "observed_match": observed, "test_passed": observed == expected, "matched_field": matched_field,
        "reasoning": reasoning, "event": event,
        "warning": "This is a local, benign learning simulation. It does not execute a rule, query, command, attack technique, or production integration.",
    }


def lab_material(item: dict[str, Any]) -> dict[str, Any]:
    topic = topic_for(item)
    technique = (item.get("attack_techniques") or ["not mapped"])[0]
    telemetry = item.get("required_telemetry") or ["Review the detection's documented telemetry requirement"]
    format_name = item.get("rule_format") or "detection"
    return {
        "fixtures": fixture_catalog(item),
        "configuration": [
            f"Collect and retain: {', '.join(telemetry)}.",
            "Normalize timestamps, host identifiers, account identifiers, and the event field used by this learning pattern.",
            f"Map the required fields into the target platform before translating this {format_name} learning template.",
            "Start with a narrow, authorized test scope and document each approved exception before tuning it.",
        ],
        "improvements": [
            "Compare the expected-signal and benign fixtures before changing the rule.",
            "Add allowlists only for documented administrative activity, approved accounts, or managed hosts.",
            "Use environment-specific baselines and review every exclusion with an owner and expiry date.",
            "Retest after telemetry changes; a passing lab fixture is not proof of production coverage.",
        ],
        "interview": [
            {"question": f"What behavior is this {topic} detection intended to surface?", "answer": f"It is a defensive learning pattern mapped to ATT&CK {technique}. Explain the behavior, the supporting telemetry, and the uncertainty rather than claiming it proves malicious activity."},
            {"question": "How would you reduce false positives safely?", "answer": "First validate the source fields and legitimate baselines. Then add narrowly documented, time-bound exceptions and retest both a matching fixture and a benign look-alike."},
            {"question": "How would you validate this before production use?", "answer": "Use authorized, benign telemetry fixtures, verify field mappings in the target platform, peer-review the rule, and record both expected and unexpected results. Never treat a lab pass as production coverage proof."},
        ],
        "lab_notice": "Fixtures are bundled, benign, and local to this device. The lab is a learning simulator, not a SIEM, execution engine, or attack environment.",
    }
