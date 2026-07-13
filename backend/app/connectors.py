import hashlib
import ipaddress
import re
import socket
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html import unescape
from urllib.parse import urlparse
from xml.etree import ElementTree

import httpx
from psycopg.types.json import Jsonb

from app.config import get_settings
from app.db import connection, fetch_one


def _allowed_host(hostname: str, original_hostname: str | None = None) -> bool:
    configured = get_settings().connector_allowlist
    if configured:
        return any(hostname == allowed or hostname.endswith(f".{allowed}") for allowed in configured)
    if not original_hostname:
        return True
    return hostname in {original_hostname, f"www.{original_hostname}"} or original_hostname == f"www.{hostname}"


def validate_connector_destination(destination: str, original_hostname: str | None = None) -> str:
    """Allow HTTPS public destinations only and constrain redirects to approved hosts."""
    parsed = urlparse(destination)
    hostname = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not hostname or parsed.username or parsed.password or parsed.port not in {None, 443}:
        raise ValueError("Connector URL must be an HTTPS destination without embedded credentials or a custom port")
    if not _allowed_host(hostname, original_hostname):
        raise ValueError(f"Connector destination host is not allowed: {hostname}")
    try:
        addresses = {address[4][0] for address in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)}
    except OSError as error:
        raise ValueError(f"Connector destination could not be resolved: {hostname}") from error
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError("Connector destination must resolve only to public IP addresses")
    return hostname


def request_log(connector_key: str, destination: str, outcome: str, status_code: int | None = None, detail: str | None = None, added: int = 0, updated: int = 0, skipped: int = 0, failed: int = 0) -> None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """INSERT INTO connector_request_log (connector_key, request_method, destination, outcome, status_code, detail, records_added, records_updated, records_skipped, records_failed)
               VALUES (%s, 'GET', %s, %s, %s, %s, %s, %s, %s, %s)""",
            (connector_key, destination, outcome, status_code, detail, added, updated, skipped, failed),
        )
        if outcome == "failed":
            cur.execute("""UPDATE connectors SET last_status = %s, records_failed = records_failed + %s,
                           failure_count = failure_count + 1,
                           retry_after_at = now() + make_interval(mins => least(360, power(2, least(failure_count, 8))::integer))
                           WHERE key = %s""", (f"failed: {(detail or 'request failed')[:160]}", failed or 1, connector_key))


def require_sync_permission(connector_key: str) -> dict:
    connector = fetch_one("SELECT * FROM connectors WHERE key = %s", (connector_key,))
    if not connector:
        raise KeyError("Connector not found")
    setting = fetch_one("SELECT network_mode FROM settings WHERE id = 1")
    if setting["network_mode"] == "offline":
        raise PermissionError("Offline Mode blocks every external request.")
    if not connector["enabled"]:
        raise PermissionError("Enable this connector and acknowledge its network disclosure before syncing.")
    return connector


def sync_cisa_kev(connector: dict) -> dict:
    """Fetch a user-enabled public feed. This function is never called automatically in Phase 2."""
    destination = connector["source_url"]
    validate_connector_destination(destination)
    try:
        response = httpx.get(destination, timeout=30, follow_redirects=False, headers={"User-Agent": "ThreatCommand-Local/0.2 (manual sync)"})
        response.raise_for_status()
        payload = response.json()
    except Exception as error:
        request_log(connector["key"], destination, "failed", detail=str(error), failed=1)
        raise RuntimeError(f"Connector request failed: {error}") from error

    added = updated = skipped = 0
    with connection() as conn, conn.cursor() as cur:
        raw = response.text
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        source_item_key = f"{connector['key']}|catalog"
        cur.execute("SELECT coalesce(max(revision), 0) + 1 AS next_revision FROM source_documents WHERE source_item_key = %s", (source_item_key,))
        next_revision = cur.fetchone()["next_revision"]
        cur.execute(
            """INSERT INTO source_documents (connector_key, source_item_key, revision, parser_version, title, source_url, content_hash, retrieved_at, raw_content, metadata)
               VALUES (%s, %s, %s, '2', %s, %s, %s, now(), %s, %s)
               ON CONFLICT (content_hash) DO UPDATE SET retrieved_at = now()""",
            (connector["key"], source_item_key, next_revision, "CISA KEV catalog", destination, digest, raw, Jsonb({"schemaVersion": payload.get("catalogVersion")})),
        )
        for item in payload.get("vulnerabilities", []):
            cve = item.get("cveID")
            if not cve:
                skipped += 1
                continue
            cur.execute("SELECT id FROM vulnerabilities WHERE cve_id = %s", (cve,))
            exists = cur.fetchone() is not None
            cur.execute(
                """INSERT INTO vulnerabilities (cve_id, title, description, severity, kev, exploitation_evidence, affected_products, potential_relevance, recommended_action, source_url, published_at)
                   VALUES (%s, %s, %s, 'high', true, %s, %s, 'Potential relevance: confirm local inventory and affected version.', 'Assess', %s, %s)
                   ON CONFLICT (cve_id) DO UPDATE SET kev = true, exploitation_evidence = EXCLUDED.exploitation_evidence, updated_at = now()""",
                (cve, item.get("vulnerabilityName", cve), item.get("shortDescription", ""), item.get("requiredAction", "CISA KEV entry"), [item.get("product", "Unknown product")], destination, item.get("dateAdded")),
            )
            added += 0 if exists else 1
            updated += 1 if exists else 0
        cur.execute(
            """UPDATE connectors SET last_sync_at = now(), last_status = 'success', records_added = records_added + %s, records_updated = records_updated + %s,
               records_skipped = records_skipped + %s, records_failed = records_failed, last_content_at = now(), failure_count = 0, retry_after_at = NULL WHERE key = %s""",
            (added, updated, skipped, connector["key"]),
        )
    request_log(connector["key"], destination, "success", response.status_code, added=added, updated=updated, skipped=skipped)
    return {"connector": connector["key"], "synced_at": datetime.now(timezone.utc), "added": added, "updated": updated, "skipped": skipped, "failed": 0}


def _text(value: str | None) -> str:
    plain = re.sub(r"<[^>]+>", " ", unescape(value or ""))
    return re.sub(r"\s+", " ", plain).strip()


def _published(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None


def _rss_entries(xml_text: str) -> list[dict]:
    """Parse RSS 2.0 and Atom without executing or rendering feed content."""
    # Public feeds commonly contain unescaped HTML ampersands and control characters.
    # Repair only XML-invalid text before parsing; feed content remains plain text and is never executed.
    sanitized = re.sub(r"&(?!#\d+;|#x[0-9a-fA-F]+;|amp;|lt;|gt;|quot;|apos;)", "&amp;", xml_text)
    sanitized = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F]", "", sanitized)
    root = ElementTree.fromstring(sanitized)
    entries: list[dict] = []
    rss_items = root.findall(".//item")
    if rss_items:
        for item in rss_items:
            entries.append({
                "title": _text(item.findtext("title")),
                "link": _text(item.findtext("link")),
                "summary": _text(item.findtext("{http://purl.org/rss/1.0/modules/content/}encoded") or item.findtext("description")),
                "published": _published(item.findtext("pubDate") or item.findtext("date")),
            })
        return entries
    atom_ns = "{http://www.w3.org/2005/Atom}"
    for entry in root.findall(f".//{atom_ns}entry"):
        link = entry.find(f"{atom_ns}link")
        entries.append({
            "title": _text(entry.findtext(f"{atom_ns}title")),
            "link": _text(link.get("href") if link is not None else ""),
            "summary": _text(entry.findtext(f"{atom_ns}content") or entry.findtext(f"{atom_ns}summary")),
            "published": _published(entry.findtext(f"{atom_ns}published") or entry.findtext(f"{atom_ns}updated")),
        })
    return entries


def _classify_feed_item(title: str, summary: str) -> tuple[str, list[str]]:
    text = f"{title} {summary}".lower()
    tags = ["source-reported", "rss"]
    zero_day_phrase = re.search(r"(zero[- ]?day|0[- ]?day)[^a-z0-9]{0,24}(vulnerabilit|flaw|exploit|attack|exploitation)", text)
    zero_day_mention = re.search(r"zero[- ]?day|0[- ]?day", text)
    if zero_day_phrase:
        tags.extend(["zero-day-watch", "zero-day-evidence"])
    elif zero_day_mention:
        tags.append("zero-day-mentioned")
    if any(term in text for term in ("actively exploited", "in-the-wild", "in the wild")):
        tags.append("active-exploitation")
    if any(term in text for term in ("ransomware", "remote code execution", "credential")):
        return "high", tags
    return "medium", tags


def sync_rss(connector: dict) -> dict:
    """Fetch a user-enabled RSS source and store source-reported items with provenance."""
    destination = connector["source_url"]
    original_hostname = validate_connector_destination(destination)
    try:
        with httpx.Client(timeout=30, follow_redirects=True, max_redirects=3, headers={"User-Agent": "ThreatCommand-Local/0.2 (manual sync)"}) as client:
            response = client.get(destination)
        response.raise_for_status()
        final_destination = str(response.url)
        validate_connector_destination(final_destination, original_hostname)
        if len(response.content) > 8 * 1024 * 1024:
            raise ValueError("RSS response exceeds the local 8 MB safety limit")
        entries = _rss_entries(response.text)
    except Exception as error:
        request_log(connector["key"], destination, "failed", detail=str(error), failed=1)
        raise RuntimeError(f"RSS connector request failed: {error}") from error

    added = updated = skipped = 0
    source_revisions = 0
    with connection() as conn, conn.cursor() as cur:
        for entry in entries:
            if not entry["title"] or not entry["link"]:
                skipped += 1
                continue
            source_item_key = f"{connector['key']}|{entry['link']}"
            content_hash = hashlib.sha256(f"{source_item_key}|{entry['title']}|{entry['summary']}".encode("utf-8")).hexdigest()
            cur.execute("SELECT coalesce(max(revision), 0) + 1 AS next_revision FROM source_documents WHERE source_item_key = %s", (source_item_key,))
            next_revision = cur.fetchone()["next_revision"]
            cur.execute(
                """INSERT INTO source_documents (connector_key, source_item_key, revision, parser_version, title, source_url, content_hash, published_at, raw_content, metadata)
                   VALUES (%s, %s, %s, '2', %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (content_hash) DO UPDATE SET retrieved_at = now() RETURNING id, (xmax = 0) AS inserted""",
                (connector["key"], source_item_key, next_revision, entry["title"], entry["link"], content_hash, entry["published"], entry["summary"], Jsonb({"feed_url": final_destination, "source_reported": True})),
            )
            document = cur.fetchone()
            severity, tags = _classify_feed_item(entry["title"], entry["summary"])
            cur.execute("""SELECT t.reference_id FROM threats t JOIN source_documents s ON s.id = t.source_document_id
                           WHERE s.source_item_key = %s ORDER BY s.revision DESC, s.retrieved_at DESC LIMIT 1""", (source_item_key,))
            existing_threat = cur.fetchone()
            reference_id = existing_threat["reference_id"] if existing_threat else f"RSS-{connector['key'].upper()}-{hashlib.sha256(source_item_key.encode('utf-8')).hexdigest()[:10]}"
            cur.execute(
                """INSERT INTO threats (reference_id, title, category, severity, confidence, summary, potential_relevance, source_count, source_document_id, published_at, tags)
                   VALUES (%s, %s, 'Cyber news / source-reported', %s, 'source reported', %s, 'Potential relevance: validate affected technology, scope, and corroborating evidence.', 1, %s, %s, %s)
                   ON CONFLICT (reference_id) DO UPDATE SET title = EXCLUDED.title, summary = EXCLUDED.summary, severity = EXCLUDED.severity, tags = EXCLUDED.tags, source_document_id = EXCLUDED.source_document_id, published_at = EXCLUDED.published_at, updated_at = now()""",
                (reference_id, entry["title"], severity, entry["summary"][:4000] or "Source-reported RSS item; review the original source link.", document["id"], entry["published"], tags),
            )
            if document["inserted"]:
                added += 1
            else:
                updated += 1
        cur.execute(
            """UPDATE connectors SET last_sync_at = now(), last_status = 'success', records_added = records_added + %s, records_updated = records_updated + %s,
               records_skipped = records_skipped + %s, records_failed = records_failed, last_content_at = CASE WHEN %s > 0 THEN now() ELSE last_content_at END,
               failure_count = 0, retry_after_at = NULL WHERE key = %s""",
            (added, updated, skipped, added, connector["key"]),
        )
    request_log(connector["key"], final_destination, "success", response.status_code, added=added, updated=updated, skipped=skipped)
    return {"connector": connector["key"], "synced_at": datetime.now(timezone.utc), "added": added, "updated": updated, "skipped": skipped, "failed": 0}


def sync_nvd(connector: dict) -> dict:
    """Fetch a bounded recent NVD API window after the user explicitly confirms Manual Sync."""
    destination = connector["source_url"]
    original_hostname = validate_connector_destination(destination)
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=7)
    params = {"lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000 UTC"), "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000 UTC")}
    try:
        with httpx.Client(timeout=45, follow_redirects=True, max_redirects=2, headers={"User-Agent": "ThreatCommand-Local/0.2 (manual sync)"}) as client:
            response = client.get(destination, params=params)
        response.raise_for_status()
        validate_connector_destination(str(response.url), original_hostname)
        payload = response.json()
    except Exception as error:
        request_log(connector["key"], destination, "failed", detail=str(error), failed=1)
        raise RuntimeError(f"NVD connector request failed: {error}") from error

    added = updated = skipped = 0
    with connection() as conn, conn.cursor() as cur:
        for wrapper in payload.get("vulnerabilities", []):
            cve = wrapper.get("cve", {})
            cve_id = cve.get("id")
            descriptions = cve.get("descriptions", [])
            description = next((item.get("value", "") for item in descriptions if item.get("lang") == "en"), "")
            if not cve_id or not description:
                skipped += 1
                continue
            metrics = cve.get("metrics", {})
            metric = next(iter(metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", []) or metrics.get("cvssMetricV2", [])), {})
            cvss_data = metric.get("cvssData", {})
            score = cvss_data.get("baseScore")
            severity = (cvss_data.get("baseSeverity") or "medium").lower()
            source_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            content_hash = hashlib.sha256(f"nvd|{cve_id}|{cve.get('lastModified', '')}".encode("utf-8")).hexdigest()
            source_item_key = f"{connector['key']}|{cve_id}"
            cur.execute("SELECT coalesce(max(revision), 0) + 1 AS next_revision FROM source_documents WHERE source_item_key = %s", (source_item_key,))
            next_revision = cur.fetchone()["next_revision"]
            cur.execute("SELECT id FROM vulnerabilities WHERE cve_id = %s", (cve_id,))
            exists = cur.fetchone() is not None
            cur.execute(
                """INSERT INTO source_documents (connector_key, source_item_key, revision, parser_version, title, source_url, content_hash, published_at, raw_content, metadata)
                   VALUES (%s, %s, %s, '2', %s, %s, %s, %s, %s, %s) ON CONFLICT (content_hash) DO NOTHING RETURNING id""",
                (connector["key"], source_item_key, next_revision, cve_id, source_url, content_hash, cve.get("published"), description, Jsonb({"last_modified": cve.get("lastModified")})),
            )
            source_revisions += 1 if cur.fetchone() else 0
            cur.execute(
                """INSERT INTO vulnerabilities (cve_id, title, description, severity, cvss, affected_products, potential_relevance, recommended_action, source_url, published_at)
                   VALUES (%s, %s, %s, %s, %s, ARRAY['See NVD record'], 'Potential relevance: confirm local inventory and affected version.', 'Assess', %s, %s)
                   ON CONFLICT (cve_id) DO UPDATE SET title = EXCLUDED.title, description = EXCLUDED.description, severity = EXCLUDED.severity,
                   cvss = EXCLUDED.cvss, source_url = EXCLUDED.source_url, updated_at = now()""",
                (cve_id, cve_id, description, severity if severity in {"critical", "high", "medium", "low"} else "medium", score, source_url, cve.get("published")),
            )
            added += 0 if exists else 1
            updated += 1 if exists else 0
        cur.execute("""UPDATE connectors SET last_sync_at = now(), last_status = 'success', records_added = records_added + %s,
                       records_updated = records_updated + %s, records_skipped = records_skipped + %s,
                       last_content_at = CASE WHEN %s > 0 THEN now() ELSE last_content_at END,
                       failure_count = 0, retry_after_at = NULL WHERE key = %s""", (added, updated, skipped, source_revisions, connector["key"]))
    request_log(connector["key"], destination, "success", response.status_code, added=added, updated=updated, skipped=skipped)
    return {"connector": connector["key"], "synced_at": datetime.now(timezone.utc), "added": added, "updated": updated, "skipped": skipped, "failed": 0}
