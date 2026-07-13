"""Local Phase 3 maintenance worker.

Scheduled sync runs only while the user-selected network mode is ``scheduled``. The scheduler
uses each enabled connector's local schedule and records every outbound request in PostgreSQL.
"""
import time

from app.connectors import sync_cisa_kev, sync_nvd, sync_rss
from app.db import connection, fetch_all, fetch_one


def run_connector(connector: dict) -> dict:
    if connector["key"] == "cisa-kev":
        return sync_cisa_kev(connector)
    if connector["key"] == "nvd-analyzed-rss":
        return sync_nvd(connector)
    if connector["key"].endswith("-rss"):
        return sync_rss(connector)
    raise NotImplementedError("No scheduled parser is registered for this connector.")


def schedule_next(connector: dict, status: str | None = None) -> None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute("""UPDATE connectors SET next_sync_at = CASE WHEN retry_after_at IS NOT NULL AND retry_after_at > now() THEN retry_after_at
                                                    ELSE now() + (COALESCE(schedule_hours, 6) * interval '1 hour') END,
                       last_status = COALESCE(%s, last_status) WHERE key = %s""", (status, connector["key"]))


def trim_expired_raw_content() -> None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute("""UPDATE source_documents d SET raw_content = NULL
                       FROM connectors c
                       WHERE d.connector_key = c.key AND d.raw_content IS NOT NULL
                         AND c.retention_days IS NOT NULL
                         AND d.retrieved_at < now() - (c.retention_days * interval '1 day')""")


def run_scheduled_maintenance() -> None:
    mode = fetch_one("SELECT network_mode FROM settings WHERE id = 1")["network_mode"]
    if mode != "scheduled":
        return
    due = fetch_all("""SELECT * FROM connectors WHERE enabled AND schedule_hours IS NOT NULL
                      AND next_sync_at IS NOT NULL AND next_sync_at <= now()
                      AND (retry_after_at IS NULL OR retry_after_at <= now()) ORDER BY next_sync_at""")
    for connector in due:
        try:
            run_connector(connector)
            schedule_next(connector)
        except NotImplementedError:
            schedule_next(connector, "scheduled parser not implemented")
        except Exception:
            # Connector-specific sync functions record failure details in the local request log.
            schedule_next(connector)
    trim_expired_raw_content()


if __name__ == "__main__":
    print("ThreatCommand local Phase 3 worker started.")
    while True:
        run_scheduled_maintenance()
        time.sleep(60)
