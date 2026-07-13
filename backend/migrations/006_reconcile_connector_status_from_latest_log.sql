WITH latest_log AS (
  SELECT DISTINCT ON (connector_key) connector_key, outcome, detail, records_failed
  FROM connector_request_log
  ORDER BY connector_key, requested_at DESC
)
UPDATE connectors c
SET last_status = CASE
      WHEN l.outcome = 'success' THEN 'success'
      ELSE 'failed: ' || left(coalesce(l.detail, 'request failed'), 160)
    END,
    records_failed = CASE
      WHEN l.outcome = 'success' THEN 0
      ELSE greatest(c.records_failed, coalesce(l.records_failed, 1))
    END
FROM latest_log l
WHERE c.key = l.connector_key;
