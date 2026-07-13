WITH latest_failure AS (
  SELECT DISTINCT ON (connector_key) connector_key, detail, records_failed
  FROM connector_request_log
  WHERE outcome = 'failed'
  ORDER BY connector_key, requested_at DESC
)
UPDATE connectors c
SET last_status = 'failed: ' || left(coalesce(f.detail, 'request failed'), 160),
    records_failed = greatest(c.records_failed, coalesce(f.records_failed, 1))
FROM latest_failure f
WHERE c.key = f.connector_key;

UPDATE connectors
SET source_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    name = 'NIST NVD CVE API',
    description = 'NVD CVE API connector. Manual sync retrieves a bounded seven-day modification window.',
    data_type = 'Vulnerability intelligence API'
WHERE key = 'nvd-analyzed-rss';
