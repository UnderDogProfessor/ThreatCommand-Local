UPDATE connectors
SET enabled = false,
    next_sync_at = NULL,
    last_status = 'parser unavailable; disabled'
WHERE key = 'mitre-attack';
