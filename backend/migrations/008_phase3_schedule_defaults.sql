UPDATE connectors
SET schedule_hours = CASE
    WHEN key = 'cisa-kev' THEN 6
    WHEN key = 'nvd-analyzed-rss' THEN 24
    WHEN key = 'mitre-attack' THEN 168
    WHEN key LIKE '%-rss' THEN 3
    ELSE COALESCE(schedule_hours, 6)
END;
