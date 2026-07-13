UPDATE threats
SET tags = ARRAY(SELECT DISTINCT value FROM unnest(array_remove(tags, 'zero-day') || ARRAY['zero-day-watch', 'zero-day-evidence']) AS value)
WHERE (title || ' ' || summary) ~* '(zero[- ]?day|0[- ]?day)[^a-z0-9]{0,24}(vulnerabilit|flaw|exploit|attack|exploitation)';

UPDATE threats
SET tags = ARRAY(SELECT DISTINCT value FROM unnest(array_remove(tags, 'zero-day') || ARRAY['zero-day-mentioned']) AS value)
WHERE (title || ' ' || summary) ~* '(zero[- ]?day|0[- ]?day)'
  AND NOT ((title || ' ' || summary) ~* '(zero[- ]?day|0[- ]?day)[^a-z0-9]{0,24}(vulnerabilit|flaw|exploit|attack|exploitation)');
