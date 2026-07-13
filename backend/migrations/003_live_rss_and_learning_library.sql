ALTER TABLE detections ADD COLUMN IF NOT EXISTS segment text NOT NULL DEFAULT 'Foundational';
ALTER TABLE detections ADD COLUMN IF NOT EXISTS learning_purpose boolean NOT NULL DEFAULT false;
ALTER TABLE detections ADD COLUMN IF NOT EXISTS library_rank integer;
CREATE UNIQUE INDEX IF NOT EXISTS detections_segment_title_unique ON detections (segment, title);

DELETE FROM connectors WHERE key = 'advisory-rss';

INSERT INTO connectors (key, name, description, source_url, data_type, license_note, enabled, schedule_hours, retention_days)
VALUES
  ('cisa-alerts-rss', 'CISA Alerts RSS', 'User-supplied CISA alert RSS source for public cybersecurity alerts.', 'https://us-cert.cisa.gov/ncas/alerts.xml', 'Cyber news / alerts', 'User-supplied source. Confirm current availability, terms, and rate limits before syncing.', false, 6, 90),
  ('zdi-rss', 'Zero Day Initiative RSS', 'User-supplied Zero Day Initiative public RSS source for research and advisories.', 'https://www.zerodayinitiative.com/rss/', 'Zero-day research / advisories', 'User-supplied source. Respect provider terms, availability, and rate limits.', false, 6, 90),
  ('cis-advisories-rss', 'CIS Advisories Feed', 'User-supplied CIS advisory feed.', 'https://www.cisecurity.org/feed/advisories', 'Cyber advisories', 'User-supplied source. Respect provider terms, availability, and rate limits.', false, 6, 90),
  ('cyberalerts-public-rss', 'Cyber Alerts Public RSS', 'User-supplied public cyber-alert feed.', 'https://cyberalerts.io/rss/latest-public', 'Cyber news / alerts', 'User-supplied source. Treat all claims as source-reported until corroborated.', false, 6, 30),
  ('0dayfans-rss', '0dayfans RSS', 'User-supplied public zero-day themed RSS feed.', 'https://0dayfans.com/feed.rss', 'Zero-day research / news', 'User-supplied source. Treat all claims as unverified until corroborated; respect source terms.', false, 6, 30)
ON CONFLICT (key) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description, source_url = EXCLUDED.source_url, data_type = EXCLUDED.data_type, license_note = EXCLUDED.license_note;
