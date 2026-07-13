INSERT INTO connectors (key, name, description, source_url, data_type, license_note, enabled, schedule_hours, retention_days)
VALUES
  ('aws-security-bulletins-rss', 'AWS Security Bulletins', 'User-supplied AWS security bulletin feed.', 'https://aws.amazon.com/security/security-bulletins/feed/', 'Vendor security advisories', 'User-supplied source. Review AWS terms, availability, and rate limits before syncing.', false, 12, 180),
  ('aws-security-blog-rss', 'AWS Security Blog', 'User-supplied AWS Security Blog feed.', 'https://feeds.feedburner.com/AWSSecurity', 'Vendor security news', 'User-supplied source. Review AWS and FeedBurner terms before syncing.', false, 12, 90),
  ('krebs-rss', 'Krebs on Security', 'User-supplied independent security news feed.', 'https://krebsonsecurity.com/feed/', 'Cyber news / analysis', 'User-supplied source. Treat reporting as source-reported until corroborated.', false, 6, 90),
  ('bleepingcomputer-rss', 'BleepingComputer', 'User-supplied security news feed.', 'https://www.bleepingcomputer.com/feed/', 'Cyber news / analysis', 'User-supplied source. Treat reporting as source-reported until corroborated.', false, 6, 90),
  ('hackernews-rss', 'The Hacker News', 'User-supplied cybersecurity news feed.', 'https://feeds.feedburner.com/TheHackersNews?format=xml', 'Cyber news / analysis', 'User-supplied source. Treat reporting as source-reported until corroborated.', false, 6, 90),
  ('grahamcluley-rss', 'Graham Cluley', 'User-supplied security news and analysis feed.', 'https://grahamcluley.com/feed/', 'Cyber news / analysis', 'User-supplied source. Treat reporting as source-reported until corroborated.', false, 12, 90),
  ('schneier-rss', 'Schneier on Security', 'User-supplied security analysis feed.', 'https://www.schneier.com/feed/atom/', 'Cyber news / analysis', 'User-supplied source. Treat reporting as source-reported until corroborated.', false, 12, 90),
  ('troyhunt-rss', 'Troy Hunt', 'User-supplied security research and breach-analysis feed.', 'https://www.troyhunt.com/rss/', 'Security research / analysis', 'User-supplied source. Treat reporting as source-reported until corroborated.', false, 12, 90),
  ('eset-welivesecurity-rss', 'ESET WeLiveSecurity', 'User-supplied vendor threat-research feed.', 'https://feeds.feedburner.com/eset/blog', 'Threat research', 'User-supplied source. Respect provider terms and rate limits.', false, 6, 90),
  ('sophos-security-operations-rss', 'Sophos Security Operations', 'User-supplied Sophos security-operations feed.', 'https://news.sophos.com/en-us/category/security-operations/feed/', 'Threat research / operations', 'User-supplied source. Respect provider terms and rate limits.', false, 6, 90),
  ('sophos-threat-research-rss', 'Sophos Threat Research', 'User-supplied Sophos threat-research feed.', 'https://news.sophos.com/en-us/category/threat-research/feed/', 'Threat research', 'User-supplied source. Respect provider terms and rate limits.', false, 6, 90),
  ('securelist-rss', 'Securelist', 'User-supplied vendor threat-research feed.', 'https://securelist.com/feed/', 'Threat research', 'User-supplied source. Respect provider terms and rate limits.', false, 6, 90),
  ('malwarebytes-rss', 'Malwarebytes Labs', 'User-supplied vendor threat-research feed.', 'https://blog.malwarebytes.com/feed/', 'Threat research', 'User-supplied source. Respect provider terms and rate limits.', false, 6, 90),
  ('cisco-talos-rss', 'Cisco Talos', 'User-supplied Cisco Talos threat-intelligence feed.', 'https://feeds.feedburner.com/feedburner/Talos', 'Threat intelligence / research', 'User-supplied source. Respect provider terms and rate limits.', false, 6, 90),
  ('sans-isc-rss', 'SANS Internet Storm Center', 'User-supplied SANS Internet Storm Center feed.', 'https://isc.sans.edu/rssfeed_full.xml', 'Security alerts / analysis', 'User-supplied source. Treat reporting as source-reported until corroborated.', false, 6, 30),
  ('darknet-diaries-rss', 'Darknet Diaries', 'User-supplied security podcast feed.', 'https://podcast.darknetdiaries.com/', 'Security podcast', 'User-supplied source. Retain source metadata and respect provider terms.', false, 24, 30),
  ('cisa-alerts-rss', 'CISA Alerts RSS', 'User-supplied CISA public alert RSS source.', 'https://www.cisa.gov/us-cert/ncas/alerts.xml', 'Cyber news / alerts', 'User-supplied source. Confirm current availability, terms, and rate limits before syncing.', false, 6, 90),
  ('nvd-analyzed-rss', 'NIST NVD Analyzed CVE RSS', 'User-supplied NVD analyzed-CVE RSS feed.', 'https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml', 'Vulnerability intelligence', 'User-supplied source. Confirm current availability, terms, and rate limits before syncing.', false, 12, 180)
ON CONFLICT (key) DO UPDATE SET
  name = EXCLUDED.name,
  description = EXCLUDED.description,
  source_url = EXCLUDED.source_url,
  data_type = EXCLUDED.data_type,
  license_note = EXCLUDED.license_note;
