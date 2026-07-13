INSERT INTO source_documents (id, connector_key, title, source_url, content_hash, raw_content, metadata)
VALUES
  ('00000000-0000-0000-0000-000000000001', 'demo-local', 'ThreatCommand Local synthetic seed', 'local://demo/seed', 'demo-seed-v1', 'Fictional synthetic data used only for the local Phase 2 demonstration.', '{"demo": true}'::jsonb)
ON CONFLICT (content_hash) DO NOTHING;

INSERT INTO threats (reference_id, title, category, severity, confidence, summary, potential_relevance, source_count, source_document_id, published_at, tags, attack_techniques, demo)
VALUES
  ('TC-DEMO-024', 'Glass Meridian targets fictional cloud sign-in flows', 'Cloud identity campaign', 'critical', 'high confidence', 'Synthetic reports describe token replay and consent-grant abuse patterns affecting collaboration tenants.', 'Potential relevance: identity providers. Confirm actual technology and evidence before acting.', 3, '00000000-0000-0000-0000-000000000001', now(), ARRAY['cloud identity', 'demo'], ARRAY['T1078', 'T1528'], true),
  ('TC-DEMO-017', 'Copper Vale uses staged remote-access tooling', 'Ransomware precursor', 'high', 'medium confidence', 'Fictional incident reporting suggests credential access followed by remote service creation in lab environments.', 'Potential relevance: Windows endpoints. No evidence of exposure or compromise.', 2, '00000000-0000-0000-0000-000000000001', now() - interval '1 day', ARRAY['ransomware', 'demo'], ARRAY['T1021', 'T1569'], true),
  ('TC-DEMO-031', 'Harbor Lantern lures mimic document-share notices', 'Phishing campaign', 'high', 'high confidence', 'Fictional phishing content uses collaboration-themed landing pages and example-only indicator patterns.', 'Potential relevance: collaboration tools. Validate with authorized email telemetry.', 4, '00000000-0000-0000-0000-000000000001', now() - interval '1 day', ARRAY['phishing', 'demo'], ARRAY['T1566', 'T1204'], true)
ON CONFLICT (reference_id) DO NOTHING;

INSERT INTO vulnerabilities (cve_id, title, description, severity, cvss, kev, exploitation_evidence, affected_products, potential_relevance, recommended_action, source_url, published_at, demo)
VALUES
  ('CVE-2026-00042', 'Fictional public appliance issue', 'Synthetic vulnerability record for patch-priority workflow demonstration.', 'critical', 9.8, true, 'Simulated KEV designation for demo purposes only.', ARRAY['Fictional Edge Appliance'], 'Potential relevance: confirm product inventory and version before action.', 'Assess', 'local://demo/cve-2026-00042', now() - interval '2 days', true),
  ('CVE-2026-00118', 'Fictional identity library issue', 'Synthetic identity-component record for local relevance review.', 'high', 8.1, false, NULL, ARRAY['Fictional Identity Library'], 'Potential relevance: cloud identity profile match.', 'Monitor', 'local://demo/cve-2026-00118', now() - interval '4 days', true)
ON CONFLICT (cve_id) DO NOTHING;

INSERT INTO actions (title, action_type, priority, linked_reference, notes)
VALUES
  ('Review cloud identity detection gap', 'Detect', 'high', 'TC-DEMO-024', 'Demo action — human review required.'),
  ('Assess CVE-2026-00042 potential relevance', 'Assess', 'high', 'CVE-2026-00042', 'Demo action — confirm inventory before action.'),
  ('Add phishing campaign to weekly brief', 'Brief', 'medium', 'TC-DEMO-031', 'Demo action — not live threat intelligence.');

INSERT INTO detections (title, description, rule_format, rule_content, attack_techniques, required_telemetry, confidence, status)
VALUES
  ('Suspicious OAuth consent grant patterns', 'Draft defensive detection for unexpected OAuth consent grants.', 'Sigma', 'title: Suspicious OAuth consent grant patterns\nstatus: experimental\nlogsource:\n  product: azure', ARRAY['T1078'], ARRAY['Identity audit logs'], 'medium', 'draft'),
  ('Encoded PowerShell review', 'Demo detection for encoded PowerShell review in authorized logs.', 'Sigma', 'title: Encoded PowerShell review\nstatus: test\ndetection:\n  selection:\n    CommandLine|contains: -EncodedCommand', ARRAY['T1059.001'], ARRAY['Windows PowerShell logs'], 'high', 'validated');

INSERT INTO knowledge_items (title, content, content_type, content_hash, source_path, tags)
VALUES
  ('Phase 2 defensive design note', 'ThreatCommand Local stores data on the local device. All generated detection and hunt content remains a human-review-required draft.', 'markdown', 'demo-knowledge-phase-2-v1', 'local://demo/design-note', ARRAY['demo', 'privacy', 'phase-2'])
ON CONFLICT (content_hash) DO NOTHING;

INSERT INTO connectors (key, name, description, source_url, data_type, license_note, enabled, schedule_hours, retention_days)
VALUES
  ('cisa-kev', 'CISA Known Exploited Vulnerabilities', 'Official catalog of vulnerabilities known to be exploited in the wild.', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', 'Vulnerability intelligence', 'Use subject to CISA terms and availability. The provider can observe the device public IP.', false, 12, 365),
  ('mitre-attack', 'MITRE ATT&CK STIX', 'ATT&CK knowledge-base STIX data template.', 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json', 'ATT&CK data', 'Use subject to MITRE license and GitHub availability.', false, 168, 365),
  ('advisory-rss', 'Advisory RSS template', 'Template for a future approved government or vendor advisory RSS source.', 'https://example.invalid/advisories.xml', 'Advisory RSS', 'Disabled example template. Replace only after reviewing source terms.', false, 6, 90)
ON CONFLICT (key) DO NOTHING;
