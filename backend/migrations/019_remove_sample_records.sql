-- Remove the retired local sample records from installations that used an earlier build.
DELETE FROM actions
WHERE linked_reference IN (
    SELECT reference_id
    FROM threats
    WHERE source_document_id = '00000000-0000-0000-0000-000000000001'
)
OR linked_reference IN (
    SELECT cve_id
    FROM vulnerabilities
    WHERE source_url LIKE 'local://%'
);

DELETE FROM threats
WHERE source_document_id = '00000000-0000-0000-0000-000000000001';

DELETE FROM vulnerabilities
WHERE source_url LIKE 'local://%';

DELETE FROM knowledge_items
WHERE source_path LIKE 'local://%';

DELETE FROM source_documents
WHERE source_url LIKE 'local://%';

UPDATE detections
SET description = 'Defensive learning rule for reviewing encoded PowerShell activity in authorized logs.'
WHERE title = 'Encoded PowerShell review';

ALTER TABLE threats DROP COLUMN IF EXISTS demo;
ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS demo;
