ALTER TABLE source_documents ADD COLUMN IF NOT EXISTS source_item_key text;
ALTER TABLE source_documents ADD COLUMN IF NOT EXISTS revision integer NOT NULL DEFAULT 1;
ALTER TABLE source_documents ADD COLUMN IF NOT EXISTS parser_version text NOT NULL DEFAULT '1';

UPDATE source_documents
SET source_item_key = coalesce(source_item_key, concat_ws('|', coalesce(connector_key, 'local'), coalesce(source_url, content_hash)));

ALTER TABLE source_documents ALTER COLUMN source_item_key SET NOT NULL;
CREATE INDEX IF NOT EXISTS source_documents_item_revision_idx ON source_documents(source_item_key, revision DESC, retrieved_at DESC);

ALTER TABLE connectors ADD COLUMN IF NOT EXISTS last_content_at timestamptz;
