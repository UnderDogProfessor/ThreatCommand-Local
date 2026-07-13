-- A local HTTP service still needs an explicit first-run access boundary.
-- The API permits only health and setup endpoints until a passphrase is configured.
ALTER TABLE settings ADD COLUMN IF NOT EXISTS access_required boolean NOT NULL DEFAULT true;
