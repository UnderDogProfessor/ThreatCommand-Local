ALTER TABLE settings ADD COLUMN IF NOT EXISTS access_password_hash text;
ALTER TABLE settings ADD COLUMN IF NOT EXISTS access_updated_at timestamptz;

CREATE TABLE IF NOT EXISTS audit_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type text NOT NULL,
    detail jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_events_created_idx ON audit_events(created_at DESC);
