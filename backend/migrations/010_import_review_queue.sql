CREATE TABLE import_review_queue (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    filename text NOT NULL,
    content_type text NOT NULL,
    content_hash text NOT NULL UNIQUE,
    local_path text NOT NULL,
    preview text NOT NULL,
    candidate_entities jsonb NOT NULL DEFAULT '{}'::jsonb,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
    created_at timestamptz NOT NULL DEFAULT now(),
    reviewed_at timestamptz
);
CREATE INDEX import_review_queue_status_idx ON import_review_queue(status, created_at DESC);
