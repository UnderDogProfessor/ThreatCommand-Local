CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE settings (
    id smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    network_mode text NOT NULL DEFAULT 'manual' CHECK (network_mode IN ('offline', 'manual', 'scheduled')),
    profile jsonb NOT NULL DEFAULT '{}'::jsonb,
    updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

CREATE TABLE source_documents (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    connector_key text,
    title text NOT NULL,
    source_url text,
    content_hash text NOT NULL UNIQUE,
    retrieved_at timestamptz NOT NULL DEFAULT now(),
    published_at timestamptz,
    raw_content text,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE threats (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    reference_id text NOT NULL UNIQUE,
    title text NOT NULL,
    category text NOT NULL,
    severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'informational')),
    confidence text NOT NULL DEFAULT 'unconfirmed',
    summary text NOT NULL,
    potential_relevance text NOT NULL DEFAULT 'Potential relevance not assessed',
    source_count integer NOT NULL DEFAULT 0,
    source_document_id uuid REFERENCES source_documents(id) ON DELETE SET NULL,
    published_at timestamptz,
    tags text[] NOT NULL DEFAULT '{}',
    attack_techniques text[] NOT NULL DEFAULT '{}',
    archived boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX threats_search_idx ON threats USING gin (to_tsvector('english', title || ' ' || summary));

CREATE TABLE vulnerabilities (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id text UNIQUE,
    title text NOT NULL,
    description text NOT NULL,
    severity text NOT NULL,
    cvss numeric(3,1),
    kev boolean NOT NULL DEFAULT false,
    exploitation_evidence text,
    affected_products text[] NOT NULL DEFAULT '{}',
    potential_relevance text NOT NULL DEFAULT 'Potential relevance not assessed',
    recommended_action text NOT NULL DEFAULT 'Assess',
    source_url text,
    published_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX vulnerabilities_search_idx ON vulnerabilities USING gin (to_tsvector('english', coalesce(cve_id, '') || ' ' || title || ' ' || description));

CREATE TABLE actions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    title text NOT NULL,
    action_type text NOT NULL DEFAULT 'Investigate',
    priority text NOT NULL DEFAULT 'medium',
    status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'complete', 'archived')),
    linked_reference text,
    notes text,
    due_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz
);

CREATE TABLE detections (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    title text NOT NULL,
    description text NOT NULL,
    rule_format text NOT NULL,
    rule_content text NOT NULL,
    attack_techniques text[] NOT NULL DEFAULT '{}',
    required_telemetry text[] NOT NULL DEFAULT '{}',
    confidence text NOT NULL DEFAULT 'medium',
    status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'reviewed', 'validated', 'archived')),
    version integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE knowledge_items (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    title text NOT NULL,
    content text NOT NULL,
    content_type text NOT NULL,
    content_hash text NOT NULL UNIQUE,
    source_path text,
    tags text[] NOT NULL DEFAULT '{}',
    ai_generated boolean NOT NULL DEFAULT false,
    embedding vector(768),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX knowledge_search_idx ON knowledge_items USING gin (to_tsvector('english', title || ' ' || content));

CREATE TABLE connectors (
    key text PRIMARY KEY,
    name text NOT NULL,
    description text NOT NULL,
    source_url text NOT NULL,
    data_type text NOT NULL,
    license_note text NOT NULL,
    credential_required boolean NOT NULL DEFAULT false,
    enabled boolean NOT NULL DEFAULT false,
    schedule_hours integer,
    retention_days integer,
    last_sync_at timestamptz,
    next_sync_at timestamptz,
    last_status text NOT NULL DEFAULT 'never synced',
    records_added integer NOT NULL DEFAULT 0,
    records_updated integer NOT NULL DEFAULT 0,
    records_skipped integer NOT NULL DEFAULT 0,
    records_failed integer NOT NULL DEFAULT 0
);

CREATE TABLE connector_request_log (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    connector_key text REFERENCES connectors(key) ON DELETE SET NULL,
    requested_at timestamptz NOT NULL DEFAULT now(),
    request_method text NOT NULL,
    destination text NOT NULL,
    outcome text NOT NULL,
    status_code integer,
    records_added integer NOT NULL DEFAULT 0,
    records_updated integer NOT NULL DEFAULT 0,
    records_skipped integer NOT NULL DEFAULT 0,
    records_failed integer NOT NULL DEFAULT 0,
    detail text
);

CREATE TABLE digests (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    title text NOT NULL,
    audience text NOT NULL,
    content text NOT NULL,
    source_references text[] NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
