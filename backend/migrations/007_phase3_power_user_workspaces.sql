CREATE TABLE watchlists (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    description text NOT NULL DEFAULT '',
    color text NOT NULL DEFAULT 'cyan',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE watchlist_items (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    watchlist_id uuid NOT NULL REFERENCES watchlists(id) ON DELETE CASCADE,
    entity_type text NOT NULL CHECK (entity_type IN ('threat', 'vulnerability', 'ioc', 'detection')),
    reference_id text NOT NULL,
    title text NOT NULL DEFAULT '',
    notes text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (watchlist_id, entity_type, reference_id)
);
CREATE INDEX watchlist_items_watchlist_idx ON watchlist_items(watchlist_id, created_at DESC);

CREATE TABLE hunt_cases (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    objective text NOT NULL,
    hypothesis text NOT NULL,
    scope text NOT NULL DEFAULT '',
    status text NOT NULL DEFAULT 'planned' CHECK (status IN ('planned', 'active', 'complete', 'escalated')),
    attack_techniques text[] NOT NULL DEFAULT '{}',
    required_telemetry text[] NOT NULL DEFAULT '{}',
    linked_reference text,
    notes text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX hunt_cases_status_idx ON hunt_cases(status, updated_at DESC);

CREATE TABLE incident_cases (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    title text NOT NULL,
    summary text NOT NULL,
    severity text NOT NULL DEFAULT 'medium' CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'contained', 'closed')),
    linked_reference text,
    notes text NOT NULL DEFAULT '',
    tags text[] NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX incident_cases_status_idx ON incident_cases(status, updated_at DESC);
