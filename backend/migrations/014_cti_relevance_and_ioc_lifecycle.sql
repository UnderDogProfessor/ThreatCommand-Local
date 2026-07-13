CREATE TABLE technology_profiles (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    vendor text NOT NULL DEFAULT '',
    product text NOT NULL DEFAULT '',
    version text NOT NULL DEFAULT '',
    criticality text NOT NULL DEFAULT 'medium' CHECK (criticality IN ('critical', 'high', 'medium', 'low')),
    internet_exposed boolean NOT NULL DEFAULT false,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired', 'unknown')),
    notes text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX technology_profiles_active_idx ON technology_profiles(status, criticality);

CREATE TABLE relevance_assessments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type text NOT NULL CHECK (entity_type IN ('vulnerability', 'threat', 'ioc')),
    reference_id text NOT NULL,
    status text NOT NULL DEFAULT 'unknown' CHECK (status IN ('unknown', 'potential', 'confirmed', 'not_applicable')),
    evidence text NOT NULL DEFAULT '',
    review_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (entity_type, reference_id)
);
CREATE INDEX relevance_assessments_status_idx ON relevance_assessments(status, updated_at DESC);

CREATE TABLE iocs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    indicator_type text NOT NULL CHECK (indicator_type IN ('ip', 'domain', 'url', 'hash', 'email', 'other')),
    value text NOT NULL,
    normalized_value text NOT NULL,
    lifecycle_status text NOT NULL DEFAULT 'observed' CHECK (lifecycle_status IN ('observed', 'suspicious', 'malicious', 'stale', 'expired', 'sinkholed', 'false_positive')),
    confidence text NOT NULL DEFAULT 'source-reported' CHECK (confidence IN ('unconfirmed', 'source-reported', 'corroborated', 'analyst-confirmed')),
    first_seen_at timestamptz,
    last_seen_at timestamptz,
    valid_until timestamptz,
    source_url text,
    notes text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (indicator_type, normalized_value)
);
CREATE INDEX iocs_lifecycle_idx ON iocs(lifecycle_status, valid_until, updated_at DESC);
