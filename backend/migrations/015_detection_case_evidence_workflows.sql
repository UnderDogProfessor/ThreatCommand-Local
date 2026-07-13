ALTER TABLE detections ADD COLUMN IF NOT EXISTS maturity text NOT NULL DEFAULT 'draft' CHECK (maturity IN ('draft', 'reviewed', 'tested', 'validated', 'deployed', 'tuned', 'monitored', 'retired'));
ALTER TABLE detections ADD COLUMN IF NOT EXISTS owner text NOT NULL DEFAULT '';
ALTER TABLE detections ADD COLUMN IF NOT EXISTS platform text NOT NULL DEFAULT '';
ALTER TABLE detections ADD COLUMN IF NOT EXISTS data_components text[] NOT NULL DEFAULT '{}';
ALTER TABLE detections ADD COLUMN IF NOT EXISTS telemetry_state text NOT NULL DEFAULT 'unknown' CHECK (telemetry_state IN ('unknown', 'unavailable', 'available', 'normalized'));
ALTER TABLE detections ADD COLUMN IF NOT EXISTS validation_notes text NOT NULL DEFAULT '';
ALTER TABLE detections ADD COLUMN IF NOT EXISTS last_validated_at timestamptz;

CREATE TABLE detection_revisions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    detection_id uuid NOT NULL REFERENCES detections(id) ON DELETE CASCADE,
    version integer NOT NULL,
    rule_content text NOT NULL,
    change_summary text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (detection_id, version)
);
CREATE TABLE detection_validation_results (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    detection_id uuid NOT NULL REFERENCES detections(id) ON DELETE CASCADE,
    fixture_name text NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('pass', 'fail', 'not_run')),
    evidence text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX detection_validation_results_idx ON detection_validation_results(detection_id, created_at DESC);

CREATE TABLE case_evidence (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    case_type text NOT NULL CHECK (case_type IN ('hunt', 'incident')),
    case_id uuid NOT NULL,
    evidence_type text NOT NULL CHECK (evidence_type IN ('fact', 'claim', 'inference', 'artifact', 'decision')),
    content text NOT NULL,
    source_url text,
    content_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (case_type, case_id, content_hash)
);
CREATE INDEX case_evidence_case_idx ON case_evidence(case_type, case_id, created_at DESC);

CREATE TABLE hunt_findings (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    hunt_id uuid NOT NULL REFERENCES hunt_cases(id) ON DELETE CASCADE,
    classification text NOT NULL CHECK (classification IN ('no_finding', 'benign', 'suspicious', 'confirmed', 'detection_candidate')),
    summary text NOT NULL,
    linked_detection_id uuid REFERENCES detections(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
