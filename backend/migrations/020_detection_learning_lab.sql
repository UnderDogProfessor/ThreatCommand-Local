ALTER TABLE detections
ADD COLUMN IF NOT EXISTS learning_level text NOT NULL DEFAULT 'intermediate'
CHECK (learning_level IN ('beginner', 'intermediate', 'advanced'));

UPDATE detections
SET learning_level = CASE
    WHEN ((library_rank - 1) % 25) + 1 <= 7 THEN 'beginner'
    WHEN ((library_rank - 1) % 25) + 1 <= 18 THEN 'intermediate'
    ELSE 'advanced'
END
WHERE learning_purpose;

CREATE TABLE detection_lab_runs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    detection_id uuid NOT NULL REFERENCES detections(id) ON DELETE CASCADE,
    fixture_id text NOT NULL,
    fixture_name text NOT NULL,
    expected_match boolean NOT NULL,
    observed_match boolean NOT NULL,
    test_passed boolean NOT NULL,
    matched_field text NOT NULL,
    reasoning text NOT NULL,
    fixture_event jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX detection_lab_runs_detection_idx ON detection_lab_runs(detection_id, created_at DESC);
