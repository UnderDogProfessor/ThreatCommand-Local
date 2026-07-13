ALTER TABLE connectors ADD COLUMN IF NOT EXISTS source_owner text NOT NULL DEFAULT 'User-selected public source';
ALTER TABLE connectors ADD COLUMN IF NOT EXISTS terms_url text;
ALTER TABLE connectors ADD COLUMN IF NOT EXISTS license_version text NOT NULL DEFAULT '';
ALTER TABLE connectors ADD COLUMN IF NOT EXISTS reliability_tier text NOT NULL DEFAULT 'source-reported' CHECK (reliability_tier IN ('official', 'vendor', 'research', 'news', 'source-reported'));
ALTER TABLE connectors ADD COLUMN IF NOT EXISTS permitted_use text NOT NULL DEFAULT 'Review source terms before synchronization.';
ALTER TABLE connectors ADD COLUMN IF NOT EXISTS policy_verified_at timestamptz;
ALTER TABLE connectors ADD COLUMN IF NOT EXISTS failure_count integer NOT NULL DEFAULT 0;
ALTER TABLE connectors ADD COLUMN IF NOT EXISTS retry_after_at timestamptz;

UPDATE connectors
SET reliability_tier = CASE
    WHEN key IN ('cisa-kev', 'cisa-alerts-rss', 'nvd-analyzed-rss') THEN 'official'
    WHEN name ILIKE '%AWS%' OR name ILIKE '%Microsoft%' OR name ILIKE '%Ubuntu%' OR name ILIKE '%Cisco%' OR name ILIKE '%Sophos%' OR name ILIKE '%ESET%' OR name ILIKE '%Malwarebytes%' THEN 'vendor'
    WHEN name ILIKE '%Krebs%' OR name ILIKE '%Schneier%' OR name ILIKE '%SANS%' OR name ILIKE '%Talos%' OR name ILIKE '%Securelist%' THEN 'research'
    ELSE 'news'
END
WHERE reliability_tier = 'source-reported';
