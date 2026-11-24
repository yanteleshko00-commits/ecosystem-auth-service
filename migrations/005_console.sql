ALTER TABLE users ADD COLUMN IF NOT EXISTS banned boolean NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS subscribed_until timestamptz;
ALTER TABLE usage_events DROP CONSTRAINT IF EXISTS usage_events_bucket_check;
ALTER TABLE usage_events ADD CONSTRAINT usage_events_bucket_check CHECK (bucket IN ('free','paid','subscription'));
