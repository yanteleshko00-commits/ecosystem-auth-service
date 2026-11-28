ALTER TABLE usage_events ADD COLUMN IF NOT EXISTS product TEXT NOT NULL DEFAULT 'legacy';
CREATE INDEX IF NOT EXISTS usage_events_user_created_status_idx ON usage_events(user_id, created_at DESC, status);
