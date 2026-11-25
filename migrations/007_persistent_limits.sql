CREATE TABLE IF NOT EXISTS security_rate_limits (rate_key TEXT PRIMARY KEY, hits INTEGER NOT NULL CHECK (hits > 0), expires_at TIMESTAMPTZ NOT NULL);
CREATE INDEX IF NOT EXISTS security_rate_limits_expiry_idx ON security_rate_limits (expires_at);
