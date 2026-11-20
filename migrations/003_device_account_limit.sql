CREATE TABLE IF NOT EXISTS device_accounts (
  device_hash TEXT NOT NULL,
  user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (device_hash, user_id)
);

CREATE INDEX IF NOT EXISTS device_accounts_device_idx
  ON device_accounts(device_hash);
