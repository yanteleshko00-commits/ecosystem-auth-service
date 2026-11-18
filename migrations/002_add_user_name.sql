ALTER TABLE users ADD COLUMN IF NOT EXISTS name TEXT;

-- Preserve existing accounts by deriving a temporary display name from the email local-part.
UPDATE users
   SET name = NULLIF(split_part(email, '@', 1), '')
 WHERE name IS NULL;

UPDATE users SET name = 'Пользователь' WHERE name IS NULL;
ALTER TABLE users ALTER COLUMN name SET NOT NULL;
