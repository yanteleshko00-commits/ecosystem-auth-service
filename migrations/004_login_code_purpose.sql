-- The login-by-email-code flow stores tokens with purpose 'login',
-- which the original CHECK constraint from 001_init.sql rejected.
ALTER TABLE email_tokens DROP CONSTRAINT IF EXISTS email_tokens_purpose_check;
ALTER TABLE email_tokens
  ADD CONSTRAINT email_tokens_purpose_check
  CHECK (purpose IN ('verify_email', 'reset_password', 'login'));
