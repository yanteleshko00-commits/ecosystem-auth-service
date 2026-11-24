import crypto from 'node:crypto';
import express from 'express';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { config } from './config.js';
import { pool, transaction } from './db.js';
import { sendCodeEmail } from './mailer.js';
import {
  clearSessionCookie, findSessionUser, hashPassword, normalizeEmail, randomCode,
  randomToken, requireUser, setSessionCookie, sha256, timingSafeEqualText,
  verifyPassword
} from './security.js';
import { requirePaymentWebhook, requireService } from './service-auth.js';
import { packages, resolveUsageBucket } from './policy.js';

export const router = express.Router();
const codeTtlMinutes = 15;
const sessionTtlSeconds = config.SESSION_TTL_DAYS * 86400;
const registerSchema = z.object({ name: z.string().trim().min(1).max(60), email: z.string().email().max(254), password: z.string().min(8).max(128) });
const loginSchema = z.object({ email: z.string().email().max(254), password: z.string().min(6).max(128) });
const emailSchema = z.object({ email: z.string().email().max(254) });
const codeSchema = z.object({ email: z.string().email().max(254), code: z.string().regex(/^\d{6}$/) });
const passwordSchema = z.string().min(8).max(128);

function issueCookieSession(res, token) {
  setSessionCookie(res, token, sessionTtlSeconds);
}

async function createEmailToken(userId, purpose) {
  const code = randomCode();
  await transaction(async db => {
    await db.query('SELECT id FROM users WHERE id = $1 FOR UPDATE',[userId]);
    await db.query(
      'UPDATE email_tokens SET used_at = NOW() WHERE user_id = $1 AND purpose = $2 AND used_at IS NULL',
      [userId, purpose]
    );
    await db.query(
      `INSERT INTO email_tokens (user_id, token_hash, purpose, expires_at)
       VALUES ($1, $2, $3, NOW() + ($4 || ' minutes')::interval)`,
      [userId, sha256(code), purpose, String(codeTtlMinutes)]
    );
  });
  return code;
}

async function consumeEmailToken(userId, code, purpose, db = pool) {
  const result = await db.query(
    `UPDATE email_tokens
        SET failed_attempts = failed_attempts + CASE WHEN token_hash = $2 THEN 0 ELSE 1 END,
            used_at = CASE WHEN token_hash = $2 OR failed_attempts >= 4 THEN NOW() ELSE used_at END
      WHERE id = (
        SELECT id FROM email_tokens
         WHERE user_id = $1 AND purpose = $3 AND used_at IS NULL
           AND expires_at > NOW() AND failed_attempts < 5
         ORDER BY created_at DESC LIMIT 1 FOR UPDATE
      ) RETURNING (token_hash = $2) AS matched`,
    [userId, sha256(code), purpose]
  );
  return result.rows[0]?.matched === true;
}

async function makeSession(userId, res) {
  const token = randomToken(48);
  await pool.query(
    'INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ($1, $2, NOW() + ($3 || \' seconds\')::interval)',
    [userId, sha256(token), String(sessionTtlSeconds)]
  );
  issueCookieSession(res, token);
}

router.get('/health', async (_req, res) => {
  await pool.query('SELECT 1');
  const hasCredentials = Boolean(config.SMTP_USER && config.SMTP_PASSWORD);
  const hasSender = Boolean(
    config.SMTP_FROM_EMAIL || config.SMTP_USER.includes('@') ||
    (config.SMTP_HOST === 'smtp.yandex.ru' && config.SMTP_USER)
  );
  const brevoConfigured = Boolean(config.BREVO_API_KEY && (config.BREVO_FROM_EMAIL || config.SMTP_FROM_EMAIL));
  const emailDeliveryConfigured = brevoConfigured || (hasCredentials && hasSender);
  const emailDeliveryNote = brevoConfigured ? 'https_api_configuration_present' :
    (!hasCredentials ? 'missing_smtp_credentials' :
    (!hasSender ? 'missing_sender_email' : 'smtp_configuration_present'));
  res.json({
    ok: true,
    service: 'ecosystem-auth',
    database: 'connected',
    emailProvider: brevoConfigured ? 'brevo' : 'yandex_smtp',
    emailDeliveryConfigured,
    emailDeliveryMode: brevoConfigured ? 'https_api' : 'smtp',
    emailDeliveryNote,
    emailCodeTtlMinutes: codeTtlMinutes
  });
});

function requireSameOrigin(req, res, next) {
  const origin = req.get('origin');
  if (origin && origin !== config.authOrigin) return res.status(403).json({ error: 'origin_not_allowed' });
  return next();
}

router.post('/v1/auth/register', requireSameOrigin, async (req, res) => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_registration_data' });
  const email = normalizeEmail(parsed.data.email);
  const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
  if (existing.rowCount) {
    return res.status(201).json({ ok: true, message: 'Если регистрация доступна, проверьте почту и введите код подтверждения.' });
  }

  // A long-lived, HttpOnly device cookie groups registrations from this browser.
  const deviceToken = req.cookies?.ecosystem_device || randomToken(32);
  if (!req.cookies?.ecosystem_device) {
    res.cookie('ecosystem_device', deviceToken, {
      httpOnly: true,
      secure: config.cookieSecure,
      sameSite: 'lax',
      path: '/',
      maxAge: 10 * 365 * 24 * 60 * 60 * 1000
    });
  }
  const deviceHash = sha256(deviceToken);
  const passwordHash = await hashPassword(parsed.data.password);
  const created = await transaction(async db => {
    // Serialize registrations for this device so simultaneous requests cannot exceed the cap.
    await db.query('SELECT pg_advisory_xact_lock(hashtext($1))', [deviceHash]);
    const count = await db.query(
      'SELECT COUNT(*)::int AS total FROM device_accounts WHERE device_hash = $1',
      [deviceHash]
    );
    if (count.rows[0].total >= 3) return { limitReached: true };
    const inserted = await db.query(
      'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) ON CONFLICT (email) DO NOTHING RETURNING id',
      [parsed.data.name, email, passwordHash]
    );
    if(!inserted.rowCount)return {alreadyExists:true};
    await db.query(
      'INSERT INTO device_accounts (device_hash, user_id) VALUES ($1, $2)',
      [deviceHash, inserted.rows[0].id]
    );
    return { userId: inserted.rows[0].id };
  });
  if(created.alreadyExists)return res.status(201).json({ok:true,message:'Если регистрация доступна, проверьте почту и введите код подтверждения.'});
  if (created.limitReached) {
    return res.status(429).json({
      error: 'device_account_limit',
      message: 'На одном устройстве можно создать не более 3 аккаунтов NEXORA ID. Войдите в существующий аккаунт.'
    });
  }
  const code = await createEmailToken(created.userId, 'verify_email');
  try {
    await sendCodeEmail({ to: email, code, purpose: 'verify_email' });
  } catch (error) {
    console.error('Registration email delivery failed:', {
      code: error.code, httpStatus: error.httpStatus, smtpResponseCode: error.smtpResponseCode, message: error.message
    });
    // A uniform response prevents account enumeration through SMTP failures.
    return res.status(201).json({ok:true,message:'Если регистрация доступна, проверьте почту и введите код подтверждения.'});
  }
  return res.status(201).json({ ok: true, message: 'Если регистрация доступна, проверьте почту и введите код подтверждения.' });
});

router.post('/v1/auth/send-login-code', requireSameOrigin, async (req, res) => {
  const parsed = emailSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_email' });

  const email = normalizeEmail(parsed.data.email);
  const result = await pool.query(
    'SELECT id FROM users WHERE email = $1 AND email_verified_at IS NOT NULL',
    [email]
  );

  // Do not reveal whether an email address has an account.
  if (result.rowCount) {
    const code = await createEmailToken(result.rows[0].id, 'login');
    try {
      await sendCodeEmail({ to: email, code, purpose: 'login' });
    } catch (error) {
      console.error('Login code email delivery failed:', {
        code: error.code, httpStatus: error.httpStatus, smtpResponseCode: error.smtpResponseCode, message: error.message
      });
      return res.status(503).json({
        error: 'email_delivery_unavailable',
        message: 'Не удалось отправить письмо. Попробуйте позже.'
      });
    }
  }

  return res.json({
    ok: true,
    message: 'Если аккаунт с этим адресом существует и подтверждён, код отправлен на почту. Он действует 15 минут.'
  });
});

router.post('/v1/auth/verify-login-code', requireSameOrigin, async (req, res) => {
  const parsed = codeSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_verification_data' });

  const email = normalizeEmail(parsed.data.email);
  const user = await pool.query(
    'SELECT id FROM users WHERE email = $1 AND email_verified_at IS NOT NULL',
    [email]
  );
  if (!user.rowCount) return res.status(400).json({ error: 'invalid_or_expired_code' });

  const verified = await transaction(async db =>
    consumeEmailToken(user.rows[0].id, parsed.data.code, 'login', db)
  );
  if (!verified) return res.status(400).json({ error: 'invalid_or_expired_code' });

  await makeSession(user.rows[0].id, res);
  return res.json({ ok: true, message: 'Вход в NEXORA ID выполнен.' });
});

router.post('/v1/auth/resend-verification', requireSameOrigin, async (req, res) => {
  const parsed = emailSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_email' });
  const email = normalizeEmail(parsed.data.email);
  const user = await pool.query('SELECT id, email_verified_at FROM users WHERE email = $1', [email]);
  if (!user.rowCount || user.rows[0].email_verified_at) {
    return res.json({ ok: true, message: 'Если аккаунт требует подтверждения, письмо будет отправлено.' });
  }
  const code = await createEmailToken(user.rows[0].id, 'verify_email');
  try {
    const info = await sendCodeEmail({ to: email, code, purpose: 'verify_email' });
    console.info('Verification email accepted by provider:', {
      messageId: info.messageId,
      acceptedCount: info.accepted?.length ?? 0,
      rejectedCount: info.rejected?.length ?? 0
    });
  } catch (error) {
    console.error('Verification email resend failed:', {
      code: error.code, httpStatus: error.httpStatus, smtpResponseCode: error.smtpResponseCode, message: error.message
    });
    return res.status(503).json({
      error: 'email_delivery_unavailable',
      message: 'Сервер не смог отправить письмо через Яндекс. Проверьте SMTP-настройки и пароль приложения.'
    });
  }
  return res.json({ ok: true, message: 'Код отправлен. Проверьте Входящие и Спам.' });
});

router.post('/v1/auth/verify-email', requireSameOrigin, async (req, res) => {
  const parsed = codeSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_verification_data' });
  const email = normalizeEmail(parsed.data.email);
  const user = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
  if (!user.rowCount) return res.status(400).json({ error: 'invalid_or_expired_code' });
  const verified = await transaction(async db => {
    const consumed = await consumeEmailToken(user.rows[0].id, parsed.data.code, 'verify_email', db);
    if (!consumed) return false;
    await db.query('UPDATE users SET email_verified_at = NOW(), updated_at = NOW() WHERE id = $1', [user.rows[0].id]);
    return true;
  });
  if (!verified) return res.status(400).json({ error: 'invalid_or_expired_code' });
  await makeSession(user.rows[0].id, res);
  return res.json({ ok: true, message: 'Email подтверждён. Вход в NEXORA ID выполнен.' });
});

router.post('/v1/auth/login', requireSameOrigin, async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_login_data' });
  const email = normalizeEmail(parsed.data.email);
  const result = await pool.query('SELECT id, banned, password_hash, email_verified_at FROM users WHERE email = $1', [email]);
  const user = result.rows[0];
  if (!user || !(await verifyPassword(user.password_hash, parsed.data.password))) {
    return res.status(401).json({ error: 'invalid_credentials', message: 'Неверный email или пароль.' });
  }
  if (user.banned) return res.status(403).json({error:'account_blocked'});
  if (!user.email_verified_at) return res.status(403).json({ error: 'email_not_verified', message: 'Сначала подтвердите email.' });
  await makeSession(user.id, res);
  return res.json({ ok: true, message: 'Вход выполнен.' });
});

router.post('/v1/auth/logout', requireSameOrigin, async (req, res) => {
  const token = req.cookies?.[config.SESSION_COOKIE_NAME];
  if (token) await pool.query('DELETE FROM sessions WHERE token_hash = $1', [sha256(token)]);
  clearSessionCookie(res);
  return res.json({ ok: true });
});

router.get('/v1/me', requireUser, (req, res) => {
  const { id, name, email, free_requests_used, paid_credits, session_id } = req.user;
  return res.json({
    sessionId: session_id,
    user: { id, name, email },
    usage: { freeRequestsUsed: free_requests_used, freeRequestsRemaining: Math.max(0, 3 - free_requests_used), paidCredits: paid_credits },
    packages
  });
});

router.patch('/v1/me', requireSameOrigin, requireUser, async (req, res) => {
  const parsed = z.object({ name: z.string().trim().min(1).max(60) }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_profile_data', message: 'Имя должно содержать от 1 до 60 символов.' });
  const result = await pool.query(
    'UPDATE users SET name = $1, updated_at = NOW() WHERE id = $2 RETURNING id, name, email',
    [parsed.data.name, req.user.id]
  );
  return res.json({ ok: true, user: result.rows[0] });
});

router.post('/v1/auth/forgot-password', requireSameOrigin, async (req, res) => {
  const parsed = emailSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_email' });
  const email = normalizeEmail(parsed.data.email);
  const result = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
  if (result.rowCount) {
    const code = await createEmailToken(result.rows[0].id, 'reset_password');
    try {
      const receipt = await sendCodeEmail({ to: email, code, purpose: 'reset_password' });
      console.info('Password reset email accepted:', { messageId: receipt.messageId });
    } catch (error) {
      console.error('Password reset email delivery failed:', {
        code: error.code, httpStatus: error.httpStatus, smtpResponseCode: error.smtpResponseCode, message: error.message
      });
      return res.status(503).json({
        error: 'email_delivery_unavailable',
        message: 'Не удалось отправить письмо. Попробуйте позже.'
      });
    }
  }
  return res.json({ ok: true, message: 'Если аккаунт существует, на него отправлен код восстановления.' });
});

router.post('/v1/auth/reset-password', requireSameOrigin, async (req, res) => {
  const schema = codeSchema.extend({ newPassword: passwordSchema });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_reset_data' });
  const email = normalizeEmail(parsed.data.email);
  const user = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
  if (!user.rowCount) return res.status(400).json({ error: 'invalid_or_expired_code' });
  const passwordHash = await hashPassword(parsed.data.newPassword);
  const changed = await transaction(async db => {
    const consumed = await consumeEmailToken(user.rows[0].id, parsed.data.code, 'reset_password', db);
    if (!consumed) return false;
    await db.query('UPDATE users SET password_hash = $1, email_verified_at = COALESCE(email_verified_at, NOW()), updated_at = NOW() WHERE id = $2', [passwordHash, user.rows[0].id]);
    await db.query('DELETE FROM sessions WHERE user_id = $1', [user.rows[0].id]);
    return true;
  });
  if (!changed) return res.status(400).json({ error: 'invalid_or_expired_code' });
  clearSessionCookie(res);
  return res.json({ ok: true, message: 'Пароль изменён. Войдите с новым паролем.' });
});

router.get('/oauth/authorize', async (req, res) => {
  const { client_id: clientId, redirect_uri: redirectUri, response_type: responseType, state, code_challenge: challenge, code_challenge_method: method, device_id: deviceId, device_signature: deviceSignature } = req.query;
  const client = config.clients.find(item => item.clientId === clientId);
  if (!client || responseType !== 'code' || typeof redirectUri !== 'string' || !client.redirectUris.includes(redirectUri) || typeof state !== 'string' || state.length < 16 || state.length > 512 || typeof challenge !== 'string' || !/^[A-Za-z0-9_-]{43,128}$/.test(challenge) || method !== 'S256') {
    return res.status(400).send('Invalid OAuth authorization request.');
  }
  if (deviceId !== undefined) {
    const expectedDeviceSignature = crypto.createHmac('sha256', client.clientSecret).update(String(deviceId)).digest('hex');
    if (typeof deviceId !== 'string' || !/^[A-Za-z0-9_-]{32,128}$/.test(deviceId) || typeof deviceSignature !== 'string' || !timingSafeEqualText(deviceSignature, expectedDeviceSignature)) {
      return res.status(400).send('Invalid device registration token.');
    }
    res.cookie('ecosystem_device', deviceId, {
      httpOnly: true,
      secure: config.cookieSecure,
      sameSite: 'lax',
      path: '/',
      maxAge: 10 * 365 * 24 * 60 * 60 * 1000
    });
  }
  const user = await findSessionUser(req);
  if (!user) {
    const next = encodeURIComponent(req.originalUrl);
    const mode = req.query.mode === 'register' ? '&mode=register' : '';
    return res.redirect(`/login?next=${next}${mode}`);
  }
  const code = randomToken(32);
  await pool.query(
    `INSERT INTO oauth_codes (code_hash, user_id, client_id, redirect_uri, code_challenge, expires_at, session_id)
     VALUES ($1, $2, $3, $4, $5, NOW() + INTERVAL '2 minutes', $6)`,
    [sha256(code), user.id, clientId, redirectUri, challenge, user.session_id]
  );
  const target = new URL(redirectUri);
  target.searchParams.set('code', code);
  target.searchParams.set('state', state);
  return res.redirect(302, target.toString());
});

router.post('/oauth/token', express.urlencoded({ extended: false }), async (req, res) => {
  const body = req.body ?? {};
  const client = config.clients.find(item => item.clientId === body.client_id);
  if (!client || !timingSafeEqualText(body.client_secret ?? '', client.clientSecret)) {
    return res.status(401).json({ error: 'invalid_client' });
  }
  if (body.grant_type !== 'authorization_code' || typeof body.code !== 'string' || typeof body.redirect_uri !== 'string' || typeof body.code_verifier !== 'string') {
    return res.status(400).json({ error: 'invalid_token_request' });
  }
  const verifier = body.code_verifier;
  if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) return res.status(400).json({ error: 'invalid_code_verifier' });
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const result = await transaction(async db => {
    const found = await db.query(
      `SELECT id, user_id, client_id, redirect_uri, code_challenge, session_id
         FROM oauth_codes WHERE code_hash = $1 AND expires_at > NOW() AND used_at IS NULL
         FOR UPDATE`, [sha256(body.code)]
    );
    const authCode = found.rows[0];
    if (!authCode || authCode.client_id !== client.clientId || authCode.redirect_uri !== body.redirect_uri || !timingSafeEqualText(authCode.code_challenge, challenge)) return null;
    await db.query('UPDATE oauth_codes SET used_at = NOW() WHERE id = $1', [authCode.id]);
    const account = await db.query('SELECT id, name, email, free_requests_used, paid_credits, email_verified_at FROM users WHERE id = $1 AND NOT banned', [authCode.user_id]);
    if (!account.rowCount || !authCode.session_id) return null;
    const live = await db.query('SELECT id FROM sessions WHERE id = $1 AND user_id = $2 AND expires_at > NOW()', [authCode.session_id, authCode.user_id]);
    return live.rowCount ? { ...account.rows[0], sessionId: authCode.session_id } : null;
  });
  if (!result) return res.status(400).json({ error: 'invalid_or_expired_authorization_code' });
  return res.json({
    sessionId: result.sessionId,
    user: { id: result.id, name: result.name, email: result.email, emailVerified: Boolean(result.email_verified_at) },
    usage: { freeRequestsUsed: result.free_requests_used, freeRequestsRemaining: Math.max(0, 3 - result.free_requests_used), paidCredits: result.paid_credits }
  });
});

router.get('/v1/internal/users/:userId/summary', requireService, async (req, res) => {
  const parsedId = z.string().uuid().safeParse(req.params.userId);
  if (!parsedId.success) return res.status(400).json({ error: 'invalid_user_id' });
  const result = await pool.query(
    'SELECT id, name, email, free_requests_used, paid_credits FROM users WHERE id = $1 AND NOT banned',
    [parsedId.data]
  );
  if (!result.rowCount) return res.status(404).json({ error: 'user_not_found' });
  const user = result.rows[0];
  return res.json({
    user: { id: user.id, name: user.name, email: user.email },
    usage: {
      freeRequestsUsed: user.free_requests_used,
      freeRequestsRemaining: Math.max(0, 3 - user.free_requests_used),
      paidCredits: user.paid_credits
    },
    packages
  });
});

// The projects client verifies the central session before any paid operation.
router.post('/v1/internal/session/validate', requireService, async (req, res) => {
  const parsed = z.object({ userId: z.string().uuid(), sessionId: z.string().uuid() }).safeParse(req.body);
  if (!parsed.success) return res.status(401).json({ error: 'invalid_session' });
  const { userId, sessionId } = parsed.data;
  const result = await pool.query(
    `SELECT u.id, u.name, u.email, u.free_requests_used, u.paid_credits
       FROM sessions s JOIN users u ON u.id = s.user_id
       WHERE s.id = $1 AND u.id = $2 AND s.expires_at > NOW()
         AND NOT u.banned AND u.email_verified_at IS NOT NULL`, [sessionId, userId]);
  if (!result.rowCount) return res.status(401).json({ error: 'invalid_session' });
  const u = result.rows[0];
  res.json({ user: { id: u.id, name: u.name, email: u.email },
    usage: { freeRequestsUsed: u.free_requests_used, freeRequestsRemaining: Math.max(0, 3 - u.free_requests_used), paidCredits: u.paid_credits }, packages });
});
router.post('/v1/internal/session/revoke', requireService, async (req, res) => {
  const parsed = z.object({ userId: z.string().uuid(), sessionId: z.string().uuid() }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_session' });
  await pool.query('DELETE FROM sessions WHERE id = $1 AND user_id = $2', [parsed.data.sessionId, parsed.data.userId]);
  res.json({ ok: true });
});

router.post('/v1/internal/usage/reserve', requireService, async (req, res) => {
  const schema = z.object({ userId: z.string().uuid(), idempotencyKey: z.string().min(8).max(128) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_usage_reservation' });
  const { userId, idempotencyKey } = parsed.data;
  const reservation = await transaction(async db => {
    const account = await db.query('SELECT free_requests_used, paid_credits, subscribed_until > NOW() AS subscribed FROM users WHERE id = $1 AND NOT banned FOR UPDATE', [userId]);
    if (!account.rowCount) return { notFound: true };
    const existing = await db.query(
      `SELECT id, bucket, status FROM usage_events
        WHERE user_id = $1 AND service_id = $2 AND idempotency_key = $3`,
      [userId, req.service.clientId, idempotencyKey]
    );
    if (existing.rowCount) return { ...existing.rows[0], replayed: true };
    const row = account.rows[0];
    const bucket = row.subscribed ? 'subscription' : resolveUsageBucket({
      freeRequestsUsed: row.free_requests_used,
      paidCredits: row.paid_credits
    });
    if (bucket === 'free') {
      await db.query('UPDATE users SET free_requests_used = free_requests_used + 1, updated_at = NOW() WHERE id = $1', [userId]);
    } else if (bucket === 'paid') {
      await db.query('UPDATE users SET paid_credits = paid_credits - 1, updated_at = NOW() WHERE id = $1', [userId]);
    } else if (!bucket) {
      return { insufficient: true };
    }
    const inserted = await db.query(
      `INSERT INTO usage_events (user_id, service_id, idempotency_key, bucket, status)
       VALUES ($1, $2, $3, $4, 'reserved') RETURNING id, bucket, status`,
      [userId, req.service.clientId, idempotencyKey, bucket]
    );
    return { ...inserted.rows[0], replayed: false };
  });
  if (reservation.notFound) return res.status(404).json({ error: 'user_not_found' });
  if (reservation.insufficient) return res.status(402).json({ error: 'no_credits', message: 'Бесплатные запросы закончились. Выберите пакет.' });
  return res.json({ reservationId: reservation.id, bucket: reservation.bucket, status: reservation.status, replayed: reservation.replayed });
});

router.post('/v1/internal/usage/:reservationId/finalize', requireService, async (req, res) => {
  const schema = z.object({ outcome: z.enum(['success', 'failure']) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success || !z.string().uuid().safeParse(req.params.reservationId).success) {
    return res.status(400).json({ error: 'invalid_finalization' });
  }
  const result = await transaction(async db => {
    const eventResult = await db.query(
      `SELECT id, user_id, bucket, status FROM usage_events
        WHERE id = $1 AND service_id = $2 FOR UPDATE`,
      [req.params.reservationId, req.service.clientId]
    );
    const event = eventResult.rows[0];
    if (!event) return { notFound: true };
    if (event.status !== 'reserved') return { status: event.status, replayed: true };
    if (parsed.data.outcome === 'success') {
      await db.query("UPDATE usage_events SET status = 'succeeded', finalized_at = NOW() WHERE id = $1", [event.id]);
      return { status: 'succeeded', replayed: false };
    }
    if (event.bucket === 'free') {
      await db.query('UPDATE users SET free_requests_used = GREATEST(0, free_requests_used - 1), updated_at = NOW() WHERE id = $1', [event.user_id]);
    } else if (event.bucket === 'paid') {
      await db.query('UPDATE users SET paid_credits = paid_credits + 1, updated_at = NOW() WHERE id = $1', [event.user_id]);
    }
    await db.query("UPDATE usage_events SET status = 'refunded', finalized_at = NOW() WHERE id = $1", [event.id]);
    return { status: 'refunded', replayed: false };
  });
  if (result.notFound) return res.status(404).json({ error: 'reservation_not_found' });
  return res.json(result);
});

router.post('/v1/internal/payments/grant', requirePaymentWebhook, async (req, res) => {
  const schema = z.object({ eventId: z.string().min(8).max(200), userId: z.string().uuid(), packageId: z.enum(['mini', 'pro', 'max']), amountRub: z.number().int().positive() });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_payment_event' });
  const pack = packages[parsed.data.packageId];
  if (pack.priceRub !== parsed.data.amountRub) return res.status(400).json({ error: 'payment_amount_mismatch' });
  const granted = await transaction(async db => {
    const account = await db.query('SELECT id FROM users WHERE id = $1 FOR UPDATE', [parsed.data.userId]);
    if (!account.rowCount) return { notFound: true };
    const inserted = await db.query(
      `INSERT INTO billing_events (id, user_id, package_id, amount_rub, credits_granted)
       VALUES ($1, $2, $3, $4, $5) ON CONFLICT (id) DO NOTHING RETURNING id`,
      [parsed.data.eventId, parsed.data.userId, parsed.data.packageId, pack.priceRub, pack.credits]
    );
    if (!inserted.rowCount) return { duplicate: true };
    await db.query('UPDATE users SET paid_credits = paid_credits + $1, updated_at = NOW() WHERE id = $2', [pack.credits, parsed.data.userId]);
    return { duplicate: false, creditsGranted: pack.credits };
  });
  if (granted.notFound) return res.status(404).json({ error: 'user_not_found' });
  return res.json({ ok: true, ...granted });
});

router.get('/logout', async (req, res) => {
  const token = req.cookies?.[config.SESSION_COOKIE_NAME];
  if (token) await pool.query('DELETE FROM sessions WHERE token_hash = $1', [sha256(token)]);
  clearSessionCookie(res);

  const clientId = typeof req.query.client_id === 'string' ? req.query.client_id : '';
  const returnTo = typeof req.query.return_to === 'string' ? req.query.return_to : '';
  const client = config.clients.find(item => item.clientId === clientId);
  let target = '/login';
  if (client && returnTo) {
    try {
      const requested = new URL(returnTo);
      const allowedOrigins = new Set(client.redirectUris.map(uri => new URL(uri).origin));
      if (requested.protocol === 'https:' && allowedOrigins.has(requested.origin)) {
        target = requested.origin + '/';
      }
    } catch {}
  }
  return res.redirect(302, target);
});

router.get('/login', (_req, res) => res.sendFile(fileURLToPath(new URL('../public/login.html', import.meta.url))));
router.get('/assets/auth.js', (_req, res) => res.sendFile(fileURLToPath(new URL('../public/auth.js', import.meta.url))));
router.get('/assets/auth.css', (_req, res) => res.sendFile(fileURLToPath(new URL('../public/auth.css', import.meta.url))));

function consoleOwner(req, res, next) {
  const key = process.env.NEXORA_CONSOLE_SECRET;
  res.set('Cache-Control', 'no-store');
  if (!key || key.length < 32 || !timingSafeEqualText(req.get('authorization'), 'Bearer ' + key)) {
    return res.status(403).json({error: 'forbidden'});
  }
  next();
}
router.get('/v1/console/users', consoleOwner, async (req, res) => {
  const list = await pool.query(`SELECT u.id, u.name, u.email, u.banned, u.created_at, u.subscribed_until,
    (SELECT MAX(e.created_at) FROM usage_events e WHERE e.user_id=u.id) AS last_usage
    FROM users u ORDER BY u.created_at DESC`);
  res.json({users:list.rows});
});
router.post('/v1/console/users', consoleOwner, async (req,res) => {
  const parsed = z.object({id:z.string().uuid(), action:z.enum(['ban','unban','subscribe','revoke']), until:z.string().datetime().optional()}).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({error:'invalid_request'});
  const {id,action,until}=parsed.data;
  if (action==='subscribe' && (!until || Date.parse(until)<=Date.now() || Date.parse(until)>Date.now()+366*86400000)) return res.status(400).json({error:'invalid_date'});
  const result=await transaction(async db=>{
    const result=['ban','unban'].includes(action)
      ? await db.query('UPDATE users SET banned=$2 WHERE id=$1 RETURNING id,banned,subscribed_until',[id,action==='ban'])
      : await db.query('UPDATE users SET subscribed_until=$2 WHERE id=$1 RETURNING id,banned,subscribed_until',[id,action==='subscribe'?until:null]);
    if(action==='ban') {
      await db.query('DELETE FROM sessions WHERE user_id=$1',[id]);
      await db.query('DELETE FROM oauth_codes WHERE user_id=$1',[id]);
    }
    return result.rows[0];
  });
  if(!result) return res.status(404).json({error:'user_not_found'});
  res.json({user:result});
});

router.get('/v1/console/usage-history', consoleOwner, async (_req,res) => {
  const data=await pool.query(
    "SELECT (created_at AT TIME ZONE 'UTC')::date::text AS day, service_id, status, COUNT(*)::int AS count, COUNT(DISTINCT user_id)::int AS accounts FROM usage_events WHERE created_at >= date_trunc('day', NOW() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' - INTERVAL '29 days' GROUP BY 1,2,3 ORDER BY 1 DESC,2,3"
  );
  const totals=await pool.query(
    "SELECT service_id, COUNT(*)::int AS requests, COUNT(*) FILTER (WHERE status='succeeded')::int AS succeeded, COUNT(*) FILTER (WHERE status='refunded')::int AS refunded, COUNT(*) FILTER (WHERE status='reserved')::int AS reserved, COUNT(DISTINCT user_id)::int AS accounts FROM usage_events WHERE created_at >= date_trunc('day', NOW() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' - INTERVAL '29 days' GROUP BY service_id ORDER BY requests DESC"
  );
  res.json({scope:'registered_usage_events',days:30,timezone:'UTC',daily:data.rows,services:totals.rows});
});
