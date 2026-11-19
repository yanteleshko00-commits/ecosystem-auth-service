import crypto from 'node:crypto';
import express from 'express';
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
const codeTtlMinutes = 10;
const sessionTtlSeconds = config.SESSION_TTL_DAYS * 86400;
const registerSchema = z.object({ name: z.string().trim().min(1).max(60), email: z.string().email().max(254), password: z.string().min(10).max(128) });
const loginSchema = z.object({ email: z.string().email().max(254), password: z.string().min(10).max(128) });
const emailSchema = z.object({ email: z.string().email().max(254) });
const codeSchema = z.object({ email: z.string().email().max(254), code: z.string().regex(/^\d{6}$/) });
const passwordSchema = z.string().min(10).max(128);

function issueCookieSession(res, token) {
  setSessionCookie(res, token, sessionTtlSeconds);
}

async function createEmailToken(userId, purpose) {
  const code = randomCode();
  await transaction(async db => {
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
    `UPDATE email_tokens SET used_at = NOW()
      WHERE id = (
        SELECT id FROM email_tokens
         WHERE user_id = $1 AND token_hash = $2 AND purpose = $3
           AND used_at IS NULL AND expires_at > NOW()
         ORDER BY created_at DESC LIMIT 1 FOR UPDATE
      ) RETURNING id`,
    [userId, sha256(code), purpose]
  );
  return result.rowCount === 1;
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
  const smtpConfigured = Boolean(config.SMTP_HOST && config.SMTP_USER && config.SMTP_PASSWORD && config.SMTP_FROM);
  res.json({ ok: true, service: 'ecosystem-auth', database: 'connected', smtpConfigured });
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
  const existing = await pool.query('SELECT id, email_verified_at FROM users WHERE email = $1', [email]);
  if (existing.rowCount) {
    return res.status(409).json({ error: 'account_already_exists', message: 'Аккаунт с таким email уже зарегистрирован. Войдите или запросите восстановление пароля.' });
  }
  const passwordHash = await hashPassword(parsed.data.password);
  const inserted = await pool.query(
    'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id',
    [parsed.data.name, email, passwordHash]
  );
  const code = await createEmailToken(inserted.rows[0].id, 'verify_email');
  try {
    await sendCodeEmail({ to: email, code, purpose: 'verify_email' });
  } catch (error) {
    console.error('Registration email delivery failed:', {
      code: error.code, responseCode: error.responseCode, command: error.command, message: error.message
    });
    return res.status(503).json({
      error: 'email_delivery_unavailable',
      message: 'Аккаунт создан, но письмо не отправлено. Проверьте настройки SMTP и подтверждённый адрес отправителя в Brevo.'
    });
  }
  return res.status(201).json({ ok: true, message: 'Проверьте почту и введите код подтверждения.' });
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
    console.info('Verification email accepted by SMTP relay:', {
      messageId: info.messageId,
      acceptedCount: info.accepted?.length ?? 0,
      rejectedCount: info.rejected?.length ?? 0
    });
  } catch (error) {
    console.error('Verification email resend failed:', {
      code: error.code, responseCode: error.responseCode, command: error.command, message: error.message
    });
    return res.status(503).json({
      error: 'email_delivery_unavailable',
      message: 'Сервер не смог отправить письмо. Проверьте настройки Brevo SMTP и подтверждённый адрес отправителя.'
    });
  }
  return res.json({ ok: true, message: 'Код принят почтовым сервером. Проверьте Входящие и Спам.' });
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
  return res.json({ ok: true, message: 'Email подтверждён. Теперь можно войти.' });
});

router.post('/v1/auth/login', requireSameOrigin, async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_login_data' });
  const email = normalizeEmail(parsed.data.email);
  const result = await pool.query('SELECT id, password_hash, email_verified_at FROM users WHERE email = $1', [email]);
  const user = result.rows[0];
  if (!user || !(await verifyPassword(user.password_hash, parsed.data.password))) {
    return res.status(401).json({ error: 'invalid_credentials', message: 'Неверный email или пароль.' });
  }
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
  const { id, name, email, free_requests_used, paid_credits } = req.user;
  return res.json({
    user: { id, name, email },
    usage: { freeRequestsUsed: free_requests_used, freeRequestsRemaining: Math.max(0, 3 - free_requests_used), paidCredits },
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
  const result = await pool.query('SELECT id FROM users WHERE email = $1 AND email_verified_at IS NOT NULL', [email]);
  if (result.rowCount) {
    const code = await createEmailToken(result.rows[0].id, 'reset_password');
    await sendCodeEmail({ to: email, code, purpose: 'reset_password' });
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
    await db.query('UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2', [passwordHash, user.rows[0].id]);
    await db.query('DELETE FROM sessions WHERE user_id = $1', [user.rows[0].id]);
    return true;
  });
  if (!changed) return res.status(400).json({ error: 'invalid_or_expired_code' });
  clearSessionCookie(res);
  return res.json({ ok: true, message: 'Пароль изменён. Войдите с новым паролем.' });
});

router.get('/oauth/authorize', async (req, res) => {
  const { client_id: clientId, redirect_uri: redirectUri, response_type: responseType, state, code_challenge: challenge, code_challenge_method: method } = req.query;
  const client = config.clients.find(item => item.clientId === clientId);
  if (!client || responseType !== 'code' || typeof redirectUri !== 'string' || !client.redirectUris.includes(redirectUri) || typeof state !== 'string' || state.length < 16 || state.length > 512 || typeof challenge !== 'string' || !/^[A-Za-z0-9_-]{43,128}$/.test(challenge) || method !== 'S256') {
    return res.status(400).send('Invalid OAuth authorization request.');
  }
  const user = await findSessionUser(req);
  if (!user) {
    const next = encodeURIComponent(req.originalUrl);
    return res.redirect(`/login?next=${next}`);
  }
  const code = randomToken(32);
  await pool.query(
    `INSERT INTO oauth_codes (code_hash, user_id, client_id, redirect_uri, code_challenge, expires_at)
     VALUES ($1, $2, $3, $4, $5, NOW() + INTERVAL '2 minutes')`,
    [sha256(code), user.id, clientId, redirectUri, challenge]
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
      `SELECT id, user_id, client_id, redirect_uri, code_challenge
         FROM oauth_codes WHERE code_hash = $1 AND expires_at > NOW() AND used_at IS NULL
         FOR UPDATE`, [sha256(body.code)]
    );
    const authCode = found.rows[0];
    if (!authCode || authCode.client_id !== client.clientId || authCode.redirect_uri !== body.redirect_uri || !timingSafeEqualText(authCode.code_challenge, challenge)) return null;
    await db.query('UPDATE oauth_codes SET used_at = NOW() WHERE id = $1', [authCode.id]);
    const account = await db.query('SELECT id, name, email, free_requests_used, paid_credits, email_verified_at FROM users WHERE id = $1', [authCode.user_id]);
    return account.rows[0] ?? null;
  });
  if (!result) return res.status(400).json({ error: 'invalid_or_expired_authorization_code' });
  return res.json({
    user: { id: result.id, name: result.name, email: result.email, emailVerified: Boolean(result.email_verified_at) },
    usage: { freeRequestsUsed: result.free_requests_used, freeRequestsRemaining: Math.max(0, 3 - result.free_requests_used), paidCredits: result.paid_credits }
  });
});

router.get('/v1/internal/users/:userId/summary', requireService, async (req, res) => {
  const parsedId = z.string().uuid().safeParse(req.params.userId);
  if (!parsedId.success) return res.status(400).json({ error: 'invalid_user_id' });
  const result = await pool.query(
    'SELECT id, name, email, free_requests_used, paid_credits FROM users WHERE id = $1',
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

router.post('/v1/internal/usage/reserve', requireService, async (req, res) => {
  const schema = z.object({ userId: z.string().uuid(), idempotencyKey: z.string().min(8).max(128) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_usage_reservation' });
  const { userId, idempotencyKey } = parsed.data;
  const reservation = await transaction(async db => {
    const account = await db.query('SELECT free_requests_used, paid_credits FROM users WHERE id = $1 FOR UPDATE', [userId]);
    if (!account.rowCount) return { notFound: true };
    const existing = await db.query(
      `SELECT id, bucket, status FROM usage_events
        WHERE user_id = $1 AND service_id = $2 AND idempotency_key = $3`,
      [userId, req.service.clientId, idempotencyKey]
    );
    if (existing.rowCount) return { ...existing.rows[0], replayed: true };
    const row = account.rows[0];
    const bucket = resolveUsageBucket({
      freeRequestsUsed: row.free_requests_used,
      paidCredits: row.paid_credits
    });
    if (bucket === 'free') {
      await db.query('UPDATE users SET free_requests_used = free_requests_used + 1, updated_at = NOW() WHERE id = $1', [userId]);
    } else if (bucket === 'paid') {
      await db.query('UPDATE users SET paid_credits = paid_credits - 1, updated_at = NOW() WHERE id = $1', [userId]);
    } else {
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
  if (!parsed.success) return res.status(400).json({ error: 'invalid_finalization' });
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
    } else {
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

router.get('/login', (_req, res) => res.sendFile(new URL('../public/login.html', import.meta.url).pathname));
router.get('/assets/auth.js', (_req, res) => res.sendFile(new URL('../public/auth.js', import.meta.url).pathname));
router.get('/assets/auth.css', (_req, res) => res.sendFile(new URL('../public/auth.css', import.meta.url).pathname));
