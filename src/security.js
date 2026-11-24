import crypto from 'node:crypto';
import argon2 from 'argon2';
import { config } from './config.js';
import { pool } from './db.js';

export const sha256 = value => crypto.createHmac('sha256', config.TOKEN_PEPPER).update(String(value)).digest('hex');
export const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');
export const randomCode = () => String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
export const normalizeEmail = email => String(email).trim().toLowerCase();
export const hashPassword = password => argon2.hash(password, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });
export const verifyPassword = (hash, password) => argon2.verify(hash, password);

export function safeNextPath(value) {
  if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//') || value.includes('\\')) return '/';
  return value;
}

export function setSessionCookie(res, token, maxAgeSeconds) {
  res.cookie(config.SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    secure: config.cookieSecure,
    sameSite: 'lax',
    path: '/',
    maxAge: maxAgeSeconds * 1000
  });
}

export function clearSessionCookie(res) {
  res.clearCookie(config.SESSION_COOKIE_NAME, {
    httpOnly: true,
    secure: config.cookieSecure,
    sameSite: 'lax',
    path: '/'
  });
}

export async function findSessionUser(req) {
  const token = req.cookies?.[config.SESSION_COOKIE_NAME];
  if (!token) return null;
  const result = await pool.query(
    `SELECT u.id, u.name, u.email, u.free_requests_used, u.paid_credits, u.email_verified_at, s.id AS session_id
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = $1 AND s.expires_at > NOW() AND NOT u.banned AND u.email_verified_at IS NOT NULL`,
    [sha256(token)]
  );
  return result.rows[0] ?? null;
}

export async function requireUser(req, res, next) {
  try {
    req.user = await findSessionUser(req);
    if (!req.user) return res.status(401).json({ error: 'authentication_required' });
    return next();
  } catch (error) {
    return next(error);
  }
}

export function timingSafeEqualText(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}
