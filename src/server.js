import 'express-async-errors';
import express from 'express';
import { fileURLToPath } from 'node:url';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import { config } from './config.js';
import { pool } from './db.js';
import { router } from './routes.js';
import { verifyEmailProvider } from './mailer.js';

const app = express();
if (config.trustProxy) app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      objectSrc: ["'none'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));
app.use(express.json({ limit: '20kb' }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));
app.use(cookieParser());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: 'draft-7', legacyHeaders: false }));
// The NEXORA lobby proxies auth requests from one server IP. Bucket requests
// by normalized email for email-based auth endpoints so users do not share
// one 12-request allowance. Keep the global limiter as a second guard.
app.use('/v1/auth', rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  keyGenerator: req => {
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    if (email && email.length <= 254 && /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email)) {
      return 'email:' + email;
    }
    return 'ip:' + req.ip;
  },
  handler: (_req, res) => res.status(429).json({
    error: 'auth_rate_limited',
    message: 'Слишком много попыток. Подождите 15 минут и попробуйте снова.'
  })
}));
app.use(express.static(fileURLToPath(new URL('../public', import.meta.url)), { index: false, maxAge: config.NODE_ENV === 'production' ? '1h' : 0 }));
app.use(router);
app.get('/', (_req, res) => res.redirect('/login'));
app.use((req, res) => res.status(404).json({ error: 'not_found' }));
app.use((error, _req, res, _next) => {
  console.error('Unhandled request error:', error);
  res.status(500).json({ error: 'internal_server_error' });
});

const server = app.listen(config.PORT, () => {
  console.log(`Ecosystem Auth listening on ${config.PORT} (${config.NODE_ENV})`);
});

void verifyEmailProvider()
  .then(result => console.info('Email provider verification:', result))
  .catch(error => console.error('Email provider verification failed:', {
    code: error.code,
    httpStatus: error.httpStatus,
    smtpResponseCode: error.smtpResponseCode,
    message: error.message
  }));

async function shutdown(signal) {
  console.log(`${signal} received. Shutting down...`);
  server.close(async () => {
    await pool.end();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
