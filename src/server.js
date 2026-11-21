import 'express-async-errors';
import express from 'express';
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
app.use('/v1/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: 'draft-7', legacyHeaders: false }));
app.use(express.static(new URL('../public', import.meta.url).pathname, { index: false, maxAge: config.NODE_ENV === 'production' ? '1h' : 0 }));
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
    apiCode: error.apiCode,
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
