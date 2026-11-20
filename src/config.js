import 'dotenv/config';
import { z } from 'zod';

const ClientSchema = z.object({
  clientId: z.string().min(2).max(80),
  clientSecret: z.string().min(32),
  serviceApiKey: z.string().min(32),
  redirectUris: z.array(z.string().url()).min(1)
});

const EnvSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(4000),
  AUTH_PUBLIC_URL: z.string().url().default('http://localhost:4000'),
  DATABASE_URL: z.string().min(1),
  DATABASE_SSL: z.string().default('false'),
  SESSION_COOKIE_NAME: z.string().default('ecosystem_session'),
  TOKEN_PEPPER: z.string().min(32),
  SESSION_TTL_DAYS: z.coerce.number().int().min(1).max(90).default(30),
  COOKIE_SECURE: z.string().default('false'),
  SMTP_HOST: z.string().default(''),
  SMTP_PORT: z.coerce.number().int().min(1).max(65535).default(587),
  SMTP_SECURE: z.string().default('false'),
  SMTP_USER: z.string().default(''),
  SMTP_PASSWORD: z.string().default(''),
  SMTP_FROM: z.string().default(''),
  OAUTH_CLIENTS_JSON: z.string().default('[]'),
  PROJECTS_OAUTH_CLIENT_SECRET: z.string().default(''),
  PROJECTS_SERVICE_API_KEY: z.string().default(''),
  PROJECTS_REDIRECT_URI: z.string().url().default('https://vse-proekty-ian-1.onrender.com/auth/callback'),
  PAYMENT_WEBHOOK_SECRET: z.string().default(''),
  TRUST_PROXY: z.string().default('false')
});

const parsed = EnvSchema.safeParse(process.env);
if (!parsed.success) {
  console.error('Invalid environment configuration:', parsed.error.flatten().fieldErrors);
  process.exit(1);
}

const raw = parsed.data;
if (raw.NODE_ENV === 'production' && !raw.AUTH_PUBLIC_URL.startsWith('https://')) {
  throw new Error('AUTH_PUBLIC_URL must use HTTPS in production.');
}
let clients;
try {
  clients = z.array(ClientSchema).parse(JSON.parse(raw.OAUTH_CLIENTS_JSON));
} catch (error) {
  console.error('OAUTH_CLIENTS_JSON must be a valid JSON array of OAuth clients.');
  throw error;
}

if (Boolean(raw.PROJECTS_OAUTH_CLIENT_SECRET) !== Boolean(raw.PROJECTS_SERVICE_API_KEY)) {
  throw new Error('Set both PROJECTS_OAUTH_CLIENT_SECRET and PROJECTS_SERVICE_API_KEY to register the projects-ian OAuth client.');
}
if (raw.PROJECTS_OAUTH_CLIENT_SECRET) {
  if (raw.PROJECTS_OAUTH_CLIENT_SECRET.length < 32 || raw.PROJECTS_SERVICE_API_KEY.length < 32) {
    throw new Error('projects-ian OAuth secrets must each contain at least 32 characters.');
  }
  if (clients.some(client => client.clientId === 'projects-ian')) {
    throw new Error('projects-ian is already present in OAUTH_CLIENTS_JSON; do not register it twice.');
  }
  clients.push({
    clientId: 'projects-ian',
    clientSecret: raw.PROJECTS_OAUTH_CLIENT_SECRET,
    serviceApiKey: raw.PROJECTS_SERVICE_API_KEY,
    redirectUris: [raw.PROJECTS_REDIRECT_URI]
  });
}

if (new Set(clients.map(c => c.clientId)).size !== clients.length) {
  throw new Error('OAUTH_CLIENTS_JSON contains duplicate clientId values.');
}

export const config = Object.freeze({
  ...raw,
  databaseSsl: raw.DATABASE_SSL === 'true',
  cookieSecure: raw.COOKIE_SECURE === 'true' || raw.NODE_ENV === 'production',
  trustProxy: raw.TRUST_PROXY === 'true',
  clients,
  authOrigin: new URL(raw.AUTH_PUBLIC_URL).origin
});
