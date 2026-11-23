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
  BREVO_API_KEY: z.string().trim().default(''),
  BREVO_FROM_EMAIL: z.string().email().or(z.literal('')).default(''),
  SMTP_HOST: z.string().trim().min(1).default('smtp.yandex.ru'),
  SMTP_PORT: z.coerce.number().int().min(1).max(65535).default(465),
  SMTP_SECURE: z.string().default('true'),
  SMTP_USER: z.string().trim().default(''),
  SMTP_PASSWORD: z.string().default(''),
  SMTP_FROM_EMAIL: z.string().email().or(z.literal('')).default(''),
  SMTP_FROM_NAME: z.string().trim().min(1).max(78).default('NEXORA ID'),
  SMTP_TIMEOUT_MS: z.coerce.number().int().min(1000).max(60000).default(15000),
  OAUTH_CLIENTS_JSON: z.string().default('[]'),
  NEXORA_CLIENT_SECRET: z.string().default(''),
  NEXORA_SERVICE_API_KEY: z.string().default(''),
  NEXORA_REDIRECT_URI: z.string().url().default('https://nexora-lobby.onrender.com/auth/callback'),
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
let clients = [];
try {
  clients = z.array(ClientSchema).parse(JSON.parse(raw.OAUTH_CLIENTS_JSON));
} catch {
  console.warn('OAUTH_CLIENTS_JSON is not a valid JSON array; using explicitly configured OAuth clients.');
}

function addConfiguredClient(clientId, clientSecret, serviceApiKey, redirectUri) {
  if (Boolean(clientSecret) !== Boolean(serviceApiKey)) {
    throw new Error('Both OAuth client secret and service API key must be set for ' + clientId + '.');
  }
  if (!clientSecret) return;
  if (clientSecret.length < 32 || serviceApiKey.length < 32) {
    throw new Error(clientId + ' OAuth secrets must each contain at least 32 characters.');
  }
  if (clients.some(client => client.clientId === clientId)) {
    throw new Error(clientId + ' is already present in OAUTH_CLIENTS_JSON; remove the duplicate or use environment-based registration only.');
  }
  clients.push({ clientId, clientSecret, serviceApiKey, redirectUris: [redirectUri] });
}

addConfiguredClient('nexora', raw.NEXORA_CLIENT_SECRET, raw.NEXORA_SERVICE_API_KEY, raw.NEXORA_REDIRECT_URI);
addConfiguredClient('projects-ian', raw.PROJECTS_OAUTH_CLIENT_SECRET, raw.PROJECTS_SERVICE_API_KEY, raw.PROJECTS_REDIRECT_URI);

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
