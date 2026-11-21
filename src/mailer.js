import { randomUUID } from 'node:crypto';
import { config } from './config.js';

let sandboxFromEmailPromise = null;

function createDeliveryError(message, { code, httpStatus, apiCode } = {}) {
  const error = new Error(message);
  if (code) error.code = code;
  if (httpStatus !== undefined) error.httpStatus = httpStatus;
  if (apiCode !== undefined) error.apiCode = apiCode;
  return error;
}

function getApiSettings() {
  const missing = [];
  if (!config.UNISENDER_API_KEY) missing.push('UNISENDER_API_KEY');
  if (!config.UNISENDER_FROM_EMAIL && config.UNISENDER_USE_SANDBOX !== 'true') {
    missing.push('UNISENDER_FROM_EMAIL (or set UNISENDER_USE_SANDBOX=true for testing)');
  }
  if (missing.length) {
    throw createDeliveryError(
      'UniSender Go API is not configured. Missing: ' + missing.join(', '),
      { code: 'UNISENDER_NOT_CONFIGURED' }
    );
  }

  let baseUrl = config.UNISENDER_API_URL;
  while (baseUrl.endsWith('/')) baseUrl = baseUrl.slice(0, -1);

  return {
    baseUrl,
    endpoint: baseUrl + '/email/send.json',
    apiKey: config.UNISENDER_API_KEY,
    fromEmail: config.UNISENDER_FROM_EMAIL,
    fromName: config.UNISENDER_FROM_NAME
  };
}

async function getSandboxFromEmail(settings, signal) {
  if (!sandboxFromEmailPromise) {
    sandboxFromEmailPromise = (async () => {
      const response = await fetch(settings.baseUrl + '/domain/get-sandbox-domain.json', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'X-API-KEY': settings.apiKey
        },
        body: '{}',
        signal
      });
      const text = await response.text();
      let payload = {};
      try {
        payload = text ? JSON.parse(text) : {};
      } catch {
        throw createDeliveryError('UniSender Go returned an invalid sandbox-domain response.', {
          code: 'UNISENDER_INVALID_RESPONSE',
          httpStatus: response.status
        });
      }

      if (!response.ok || payload.status !== 'success' || !payload.domain) {
        throw createDeliveryError(
          payload.message || 'UniSender Go could not create a sandbox domain. An account-level API key may be required.',
          {
            code: 'UNISENDER_SANDBOX_ERROR',
            httpStatus: response.status,
            apiCode: payload.code
          }
        );
      }

      let domain;
      try {
        const domainUrl = String(payload.domain).includes('://')
          ? String(payload.domain)
          : 'https://' + String(payload.domain);
        domain = new URL(domainUrl).hostname;
      } catch {
        throw createDeliveryError('UniSender Go returned an invalid sandbox domain.', {
          code: 'UNISENDER_INVALID_SANDBOX_DOMAIN'
        });
      }
      if (!domain) {
        throw createDeliveryError('UniSender Go returned an empty sandbox domain.', {
          code: 'UNISENDER_INVALID_SANDBOX_DOMAIN'
        });
      }
      return 'noreply@' + domain;
    })().catch(error => {
      sandboxFromEmailPromise = null;
      throw error;
    });
  }

  return sandboxFromEmailPromise;
}

export async function verifyEmailProvider() {
  if (!config.UNISENDER_API_KEY) {
    throw createDeliveryError('UniSender Go API key is missing.', { code: 'UNISENDER_NOT_CONFIGURED' });
  }
  if (config.UNISENDER_USE_SANDBOX !== 'true') {
    if (!config.UNISENDER_FROM_EMAIL) {
      throw createDeliveryError('Verified sender email is missing.', { code: 'UNISENDER_NOT_CONFIGURED' });
    }
    return { status: 'configured', mode: 'production' };
  }

  const settings = getApiSettings();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), config.UNISENDER_TIMEOUT_MS);
  timeout.unref?.();
  try {
    const fromEmail = await getSandboxFromEmail(settings, controller.signal);
    return {
      status: 'connected',
      mode: 'sandbox',
      senderDomain: fromEmail.slice(fromEmail.indexOf('@') + 1)
    };
  } catch (error) {
    if (error.name === 'AbortError' || error.name === 'TimeoutError') {
      throw createDeliveryError('UniSender Go API request timed out.', { code: 'UNISENDER_TIMEOUT' });
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

export async function sendCodeEmail({ to, code, purpose }) {
  const isReset = purpose === 'reset_password';
  const isLogin = purpose === 'login';
  const subject = isLogin
    ? 'Код для входа в NEXORA ID'
    : isReset ? 'Код для смены пароля NEXORA ID' : 'Подтверждение email в NEXORA ID';
  const heading = isLogin
    ? 'Вход в NEXORA ID'
    : isReset ? 'Смена пароля' : 'Подтверждение email';
  const action = isLogin
    ? 'Введите этот код на странице входа в NEXORA ID.'
    : isReset ? 'Введите этот код, чтобы сменить пароль.'
    : 'Введите этот код, чтобы подтвердить адрес электронной почты.';

  const authBaseUrl = config.AUTH_PUBLIC_URL.endsWith('/')
    ? config.AUTH_PUBLIC_URL.slice(0, -1)
    : config.AUTH_PUBLIC_URL;
  const loginUrl = authBaseUrl + '/login';
  const text = [
    heading,
    '',
    'Код: ' + code,
    '',
    action,
    'Код действует 15 минут. Никому его не сообщайте.',
    '',
    'NEXORA ID — один аккаунт для сервисов экосистемы.'
  ].join('\n');

  const html = [
    '<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>',
    '<body style="margin:0;padding:28px 14px;background:#f3f5f9;color:#172033;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Arial,sans-serif">',
    '<div style="max-width:500px;margin:0 auto;background:#fff;border:1px solid #e8edf5;border-radius:24px;overflow:hidden">',
    '<div style="padding:25px 30px 8px"><div style="display:inline-block;padding:9px 13px;border-radius:12px;background:#eaf1ff;color:#2568dc;font-size:13px;font-weight:800;letter-spacing:.08em">NEXORA ID</div>',
    '<h1 style="margin:22px 0 8px;font-size:25px;line-height:1.2;letter-spacing:-.03em">' + escapeHtml(heading) + '</h1>',
    '<p style="margin:0;color:#64718a;font-size:15px;line-height:1.55">' + escapeHtml(action) + '</p></div>',
    '<div style="padding:22px 30px 12px"><div style="padding:22px 12px;border:1px solid #e3eaf6;border-radius:16px;background:#f5f8fd;text-align:center">',
    '<div style="font-size:12px;color:#75829a;letter-spacing:.08em;font-weight:700">ВАШ КОД</div>',
    '<div style="margin-top:9px;font-size:36px;line-height:1.25;font-weight:800;letter-spacing:9px;color:#172033">' + escapeHtml(code) + '</div></div>',
    '<p style="margin:14px 0 0;color:#7a879b;font-size:13px;line-height:1.5">Код действует <strong>15 минут</strong>. Не пересылайте его и никому не сообщайте.</p>',
    '<div style="margin:24px 0 12px;text-align:center"><a href="' + escapeHtml(loginUrl) + '" style="display:inline-block;padding:13px 22px;border-radius:12px;background:#246be8;color:#fff;text-decoration:none;font-size:15px;font-weight:700">Открыть NEXORA ID</a></div></div>',
    '<div style="padding:18px 30px 24px;border-top:1px solid #edf0f5;color:#8a95a7;font-size:12px;line-height:1.55">Если вы не запрашивали этот код, просто проигнорируйте письмо.<br>NEXORA ID · Единый аккаунт экосистемы</div>',
    '</div></body></html>'
  ].join('');

  const settings = getApiSettings();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), config.UNISENDER_TIMEOUT_MS);
  timeout.unref?.();

  try {
    const fromEmail = settings.fromEmail || await getSandboxFromEmail(settings, controller.signal);
    const response = await fetch(settings.endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-API-KEY': settings.apiKey
      },
      body: JSON.stringify({
        message: {
          recipients: [{ email: to }],
          subject,
          from_email: fromEmail,
          from_name: settings.fromName,
          body: { html, plaintext: text },
          global_language: 'ru',
          template_engine: 'none',
          idempotence_key: randomUUID()
        }
      }),
      signal: controller.signal
    });

    const responseText = await response.text();
    let payload = {};
    try {
      payload = responseText ? JSON.parse(responseText) : {};
    } catch {
      throw createDeliveryError('UniSender Go API returned an invalid JSON response.', {
        code: 'UNISENDER_INVALID_RESPONSE',
        httpStatus: response.status
      });
    }

    if (!response.ok || payload.status !== 'success') {
      throw createDeliveryError(
        payload.message || 'UniSender Go API rejected the email request.',
        {
          code: 'UNISENDER_API_ERROR',
          httpStatus: response.status,
          apiCode: payload.code
        }
      );
    }

    const rejected = payload.failed_emails && typeof payload.failed_emails === 'object'
      ? payload.failed_emails : {};
    const rejectedAddress = Object.keys(rejected).find(
      address => address.toLowerCase() === String(to).toLowerCase()
    );
    if (rejectedAddress) {
      throw createDeliveryError('UniSender Go rejected recipient: ' + rejected[rejectedAddress], {
        code: 'UNISENDER_RECIPIENT_REJECTED',
        httpStatus: response.status,
        apiCode: payload.code
      });
    }

    const accepted = Array.isArray(payload.emails) ? payload.emails : [to];
    if (Array.isArray(payload.emails) && !payload.emails.some(
      address => String(address).toLowerCase() === String(to).toLowerCase()
    )) {
      throw createDeliveryError('UniSender Go did not confirm acceptance of the recipient.', {
        code: 'UNISENDER_RECIPIENT_NOT_ACCEPTED',
        httpStatus: response.status,
        apiCode: payload.code
      });
    }

    return {
      messageId: payload.job_id ?? null,
      status: 'accepted',
      accepted,
      rejected: Object.keys(rejected)
    };
  } catch (error) {
    if (error.name === 'AbortError' || error.name === 'TimeoutError') {
      throw createDeliveryError('UniSender Go API request timed out.', {
        code: 'UNISENDER_TIMEOUT'
      });
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}
