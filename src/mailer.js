import { config } from './config.js';

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character]);
}

function getMissingEmailConfig() {
  const missing = [];
  if (!config.UNISENDER_API_KEY) missing.push('UNISENDER_API_KEY');
  if (!config.UNISENDER_FROM_EMAIL) missing.push('UNISENDER_FROM_EMAIL');
  if (missing.length) {
    throw new Error('Unisender Go email delivery is not configured. Missing: ' + missing.join(', '));
  }
}

export async function sendCodeEmail({ to, code, purpose }) {
  getMissingEmailConfig();

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
  const loginUrl = config.AUTH_PUBLIC_URL.replace(/\/$/, '') + '/login';
  const codeText = escapeHtml(code);
  const text = heading + '\n\nКод: ' + code + '\n\n' + action +
    '\nКод действует 15 минут. Никому его не сообщайте.\n\nNEXORA ID — один аккаунт для сервисов экосистемы.';
  const html = [
    '<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>',
    '<body style="margin:0;padding:28px 14px;background:#f3f5f9;color:#172033;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Arial,sans-serif">',
    '<div style="max-width:500px;margin:0 auto;background:#fff;border:1px solid #e8edf5;border-radius:24px;overflow:hidden">',
    '<div style="padding:25px 30px 8px"><div style="display:inline-block;padding:9px 13px;border-radius:12px;background:#eaf1ff;color:#2568dc;font-size:13px;font-weight:800;letter-spacing:.08em">NEXORA ID</div>',
    '<h1 style="margin:22px 0 8px;font-size:25px;line-height:1.2;letter-spacing:-.03em">' + escapeHtml(heading) + '</h1>',
    '<p style="margin:0;color:#64718a;font-size:15px;line-height:1.55">' + escapeHtml(action) + '</p></div>',
    '<div style="padding:22px 30px 12px"><div style="padding:22px 12px;border:1px solid #e3eaf6;border-radius:16px;background:#f5f8fd;text-align:center">',
    '<div style="font-size:12px;color:#75829a;letter-spacing:.08em;font-weight:700">ВАШ КОД</div>',
    '<div style="margin-top:9px;font-size:36px;line-height:1.25;font-weight:800;letter-spacing:9px;color:#172033">' + codeText + '</div></div>',
    '<p style="margin:14px 0 0;color:#7a879b;font-size:13px;line-height:1.5">Код действует <strong>15 минут</strong>. Не пересылайте его и никому не сообщайте.</p>',
    '<div style="margin:24px 0 12px;text-align:center"><a href="' + escapeHtml(loginUrl) + '" style="display:inline-block;padding:13px 22px;border-radius:12px;background:#246be8;color:#fff;text-decoration:none;font-size:15px;font-weight:700">Открыть NEXORA ID</a></div></div>',
    '<div style="padding:18px 30px 24px;border-top:1px solid #edf0f5;color:#8a95a7;font-size:12px;line-height:1.55">Если вы не запрашивали этот код, просто проигнорируйте письмо.<br>NEXORA ID · Единый аккаунт экосистемы</div>',
    '</div></body></html>'
  ].join('');

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12000);
  timeout.unref?.();

  let response;
  try {
    response = await fetch(config.UNISENDER_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-API-KEY': config.UNISENDER_API_KEY
      },
      body: JSON.stringify({
        message: {
          recipients: [{ email: to }],
          body: { html, plaintext: text },
          subject,
          global_language: 'ru',
          from_email: config.UNISENDER_FROM_EMAIL,
          from_name: config.UNISENDER_FROM_NAME || 'NEXORA ID',
          tags: ['nexora-id', 'authentication']
        }
      }),
      signal: controller.signal
    });
  } catch (error) {
    if (error?.name === 'AbortError') {
      const timeoutError = new Error('Unisender Go API request timed out.');
      timeoutError.code = 'UNISENDER_TIMEOUT';
      throw timeoutError;
    }
    const networkError = new Error('Could not connect to Unisender Go API.');
    networkError.code = 'UNISENDER_NETWORK_ERROR';
    throw networkError;
  } finally {
    clearTimeout(timeout);
  }

  let result;
  try {
    result = await response.json();
  } catch {
    const parseError = new Error('Unisender Go API returned an invalid response.');
    parseError.httpStatus = response.status;
    throw parseError;
  }

  if (!response.ok || result?.status !== 'success') {
    const apiError = new Error(
      'Unisender Go API rejected the request' +
      ' (HTTP ' + response.status +
      (Number.isInteger(result?.code) ? ', API code ' + result.code : '') + ').'
    );
    apiError.httpStatus = response.status;
    if (typeof result?.code === 'string' || Number.isInteger(result?.code)) {
      apiError.apiCode = String(result.code).slice(0, 80);
    }
    throw apiError;
  }

  const failedRecipients = result.failed_emails && typeof result.failed_emails === 'object'
    ? Object.entries(result.failed_emails)
    : [];
  const rejected = failedRecipients.find(([email]) => email.toLowerCase() === to.toLowerCase());
  if (rejected) {
    const recipientError = new Error('Unisender Go rejected the recipient (' + String(rejected[1]).slice(0, 80) + ').');
    recipientError.code = 'UNISENDER_RECIPIENT_REJECTED';
    throw recipientError;
  }

  return {
    messageId: result.job_id,
    accepted: result.emails ?? [to],
    rejected: []
  };
}
