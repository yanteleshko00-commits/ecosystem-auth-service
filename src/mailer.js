import nodemailer from 'nodemailer';
import { config } from './config.js';

let transporter;

function createDeliveryError(message, { code, smtpResponseCode, cause } = {}) {
  const error = new Error(message, cause ? { cause } : undefined);
  if (code) error.code = code;
  if (smtpResponseCode !== undefined) error.smtpResponseCode = smtpResponseCode;
  return error;
}

function getSenderAddress() {
  if (config.SMTP_FROM_EMAIL) return config.SMTP_FROM_EMAIL;
  if (config.SMTP_USER.includes('@')) return config.SMTP_USER;
  if (config.SMTP_HOST === 'smtp.yandex.ru') return config.SMTP_USER + '@yandex.ru';
  throw createDeliveryError('SMTP_FROM_EMAIL is required for this SMTP host.', {
    code: 'SMTP_SENDER_NOT_CONFIGURED'
  });
}

function getTransporter() {
  const missing = [];
  if (!config.SMTP_USER) missing.push('SMTP_USER');
  if (!config.SMTP_PASSWORD) missing.push('SMTP_PASSWORD');

  if (missing.length) {
    throw createDeliveryError(
      'Yandex SMTP is not configured. Missing: ' + missing.join(', '),
      { code: 'SMTP_NOT_CONFIGURED' }
    );
  }

  if (!transporter) {
    transporter = nodemailer.createTransport({
      host: config.SMTP_HOST,
      port: config.SMTP_PORT,
      secure: config.SMTP_SECURE === 'true',
      auth: {
        user: config.SMTP_USER,
        pass: config.SMTP_PASSWORD
      },
      connectionTimeout: config.SMTP_TIMEOUT_MS,
      greetingTimeout: config.SMTP_TIMEOUT_MS,
      socketTimeout: config.SMTP_TIMEOUT_MS,
      tls: {
        minVersion: 'TLSv1.2'
      }
    });
  }

  return transporter;
}

function brevoEnabled() {
  return Boolean(config.BREVO_API_KEY);
}

function getBrevoSender() {
  const email = config.BREVO_FROM_EMAIL || config.SMTP_FROM_EMAIL || '';
  if (!email) throw createDeliveryError('BREVO_FROM_EMAIL is required for HTTPS email delivery.', { code: 'BREVO_SENDER_NOT_CONFIGURED' });
  return email;
}

async function sendViaBrevo({ to, subject, html, text }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12000);
  let response;
  try {
    response = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'api-key': config.BREVO_API_KEY,
        'content-type': 'application/json',
        accept: 'application/json'
      },
      body: JSON.stringify({
        sender: { name: config.SMTP_FROM_NAME, email: getBrevoSender() },
        to: [{ email: to }],
        replyTo: { email: 'yateleshko@yandex.ru', name: 'NEXORA ID' },
        subject, htmlContent: html, textContent: text
      }),
      signal: controller.signal
    });
  } catch (error) {
    throw createDeliveryError('HTTPS email provider is unreachable.', {
      code: error.name === 'AbortError' ? 'BREVO_TIMEOUT' : 'BREVO_CONNECTION_FAILED',
      cause: error
    });
  } finally {
    clearTimeout(timer);
  }
  if (!response.ok) {
    console.error('Brevo email request failed:', { status: response.status });
    throw createDeliveryError('HTTPS email provider rejected the message.', {
      code: 'BREVO_HTTP_' + response.status
    });
  }
  const result = await response.json().catch(() => ({}));
  if (!result.messageId && !Array.isArray(result.messageIds)) {
    throw createDeliveryError('HTTPS email provider did not confirm acceptance.', {
      code: 'BREVO_NO_MESSAGE_ID'
    });
  }
  return { status: 'accepted', messageId: result.messageId ?? result.messageIds?.[0] ?? null };
}

export async function verifyEmailProvider() {
  if (brevoEnabled()) {
    getBrevoSender();
    return { status: 'configured', mode: 'https_api', provider: 'brevo' };
  }
  getSenderAddress();
  const transport = getTransporter();
  try {
    await transport.verify();
    return {
      status: 'connected',
      mode: 'smtp',
      host: config.SMTP_HOST,
      port: config.SMTP_PORT
    };
  } catch (error) {
    console.error('SMTP connectivity diagnostics:', {
      code: error.code || 'SMTP_VERIFY_FAILED',
      command: error.command || null,
      smtpResponseCode: error.responseCode ?? null,
      reason: error.code === 'ETIMEDOUT' ? 'connection_timeout' :
        error.code === 'EAUTH' ? 'smtp_authentication_rejected' :
        error.code === 'ECONNREFUSED' ? 'connection_refused' : 'smtp_connection_error'
    });
    throw createDeliveryError('Yandex SMTP connection verification failed.', {
      code: error.code || 'SMTP_VERIFY_FAILED',
      smtpResponseCode: error.responseCode,
      cause: error
    });
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

  if (brevoEnabled()) return sendViaBrevo({ to, subject, html, text });

  try {
    const info = await getTransporter().sendMail({
      from: {
        name: config.SMTP_FROM_NAME,
        address: getSenderAddress()
      },
      to,
      subject,
      text,
      html
    });

    const accepted = Array.isArray(info.accepted) ? info.accepted.map(String) : [];
    const rejected = Array.isArray(info.rejected) ? info.rejected.map(String) : [];
    const recipientAccepted = accepted.some(
      address => address.toLowerCase() === String(to).toLowerCase()
    );

    if (!recipientAccepted) {
      throw createDeliveryError('Yandex SMTP did not confirm acceptance of the recipient.', {
        code: 'SMTP_RECIPIENT_NOT_ACCEPTED'
      });
    }

    return {
      messageId: info.messageId ?? null,
      status: 'accepted',
      accepted,
      rejected
    };
  } catch (error) {
    if (error.code === 'SMTP_NOT_CONFIGURED' || error.code === 'SMTP_RECIPIENT_NOT_ACCEPTED') {
      throw error;
    }
    throw createDeliveryError('Yandex SMTP could not send the email.', {
      code: error.code || 'SMTP_SEND_FAILED',
      smtpResponseCode: error.responseCode,
      cause: error
    });
  }
}
