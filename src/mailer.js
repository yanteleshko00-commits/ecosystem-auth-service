import nodemailer from 'nodemailer';
import { config } from './config.js';

let transporter;
function getTransporter() {
  const missing = [];
  if (!config.SMTP_HOST) missing.push('SMTP_HOST');
  if (!config.SMTP_USER) missing.push('SMTP_USER');
  if (!config.SMTP_PASSWORD) missing.push('SMTP_PASSWORD');
  if (!config.SMTP_FROM) missing.push('SMTP_FROM');
  if (missing.length) {
    throw new Error('Email delivery is not configured. Missing: ' + missing.join(', '));
  }
  if (!transporter) {
    transporter = nodemailer.createTransport({
      host: config.SMTP_HOST,
      port: config.SMTP_PORT,
      secure: config.SMTP_SECURE === 'true',
      auth: { user: config.SMTP_USER, pass: config.SMTP_PASSWORD },
      connectionTimeout: 12000,
      greetingTimeout: 12000,
      socketTimeout: 15000
    });
  }
  return transporter;
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character]);
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
  return getTransporter().sendMail({ from: config.SMTP_FROM, to, subject, text, html });
}
