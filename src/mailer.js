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
    throw new Error(`Email delivery is not configured. Missing: ${missing.join(', ')}`);
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

export async function sendCodeEmail({ to, code, purpose }) {
  const isReset = purpose === 'reset_password';
  const subject = isReset ? 'Код для смены пароля' : 'Подтверждение email';
  const heading = isReset ? 'Смена пароля' : 'Подтверждение адреса';
  const text = `${heading}\n\nВаш код: ${code}\n\nКод действует 10 минут. Никому его не сообщайте.`;
  const html = `<!doctype html><html lang="ru"><meta charset="utf-8"><body style="margin:0;background:#f4f6fa;font-family:Arial,sans-serif;color:#172033"><div style="max-width:480px;margin:32px auto;padding:32px;background:#fff;border-radius:20px"><h1 style="font-size:22px">${heading}</h1><p>Введите этот код на странице аккаунта:</p><div style="font-size:32px;font-weight:700;letter-spacing:8px;padding:18px;background:#f1f4f9;border-radius:12px;text-align:center">${code}</div><p style="color:#657087;font-size:13px">Код действует 10 минут. Если вы не запрашивали его, просто проигнорируйте письмо.</p></div></body></html>`;
  return getTransporter().sendMail({ from: config.SMTP_FROM, to, subject, text, html });
}
