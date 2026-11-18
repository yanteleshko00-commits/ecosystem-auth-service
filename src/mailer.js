import nodemailer from 'nodemailer';
import { config } from './config.js';

let transporter;
function getTransporter() {
  if (!config.SMTP_HOST || !config.SMTP_USER || !config.SMTP_PASSWORD) {
    throw new Error('Email delivery is not configured. Set SMTP_HOST, SMTP_USER and SMTP_PASSWORD.');
  }
  if (!transporter) {
    transporter = nodemailer.createTransport({
      host: config.SMTP_HOST,
      port: config.SMTP_PORT,
      secure: config.SMTP_SECURE === 'true',
      auth: { user: config.SMTP_USER, pass: config.SMTP_PASSWORD }
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
