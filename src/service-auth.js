import { config } from './config.js';
import { timingSafeEqualText } from './security.js';

export function requireService(req, res, next) {
  const serviceId = req.get('x-service-id');
  const suppliedKey = req.get('x-service-api-key');
  const client = config.clients.find(item => item.clientId === serviceId);
  const projectKey=process.env.PROJECTS_SECURITY_SERVICE_KEY||'';
  const matched=client&&suppliedKey&&(timingSafeEqualText(suppliedKey,client.serviceApiKey)||(client.clientId==='projects-ian'&&projectKey.length>=32&&timingSafeEqualText(suppliedKey,projectKey)));
  if (!matched) {
    return res.status(401).json({ error: 'service_authentication_failed' });
  }
  req.service = client;
  return next();
}

export function requirePaymentWebhook(req, res, next) {
  const supplied = req.get('x-payment-webhook-secret');
  if (config.PAYMENT_WEBHOOK_SECRET.length < 32 || !supplied || !timingSafeEqualText(supplied, config.PAYMENT_WEBHOOK_SECRET)) {
    return res.status(401).json({ error: 'payment_webhook_authentication_failed' });
  }
  return next();
}
