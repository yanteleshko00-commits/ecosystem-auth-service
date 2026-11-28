import {readPublicFile,sendPublicAsset} from './public-performance.js';
import {serveBrand} from './brand.js';
import 'express-async-errors';
import express from 'express';
import { isIP } from 'node:net';
import { timingSafeEqualText } from './security.js';
import { fileURLToPath } from 'node:url';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import { config } from './config.js';
import { pool } from './db.js';
import { router } from './routes.js';
import { validRateEmail, takePersistentRate } from './rate-limits.js';
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
function authenticatedProxyIp(req) {
  const serviceId=req.get('x-service-id');
  const client=config.clients.find(c=>c.clientId==='nexora'&&c.clientId===serviceId);
  const key=req.get('x-service-api-key');
  const ip=req.get('x-nexora-client-ip');
  return client&&key&&ip&&isIP(ip)&&timingSafeEqualText(key,client.serviceApiKey)?ip:null;
}
const addressKey=req=>authenticatedProxyIp(req)||req.ip;
app.use((req,_res,next)=>{req.clientAddress=addressKey(req);next();});
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: 'draft-7', legacyHeaders: false,keyGenerator:addressKey }));
app.use('/v1/auth', async (req,res,next)=>{
  const email=validRateEmail(req.body?.email);
  const ip=await takePersistentRate(pool,'auth-ip',req.clientAddress,100,900);
  const account=ip&&(!email||await takePersistentRate(pool,'auth-email',email,20,900));
  if(!account)return res.status(429).set('Retry-After','900').json({error:'auth_rate_limited',message:'Слишком много попыток. Повторите позже.'});
  next();
});
const cleanup=setInterval(()=>pool.query("DELETE FROM security_rate_limits WHERE expires_at < NOW()").catch(e=>console.error('rate cleanup:',e.code)),3600000);
cleanup.unref();
app.use((req,res,next)=>{if(!serveBrand(req,res,req.path,'NEXORA ID'))next();});
// Public shell only: workspace and authentication API are not cached.
app.use(async(req,res,next)=>{
 if(!['GET','HEAD'].includes(req.method))return next();
 const name=({'/login':'login.html','/login.html':'login.html','/assets/auth.js':'auth.js','/auth.js':'auth.js','/assets/auth.css':'auth.css','/auth.css':'auth.css'})[req.path];
 if(!name||typeof name!=='string')return next();
 try{
  const body=await readPublicFile(fileURLToPath(new URL('../public/'+name,import.meta.url)));
  return sendPublicAsset(req,res,name,body,{'Content-Type':name.endsWith('.html')?'text/html; charset=utf-8':name.endsWith('.css')?'text/css; charset=utf-8':'text/javascript; charset=utf-8','Cache-Control':name.endsWith('.html')?'public, max-age=0, must-revalidate':'public, max-age=300'});
 }catch(error){return next(error);}
});
app.use(express.static(fileURLToPath(new URL('../public', import.meta.url)), { index: false, maxAge: config.NODE_ENV === 'production' ? '1h' : 0 }));
app.use(router);
app.get('/', (_req, res) => res.redirect('/login'));
app.use((req, res) => res.status(404).json({ error: 'not_found' }));
app.use((error, _req, res, _next) => {
  if(error.type==='entity.too.large')return res.status(413).json({error:'payload_too_large'});
  if(error.type==='entity.parse.failed')return res.status(400).json({error:'invalid_json'});
  console.error('Unhandled request error:', error.name, error.code);
  res.status(500).json({ error: 'internal_server_error' });
});

const server = app.listen(config.PORT, () => {
  console.log(`Ecosystem Auth listening on ${config.PORT} (${config.NODE_ENV})`);
});

server.headersTimeout=15000;
server.requestTimeout=30000;
server.maxHeadersCount=80;
server.keepAliveTimeout=5000;
void verifyEmailProvider()
  .then(result => console.info('Email provider verification:', result))
  .catch(error => console.error('Email provider verification failed:', {
    code: error.code,
    httpStatus: error.httpStatus,
    smtpResponseCode: error.smtpResponseCode,
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
