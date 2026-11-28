import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import crypto from 'node:crypto';

test('PostgreSQL: OTP lockout, OAuth session, usage and payment idempotency', {skip:process.env.RUN_AUTH_INTEGRATION!=='1',timeout:60000},async()=>{
 const pepper=process.env.TOKEN_PEPPER;
 const key=process.env.NEXORA_SERVICE_API_KEY;
 const secret=process.env.NEXORA_CLIENT_SECRET;
 const webhook=process.env.PAYMENT_WEBHOOK_SECRET;
 const base=process.env.AUTH_PUBLIC_URL;
 const {pool}=await import('../src/db.js');
 const hash=s=>crypto.createHmac('sha256',pepper).update(s).digest('hex');
 const email='integration-'+crypto.randomUUID()+'@example.test';
 let uid,child;
 const call=async(path,body,headers={})=>{
   const r=await fetch(base+path,{method:'POST',headers:{'Content-Type':'application/json',...headers},body:JSON.stringify(body),signal:AbortSignal.timeout(5000)});
   return {status:r.status,data:await r.json()};
 };
 const svc={'x-service-id':'nexora','x-service-api-key':key};
 try{
   const u=await pool.query("INSERT INTO users (name,email,password_hash,email_verified_at) VALUES ('CI test', $1,'not-used',NOW()) RETURNING id",[email]);
   uid=u.rows[0].id;
   await pool.query("INSERT INTO email_tokens (user_id,token_hash,purpose,expires_at) VALUES ($1,$2,'login',NOW()+INTERVAL '15 minutes')",[uid,hash('123456')]);
   child=spawn(process.execPath,['src/server.js'],{env:process.env,stdio:'ignore'});
   let ready=false;for(let i=0;i<50;i++){try{if((await fetch(base+'/health',{signal:AbortSignal.timeout(1000)})).ok){ready=true;break;}}catch{}await new Promise(r=>setTimeout(r,200));}
   assert.equal(ready,true,'auth server must start');
   for(let i=0;i<5;i++)assert.equal((await call('/v1/auth/verify-login-code',{email,code:'000000'})).status,400);
   assert.equal((await call('/v1/auth/verify-login-code',{email,code:'123456'})).status,400);
   const locked=await pool.query("SELECT failed_attempts,used_at FROM email_tokens WHERE user_id=$1",[uid]);
   assert.equal(locked.rows[0].failed_attempts,5);assert.ok(locked.rows[0].used_at);
   const session=(await pool.query("INSERT INTO sessions(user_id,token_hash,expires_at) VALUES($1,$2,NOW()+INTERVAL '1 day') RETURNING id",[uid,hash('session-'+crypto.randomUUID())])).rows[0].id;
   const code=crypto.randomBytes(32).toString('base64url'),verifier=crypto.randomBytes(32).toString('base64url');
   const challenge=crypto.createHash('sha256').update(verifier).digest('base64url');
   const redirect=process.env.NEXORA_REDIRECT_URI;
   await pool.query("INSERT INTO oauth_codes (code_hash,user_id,client_id,redirect_uri,code_challenge,expires_at,session_id) VALUES($1,$2,'nexora',$3,$4,NOW()+INTERVAL '2 minutes',$5)",[hash(code),uid,redirect,challenge,session]);
   const body={client_id:'nexora',client_secret:secret,grant_type:'authorization_code',code,code_verifier:verifier,redirect_uri:redirect};
   const oauth=await call('/oauth/token',body);assert.equal(oauth.status,200);assert.equal(oauth.data.sessionId,session);
   assert.equal((await call('/oauth/token',body)).status,400);
   assert.equal((await call('/v1/internal/session/validate',{userId:uid,sessionId:session},svc)).status,200);
   const reservation={userId:uid,sessionId:session,idempotencyKey:crypto.randomUUID()};
   const one=await call('/v1/internal/usage/reserve',reservation,svc);
   const two=await call('/v1/internal/usage/reserve',reservation,svc);
   assert.equal(one.status,200);assert.equal(two.data.reservationId,one.data.reservationId);assert.equal(two.data.replayed,true);
   const finalize='/v1/internal/usage/'+one.data.reservationId+'/finalize';
   assert.equal((await call(finalize,{outcome:'failure'},svc)).data.status,'refunded');
   assert.equal((await call(finalize,{outcome:'failure'},svc)).data.replayed,true);
   const payment={eventId:crypto.randomUUID(),userId:uid,packageId:'mini',amountRub:200};
   const payHeaders={'x-payment-webhook-secret':webhook};
   assert.equal((await call('/v1/internal/payments/grant',payment,payHeaders)).data.creditsGranted,3);
   assert.equal((await call('/v1/internal/payments/grant',payment,payHeaders)).data.duplicate,true);
   const balance=await pool.query('SELECT free_requests_used,paid_credits FROM users WHERE id=$1',[uid]);
   assert.equal(balance.rows[0].free_requests_used,0);assert.equal(balance.rows[0].paid_credits,3);
   await pool.query("UPDATE users SET subscribed_until=NOW()+INTERVAL '1 day' WHERE id=$1",[uid]);
   const live=await call('/v1/internal/session/validate',{userId:uid,sessionId:session},svc);
   assert.equal(live.data.subscription.active,true);
   const reserved=await Promise.all(['chat','image','text','math'].map(product=>call('/v1/internal/usage/reserve',{userId:uid,sessionId:session,idempotencyKey:crypto.randomUUID(),product},svc)));
   assert.ok(reserved.every(r=>r.status===200&&r.data.bucket==='subscription'));
   assert.equal((await call('/v1/internal/usage/reserve',{userId:uid,sessionId:session,idempotencyKey:crypto.randomUUID(),product:'game'},svc)).status,429);
   for(const r of reserved)assert.equal((await call('/v1/internal/usage/'+r.data.reservationId+'/finalize',{outcome:'success'},svc)).status,200);
   const after=await pool.query('SELECT paid_credits FROM users WHERE id=$1',[uid]);assert.equal(after.rows[0].paid_credits,3);
   assert.equal((await call('/v1/internal/session/revoke',{userId:uid,sessionId:session},svc)).status,200);
   assert.equal((await call('/v1/internal/session/validate',{userId:uid,sessionId:session},svc)).status,401);
   assert.equal((await call('/v1/internal/usage/reserve',{...reservation,idempotencyKey:crypto.randomUUID()},svc)).status,404);
 }finally{
   if(child){child.kill('SIGTERM');}
   if(uid)await pool.query('DELETE FROM users WHERE id=$1',[uid]);
   await pool.end();
 }
});
