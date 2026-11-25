import crypto from 'node:crypto';
export function validRateEmail(value){
  const email=typeof value==='string'?value.trim().toLowerCase():'';
  return email.length<=254&&/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)?email:'';
}
export async function takePersistentRate(db,scope,value,max,seconds){
  if(typeof value!=='string'||!value||!Number.isInteger(max)||max<1||!Number.isInteger(seconds)||seconds<1)return false;
  const pepper=process.env.TOKEN_PEPPER||'';
  if(pepper.length<32)throw Error('rate_limit_pepper_missing');
  const key=crypto.createHmac('sha256',pepper).update(scope+'\0'+value).digest('hex');
  const result=await db.query(`INSERT INTO security_rate_limits (rate_key,hits,expires_at)
    VALUES ($1,1,NOW()+$2*INTERVAL '1 second')
    ON CONFLICT (rate_key) DO UPDATE SET
      hits=CASE WHEN security_rate_limits.expires_at<=NOW() THEN 1 ELSE security_rate_limits.hits+1 END,
      expires_at=CASE WHEN security_rate_limits.expires_at<=NOW() THEN EXCLUDED.expires_at ELSE security_rate_limits.expires_at END
    WHERE security_rate_limits.expires_at<=NOW() OR security_rate_limits.hits<$3
    RETURNING hits`,[key,seconds,max]);
  return result.rowCount===1;
}
