import pg from 'pg';
import { config } from './config.js';

const { Pool } = pg;
const mode=process.env.DATABASE_SSL_MODE||'';
let connectionString=config.DATABASE_URL;
let ssl=config.databaseSsl?{rejectUnauthorized:true}:undefined;
if(mode==='render-internal'){
  const url=new URL(connectionString);
  if(!/^dpg-[a-z0-9]+(?:-[a-z0-9]+)?$/.test(url.hostname))throw Error('render-internal TLS mode requires the private Render database hostname');
  // Render internal TLS certificates are self-signed. Require encryption and
  // permit the private-network certificate only for the internal hostname.
  for(const key of ['sslmode','ssl','sslcert','sslkey','sslrootcert'])url.searchParams.delete(key);
  connectionString=url.toString();
  ssl={rejectUnauthorized:false};
}else if(mode==='verify-full'){
  const url=new URL(connectionString);
  for(const key of ['sslmode','ssl','sslcert','sslkey','sslrootcert'])url.searchParams.delete(key);
  connectionString=url.toString();ssl={rejectUnauthorized:true};
}else if(mode)throw Error('Invalid DATABASE_SSL_MODE');
export const pool = new Pool({
  connectionString,
  ssl,
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 8_000
});

export async function transaction(work) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await work(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}
