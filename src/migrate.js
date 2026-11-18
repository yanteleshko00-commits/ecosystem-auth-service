import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { pool, transaction } from './db.js';

try {
  const migrationPath = fileURLToPath(new URL('../migrations/001_init.sql', import.meta.url));
  const sql = await fs.readFile(migrationPath, 'utf8');
  await transaction(async client => {
    await client.query(sql);
  });
  console.log('Database migration completed.');
} catch (error) {
  console.error('Database migration failed:', error);
  process.exitCode = 1;
} finally {
  await pool.end();
}
