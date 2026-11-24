import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { pool, transaction } from './db.js';

const migrations = [
  '001_init.sql',
  '002_add_user_name.sql',
  '003_device_account_limit.sql',
  '004_login_code_purpose.sql', '005_console.sql', '006_security.sql'
];

try {
  for (const migration of migrations) {
    const migrationPath = fileURLToPath(new URL(`../migrations/${migration}`, import.meta.url));
    const sql = await fs.readFile(migrationPath, 'utf8');
    await transaction(async client => {
      await client.query(sql);
    });
    console.log(`Database migration completed: ${migration}`);
  }
} catch (error) {
  console.error('Database migration failed:', error);
  process.exitCode = 1;
} finally {
  await pool.end();
}
