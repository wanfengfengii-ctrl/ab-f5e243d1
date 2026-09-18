'use strict';
// Applies SQL migrations from the migrations/ directory in filename order.
// Safe to run on every boot: schema_migrations records applied versions, and
// a transaction-scoped advisory lock serializes the several API instances and
// the worker that may boot at the same time.

import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const migrationsDir = join(here, '..', '..', 'migrations');
const MIGRATION_LOCK_KEY = 912367221;

export async function runMigrations(pool) {
  const files = readdirSync(migrationsDir)
    .filter((f) => /^\d+_.*\.sql$/.test(f))
    .sort();

  const client = await pool.connect();
  try {
    await client.query(
      'CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())'
    );
    await client.query('SELECT pg_advisory_lock($1)', [MIGRATION_LOCK_KEY]);
    for (const f of files) {
      const { rows } = await client.query(
        'SELECT 1 FROM schema_migrations WHERE version = $1',
        [f]
      );
      if (rows.length) continue;
      const sql = readFileSync(join(migrationsDir, f), 'utf8');
      await client.query(sql);
      await client.query('INSERT INTO schema_migrations (version) VALUES ($1)', [f]);
      console.log(`[migrations] applied ${f}`);
    }
  } finally {
    await client
      .query('SELECT pg_advisory_unlock($1)', [MIGRATION_LOCK_KEY])
      .catch(() => {});
    client.release();
  }
}
