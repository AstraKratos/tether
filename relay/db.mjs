// Relay storage: SQLite (node:sqlite). Postgres is a deploy-time swap; the relay is
// deliberately dumb (plan §3.2) — it stores ciphertext and routing metadata only.
import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';

export function openDb(file) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS accounts(
      id TEXT PRIMARY KEY, name TEXT, token_hash TEXT NOT NULL, created_at INTEGER);
    CREATE TABLE IF NOT EXISTS devices(
      id TEXT PRIMARY KEY, account_id TEXT NOT NULL, name TEXT, platform TEXT,
      pubkey TEXT NOT NULL, paired_at INTEGER, last_seen INTEGER);
    CREATE TABLE IF NOT EXISTS clients(
      id TEXT PRIMARY KEY, account_id TEXT NOT NULL, name TEXT,
      token_hash TEXT NOT NULL, created_at INTEGER, last_seen INTEGER);
    CREATE TABLE IF NOT EXISTS client_links(
      id TEXT PRIMARY KEY, account_id TEXT NOT NULL, code_hash TEXT NOT NULL,
      expires_at INTEGER, used_at INTEGER);
    CREATE TABLE IF NOT EXISTS pairings(
      id TEXT PRIMARY KEY, account_id TEXT NOT NULL, code_hash TEXT NOT NULL,
      expires_at INTEGER, used_at INTEGER);
    CREATE TABLE IF NOT EXISTS sessions(
      device_id TEXT NOT NULL, session_id TEXT NOT NULL, agent TEXT, state TEXT,
      meta_ct TEXT, created_at INTEGER, updated_at INTEGER,
      PRIMARY KEY(device_id, session_id));
    CREATE TABLE IF NOT EXISTS events(
      device_id TEXT NOT NULL, session_id TEXT NOT NULL, seq INTEGER NOT NULL,
      ts TEXT, ct TEXT NOT NULL,
      PRIMARY KEY(device_id, session_id, seq));
    CREATE TABLE IF NOT EXISTS approvals(
      id TEXT PRIMARY KEY, device_id TEXT, session_id TEXT, request_ct TEXT,
      status TEXT, deadline INTEGER, created_at INTEGER, decided_at INTEGER, decided_by TEXT);
    CREATE TABLE IF NOT EXISTS prompts(
      id TEXT PRIMARY KEY, device_id TEXT, session_id TEXT, body_ct TEXT,
      status TEXT, detail TEXT, created_at INTEGER, updated_at INTEGER);
  `);
  // email/password login (added later): migrate existing databases in place.
  // pass_salt + auth_hash verify the login; key_ct is the account's e2e key wrapped by a
  // password-derived key in the BROWSER — the relay stores it but can never open it.
  for (const col of ['email TEXT', 'pass_salt TEXT', 'auth_hash TEXT', 'key_ct TEXT']) {
    try { db.exec(`ALTER TABLE accounts ADD COLUMN ${col}`); } catch {}
  }
  db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_email ON accounts(email) WHERE email IS NOT NULL');
  // the question a session is currently blocked on, so a client connecting later still sees it
  try { db.exec('ALTER TABLE sessions ADD COLUMN note_ct TEXT'); } catch {}
  return db;
}
