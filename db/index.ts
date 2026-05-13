import { Database } from 'bun:sqlite';
import fs from 'fs/promises';
import path from 'path';
import { aadFor, decryptSecret, encryptSecret, tagDigest } from '../crypto/aead.js';
import type { SecretRow } from '../types.js';

export class VaultDatabase {
  private readonly db: Database;

  private constructor(db: Database, private readonly dbKey: Uint8Array) {
    this.db = db;
    this.migrate();
  }

  static async open(dbPath: string, dbKey: Uint8Array): Promise<VaultDatabase> {
    await fs.mkdir(path.dirname(dbPath), { recursive: true, mode: 0o700 });
    return new VaultDatabase(new Database(dbPath), dbKey);
  }

  static openInMemory(dbKey: Uint8Array): VaultDatabase {
    return new VaultDatabase(new Database(':memory:'), dbKey);
  }

  close(): void {
    this.db.close();
  }

  write(namespace: string, key: string, value: string): { namespace: string; key: string; value: string; version: number; tag: string } {
    const existing = this.getRow(namespace, key);
    const version = (existing?.version ?? 0) + 1;
    const now = new Date().toISOString();
    const encrypted = encryptSecret(new TextEncoder().encode(value), this.dbKey, aadFor(namespace, key, version));
    this.db.query(`
      INSERT INTO secrets (namespace, key, nonce, ciphertext, tag, version, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(namespace, key) DO UPDATE SET
        nonce = excluded.nonce,
        ciphertext = excluded.ciphertext,
        tag = excluded.tag,
        version = excluded.version,
        updated_at = excluded.updated_at
    `).run(namespace, key, encrypted.nonce, encrypted.ciphertext, encrypted.tag, version, existing?.created_at ?? now, now);
    return { namespace, key, value, version, tag: tagDigest(encrypted.tag) };
  }

  read(namespace: string, key: string): { namespace: string; key: string; value: string; version: number } | null {
    const row = this.getRow(namespace, key);
    if (!row) return null;
    return {
      namespace,
      key,
      value: new TextDecoder().decode(decryptSecret(row, this.dbKey, aadFor(namespace, key, row.version))),
      version: row.version,
    };
  }

  list(namespace: string): Array<{ key: string; version: number; updated_at: string }> {
    return this.db.query('SELECT key, version, updated_at FROM secrets WHERE namespace = ? ORDER BY key ASC').all(namespace) as any[];
  }

  rows(namespace?: string): SecretRow[] {
    return (namespace
      ? this.db.query('SELECT * FROM secrets WHERE namespace = ? ORDER BY namespace ASC, key ASC').all(namespace)
      : this.db.query('SELECT * FROM secrets ORDER BY namespace ASC, key ASC').all()) as SecretRow[];
  }

  getRow(namespace: string, key: string): SecretRow | null {
    return this.db.query('SELECT * FROM secrets WHERE namespace = ? AND key = ?').get(namespace, key) as SecretRow | null;
  }

  namespaceVersion(namespace: string): number {
    const row = this.db.query('SELECT COALESCE(MAX(version), 0) AS version FROM secrets WHERE namespace = ?').get(namespace) as any;
    return Number(row?.version ?? 0);
  }

  transaction<T>(fn: () => T): T {
    return this.db.transaction(fn)();
  }

  private migrate(): void {
    this.db.run(`
      CREATE TABLE IF NOT EXISTS secrets (
        namespace TEXT NOT NULL,
        key TEXT NOT NULL,
        nonce TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        tag TEXT NOT NULL,
        version INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (namespace, key)
      )
    `);
  }
}
