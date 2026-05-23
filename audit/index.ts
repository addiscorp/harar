import { createHash } from 'node:crypto';
import { Database } from 'bun:sqlite';
import fs from 'fs/promises';
import path from 'path';
import type { VaultAuditEvent } from '../types.js';

export class VaultAuditLog {
  private constructor(private readonly db: Database) {
    this.migrate();
  }

  static async open(dbPath: string): Promise<VaultAuditLog> {
    await fs.mkdir(path.dirname(dbPath), { recursive: true, mode: 0o700 });
    return new VaultAuditLog(new Database(dbPath));
  }

  static openInMemory(): VaultAuditLog {
    return new VaultAuditLog(new Database(':memory:'));
  }

  close(): void {
    this.db.close();
  }

  append(event: VaultAuditEvent): { seq: number; row_hash: string } {
    const previous = this.head();
    const seq = (previous?.seq ?? 0) + 1;
    const createdAt = new Date().toISOString();
    const details = event.details ? JSON.stringify(event.details) : '';
    const hashInput: Record<string, unknown> = {
      seq,
      created_at: createdAt,
      principal: event.principal,
      op: event.op,
      namespace: event.namespace ?? '',
      key: event.key ?? '',
      tag: event.tag ?? '',
      prev_hash: previous?.row_hash ?? '',
    };
    if (details) hashInput.details = details;
    const rowHash = auditHash(hashInput);
    this.db.query(`
      INSERT INTO audit_events (seq, created_at, principal, op, namespace, key, tag, details, prev_hash, row_hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(seq, createdAt, event.principal, event.op, event.namespace ?? null, event.key ?? null, event.tag ?? null, details || null, previous?.row_hash ?? null, rowHash);
    return { seq, row_hash: rowHash };
  }

  query(limit = 100, offset = 0): any[] {
    return this.db.query('SELECT * FROM audit_events ORDER BY seq DESC LIMIT ? OFFSET ?').all(limit, offset) as any[];
  }

  head(): { seq: number; row_hash: string } | null {
    return this.db.query('SELECT seq, row_hash FROM audit_events ORDER BY seq DESC LIMIT 1').get() as { seq: number; row_hash: string } | null;
  }

  verifyChain(): boolean {
    const rows = this.db.query('SELECT * FROM audit_events ORDER BY seq ASC').all() as any[];
    let prev = '';
    for (const row of rows) {
      const hashInput: Record<string, unknown> = {
        seq: row.seq,
        created_at: row.created_at,
        principal: row.principal,
        op: row.op,
        namespace: row.namespace ?? '',
        key: row.key ?? '',
        tag: row.tag ?? '',
        prev_hash: prev,
      };
      if (row.details) hashInput.details = row.details;
      const expected = auditHash(hashInput);
      if (expected !== row.row_hash || (row.prev_hash ?? '') !== prev) return false;
      prev = row.row_hash;
    }
    return true;
  }

  private migrate(): void {
    this.db.run(`
      CREATE TABLE IF NOT EXISTS audit_events (
        seq INTEGER PRIMARY KEY,
        created_at TEXT NOT NULL,
        principal TEXT NOT NULL,
        op TEXT NOT NULL,
        namespace TEXT,
        key TEXT,
        tag TEXT,
        details TEXT,
        prev_hash TEXT,
        row_hash TEXT NOT NULL
      )
    `);
    const columns = this.db.query('PRAGMA table_info(audit_events)').all() as Array<{ name: string }>;
    if (!columns.some((column) => column.name === 'details')) {
      this.db.run('ALTER TABLE audit_events ADD COLUMN details TEXT');
    }
  }
}

export async function anchorAuditHead(url: string | undefined, head: { seq: number; row_hash: string } | null): Promise<'skipped' | 'anchored'> {
  if (!url || !head) return 'skipped';
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ source: 'gild-vault', seq: head.seq, row_hash: head.row_hash }),
  });
  if (response.status === 404 || response.status === 501) return 'skipped';
  if (!response.ok) throw new Error(`audit anchor failed: ${response.status}`);
  return 'anchored';
}

function auditHash(row: Record<string, unknown>): string {
  return createHash('sha256').update(JSON.stringify(row)).digest('hex');
}
