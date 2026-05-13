import { describe, expect, test } from 'bun:test';
import fs from 'fs/promises';
import os from 'os';
import path from 'path';
import { generateDbKey } from '../crypto/aead.js';
import { VaultDatabase } from '../db/index.js';
import { migrateEnvFile, parseEnv } from './env.js';

describe('vault env migration', () => {
  test('parses env files and dry-run does not quarantine', async () => {
    expect(parseEnv('A=1\nB=\"two\"\n# nope\n')).toEqual({ A: '1', B: 'two' });
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vault-env-'));
    const envPath = path.join(dir, '.env');
    await fs.writeFile(envPath, 'API_KEY=secret\n');
    const db = VaultDatabase.openInMemory(generateDbKey());

    const result = await migrateEnvFile({ envPath, namespace: 'platform/deka', db, dryRun: true });

    expect(result.imported[0].key).toBe('API_KEY');
    expect(await fs.readFile(envPath, 'utf8')).toContain('API_KEY');
    expect(db.read('platform/deka', 'API_KEY')).toBeNull();
    db.close();
  });

  test('imports, verifies read-back, and quarantines instead of deleting', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vault-env-'));
    const envPath = path.join(dir, '.env');
    await fs.writeFile(envPath, 'API_KEY=secret\n');
    const db = VaultDatabase.openInMemory(generateDbKey());

    const result = await migrateEnvFile({ envPath, namespace: 'platform/deka', db });

    expect(db.read('platform/deka', 'API_KEY')?.value).toBe('secret');
    expect(result.quarantined_path).toContain('.vault-quarantine');
    await expect(fs.stat(envPath)).rejects.toThrow();
    expect(await fs.readFile(result.quarantined_path!, 'utf8')).toContain('API_KEY');
    db.close();
  });
});
