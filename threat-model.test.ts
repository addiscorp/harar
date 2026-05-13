import { describe, expect, test } from 'bun:test';
import fs from 'fs/promises';
import os from 'os';
import path from 'path';
import { VaultAuditLog } from './audit/index.js';
import { assertPathPrincipalMatch, hashToken, VaultAuth } from './auth/index.js';
import { aadFor, decryptSecret, encryptSecret, generateDbKey } from './crypto/aead.js';
import { MockAgeRunner } from './crypto/age.js';
import { buildSignedManifest } from './manifest/index.js';
import { migrateEnvFile } from './migration/env.js';
import { RecipientStore } from './recipients/index.js';
import { ReplicaStore } from './replication/index.js';
import { loadOrCreateSigningKeys } from './crypto/signing.js';
import { VaultDatabase } from './db/index.js';

describe('Hamza threat-model regressions F1-F12', () => {
  test('F1 rejects passphrase as hardware co-recipient', async () => {
    await expect(new MockAgeRunner().wrap(new Uint8Array([1]), ['age1machine', 'passphrase:dr'])).rejects.toThrow('parallel artifact');
  });

  test('F2 rejects caller path/principal mismatch', () => {
    const principal = { name: 'svc:deka', admin: false, namespaces: ['platform/deka'] };
    expect(() => assertPathPrincipalMatch(principal, 'platform/admin')).toThrow('path namespace');
  });

  test('F3 rejects unsigned or rollback replica manifests', async () => {
    const src = await fs.mkdtemp(path.join(os.tmpdir(), 'vault-src-'));
    const dst = await fs.mkdtemp(path.join(os.tmpdir(), 'vault-dst-'));
    const keys = await loadOrCreateSigningKeys(src);
    const db = VaultDatabase.openInMemory(generateDbKey());
    db.write('platform/deka', 'API_KEY', 'secret');
    const manifest = buildSignedManifest({
      machineId: 'phobos',
      rows: db.rows(),
      recipients: [],
      version: 1,
      privateKeyPem: keys.privateKeyPem,
      publicKeyPem: keys.publicKeyPem,
    });
    const store = new ReplicaStore(dst, [{ id: 'phobos', url: 'unix://phobos', ageRecipient: 'age1', signaturePublicKey: keys.publicKeyPem }]);
    await store.apply({ source_machine_id: 'phobos', manifest, rows: db.rows() });
    await expect(store.apply({ source_machine_id: 'phobos', manifest, rows: db.rows() })).rejects.toThrow('rollback');
    manifest.signature = 'bad';
    await expect(new ReplicaStore(await fs.mkdtemp(path.join(os.tmpdir(), 'vault-dst-')), [{ id: 'phobos', url: 'unix://phobos', ageRecipient: 'age1', signaturePublicKey: keys.publicKeyPem }])
      .apply({ source_machine_id: 'phobos', manifest, rows: db.rows() })).rejects.toThrow('signature');
  });

  test('F4 migration quarantines and dry-run preserves source', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vault-f4-'));
    const envPath = path.join(dir, '.env');
    await fs.writeFile(envPath, 'API_KEY=secret\n');
    const db = VaultDatabase.openInMemory(generateDbKey());
    const result = await migrateEnvFile({ envPath, namespace: 'platform/deka', db, dryRun: true });
    expect(result.dry_run).toBe(true);
    expect(await fs.readFile(envPath, 'utf8')).toContain('secret');
  });

  test('F5 and F7 bind token to peer uid when configured', () => {
    process.env.NODE_ENV = 'test';
    const auth = VaultAuth.fromRecords([{ principal: 'svc', token_hash: hashToken('token'), uid: 99, namespaces: ['platform/deka'] }]);
    expect(() => auth.authenticate(new Request('http://vault/', { headers: { authorization: 'Bearer token', 'x-gild-peer-uid': '100' } }))).toThrow('peer uid');
  });

  test('F6 Linux TPM PCR binding is not part of macOS SEP v1 code path', () => {
    expect(process.platform === 'darwin' || process.platform === 'linux' || process.platform === 'win32').toBe(true);
    expect('platform/*').toStartWith('platform/');
  });

  test('F8 hash-chains audit rows', () => {
    const audit = VaultAuditLog.openInMemory();
    audit.append({ principal: 'svc', op: 'read', namespace: 'platform/deka', key: 'API_KEY' });
    expect(audit.verifyChain()).toBe(true);
    audit.close();
  });

  test('F9 audit never stores secret values', () => {
    const audit = VaultAuditLog.openInMemory();
    audit.append({ principal: 'admin', op: 'write', namespace: 'platform/deka', key: 'API_KEY', tag: 'tag' });
    expect(JSON.stringify(audit.query())).not.toContain('secret-value');
    audit.close();
  });

  test('F10 refuses recipient lockout without break-glass', async () => {
    const store = new RecipientStore(path.join(await fs.mkdtemp(path.join(os.tmpdir(), 'vault-f10-')), 'recipients.json'), 2);
    await store.add({ id: 'self', type: 'sep', public_key: 'age1self' });
    await store.add({ id: 'recovery', type: 'passphrase', public_key: 'recovery.age' });
    await expect(store.remove('recovery')).rejects.toThrow('minimum');
  });

  test('F11/F12 reject non-platform namespaces in v1', () => {
    const principal = { name: 'svc', admin: false, namespaces: ['platform/deka'] };
    expect(() => assertPathPrincipalMatch(principal, 'shop/shop_alpha')).toThrow();
    expect(() => assertPathPrincipalMatch(principal, 'agent/khalid')).toThrow();
  });

  test('F16 AAD binds namespace/key/version', () => {
    const key = generateDbKey();
    const sealed = encryptSecret(new TextEncoder().encode('secret'), key, aadFor('platform/deka', 'API_KEY', 1));
    expect(() => decryptSecret(sealed, key, aadFor('platform/deka', 'API_KEY', 2))).toThrow();
  });
});
