import { describe, expect, test } from 'bun:test';
import fs from 'fs/promises';
import os from 'os';
import path from 'path';
import { VaultAcl } from '../acl/index.js';
import { VaultAuditLog } from '../audit/index.js';
import { hashToken, VaultAuth } from '../auth/index.js';
import { generateDbKey } from '../crypto/aead.js';
import { loadOrCreateSigningKeys } from '../crypto/signing.js';
import { VaultDatabase } from '../db/index.js';
import { handleVaultRequest, type VaultApiDeps } from './index.js';
import { manifestHeadHash } from '../manifest/index.js';
import { RecipientStore } from '../recipients/index.js';
import { ReplicaStore } from '../replication/index.js';
import type { PeerCredentials } from '../types.js';

describe('vault API lifecycle', () => {
  test('write -> list -> read -> rotate -> recipient-add -> replicate-to-peer', async () => {
    const source = await deps('phobos');
    const peer = await deps('bugsy', source.signingKeys.publicKeyPem);

    await expectJson(source, 'POST', '/secret/platform/deka/API_KEY', 'admin-token', { value: 'secret-value' }, 200);
    const listed = await expectJson(source, 'GET', '/secret/platform/deka', 'svc-token', undefined, 200);
    expect(listed.keys[0]).toMatchObject({ key: 'API_KEY', version: 1 });

    const read = await expectJson(source, 'GET', '/secret/platform/deka/API_KEY', 'svc-token', undefined, 200);
    expect(read).toEqual({ value: 'secret-value', version: 1 });

    await expectJson(source, 'POST', '/recipient', 'admin-token', { id: 'peer-bugsy', type: 'peer', public_key: 'age1bugsy' }, 200);
    const rotated = await expectJson(source, 'POST', '/recipient/rotate', 'admin-token', undefined, 200);
    expect(rotated.recipients.length).toBeGreaterThanOrEqual(2);

    const bundle = await expectJson(source, 'GET', '/replicate/pull', 'admin-token', undefined, 200);
    await expectJson(peer, 'POST', '/replicate/push', 'admin-token', bundle, 200);
    const nextBundle = await expectJson(source, 'GET', '/replicate/pull', 'admin-token', undefined, 200);
    expect(nextBundle.manifest.manifest.version).toBe(bundle.manifest.manifest.version + 1);
    expect(nextBundle.manifest.manifest.prev_manifest_hash).toBe(manifestHeadHash(bundle.manifest));
    await expectJson(peer, 'POST', '/replicate/push', 'admin-token', nextBundle, 200);
    const replicaRows = JSON.parse(await fs.readFile(path.join(peer.config.dataDir, 'replicas', 'phobos', 'secrets.rows.json'), 'utf8'));
    expect(replicaRows[0].ciphertext).toBeString();
    expect(JSON.stringify(replicaRows)).not.toContain('secret-value');
  });

  test('uid-bound bearer rejects mismatched or missing peer credentials', async () => {
    const api = await deps('phobos');

    await expectJson(api, 'GET', '/secret/platform/deka', 'uid-token', undefined, 403, { uid: 502, gid: 20, pid: 123 });
    await expectJson(api, 'GET', '/secret/platform/deka', 'uid-token', undefined, 403);
  });
});

async function deps(machineId: string, phobosSigPub?: string): Promise<VaultApiDeps> {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), `vault-${machineId}-`));
  const recipients = new RecipientStore(path.join(dataDir, 'recipients', 'recipients.json'), 2);
  await recipients.add({ id: 'self-sep', type: 'sep', public_key: `age1${machineId}` });
  await recipients.add({ id: 'recovery', type: 'passphrase', public_key: 'recovery.age' });
  return {
    config: {
      dataDir,
      socketPath: path.join(dataDir, 'sock'),
      tokensPath: path.join(dataDir, 'tokens.json'),
      machineId,
      minRecipients: 2,
      peers: phobosSigPub ? [{ id: 'phobos', url: 'unix://phobos', ageRecipient: 'age1phobos', signaturePublicKey: phobosSigPub }] : [],
    },
    auth: VaultAuth.fromRecords([
      { principal: 'admin', token_hash: hashToken('admin-token'), admin: true, namespaces: ['platform/*'] },
      { principal: 'svc:deka', token_hash: hashToken('svc-token'), namespaces: ['platform/deka'] },
      { principal: 'svc:uid', token_hash: hashToken('uid-token'), uid: 501, namespaces: ['platform/deka'] },
    ]),
    acl: new VaultAcl(),
    db: VaultDatabase.openInMemory(generateDbKey()),
    audit: VaultAuditLog.openInMemory(),
    recipients,
    replicas: new ReplicaStore(dataDir, phobosSigPub ? [{ id: 'phobos', url: 'unix://phobos', ageRecipient: 'age1phobos', signaturePublicKey: phobosSigPub }] : []),
    signingKeys: await loadOrCreateSigningKeys(dataDir),
  };
}

async function expectJson(
  deps: VaultApiDeps,
  method: string,
  pathname: string,
  token: string,
  body: unknown,
  status: number,
  peerCredentials?: PeerCredentials
): Promise<any> {
  const response = await handleVaultRequest(new Request(`http://vault${pathname}`, {
    method,
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  }), deps, peerCredentials);
  expect(response.status).toBe(status);
  return response.json();
}
