import { describe, expect, test } from 'bun:test';
import fs from 'fs/promises';
import jwt from 'jsonwebtoken';
import os from 'os';
import path from 'path';
import { VaultAcl } from '../acl/index.js';
import { VaultAuditLog } from '../audit/index.js';
import { hashToken, VaultAuth } from '../auth/index.js';
import { VaultJwtVerifier } from '../auth/jwt.js';
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

    await expectJson(source, 'POST', '/secret/platform/deka/API_KEY', 'admin-token', { value: 'secret-value' }, 200, adminPeer);
    const listed = await expectJson(source, 'GET', '/secret/platform/deka', 'svc-token', undefined, 200, svcPeer);
    expect(listed.keys[0]).toMatchObject({ key: 'API_KEY', version: 1 });

    const read = await expectJson(source, 'GET', '/secret/platform/deka/API_KEY', 'svc-token', undefined, 200, svcPeer);
    expect(read).toEqual({ value: 'secret-value', version: 1 });

    await expectJson(source, 'POST', '/recipient', 'admin-token', { id: 'peer-bugsy', type: 'peer', public_key: 'age1bugsy' }, 200, adminPeer);
    const rotated = await expectJson(source, 'POST', '/recipient/rotate', 'admin-token', undefined, 200, adminPeer);
    expect(rotated.recipients.length).toBeGreaterThanOrEqual(2);

    const bundle = await expectJson(source, 'GET', '/replicate/pull', 'admin-token', undefined, 200, adminPeer);
    await expectJson(peer, 'POST', '/replicate/push', 'admin-token', bundle, 200, adminPeer);
    const nextBundle = await expectJson(source, 'GET', '/replicate/pull', 'admin-token', undefined, 200, adminPeer);
    expect(nextBundle.manifest.manifest.version).toBe(bundle.manifest.manifest.version + 1);
    expect(nextBundle.manifest.manifest.prev_manifest_hash).toBe(manifestHeadHash(bundle.manifest));
    await expectJson(peer, 'POST', '/replicate/push', 'admin-token', nextBundle, 200, adminPeer);
    const replicaRows = JSON.parse(await fs.readFile(path.join(peer.config.dataDir, 'replicas', 'phobos', 'secrets.rows.json'), 'utf8'));
    expect(replicaRows[0].ciphertext).toBeString();
    expect(JSON.stringify(replicaRows)).not.toContain('secret-value');
  });

  test('uid-bound bearer rejects mismatched or missing peer credentials', async () => {
    const api = await deps('phobos');

    await expectJson(api, 'GET', '/secret/platform/deka', 'uid-token', undefined, 403, { uid: 502, gid: 20, pid: 123 });
    await expectJson(api, 'GET', '/secret/platform/deka', 'uid-token', undefined, 403);
  });

  test('breakglass token is explicit and audited when peer credentials are unavailable', async () => {
    const api = await deps('phobos');
    await expectJson(api, 'GET', '/audit', 'breakglass-token', undefined, 200);
    expect(api.audit.query().some((row) => row.principal === 'breakglass:root' && row.op === 'breakglass_auth')).toBe(true);
  });

  test('valid HS256 JWT can read /v1/secret from the mapped workload namespace', async () => {
    const api = await deps('phobos');
    api.db.write('platform/deka', 'API_KEY', 'secret-value');

    const body = await expectJwtJson(api, jwtFor(api, {}), 200);

    expect(body).toEqual({ value: 'secret-value', version: 1 });
    expect(api.audit.query().some((row) => row.principal === 'vault-agent@phobos:deka-platform' && row.op === 'jwt_read')).toBe(true);
  });

  test('HS256 JWT with wrong signature is rejected', async () => {
    const api = await deps('phobos');
    api.db.write('platform/deka', 'API_KEY', 'secret-value');

    await expectJwtJson(api, jwtFor(api, {}, 'wrong-secret'), 401);
    expectVerifyFailAudit(api, {
      reason: 'JWT verification failed: invalid signature',
      iss: 'vault-agent@phobos',
      sub: 'deka-platform',
      aud: 'vault.tana.gg',
    });
  });

  test('expired HS256 JWT is rejected', async () => {
    const api = await deps('phobos');

    await expectJwtJson(api, jwtFor(api, { exp: 1 }), 401);
    expectVerifyFailAudit(api, {
      reason: 'JWT verification failed: jwt expired',
      iss: 'vault-agent@phobos',
      sub: 'deka-platform',
      aud: 'vault.tana.gg',
    });
  });

  test('HS256 JWT with wrong audience is rejected', async () => {
    const api = await deps('phobos');

    await expectJwtJson(api, jwtFor(api, { aud: 'not-vault.tana.gg' }), 401);
    expectVerifyFailAudit(api, {
      reason: 'JWT verification failed: jwt audience invalid. expected: vault.tana.gg',
      iss: 'vault-agent@phobos',
      sub: 'deka-platform',
      aud: 'not-vault.tana.gg',
    });
  });

  test('HS256 JWT with unknown issuer is rejected', async () => {
    const api = await deps('phobos');

    await expectJwtJson(api, jwtFor(api, { iss: 'vault-agent@unknown' }), 401);
    expectVerifyFailAudit(api, {
      reason: 'unknown JWT issuer',
      iss: 'vault-agent@unknown',
      sub: 'deka-platform',
      aud: 'vault.tana.gg',
    });
  });
});

async function deps(machineId: string, phobosSigPub?: string): Promise<VaultApiDeps> {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), `vault-${machineId}-`));
  const devKeyPath = path.join(dataDir, 'dev-key');
  await fs.writeFile(devKeyPath, 'dev-secret');
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
      jwt: {
        audience: 'vault.tana.gg',
        devKeyPath,
        agents: [{ issuer: 'vault-agent@phobos', provider: 'hs256-dev' }],
        workloads: [{ subject: 'deka-platform', namespace: 'platform/deka' }],
      },
    },
    auth: VaultAuth.fromRecords([
      { principal: 'admin', token_hash: hashToken('admin-token'), uid: 500, admin: true, namespaces: ['platform/*'] },
      { principal: 'svc:deka', token_hash: hashToken('svc-token'), uid: 501, namespaces: ['platform/deka'] },
      { principal: 'svc:uid', token_hash: hashToken('uid-token'), uid: 501, namespaces: ['platform/deka'] },
      { principal: 'breakglass:root', token_hash: hashToken('breakglass-token'), key_type: 'breakglass', admin: true, namespaces: ['platform/*'] },
    ]),
    jwtVerifier: VaultJwtVerifier.fromConfig({
      dataDir,
      socketPath: path.join(dataDir, 'sock'),
      tokensPath: path.join(dataDir, 'tokens.json'),
      machineId,
      minRecipients: 2,
      peers: [],
      jwt: {
        audience: 'vault.tana.gg',
        devKeyPath,
        agents: [{ issuer: 'vault-agent@phobos', provider: 'hs256-dev' }],
        workloads: [{ subject: 'deka-platform', namespace: 'platform/deka' }],
      },
    }),
    acl: new VaultAcl(),
    db: VaultDatabase.openInMemory(generateDbKey()),
    audit: VaultAuditLog.openInMemory(),
    recipients,
    rotateRecipients: async () => recipients.rotate(),
    replicas: new ReplicaStore(dataDir, phobosSigPub ? [{ id: 'phobos', url: 'unix://phobos', ageRecipient: 'age1phobos', signaturePublicKey: phobosSigPub }] : []),
    signingKeys: await loadOrCreateSigningKeys(dataDir),
  };
}

const adminPeer = { uid: 500, gid: 20, pid: 123 };
const svcPeer = { uid: 501, gid: 20, pid: 123 };

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

async function expectJwtJson(deps: VaultApiDeps, token: string, status: number): Promise<any> {
  const response = await handleVaultRequest(new Request('http://vault/v1/secret/API_KEY', {
    method: 'GET',
    headers: { authorization: `Bearer ${token}` },
  }), deps);
  expect(response.status).toBe(status);
  return response.json();
}

function expectVerifyFailAudit(deps: VaultApiDeps, expected: { reason: string; iss: string; sub: string; aud: string }): void {
  const rows = deps.audit.query();
  const matching = rows.find((row) => {
    if (row.op !== 'verify_fail' || row.tag !== expected.reason) return false;
    const details = JSON.parse(row.details);
    return details.kind === 'verify_fail'
      && details.reason === expected.reason
      && details.iss === expected.iss
      && details.sub === expected.sub
      && details.aud === expected.aud;
  });
  expect(matching).toBeTruthy();
}

function jwtFor(deps: VaultApiDeps, overrides: Record<string, unknown>, secret = 'dev-secret'): string {
  const now = Math.floor(Date.now() / 1000);
  return jwt.sign({
    iss: 'vault-agent@phobos',
    sub: 'deka-platform',
    aud: deps.config.jwt.audience,
    scope: 'vault:read:platform/deka/*',
    iat: now,
    exp: now + 60,
    ...overrides,
  }, secret, { algorithm: 'HS256' });
}
