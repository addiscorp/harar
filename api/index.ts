import path from 'path';
import jwt from 'jsonwebtoken';
import { VaultAcl } from '../acl/index.js';
import { anchorAuditHead, VaultAuditLog } from '../audit/index.js';
import { assertPathPrincipalMatch, requireAdmin, requireNamespaceAccess, VaultAuth } from '../auth/index.js';
import { VaultJwtVerifier } from '../auth/jwt.js';
import type { SigningKeys } from '../crypto/signing.js';
import type { VaultDatabase } from '../db/index.js';
import { buildSignedManifest } from '../manifest/index.js';
import { manifestHeadHash } from '../manifest/index.js';
import { RecipientStore } from '../recipients/index.js';
import { ReplicaStore } from '../replication/index.js';
import type { PeerCredentials, ReplicaBundle, VaultConfig } from '../types.js';

export interface VaultApiDeps {
  config: VaultConfig;
  auth: VaultAuth;
  jwtVerifier: VaultJwtVerifier;
  acl: VaultAcl;
  db: VaultDatabase;
  audit: VaultAuditLog;
  recipients: RecipientStore;
  rotateRecipients: (options?: { force?: boolean }) => Promise<unknown[]>;
  replicas: ReplicaStore;
  signingKeys: SigningKeys;
}

export async function handleVaultRequest(request: Request, deps: VaultApiDeps, peerCredentials?: PeerCredentials): Promise<Response> {
  const url = new URL(request.url);
  try {
    if (request.method === 'GET' && url.pathname === '/health') return json({ ok: true, machine_id: deps.config.machineId });

    const jwtSecretMatch = url.pathname.match(/^\/v1\/secret\/([^/]+)$/);
    if (jwtSecretMatch) {
      if (request.method !== 'GET') return json({ error: 'method_not_allowed' }, 405);
      const key = decodeURIComponent(jwtSecretMatch[1]);
      const auth = await deps.jwtVerifier.verify(request).catch((error: any) => {
        recordJwtVerifyFailure(deps.audit, request, error);
        throw error;
      });
      const secret = deps.db.read(auth.namespace, key);
      deps.audit.append({ principal: `${auth.issuer}:${auth.subject}`, op: secret ? 'jwt_read' : 'jwt_read_missing', namespace: auth.namespace, key });
      if (!secret) return json({ error: 'not_found' }, 404);
      return json({ value: secret.value, version: secret.version });
    }

    const auth = deps.auth.authenticate(request, peerCredentials);
    if (auth.principal.keyType === 'breakglass') {
      deps.audit.append({ principal: auth.principal.name, op: 'breakglass_auth' });
    }
    const secretMatch = url.pathname.match(/^\/secret\/([^/]+\/[^/]+)(?:\/([^/]+))?$/);
    if (secretMatch) {
      const namespace = decodeURIComponent(secretMatch[1]);
      const key = secretMatch[2] ? decodeURIComponent(secretMatch[2]) : undefined;
      assertPathPrincipalMatch(auth.principal, namespace);

      if (request.method === 'GET' && key) {
        requireNamespaceAccess(auth.principal, namespace);
        if (!await deps.acl.canRead(auth.principal, namespace)) return json({ error: 'forbidden' }, 403);
        const secret = deps.db.read(namespace, key);
        deps.audit.append({ principal: auth.principal.name, op: secret ? 'read' : 'read_missing', namespace, key });
        if (!secret) return json({ error: 'not_found' }, 404);
        return json({ value: secret.value, version: secret.version });
      }

      if (request.method === 'POST' && key) {
        requireAdmin(auth.principal);
        const body = await request.json();
        const result = deps.db.write(namespace, key, String(body.value ?? ''));
        deps.audit.append({ principal: auth.principal.name, op: 'write', namespace, key, tag: result.tag });
        return json({ ok: true, version: result.version });
      }

      if (request.method === 'GET' && !key) {
        requireNamespaceAccess(auth.principal, namespace);
        deps.audit.append({ principal: auth.principal.name, op: 'list', namespace });
        return json({ keys: deps.db.list(namespace), namespace_version: deps.db.namespaceVersion(namespace) });
      }
    }

    if (url.pathname === '/recipient' && request.method === 'POST') {
      requireAdmin(auth.principal);
      const recipient = await deps.recipients.add(await request.json());
      deps.audit.append({ principal: auth.principal.name, op: 'recipient_add', key: recipient.id });
      return json({ recipient });
    }
    if (url.pathname === '/recipient' && request.method === 'GET') {
      requireAdmin(auth.principal);
      return json({ recipients: await deps.recipients.list() });
    }
    const recipientRemove = url.pathname.match(/^\/recipient\/([^/]+)$/);
    if (recipientRemove && request.method === 'DELETE') {
      requireAdmin(auth.principal);
      await deps.recipients.remove(decodeURIComponent(recipientRemove[1]), url.searchParams.get('break_glass') === '1');
      deps.audit.append({ principal: auth.principal.name, op: 'recipient_remove', key: decodeURIComponent(recipientRemove[1]) });
      return json({ ok: true });
    }
    if (url.pathname === '/recipient/rotate' && request.method === 'POST') {
      requireAdmin(auth.principal);
      const body = request.headers.get('content-length') === '0' ? undefined : await optionalJson(request);
      const recipients = await deps.rotateRecipients({ force: body?.force === true });
      deps.audit.append({ principal: auth.principal.name, op: 'recipient_rotate' });
      return json({ recipients });
    }
    if (url.pathname === '/audit' && request.method === 'GET') {
      requireAdmin(auth.principal);
      return json({ rows: deps.audit.query(Number(url.searchParams.get('limit') ?? 100), Number(url.searchParams.get('offset') ?? 0)) });
    }
    if (url.pathname === '/audit/anchor' && request.method === 'POST') {
      requireAdmin(auth.principal);
      return json({ status: await anchorAuditHead(deps.config.auditAnchorUrl, deps.audit.head()) });
    }
    if (url.pathname === '/replicate/pull' && request.method === 'GET') {
      requireAdmin(auth.principal);
      const rows = deps.db.rows();
      const state = deps.db.manifestState(deps.config.machineId);
      const manifest = buildSignedManifest({
        machineId: deps.config.machineId,
        rows,
        recipients: await deps.recipients.list(),
        version: state.seq + 1,
        prevManifestHash: state.head_hash,
        privateKeyPem: deps.signingKeys.privateKeyPem,
        publicKeyPem: deps.signingKeys.publicKeyPem,
      });
      deps.db.updateManifestState(deps.config.machineId, manifest.manifest.version, manifestHeadHash(manifest));
      return json({ source_machine_id: deps.config.machineId, manifest, rows });
    }
    if (url.pathname === '/replicate/push' && request.method === 'POST') {
      requireAdmin(auth.principal);
      await deps.replicas.apply(await request.json() as ReplicaBundle);
      deps.audit.append({ principal: auth.principal.name, op: 'replica_apply' });
      return json({ ok: true });
    }
    return json({ error: 'not_found' }, 404);
  } catch (error: any) {
    const status = error?.status ?? 500;
    if (status === 401) {
      console.warn(`vault auth failure: ${error?.message ?? String(error)}`);
    }
    return json({ error: status === 500 ? 'internal_error' : 'request_error', message: error?.message ?? String(error) }, status);
  }
}

function recordJwtVerifyFailure(audit: VaultAuditLog, request: Request, error: any): void {
  const reason = error?.message ?? String(error);
  const claims = unverifiedJwtClaims(request);
  recordAuditEntry(audit, {
    kind: 'verify_fail',
    reason,
    iss: claims.iss,
    sub: claims.sub,
    aud: claims.aud,
    alg: claims.alg,
  });
}

function recordAuditEntry(audit: VaultAuditLog, entry: {
  kind: 'verify_fail';
  reason: string;
  iss?: unknown;
  sub?: unknown;
  aud?: unknown;
  alg?: unknown;
}): void {
  const issuer = typeof entry.iss === 'string' && entry.iss.length > 0 ? entry.iss : 'unknown';
  const subject = typeof entry.sub === 'string' && entry.sub.length > 0 ? entry.sub : 'unknown';
  audit.append({
    principal: `${issuer}:${subject}`,
    op: entry.kind,
    tag: entry.reason,
    details: entry,
  });
}

function unverifiedJwtClaims(request: Request): { iss?: unknown; sub?: unknown; aud?: unknown; alg?: unknown } {
  const token = bearerToken(request);
  if (!token) return {};
  const decoded = jwt.decode(token, { complete: true });
  if (!decoded || typeof decoded === 'string') return {};
  const payload = decoded.payload && typeof decoded.payload === 'object' ? decoded.payload as jwt.JwtPayload : {};
  return {
    iss: payload.iss,
    sub: payload.sub,
    aud: payload.aud,
    alg: decoded.header?.alg,
  };
}

function bearerToken(request: Request): string | null {
  const auth = request.headers.get('authorization');
  const prefix = 'Bearer ';
  return auth?.startsWith(prefix) ? auth.slice(prefix.length) : null;
}

async function optionalJson(request: Request): Promise<any | undefined> {
  try {
    return await request.json();
  } catch {
    return undefined;
  }
}

export function vaultPaths(dataDir: string): { secretsDb: string; auditDb: string; recipientsJson: string } {
  return {
    secretsDb: path.join(dataDir, 'secrets.db'),
    auditDb: path.join(dataDir, 'audit.db'),
    recipientsJson: path.join(dataDir, 'recipients', 'recipients.json'),
  };
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
}
