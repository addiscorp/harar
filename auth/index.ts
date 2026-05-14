import { createHash, timingSafeEqual } from 'node:crypto';
import fs from 'fs/promises';
import type { PeerCredentials, Principal, TokenRecord } from '../types.js';
import { PLATFORM_NAMESPACE_PREFIX } from '../types.js';

export interface AuthContext {
  principal: Principal;
  tokenHash: string;
}

export class VaultAuth {
  private constructor(private readonly records: TokenRecord[]) {
    validateTokenRecords(records);
  }

  static async fromFile(path: string): Promise<VaultAuth> {
    const parsed = JSON.parse(await fs.readFile(path, 'utf8'));
    return new VaultAuth(Array.isArray(parsed) ? parsed : parsed.tokens ?? []);
  }

  static fromRecords(records: TokenRecord[]): VaultAuth {
    return new VaultAuth(records);
  }

  authenticate(request: Request, peerCredentials?: PeerCredentials): AuthContext {
    const token = bearerToken(request);
    if (!token) throw authError('missing bearer token', 401);
    const tokenHash = hashToken(token);
    const record = this.records.find((candidate) => safeCompare(candidate.token_hash, tokenHash));
    if (!record) throw authError('invalid bearer token', 401);
    const keyType = record.key_type ?? 'service';
    if (keyType !== 'breakglass' && !peerCredentials) {
      throw authError('peer credentials unavailable', 403);
    }
    const peerUid = peerCredentials?.uid;
    if (keyType !== 'breakglass' && peerUid !== undefined && record.uid !== peerUid) {
      throw authError('peer uid does not match token principal', 403);
    }
    if (keyType !== 'breakglass' && record.gid !== undefined && peerCredentials?.gid !== record.gid) {
      throw authError('peer gid does not match token principal', 403);
    }
    return {
      tokenHash,
      principal: {
        name: record.principal,
        uid: record.uid,
        gid: record.gid,
        keyType,
        admin: record.admin === true,
        namespaces: record.namespaces,
      },
    };
  }
}

function validateTokenRecords(records: TokenRecord[]): void {
  for (const record of records) {
    const keyType = record.key_type ?? 'service';
    if (keyType !== 'service' && keyType !== 'breakglass') {
      throw new Error(`unsupported token key_type for ${record.principal}`);
    }
    if (keyType !== 'breakglass' && record.uid === undefined) {
      throw new Error(`non-breakglass token ${record.principal} must declare uid`);
    }
  }
}

export function requirePlatformNamespace(namespace: string): void {
  if (!namespace.startsWith(PLATFORM_NAMESPACE_PREFIX)) {
    throw authError('only platform/* namespaces are enabled in vault v1', 403);
  }
}

export function requireNamespaceAccess(principal: Principal, namespace: string): void {
  requirePlatformNamespace(namespace);
  if (principal.admin) return;
  if (!principal.namespaces.some((allowed) => namespaceMatches(namespace, allowed))) {
    throw authError('principal is not allowed to access namespace', 403);
  }
}

export function requireAdmin(principal: Principal): void {
  if (!principal.admin) throw authError('admin principal required', 403);
}

export function assertPathPrincipalMatch(principal: Principal, namespace: string): void {
  if (principal.admin) return;
  if (!principal.namespaces.some((allowed) => namespaceMatches(namespace, allowed))) {
    throw authError('path namespace does not match authenticated principal', 403);
  }
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export function authError(message: string, status: number): Error & { status: number } {
  const error = new Error(message) as Error & { status: number };
  error.status = status;
  return error;
}

function bearerToken(request: Request): string | null {
  const auth = request.headers.get('authorization');
  const prefix = 'Bearer ';
  return auth?.startsWith(prefix) ? auth.slice(prefix.length) : null;
}

function namespaceMatches(namespace: string, allowed: string): boolean {
  if (allowed.endsWith('*')) return namespace.startsWith(allowed.slice(0, -1));
  return namespace === allowed;
}

function safeCompare(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}
