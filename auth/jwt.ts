import fs from 'fs/promises';
import jwt from 'jsonwebtoken';
import type { VaultConfig, VaultJwtAgent } from '../types.js';

const DEFAULT_AUDIENCE = 'vault.tana.gg';

export interface JwtAuthContext {
  issuer: string;
  subject: string;
  namespace: string;
  scope: string;
}

interface VaultJwtClaims extends jwt.JwtPayload {
  iss: string;
  sub: string;
  aud: string | string[];
  scope?: string;
}

export class VaultJwtVerifier {
  private readonly publicKeyCache = new Map<string, Promise<string>>();

  constructor(private readonly config: VaultConfig['jwt']) {}

  static fromConfig(config: VaultConfig): VaultJwtVerifier {
    return new VaultJwtVerifier(config.jwt);
  }

  async verify(request: Request): Promise<JwtAuthContext> {
    const token = bearerToken(request);
    if (!token) throw jwtAuthError('missing bearer token');

    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || typeof decoded === 'string') throw jwtAuthError('malformed JWT');
    const unverified = decoded.payload as jwt.JwtPayload;
    const issuer = stringClaim(unverified.iss);
    if (!issuer) throw jwtAuthError('JWT missing issuer');

    const agent = this.config.agents.find((candidate) => candidate.issuer === issuer);
    if (!agent) throw jwtAuthError('unknown JWT issuer');

    const algorithm = decoded.header.alg;
    const key = await this.keyForAgent(agent, algorithm);
    let payload: VaultJwtClaims;
    try {
      payload = jwt.verify(token, key, {
        algorithms: [algorithmForProvider(agent.provider)],
        audience: this.config.audience,
        issuer: agent.issuer,
      }) as VaultJwtClaims;
    } catch (error: any) {
      throw jwtAuthError(`JWT verification failed: ${error?.message ?? String(error)}`);
    }

    const subject = stringClaim(payload.sub);
    if (!subject) throw jwtAuthError('JWT missing subject');
    const workload = this.config.workloads.find((candidate) => candidate.subject === subject);
    if (!workload) throw jwtAuthError('unknown JWT subject');

    const scope = stringClaim(payload.scope);
    const requiredScope = `vault:read:${workload.namespace}/*`;
    if (!scope?.split(/\s+/).includes(requiredScope)) {
      throw jwtAuthError('JWT scope does not allow workload namespace');
    }

    return {
      issuer: payload.iss,
      subject,
      namespace: workload.namespace,
      scope,
    };
  }

  private async keyForAgent(agent: VaultJwtAgent, headerAlgorithm?: string): Promise<string | Buffer> {
    const expected = algorithmForProvider(agent.provider);
    if (headerAlgorithm !== expected) {
      throw jwtAuthError(`JWT algorithm mismatch: expected ${expected}`);
    }

    if (agent.provider === 'hs256-dev') {
      return fs.readFile(agent.devKeyPath ?? this.config.devKeyPath);
    }

    if (agent.publicKeyPem) return agent.publicKeyPem;
    if (agent.publicKeyUrl) return this.fetchPublicKey(agent.publicKeyUrl);
    throw jwtAuthError(`TPM JWT issuer ${agent.issuer} has no public key configured`);
  }

  private fetchPublicKey(url: string): Promise<string> {
    const cached = this.publicKeyCache.get(url);
    if (cached) return cached;
    const loaded = fetch(url).then(async (response) => {
      if (!response.ok) throw jwtAuthError(`TPM public key fetch failed with HTTP ${response.status}`);
      return response.text();
    });
    this.publicKeyCache.set(url, loaded);
    return loaded;
  }
}

export function jwtAuthError(message: string): Error & { status: number } {
  const error = new Error(message) as Error & { status: number };
  error.status = 401;
  return error;
}

function bearerToken(request: Request): string | null {
  const auth = request.headers.get('authorization');
  const prefix = 'Bearer ';
  return auth?.startsWith(prefix) ? auth.slice(prefix.length) : null;
}

function algorithmForProvider(provider: VaultJwtAgent['provider']): 'HS256' | 'RS256' {
  return provider === 'hs256-dev' ? 'HS256' : 'RS256';
}

function stringClaim(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

export function defaultVaultJwtConfig(): VaultConfig['jwt'] {
  return {
    audience: DEFAULT_AUDIENCE,
    devKeyPath: '/etc/tana-vault-agent/dev-key',
    agents: [],
    workloads: [],
  };
}
