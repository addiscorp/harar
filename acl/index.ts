import type { Principal } from '../types.js';

interface CacheEntry {
  allowed: boolean;
  expiresAt: number;
}

export class VaultAcl {
  private readonly cache = new Map<string, CacheEntry>();

  constructor(private readonly ttlMs = 30_000) {}

  async canRead(principal: Principal, namespace: string): Promise<boolean> {
    if (principal.admin) return true;
    const cacheKey = `${principal.name}\n${namespace}`;
    const cached = this.cache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) return cached.allowed;
    const allowed = principal.namespaces.some((candidate) => candidate.endsWith('*') ? namespace.startsWith(candidate.slice(0, -1)) : candidate === namespace);
    this.cache.set(cacheKey, { allowed, expiresAt: Date.now() + this.ttlMs });
    return allowed;
  }
}
