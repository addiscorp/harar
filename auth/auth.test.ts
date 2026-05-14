import { describe, expect, test } from 'bun:test';
import { hashToken, VaultAuth } from './index.js';

describe('vault auth', () => {
  test('derives principal from bearer token and rejects namespace mismatch', () => {
    const auth = VaultAuth.fromRecords([{
      principal: 'svc:deka',
      token_hash: hashToken('token-a'),
      namespaces: ['platform/deka'],
    }]);

    const ctx = auth.authenticate(new Request('http://vault/secret/platform/deka/API_KEY', {
      headers: { authorization: 'Bearer token-a' },
    }));
    expect(ctx.principal.name).toBe('svc:deka');

    expect(() => auth.authenticate(new Request('http://vault/secret/platform/deka/API_KEY'))).toThrow('missing bearer');
  });

  test('rejects peer uid mismatch when credentials are available', () => {
    const auth = VaultAuth.fromRecords([{
      principal: 'svc:deka',
      token_hash: hashToken('token-a'),
      uid: 501,
      namespaces: ['platform/deka'],
    }]);

    expect(() => auth.authenticate(new Request('http://vault/', {
      headers: { authorization: 'Bearer token-a' },
    }), { uid: 502, gid: 20, pid: 123 })).toThrow('peer uid');
  });

  test('rejects uid-bound token when peer credentials are unavailable', () => {
    const auth = VaultAuth.fromRecords([{
      principal: 'svc:deka',
      token_hash: hashToken('token-a'),
      uid: 501,
      namespaces: ['platform/deka'],
    }]);

    expect(() => auth.authenticate(new Request('http://vault/', {
      headers: { authorization: 'Bearer token-a' },
    }))).toThrow('peer credentials unavailable');
  });
});
