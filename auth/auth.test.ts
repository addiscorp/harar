import { describe, expect, test } from 'bun:test';
import { hashToken, VaultAuth } from './index.js';

describe('vault auth', () => {
  test('derives principal from bearer token and rejects namespace mismatch', () => {
    process.env.GILD_VAULT_ALLOW_MISSING_PEERCRED = '1';
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
    delete process.env.GILD_VAULT_ALLOW_MISSING_PEERCRED;
  });

  test('rejects peer uid mismatch when credentials are available', () => {
    process.env.NODE_ENV = 'test';
    const auth = VaultAuth.fromRecords([{
      principal: 'svc:deka',
      token_hash: hashToken('token-a'),
      uid: 501,
      namespaces: ['platform/deka'],
    }]);

    expect(() => auth.authenticate(new Request('http://vault/', {
      headers: { authorization: 'Bearer token-a', 'x-gild-peer-uid': '502' },
    }))).toThrow('peer uid');
  });
});
