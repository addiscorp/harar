import { describe, expect, test } from 'bun:test';
import { aadFor, decryptSecret, encryptSecret, generateDbKey } from './aead.js';

describe('vault AEAD', () => {
  test('encrypts with unique XChaCha nonces', () => {
    const key = generateDbKey();
    const aad = aadFor('platform/deka', 'TOKEN', 1);
    const a = encryptSecret(new TextEncoder().encode('secret'), key, aad);
    const b = encryptSecret(new TextEncoder().encode('secret'), key, aad);

    expect(a.nonce).not.toBe(b.nonce);
    expect(decryptSecret(a, key, aad).toString()).not.toBe('');
  });

  test('enforces namespace/key/version AAD', () => {
    const key = generateDbKey();
    const sealed = encryptSecret(new TextEncoder().encode('secret'), key, aadFor('platform/deka', 'TOKEN', 1));

    expect(() => decryptSecret(sealed, key, aadFor('platform/deka', 'TOKEN', 2))).toThrow();
    expect(new TextDecoder().decode(decryptSecret(sealed, key, aadFor('platform/deka', 'TOKEN', 1)))).toBe('secret');
  });
});
