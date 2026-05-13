import { describe, expect, test } from 'bun:test';
import { MockAgeRunner } from './age.js';

describe('vault age wrapper', () => {
  test('keeps passphrase recovery as parallel artifact', async () => {
    const age = new MockAgeRunner();
    const plaintext = new TextEncoder().encode('db-key');
    const hardware = await age.wrap(plaintext, ['age1machine']);
    const recovery = await age.wrapPassphrase(plaintext, 'seven words');

    expect(new TextDecoder().decode(await age.unwrap(hardware, 'self.sep.identity'))).toBe('db-key');
    expect(new TextDecoder().decode(await age.unwrapPassphrase(recovery, 'seven words'))).toBe('db-key');
    await expect(age.wrap(plaintext, ['age1machine', 'passphrase:seven words'])).rejects.toThrow('parallel artifact');
  });
});
