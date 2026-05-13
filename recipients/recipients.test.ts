import { describe, expect, test } from 'bun:test';
import fs from 'fs/promises';
import os from 'os';
import path from 'path';
import { RecipientStore } from './index.js';

describe('vault recipients', () => {
  test('refuses removal below minimum without break-glass', async () => {
    const store = new RecipientStore(path.join(await fs.mkdtemp(path.join(os.tmpdir(), 'vault-recips-')), 'recipients.json'), 2);
    await store.add({ id: 'self-sep', type: 'sep', public_key: 'age1self' });
    await store.add({ id: 'recovery', type: 'passphrase', public_key: 'recovery.age' });

    await expect(store.remove('recovery')).rejects.toThrow('minimum recovery');
    await store.remove('recovery', true);
    expect(await store.list()).toHaveLength(1);
  });
});
