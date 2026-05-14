import { describe, expect, test } from 'bun:test';
import fs from 'fs/promises';
import os from 'os';
import path from 'path';
import { MockAgeRunner } from '../crypto/age.js';
import { RecipientStore } from '../recipients/index.js';
import { VaultKeyring } from './keyring.js';

describe('vault keyring recovery and rotation', () => {
  test('unseals via passphrase recovery artifact when hardware identity is unavailable', async () => {
    const { dataDir, recipients } = await fixture();
    const keyring = new VaultKeyring(dataDir, new MockAgeRunner(), recipients, { allowPageableKey: true });
    const created = await keyring.unsealOrCreate({ identityPath: 'recipient:age1self', recoveryPassphrase: 'correct horse' });
    keyring.zero(created);

    const recovered = await new VaultKeyring(dataDir, new FailingHardwareAgeRunner(), recipients, { allowPageableKey: true })
      .unsealOrCreate({ recoveryPassphrase: 'correct horse' });
    expect(recovered.byteLength).toBe(32);
  });

  test('unseals via hardware artifact when no passphrase is provided', async () => {
    const { dataDir, recipients } = await fixture();
    const keyring = new VaultKeyring(dataDir, new MockAgeRunner(), recipients, { allowPageableKey: true });
    const created = await keyring.unsealOrCreate({ identityPath: 'recipient:age1self', recoveryPassphrase: 'correct horse' });
    keyring.zero(created);

    const recovered = await new VaultKeyring(dataDir, new MockAgeRunner(), recipients, { allowPageableKey: true })
      .unsealOrCreate({ identityPath: 'recipient:age1self' });
    expect(recovered.byteLength).toBe(32);
  });

  test('rotate rewraps so an added hardware recipient can decrypt', async () => {
    const { dataDir, recipients, key } = await sealedFixture();
    await recipients.add({ id: 'next', type: 'sep', public_key: 'age1next' });

    await new VaultKeyring(dataDir, new MockAgeRunner(), recipients, { allowPageableKey: true })
      .rotate(key, { identityPath: 'recipient:age1next', recoveryPassphrase: 'correct horse' });

    const wrapped = await fs.readFile(path.join(dataDir, 'recipients', 'db-key.age'));
    await expect(new MockAgeRunner().unwrap(wrapped, 'recipient:age1next')).resolves.toBeInstanceOf(Uint8Array);
  });

  test('rotate rewraps so a removed hardware recipient cannot decrypt', async () => {
    const { dataDir, recipients, key } = await sealedFixture();
    await recipients.add({ id: 'next', type: 'sep', public_key: 'age1next' });
    await recipients.remove('self', true);

    await new VaultKeyring(dataDir, new MockAgeRunner(), recipients, { allowPageableKey: true })
      .rotate(key, { identityPath: 'recipient:age1next', recoveryPassphrase: 'correct horse' });

    const wrapped = await fs.readFile(path.join(dataDir, 'recipients', 'db-key.age'));
    await expect(new MockAgeRunner().unwrap(wrapped, 'recipient:age1self')).rejects.toThrow('not a recipient');
    await expect(new MockAgeRunner().unwrap(wrapped, 'recipient:age1next')).resolves.toBeInstanceOf(Uint8Array);
  });

  test('rotate refuses lockout and preserves old artifact when verification fails', async () => {
    const { dataDir, recipients, key } = await sealedFixture();
    await recipients.remove('self', true);
    await expect(new VaultKeyring(dataDir, new MockAgeRunner(), recipients, { allowPageableKey: true })
      .rotate(key, { identityPath: 'recipient:age1self', recoveryPassphrase: 'correct horse' })).rejects.toThrow('not enough');

    await recipients.add({ id: 'next', type: 'sep', public_key: 'age1next' });
    await recipients.remove('recovery', true);
    await recipients.add({ id: 'recovery-2', type: 'passphrase', public_key: 'recovery.age' });
    const before = await fs.readFile(path.join(dataDir, 'recipients', 'db-key.age'), 'utf8');
    await expect(new VaultKeyring(dataDir, new FailingRecoveryVerifyAgeRunner(), recipients, { allowPageableKey: true })
      .rotate(key, { identityPath: 'recipient:age1next', recoveryPassphrase: 'correct horse' })).rejects.toThrow('DR');
    const after = await fs.readFile(path.join(dataDir, 'recipients', 'db-key.age'), 'utf8');
    expect(after).toBe(before);
  });
});

async function fixture() {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vault-keyring-'));
  const recipients = new RecipientStore(path.join(dataDir, 'recipients', 'recipients.json'), 2);
  await recipients.add({ id: 'self', type: 'sep', public_key: 'age1self' });
  await recipients.add({ id: 'recovery', type: 'passphrase', public_key: 'recovery.age' });
  return { dataDir, recipients };
}

async function sealedFixture() {
  const { dataDir, recipients } = await fixture();
  const keyring = new VaultKeyring(dataDir, new MockAgeRunner(), recipients, { allowPageableKey: true });
  const key = await keyring.unsealOrCreate({ identityPath: 'recipient:age1self', recoveryPassphrase: 'correct horse' });
  return { dataDir, recipients, key };
}

class FailingHardwareAgeRunner extends MockAgeRunner {
  async unwrap(): Promise<Uint8Array> {
    throw new Error('hardware unavailable');
  }
}

class FailingRecoveryVerifyAgeRunner extends MockAgeRunner {
  async unwrapPassphrase(): Promise<Uint8Array> {
    throw new Error('DR verification failed');
  }
}
