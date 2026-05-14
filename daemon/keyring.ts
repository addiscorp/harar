import fs from 'fs/promises';
import path from 'path';
import { generateDbKey, zeroBuffer } from '../crypto/aead.js';
import type { AgeRunner } from '../crypto/age.js';
import { lockMemory, unlockMemory } from '../memory-lock.js';
import type { RecipientStore } from '../recipients/index.js';

export class VaultKeyring {
  constructor(
    private readonly dataDir: string,
    private readonly age: AgeRunner,
    private readonly recipients: RecipientStore,
    private readonly options: { allowPageableKey?: boolean } = {}
  ) {}

  async unsealOrCreate(options: { identityPath?: string; recoveryPassphrase?: string }): Promise<Uint8Array> {
    const wrappedPath = path.join(this.dataDir, 'recipients', 'db-key.age');
    const recoveryPath = path.join(this.dataDir, 'recipients', 'recovery.age');
    let wrapped: Uint8Array | undefined;
    try {
      wrapped = await fs.readFile(wrappedPath);
    } catch (error: any) {
      if (error?.code !== 'ENOENT') throw error;
    }
    if (wrapped) {
      if (options.identityPath) {
        try {
          return this.lock(await this.age.unwrap(wrapped, options.identityPath));
        } catch (error) {
          if (!options.recoveryPassphrase) throw error;
        }
      }
      if (options.recoveryPassphrase) {
        return this.lock(await this.age.unwrapPassphrase(await fs.readFile(recoveryPath), options.recoveryPassphrase));
      }
      throw new Error('missing SEP identity path or recovery passphrase for vault unseal');
    }

    const recipients = await this.recipients.publicRecipients();
    if (recipients.length === 0) {
      throw new Error('cannot bootstrap vault without at least one SEP/public recipient');
    }
    const dbKey = generateDbKey();
    await fs.mkdir(path.dirname(wrappedPath), { recursive: true, mode: 0o700 });
    await fs.writeFile(wrappedPath, await this.age.wrap(dbKey, recipients.length > 0 ? recipients : ['mock-recipient']), { mode: 0o600 });
    if (options.recoveryPassphrase) {
      await fs.writeFile(path.join(this.dataDir, 'recipients', 'recovery.age'), await this.age.wrapPassphrase(dbKey, options.recoveryPassphrase), { mode: 0o600 });
    }
    return this.lock(dbKey);
  }

  async rotate(dbKey: Uint8Array, options: { identityPath?: string; recoveryPassphrase?: string; force?: boolean } = {}) {
    const active = await this.recipients.list();
    const publicRecipients = active.filter((record) => record.type !== 'passphrase');
    const passphraseRecipients = active.filter((record) => record.type === 'passphrase');
    if (!options.force && active.length < this.recipients.minRequired()) {
      throw new Error('not enough active recipients to rotate');
    }
    if (!options.force && (publicRecipients.length === 0 || passphraseRecipients.length === 0)) {
      throw new Error('rotation requires at least one hardware/public recipient and one DR passphrase recipient');
    }
    if (publicRecipients.length === 0) throw new Error('rotation has no hardware/public recipient to wrap');
    if (passphraseRecipients.length > 0 && !options.recoveryPassphrase) {
      throw new Error('recovery passphrase is required to rotate DR artifact');
    }

    const recipientsDir = path.join(this.dataDir, 'recipients');
    const wrappedPath = path.join(recipientsDir, 'db-key.age');
    const recoveryPath = path.join(recipientsDir, 'recovery.age');
    const nextHardware = await this.age.wrap(dbKey, publicRecipients.map((record) => record.public_key));
    const nextRecovery = options.recoveryPassphrase
      ? await this.age.wrapPassphrase(dbKey, options.recoveryPassphrase)
      : undefined;

    if (!options.identityPath) throw new Error('SEP identity path is required to verify rotated hardware artifact');
    await this.age.unwrap(nextHardware, options.identityPath);
    if (nextRecovery && options.recoveryPassphrase) await this.age.unwrapPassphrase(nextRecovery, options.recoveryPassphrase);
    if (passphraseRecipients.length > 0 && !nextRecovery) throw new Error('rotated DR artifact verification failed');

    await fs.mkdir(recipientsDir, { recursive: true, mode: 0o700 });
    await atomicWrite(wrappedPath, nextHardware);
    if (nextRecovery) await atomicWrite(recoveryPath, nextRecovery);
    return this.recipients.markVerified(active.map((record) => record.id));
  }

  zero(key: Uint8Array): void {
    unlockMemory(key);
    zeroBuffer(key);
  }

  private lock(key: Uint8Array): Uint8Array {
    if (!lockMemory(key) && !this.options.allowPageableKey) {
      throw new Error('DB key memory lock failed; refusing to start without --allow-pageable-key');
    }
    return key;
  }
}

async function atomicWrite(target: string, data: Uint8Array): Promise<void> {
  const tmp = `${target}.tmp-${process.pid}-${Date.now()}`;
  await fs.writeFile(tmp, data, { mode: 0o600 });
  await fs.rename(tmp, target);
}
