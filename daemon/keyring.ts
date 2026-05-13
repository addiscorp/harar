import fs from 'fs/promises';
import path from 'path';
import { generateDbKey, zeroBuffer } from '../crypto/aead.js';
import type { AgeRunner } from '../crypto/age.js';
import type { RecipientStore } from '../recipients/index.js';

export class VaultKeyring {
  constructor(
    private readonly dataDir: string,
    private readonly age: AgeRunner,
    private readonly recipients: RecipientStore
  ) {}

  async unsealOrCreate(options: { identityPath?: string; recoveryPassphrase?: string }): Promise<Uint8Array> {
    const wrappedPath = path.join(this.dataDir, 'recipients', 'db-key.age');
    try {
      const wrapped = await fs.readFile(wrappedPath);
      if (options.recoveryPassphrase) return this.age.unwrapPassphrase(wrapped, options.recoveryPassphrase);
      if (!options.identityPath) throw new Error('missing SEP identity path for vault unseal');
      return this.age.unwrap(wrapped, options.identityPath);
    } catch (error: any) {
      if (error?.code !== 'ENOENT') throw error;
    }

    const recipients = await this.recipients.publicRecipients();
    if (recipients.length === 0 && process.env.NODE_ENV !== 'test') {
      throw new Error('cannot bootstrap vault without at least one SEP/public recipient');
    }
    const dbKey = generateDbKey();
    await fs.mkdir(path.dirname(wrappedPath), { recursive: true, mode: 0o700 });
    await fs.writeFile(wrappedPath, await this.age.wrap(dbKey, recipients.length > 0 ? recipients : ['mock-recipient']), { mode: 0o600 });
    if (options.recoveryPassphrase) {
      await fs.writeFile(path.join(this.dataDir, 'recipients', 'recovery.age'), await this.age.wrapPassphrase(dbKey, options.recoveryPassphrase), { mode: 0o600 });
    }
    return dbKey;
  }

  zero(key: Uint8Array): void {
    zeroBuffer(key);
  }
}
