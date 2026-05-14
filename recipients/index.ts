import fs from 'fs/promises';
import path from 'path';
import type { RecipientRecord } from '../types.js';

export class RecipientStore {
  constructor(private readonly path: string, private readonly minRecipients: number) {}

  async list(includeRemoved = false): Promise<RecipientRecord[]> {
    const records = await this.readAll();
    return includeRemoved ? records : records.filter((record) => !record.removed_at);
  }

  async add(input: Omit<RecipientRecord, 'created_at'> & { created_at?: string }): Promise<RecipientRecord> {
    const records = await this.readAll();
    if (records.some((record) => record.id === input.id && !record.removed_at)) throw new Error(`recipient already exists: ${input.id}`);
    const record = { ...input, created_at: input.created_at ?? new Date().toISOString(), removed_at: input.removed_at ?? null };
    records.push(record);
    await this.writeAll(records);
    return record;
  }

  async remove(id: string, breakGlass = false): Promise<void> {
    const records = await this.readAll();
    const active = records.filter((record) => !record.removed_at);
    if (!breakGlass && active.length - 1 < this.minRecipients) {
      throw new Error('recipient removal would drop below configured minimum recovery paths');
    }
    const record = records.find((candidate) => candidate.id === id && !candidate.removed_at);
    if (!record) throw new Error(`recipient not found: ${id}`);
    record.removed_at = new Date().toISOString();
    await this.writeAll(records);
  }

  async rotate(): Promise<RecipientRecord[]> {
    const records = await this.readAll();
    const active = records.filter((record) => !record.removed_at);
    if (active.length < this.minRecipients) throw new Error('not enough active recipients to rotate');
    return this.markVerified(active.map((record) => record.id));
  }

  async markVerified(ids: string[]): Promise<RecipientRecord[]> {
    const records = await this.readAll();
    const active = records.filter((record) => !record.removed_at && ids.includes(record.id));
    const now = new Date().toISOString();
    for (const record of active) record.last_verified_at = now;
    await this.writeAll(records);
    return active;
  }

  async publicRecipients(): Promise<string[]> {
    return (await this.list()).filter((record) => record.type !== 'passphrase').map((record) => record.public_key);
  }

  minRequired(): number {
    return this.minRecipients;
  }

  private async readAll(): Promise<RecipientRecord[]> {
    try {
      return JSON.parse(await fs.readFile(this.path, 'utf8'));
    } catch (error: any) {
      if (error?.code !== 'ENOENT') throw error;
      return [];
    }
  }

  private async writeAll(records: RecipientRecord[]): Promise<void> {
    await fs.mkdir(path.dirname(this.path), { recursive: true, mode: 0o700 });
    await fs.writeFile(this.path, JSON.stringify(records, null, 2), { mode: 0o600 });
  }
}
