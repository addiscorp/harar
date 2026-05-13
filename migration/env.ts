import { createHash } from 'node:crypto';
import fs from 'fs/promises';
import path from 'path';
import type { VaultDatabase } from '../db/index.js';

export interface EnvMigrationResult {
  imported: Array<{ namespace: string; key: string; sha256: string }>;
  quarantined_path?: string;
  dry_run: boolean;
}

export async function migrateEnvFile(input: {
  envPath: string;
  namespace: string;
  db: VaultDatabase;
  dryRun?: boolean;
  quarantineRoot?: string;
}): Promise<EnvMigrationResult> {
  const text = await fs.readFile(input.envPath, 'utf8');
  const parsed = parseEnv(text);
  const imported: EnvMigrationResult['imported'] = [];

  input.db.transaction(() => {
    for (const [key, value] of Object.entries(parsed)) {
      if (!input.dryRun) input.db.write(input.namespace, key, value);
      imported.push({ namespace: input.namespace, key, sha256: createHash('sha256').update(value).digest('hex') });
    }
  });

  if (input.dryRun) return { imported, dry_run: true };

  for (const [key, value] of Object.entries(parsed)) {
    const readBack = input.db.read(input.namespace, key);
    if (readBack?.value !== value) throw new Error(`vault read-back failed for ${input.namespace}/${key}`);
  }

  const quarantineRoot = input.quarantineRoot ?? path.join(path.dirname(input.envPath), '.vault-quarantine');
  const quarantineDir = path.join(quarantineRoot, new Date().toISOString().replace(/[:.]/g, '-'));
  await fs.mkdir(quarantineDir, { recursive: true, mode: 0o700 });
  const quarantinePath = path.join(quarantineDir, path.basename(input.envPath));
  await fs.rename(input.envPath, quarantinePath);
  return { imported, dry_run: false, quarantined_path: quarantinePath };
}

export function parseEnv(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const match = line.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (!match) continue;
    out[match[1]] = unquote(match[2]);
  }
  return out;
}

function unquote(value: string): string {
  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
    return value.slice(1, -1);
  }
  return value;
}
