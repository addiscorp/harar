import fs from 'fs/promises';
import { load as loadToml } from 'js-toml';
import os from 'os';
import path from 'path';
import type { VaultConfig } from './types.js';

export const DEFAULT_DATA_DIR = '/var/lib/gild-vault';
export const DEFAULT_SOCKET_PATH = '/run/gild-vault/sock';
export const DEFAULT_CONFIG_PATH = '/etc/gild-vault/config.toml';
export const DEFAULT_TOKENS_PATH = '/etc/gild-vault/tokens.json';

export async function loadVaultConfig(configPath = process.env.GILD_VAULT_CONFIG ?? DEFAULT_CONFIG_PATH): Promise<VaultConfig> {
  let fileConfig: any = {};
  try {
    const text = await fs.readFile(configPath, 'utf8');
    fileConfig = configPath.endsWith('.json') ? JSON.parse(text) : loadToml(text);
  } catch (error: any) {
    if (error?.code !== 'ENOENT') throw error;
  }

  return {
    dataDir: process.env.GILD_VAULT_DATA_DIR ?? fileConfig.data_dir ?? fileConfig.dataDir ?? DEFAULT_DATA_DIR,
    socketPath: process.env.GILD_VAULT_SOCKET ?? fileConfig.socket_path ?? fileConfig.socketPath ?? DEFAULT_SOCKET_PATH,
    tokensPath: process.env.GILD_VAULT_TOKENS ?? fileConfig.tokens_path ?? fileConfig.tokensPath ?? DEFAULT_TOKENS_PATH,
    machineId: process.env.GILD_VAULT_MACHINE_ID ?? fileConfig.machine_id ?? fileConfig.machineId ?? os.hostname() ?? 'unknown',
    peers: normalizePeers(fileConfig.peers ?? []),
    minRecipients: Number(fileConfig.min_recipients ?? fileConfig.minRecipients ?? 2),
    auditAnchorUrl: fileConfig.audit_anchor_url ?? fileConfig.auditAnchorUrl,
  };
}

export async function ensureVaultDirs(config: VaultConfig): Promise<void> {
  await fs.mkdir(config.dataDir, { recursive: true, mode: 0o700 });
  await fs.mkdir(path.join(config.dataDir, 'recipients', 'peers'), { recursive: true, mode: 0o700 });
  await fs.mkdir(path.join(config.dataDir, 'replicas'), { recursive: true, mode: 0o700 });
  await fs.mkdir(path.dirname(config.socketPath), { recursive: true, mode: 0o770 });
}

function normalizePeers(peers: any): VaultConfig['peers'] {
  if (Array.isArray(peers)) return peers;
  return Object.entries(peers).map(([id, value]: [string, any]) => ({
    id,
    url: value.url,
    ageRecipient: value.age_recipient ?? value.ageRecipient,
    signaturePublicKey: value.signature_public_key ?? value.signaturePublicKey,
  }));
}
