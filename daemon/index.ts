import fs from 'fs/promises';
import { VaultAcl } from '../acl/index.js';
import { VaultAuditLog } from '../audit/index.js';
import { VaultAuth } from '../auth/index.js';
import { ensureVaultDirs, loadVaultConfig } from '../config.js';
import { SubprocessAgeRunner } from '../crypto/age.js';
import { loadOrCreateSigningKeys } from '../crypto/signing.js';
import { VaultDatabase } from '../db/index.js';
import { handleVaultRequest, vaultPaths } from '../api/index.js';
import { RecipientStore } from '../recipients/index.js';
import { ReplicaStore } from '../replication/index.js';
import { VaultKeyring } from './keyring.js';

export interface VaultDaemonOptions {
  config?: string;
  socket?: string;
  sepIdentity?: string;
  recoveryPassphrase?: string;
}

export interface RunningVaultDaemon {
  server: Server;
  stop: () => Promise<void>;
  url: string;
}

type Server = ReturnType<typeof Bun.serve>;

export async function vaultDaemon(options: VaultDaemonOptions = {}): Promise<never> {
  try {
    const running = await startVaultDaemon(options);
    installShutdownHandlers(running);
    console.log(`gild vault daemon listening on ${running.url}`);
    return await new Promise<never>(() => {});
  } catch (error: any) {
    console.error(`Error: ${error.message ?? String(error)}`);
    process.exit(1);
    throw error;
  }
}

export async function startVaultDaemon(options: VaultDaemonOptions = {}): Promise<RunningVaultDaemon> {
  disableCoreDumps();
  const config = await loadVaultConfig(options.config);
  if (options.socket) config.socketPath = options.socket;
  await ensureVaultDirs(config);
  await fs.rm(config.socketPath, { force: true });

  const paths = vaultPaths(config.dataDir);
  const recipients = new RecipientStore(paths.recipientsJson, config.minRecipients);
  const age = new SubprocessAgeRunner();
  const keyring = new VaultKeyring(config.dataDir, age, recipients);
  const dbKey = await keyring.unsealOrCreate({
    identityPath: options.sepIdentity ?? process.env.GILD_VAULT_SEP_IDENTITY,
    recoveryPassphrase: options.recoveryPassphrase ?? process.env.GILD_VAULT_RECOVERY_PASSPHRASE,
  });
  const deps = {
    config,
    auth: await VaultAuth.fromFile(config.tokensPath),
    acl: new VaultAcl(),
    db: await VaultDatabase.open(paths.secretsDb, dbKey),
    audit: await VaultAuditLog.open(paths.auditDb),
    recipients,
    replicas: new ReplicaStore(config.dataDir, config.peers),
    signingKeys: await loadOrCreateSigningKeys(config.dataDir),
  };

  const server = Bun.serve({
    unix: config.socketPath,
    fetch: (request) => handleVaultRequest(request, deps),
  });

  return {
    server,
    url: `unix://${config.socketPath}`,
    stop: async () => {
      server.stop(true);
      deps.db.close();
      deps.audit.close();
      keyring.zero(dbKey);
    },
  };
}

function disableCoreDumps(): void {
  if (process.platform !== 'win32') {
    try {
      Bun.spawnSync({ cmd: ['sh', '-c', 'ulimit -c 0'] });
    } catch {
      // Best-effort in Bun; launchd also sets CoreDumps = 0.
    }
  }
}

function installShutdownHandlers(running: RunningVaultDaemon): void {
  let stopping = false;
  const shutdown = async () => {
    if (stopping) return;
    stopping = true;
    await running.stop();
    process.exit(0);
  };
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);
}
