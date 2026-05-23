import fs from 'fs/promises';
import { VaultAcl } from '../acl/index.js';
import { VaultAuditLog } from '../audit/index.js';
import { VaultAuth } from '../auth/index.js';
import { VaultJwtVerifier } from '../auth/jwt.js';
import { ensureVaultDirs, loadVaultConfig } from '../config.js';
import { SubprocessAgeRunner } from '../crypto/age.js';
import { loadOrCreateSigningKeys } from '../crypto/signing.js';
import { VaultDatabase } from '../db/index.js';
import { handleVaultRequest, vaultPaths } from '../api/index.js';
import { disableCoreDumps, getPeerCredentials } from '../native.js';
import { RecipientStore } from '../recipients/index.js';
import { ReplicaStore } from '../replication/index.js';
import type { PeerCredentials } from '../types.js';
import { VaultKeyring } from './keyring.js';

export interface VaultDaemonOptions {
  config?: string;
  socket?: string;
  sepIdentity?: string;
  recoveryPassphraseProvider?: () => Promise<string | undefined>;
  allowPageableKey?: boolean;
}

export interface RunningVaultDaemon {
  server: Server;
  stop: () => Promise<void>;
  url: string;
}

type Server = ReturnType<typeof Bun.listen>;

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
  const config = await loadVaultConfig(options.config);
  if (options.socket) config.socketPath = options.socket;
  await ensureVaultDirs(config);
  await fs.rm(config.socketPath, { force: true });

  const paths = vaultPaths(config.dataDir);
  if (!disableCoreDumps()) {
    await writeStartupFatal(paths.auditDb, 'disable_core_dumps_failed');
    console.error('startup fatal: failed to disable core dumps');
    throw new Error('failed to disable core dumps');
  }

  const recipients = new RecipientStore(paths.recipientsJson, config.minRecipients);
  const age = new SubprocessAgeRunner();
  const keyring = new VaultKeyring(config.dataDir, age, recipients, { allowPageableKey: options.allowPageableKey });
  const recoveryPassphrase = await loadRecoveryPassphrase(config.dataDir, options.recoveryPassphraseProvider);
  let dbKey: Uint8Array;
  try {
    dbKey = await keyring.unsealOrCreate({
      identityPath: options.sepIdentity ?? process.env.GILD_VAULT_SEP_IDENTITY,
      recoveryPassphrase,
    });
  } catch (error: any) {
    if (String(error?.message ?? error).includes('memory lock failed')) {
      await writeStartupFatal(paths.auditDb, 'db_key_memory_lock_failed');
      console.error('startup fatal: failed to lock DB key memory; use --allow-pageable-key only for local development');
    }
    throw error;
  }
  const deps = {
    config,
    auth: await VaultAuth.fromFile(config.tokensPath),
    jwtVerifier: VaultJwtVerifier.fromConfig(config),
    acl: new VaultAcl(),
    db: await VaultDatabase.open(paths.secretsDb, dbKey),
    audit: await VaultAuditLog.open(paths.auditDb),
    recipients,
    rotateRecipients: (rotateOptions?: { force?: boolean }) => keyring.rotate(dbKey, {
      identityPath: options.sepIdentity ?? process.env.GILD_VAULT_SEP_IDENTITY,
      recoveryPassphrase,
      force: rotateOptions?.force,
    }),
    replicas: new ReplicaStore(config.dataDir, config.peers),
    signingKeys: await loadOrCreateSigningKeys(config.dataDir),
  };

  const server = Bun.listen<{ buffer: Uint8Array; peerCredentials?: PeerCredentials }>({
    unix: config.socketPath,
    socket: {
      open(socket) {
        const rawSocket = socket as any;
        socket.data = {
          buffer: new Uint8Array(),
          peerCredentials: getPeerCredentials(rawSocket.fd),
        };
      },
      data(socket, chunk) {
        const rawSocket = socket as any;
        const previous = socket.data?.buffer ?? new Uint8Array();
        const incoming = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
        const buffer = new Uint8Array(previous.byteLength + incoming.byteLength);
        buffer.set(previous);
        buffer.set(incoming, previous.byteLength);
        socket.data.buffer = buffer;

        const parsed = parseHttpRequest(buffer);
        if (!parsed) return;
        rawSocket.pause();
        handleVaultRequest(parsed.request, deps, socket.data.peerCredentials)
          .then((response) => writeHttpResponse(socket, response))
          .catch((error) => writeHttpResponse(socket, new Response(JSON.stringify({
            error: 'internal_error',
            message: error?.message ?? String(error),
          }), { status: 500, headers: { 'content-type': 'application/json' } })));
      },
    },
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

async function writeStartupFatal(auditDb: string, reason: string): Promise<void> {
  const audit = await VaultAuditLog.open(auditDb);
  try {
    audit.append({ principal: 'system', op: 'startup_fatal', tag: reason });
  } finally {
    audit.close();
  }
}

async function loadRecoveryPassphrase(dataDir: string, provider?: () => Promise<string | undefined>): Promise<string | undefined> {
  if (provider) return provider();
  const fd = process.env.GILD_VAULT_RECOVERY_PASSPHRASE_FD;
  if (fd) return readPassphraseFd(fd);
  const configuredPath = process.env.GILD_VAULT_RECOVERY_PASSPHRASE_FILE;
  const defaultPath = pathJoin(dataDir, 'recovery.passphrase');
  return readPassphraseFile(configuredPath ?? defaultPath, configuredPath !== undefined);
}

async function readPassphraseFd(fd: string): Promise<string> {
  const text = await fs.readFile(`/proc/self/fd/${Number(fd)}`, 'utf8');
  return text.replace(/\r?\n$/, '');
}

async function readPassphraseFile(filePath: string, required: boolean): Promise<string | undefined> {
  let stat;
  try {
    stat = await fs.stat(filePath);
  } catch (error: any) {
    if (!required && error?.code === 'ENOENT') return undefined;
    throw error;
  }
  if ((stat.mode & 0o077) !== 0) throw new Error(`recovery passphrase file must be mode 0600: ${filePath}`);
  if (typeof process.getuid === 'function' && process.getuid() === 0 && stat.uid !== 0) {
    throw new Error(`recovery passphrase file must be owned by root: ${filePath}`);
  }
  return (await fs.readFile(filePath, 'utf8')).replace(/\r?\n$/, '');
}

function pathJoin(...parts: string[]): string {
  return parts.join('/').replace(/\/+/g, '/');
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

function parseHttpRequest(buffer: Uint8Array): { request: Request; consumed: number } | null {
  const headerEnd = findHeaderEnd(buffer);
  if (headerEnd === -1) return null;

  const headerText = new TextDecoder().decode(buffer.slice(0, headerEnd));
  const lines = headerText.split('\r\n');
  const [method, target] = lines[0]?.split(' ') ?? [];
  if (!method || !target) throw new Error('invalid HTTP request line');

  const headers = new Headers();
  for (const line of lines.slice(1)) {
    const split = line.indexOf(':');
    if (split <= 0) continue;
    headers.set(line.slice(0, split).trim(), line.slice(split + 1).trim());
  }

  const contentLength = Number(headers.get('content-length') ?? 0);
  if (!Number.isInteger(contentLength) || contentLength < 0) throw new Error('invalid content-length');
  const bodyStart = headerEnd + 4;
  const bodyEnd = bodyStart + contentLength;
  if (buffer.byteLength < bodyEnd) return null;

  const body = contentLength === 0 ? undefined : buffer.slice(bodyStart, bodyEnd);
  return {
    consumed: bodyEnd,
    request: new Request(`http://vault${target}`, { method, headers, body }),
  };
}

function findHeaderEnd(buffer: Uint8Array): number {
  for (let i = 0; i <= buffer.byteLength - 4; i += 1) {
    if (buffer[i] === 13 && buffer[i + 1] === 10 && buffer[i + 2] === 13 && buffer[i + 3] === 10) return i;
  }
  return -1;
}

async function writeHttpResponse(socket: { write: (data: string | Uint8Array) => unknown; end: () => unknown }, response: Response): Promise<void> {
  const body = new Uint8Array(await response.arrayBuffer());
  const headers = new Headers(response.headers);
  headers.set('content-length', String(body.byteLength));
  headers.set('connection', 'close');

  let head = `HTTP/1.1 ${response.status} ${statusText(response.status)}\r\n`;
  for (const [key, value] of Array.from((headers as any).entries()) as Array<[string, string]>) head += `${key}: ${value}\r\n`;
  head += '\r\n';

  socket.write(head);
  if (body.byteLength > 0) socket.write(body);
  socket.end();
}

function statusText(status: number): string {
  if (status === 200) return 'OK';
  if (status === 400) return 'Bad Request';
  if (status === 401) return 'Unauthorized';
  if (status === 403) return 'Forbidden';
  if (status === 404) return 'Not Found';
  if (status === 500) return 'Internal Server Error';
  return 'OK';
}
