import { spawn } from 'bun';
import { DEFAULT_SOCKET_PATH } from '../config.js';

interface CliOptions {
  socket?: string;
  token?: string;
}

export async function vaultCli(argv: string[], options: CliOptions = {}): Promise<void> {
  const [cmd, ...rest] = argv;
  const socket = options.socket ?? process.env.GILD_VAULT_SOCKET ?? DEFAULT_SOCKET_PATH;
  const token = options.token ?? process.env.GILD_VAULT_TOKEN;

  if (cmd === 'health') {
    console.log(JSON.stringify(await request(socket, token, 'GET', '/health'), null, 2));
    return;
  }
  if (cmd === 'list') {
    const namespace = required(rest[0], 'namespace');
    console.log(JSON.stringify(await request(socket, token, 'GET', `/secret/${encodeURIComponent(namespace)}`), null, 2));
    return;
  }
  if (cmd === 'read') {
    const { namespace, key } = splitSecretPath(required(rest[0], 'namespace/key'));
    if (!rest.includes('--show') && process.stdout.isTTY) {
      throw new Error('refusing to print secret without --show');
    }
    const body = await request(socket, token, 'GET', `/secret/${encodeURIComponent(namespace)}/${encodeURIComponent(key)}`);
    process.stdout.write(`${body.value}\n`);
    return;
  }
  if (cmd === 'write') {
    const { namespace, key } = splitSecretPath(required(rest[0], 'namespace/key'));
    const value = await new Response(Bun.stdin.stream()).text();
    console.log(JSON.stringify(await request(socket, token, 'POST', `/secret/${encodeURIComponent(namespace)}/${encodeURIComponent(key)}`, { value }), null, 2));
    return;
  }
  if (cmd === 'load') {
    const separator = rest.indexOf('--');
    if (separator === -1) throw new Error('usage: gild vault load <namespace> -- <cmd> <args>');
    const namespace = required(rest[0], 'namespace');
    const command = rest.slice(separator + 1);
    if (command.length === 0) throw new Error('missing command after --');
    const listed = await request(socket, token, 'GET', `/secret/${encodeURIComponent(namespace)}`);
    const env: Record<string, string> = { ...process.env } as Record<string, string>;
    for (const item of listed.keys ?? []) {
      const body = await request(socket, token, 'GET', `/secret/${encodeURIComponent(namespace)}/${encodeURIComponent(item.key)}`);
      env[item.key] = body.value;
    }
    const proc = spawn({ cmd: command, env, stdin: 'inherit', stdout: 'inherit', stderr: 'inherit' });
    process.exit(await proc.exited);
  }
  if (cmd === 'recipient') {
    await recipientCli(socket, token, rest);
    return;
  }
  if (cmd === 'audit') {
    console.log(JSON.stringify(await request(socket, token, 'GET', '/audit'), null, 2));
    return;
  }
  if (cmd === 'migrate-env') {
    throw new Error('migrate-env is daemon-side transactional API work; use POST /secret import flow in v1 tests');
  }

  throw new Error(`unknown vault command: ${cmd ?? ''}`);
}

async function recipientCli(socket: string, token: string | undefined, argv: string[]): Promise<void> {
  const [cmd, ...rest] = argv;
  if (cmd === 'list') {
    console.log(JSON.stringify(await request(socket, token, 'GET', '/recipient'), null, 2));
    return;
  }
  if (cmd === 'add') {
    const [id, type, publicKey] = rest;
    console.log(JSON.stringify(await request(socket, token, 'POST', '/recipient', { id, type, public_key: publicKey }), null, 2));
    return;
  }
  if (cmd === 'remove') {
    const id = required(rest[0], 'recipient id');
    console.log(JSON.stringify(await request(socket, token, 'DELETE', `/recipient/${encodeURIComponent(id)}`), null, 2));
    return;
  }
  if (cmd === 'rotate') {
    console.log(JSON.stringify(await request(socket, token, 'POST', '/recipient/rotate'), null, 2));
    return;
  }
  throw new Error(`unknown recipient command: ${cmd ?? ''}`);
}

async function request(socket: string, token: string | undefined, method: string, path: string, body?: unknown): Promise<any> {
  const cmd = ['curl', '--silent', '--show-error', '--unix-socket', socket, '-X', method, '-H', 'content-type: application/json'];
  if (token) cmd.push('-H', `authorization: Bearer ${token}`);
  if (body !== undefined) cmd.push('--data-binary', JSON.stringify(body));
  cmd.push(`http://localhost${path}`);
  const proc = spawn({ cmd, stdout: 'pipe', stderr: 'pipe' });
  const [exitCode, stdout, stderr] = await Promise.all([
    proc.exited,
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  if (exitCode !== 0) throw new Error(stderr.trim() || `curl exited ${exitCode}`);
  const parsed = JSON.parse(stdout || '{}');
  if (parsed.error) throw new Error(parsed.message ?? parsed.error);
  return parsed;
}

function splitSecretPath(value: string): { namespace: string; key: string } {
  const idx = value.lastIndexOf('/');
  if (idx <= 0 || idx === value.length - 1) throw new Error('secret path must be namespace/key');
  return { namespace: value.slice(0, idx), key: value.slice(idx + 1) };
}

function required(value: string | undefined, name: string): string {
  if (!value) throw new Error(`missing ${name}`);
  return value;
}
