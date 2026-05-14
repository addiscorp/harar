import { spawn } from 'bun';
import fs from 'fs/promises';
import os from 'os';
import path from 'path';

export interface AgeRunner {
  wrap(plaintext: Uint8Array, recipients: string[]): Promise<Uint8Array>;
  unwrap(ciphertext: Uint8Array, identityPath: string): Promise<Uint8Array>;
  wrapPassphrase(plaintext: Uint8Array, passphrase: string): Promise<Uint8Array>;
  unwrapPassphrase(ciphertext: Uint8Array, passphrase: string): Promise<Uint8Array>;
}

export class SubprocessAgeRunner implements AgeRunner {
  constructor(private readonly ageBin = process.env.GILD_AGE_BIN ?? 'age') {}

  async wrap(plaintext: Uint8Array, recipients: string[]): Promise<Uint8Array> {
    if (recipients.length === 0) throw new Error('at least one hardware/public recipient is required');
    return runAge(this.ageBin, ['-e', ...recipients.flatMap((recipient) => ['-r', recipient])], plaintext);
  }

  async unwrap(ciphertext: Uint8Array, identityPath: string): Promise<Uint8Array> {
    return runAge(this.ageBin, ['-d', '-i', identityPath], ciphertext);
  }

  async wrapPassphrase(plaintext: Uint8Array, passphrase: string): Promise<Uint8Array> {
    return runAge(this.ageBin, ['-e', '-p'], plaintext, passphrase);
  }

  async unwrapPassphrase(ciphertext: Uint8Array, passphrase: string): Promise<Uint8Array> {
    return runAge(this.ageBin, ['-d', '-p'], ciphertext, passphrase);
  }
}

export class MockAgeRunner implements AgeRunner {
  async wrap(plaintext: Uint8Array, recipients: string[]): Promise<Uint8Array> {
    if (recipients.some((recipient) => recipient.startsWith('passphrase:'))) {
      throw new Error('passphrase recovery must be a parallel artifact, not an age co-recipient');
    }
    return encodeMock('hardware', recipients.join(','), plaintext);
  }

  async unwrap(ciphertext: Uint8Array, identityPath = 'mock'): Promise<Uint8Array> {
    const decoded = decodeMock(ciphertext);
    if (decoded.mode !== 'hardware') throw new Error(`cannot unwrap ${decoded.mode} with hardware identity`);
    if (identityPath.startsWith('recipient:') && !decoded.context.split(',').includes(identityPath.slice('recipient:'.length))) {
      throw new Error('identity is not a recipient for this artifact');
    }
    return decoded.plaintext;
  }

  async wrapPassphrase(plaintext: Uint8Array, passphrase: string): Promise<Uint8Array> {
    return encodeMock('passphrase', passphrase, plaintext);
  }

  async unwrapPassphrase(ciphertext: Uint8Array, passphrase: string): Promise<Uint8Array> {
    const decoded = decodeMock(ciphertext);
    if (decoded.mode !== 'passphrase' || decoded.context !== passphrase) throw new Error('invalid passphrase recovery artifact');
    return decoded.plaintext;
  }
}

async function runAge(bin: string, args: string[], stdin: Uint8Array, passphrase?: string): Promise<Uint8Array> {
  if (passphrase !== undefined) return runAgePassphrase(bin, args, stdin, passphrase);
  const proc = spawn({
    cmd: [bin, ...args],
    stdin: 'pipe',
    stdout: 'pipe',
    stderr: 'pipe',
    env: scrubbedEnv(),
  });
  proc.stdin.write(stdin);
  proc.stdin.end();
  const [exitCode, stdout, stderr] = await Promise.all([
    proc.exited,
    new Response(proc.stdout).arrayBuffer(),
    new Response(proc.stderr).text(),
  ]);
  if (exitCode !== 0) throw new Error(`age failed: ${stderr.trim() || `exit ${exitCode}`}`);
  return new Uint8Array(stdout);
}

async function runAgePassphrase(bin: string, args: string[], payload: Uint8Array, passphrase: string): Promise<Uint8Array> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'gild-age-'));
  const inputPath = path.join(dir, 'payload');
  const outputPath = path.join(dir, 'payload.age');
  try {
    await fs.writeFile(inputPath, payload, { mode: 0o600 });
    const proc = spawn({
      cmd: [bin, ...args, '-o', outputPath, inputPath],
      stdin: 'pipe',
      stdout: 'pipe',
      stderr: 'pipe',
      env: scrubbedEnv(),
    });
    proc.stdin.write(new TextEncoder().encode(`${passphrase}\n${passphrase}\n`));
    proc.stdin.end();
    const [exitCode, stderr] = await Promise.all([
      proc.exited,
      new Response(proc.stderr).text(),
    ]);
    if (exitCode !== 0) throw new Error(`age failed: ${stderr.trim() || `exit ${exitCode}`}`);
    return new Uint8Array(await fs.readFile(outputPath));
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
}

function scrubbedEnv(): Record<string, string> {
  const env = { ...process.env };
  delete env.AGE_PASSPHRASE;
  delete env.GILD_VAULT_RECOVERY_PASSPHRASE;
  return env as Record<string, string>;
}

function encodeMock(mode: string, context: string, plaintext: Uint8Array): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({ mode, context, plaintext: Buffer.from(plaintext).toString('base64') }));
}

function decodeMock(ciphertext: Uint8Array): { mode: string; context: string; plaintext: Uint8Array } {
  const parsed = JSON.parse(new TextDecoder().decode(ciphertext));
  return { mode: parsed.mode, context: parsed.context, plaintext: Buffer.from(parsed.plaintext, 'base64') };
}
