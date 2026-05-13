import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import fs from 'fs/promises';
import path from 'path';

export interface SigningKeys {
  publicKeyPem: string;
  privateKeyPem: string;
}

export async function loadOrCreateSigningKeys(dataDir: string): Promise<SigningKeys> {
  const dir = path.join(dataDir, 'recipients');
  const privatePath = path.join(dir, 'manifest.ed25519');
  const publicPath = path.join(dir, 'manifest.ed25519.pub');
  try {
    return {
      privateKeyPem: await fs.readFile(privatePath, 'utf8'),
      publicKeyPem: await fs.readFile(publicPath, 'utf8'),
    };
  } catch (error: any) {
    if (error?.code !== 'ENOENT') throw error;
  }
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const pair = generateKeyPairSync('ed25519');
  const privateKeyPem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const publicKeyPem = pair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  await fs.writeFile(privatePath, privateKeyPem, { mode: 0o600 });
  await fs.writeFile(publicPath, publicKeyPem, { mode: 0o644 });
  return { privateKeyPem, publicKeyPem };
}

export function signBytes(privateKeyPem: string, bytes: Uint8Array): string {
  return sign(null, bytes, createPrivateKey(privateKeyPem)).toString('base64');
}

export function verifyBytes(publicKeyPem: string, bytes: Uint8Array, signature: string): boolean {
  return verify(null, bytes, createPublicKey(publicKeyPem), Buffer.from(signature, 'base64'));
}
