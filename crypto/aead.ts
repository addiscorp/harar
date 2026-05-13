import { createHash, randomBytes } from 'node:crypto';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';

const KEY_BYTES = 32;
const NONCE_BYTES = 24;
const TAG_BYTES = 16;

export interface EncryptedValue {
  nonce: string;
  ciphertext: string;
  tag: string;
}

export function generateDbKey(): Uint8Array {
  return randomBytes(KEY_BYTES);
}

export function aadFor(namespace: string, key: string, version: number): Uint8Array {
  return new TextEncoder().encode(`${namespace}|${key}|${version}`);
}

export function encryptSecret(plaintext: Uint8Array, dbKey: Uint8Array, aad: Uint8Array): EncryptedValue {
  assertKey(dbKey);
  const nonce = randomBytes(NONCE_BYTES);
  const sealed = xchacha20poly1305(dbKey, nonce, aad).encrypt(plaintext);
  return {
    nonce: Buffer.from(nonce).toString('base64'),
    ciphertext: Buffer.from(sealed.slice(0, sealed.length - TAG_BYTES)).toString('base64'),
    tag: Buffer.from(sealed.slice(sealed.length - TAG_BYTES)).toString('base64'),
  };
}

export function decryptSecret(value: EncryptedValue, dbKey: Uint8Array, aad: Uint8Array): Uint8Array {
  assertKey(dbKey);
  return xchacha20poly1305(dbKey, Buffer.from(value.nonce, 'base64'), aad)
    .decrypt(Buffer.concat([Buffer.from(value.ciphertext, 'base64'), Buffer.from(value.tag, 'base64')]));
}

export function sha256Base64(data: string | Uint8Array): string {
  return createHash('sha256').update(data).digest('base64');
}

export function tagDigest(tag: string): string {
  return sha256Base64(tag).slice(0, 22);
}

export function zeroBuffer(buffer: Uint8Array): void {
  buffer.fill(0);
}

function assertKey(key: Uint8Array): void {
  if (key.length !== KEY_BYTES) throw new Error(`vault DB key must be ${KEY_BYTES} bytes`);
}
