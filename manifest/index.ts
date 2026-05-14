import { sha256Base64 } from '../crypto/aead.js';
import { signBytes, verifyBytes } from '../crypto/signing.js';
import type { RecipientRecord, SecretRow, SignedManifest } from '../types.js';

export function canonicalManifestBytes(manifest: SignedManifest['manifest']): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(sortObject(manifest)));
}

export function buildSignedManifest(input: {
  machineId: string;
  rows: SecretRow[];
  recipients: RecipientRecord[];
  version: number;
  prevManifestHash?: string | null;
  privateKeyPem: string;
  publicKeyPem: string;
}): SignedManifest {
  const manifest: SignedManifest['manifest'] = {
    machine_id: input.machineId,
    version: input.version,
    created_at: new Date().toISOString(),
    prev_manifest_hash: input.prevManifestHash ?? null,
    recipients: input.recipients.filter((recipient) => !recipient.removed_at).map((recipient) => recipient.id).sort(),
    namespaces: [...new Set(input.rows.map((row) => row.namespace))].sort(),
    secrets: input.rows.map((row) => ({
      namespace: row.namespace,
      key: row.key,
      version: row.version,
      ciphertext_hash: sha256Base64(`${row.nonce}.${row.ciphertext}.${row.tag}`),
    })).sort((a, b) => `${a.namespace}/${a.key}`.localeCompare(`${b.namespace}/${b.key}`)),
  };
  return {
    manifest,
    signature: signBytes(input.privateKeyPem, canonicalManifestBytes(manifest)),
    signature_public_key: input.publicKeyPem,
  };
}

export function verifySignedManifest(signed: SignedManifest, expectedPublicKey?: string): boolean {
  if (expectedPublicKey && signed.signature_public_key.trim() !== expectedPublicKey.trim()) return false;
  return verifyBytes(signed.signature_public_key, canonicalManifestBytes(signed.manifest), signed.signature);
}

export function manifestHeadHash(signed: SignedManifest): string {
  return sha256Base64(JSON.stringify({
    manifest: sortObject(signed.manifest),
    signature: signed.signature,
    signature_public_key: signed.signature_public_key,
  }));
}

export function verifyManifestRows(signed: SignedManifest, rows: SecretRow[]): boolean {
  const expected = new Map(signed.manifest.secrets.map((entry) => [`${entry.namespace}/${entry.key}`, entry]));
  for (const row of rows) {
    const entry = expected.get(`${row.namespace}/${row.key}`);
    if (!entry || entry.version !== row.version) return false;
    if (entry.ciphertext_hash !== sha256Base64(`${row.nonce}.${row.ciphertext}.${row.tag}`)) return false;
  }
  return rows.length === expected.size;
}

function sortObject(value: any): any {
  if (Array.isArray(value)) return value.map(sortObject);
  if (!value || typeof value !== 'object') return value;
  return Object.keys(value).sort().reduce((acc: any, key) => {
    acc[key] = sortObject(value[key]);
    return acc;
  }, {});
}
