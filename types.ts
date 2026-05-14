export const PLATFORM_NAMESPACE_PREFIX = 'platform/';

export interface VaultConfig {
  dataDir: string;
  socketPath: string;
  tokensPath: string;
  machineId: string;
  peers: VaultPeer[];
  minRecipients: number;
  auditAnchorUrl?: string;
}

export interface VaultPeer {
  id: string;
  url: string;
  ageRecipient: string;
  signaturePublicKey: string;
}

export interface TokenRecord {
  principal: string;
  token_hash: string;
  key_type?: 'service' | 'breakglass';
  uid?: number;
  gid?: number;
  admin?: boolean;
  namespaces: string[];
}

export interface Principal {
  name: string;
  uid?: number;
  gid?: number;
  keyType?: 'service' | 'breakglass';
  admin: boolean;
  namespaces: string[];
}

export interface PeerCredentials {
  uid: number;
  gid: number;
  pid?: number;
}

export interface SecretRow {
  namespace: string;
  key: string;
  nonce: string;
  ciphertext: string;
  tag: string;
  version: number;
  created_at: string;
  updated_at: string;
}

export interface RecipientRecord {
  id: string;
  type: 'sep' | 'passphrase' | 'peer' | 'mock';
  public_key: string;
  identity_path?: string;
  created_at: string;
  removed_at?: string | null;
  last_verified_at?: string | null;
}

export interface SignedManifest {
  manifest: {
    machine_id: string;
    version: number;
    created_at: string;
    prev_manifest_hash?: string | null;
    recipients: string[];
    namespaces: string[];
    secrets: Array<{
      namespace: string;
      key: string;
      version: number;
      ciphertext_hash: string;
    }>;
  };
  signature: string;
  signature_public_key: string;
}

export interface ReplicaBundle {
  source_machine_id: string;
  manifest: SignedManifest;
  rows: SecretRow[];
  allow_admin_rollback?: boolean;
}

export interface VaultAuditEvent {
  principal: string;
  op: string;
  namespace?: string;
  key?: string;
  tag?: string;
}
