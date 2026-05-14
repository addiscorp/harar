import fs from 'fs/promises';
import path from 'path';
import { manifestHeadHash, verifyManifestRows, verifySignedManifest } from '../manifest/index.js';
import type { ReplicaBundle, VaultPeer } from '../types.js';

export class ReplicaStore {
  constructor(private readonly dataDir: string, private readonly peers: VaultPeer[]) {}

  async apply(bundle: ReplicaBundle): Promise<void> {
    const peer = this.peers.find((candidate) => candidate.id === bundle.source_machine_id);
    if (!peer) throw new Error(`unexpected replica source: ${bundle.source_machine_id}`);
    if (bundle.manifest.manifest.machine_id !== bundle.source_machine_id) {
      throw new Error('replica manifest machine_id does not match source');
    }
    if (!verifySignedManifest(bundle.manifest, peer.signaturePublicKey)) throw new Error('replica manifest signature verification failed');
    if (!verifyManifestRows(bundle.manifest, bundle.rows)) throw new Error('replica manifest row hash verification failed');
    const dir = path.join(this.dataDir, 'replicas', bundle.source_machine_id);
    await fs.mkdir(dir, { recursive: true, mode: 0o700 });
    const current = await this.currentState(dir);
    const incomingSeq = bundle.manifest.manifest.version;
    if (incomingSeq <= current.seq && !bundle.allow_admin_rollback) throw new Error('replica rollback refused');
    if (incomingSeq !== current.seq + 1 && !bundle.allow_admin_rollback) throw new Error('replica non-contiguous manifest refused');
    if ((bundle.manifest.manifest.prev_manifest_hash ?? null) !== current.head_hash && !bundle.allow_admin_rollback) {
      throw new Error('replica manifest chain head mismatch');
    }
    const headHash = manifestHeadHash(bundle.manifest);
    await fs.writeFile(path.join(dir, 'manifest.json'), JSON.stringify(bundle.manifest, null, 2), { mode: 0o600 });
    await fs.writeFile(path.join(dir, 'secrets.rows.json'), JSON.stringify(bundle.rows, null, 2), { mode: 0o600 });
    await fs.writeFile(path.join(dir, 'manifest_state.json'), JSON.stringify({
      source_machine_id: bundle.source_machine_id,
      seq: incomingSeq,
      head_hash: headHash,
      updated_at: new Date().toISOString(),
    }, null, 2), { mode: 0o600 });
  }

  private async currentState(dir: string): Promise<{ seq: number; head_hash: string | null }> {
    try {
      const state = JSON.parse(await fs.readFile(path.join(dir, 'manifest_state.json'), 'utf8'));
      return { seq: Number(state.seq ?? 0), head_hash: state.head_hash ?? null };
    } catch (error: any) {
      if (error?.code !== 'ENOENT') throw error;
      return { seq: 0, head_hash: null };
    }
  }
}
