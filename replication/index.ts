import fs from 'fs/promises';
import path from 'path';
import { verifyManifestRows, verifySignedManifest } from '../manifest/index.js';
import type { ReplicaBundle, VaultPeer } from '../types.js';

export class ReplicaStore {
  constructor(private readonly dataDir: string, private readonly peers: VaultPeer[]) {}

  async apply(bundle: ReplicaBundle): Promise<void> {
    const peer = this.peers.find((candidate) => candidate.id === bundle.source_machine_id);
    if (!peer) throw new Error(`unexpected replica source: ${bundle.source_machine_id}`);
    if (!verifySignedManifest(bundle.manifest, peer.signaturePublicKey)) throw new Error('replica manifest signature verification failed');
    if (!verifyManifestRows(bundle.manifest, bundle.rows)) throw new Error('replica manifest row hash verification failed');
    const dir = path.join(this.dataDir, 'replicas', bundle.source_machine_id);
    await fs.mkdir(dir, { recursive: true, mode: 0o700 });
    const current = await this.currentVersion(dir);
    if (bundle.manifest.manifest.version <= current) throw new Error('replica rollback refused');
    await fs.writeFile(path.join(dir, 'manifest.json'), JSON.stringify(bundle.manifest, null, 2), { mode: 0o600 });
    await fs.writeFile(path.join(dir, 'secrets.rows.json'), JSON.stringify(bundle.rows, null, 2), { mode: 0o600 });
  }

  private async currentVersion(dir: string): Promise<number> {
    try {
      const manifest = JSON.parse(await fs.readFile(path.join(dir, 'manifest.json'), 'utf8'));
      return Number(manifest.manifest?.version ?? 0);
    } catch (error: any) {
      if (error?.code !== 'ENOENT') throw error;
      return 0;
    }
  }
}
