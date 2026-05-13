import { describe, expect, test } from 'bun:test';
import { VaultAuditLog } from './index.js';

describe('vault audit', () => {
  test('hash chains audit rows', () => {
    const audit = VaultAuditLog.openInMemory();
    audit.append({ principal: 'admin', op: 'write', namespace: 'platform/deka', key: 'API_KEY', tag: 'tag1' });
    audit.append({ principal: 'svc:deka', op: 'read', namespace: 'platform/deka', key: 'API_KEY' });

    expect(audit.query()).toHaveLength(2);
    expect(audit.verifyChain()).toBe(true);
    audit.close();
  });
});
