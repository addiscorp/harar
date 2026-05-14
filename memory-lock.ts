import { lockMemory as nativeLockMemory, unlockMemory as nativeUnlockMemory } from './native.js';

const locked = new WeakSet<Uint8Array>();

export function lockMemory(buffer: Uint8Array): boolean {
  const ok = nativeLockMemory(buffer);
  if (ok) locked.add(buffer);
  return ok;
}

export function unlockMemory(buffer: Uint8Array): void {
  if (!locked.has(buffer)) return;
  try {
    nativeUnlockMemory(buffer);
  } catch {
    // The key is still zeroed by the caller even if munlock is unavailable.
  } finally {
    locked.delete(buffer);
  }
}
