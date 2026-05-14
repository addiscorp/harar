import { dlopen, FFIType, ptr } from 'bun:ffi';
import type { PeerCredentials } from './types.js';

const RLIMIT_CORE = 4;
const SOL_SOCKET = 1;
const SO_PEERCRED = 17;
const FFI_USIZE = (FFIType as any).usize;

type LibcSymbols = {
  getsockopt?: (fd: number, level: number, option: number, value: unknown, len: unknown) => number;
  getpeereid?: (fd: number, uid: unknown, gid: unknown) => number;
  setrlimit: (resource: number, limit: unknown) => number;
  getrlimit: (resource: number, limit: unknown) => number;
  mlock: (addr: unknown, len: number) => number;
  munlock: (addr: unknown, len: number) => number;
};

let libc: { symbols: LibcSymbols } | null | undefined;

export function getPeerCredentials(fd: number): PeerCredentials | undefined {
  const symbols = getLibc();
  if (!symbols) return undefined;

  if (process.platform === 'darwin' && symbols.getpeereid) {
    const uid = new Uint32Array([0]);
    const gid = new Uint32Array([0]);
    const rc = symbols.getpeereid(fd, ptr(uid), ptr(gid));
    return rc === 0 ? { uid: uid[0], gid: gid[0] } : undefined;
  }

  if (process.platform !== 'linux' || !symbols.getsockopt) return undefined;
  const cred = new Uint8Array(12);
  const len = new Uint32Array([cred.byteLength]);
  const rc = symbols.getsockopt(fd, SOL_SOCKET, SO_PEERCRED, ptr(cred), ptr(len));
  if (rc !== 0 || len[0] < cred.byteLength) return undefined;

  const view = new DataView(cred.buffer, cred.byteOffset, cred.byteLength);
  return {
    pid: view.getInt32(0, true),
    uid: view.getUint32(4, true),
    gid: view.getUint32(8, true),
  };
}

export function disableCoreDumps(): boolean {
  if (process.platform !== 'linux' && process.platform !== 'darwin') return false;
  const symbols = getLibc();
  if (!symbols) return false;

  const limit = new BigUint64Array([0n, 0n]);
  return symbols.setrlimit(RLIMIT_CORE, ptr(limit)) === 0;
}

export function coreDumpLimit(): { soft: bigint; hard: bigint } | null {
  if (process.platform !== 'linux' && process.platform !== 'darwin') return null;
  const symbols = getLibc();
  if (!symbols) return null;

  const limit = new BigUint64Array([0n, 0n]);
  if (symbols.getrlimit(RLIMIT_CORE, ptr(limit)) !== 0) return null;
  return { soft: limit[0], hard: limit[1] };
}

export function lockMemory(buffer: Uint8Array): boolean {
  const symbols = getLibc();
  if (!symbols || buffer.byteLength === 0) return false;
  return symbols.mlock(ptr(buffer), buffer.byteLength) === 0;
}

export function unlockMemory(buffer: Uint8Array): boolean {
  const symbols = getLibc();
  if (!symbols || buffer.byteLength === 0) return false;
  return symbols.munlock(ptr(buffer), buffer.byteLength) === 0;
}

function getLibc(): LibcSymbols | null {
  if (libc === undefined) libc = loadLibc();
  return libc?.symbols ?? null;
}

function loadLibc(): { symbols: LibcSymbols } | null {
  try {
    if (process.platform === 'darwin') {
      return dlopen('/usr/lib/libSystem.B.dylib', {
        getpeereid: {
          args: [FFIType.i32, FFIType.ptr, FFIType.ptr],
          returns: FFIType.i32,
        },
        setrlimit: {
          args: [FFIType.i32, FFIType.ptr],
          returns: FFIType.i32,
        },
        getrlimit: {
          args: [FFIType.i32, FFIType.ptr],
          returns: FFIType.i32,
        },
        mlock: {
          args: [FFIType.ptr, FFI_USIZE],
          returns: FFIType.i32,
        },
        munlock: {
          args: [FFIType.ptr, FFI_USIZE],
          returns: FFIType.i32,
        },
      }) as unknown as { symbols: LibcSymbols };
    }
    if (process.platform !== 'linux') return null;
    return dlopen('libc.so.6', {
      getsockopt: {
        args: [FFIType.i32, FFIType.i32, FFIType.i32, FFIType.ptr, FFIType.ptr],
        returns: FFIType.i32,
      },
      setrlimit: {
        args: [FFIType.i32, FFIType.ptr],
        returns: FFIType.i32,
      },
      getrlimit: {
        args: [FFIType.i32, FFIType.ptr],
        returns: FFIType.i32,
      },
      mlock: {
        args: [FFIType.ptr, FFI_USIZE],
        returns: FFIType.i32,
      },
      munlock: {
        args: [FFIType.ptr, FFI_USIZE],
        returns: FFIType.i32,
      },
    }) as unknown as { symbols: LibcSymbols };
  } catch {
    return null;
  }
}
