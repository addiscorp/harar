// harar edge: an optional, always-on member of your harar ring, in your own
// Cloudflare, Vercel or Supabase account. The design is harar's docs/edge.md.
//
// This one file is the whole API. It uses only Web APIs (crypto.subtle,
// Request, Response, fetch), so it is the same file on every platform; a
// platform's entry file gives it SQL, the edge key and its config.
//
// It holds the secrets devices put here for services, sealed under the edge
// key; service tokens that may read or write them; the devices paired with
// it; and a hash-chained log of every request, shipped as OpenTelemetry logs
// to sinks that should live in another account.

export const VERSION = "0.3.1";

// ---------------------------------------------------------------- config

/** A row from SQL: column name → value. */
export type Row = Record<string, unknown>;

/** SQL with `?` placeholders, in statements SQLite and Postgres both accept. */
export interface Sql {
  query(sql: string, params?: unknown[]): Promise<Row[]>;
}

/** Where the log goes: an OTLP/HTTP endpoint and the headers it needs. */
export interface Sink {
  otlp: string;
  headers?: Record<string, string>;
}

export interface LogConfig {
  sinks?: Sink[];
  /** Which allowed actions to log; refusals are always logged. */
  events?: "all" | Action[];
  /** "serve": answer and ship later. "refuse": ship first, or answer 503. */
  whenSinksFail?: "serve" | "refuse";
}

export interface Config {
  /** SHA-256 (hex) of the setup code `harar edge init` printed. */
  setupCodeHash: string;
  /** The edge key: 32 random bytes, base64, from the platform's secret store. */
  key: string;
  sql: Sql;
  log?: LogConfig;
  /** Where the API is mounted: "" or, on Supabase, "/harar-edge". */
  basePath?: string;
  /** Keeps shipping the log after the answer (a Worker's ctx.waitUntil). */
  waitUntil?: (work: Promise<unknown>) => void;
  /** For tests: the clock (ms) and the network the sinks are reached through. */
  now?: () => number;
  fetch?: typeof fetch;
}

export type Action =
  | "pair"
  | "pairing.create"
  | "device.list"
  | "device.remove"
  | "secret.list"
  | "secret.put"
  | "secret.rotate"
  | "secret.delete"
  | "resolve"
  | "token.create"
  | "token.list"
  | "token.revoke"
  | "log.read";

// ---------------------------------------------------------------- adapters

/** Cloudflare D1. */
export function d1(db: {
  prepare(sql: string): { bind(...values: unknown[]): { all(): Promise<{ results: Row[] }> } };
}): Sql {
  return {
    async query(sql, params = []) {
      return (await db.prepare(sql).bind(...params).all()).results;
    },
  };
}

/** Postgres (Vercel, Supabase): `?` placeholders become `$1`, `$2`, … */
export function postgres(query: (sql: string, params: unknown[]) => Promise<Row[]>): Sql {
  return {
    query(sql, params = []) {
      let n = 0;
      return query(sql.replace(/\?/g, () => `$${++n}`), params);
    },
  };
}

export const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS harar_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS harar_devices (id TEXT PRIMARY KEY, name TEXT NOT NULL, public_key TEXT NOT NULL,
     paired_at TEXT NOT NULL, paired_by TEXT NOT NULL, removed_at TEXT)`,
  `CREATE TABLE IF NOT EXISTS harar_pairings (hash TEXT PRIMARY KEY, created_by TEXT NOT NULL,
     expires_at TEXT NOT NULL, used_at TEXT)`,
  `CREATE TABLE IF NOT EXISTS harar_nonces (device TEXT NOT NULL, nonce TEXT NOT NULL, expires_at TEXT NOT NULL,
     PRIMARY KEY (device, nonce))`,
  `CREATE TABLE IF NOT EXISTS harar_secrets (path TEXT NOT NULL, version INTEGER NOT NULL, sealed TEXT,
     wrapped_key TEXT, kind TEXT NOT NULL, written_by TEXT NOT NULL, written_at TEXT NOT NULL,
     PRIMARY KEY (path, version))`,
  `CREATE TABLE IF NOT EXISTS harar_tokens (id TEXT PRIMARY KEY, name TEXT NOT NULL, hash TEXT NOT NULL,
     read TEXT NOT NULL, write TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL,
     expires_at TEXT, revoked_at TEXT)`,
  `CREATE TABLE IF NOT EXISTS harar_log (seq INTEGER PRIMARY KEY, at TEXT NOT NULL, actor TEXT NOT NULL,
     action TEXT NOT NULL, resource TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT NOT NULL, ip TEXT NOT NULL,
     prev_hash TEXT NOT NULL, hash TEXT NOT NULL, shipped INTEGER NOT NULL)`,
];

// ---------------------------------------------------------------- limits

const MAX_BODY = 64 * 1024;
const MAX_VALUE = 32 * 1024;
const MAX_REFS = 100;
const CLOCK_SKEW_S = 300;
const NONCE_LIFE_MS = 10 * 60 * 1000;
const PAIRING_LIFE_MS = 10 * 60 * 1000;
const SHIP_BATCH = 100;
const REFERENCE_PREFIX = "harar://";

// ---------------------------------------------------------------- bytes

/** Bytes backed by a plain ArrayBuffer, which is what crypto.subtle takes. */
type Bytes = Uint8Array<ArrayBuffer>;

const utf8 = new TextEncoder();

function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** base64 or base64url, padded or not; null if it isn't either. */
function unb64(text: string): Bytes | null {
  if (!/^[A-Za-z0-9+/_-]*={0,2}$/.test(text)) return null;
  const bare = text.replace(/=+$/, "").replace(/-/g, "+").replace(/_/g, "/");
  try {
    const s = atob(bare.padEnd(Math.ceil(bare.length / 4) * 4, "="));
    return Uint8Array.from(s, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function random(n: number): Bytes {
  return crypto.getRandomValues(new Uint8Array(n));
}

async function sha256(data: Bytes | string): Promise<string> {
  const bytes = typeof data === "string" ? utf8.encode(data) : data;
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}

function concat(a: Uint8Array, b: Uint8Array): Bytes {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

// ---------------------------------------------------------------- sealing

/** Seals `value` for path@version: a fresh data key, wrapped by the edge key. */
async function seal(edgeKey: CryptoKey, path: string, version: number, value: string) {
  const ad = utf8.encode(`harar-edge|${path}|${version}`);
  const raw = random(32);
  const dataKey = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]);
  const iv1 = random(12);
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv1, additionalData: ad }, dataKey, utf8.encode(value)));
  const iv2 = random(12);
  const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv2, additionalData: ad }, edgeKey, raw));
  raw.fill(0);
  return { sealed: b64url(concat(iv1, sealed)), wrapped_key: b64url(concat(iv2, wrapped)) };
}

async function unseal(edgeKey: CryptoKey, path: string, version: number, sealed: string, wrappedKey: string): Promise<string> {
  const ad = utf8.encode(`harar-edge|${path}|${version}`);
  const w = unb64(wrappedKey);
  const s = unb64(sealed);
  if (!w || !s) throw new Refusal(500, "sealed", `${path} is not readable`);
  const raw = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: w.slice(0, 12), additionalData: ad }, edgeKey, w.slice(12)));
  const dataKey = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
  raw.fill(0);
  const value = await crypto.subtle.decrypt({ name: "AES-GCM", iv: s.slice(0, 12), additionalData: ad }, dataKey, s.slice(12));
  return new TextDecoder().decode(value);
}

// ---------------------------------------------------------------- names

/** A secret path: segments of [A-Za-z0-9._-], no empty, "." or ".." segment. */
function validPath(path: string): boolean {
  if (path.length === 0 || path.length > 256) return false;
  return path.split("/").every((seg) => /^[A-Za-z0-9._-]+$/.test(seg) && seg !== "." && seg !== "..");
}

/** A path pattern: a path, or a prefix ending in `*` (`prod/site/*`, `*`). */
function validPattern(pattern: string): boolean {
  if (!pattern.endsWith("*")) return validPath(pattern);
  const prefix = pattern.slice(0, -1);
  return prefix === "" || (/^[A-Za-z0-9._/-]+$/.test(prefix) && !prefix.includes("*") && !prefix.startsWith("/") && !prefix.includes("//"));
}

function matches(pattern: string, path: string): boolean {
  return pattern.endsWith("*") ? path.startsWith(pattern.slice(0, -1)) : pattern === path;
}

/** The key a `harar://` reference names, as the clients' `reference()`. */
function reference(value: unknown): string | null {
  if (typeof value !== "string" || !value.startsWith(REFERENCE_PREFIX)) return null;
  const key = value.slice(REFERENCE_PREFIX.length);
  return key !== "" && !/\s/.test(key) && validPath(key) ? key : null;
}

// ---------------------------------------------------------------- errors

class Refusal extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

// ---------------------------------------------------------------- the edge

type Actor = { kind: "device"; id: string } | { kind: "token"; id: string; read: string[]; write: string[] } | { kind: "anonymous" };

function actorName(actor: Actor): string {
  return actor.kind === "anonymous" ? "anonymous" : `${actor.kind}:${actor.id}`;
}

const schemas = new WeakMap<Sql, Promise<void>>();

function ready(sql: Sql): Promise<void> {
  let done = schemas.get(sql);
  if (!done) {
    done = (async () => {
      for (const statement of SCHEMA) await sql.query(statement);
    })();
    done.catch(() => schemas.delete(sql));
    schemas.set(sql, done);
  }
  return done;
}

/** The edge API for one platform's config. */
export function edge(config: Config): { fetch(request: Request): Promise<Response> } {
  const sql = config.sql;
  const now = config.now ?? Date.now;
  const net = config.fetch ?? ((input: RequestInfo | URL, init?: RequestInit) => fetch(input, init));
  const sinks = config.log?.sinks ?? [];
  const events = config.log?.events ?? "all";
  const refuseWithoutSinks = config.log?.whenSinksFail === "refuse";
  const base = (config.basePath ?? "").replace(/\/+$/, "");
  let edgeKey: Promise<CryptoKey> | undefined;

  function key(): Promise<CryptoKey> {
    edgeKey ??= (async () => {
      const raw = unb64(config.key ?? "");
      if (!raw || raw.length !== 32) throw new Refusal(500, "edge_key", "the edge key is not 32 bytes of base64; see harar edge init");
      return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
    })();
    return edgeKey;
  }

  const iso = (ms = now()) => new Date(ms).toISOString();

  // ---------------------------------------------------------- the log

  type Entry = { actor: string; action: Action; resource: string; decision: "allow" | "deny"; reason: string; ip: string };

  async function record(entry: Entry): Promise<void> {
    if (entry.decision === "allow" && events !== "all" && !events.includes(entry.action)) return;
    for (let attempt = 0; attempt < 8; attempt++) {
      const [last] = await sql.query(`SELECT seq, hash FROM harar_log ORDER BY seq DESC LIMIT 1`);
      const seq = last ? Number(last.seq) + 1 : 1;
      const prev = last ? String(last.hash) : "";
      const at = iso();
      const hash = await sha256(prev + "\n" + JSON.stringify([seq, at, entry.actor, entry.action, entry.resource, entry.decision, entry.reason, entry.ip]));
      const inserted = await sql.query(
        `INSERT INTO harar_log (seq, at, actor, action, resource, decision, reason, ip, prev_hash, hash, shipped)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0) ON CONFLICT DO NOTHING RETURNING seq`,
        [seq, at, entry.actor, entry.action, entry.resource, entry.decision, entry.reason, entry.ip, prev, hash],
      );
      if (inserted.length === 1) return;
    }
    throw new Refusal(503, "log_busy", "the log could not be written; try again");
  }

  /** Ships unshipped rows to every sink; true when they all took them. */
  async function ship(): Promise<boolean> {
    if (sinks.length === 0) return true;
    for (;;) {
      const rows = await sql.query(
        `SELECT seq, at, actor, action, resource, decision, reason, ip, prev_hash, hash FROM harar_log
         WHERE shipped = 0 ORDER BY seq LIMIT ${SHIP_BATCH}`,
      );
      if (rows.length === 0) return true;
      const body = JSON.stringify(otlp(rows));
      const sent = await Promise.all(
        sinks.map(async (sink) => {
          try {
            const res = await net(sink.otlp.replace(/\/+$/, "") + "/v1/logs", {
              method: "POST",
              headers: { "content-type": "application/json", ...sink.headers },
              body,
            });
            return res.ok;
          } catch {
            return false;
          }
        }),
      );
      if (!sent.every(Boolean)) return false;
      await sql.query(`UPDATE harar_log SET shipped = 1 WHERE shipped = 0 AND seq <= ?`, [Number(rows[rows.length - 1].seq)]);
      if (rows.length < SHIP_BATCH) return true;
    }
  }

  /** Ships after the answer where the platform keeps working for us
   *  (waitUntil); otherwise before it, so no row waits for a later request. */
  async function shipLater(): Promise<void> {
    const work = ship().catch(() => false);
    if (config.waitUntil) config.waitUntil(work);
    else await work;
  }

  // ---------------------------------------------------------- callers

  async function authenticate(request: Request, body: Bytes, url: URL): Promise<Actor> {
    const deviceId = request.headers.get("harar-device");
    if (deviceId !== null) return { kind: "device", id: await verifyDevice(request, body, url, deviceId) };
    const auth = request.headers.get("authorization");
    if (auth !== null) return verifyToken(auth);
    return { kind: "anonymous" };
  }

  async function verifyDevice(request: Request, body: Bytes, url: URL, id: string): Promise<string> {
    const time = request.headers.get("harar-time") ?? "";
    const nonce = request.headers.get("harar-nonce") ?? "";
    const signature = unb64(request.headers.get("harar-signature") ?? "");
    if (!/^\d{1,12}$/.test(time) || !/^[A-Za-z0-9_-]{16,64}$/.test(nonce) || !signature || signature.length !== 64) {
      throw new Refusal(401, "bad_signature", "a device request needs Harar-Time, Harar-Nonce and Harar-Signature");
    }
    if (Math.abs(now() / 1000 - Number(time)) > CLOCK_SKEW_S) throw new Refusal(401, "clock", "Harar-Time is more than 5 minutes off");
    const [device] = await sql.query(`SELECT public_key FROM harar_devices WHERE id = ? AND removed_at IS NULL`, [id]);
    if (!device) throw new Refusal(401, "unknown_device", "this device is not paired with this edge");
    const signed = utf8.encode(
      ["harar-edge-v1", request.method, url.pathname + url.search, time, nonce, await sha256(body)].join("\n"),
    );
    const publicKey = await crypto.subtle.importKey("raw", unb64(String(device.public_key))!, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    if (!(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, signature, signed))) {
      throw new Refusal(401, "bad_signature", "the signature does not match this device's key");
    }
    await sql.query(`DELETE FROM harar_nonces WHERE expires_at < ?`, [iso()]);
    const fresh = await sql.query(`INSERT INTO harar_nonces (device, nonce, expires_at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING RETURNING nonce`, [
      id,
      nonce,
      iso(now() + NONCE_LIFE_MS),
    ]);
    if (fresh.length !== 1) throw new Refusal(401, "replay", "this request was already used");
    return id;
  }

  async function verifyToken(auth: string): Promise<Actor> {
    const m = /^Bearer harar_edge_([0-9a-f]{16})_([A-Za-z0-9_-]{43})$/.exec(auth);
    if (!m) throw new Refusal(401, "bad_token", "not a harar edge token");
    const [token] = await sql.query(`SELECT id, hash, read, write, expires_at, revoked_at FROM harar_tokens WHERE id = ?`, [m[1]]);
    if (!token || String(token.hash) !== (await sha256(m[2]))) throw new Refusal(401, "bad_token", "not a harar edge token");
    if (token.revoked_at !== null) throw new Refusal(401, "revoked", "this token was revoked");
    if (token.expires_at !== null && String(token.expires_at) <= iso()) throw new Refusal(401, "expired", "this token expired");
    return { kind: "token", id: m[1], read: JSON.parse(String(token.read)), write: JSON.parse(String(token.write)) };
  }

  function mayRead(actor: Actor, path: string): boolean {
    return actor.kind === "device" || (actor.kind === "token" && actor.read.some((p) => matches(p, path)));
  }

  function mayWrite(actor: Actor, path: string): boolean {
    return actor.kind === "device" || (actor.kind === "token" && actor.write.some((p) => matches(p, path)));
  }

  function device(actor: Actor): string {
    if (actor.kind !== "device") throw new Refusal(403, "devices_only", "only a paired device may do this");
    return actor.id;
  }

  // ---------------------------------------------------------- secrets

  async function latest(path: string): Promise<Row | undefined> {
    const [row] = await sql.query(
      `SELECT version, sealed, wrapped_key, kind FROM harar_secrets WHERE path = ? ORDER BY version DESC LIMIT 1`,
      [path],
    );
    return row;
  }

  async function write(path: string, value: string | null, kind: "write" | "rotate" | "delete", by: string): Promise<number> {
    const k = await key();
    for (let attempt = 0; attempt < 8; attempt++) {
      const version = Number((await latest(path))?.version ?? 0) + 1;
      const sealed = value === null ? { sealed: null, wrapped_key: null } : await seal(k, path, version, value);
      const inserted = await sql.query(
        `INSERT INTO harar_secrets (path, version, sealed, wrapped_key, kind, written_by, written_at)
         VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING RETURNING version`,
        [path, version, sealed.sealed, sealed.wrapped_key, kind, by, iso()],
      );
      if (inserted.length === 1) return version;
    }
    throw new Refusal(503, "busy", `${path} is being written by someone else; try again`);
  }

  // ---------------------------------------------------------- requests

  type Handled = { status: number; body: unknown };
  /** What a request does, and what it is for the log, decided before it acts. */
  type Plan = { action: Action; resource: string; act: () => Promise<Handled> };

  async function plan(request: Request, url: URL, path: string, actor: Actor, body: Bytes): Promise<Plan> {
    const method = request.method;
    const input = (): Record<string, unknown> => {
      try {
        const parsed = JSON.parse(new TextDecoder().decode(body));
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return parsed;
      } catch {
        // falls through
      }
      throw new Refusal(400, "bad_json", "the body is not a JSON object");
    };

    if (method === "POST" && path === "/v1/pair") {
      const { code, name, public_key } = input();
      if (typeof code !== "string" || typeof name !== "string" || name.length === 0 || name.length > 100 || typeof public_key !== "string") {
        throw new Refusal(400, "bad_request", "pair takes { code, name, public_key }");
      }
      const raw = unb64(public_key);
      if (!raw || raw.length !== 65 || raw[0] !== 4) throw new Refusal(400, "bad_key", "public_key is a raw P-256 point (65 bytes), base64url");
      await crypto.subtle.importKey("raw", raw, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]).catch(() => {
        throw new Refusal(400, "bad_key", "public_key is not a P-256 point");
      });
      // The code is checked here, so a wrong one is only ever a refusal in
      // the log; act() then takes it, once, for whichever request is first.
      const codeHash = await sha256(code);
      const setup = /^[0-9a-f]{64}$/i.test(config.setupCodeHash) && codeHash === config.setupCodeHash.toLowerCase();
      if (setup) {
        const [used] = await sql.query(`SELECT v FROM harar_meta WHERE k = 'setup_used'`);
        if (used) throw new Refusal(403, "code_used", "the setup code was already used");
      } else {
        const [pairing] = await sql.query(`SELECT created_by FROM harar_pairings WHERE hash = ? AND used_at IS NULL AND expires_at > ?`, [codeHash, iso()]);
        if (!pairing) throw new Refusal(403, "bad_code", "the code is wrong, used or expired");
      }
      return {
        action: "pair",
        resource: name,
        act: async () => {
          let pairedBy: string;
          if (setup) {
            const first = await sql.query(`INSERT INTO harar_meta (k, v) VALUES ('setup_used', ?) ON CONFLICT DO NOTHING RETURNING k`, [iso()]);
            if (first.length !== 1) throw new Refusal(403, "code_used", "the setup code was already used");
            pairedBy = "setup";
          } else {
            const [pairing] = await sql.query(
              `UPDATE harar_pairings SET used_at = ? WHERE hash = ? AND used_at IS NULL AND expires_at > ? RETURNING created_by`,
              [iso(), codeHash, iso()],
            );
            if (!pairing) throw new Refusal(403, "bad_code", "the code is wrong, used or expired");
            pairedBy = String(pairing.created_by);
          }
          const id = `d-${hex(random(8))}`;
          await sql.query(`INSERT INTO harar_devices (id, name, public_key, paired_at, paired_by) VALUES (?, ?, ?, ?, ?)`, [
            id,
            name,
            b64url(raw),
            iso(),
            pairedBy,
          ]);
          return { status: 201, body: { device: id } };
        },
      };
    }

    if (method === "POST" && path === "/v1/pairings") {
      const by = device(actor);
      return {
        action: "pairing.create",
        resource: "",
        act: async () => {
          const code = b64url(random(16));
          const expires = iso(now() + PAIRING_LIFE_MS);
          await sql.query(`INSERT INTO harar_pairings (hash, created_by, expires_at) VALUES (?, ?, ?)`, [await sha256(code), by, expires]);
          return { status: 201, body: { code, expires_at: expires } };
        },
      };
    }

    if (method === "GET" && path === "/v1/devices") {
      device(actor);
      return {
        action: "device.list",
        resource: "",
        act: async () => ({
          status: 200,
          body: { devices: await sql.query(`SELECT id, name, paired_at, paired_by FROM harar_devices WHERE removed_at IS NULL ORDER BY paired_at`) },
        }),
      };
    }

    const deviceMatch = /^\/v1\/devices\/(d-[0-9a-f]{16})$/.exec(path);
    if (method === "DELETE" && deviceMatch) {
      device(actor);
      const id = deviceMatch[1];
      const live = await sql.query(`SELECT id FROM harar_devices WHERE removed_at IS NULL`);
      if (!live.some((d) => d.id === id)) throw new Refusal(404, "not_found", `no paired device ${id}`);
      if (live.length === 1) throw new Refusal(409, "last_device", "the last device can't be removed; pair another first");
      return {
        action: "device.remove",
        resource: id,
        act: async () => {
          await sql.query(`UPDATE harar_devices SET removed_at = ? WHERE id = ? AND removed_at IS NULL`, [iso(), id]);
          return { status: 200, body: { removed: id } };
        },
      };
    }

    if (method === "GET" && path === "/v1/secrets") {
      device(actor);
      return {
        action: "secret.list",
        resource: "",
        act: async () => {
          const rows = await sql.query(`SELECT path, version, kind, written_at FROM harar_secrets ORDER BY path, version DESC`);
          const secrets: Row[] = [];
          for (const row of rows) {
            if (secrets.length > 0 && secrets[secrets.length - 1].path === row.path) continue;
            secrets.push(row);
          }
          return {
            status: 200,
            body: { secrets: secrets.filter((s) => s.kind !== "delete").map((s) => ({ path: s.path, version: Number(s.version), written_at: s.written_at })) },
          };
        },
      };
    }

    if (path.startsWith("/v1/secrets/") && (method === "PUT" || method === "DELETE")) {
      let secret: string;
      try {
        secret = decodeURIComponent(path.slice("/v1/secrets/".length));
      } catch {
        throw new Refusal(400, "bad_path", "not a secret path");
      }
      if (!validPath(secret)) throw new Refusal(400, "bad_path", "a secret path is segments of A-Z a-z 0-9 . _ -");
      if (!mayWrite(actor, secret)) throw new Refusal(403, "not_allowed", `this caller may not write ${secret}`);
      const by = actorName(actor);
      if (method === "DELETE") {
        const current = await latest(secret);
        if (!current || current.kind === "delete") throw new Refusal(404, "not_found", `no secret ${secret}`);
        return {
          action: "secret.delete",
          resource: secret,
          act: async () => ({ status: 200, body: { path: secret, version: await write(secret, null, "delete", by) } }),
        };
      }
      const { value, rotate } = input();
      if (typeof value !== "string" || utf8.encode(value).length > MAX_VALUE) {
        throw new Refusal(400, "bad_value", `value is a string of at most ${MAX_VALUE} bytes`);
      }
      const kind = rotate === true ? "rotate" : "write";
      return {
        action: kind === "rotate" ? "secret.rotate" : "secret.put",
        resource: secret,
        act: async () => ({ status: 200, body: { path: secret, version: await write(secret, value, kind, by) } }),
      };
    }

    if (method === "POST" && path === "/v1/resolve") {
      const { refs } = input();
      if (!Array.isArray(refs) || refs.length === 0 || refs.length > MAX_REFS) {
        throw new Refusal(400, "bad_request", `resolve takes { refs: [...] }, 1 to ${MAX_REFS} harar:// references`);
      }
      const keys = refs.map((ref) => {
        const k = reference(ref);
        if (k === null) throw new Refusal(400, "not_a_reference", `not a harar:// reference: ${JSON.stringify(ref)}`);
        return k;
      });
      for (const k of keys) {
        if (!mayRead(actor, k)) throw new Refusal(403, "not_allowed", `this caller may not read ${k}`);
      }
      const rows = await Promise.all(keys.map((k) => latest(k)));
      rows.forEach((row, i) => {
        if (!row || row.kind === "delete") throw new Refusal(404, "not_found", `no secret ${keys[i]}`);
      });
      return {
        action: "resolve",
        resource: keys.join(","),
        act: async () => {
          const k = await key();
          const values = await Promise.all(
            rows.map((row, i) => unseal(k, keys[i], Number(row!.version), String(row!.sealed), String(row!.wrapped_key))),
          );
          return { status: 200, body: { values } };
        },
      };
    }

    if (method === "POST" && path === "/v1/tokens") {
      const by = device(actor);
      const { name, read = [], write: writes = [], expires_in } = input();
      const patterns = (list: unknown) => Array.isArray(list) && list.length <= 50 && list.every((p) => typeof p === "string" && validPattern(p));
      if (typeof name !== "string" || name.length === 0 || name.length > 100 || !patterns(read) || !patterns(writes)) {
        throw new Refusal(400, "bad_request", "tokens take { name, read: [patterns], write: [patterns], expires_in? }; a pattern is a path or a prefix ending in *");
      }
      if (expires_in !== undefined && (typeof expires_in !== "number" || !Number.isInteger(expires_in) || expires_in <= 0)) {
        throw new Refusal(400, "bad_request", "expires_in is whole seconds");
      }
      return {
        action: "token.create",
        resource: name,
        act: async () => {
          const id = hex(random(8));
          const secret = b64url(random(32));
          const expires = expires_in === undefined ? null : iso(now() + (expires_in as number) * 1000);
          await sql.query(
            `INSERT INTO harar_tokens (id, name, hash, read, write, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [id, name, await sha256(secret), JSON.stringify(read), JSON.stringify(writes), by, iso(), expires],
          );
          return { status: 201, body: { id, token: `harar_edge_${id}_${secret}`, expires_at: expires } };
        },
      };
    }

    if (method === "GET" && path === "/v1/tokens") {
      device(actor);
      return {
        action: "token.list",
        resource: "",
        act: async () => {
          const rows = await sql.query(`SELECT id, name, read, write, created_by, created_at, expires_at, revoked_at FROM harar_tokens ORDER BY created_at`);
          return { status: 200, body: { tokens: rows.map((t) => ({ ...t, read: JSON.parse(String(t.read)), write: JSON.parse(String(t.write)) })) } };
        },
      };
    }

    const tokenMatch = /^\/v1\/tokens\/([0-9a-f]{16})$/.exec(path);
    if (method === "DELETE" && tokenMatch) {
      device(actor);
      const id = tokenMatch[1];
      const [token] = await sql.query(`SELECT revoked_at FROM harar_tokens WHERE id = ?`, [id]);
      if (!token || token.revoked_at !== null) throw new Refusal(404, "not_found", `no live token ${id}`);
      return {
        action: "token.revoke",
        resource: id,
        act: async () => {
          await sql.query(`UPDATE harar_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, [iso(), id]);
          return { status: 200, body: { revoked: id } };
        },
      };
    }

    if (method === "GET" && path === "/v1/log") {
      device(actor);
      const after = url.searchParams.get("after") ?? "0";
      if (!/^\d{1,12}$/.test(after)) throw new Refusal(400, "bad_request", "after is a sequence number");
      return {
        action: "log.read",
        resource: "",
        act: async () => ({
          status: 200,
          body: {
            log: (
              await sql.query(
                `SELECT seq, at, actor, action, resource, decision, reason, ip, prev_hash, hash FROM harar_log WHERE seq > ? ORDER BY seq LIMIT 1000`,
                [Number(after)],
              )
            ).map((r) => ({ ...r, seq: Number(r.seq) })),
          },
        }),
      };
    }

    throw new Refusal(404, "no_route", `${method} ${path} is not part of the harar edge API`);
  }

  /** The action a refused request was asking for, for the log. */
  function attempted(method: string, path: string): Action | null {
    const routes: [string, RegExp, Action][] = [
      ["POST", /^\/v1\/pair$/, "pair"],
      ["POST", /^\/v1\/pairings$/, "pairing.create"],
      ["GET", /^\/v1\/devices$/, "device.list"],
      ["DELETE", /^\/v1\/devices\//, "device.remove"],
      ["GET", /^\/v1\/secrets$/, "secret.list"],
      ["PUT", /^\/v1\/secrets\//, "secret.put"],
      ["DELETE", /^\/v1\/secrets\//, "secret.delete"],
      ["POST", /^\/v1\/resolve$/, "resolve"],
      ["POST", /^\/v1\/tokens$/, "token.create"],
      ["GET", /^\/v1\/tokens$/, "token.list"],
      ["DELETE", /^\/v1\/tokens\//, "token.revoke"],
      ["GET", /^\/v1\/log$/, "log.read"],
    ];
    return routes.find(([m, re]) => m === method && re.test(path))?.[2] ?? null;
  }

  function ipOf(request: Request): string {
    const h = request.headers;
    return h.get("cf-connecting-ip") ?? h.get("x-real-ip") ?? h.get("x-forwarded-for")?.split(",")[0].trim() ?? "";
  }

  return {
    async fetch(request: Request): Promise<Response> {
      const url = new URL(request.url);
      if (base && !(url.pathname === base || url.pathname.startsWith(base + "/"))) return json(404, { error: "no_route", message: "not here" });
      const path = url.pathname.slice(base.length) || "/";
      if (request.method === "GET" && path === "/v1/health") {
        return json(200, { version: VERSION, log: { sinks: sinks.length, whenSinksFail: refuseWithoutSinks ? "refuse" : "serve" } });
      }
      const ip = ipOf(request);
      let actor: Actor = { kind: "anonymous" };
      try {
        await ready(sql);
        const declared = Number(request.headers.get("content-length") ?? "0");
        if (declared > MAX_BODY) throw new Refusal(413, "too_large", `bodies are at most ${MAX_BODY} bytes`);
        const body = new Uint8Array(await request.arrayBuffer());
        if (body.length > MAX_BODY) throw new Refusal(413, "too_large", `bodies are at most ${MAX_BODY} bytes`);
        actor = await authenticate(request, body, url);
        const planned = await plan(request, url, path, actor, body);
        await record({ actor: actorName(actor), action: planned.action, resource: planned.resource, decision: "allow", reason: "", ip });
        // In "refuse" mode nothing happens until every sink has the row.
        if (refuseWithoutSinks && !(await ship())) throw new Refusal(503, "log_unavailable", "the log sinks are unreachable, so this edge refuses to serve");
        const done = await planned.act();
        if (!refuseWithoutSinks) await shipLater();
        return json(done.status, done.body);
      } catch (error) {
        const refusal = error instanceof Refusal ? error : new Refusal(500, "internal", "the edge failed; see its platform logs");
        if (!(error instanceof Refusal)) console.error("harar edge:", error);
        const action = attempted(request.method, path);
        if (action !== null && refusal.code !== "log_busy") {
          try {
            await record({ actor: actorName(actor), action, resource: "", decision: "deny", reason: refusal.code, ip });
            await shipLater();
          } catch {
            // the refusal stands even if it can't be logged
          }
        }
        return json(refusal.status, { error: refusal.code, message: refusal.message });
      }
    },
  };
}

/** Rows as one OTLP/HTTP JSON logs request. */
function otlp(rows: Row[]) {
  const str = (key: string, value: unknown) => ({ key, value: { stringValue: String(value) } });
  return {
    resourceLogs: [
      {
        resource: { attributes: [str("service.name", "harar-edge"), str("service.version", VERSION)] },
        scopeLogs: [
          {
            scope: { name: "harar-edge", version: VERSION },
            logRecords: rows.map((r) => ({
              timeUnixNano: (BigInt(Date.parse(String(r.at))) * 1000000n).toString(),
              severityNumber: r.decision === "allow" ? 9 : 13,
              severityText: r.decision === "allow" ? "INFO" : "WARN",
              body: { stringValue: `${r.actor} ${r.action} ${r.resource} ${r.decision}${r.reason ? ` (${r.reason})` : ""}` },
              attributes: [
                { key: "harar.seq", value: { intValue: String(r.seq) } },
                str("harar.actor", r.actor),
                str("harar.action", r.action),
                str("harar.resource", r.resource),
                str("harar.decision", r.decision),
                str("harar.reason", r.reason),
                str("client.address", r.ip),
                str("harar.prev_hash", r.prev_hash),
                str("harar.hash", r.hash),
              ],
            })),
          },
        ],
      },
    ],
  };
}
