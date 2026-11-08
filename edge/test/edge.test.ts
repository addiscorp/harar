// The edge against real SQL (SQLite always; Postgres too when
// HARAR_TEST_POSTGRES names one), real P-256 device keys and a stand-in log
// sink: every test asserts what a caller or the database would see.
import assert from "node:assert/strict";
import { createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync, webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { after, describe, test } from "node:test";

import { VERSION, edge, keyId, postgres, type Config, type Row, type Sql } from "../harar-edge.ts";

const SETUP = "the-setup-code-from-init";
const setupHash = createHash("sha256").update(SETUP).digest("hex");
const KEY = Buffer.from(webcrypto.getRandomValues(new Uint8Array(32))).toString("base64");

function sqlite(): Sql & { db: DatabaseSync } {
  const db = new DatabaseSync(":memory:");
  return {
    db,
    async query(sql, params = []) {
      return db.prepare(sql).all(...(params as (string | number | null)[])) as Row[];
    },
  };
}

type Backend = { name: string; make: () => Promise<Sql & { all(sql: string): Promise<Row[]> }> };

const backends: Backend[] = [
  {
    name: "sqlite",
    make: async () => {
      const s = sqlite();
      return { query: s.query, all: (q) => s.query(q) };
    },
  },
];

if (process.env.HARAR_TEST_POSTGRES) {
  const { default: pg } = await import("postgres");
  let n = 0;
  backends.push({
    name: "postgres",
    make: async () => {
      const schema = `harar_test_${process.pid}_${++n}`;
      const admin = pg(process.env.HARAR_TEST_POSTGRES!, { onnotice: () => {} });
      await admin.unsafe(`CREATE SCHEMA ${schema}`);
      await admin.end();
      const conn = pg(process.env.HARAR_TEST_POSTGRES!, { onnotice: () => {}, connection: { search_path: schema } as never });
      after(() => conn.end());
      const sql = postgres((q, p) => conn.unsafe(q, p as never[]) as unknown as Promise<Row[]>);
      return { ...sql, all: (q) => sql.query(q) };
    },
  });
}

/** A stand-in OTLP sink that records what it was sent, and can be down. */
function sink() {
  const got: { url: string; headers: Record<string, string>; body: any }[] = [];
  const state = { down: false };
  const net = (async (input: RequestInfo | URL, init?: RequestInit) => {
    if (state.down) throw new TypeError("connection refused");
    got.push({ url: String(input), headers: init?.headers as Record<string, string>, body: JSON.parse(String(init?.body)) });
    return new Response("{}", { status: 200 });
  }) as typeof fetch;
  return { got, state, net, records: () => got.flatMap((g) => g.body.resourceLogs[0].scopeLogs[0].logRecords) };
}

async function setup(backend: Backend, extra: Partial<Config> = {}) {
  const sql = await backend.make();
  const clock = { ms: Date.parse("2026-11-08T12:00:00Z") };
  const pending: Promise<unknown>[] = [];
  const api = edge({
    setupCodeHash: setupHash,
    key: KEY,
    sql,
    now: () => clock.ms,
    waitUntil: (p) => pending.push(p),
    ...extra,
  });
  const call = async (method: string, path: string, init: { body?: unknown; headers?: Record<string, string> } = {}) => {
    const res = await api.fetch(
      new Request(`https://edge.example${extra.basePath ?? ""}${path}`, {
        method,
        headers: { "content-type": "application/json", "x-real-ip": "203.0.113.7", ...init.headers },
        body: init.body === undefined ? undefined : JSON.stringify(init.body),
      }),
    );
    await Promise.all(pending.splice(0));
    return { status: res.status, body: (await res.json()) as any };
  };
  return { sql, clock, call, api };
}

/** A device: a P-256 key that signs requests the way docs/edge.md says. */
async function device(call: Awaited<ReturnType<typeof setup>>["call"], clock: { ms: number }, code = SETUP, name = "mac", given?: webcrypto.CryptoKeyPair) {
  const keys = given ?? (await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]));
  const raw = new Uint8Array(await webcrypto.subtle.exportKey("raw", keys.publicKey));
  const paired = await call("POST", "/v1/pair", { body: { code, name, public_key: Buffer.from(raw).toString("base64url") } });
  const sign = async (method: string, path: string, body?: unknown, tweak: { time?: number; nonce?: string; bodyOverride?: string } = {}) => {
    const text = body === undefined ? "" : JSON.stringify(body);
    const time = String(tweak.time ?? Math.floor(clock.ms / 1000));
    const nonce = tweak.nonce ?? Buffer.from(webcrypto.getRandomValues(new Uint8Array(16))).toString("base64url");
    const digest = createHash("sha256").update(text).digest("hex");
    const signed = ["harar-edge-v1", method, path, time, nonce, digest].join("\n");
    const sig = new Uint8Array(await webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keys.privateKey, new TextEncoder().encode(signed)));
    return {
      headers: { "harar-device": paired.body.device, "harar-time": time, "harar-nonce": nonce, "harar-signature": Buffer.from(sig).toString("base64url") },
      nonce,
    };
  };
  const as = async (method: string, path: string, body?: unknown) => call(method, path, { body, headers: (await sign(method, path, body)).headers });
  return { id: paired.body.device as string, paired, sign, as, keys };
}

type Device = Awaited<ReturnType<typeof device>>;

const sha = (text: string) => createHash("sha256").update(text).digest("hex");

/** What docs/edge.md §5a says an author signs: written here from the doc, not
 *  imported, so the edge and this test can't share a mistake. */
function canonicalOp(op: Row, sealedSha256: string, wrappedKeySha256: string): string {
  return ["harar-op-v1", op.author, op.seq, op.prev, op.kind, op.key, op.version, sealedSha256, wrappedKeySha256, op.at].join("\n");
}

/** An op's hash: sha256 of what its author signed. */
const hashOf = (op: Row) => sha(canonicalOp(op, sha(String(op.sealed)), sha(String(op.wrapped_key))));

async function signOp(keys: Device["keys"], op: Row): Promise<Row> {
  const text = canonicalOp(op, sha(String(op.sealed)), sha(String(op.wrapped_key)));
  const sig = new Uint8Array(await webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keys.privateKey, new TextEncoder().encode(text)));
  return { ...op, sig: Buffer.from(sig).toString("base64url") };
}

/** A ring member the way #101 describes one: it holds the ring key (which
 *  the edge never sees), names a secret by HMAC(ring key, path), seals the
 *  path and value under a fresh data key wrapped by the ring key, and chains
 *  its ops by hash. */
function member(dev: Device, clock: { ms: number }, ring: Buffer = Buffer.from(webcrypto.getRandomValues(new Uint8Array(32)))) {
  let seq = 0;
  let prev = "";
  const keyOf = (path: string) => createHmac("sha256", ring).update(path).digest("base64url");
  const gcm = (key: Buffer, plain: Buffer, ad: string) => {
    const iv = Buffer.from(webcrypto.getRandomValues(new Uint8Array(12)));
    const c = createCipheriv("aes-256-gcm", key, iv).setAAD(Buffer.from(ad));
    return Buffer.concat([iv, c.update(plain), c.final(), c.getAuthTag()]);
  };
  /** The next op in this member's chain (or, with `fork`, one that doesn't advance it). */
  async function op(kind: string, path: string, value: string | null, extra: Partial<Row> = {}): Promise<Row> {
    const key = keyOf(path);
    const version = Number(extra.version ?? 1);
    const ad = `harar-op|${key}|${version}`;
    const dataKey = Buffer.from(webcrypto.getRandomValues(new Uint8Array(32)));
    const sealed = gcm(dataKey, Buffer.from(JSON.stringify({ path, value })), ad).toString("base64url");
    const wrapped_key = gcm(ring, dataKey, ad).toString("base64url");
    const { fork, ...fields } = extra;
    const signed = await signOp(dev.keys, { author: dev.id, seq: seq + 1, prev, kind, key, version, sealed, wrapped_key, at: clock.ms, ...fields });
    if (!fork) {
      seq = Number(signed.seq);
      prev = hashOf(signed);
    }
    return signed;
  }
  return { ring, keyOf, op, dev };
}

/** Opens a stored op with a candidate ring key; throws unless it's the one. */
function open(op: Row, ring: Buffer): { path: string; value: string | null } {
  const ad = `harar-op|${op.key}|${op.version}`;
  const ungcm = (key: Buffer, sealed: Buffer) => {
    const d = createDecipheriv("aes-256-gcm", key, sealed.subarray(0, 12)).setAAD(Buffer.from(ad));
    d.setAuthTag(sealed.subarray(sealed.length - 16));
    return Buffer.concat([d.update(sealed.subarray(12, sealed.length - 16)), d.final()]);
  };
  const dataKey = ungcm(ring, Buffer.from(String(op.wrapped_key), "base64url"));
  return JSON.parse(ungcm(dataKey, Buffer.from(String(op.sealed), "base64url")).toString());
}

/** Checks each author's chain as a member would: seq from 1 with no gaps,
 *  prev = the hash before, the hash recomputed and the signature verified,
 *  compacted ops included (they keep their ciphertext's sha256). */
async function checkOps(ops: Row[], devices: Device[]) {
  const byAuthor = new Map<string, Row[]>();
  for (const op of ops) byAuthor.set(String(op.author), [...(byAuthor.get(String(op.author)) ?? []), op]);
  for (const [author, chain] of byAuthor) {
    const dev = devices.find((d) => d.id === author);
    assert.ok(dev, `a device for ${author}`);
    let prev = "";
    for (const [i, op] of chain.entries()) {
      assert.equal(op.seq, i + 1, `${author}'s ops have no gaps`);
      assert.equal(op.prev, prev, `${author} op ${op.seq}'s prev`);
      if (!op.compacted) {
        assert.equal(op.sealed_sha256, sha(String(op.sealed)));
        assert.equal(op.wrapped_key_sha256, sha(String(op.wrapped_key)));
      }
      const text = canonicalOp(op, String(op.sealed_sha256), String(op.wrapped_key_sha256));
      assert.equal(op.hash, sha(text), `${author} op ${op.seq}'s hash`);
      const ok = await webcrypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, dev.keys.publicKey, Buffer.from(String(op.sig), "base64url"), new TextEncoder().encode(text));
      assert.ok(ok, `${author} op ${op.seq}'s signature`);
      prev = String(op.hash);
    }
  }
}

/** Pages through POST /v1/sync from `since` to the end. */
async function pull(dev: Device, since: Record<string, number> = {}) {
  const ops: Row[] = [];
  for (;;) {
    const page = await dev.as("POST", "/v1/sync", { since });
    assert.equal(page.status, 200);
    ops.push(...page.body.ops);
    since = page.body.next;
    if (!page.body.more) return { ops, since };
  }
}

/** The op as sent, from a row or served op: the fields a member signed. */
const sent = (op: Row) => Object.fromEntries(["author", "seq", "prev", "kind", "key", "version", "sealed", "wrapped_key", "at", "sig"].map((k) => [k, op[k]]));

/** The secret part of a token: what the edge must never store or log. */
const secretOf = (token: string) => token.slice("harar_edge_".length + 17);

/** The log is a hash chain: recompute it from the rows. */
function checkChain(rows: Row[]) {
  let prev = "";
  for (const r of rows) {
    assert.equal(r.prev_hash, prev);
    const want = createHash("sha256")
      .update(prev + "\n" + JSON.stringify([Number(r.seq), r.at, r.actor, r.action, r.resource, r.decision, r.reason, r.ip]))
      .digest("hex");
    assert.equal(r.hash, want, `row ${r.seq}'s hash`);
    prev = String(r.hash);
  }
}

for (const backend of backends) {
  describe(`harar edge on ${backend.name}`, () => {
    test("the setup code pairs one device, once; later devices need a code a paired device made", async () => {
      const { call, clock } = await setup(backend);
      const mac = await device(call, clock);
      assert.equal(mac.paired.status, 201);
      assert.match(mac.id, /^d-[0-9a-f]{16}$/);
      const again = await device(call, clock);
      assert.deepEqual([again.paired.status, again.paired.body.error], [403, "code_used"]);
      const wrong = await device(call, clock, "not-a-code");
      assert.deepEqual([wrong.paired.status, wrong.paired.body.error], [403, "bad_code"]);

      const pairing = await mac.as("POST", "/v1/pairings");
      assert.equal(pairing.status, 201);
      const phone = await device(call, clock, pairing.body.code, "phone");
      assert.equal(phone.paired.status, 201);
      const reuse = await device(call, clock, pairing.body.code, "thief");
      assert.deepEqual([reuse.paired.status, reuse.paired.body.error], [403, "bad_code"]);

      // Two devices racing with one code: exactly one is paired.
      const raced = await mac.as("POST", "/v1/pairings");
      const racers = await Promise.all([device(call, clock, raced.body.code, "racer-1"), device(call, clock, raced.body.code, "racer-2")]);
      assert.deepEqual(racers.map((r) => r.paired.status).sort(), [201, 403]);

      const late = await mac.as("POST", "/v1/pairings");
      clock.ms += 11 * 60 * 1000;
      const expired = await device(call, clock, late.body.code, "late");
      assert.deepEqual([expired.paired.status, expired.paired.body.error], [403, "bad_code"]);

      const devices = await phone.as("GET", "/v1/devices");
      assert.deepEqual(
        devices.body.devices.map((d: Row) => d.name).filter((n: string) => !n.startsWith("racer")),
        ["mac", "phone"],
      );
      assert.equal(devices.body.devices.filter((d: Row) => String(d.name).startsWith("racer")).length, 1);
      assert.deepEqual(devices.body.devices.slice(0, 2).map((d: Row) => d.paired_by), ["setup", mac.id]);
    });

    test("a used or wrong code is only ever a refusal in the log, never allowed first", async () => {
      const { call, clock } = await setup(backend);
      const mac = await device(call, clock);
      const used = await mac.as("POST", "/v1/pairings");
      await device(call, clock, used.body.code, "phone");
      await device(call, clock, SETUP, "again");
      await device(call, clock, used.body.code, "thief");
      await device(call, clock, "wrong", "guess");
      const log = (await mac.as("GET", "/v1/log")).body.log;
      assert.deepEqual(
        log.filter((r: Row) => r.action === "pair").map((r: Row) => [r.decision, r.resource, r.reason]),
        [
          ["allow", "mac", ""],
          ["allow", "phone", ""],
          ["deny", "", "code_used"],
          ["deny", "", "bad_code"],
          ["deny", "", "bad_code"],
        ],
      );
    });

    test("a device request is only good signed, fresh, once, by a device still paired", async () => {
      const { call, clock } = await setup(backend);
      const mac = await device(call, clock);
      assert.equal((await mac.as("GET", "/v1/secrets")).status, 200);

      const signed = await mac.sign("PUT", "/v1/secrets/a", { value: "x" });
      const tampered = await call("PUT", "/v1/secrets/a", { body: { value: "evil" }, headers: signed.headers });
      assert.deepEqual([tampered.status, tampered.body.error], [401, "bad_signature"]);

      const ok = await call("PUT", "/v1/secrets/a", { body: { value: "x" }, headers: signed.headers });
      assert.equal(ok.status, 200);
      const replay = await call("PUT", "/v1/secrets/a", { body: { value: "x" }, headers: signed.headers });
      assert.deepEqual([replay.status, replay.body.error], [401, "replay"]);

      const old = await mac.sign("GET", "/v1/secrets", undefined, { time: Math.floor(clock.ms / 1000) - 400 });
      assert.deepEqual((await call("GET", "/v1/secrets", { headers: old.headers })).body.error, "clock");

      const other = await mac.sign("GET", "/v1/secrets");
      const elsewhere = await call("GET", "/v1/tokens", { headers: other.headers });
      assert.deepEqual([elsewhere.status, elsewhere.body.error], [401, "bad_signature"], "a signature is for one method and path");

      const pairing = await mac.as("POST", "/v1/pairings");
      const phone = await device(call, clock, pairing.body.code, "phone");
      assert.equal((await phone.as("DELETE", `/v1/devices/${mac.id}`)).status, 200);
      const gone = await mac.as("GET", "/v1/secrets");
      assert.deepEqual([gone.status, gone.body.error], [401, "unknown_device"]);
      const last = await phone.as("DELETE", `/v1/devices/${phone.id}`);
      assert.deepEqual([last.status, last.body.error], [409, "last_device"]);
    });

    test("a service token resolves exactly what it may read, all or nothing, and writes only its patterns", async () => {
      const { call, clock, sql } = await setup(backend);
      const mac = await device(call, clock);
      for (const [path, value] of [
        ["prod/shop/STRIPE_KEY", "sk_live_real"],
        ["prod/shop/OTHER", "other"],
        ["prod/site/DATABASE_URL", "postgres://secret"],
      ]) {
        assert.equal((await mac.as("PUT", `/v1/secrets/${path}`, { value })).status, 200);
      }
      const made = await mac.as("POST", "/v1/tokens", { name: "railway-shop", read: ["prod/shop/*"], write: ["prod/shop/ROTATED"] });
      assert.equal(made.status, 201);
      assert.match(made.body.token, /^harar_edge_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$/);
      const bearer = { authorization: `Bearer ${made.body.token}` };

      const resolved = await call("POST", "/v1/resolve", { body: { refs: ["harar://prod/shop/STRIPE_KEY", "harar://prod/shop/OTHER"] }, headers: bearer });
      assert.deepEqual(resolved, { status: 200, body: { values: ["sk_live_real", "other"] } });

      const mixed = await call("POST", "/v1/resolve", { body: { refs: ["harar://prod/shop/STRIPE_KEY", "harar://prod/site/DATABASE_URL"] }, headers: bearer });
      assert.deepEqual([mixed.status, mixed.body.error, mixed.body.values], [403, "not_allowed", undefined]);
      assert.ok(!JSON.stringify(mixed.body).includes("sk_live_real"), "nothing leaks from a refused resolve");

      for (const ref of ["prod/shop/STRIPE_KEY", "op://Prod/Stripe/credential", "harar://", "harar://a b", "harar://../x"]) {
        const bad = await call("POST", "/v1/resolve", { body: { refs: [ref] }, headers: bearer });
        assert.deepEqual([bad.status, bad.body.error], [400, "not_a_reference"], ref);
      }

      assert.equal((await call("PUT", "/v1/secrets/prod/shop/ROTATED", { body: { value: "new" }, headers: bearer })).status, 200);
      const outside = await call("PUT", "/v1/secrets/prod/shop/STRIPE_KEY", { body: { value: "evil" }, headers: bearer });
      assert.deepEqual([outside.status, outside.body.error], [403, "not_allowed"]);
      const tokens = await call("POST", "/v1/tokens", { body: { name: "more", read: ["*"] }, headers: bearer });
      assert.deepEqual([tokens.status, tokens.body.error], [403, "devices_only"]);
      assert.equal((await call("GET", "/v1/log", { headers: bearer })).status, 403);

      // The database holds the token's hash, never the token or a value.
      const dump = JSON.stringify(await sql.all(`SELECT * FROM harar_tokens`)) + JSON.stringify(await sql.all(`SELECT * FROM harar_secrets`));
      for (const plain of [secretOf(made.body.token), "sk_live_real", "postgres://secret"]) assert.ok(!dump.includes(plain), plain);

      const listed = await mac.as("GET", "/v1/tokens");
      assert.deepEqual(listed.body.tokens.map((t: Row) => [t.name, t.read, t.revoked_at]), [["railway-shop", ["prod/shop/*"], null]]);
      assert.ok(!JSON.stringify(listed.body).includes(secretOf(made.body.token)));

      assert.equal((await mac.as("DELETE", `/v1/tokens/${made.body.id}`)).status, 200);
      const revoked = await call("POST", "/v1/resolve", { body: { refs: ["harar://prod/shop/STRIPE_KEY"] }, headers: bearer });
      assert.deepEqual([revoked.status, revoked.body.error], [401, "revoked"]);

      const brief = await mac.as("POST", "/v1/tokens", { name: "ci", read: ["prod/*"], expires_in: 60 });
      clock.ms += 61_000;
      const expired = await call("POST", "/v1/resolve", { body: { refs: ["harar://prod/shop/OTHER"] }, headers: { authorization: `Bearer ${brief.body.token}` } });
      assert.deepEqual([expired.status, expired.body.error], [401, "expired"]);
      const forged = await call("POST", "/v1/resolve", {
        body: { refs: ["harar://prod/shop/OTHER"] },
        headers: { authorization: `Bearer harar_edge_${brief.body.id}_${"A".repeat(43)}` },
      });
      assert.deepEqual([forged.status, forged.body.error], [401, "bad_token"]);
    });

    test("versions count up, rotate and delete are versions too, and a sealed value only opens in its own row", async () => {
      const { call, clock, sql } = await setup(backend);
      const mac = await device(call, clock);
      assert.deepEqual((await mac.as("PUT", "/v1/secrets/a/KEY", { value: "one" })).body, { path: "a/KEY", version: 1 });
      assert.deepEqual((await mac.as("PUT", "/v1/secrets/a/KEY", { value: "two", rotate: true })).body, { path: "a/KEY", version: 2 });
      assert.equal((await mac.as("PUT", "/v1/secrets/b/KEY", { value: "bee" })).status, 200);
      assert.deepEqual((await mac.as("POST", "/v1/resolve", { refs: ["harar://a/KEY"] })).body.values, ["two"]);

      const listed = await mac.as("GET", "/v1/secrets");
      assert.deepEqual(listed.body.secrets.map((s: Row) => [s.path, s.version]), [["a/KEY", 2], ["b/KEY", 1]]);
      assert.ok(!JSON.stringify(listed.body).includes("two"));

      // Moving b's ciphertext into a's newest row must not decrypt.
      const [b] = await sql.all(`SELECT sealed, wrapped_key FROM harar_secrets WHERE path = 'b/KEY'`);
      await sql.query(`UPDATE harar_secrets SET sealed = ?, wrapped_key = ? WHERE path = 'a/KEY' AND version = 2`, [b.sealed, b.wrapped_key]);
      const moved = await mac.as("POST", "/v1/resolve", { refs: ["harar://a/KEY"] });
      assert.equal(moved.status, 500);
      assert.ok(!JSON.stringify(moved.body).includes("bee"));

      assert.deepEqual((await mac.as("DELETE", "/v1/secrets/b/KEY")).body, { path: "b/KEY", version: 2 });
      const deleted = await mac.as("POST", "/v1/resolve", { refs: ["harar://b/KEY"] });
      assert.deepEqual([deleted.status, deleted.body.error], [404, "not_found"]);
      assert.deepEqual((await mac.as("GET", "/v1/secrets")).body.secrets.map((s: Row) => s.path), ["a/KEY"]);
      assert.equal((await mac.as("PUT", "/v1/secrets/a%20b", { value: "v" })).body.error, "bad_path");
    });

    test("every request is one row in a hash chain; values, tokens and codes never appear in it", async () => {
      const { call, clock, sql } = await setup(backend);
      const mac = await device(call, clock);
      await mac.as("PUT", "/v1/secrets/prod/KEY", { value: "the-value" });
      await mac.as("PUT", "/v1/secrets/prod/KEY", { value: "the-value-2", rotate: true });
      const made = await mac.as("POST", "/v1/tokens", { name: "svc", read: ["prod/*"] });
      await call("POST", "/v1/resolve", { body: { refs: ["harar://prod/KEY"] }, headers: { authorization: `Bearer ${made.body.token}` } });
      await call("PUT", "/v1/secrets/prod/KEY", { body: { value: "evil" }, headers: { authorization: `Bearer ${made.body.token}` } });
      await call("GET", "/v1/secrets");

      const log = await mac.as("GET", "/v1/log?after=0");
      assert.deepEqual(
        log.body.log.map((r: Row) => [r.actor, r.action, r.resource, r.decision, r.reason]),
        [
          ["anonymous", "pair", "mac", "allow", ""],
          [`device:${mac.id}`, "secret.put", "prod/KEY", "allow", ""],
          [`device:${mac.id}`, "secret.rotate", "prod/KEY", "allow", ""],
          [`device:${mac.id}`, "token.create", "svc", "allow", ""],
          [`token:${made.body.id}`, "resolve", "prod/KEY", "allow", ""],
          [`token:${made.body.id}`, "secret.put", "", "deny", "not_allowed"],
          ["anonymous", "secret.list", "", "deny", "devices_only"],
          [`device:${mac.id}`, "log.read", "", "allow", ""],
        ],
      );
      assert.ok(log.body.log.every((r: Row) => r.ip === "203.0.113.7"));
      checkChain(log.body.log);
      const all = JSON.stringify(await sql.all(`SELECT * FROM harar_log`));
      for (const secret of ["the-value", "evil", secretOf(made.body.token), SETUP]) assert.ok(!all.includes(secret), secret);

      // Editing one row breaks the chain from there on.
      await sql.query(`UPDATE harar_log SET resource = 'prod/OTHER' WHERE seq = 5`);
      const edited = (await mac.as("GET", "/v1/log?after=0")).body.log;
      assert.throws(() => checkChain(edited), /row 5's hash/);
    });

    test("the log ships to every sink as OTLP; a sink that's down holds rows until it's back", async () => {
      const a = sink();
      const { call, clock, sql } = await setup(backend, {
        fetch: a.net,
        log: { sinks: [{ otlp: "https://logs.other-account.example/", headers: { authorization: "Bearer ingest-only" } }] },
      });
      const mac = await device(call, clock);
      await mac.as("PUT", "/v1/secrets/k", { value: "v" });
      assert.equal(a.got[0].url, "https://logs.other-account.example/v1/logs");
      assert.equal(a.got[0].headers.authorization, "Bearer ingest-only");
      const resource = a.got[0].body.resourceLogs[0].resource.attributes;
      assert.deepEqual(resource.find((x: any) => x.key === "service.name").value, { stringValue: "harar-edge" });
      const records = a.records();
      assert.deepEqual(
        records.map((r: any) => Object.fromEntries(r.attributes.map((x: any) => [x.key, x.value.stringValue ?? x.value.intValue]))).map((x: any) => [x["harar.seq"], x["harar.action"], x["harar.resource"]]),
        [["1", "pair", "mac"], ["2", "secret.put", "k"]],
      );
      assert.equal(records[1].timeUnixNano, String(BigInt(clock.ms) * 1000000n));

      a.state.down = true;
      assert.equal((await mac.as("PUT", "/v1/secrets/k", { value: "v2" })).status, 200, "serve: answers while the sink is down");
      assert.deepEqual((await sql.all(`SELECT seq FROM harar_log WHERE shipped = 0`)).map((r) => Number(r.seq)), [3]);
      a.state.down = false;
      await mac.as("GET", "/v1/secrets");
      assert.deepEqual(a.records().map((r: any) => r.attributes[0].value.intValue), ["1", "2", "3", "4"]);
      assert.equal((await sql.all(`SELECT seq FROM harar_log WHERE shipped = 0`)).length, 0);
    });

    test("refuse: with the sinks down nothing happens, and the edge says why", async () => {
      const a = sink();
      const { call, clock, sql } = await setup(backend, { fetch: a.net, log: { sinks: [{ otlp: "https://logs.example" }], whenSinksFail: "refuse" } });
      const mac = await device(call, clock);
      a.state.down = true;
      const put = await mac.as("PUT", "/v1/secrets/k", { value: "v" });
      assert.deepEqual([put.status, put.body.error], [503, "log_unavailable"]);
      assert.equal((await sql.all(`SELECT * FROM harar_secrets`)).length, 0, "the secret was not written");
      a.state.down = false;
      assert.equal((await mac.as("PUT", "/v1/secrets/k", { value: "v" })).status, 200);
      assert.equal((await sql.all(`SELECT * FROM harar_secrets`)).length, 1);
    });

    test("events picks which allowed actions are logged; refusals always are", async () => {
      const { call, clock } = await setup(backend, { log: { events: ["resolve", "secret.put"] } });
      const mac = await device(call, clock);
      await mac.as("PUT", "/v1/secrets/k", { value: "v" });
      await mac.as("GET", "/v1/secrets");
      await call("GET", "/v1/secrets");
      await mac.as("POST", "/v1/resolve", { refs: ["harar://k"] });
      const log = await mac.as("GET", "/v1/log");
      assert.deepEqual(log.body.log.map((r: Row) => [r.action, r.decision]), [["secret.put", "allow"], ["secret.list", "deny"], ["resolve", "allow"]]);
    });

    test("behind a mount (Supabase's /harar-edge), a device signs the API path and is let in", async () => {
      const { call, clock } = await setup(backend, { basePath: "/harar-edge" });
      const mac = await device(call, clock);
      assert.equal(mac.paired.status, 201);
      assert.equal((await mac.as("PUT", "/v1/secrets/k", { value: "v" })).status, 200);
      assert.deepEqual((await mac.as("POST", "/v1/resolve", { refs: ["harar://k"] })).body.values, ["v"]);
    });

    test("health says the version and the logging, and a base path mounts the API", async () => {
      const { api } = await setup(backend, { basePath: "/harar-edge" });
      const health = await api.fetch(new Request("https://x.supabase.co/harar-edge/v1/health"));
      const id = createHash("sha256").update(Buffer.concat([Buffer.from("harar-edge-key-id\n"), Buffer.from(KEY, "base64")])).digest("hex").slice(0, 16);
      assert.deepEqual(await health.json(), { version: VERSION, key: { ready: true, id }, log: { sinks: 0, whenSinksFail: "serve" } });
      assert.equal(await keyId(Buffer.from(KEY, "base64")), id);
      assert.equal((await api.fetch(new Request("https://x.supabase.co/v1/health"))).status, 404);
    });

    test("health says when the platform gave the edge no usable key, and the edge serves nothing sealed", async () => {
      const { call, clock } = await setup(backend, { key: "" });
      assert.deepEqual((await call("GET", "/v1/health")).body.key, { ready: false, id: null });
      const mac = await device(call, clock);
      const put = await mac.as("PUT", "/v1/secrets/k", { value: "v" });
      assert.deepEqual([put.status, put.body.error], [500, "edge_key"]);
    });

    test("the recovery copy is kept for devices only, replaced by the newest, and every read is logged", async () => {
      const { call, clock } = await setup(backend);
      const mac = await device(call, clock);
      assert.deepEqual((await mac.as("GET", "/v1/recovery")).body.error, "not_found");
      assert.equal((await mac.as("PUT", "/v1/recovery", { sealed: "age-encrypted-1" })).status, 200);
      assert.equal((await mac.as("PUT", "/v1/recovery", { sealed: "age-encrypted-2" })).status, 200);
      const got = await mac.as("GET", "/v1/recovery");
      assert.deepEqual([got.status, got.body.sealed, got.body.by], [200, "age-encrypted-2", mac.id]);

      const made = await mac.as("POST", "/v1/tokens", { name: "svc", read: ["*"], write: ["*"] });
      const bearer = { authorization: `Bearer ${made.body.token}` };
      assert.equal((await call("GET", "/v1/recovery", { headers: bearer })).body.error, "devices_only");
      assert.equal((await call("PUT", "/v1/recovery", { body: { sealed: "evil" }, headers: bearer })).body.error, "devices_only");
      assert.equal((await mac.as("GET", "/v1/recovery")).body.sealed, "age-encrypted-2");

      const log = (await mac.as("GET", "/v1/log")).body.log.filter((r: Row) => String(r.action).startsWith("recovery"));
      assert.deepEqual(
        log.map((r: Row) => [r.action, r.decision, r.reason]),
        [
          ["recovery.read", "deny", "not_found"],
          ["recovery.set", "allow", ""],
          ["recovery.set", "allow", ""],
          ["recovery.read", "allow", ""],
          ["recovery.read", "deny", "devices_only"],
          ["recovery.set", "deny", "devices_only"],
          ["recovery.read", "allow", ""],
        ],
      );
    });

    // ------------------------------------------------------------ sync

    /** Two paired devices, each a member of one ring. */
    async function ring(backend: Backend, extra: Partial<Config> = {}) {
      const env = await setup(backend, extra);
      const mac = await device(env.call, env.clock);
      const pairing = await mac.as("POST", "/v1/pairings");
      const phone = await device(env.call, env.clock, pairing.body.code, "phone");
      const macM = member(mac, env.clock);
      const phoneM = member(phone, env.clock, macM.ring);
      const log = async () => (await env.sql.all(`SELECT action, resource, decision, reason FROM harar_log ORDER BY seq`)).map((r) => [r.action, r.resource, r.decision, r.reason]);
      return { ...env, mac, phone, macM, phoneM, log };
    }

    test("sync: ops round-trip between members exactly as sent, in each author's order, and a retried PUT is a no-op", async () => {
      const { mac, phone, macM, phoneM, log } = await ring(backend);
      const ops = [await macM.op("put", "prod/shop/STRIPE_KEY", "sk_live_1"), await macM.op("put", "prod/site/DB", "postgres://x"), await macM.op("rotate", "prod/shop/STRIPE_KEY", "sk_live_2", { version: 2 })];
      const put = await mac.as("PUT", "/v1/sync", { ops });
      assert.deepEqual(put, { status: 200, body: { stored: 3, duplicates: 0 } });

      const got = await phone.as("POST", "/v1/sync", { since: {} });
      assert.equal(got.status, 200);
      assert.deepEqual(got.body.ops.map(sent), ops);
      assert.deepEqual(got.body.next, { [mac.id]: 3 });
      assert.equal(got.body.more, false);
      assert.ok(got.body.ops.every((o: Row) => o.compacted === false));
      await checkOps(got.body.ops, [mac, phone]);
      assert.deepEqual(got.body.ops.map((o: Row) => open(o, phoneM.ring)), [
        { path: "prod/shop/STRIPE_KEY", value: "sk_live_1" },
        { path: "prod/site/DB", value: "postgres://x" },
        { path: "prod/shop/STRIPE_KEY", value: "sk_live_2" },
      ]);
      assert.equal(got.body.ops[0].key, got.body.ops[2].key, "one path, one key");

      const mine = await phoneM.op("delete", "prod/site/DB", null, { version: 2 });
      assert.equal((await phone.as("PUT", "/v1/sync", { ops: [mine] })).body.stored, 1);
      const back = await mac.as("POST", "/v1/sync", { since: got.body.next });
      assert.deepEqual(back.body.ops.map(sent), [mine]);
      assert.deepEqual(back.body.next, { [mac.id]: 3, [phone.id]: 1 });

      // A retried PUT (the answer was lost): nothing new, nothing refused.
      assert.deepEqual((await mac.as("PUT", "/v1/sync", { ops })).body, { stored: 0, duplicates: 3 });
      const next = await macM.op("put", "a", "b");
      assert.deepEqual((await mac.as("PUT", "/v1/sync", { ops: [...ops.slice(1), next] })).body, { stored: 1, duplicates: 2 });

      assert.deepEqual((await log()).filter((r) => String(r[0]).startsWith("sync")), [
        ["sync.put", `${mac.id}:1-3`, "allow", ""],
        ["sync.read", "", "allow", ""],
        ["sync.put", `${phone.id}:1-1`, "allow", ""],
        ["sync.read", "", "allow", ""],
        ["sync.put", "", "allow", ""],
        ["sync.put", `${mac.id}:4-4`, "allow", ""],
      ]);
    });

    test("sync: the edge holds only what members sent, and nothing it holds opens an op", async () => {
      const { sql, mac, phone, macM, phoneM } = await ring(backend);
      const values = ["sk_live_never_on_the_edge", "postgres://user:pw@db/never"];
      const paths = ["prod/shop/STRIPE_SECRET_PATH", "prod/site/DATABASE_URL_PATH"];
      const ops = [await macM.op("put", paths[0], values[0]), await macM.op("put", paths[1], values[1])];
      await mac.as("PUT", "/v1/sync", { ops });
      await phone.as("POST", "/v1/sync", {});

      // The rows are the ops as sent, plus what the edge derives from them.
      const rows = await sql.all(`SELECT * FROM harar_ops ORDER BY seq`);
      assert.deepEqual(
        rows.map((r) => ({ ...r, seq: Number(r.seq), version: Number(r.version), at: Number(r.at) })),
        ops.map((op) => {
          const sealedSha256 = sha(String(op.sealed));
          const wrappedKeySha256 = sha(String(op.wrapped_key));
          return { ...op, sealed_sha256: sealedSha256, wrapped_key_sha256: wrappedKeySha256, hash: hashOf(op), stored_at: rows[0].stored_at, batch: null };
        }),
      );

      // No value or path anywhere in the database: the edge never learns
      // secret names, only HMACs of them.
      const tables = ["harar_meta", "harar_devices", "harar_pairings", "harar_nonces", "harar_secrets", "harar_tokens", "harar_log", "harar_ops"];
      const dump = JSON.stringify(await Promise.all(tables.map((t) => sql.all(`SELECT * FROM ${t}`))));
      for (const plain of [...values, ...paths]) assert.ok(!dump.includes(plain), plain);
      assert.equal((await sql.all(`SELECT * FROM harar_secrets`)).length, 0, "sync never touches what the edge serves");

      // Every 32-byte string the database holds, and the edge key itself: none
      // opens an op. The ring key, which only members have, does.
      const candidates = [Buffer.from(KEY, "base64")];
      for (const m of dump.matchAll(/[A-Za-z0-9+/_-]{40,}={0,2}/g)) {
        for (const enc of ["base64url", "base64", "hex"] as const) {
          const b = Buffer.from(m[0], enc);
          if (b.length === 32) candidates.push(b);
        }
      }
      assert.ok(candidates.length > 20, `tried ${candidates.length} candidates`);
      for (const op of ops) {
        for (const c of candidates) assert.throws(() => open(op, c));
        assert.equal(open(op, phoneM.ring).value !== null, true);
      }
    });

    test("sync: a bad signature, seq, prev or author, a fork, a future time or a service token is refused with one deny row, and nothing is stored", async () => {
      const { call, sql, clock, mac, phone, macM, phoneM, log } = await ring(backend);
      const first = await macM.op("put", "k", "v1");
      assert.equal((await mac.as("PUT", "/v1/sync", { ops: [first] })).status, 200);
      const stored = async () => (await sql.all(`SELECT seq FROM harar_ops`)).length;

      const tampered = { ...(await macM.op("put", "k", "v2", { fork: true })), sealed: String(first.sealed) };
      const wrongSeq = await macM.op("put", "k", "v2", { fork: true, seq: 3 });
      const wrongPrev = await macM.op("put", "k", "v2", { fork: true, prev: sha("not the previous op") });
      const fork = await macM.op("put", "k", "other", { fork: true, seq: 1, prev: "" });
      const future = await macM.op("put", "k", "v2", { fork: true, at: clock.ms + 6 * 60 * 1000 });
      const stranger = await signOp(mac.keys, { ...(await macM.op("put", "k", "v2", { fork: true })), author: "d-0123456789abcdef" });
      const cases: [string, unknown, string, number][] = [
        ["tampered sealed", { ops: [tampered] }, "bad_op_signature", 403],
        ["seq skips one", { ops: [wrongSeq] }, "wrong_seq", 409],
        ["prev is not the last op", { ops: [wrongPrev] }, "wrong_prev", 409],
        ["another op 1", { ops: [fork] }, "fork", 409],
        ["at in the future", { ops: [future] }, "clock", 400],
        ["not a paired device", { ops: [stranger] }, "unknown_author", 403],
        ["an extra field", { ops: [{ ...first, path: "k" }] }, "bad_op", 400],
        ["no ops", { ops: [] }, "bad_request", 400],
      ];
      for (const [what, body, code, status] of cases) {
        const before = (await log()).length;
        const res = await mac.as("PUT", "/v1/sync", body);
        assert.deepEqual([res.status, res.body.error], [status, code], what);
        assert.deepEqual((await log()).slice(before), [["sync.put", "", "deny", code]], `${what}: one deny row`);
        assert.equal(await stored(), 1, `${what}: nothing stored`);
      }

      // A service token can neither push nor pull, whatever it may read.
      const made = await mac.as("POST", "/v1/tokens", { name: "svc", read: ["*"], write: ["*"] });
      const bearer = { authorization: `Bearer ${made.body.token}` };
      for (const method of ["PUT", "POST"]) {
        const before = (await log()).length;
        const res = await call(method, "/v1/sync", { body: method === "PUT" ? { ops: [await macM.op("put", "k", "v2", { fork: true })] } : { since: {} }, headers: bearer });
        assert.deepEqual([res.status, res.body.error], [403, "devices_only"]);
        assert.deepEqual((await log()).slice(before), [[method === "PUT" ? "sync.put" : "sync.read", "", "deny", "devices_only"]]);
      }
      assert.equal(await stored(), 1);

      // Once the phone is unpaired, its ops are refused, even relayed by the
      // Mac and signed while it was still paired; what it sent before stays.
      const early = await phoneM.op("put", "p", "1");
      const late = await phoneM.op("put", "p", "2");
      assert.equal((await phone.as("PUT", "/v1/sync", { ops: [early] })).status, 200);
      assert.equal((await mac.as("DELETE", `/v1/devices/${phone.id}`)).status, 200);
      const relayed = await mac.as("PUT", "/v1/sync", { ops: [late] });
      assert.deepEqual([relayed.status, relayed.body.error], [403, "unknown_author"]);
      assert.deepEqual((await log()).at(-1), ["sync.put", "", "deny", "unknown_author"]);
      assert.deepEqual((await pull(mac)).ops.map((o) => [o.author, o.seq]), [[mac.id, 1], [phone.id, 1]].sort());
    });

    test("sync: one bad op refuses the whole batch, and a batch racing another for the same seq is stored whole or not at all", async () => {
      const { sql, mac, macM, phone } = await ring(backend);
      const good = [await macM.op("put", "a", "1"), await macM.op("put", "b", "2")];
      const bad = { ...(await macM.op("put", "c", "3", { fork: true })), sig: String(good[0].sig) };
      const refused = await mac.as("PUT", "/v1/sync", { ops: [...good, bad] });
      assert.deepEqual([refused.status, refused.body.error], [403, "bad_op_signature"]);
      assert.equal((await sql.all(`SELECT seq FROM harar_ops`)).length, 0);
      assert.equal((await mac.as("PUT", "/v1/sync", { ops: good })).body.stored, 2);

      // Two batches of two ops, both continuing the Mac's chain from op 2, sent
      // at once: both pass the checks, one gets op 3's place first, and the
      // other must leave nothing behind (its op 4 included).
      const batch = async (name: string) => {
        const three = await macM.op("put", name, "3", { fork: true });
        return [three, await macM.op("put", name, "4", { fork: true, seq: 4, prev: hashOf(three) })];
      };
      const [xBatch, yBatch] = [await batch("x"), await batch("y")];
      const [rx, ry] = await Promise.all([mac.as("PUT", "/v1/sync", { ops: xBatch }), mac.as("PUT", "/v1/sync", { ops: yBatch })]);
      assert.deepEqual([rx.status, ry.status].sort(), [200, 409]);
      assert.ok(["sync_busy", "fork"].includes((rx.status === 409 ? rx : ry).body.error));
      const winner = rx.status === 200 ? xBatch : yBatch;
      const rows = (await pull(phone)).ops;
      assert.deepEqual(rows.map(sent), [...good, ...winner]);
      assert.equal((await sql.all(`SELECT seq FROM harar_ops WHERE batch IS NOT NULL`)).length, 0, "the loser left nothing behind");
    });

    test("sync: a batch still being written is invisible, one that fails part-way is taken out whole, and one a crashed request left is cleared after a minute", async () => {
      const { sql, clock, mac, macM, phone, phoneM } = await ring(backend);
      const op = await macM.op("put", "a", "1");
      await sql.query(
        `INSERT INTO harar_ops (author, seq, prev, kind, key, version, sealed, wrapped_key, sealed_sha256, wrapped_key_sha256, at, sig, hash, stored_at, batch)
         VALUES (?, 1, '', 'put', ?, 1, 'x', 'y', 's', 'w', 0, 'sig', 'stale', ?, 'crashed')`,
        [mac.id, op.key, new Date(clock.ms).toISOString()],
      );
      assert.deepEqual((await phone.as("POST", "/v1/sync", { since: {} })).body, { ops: [], next: {}, more: false });
      // The phone's op goes in first, then the Mac's hits the stale row: the
      // phone's must be taken out again, not left half-written.
      const theirs = await phoneM.op("put", "b", "2", { fork: true });
      const blocked = await mac.as("PUT", "/v1/sync", { ops: [theirs, op] });
      assert.deepEqual([blocked.status, blocked.body.error], [409, "sync_busy"]);
      assert.deepEqual((await sql.all(`SELECT hash FROM harar_ops`)).map((r) => r.hash), ["stale"], "only the crashed row");
      clock.ms += 2 * 60 * 1000;
      const again = await signOp(mac.keys, { ...op, at: clock.ms });
      assert.equal((await mac.as("PUT", "/v1/sync", { ops: [again] })).status, 200);
      assert.deepEqual((await pull(phone)).ops.map(sent), [again]);
    });

    test("sync: pages are capped by ops and by bytes, and following next reads every op once", async () => {
      const { mac, phone, macM, phoneM } = await ring(backend);
      const macOps: Row[] = [];
      for (let i = 0; i < 150; i++) macOps.push(await macM.op("put", `k${i}`, `v${i}`));
      for (let i = 0; i < 150; i += 100) assert.equal((await mac.as("PUT", "/v1/sync", { ops: macOps.slice(i, i + 100) })).status, 200);
      const phoneOps: Row[] = [];
      for (let i = 0; i < 5; i++) phoneOps.push(await phoneM.op("put", `p${i}`, `v${i}`));
      await phone.as("PUT", "/v1/sync", { ops: phoneOps });

      const first = await phone.as("POST", "/v1/sync", { since: {} });
      assert.equal(first.body.ops.length, 100);
      assert.equal(first.body.more, true);
      const all = await pull(phone);
      const byAuthor = (ops: Row[], id: string) => ops.filter((o) => o.author === id).map(sent);
      assert.deepEqual(byAuthor(all.ops, mac.id), macOps);
      assert.deepEqual(byAuthor(all.ops, phone.id), phoneOps);
      assert.equal(all.ops.length, 155, "every op once");
      assert.deepEqual(all.since, { [mac.id]: 150, [phone.id]: 5 });
      assert.deepEqual((await phone.as("POST", "/v1/sync", { since: all.since })).body, { ops: [], next: all.since, more: false });
      // Only the mac's newer ops after its seq 140.
      assert.deepEqual((await phone.as("POST", "/v1/sync", { since: { [mac.id]: 140, [phone.id]: 5 } })).body.ops.map((o: Row) => o.seq), [141, 142, 143, 144, 145, 146, 147, 148, 149, 150]);

      // Big ops: a page stops once it holds a mebibyte.
      const big: Row[] = [];
      for (let i = 0; i < 25; i++) {
        const o = await macM.op("put", `big${i}`, "x".repeat(32 * 1024));
        big.push(o);
        assert.equal((await mac.as("PUT", "/v1/sync", { ops: [o] })).status, 200);
      }
      const page = await phone.as("POST", "/v1/sync", { since: all.since });
      assert.equal(page.body.more, true);
      assert.ok(page.body.ops.length < 25 && page.body.ops.length >= 20, `${page.body.ops.length} big ops in a page`);
      assert.deepEqual((await pull(phone, all.since)).ops.map(sent), big);

      for (const since of [[], { "not-a-device": 1 }, { [mac.id]: -1 }]) {
        assert.equal((await phone.as("POST", "/v1/sync", { since })).body.error, "bad_request", JSON.stringify(since));
      }
    });

    /** A membership entry as members write one: plain JSON in `sealed`. */
    const entryOp = (m: ReturnType<typeof member>, kind: string, entry: Record<string, unknown>) =>
      m.op(kind, "entry", null, { sealed: Buffer.from(JSON.stringify(entry)).toString("base64url"), wrapped_key: "" });

    test("sync: since names the members; everyone else comes through one discovery cursor", async () => {
      const env = await ring(backend);
      const { mac, phone, macM } = env;
      const pairing = await mac.as("POST", "/v1/pairings");
      const stranger = await device(env.call, env.clock, pairing.body.code, "stranger");
      const strangerM = member(stranger, env.clock);
      await mac.as("PUT", "/v1/sync", { ops: [await macM.op("put", "a", "1"), await macM.op("put", "b", "2")] });
      await stranger.as("PUT", "/v1/sync", { ops: [await strangerM.op("member.add", "x", null), await strangerM.op("put", "s", "1")] });
      const fresh = await phone.as("POST", "/v1/sync", { since: { [mac.id]: 0 }, discover: "" });
      assert.deepEqual(fresh.body.ops.filter((o: Row) => o.author === stranger.id), [], "discovery waits a few seconds, so a batch still committing is never passed over");
      env.clock.ms += 10_000;
      const first = await phone.as("POST", "/v1/sync", { since: { [mac.id]: 0 }, discover: "" });
      assert.equal(first.status, 200);
      assert.equal(typeof first.body.discover, "string", "the edge hands back a discovery cursor");
      assert.deepEqual(first.body.ops.map((o: Row) => [o.author, o.seq]).sort(), [[mac.id, 1], [mac.id, 2], [stranger.id, 1], [stranger.id, 2]].sort());
      assert.deepEqual(Object.keys(first.body.next), [mac.id], "next names only the authors in since");
      const again = await phone.as("POST", "/v1/sync", { since: first.body.next, discover: first.body.discover });
      assert.deepEqual(again.body.ops, [], "nothing discovered twice");
      await stranger.as("PUT", "/v1/sync", { ops: [await strangerM.op("put", "t", "2")] });
      env.clock.ms += 10_000;
      const later = await phone.as("POST", "/v1/sync", { since: first.body.next, discover: first.body.discover });
      assert.deepEqual(later.body.ops.map((o: Row) => [o.author, o.seq]), [[stranger.id, 3]]);
    });

    test("devices: the ring's authority can't be unpaired by another device, nor a member without the authority's removal", async () => {
      const env = await ring(backend);
      const { mac, phone, macM } = env;
      const pairing = await mac.as("POST", "/v1/pairings");
      const stranger = await device(env.call, env.clock, pairing.body.code, "stranger");
      const keys = (d: { id: string }) => ({ device: d.id, name: "n", sign_pub: "s", agree_pub: "a" });
      const found = await entryOp(macM, "member.add", { type: "found", n: 0, prev: "", epoch: 0, id: "i", member: keys(mac), wraps: {} });
      const add = await entryOp(macM, "member.add", { type: "add", n: 1, prev: "h", epoch: 0, id: "i", member: keys(phone), wraps: {} });
      assert.equal((await mac.as("PUT", "/v1/sync", { ops: [found, add] })).status, 200);

      const byPhone = await phone.as("DELETE", `/v1/devices/${mac.id}`);
      assert.deepEqual([byPhone.status, byPhone.body.error], [403, "authority"], "only the authority unpairs itself");
      const early = await mac.as("DELETE", `/v1/devices/${phone.id}`);
      assert.deepEqual([early.status, early.body.error], [409, "needs_removal"], "a member goes only after the authority's removal");
      const remove = await entryOp(macM, "rekey", { type: "remove", n: 2, prev: "h2", epoch: 1, id: "j", removed: [{ device: phone.id, after: 0 }], wraps: {} });
      assert.equal((await mac.as("PUT", "/v1/sync", { ops: [remove] })).status, 200);
      assert.equal((await mac.as("DELETE", `/v1/devices/${phone.id}`)).status, 200);
      assert.equal((await mac.as("DELETE", `/v1/devices/${stranger.id}`)).status, 200, "a device that isn't a member goes as before");
    });

    test("sync: a page shares its room among authors, so one author with many ops never starves the others", async () => {
      const { mac, phone, macM, phoneM } = await ring(backend);
      const [first, second] = mac.id < phone.id ? [macM, phoneM] : [phoneM, macM];
      const [firstDev, secondDev] = mac.id < phone.id ? [mac, phone] : [phone, mac];
      // The author that sorts first has 250 ops; the other has 3.
      const many: Row[] = [];
      for (let i = 0; i < 250; i++) many.push(await first.op("put", `k${i}`, "v"));
      for (let i = 0; i < 250; i += 100) assert.equal((await firstDev.as("PUT", "/v1/sync", { ops: many.slice(i, i + 100) })).status, 200);
      const few = [await second.op("put", "a", "1"), await second.op("put", "b", "2"), await second.op("put", "c", "3")];
      await secondDev.as("PUT", "/v1/sync", { ops: few });
      const page = await phone.as("POST", "/v1/sync", { since: {} });
      assert.ok(page.body.ops.length <= 100);
      assert.deepEqual(page.body.ops.filter((o: Row) => o.author === secondDev.id).map((o: Row) => o.seq), [1, 2, 3], "the second author's ops are on the first page");
      assert.equal(page.body.more, true);
      assert.deepEqual((await pull(phone)).ops.map(sent).length, 253, "and following next still reads every op once");
    });

    test("sync: compaction drops an op only for a later write to its key by the same author", async () => {
      const { clock, mac, phone, macM, phoneM } = await ring(backend);
      const t = clock.ms;
      // The phone's op is the latest it wrote on K; the Mac copies K's name
      // (anyone paired can) and writes later. The phone's op must survive.
      const phones = await phoneM.op("put", "K", "the phone's", { at: t });
      await phone.as("PUT", "/v1/sync", { ops: [phones] });
      const copied = await macM.op("put", "K", "a later write by someone else", { at: t + 1000, key: phones.key });
      await mac.as("PUT", "/v1/sync", { ops: [copied] });
      clock.ms = t + 31 * 24 * 60 * 60 * 1000;
      const { ops } = await pull(mac);
      assert.equal(ops.find((o) => o.author === phone.id)?.compacted, false, "the phone's latest op on K keeps its ciphertext");
    });

    test("sync: compaction drops only superseded put/rotate/delete ops older than 30 days, and every chain still verifies", async () => {
      const { clock, mac, phone, macM, phoneM } = await ring(backend);
      const t = clock.ms;
      const k1 = await macM.op("put", "K", "old", { at: t });
      const k2 = await macM.op("rotate", "K", "new", { at: t + 1000, version: 2 });
      const l1 = await macM.op("put", "L", "only", { at: t });
      const m1 = await macM.op("member.add", "member", "phone", { at: t });
      const m2 = await macM.op("member.add", "member", "laptop", { at: t + 1000 });
      const n1 = await macM.op("put", "N", "gone", { at: t });
      const n2 = await macM.op("delete", "N", null, { at: t + 1000, version: 2 });
      const q1 = await macM.op("put", "Q", "mac: later at", { at: t + 5000 });
      // Same at on one key by one author: the larger seq supersedes.
      const s1 = await macM.op("put", "S", "first", { at: t + 2000 });
      const s2 = await macM.op("rotate", "S", "second", { at: t + 2000, version: 2 });
      await mac.as("PUT", "/v1/sync", { ops: [k1, k2, l1, m1, m2, n1, n2, q1, s1, s2] });
      // The phone writes Q too: another author's op on the key compacts
      // nothing, either way.
      const q2 = await phoneM.op("put", "Q", "phone: earlier at", { at: t + 4000 });
      clock.ms += 1000;
      await phone.as("PUT", "/v1/sync", { ops: [q2] });

      const compacted = async () => (await pull(mac)).ops.filter((o) => o.compacted).map((o) => [o.author, o.seq]);
      clock.ms = t + 29 * 24 * 60 * 60 * 1000;
      assert.deepEqual(await compacted(), [], "nothing before 30 days");
      clock.ms = t + 31 * 24 * 60 * 60 * 1000;
      const ids = (ops: Row[]) => ops.map((o) => [o.author, o.seq]).sort();
      assert.deepEqual((await compacted()).sort(), ids([k1, n1, s1]));

      const { ops } = await pull(phone);
      const kept = ops.filter((o) => !o.compacted);
      assert.deepEqual(ids(kept), ids([k2, l1, m1, m2, n2, q1, s2, q2]));
      for (const o of kept) assert.deepEqual(sent(o), sent([k1, k2, l1, m1, m2, n1, n2, q1, s1, s2, q2].find((x) => x.author === o.author && x.seq === o.seq)!));
      for (const o of ops.filter((x) => x.compacted)) assert.deepEqual([o.sealed, o.wrapped_key], [null, null]);
      await checkOps(ops, [mac, phone]);

      // A member who lost the ring's history still learns each author's latest of each key.
      assert.deepEqual(kept.filter((o) => o.kind !== "member.add").map((o) => open(o, macM.ring).value).sort(), ["mac: later at", "new", "only", null, "second", "phone: earlier at"].sort());
    });

    test("sync: harar's own ops (test/sync-vectors.json, made by the Rust member) are what docs/edge.md says, and the edge takes them as they are", async () => {
      const env = await setup(backend);
      const v = JSON.parse(readFileSync(new URL("./sync-vectors.json", import.meta.url), "utf8"));
      const pub = Buffer.from(v.device.sign_pub, "base64url");
      const curve = { name: "ECDSA", namedCurve: "P-256" };
      const jwk = { kty: "EC", crv: "P-256", x: pub.subarray(1, 33).toString("base64url"), y: pub.subarray(33).toString("base64url"), d: v.device.sign_d };
      const keys = { privateKey: await webcrypto.subtle.importKey("jwk", jwk, curve, false, ["sign"]), publicKey: await webcrypto.subtle.importKey("raw", pub, curve, true, ["verify"]) };
      const ring = Buffer.from(v.ring, "base64url");
      // The ring's subkeys (docs/edge.md §5b): names, and the wrap of data keys.
      const subkey = (info: string) => Buffer.from(hkdfSync("sha256", ring, "harar-ring-v1", info, 32));
      const [nameKey, wrapKey] = [subkey("harar-ring-name"), subkey("harar-ring-wrap")];

      // Read the way this file reads docs/edge.md, not the way harar does.
      for (const [i, { op, canonical, hash, opens }] of v.ops.entries()) {
        assert.equal(canonicalOp(op, sha(op.sealed), sha(op.wrapped_key)), canonical, `op ${op.seq}'s canonical encoding`);
        assert.equal(sha(canonical), hash, `op ${op.seq}'s hash`);
        assert.equal(op.prev, i === 0 ? "" : v.ops[i - 1].hash, `op ${op.seq}'s prev`);
        const sig = Buffer.from(op.sig, "base64url");
        assert.ok(await webcrypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, keys.publicKey, sig, new TextEncoder().encode(canonical)), `op ${op.seq}'s signature`);
        if (opens) {
          assert.deepEqual(open(op, wrapKey), opens, `op ${op.seq} opens with the ring's wrap subkey`);
          assert.throws(() => open(op, ring), `op ${op.seq}'s data key isn't wrapped by the bare ring key`);
          assert.equal(createHmac("sha256", nameKey).update(opens.path).digest("base64url"), op.key, `op ${op.seq}'s key is the HMAC of its path under the name subkey`);
        }
      }

      // The edge: a device with the vectors' key, under the vectors' id.
      const dev = await device(env.call, env.clock, SETUP, "vector", keys);
      await env.sql.query(`UPDATE harar_devices SET id = ? WHERE id = ?`, [v.device.id, dev.id]);
      const as = async (method: string, path: string, body?: unknown) =>
        env.call(method, path, { body, headers: { ...(await dev.sign(method, path, body)).headers, "harar-device": v.device.id } });
      const ops = v.ops.map((o: Row) => o.op);
      assert.deepEqual(await as("PUT", "/v1/sync", { ops }), { status: 200, body: { stored: 4, duplicates: 0 } });
      const got = await as("POST", "/v1/sync", { since: {} });
      assert.deepEqual(got.body.ops.map((o: Row) => o.hash), v.ops.map((o: Row) => o.hash), "the edge hashes them as harar does");
      assert.deepEqual(got.body.ops.map(sent), ops);
    });
  });
}

test("postgres() numbers the placeholders", async () => {
  const seen: [string, unknown[]][] = [];
  const sql = postgres(async (q, p) => {
    seen.push([q, p]);
    return [];
  });
  await sql.query("SELECT a FROM t WHERE b = ? AND c = ?", [1, 2]);
  assert.deepEqual(seen, [["SELECT a FROM t WHERE b = $1 AND c = $2", [1, 2]]]);
});
