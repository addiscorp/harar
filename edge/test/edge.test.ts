// The edge against real SQL (SQLite always; Postgres too when
// HARAR_TEST_POSTGRES names one), real P-256 device keys and a stand-in log
// sink: every test asserts what a caller or the database would see.
import assert from "node:assert/strict";
import { createHash, webcrypto } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { after, describe, test } from "node:test";

import { VERSION, edge, postgres, type Config, type Row, type Sql } from "../harar-edge.ts";

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
      new Request(`https://edge.example${path}`, {
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
async function device(call: Awaited<ReturnType<typeof setup>>["call"], clock: { ms: number }, code = SETUP, name = "mac") {
  const keys = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
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
  return { id: paired.body.device as string, paired, sign, as };
}

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

    test("health says the version and the logging, and a base path mounts the API", async () => {
      const { api } = await setup(backend, { basePath: "/harar-edge" });
      const health = await api.fetch(new Request("https://x.supabase.co/harar-edge/v1/health"));
      assert.deepEqual(await health.json(), { version: VERSION, log: { sinks: 0, whenSinksFail: "serve" } });
      assert.equal((await api.fetch(new Request("https://x.supabase.co/v1/health"))).status, 404);
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
