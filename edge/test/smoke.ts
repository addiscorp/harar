// One user's journey against a running edge, whatever runs it: pair a device
// with the setup code, put a secret, make a token, resolve with it, see a
// refusal, rotate, revoke, and read the log back as an unbroken chain.
//
//   node test/smoke.ts <base url> <setup code>
import assert from "node:assert/strict";
import { createHash, webcrypto } from "node:crypto";

export async function smoke(base: string, code: string): Promise<string[]> {
  const done: string[] = [];
  const keys = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const raw = Buffer.from(await webcrypto.subtle.exportKey("raw", keys.publicKey)).toString("base64url");
  const url = new URL(base);
  const prefix = url.pathname.replace(/\/+$/, "");

  const call = async (method: string, path: string, body?: unknown, headers: Record<string, string> = {}) => {
    const res = await fetch(`${url.origin}${prefix}${path}`, {
      method,
      headers: { "content-type": "application/json", ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: res.status, body: (await res.json()) as any };
  };

  const health = await call("GET", "/v1/health");
  assert.equal(health.status, 200, JSON.stringify(health.body));
  done.push(`health: version ${health.body.version}`);

  const paired = await call("POST", "/v1/pair", { code, name: "smoke", public_key: raw });
  assert.equal(paired.status, 201, JSON.stringify(paired.body));
  const id = paired.body.device;
  done.push(`paired ${id}`);

  const as = async (method: string, path: string, body?: unknown) => {
    const text = body === undefined ? "" : JSON.stringify(body);
    const time = String(Math.floor(Date.now() / 1000));
    const nonce = Buffer.from(webcrypto.getRandomValues(new Uint8Array(16))).toString("base64url");
    const signed = ["harar-edge-v1", method, path, time, nonce, createHash("sha256").update(text).digest("hex")].join("\n");
    const sig = await webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keys.privateKey, new TextEncoder().encode(signed));
    return call(method, path, body, {
      "harar-device": id,
      "harar-time": time,
      "harar-nonce": nonce,
      "harar-signature": Buffer.from(sig).toString("base64url"),
    });
  };

  assert.deepEqual((await as("PUT", "/v1/secrets/prod/shop/STRIPE_KEY", { value: "sk_live_smoke" })).body, { path: "prod/shop/STRIPE_KEY", version: 1 });
  await as("PUT", "/v1/secrets/prod/site/DATABASE_URL", { value: "postgres://smoke" });
  done.push("put two secrets");

  const token = await as("POST", "/v1/tokens", { name: "smoke-service", read: ["prod/shop/*"] });
  assert.equal(token.status, 201, JSON.stringify(token.body));
  const bearer = { authorization: `Bearer ${token.body.token}` };
  const resolved = await call("POST", "/v1/resolve", { refs: ["harar://prod/shop/STRIPE_KEY"] }, bearer);
  assert.deepEqual(resolved, { status: 200, body: { values: ["sk_live_smoke"] } });
  done.push("a service token resolved harar://prod/shop/STRIPE_KEY");

  const refused = await call("POST", "/v1/resolve", { refs: ["harar://prod/site/DATABASE_URL"] }, bearer);
  assert.deepEqual([refused.status, refused.body.error], [403, "not_allowed"]);
  done.push("and was refused harar://prod/site/DATABASE_URL");

  assert.equal((await as("PUT", "/v1/secrets/prod/shop/STRIPE_KEY", { value: "sk_live_rotated", rotate: true })).body.version, 2);
  assert.deepEqual((await call("POST", "/v1/resolve", { refs: ["harar://prod/shop/STRIPE_KEY"] }, bearer)).body.values, ["sk_live_rotated"]);
  done.push("rotated; the token sees the new value");

  assert.equal((await as("DELETE", `/v1/tokens/${token.body.id}`)).status, 200);
  assert.equal((await call("POST", "/v1/resolve", { refs: ["harar://prod/shop/STRIPE_KEY"] }, bearer)).status, 401);
  done.push("revoked; the token is refused");

  const log = (await as("GET", "/v1/log")).body.log as any[];
  let prev = "";
  for (const r of log) {
    assert.equal(r.prev_hash, prev);
    assert.equal(r.hash, createHash("sha256").update(prev + "\n" + JSON.stringify([r.seq, r.at, r.actor, r.action, r.resource, r.decision, r.reason, r.ip])).digest("hex"));
    prev = r.hash;
  }
  assert.deepEqual(
    log.map((r) => `${r.action}:${r.decision}`),
    ["pair:allow", "secret.put:allow", "secret.put:allow", "token.create:allow", "resolve:allow", "resolve:deny", "secret.rotate:allow", "resolve:allow", "token.revoke:allow", "resolve:deny", "log.read:allow"],
  );
  assert.ok(!JSON.stringify(log).includes("sk_live"), "no value in the log");
  done.push(`log: ${log.length} rows, chain intact, no values`);
  return done;
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  const [base, code] = process.argv.slice(2);
  for (const line of await smoke(base, code)) console.log(`ok  ${line}`);
}
