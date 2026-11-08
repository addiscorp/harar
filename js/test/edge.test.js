// The client against a stand-in harar edge over HTTP: what it sends is the
// edge's POST /v1/resolve (docs/edge.md §5) with the service token, and
// every way the edge can say no is an error naming why. The same cases as
// the other clients' edge tests.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { vault } from '../index.js'

const TOKEN = `harar_edge_0123456789abcdef_${'A'.repeat(43)}`

/** A stand-in edge, mounted under `/functions/v1/harar-edge` as on Supabase. */
async function edge(reply) {
  const requests = []
  const server = createServer((req, res) => {
    let body = ''
    req.on('data', (c) => (body += c))
    req.on('end', () => {
      requests.push({ method: req.method, url: req.url, auth: req.headers.authorization, type: req.headers['content-type'], body: JSON.parse(body) })
      const [status, text] = reply(JSON.parse(body))
      res.writeHead(status, { 'content-type': 'application/json' })
      res.end(text)
    })
  })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  return { url: `http://127.0.0.1:${server.address().port}/functions/v1/harar-edge/`, requests, stop: () => server.close() }
}

const values = { 'harar://prod/shop/STRIPE_KEY': 'sk_live_real', 'harar://prod/shop/OTHER': 'other' }
const stripe = ({ refs }) =>
  refs.every((r) => r in values)
    ? [200, JSON.stringify({ values: refs.map((r) => values[r]) })]
    : [403, JSON.stringify({ error: 'not_allowed', message: 'this caller may not read prod/site/DATABASE_URL' })]

test('an edge vault resolves with one POST of /v1/resolve, the service token as its bearer', async () => {
  const e = await edge(stripe)
  try {
    const v = vault({ edge: e.url, token: TOKEN })
    assert.equal(await v.secrets.resolve('harar://prod/shop/STRIPE_KEY'), 'sk_live_real')
    assert.deepEqual(await v.secrets.resolveAll(['harar://prod/shop/STRIPE_KEY', 'harar://prod/shop/OTHER']), ['sk_live_real', 'other'])
    assert.deepEqual(await v.secrets.resolveAll([]), [])
    await assert.rejects(v.secrets.resolve('harar://prod/site/DATABASE_URL'), /harar refused harar:\/\/prod\/site\/DATABASE_URL: not_allowed: this caller may not read/)
    for (const notOne of ['prod/shop/STRIPE_KEY', 'op://Prod/Stripe/credential', 'harar://', 'harar://a b', undefined])
      await assert.rejects(v.secrets.resolve(notOne), /not a harar:\/\/ reference/)
    await assert.rejects(v.secrets.resolveAll(['harar://prod/shop/OTHER', 'nope']), /not a harar:\/\/ reference: "nope"/)
    assert.deepEqual(e.requests, [
      { method: 'POST', url: '/functions/v1/harar-edge/v1/resolve', auth: `Bearer ${TOKEN}`, type: 'application/json', body: { refs: ['harar://prod/shop/STRIPE_KEY'] } },
      { method: 'POST', url: '/functions/v1/harar-edge/v1/resolve', auth: `Bearer ${TOKEN}`, type: 'application/json', body: { refs: ['harar://prod/shop/STRIPE_KEY', 'harar://prod/shop/OTHER'] } },
      { method: 'POST', url: '/functions/v1/harar-edge/v1/resolve', auth: `Bearer ${TOKEN}`, type: 'application/json', body: { refs: ['harar://prod/site/DATABASE_URL'] } },
    ])
    assert.equal(v.hosts, undefined, 'an edge vault has no hosts')
    assert.equal(v.send, undefined, 'an edge vault has no send')
  } finally {
    e.stop()
  }
})

test('every way an edge can fail is an error naming why, and the token is never in it', async () => {
  for (const [status, text, why] of [
    [200, 'not json', /did not answer with JSON \(200\)/],
    [502, '<html>bad gateway</html>', /did not answer with JSON \(502\)/],
    [200, '[1]', /did not answer with an object/],
    [200, JSON.stringify({ values: [] }), /no value for/],
    [200, JSON.stringify({ values: [7] }), /no value for/],
    [401, JSON.stringify({ error: 'revoked', message: 'this token was revoked' }), /harar refused .*: revoked: this token was revoked/],
    [500, JSON.stringify({}), /harar refused .*: 500/],
    [200, 'x'.repeat(1024 * 1024 + 1), /too long an answer/],
  ]) {
    const e = await edge(() => [status, text])
    try {
      const error = await vault({ edge: e.url, token: TOKEN }).secrets.resolve('harar://a/b').then(
        () => assert.fail('resolved'),
        (err) => err,
      )
      assert.match(error.message, why)
      assert.ok(!error.message.includes(TOKEN.slice(28)), 'the token stays out of errors')
    } finally {
      e.stop()
    }
  }
  await assert.rejects(vault({ edge: 'http://127.0.0.1:1', token: TOKEN }).secrets.resolve('harar://a/b'), /^Error: harar at http:\/\/127.0.0.1:1: /)
})

test('an edge is https (or this machine), its token is a harar edge token, and it is one or the other of socket and edge', () => {
  assert.throws(() => vault({ edge: 'http://edge.example', token: TOKEN }), /the edge is an https:\/\/ URL/)
  assert.throws(() => vault({ edge: 'http://localhost.evil.example', token: TOKEN }), /the edge is an https:\/\/ URL/)
  assert.throws(() => vault({ edge: 'https://edge.example' }), /the token is a harar edge service token/)
  assert.throws(() => vault({ edge: 'https://edge.example', token: 'sk_live_oops' }), (e) => /service token/.test(e.message) && !e.message.includes('sk_live_oops'))
  assert.throws(() => vault({ edge: 'https://edge.example', token: TOKEN, socket: '/run/harar.sock' }), /a socket or an edge, not both/)
  assert.ok(vault({ edge: 'https://harar-edge.you.workers.dev', token: TOKEN }).secrets)
  assert.ok(vault({ edge: 'http://localhost:8787', token: TOKEN }).secrets)
})
