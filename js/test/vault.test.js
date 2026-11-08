// The client against a stand-in harar on a unix socket: the requests it
// sends are the ones harar's `hosts` and `send` take (the harar
// crate's PrimaryRequest::Hosts { key } and Send { key, host }, tag "op"), and every
// way harar can say no is an error naming why.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { agentSocket, vault } from '../index.js'

async function harar(reply) {
  const dir = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'harar-js-'))
  const socket = join(dir, 'h.sock')
  const requests = []
  const server = createServer((conn) => {
    let body = ''
    conn.on('data', (c) => (body += c))
    conn.on('end', () => {
      const request = JSON.parse(body)
      requests.push(request)
      conn.end(reply(request))
    })
  })
  await new Promise((r) => server.listen(socket, r))
  return {
    socket,
    requests,
    stop: () => {
      server.close()
      rmSync(dir, { recursive: true, force: true })
    },
  }
}

test('hosts and send ask harar exactly, and a send is for one host', async () => {
  const h = await harar((r) =>
    r.op === 'hosts'
      ? JSON.stringify({ ok: true, hosts: ['api.stripe.com', '*.stripe.com'] })
      : r.op === 'send' && r.host === 'api.stripe.com'
        ? JSON.stringify({ ok: true, value: 'sk_live_real' })
        : JSON.stringify({ ok: false, error: 'not_allowed' }),
  )
  try {
    const v = vault({ socket: h.socket })
    assert.deepEqual(await v.hosts('prod/shop/STRIPE_KEY'), ['api.stripe.com', '*.stripe.com'])
    assert.equal(await v.send('prod/shop/STRIPE_KEY', 'api.stripe.com'), 'sk_live_real')
    await assert.rejects(
      v.send('prod/shop/STRIPE_KEY', 'evil.example.com'),
      /harar refused prod\/shop\/STRIPE_KEY to evil.example.com: not_allowed/,
    )
    assert.deepEqual(h.requests, [
      { op: 'hosts', key: 'prod/shop/STRIPE_KEY' },
      { op: 'send', key: 'prod/shop/STRIPE_KEY', host: 'api.stripe.com' },
      { op: 'send', key: 'prod/shop/STRIPE_KEY', host: 'evil.example.com' },
    ])
  } finally {
    h.stop()
  }
})

test('every way harar can fail is an error naming why', async () => {
  for (const [answer, why] of [
    ['not json', /did not answer with JSON/],
    ['null', /did not answer with an object/],
    ['[1]', /did not answer with an object/],
    [JSON.stringify({ ok: true }), /no value|no hosts/],
    [JSON.stringify({ ok: false, error: 'locked' }), /harar refused .*: locked/],
  ]) {
    const h = await harar(() => answer)
    try {
      const v = vault({ socket: h.socket })
      await assert.rejects(v.send('a/b', 'x.example.com'), why)
      await assert.rejects(v.hosts('a/b'), why)
    } finally {
      h.stop()
    }
  }
  await assert.rejects(
    vault({ socket: '/nonexistent/h.sock' }).hosts('a/b'),
    /harar at \/nonexistent\/h.sock/,
  )
  assert.throws(() => vault({ socket: 'relative.sock' }), /absolute path/)
})

test('secrets.resolve reads the key a harar:// reference names, as op:// does in 1Password', async () => {
  const h = await harar((r) =>
    r.key === 'prod/shop/STRIPE_KEY'
      ? JSON.stringify({ ok: true, value: 'sk_live_real' })
      : r.key === 'prod/shop/OTHER'
        ? JSON.stringify({ ok: true, value: 'other' })
        : JSON.stringify({ ok: false, error: 'not_found' }),
  )
  try {
    const v = vault({ socket: h.socket })
    assert.equal(await v.secrets.resolve('harar://prod/shop/STRIPE_KEY'), 'sk_live_real')
    assert.deepEqual(await v.secrets.resolveAll(['harar://prod/shop/STRIPE_KEY', 'harar://prod/shop/OTHER']), [
      'sk_live_real',
      'other',
    ])
    await assert.rejects(v.secrets.resolve('harar://prod/shop/GONE'), /harar refused harar:\/\/prod\/shop\/GONE: not_found/)
    // Not a reference: refused before harar is asked anything.
    for (const notOne of ['prod/shop/STRIPE_KEY', 'op://Prod/Stripe/credential', 'harar://', 'harar://a b', undefined])
      await assert.rejects(v.secrets.resolve(notOne), /not a harar:\/\/ reference/)
    assert.deepEqual(h.requests, [
      { op: 'get', key: 'prod/shop/STRIPE_KEY' },
      { op: 'get', key: 'prod/shop/STRIPE_KEY' },
      { op: 'get', key: 'prod/shop/OTHER' },
      { op: 'get', key: 'prod/shop/GONE' },
    ])
  } finally {
    h.stop()
  }
})

test('vault() with no socket asks the agent where `harar agent` listens', async () => {
  const saved = { HOME: process.env.HOME, XDG_RUNTIME_DIR: process.env.XDG_RUNTIME_DIR }
  try {
    process.env.HOME = '/home/someone'
    process.env.XDG_RUNTIME_DIR = '/run/user/1000'
    assert.equal(
      agentSocket(),
      process.platform === 'darwin'
        ? '/home/someone/Library/Application Support/harar/agent.sock'
        : '/run/user/1000/harar/agent.sock',
    )
    delete process.env.XDG_RUNTIME_DIR
    if (process.platform !== 'darwin') assert.equal(agentSocket(), '/home/someone/.harar/agent.sock')
    await assert.rejects(vault().secrets.resolve('harar://a/b'), (e) => e.message.startsWith(`harar at ${agentSocket()}:`))
  } finally {
    for (const [k, v] of Object.entries(saved)) if (v === undefined) delete process.env[k]; else process.env[k] = v
  }
})
