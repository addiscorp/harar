// actors() against a stand-in primary on a unix socket: the requests are the
// ones the harar crate's PrimaryRequest::ActorAdd / ActorRemove / ActorShow
// take (tag "op", field "actor"), `show` reads the member back, a name that
// is not a member is null, and every other no, or no answer, is an error.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { actors, PRIMARY_SOCKET } from '../index.js'

async function primary(reply) {
  const dir = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'harar-js-'))
  const socket = join(dir, 'p.sock')
  const requests = []
  // Half open: a primary that never answers keeps its side open.
  const server = createServer({ allowHalfOpen: true }, (conn) => {
    let body = ''
    conn.on('data', (c) => (body += c))
    conn.on('end', () => {
      const request = JSON.parse(body)
      requests.push(request)
      const answer = reply(request)
      if (answer !== undefined) conn.end(answer)
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

const ava = { name: 'gg.addis.agent.ava', groups: ['staff'], added_at: 1800000000, added_by: 'gg.addis.service.id' }

test('add, show and remove ask the primary exactly', async () => {
  const p = await primary((r) =>
    r.op === 'actor_show'
      ? JSON.stringify(r.actor === ava.name ? { ok: true, actor: ava } : { ok: false, error: 'not_found' })
      : JSON.stringify({ ok: true }),
  )
  try {
    const members = actors({ socket: p.socket })
    await members.add('gg.addis.agent.ava')
    assert.deepEqual(await members.show('gg.addis.agent.ava'), {
      name: 'gg.addis.agent.ava', groups: ['staff'], addedAt: 1800000000, addedBy: 'gg.addis.service.id',
    })
    assert.equal(await members.show('gg.addis.human.meron'), null, 'not a member')
    await members.remove('gg.addis.agent.ava')
    assert.deepEqual(p.requests, [
      { op: 'actor_add', actor: 'gg.addis.agent.ava' },
      { op: 'actor_show', actor: 'gg.addis.agent.ava' },
      { op: 'actor_show', actor: 'gg.addis.human.meron' },
      { op: 'actor_remove', actor: 'gg.addis.agent.ava' },
    ])
  } finally {
    p.stop()
  }
})

test('a refusal is an error with harar\'s reason, never a quiet null', async () => {
  const p = await primary(() => JSON.stringify({ ok: false, error: 'no_binding' }))
  try {
    const members = actors({ socket: p.socket })
    await assert.rejects(members.add('gg.addis.agent.ava'), (e) => e.code === 'no_binding' && /harar refused adding gg.addis.agent.ava: no_binding/.test(e.message))
    await assert.rejects(members.show('gg.addis.agent.ava'), (e) => e.code === 'no_binding')
    await assert.rejects(members.remove('gg.addis.agent.ava'), /no_binding/)
  } finally {
    p.stop()
  }
})

test('a member that does not match what was asked, or a malformed one, is an error', async () => {
  for (const actor of [{ ...ava, name: 'gg.addis.agent.eve' }, { ...ava, groups: 'staff' }, { ...ava, added_at: 'x' }, null]) {
    const p = await primary(() => JSON.stringify({ ok: true, actor }))
    try {
      await assert.rejects(actors({ socket: p.socket }).show('gg.addis.agent.ava'), /harar sent no member/)
    } finally {
      p.stop()
    }
  }
})

test('no primary, or one that never answers, fails within the timeout', async () => {
  await assert.rejects(actors({ socket: '/nonexistent/harar.sock' }).show('gg.addis.agent.ava'), /harar at \/nonexistent\/harar.sock/)
  const p = await primary(() => undefined)
  try {
    const started = Date.now()
    await assert.rejects(actors({ socket: p.socket, timeoutMs: 200 }).show('gg.addis.agent.ava'), /did not answer in 0.2 s/)
    assert.ok(Date.now() - started < 5000)
  } finally {
    p.stop()
  }
})

test('names are checked before anything is sent', async () => {
  const members = actors({ socket: '/nonexistent/harar.sock' })
  for (const wrong of ['ava', 'gg.addis.service.web', 'gg.addis.agent.', 'gg.addis.agent.a b', 42]) {
    await assert.rejects(members.add(wrong), /not a member's name/)
  }
  assert.throws(() => actors({ socket: 'relative.sock' }), /absolute path/)
  assert.equal(PRIMARY_SOCKET, '/run/harar.sock')
})
