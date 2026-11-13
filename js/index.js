// harar's client for JavaScript and TypeScript:
//
//   import { vault } from 'harar'
//   const harar = vault()                                      // the agent on this machine
//   await harar.secrets.resolve('harar://prod/shop/STRIPE_KEY') // the key it names
//
// A gateway that attaches keys on their way out asks where each may go, and
// for it for one host only: hosts(secret) and send(secret, host).
//
// One JSON request on harar's local socket, the write side closed, one JSON
// answer: the protocol the per-user agent and a primary both speak. harar
// decides every send, and records the host; this client holds nothing.
import { connect } from 'node:net'
import { join } from 'node:path'

/** harar's answers are small; anything longer is refused. */
const MAX_ANSWER = 1024 * 1024
/** How long harar has to answer (a per-user agent may be asking for Touch ID). */
const TIMEOUT_MS = 60_000

/** A refusal from harar: `code` is harar's own reason (`no_binding`, `not_found`, …). */
class Refused extends Error {
  constructor(message, code) {
    super(message)
    this.code = code
  }
}

/** One request to harar, and its answer if it says ok; otherwise why not. */
function ask(socket, request, what, timeoutMs = TIMEOUT_MS) {
  return new Promise((done, fail) => {
    const conn = connect(socket)
    const chunks = []
    let size = 0
    conn.setTimeout(timeoutMs, () =>
      conn.destroy(new Error(`harar did not answer in ${timeoutMs / 1000} s`)),
    )
    conn.on('connect', () => conn.end(JSON.stringify(request)))
    conn.on('data', (chunk) => {
      size += chunk.length
      if (size > MAX_ANSWER) conn.destroy(new Error('harar sent too long an answer'))
      else chunks.push(chunk)
    })
    conn.on('error', (e) => fail(new Error(`harar at ${socket}: ${e.message}`)))
    conn.on('end', () => {
      let answer
      try {
        answer = JSON.parse(Buffer.concat(chunks).toString('utf8'))
      } catch {
        return fail(new Error(`harar at ${socket} did not answer with JSON`))
      }
      if (typeof answer !== 'object' || answer === null || Array.isArray(answer))
        return fail(new Error(`harar at ${socket} did not answer with an object`))
      if (answer.ok === true) return done(answer)
      const code = typeof answer.error === 'string' ? answer.error : 'no answer'
      fail(new Refused(`harar refused ${what}: ${code}`, code))
    })
  })
}

/** What a reference to a vault key starts with, as `op://` for 1Password. */
export const REFERENCE_PREFIX = 'harar://'

/** The vault key `value` names, if the whole value is a `harar://` reference. */
export function reference(value) {
  if (typeof value !== 'string' || !value.startsWith(REFERENCE_PREFIX)) return undefined
  const key = value.slice(REFERENCE_PREFIX.length)
  return key !== '' && !/\s/u.test(key) ? key : undefined
}

/** Where the per-user agent (`harar agent`) listens: the harar binary's rule. */
export function agentSocket() {
  const { HOME, XDG_RUNTIME_DIR } = process.env
  if (process.platform === 'darwin' && HOME)
    return join(HOME, 'Library/Application Support/harar', 'agent.sock')
  if (XDG_RUNTIME_DIR) return join(XDG_RUNTIME_DIR, 'harar', 'agent.sock')
  return join(HOME || '/', '.harar', 'agent.sock')
}

/** A harar edge service token, as `harar edge token create` makes it. */
const EDGE_TOKEN = /^harar_edge_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$/
/** https://, or http:// to this machine only. */
const EDGE_URL = /^(https:\/\/[^/]|http:\/\/(127\.0\.0\.1|localhost|\[::1\])([:/]|$))/

/** The values `refs` name, from a harar edge (docs/edge.md): one POST of
 *  /v1/resolve with the service token, all or nothing. */
async function askEdge(edge, token, refs, what) {
  let res
  try {
    res = await fetch(`${edge}/v1/resolve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify({ refs }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    })
  } catch (e) {
    const why = e?.name === 'TimeoutError' ? `did not answer in ${TIMEOUT_MS / 1000} s` : e?.cause?.message ?? e?.message
    throw new Error(`harar at ${edge}: ${why}`)
  }
  const text = await readCapped(res, edge)
  let answer
  try {
    answer = JSON.parse(text)
  } catch {
    throw new Error(`harar at ${edge} did not answer with JSON (${res.status})`)
  }
  if (typeof answer !== 'object' || answer === null || Array.isArray(answer))
    throw new Error(`harar at ${edge} did not answer with an object`)
  if (!res.ok) {
    const code = typeof answer.error === 'string' ? answer.error : String(res.status)
    const why = typeof answer.message === 'string' ? `: ${answer.message}` : ''
    throw new Error(`harar refused ${what}: ${code}${why}`)
  }
  const { values } = answer
  if (!Array.isArray(values) || values.length !== refs.length || !values.every((v) => typeof v === 'string'))
    throw new Error(`harar sent no value for ${what}`)
  return values
}

/** The body, refused past MAX_ANSWER bytes. */
async function readCapped(res, edge) {
  const chunks = []
  let size = 0
  for await (const chunk of res.body ?? []) {
    size += chunk.length
    if (size > MAX_ANSWER) throw new Error('harar sent too long an answer')
    chunks.push(chunk)
  }
  return Buffer.concat(chunks).toString('utf8')
}

/** References checked here first, so a typo never leaves this process. */
function keysOf(refs) {
  for (const ref of refs)
    if (reference(ref) === undefined) throw new Error(`not a harar:// reference: ${JSON.stringify(ref)}`)
}

/** A vault at a harar edge: only `secrets`, since hosts and send are for
 *  gateways on harar's local socket. */
function edgeVault(edge, token) {
  if (typeof edge !== 'string' || !EDGE_URL.test(edge))
    throw new Error('vault({ edge }): the edge is an https:// URL')
  if (typeof token !== 'string' || !EDGE_TOKEN.test(token))
    throw new Error('vault({ edge, token }): the token is a harar edge service token (harar edge token create)')
  const base = edge.replace(/\/+$/, '')
  return {
    secrets: {
      async resolve(ref) {
        keysOf([ref])
        return (await askEdge(base, token, [ref], ref))[0]
      },
      async resolveAll(refs) {
        if (!Array.isArray(refs)) throw new Error('resolveAll takes an array of harar:// references')
        if (refs.length === 0) return []
        keysOf(refs)
        return askEdge(base, token, refs, refs.length === 1 ? refs[0] : `${refs.length} references`)
      },
    },
  }
}

/** Where a primary (`harar serve`) listens by default. */
export const PRIMARY_SOCKET = '/run/harar.sock'
/** An identity service asks on behalf of a person signing in: it waits seconds, not a minute. */
const ACTORS_TIMEOUT_MS = 10_000
/** A member's name: `<org>.human.<local>` or `<org>.agent.<local>` (harar decides the rest). */
const MEMBER = /^[a-z0-9-]+(\.[a-z0-9-]+)+\.(human|agent)\.[a-z0-9-]+$/

/** The org's members at a primary (architecture, §2a): `add`, `remove` and
 *  `show`, for an identity service on the same machine. A refusal or a
 *  primary that can't be reached is an error; only `show` of a name that is
 *  not a member answers null. */
export function actors(options = {}) {
  const { socket = PRIMARY_SOCKET, timeoutMs = ACTORS_TIMEOUT_MS } = options
  if (typeof socket !== 'string' || !socket.startsWith('/'))
    throw new Error('actors({ socket }): the socket is an absolute path')
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0)
    throw new Error('actors({ timeoutMs }): a whole number of milliseconds')
  const named = (actor) => {
    if (typeof actor !== 'string' || !MEMBER.test(actor))
      throw new Error(`not a member's name: ${JSON.stringify(actor)}`)
    return actor
  }
  return {
    async add(actor) {
      await ask(socket, { op: 'actor_add', actor: named(actor) }, `adding ${actor}`, timeoutMs)
    },
    async remove(actor) {
      await ask(socket, { op: 'actor_remove', actor: named(actor) }, `removing ${actor}`, timeoutMs)
    },
    async show(actor) {
      let answer
      try {
        answer = await ask(socket, { op: 'actor_show', actor: named(actor) }, actor, timeoutMs)
      } catch (e) {
        if (e instanceof Refused && e.code === 'not_found') return null
        throw e
      }
      const found = answer.actor
      if (
        typeof found !== 'object' || found === null || found.name !== actor ||
        !Array.isArray(found.groups) || !found.groups.every((g) => typeof g === 'string') ||
        !Number.isInteger(found.added_at) || typeof found.added_by !== 'string'
      )
        throw new Error(`harar sent no member for ${actor}`)
      return { name: found.name, groups: found.groups, addedAt: found.added_at, addedBy: found.added_by }
    },
  }
}

/** A vault on harar's socket: the agent on this machine unless `socket` names
 *  another; or, with `{ edge, token }`, a harar edge. */
export function vault(options = {}) {
  if (options.edge !== undefined || options.token !== undefined) {
    if (options.socket !== undefined) throw new Error('vault(): a socket or an edge, not both')
    return edgeVault(options.edge, options.token)
  }
  const { socket = agentSocket() } = options
  if (typeof socket !== 'string' || !socket.startsWith('/'))
    throw new Error('vault({ socket }): the socket is an absolute path')
  const resolve = async (ref) => {
    const key = reference(ref)
    if (key === undefined) throw new Error(`not a harar:// reference: ${JSON.stringify(ref)}`)
    const { value } = await ask(socket, { op: 'get', key }, ref)
    if (typeof value !== 'string') throw new Error(`harar sent no value for ${ref}`)
    return value
  }
  return {
    secrets: {
      resolve,
      async resolveAll(refs) {
        const values = []
        for (const ref of refs) values.push(await resolve(ref))
        return values
      },
    },
    async hosts(secret) {
      const { hosts } = await ask(socket, { op: 'hosts', key: secret }, secret)
      if (!Array.isArray(hosts) || !hosts.every((h) => typeof h === 'string'))
        throw new Error(`harar sent no hosts for ${secret}`)
      return hosts
    },
    async send(secret, host) {
      const { value } = await ask(
        socket,
        { op: 'send', key: secret, host },
        `${secret} to ${host}`,
      )
      if (typeof value !== 'string')
        throw new Error(`harar refused ${secret} to ${host}: no value`)
      return value
    },
  }
}
