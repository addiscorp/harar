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

/** One request to harar, and its answer if it says ok; otherwise why not. */
function ask(socket, request, what) {
  return new Promise((done, fail) => {
    const conn = connect(socket)
    const chunks = []
    let size = 0
    conn.setTimeout(TIMEOUT_MS, () =>
      conn.destroy(new Error(`harar did not answer in ${TIMEOUT_MS / 1000} s`)),
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
      fail(
        new Error(
          `harar refused ${what}: ${typeof answer.error === 'string' ? answer.error : 'no answer'}`,
        ),
      )
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

/** A vault on harar's socket: the agent on this machine unless `socket` names another. */
export function vault({ socket = agentSocket() } = {}) {
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
