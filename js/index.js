// harar's client for JavaScript and TypeScript:
//
//   import { vault } from 'harar'
//   const v = vault({ socket: '/run/harar.sock' })
//   await v.hosts('prod/shop/STRIPE_KEY')                    // ['api.stripe.com']
//   await v.send('prod/shop/STRIPE_KEY', 'api.stripe.com')    // the key, for that host only
//
// One JSON request on harar's local socket, the write side closed, one JSON
// answer: the protocol the per-user agent and a primary both speak. harar
// decides every send, and records the host; this client holds nothing.
import { connect } from 'node:net'

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

/** A vault on harar's socket: what a gateway asks where keys may go. */
export function vault({ socket }) {
  if (typeof socket !== 'string' || !socket.startsWith('/'))
    throw new Error('vault({ socket }): the socket is an absolute path')
  return {
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
