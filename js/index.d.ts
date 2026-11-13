/** A vault on harar's local socket. */
export interface Vault {
  /** `harar://` references resolved to their values, the shape of 1Password's
   *  `client.secrets.resolve('op://…')`. Read when asked for; held only by you. */
  secrets: {
    /** The value `reference` (`harar://prod/shop/STRIPE_KEY`) names. */
    resolve(reference: string): Promise<string>
    /** Each reference's value, in order; the first that fails is the error. */
    resolveAll(references: string[]): Promise<string[]>
  }
  /** For a gateway (`import { gateway } from 'rixse'`): the host patterns
   *  `secret` may go to, an exact name or `*.example.com` for any name under
   *  it (never the name itself). */
  hosts(secret: string): Promise<string[]>
  /** For a gateway: `secret`'s value, for a request to `host` only. */
  send(secret: string, host: string): Promise<string>
}

/** A vault at a harar edge (docs/edge.md): it resolves references, and only
 *  those its service token may read. */
export interface EdgeVault {
  secrets: Vault['secrets']
}

/** harar at `socket`: by default the per-user agent on this machine
 *  (`harar agent`), else a primary (`/run/harar.sock`). */
export function vault(options?: { socket?: string }): Vault
/** A harar edge, for a service off your network: its URL
 *  (`https://harar-edge.<you>.workers.dev`) and a service token from
 *  `harar edge token create`, read from the platform's secrets. */
export function vault(options: { edge: string; token: string }): EdgeVault

/** A member of the org, as a primary shows it. */
export interface Member {
  /** `gg.addis.agent.ava`, `gg.addis.human.sami`. */
  name: string
  /** The local labels of the roles bound to it in every zone (`<org>.zone.*`), sorted. */
  groups: string[]
  /** Unix seconds. */
  addedAt: number
  /** Who added it. */
  addedBy: string
}

/** The org's members at a primary, for an identity service on its machine. */
export interface Actors {
  /** Registers a human or an agent. Already there: ok, nothing changes. */
  add(actor: string): Promise<void>
  /** Takes it out, with every binding that names it exactly. Not there: ok. */
  remove(actor: string): Promise<void>
  /** The member and its groups, read from the policy as it is now; null when it is not a member. */
  show(actor: string): Promise<Member | null>
}

/** The primary at `socket` (default `/run/harar.sock`). Each call waits at
 *  most `timeoutMs` (default 10 000) before it fails. */
export function actors(options?: { socket?: string; timeoutMs?: number }): Actors

/** Where a primary listens by default. */
export const PRIMARY_SOCKET: '/run/harar.sock'

/** What a reference to a vault key starts with. */
export const REFERENCE_PREFIX: 'harar://'
/** The vault key `value` names, if the whole value is a `harar://` reference. */
export function reference(value: string): string | undefined
/** Where the per-user agent listens. */
export function agentSocket(): string
