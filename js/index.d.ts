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

/** harar at `socket`: by default the per-user agent on this machine
 *  (`harar agent`), else a primary (`/run/harar.sock`). */
export function vault(options?: { socket?: string }): Vault

/** What a reference to a vault key starts with. */
export const REFERENCE_PREFIX: 'harar://'
/** The vault key `value` names, if the whole value is a `harar://` reference. */
export function reference(value: string): string | undefined
/** Where the per-user agent listens. */
export function agentSocket(): string
