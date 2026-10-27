/** A vault on harar's local socket: where each secret may go, and the
 *  secret itself for one host only. The shape a gateway asks for
 *  (`import { gateway } from 'rixse'`). */
export interface Vault {
  /** The host patterns `secret` may go to: an exact name, or `*.example.com`
   *  for any name under it (never the name itself). */
  hosts(secret: string): Promise<string[]>
  /** `secret`'s value, for a request to `host` only. harar decides, and
   *  records the host. */
  send(secret: string, host: string): Promise<string>
}

/** harar at `socket`: a per-user agent or a primary. */
export function vault(options: { socket: string }): Vault
