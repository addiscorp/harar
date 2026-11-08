// harar edge on Cloudflare Workers, written by `harar edge init --cloudflare`.
// The API is ./harar-edge.ts; the design is harar's docs/edge.md.
import { d1, edge, type Config } from "./harar-edge.ts";

interface Env {
  /** D1, from wrangler.toml. */
  DB: Parameters<typeof d1>[0];
  /** The edge key: `npx wrangler secret put HARAR_EDGE_KEY < .harar-edge.key`. */
  HARAR_EDGE_KEY: string;
  /** The log sink's write-only token, if it needs one: `npx wrangler secret put HARAR_LOG_TOKEN`. */
  HARAR_LOG_TOKEN?: string;
}

// The setup code's SHA-256: the code itself was shown once, by init.
const SETUP_CODE_HASH = "__HARAR_SETUP_CODE_HASH__";
// Where the log goes: an OTLP/HTTP endpoint in another account, or "" for none.
const LOG_SINK = "__HARAR_LOG_SINK__";

export default {
  fetch(request: Request, env: Env, ctx: { waitUntil(work: Promise<unknown>): void }): Promise<Response> {
    const config: Config = {
      setupCodeHash: SETUP_CODE_HASH,
      key: env.HARAR_EDGE_KEY,
      sql: d1(env.DB),
      log: {
        sinks: LOG_SINK ? [{ otlp: LOG_SINK, headers: env.HARAR_LOG_TOKEN ? { authorization: `Bearer ${env.HARAR_LOG_TOKEN}` } : {} }] : [],
        events: "all",
        whenSinksFail: "serve",
      },
      waitUntil: (work) => ctx.waitUntil(work),
    };
    return edge(config).fetch(request);
  },
};
