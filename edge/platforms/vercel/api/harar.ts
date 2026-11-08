// harar edge on Vercel Functions, written by `harar edge init --vercel`.
// The API is ../harar-edge.ts; the design is harar's docs/edge.md.
//
// Vercel keeps secrets in environment variables, so these three are read
// here and nowhere else: DATABASE_URL (any Postgres: Vercel's marketplace,
// Neon, Supabase), HARAR_EDGE_KEY, and HARAR_LOG_TOKEN if the sink needs one.
import pg from "postgres";

import { edge, postgres, type Config, type Row } from "../harar-edge.ts";

// The setup code's SHA-256: the code itself was shown once, by init.
const SETUP_CODE_HASH = "__HARAR_SETUP_CODE_HASH__";
// Where the log goes: an OTLP/HTTP endpoint in another account, or "" for none.
const LOG_SINK = "__HARAR_LOG_SINK__";

const db = pg(process.env.DATABASE_URL ?? "", { prepare: false, onnotice: () => {} });
const logToken = process.env.HARAR_LOG_TOKEN;

const config: Config = {
  setupCodeHash: SETUP_CODE_HASH,
  key: process.env.HARAR_EDGE_KEY ?? "",
  sql: postgres((sql, params) => db.unsafe(sql, params as never[]) as unknown as Promise<Row[]>),
  log: {
    sinks: LOG_SINK ? [{ otlp: LOG_SINK, headers: logToken ? { authorization: `Bearer ${logToken}` } : {} }] : [],
    events: "all",
    whenSinksFail: "serve",
  },
};

const api = edge(config);
const handle = (request: Request) => api.fetch(request);
export { handle as GET, handle as POST, handle as PUT, handle as DELETE };
