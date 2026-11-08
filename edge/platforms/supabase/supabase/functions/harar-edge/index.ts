// harar edge on Supabase Edge Functions, written by `harar edge init --supabase`.
// The API is ./harar-edge.ts; the design is harar's docs/edge.md.
//
// Supabase gives the function its database as SUPABASE_DB_URL. Set the edge
// key with `supabase secrets set --env-file .harar-edge.env`, and
// HARAR_LOG_TOKEN the same way if the sink needs one.
import pg from "npm:postgres@3.4.9";

import { edge, postgres, type Config, type Row } from "./harar-edge.ts";

// The setup code's SHA-256: the code itself was shown once, by init.
const SETUP_CODE_HASH = "__HARAR_SETUP_CODE_HASH__";
// Where the log goes: an OTLP/HTTP endpoint in another account, or "" for none.
const LOG_SINK = "__HARAR_LOG_SINK__";

const db = pg(Deno.env.get("SUPABASE_DB_URL") ?? "", { prepare: false, onnotice: () => {} });
const logToken = Deno.env.get("HARAR_LOG_TOKEN");

const config: Config = {
  setupCodeHash: SETUP_CODE_HASH,
  key: Deno.env.get("HARAR_EDGE_KEY") ?? "",
  sql: postgres((sql, params) => db.unsafe(sql, params as never[]) as unknown as Promise<Row[]>),
  // Supabase serves a function under its name.
  basePath: "/harar-edge",
  log: {
    sinks: LOG_SINK ? [{ otlp: LOG_SINK, headers: logToken ? { authorization: `Bearer ${logToken}` } : {} }] : [],
    events: "all",
    whenSinksFail: "serve",
  },
  // On Supabase, shipping continues after the answer; elsewhere (deno run) it
  // happens before it.
  waitUntil: typeof EdgeRuntime === "undefined" ? undefined : (work) => EdgeRuntime.waitUntil(work),
};

const api = edge(config);
Deno.serve((request) => api.fetch(request));

declare const EdgeRuntime: { waitUntil(work: Promise<unknown>): void } | undefined;
