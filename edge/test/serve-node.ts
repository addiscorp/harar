// The edge on Node with node:sqlite: no platform, for trying an edge on this
// machine and for CI's check that the harar CLI and the edge agree.
//
//   node test/serve-node.ts <folder harar edge init wrote> <port>
//
// It takes the edge key and the setup code's hash from the files init wrote
// (.harar-edge.key, .harar-edge.setup), and keeps its database in memory.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { edge, type Row } from "../harar-edge.ts";

const [dir, port] = process.argv.slice(2);
const db = new DatabaseSync(":memory:");
const api = edge({
  setupCodeHash: createHash("sha256").update(readFileSync(join(dir, ".harar-edge.setup"), "utf8").trim()).digest("hex"),
  key: readFileSync(join(dir, ".harar-edge.key"), "utf8").trim(),
  sql: { query: async (sql, params = []) => db.prepare(sql).all(...(params as (string | number | null)[])) as Row[] },
});

createServer(async (req, res) => {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const response = await api.fetch(
    new Request(`http://127.0.0.1:${port}${req.url}`, {
      method: req.method,
      headers: { ...(req.headers as Record<string, string>), "x-real-ip": req.socket.remoteAddress ?? "" },
      body: chunks.length ? Buffer.concat(chunks) : undefined,
    }),
  );
  res.writeHead(response.status, Object.fromEntries(response.headers));
  res.end(Buffer.from(await response.arrayBuffer()));
}).listen(Number(port), "127.0.0.1", () => console.log(`harar edge on http://127.0.0.1:${port}`));
