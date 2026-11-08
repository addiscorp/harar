// Serves an assembled Vercel entry (api/harar.ts) with Node's HTTP server,
// routing /v1/* to it as vercel.json does, so test/smoke.ts can run against
// the same handlers Vercel calls.
//
//   DATABASE_URL=… HARAR_EDGE_KEY=… node test/serve-vercel.ts <assembled dir> <port>
import { createServer } from "node:http";
import { join, resolve } from "node:path";

const [dir, port] = process.argv.slice(2);
const api = await import(join(resolve(dir), "api/harar.ts"));
createServer(async (req, res) => {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const request = new Request(`http://127.0.0.1:${port}${req.url}`, {
    method: req.method,
    headers: req.headers as Record<string, string>,
    body: chunks.length ? Buffer.concat(chunks) : undefined,
  });
  const handler = req.url?.startsWith("/v1/") ? api[req.method ?? "GET"] : undefined;
  const response: Response = handler ? await handler(request) : new Response("{}", { status: 404 });
  res.writeHead(response.status, Object.fromEntries(response.headers));
  res.end(Buffer.from(await response.arrayBuffer()));
}).listen(Number(port), "127.0.0.1");
