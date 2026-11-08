// Lays out one platform's folder the way `harar edge init` will (from
// platforms/layout.json): the core file and the platform's files, with the
// placeholders filled. Used to check and run each platform's entry.
//
//   node test/assemble.ts <cloudflare|vercel|supabase> <dir> <setup code hash> [log sink]
import { cpSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

const here = dirname(new URL(import.meta.url).pathname);
const root = join(here, "..");

export function assemble(platform: string, dir: string, fill: Record<string, string>): void {
  const layout = JSON.parse(readFileSync(join(root, "platforms/layout.json"), "utf8"))[platform];
  if (!layout) throw new Error(`no platform ${platform}`);
  const from = join(root, "platforms", platform);
  const walk = (rel: string): string[] =>
    readdirSync(join(from, rel)).flatMap((name) => {
      const path = join(rel, name);
      return statSync(join(from, path)).isDirectory() ? walk(path) : [path];
    });
  for (const rel of walk("")) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    let text = readFileSync(join(from, rel), "utf8");
    for (const [name, value] of Object.entries(fill)) text = text.replaceAll(`__${name}__`, value);
    writeFileSync(join(dir, rel), text);
  }
  mkdirSync(dirname(join(dir, layout.core)), { recursive: true });
  cpSync(join(root, "harar-edge.ts"), join(dir, layout.core));
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  const [platform, dir, hash, sink = ""] = process.argv.slice(2);
  assemble(platform, dir, { HARAR_SETUP_CODE_HASH: hash, HARAR_LOG_SINK: sink, HARAR_D1_ID: "00000000-0000-0000-0000-000000000000" });
}
