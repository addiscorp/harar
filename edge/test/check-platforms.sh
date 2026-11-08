#!/bin/sh
# Lays out each platform's folder as `harar edge init` will and typechecks its
# entry against the core file next to it: tsc for Cloudflare and Vercel,
# deno check for Supabase (Deno). Run from edge/ after npm ci.
set -eu
cd "$(dirname "$0")/.."
out=.assembled
find "$out" -mindepth 1 -delete 2>/dev/null || true
hash=0000000000000000000000000000000000000000000000000000000000000000
for p in cloudflare vercel supabase; do
  node test/assemble.ts "$p" "$out/$p" "$hash" "https://otlp.example"
done
tsc_flags="--ignoreConfig --noEmit --strict --target es2022 --module nodenext --moduleResolution nodenext --allowImportingTsExtensions --verbatimModuleSyntax --skipLibCheck --lib es2023,dom --types node"
npx tsc $tsc_flags "$out/cloudflare/worker.ts"
echo "cloudflare: worker.ts typechecks"
npx tsc $tsc_flags "$out/vercel/api/harar.ts"
echo "vercel: api/harar.ts typechecks"
deno check "$out/supabase/supabase/functions/harar-edge/index.ts"
echo "supabase: index.ts passes deno check"
