#!/bin/sh
# Every client against a real harar edge: `harar edge init` writes it, Node
# serves it (node:sqlite), the harar CLI pairs, puts two secrets and makes a
# token that may read prod/shop/*, and then the TypeScript, Python, Ruby,
# PHP, Go and Rust clients each resolve harar://prod/shop/STRIPE_KEY with it
# and are refused harar://prod/site/DATABASE_URL.
#
#   edge/test/clients-e2e.sh <path to the harar binary>
#
# In CI (CI=true) a missing runtime fails; elsewhere it is skipped and said.
set -eu
harar="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
cd "$(dirname "$0")/../.."
work="$(mktemp -d "${TMPDIR:-/tmp}/harar-clients-e2e.XXXXXX")"
port=18788
url="http://127.0.0.1:$port"
server=""
cleanup() {
  [ -n "$server" ] && kill "$server" 2>/dev/null || true
  find "$work" -mindepth 1 -delete 2>/dev/null || true
  rmdir "$work" 2>/dev/null || true
}
trap cleanup EXIT
# Only harar runs with a scratch home (its agent state); the language
# toolchains keep the real one.
mkdir -p "$work/home"
h() { HOME="$work/home" "$harar" "$@"; }

h edge init --vercel --dir "$work/edge" --log-sink "" </dev/null >/dev/null
node edge/test/serve-node.ts "$work/edge" "$port" >"$work/server.log" 2>&1 &
server=$!
i=0
until curl -fs -o /dev/null "$url/v1/health"; do
  i=$((i + 1)); [ "$i" -lt 50 ] || { cat "$work/server.log"; exit 1; }; sleep 0.2
done
h edge pair "$url" --dir "$work/edge" --file-key --name clients >/dev/null
printf 'sk_live_e2e' | h edge put prod/shop/STRIPE_KEY --secret-stdin >/dev/null
printf 'postgres://e2e' | h edge put prod/site/DATABASE_URL --secret-stdin >/dev/null
token="$(h edge token create clients --read 'prod/shop/*' | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s).token))')"

# Each client prints the value it resolved, then the refusal's message.
have() {
  if command -v "$1" >/dev/null 2>&1; then return 0; fi
  if [ "${CI:-}" = true ]; then echo "$1 is missing in CI"; exit 1; fi
  echo "skip $2: no $1 here"
  return 1
}
check() { # <client> <output>
  value="$(printf '%s\n' "$2" | sed -n 1p)"
  refusal="$(printf '%s\n' "$2" | sed -n 2p)"
  [ "$value" = sk_live_e2e ] || { echo "$1 resolved ${value:-nothing}: $2"; exit 1; }
  case "$refusal" in *"harar://prod/site/DATABASE_URL"*not_allowed*) ;; *) echo "$1 was not refused as it should be: $refusal"; exit 1 ;; esac
  echo "ok  $1: resolved the key it may read, refused the one it may not"
}

if have node typescript; then
  check typescript "$(node --input-type=module -e '
    import { vault } from "./js/index.js"
    const [edge, token] = process.argv.slice(1)
    const v = vault({ edge, token })
    console.log(await v.secrets.resolve("harar://prod/shop/STRIPE_KEY"))
    await v.secrets.resolve("harar://prod/site/DATABASE_URL").catch((e) => console.log(e.message))
  ' "$url" "$token")"
fi

if have python3 python; then
  check python "$(PYTHONPATH=python/src python3 -c '
import sys
from harar import HararError, vault
v = vault(edge=sys.argv[1], token=sys.argv[2])
print(v.secrets.resolve("harar://prod/shop/STRIPE_KEY"))
try:
    v.secrets.resolve("harar://prod/site/DATABASE_URL")
except HararError as e:
    print(e)
' "$url" "$token")"
fi

if have ruby ruby; then
  check ruby "$(ruby -Iruby/lib -e '
require "harar"
v = Harar.vault(edge: ARGV[0], token: ARGV[1])
puts v.secrets.resolve("harar://prod/shop/STRIPE_KEY")
begin
  v.secrets.resolve("harar://prod/site/DATABASE_URL")
rescue Harar::Error => e
  puts e.message
end
' "$url" "$token")"
fi

if have php php; then
  check php "$(php -r '
foreach (["HararError", "Secrets", "Vault", "EdgeSecrets", "EdgeVault", "functions"] as $f) { require "php/src/$f.php"; }
$v = Harar\vault(edge: $argv[1], token: $argv[2]);
echo $v->secrets->resolve("harar://prod/shop/STRIPE_KEY"), "\n";
try { $v->secrets->resolve("harar://prod/site/DATABASE_URL"); } catch (Harar\HararError $e) { echo $e->getMessage(), "\n"; }
' "$url" "$token")"
fi

if have go go; then
  (cd go && HARAR_TEST_EDGE_URL="$url" HARAR_TEST_EDGE_TOKEN="$token" go test -count=1 -run '^TestLiveEdge$' -v ./... >"$work/go.log" 2>&1) \
    || { cat "$work/go.log"; exit 1; }
  grep -q -- '--- PASS: TestLiveEdge' "$work/go.log" || { echo "go: TestLiveEdge did not run"; cat "$work/go.log"; exit 1; }
  echo "ok  go: resolved the key it may read, refused the one it may not"
fi

if have cargo rust; then
  HARAR_TEST_EDGE_URL="$url" HARAR_TEST_EDGE_TOKEN="$token" \
    cargo test --locked -p harar --features edge --test edge_live -- --nocapture >"$work/rust.log" 2>&1 \
    || { cat "$work/rust.log"; exit 1; }
  ! grep -q "no live edge" "$work/rust.log" || { echo "rust: the live test did not see the edge"; exit 1; }
  echo "ok  rust: resolved the key it may read, refused the one it may not"
fi
