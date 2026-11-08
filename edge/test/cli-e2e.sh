#!/bin/sh
# The harar CLI against a running edge: `harar edge init` writes the folder,
# the edge serves it (Node, node:sqlite), and the CLI pairs, puts, makes a
# token, rotates, revokes and reads the log, while curl plays the service.
# Fails if the CLI and the edge disagree on anything, the signature format
# first of all.
#
#   edge/test/cli-e2e.sh <path to the harar binary>
set -eu
harar="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
cd "$(dirname "$0")/.."
work="$(mktemp -d "${TMPDIR:-/tmp}/harar-edge-e2e.XXXXXX")"
port=18787
url="http://127.0.0.1:$port"
server=""
cleanup() {
  [ -n "$server" ] && kill "$server" 2>/dev/null || true
  find "$work" -mindepth 1 -delete 2>/dev/null || true
  rmdir "$work" 2>/dev/null || true
}
trap cleanup EXIT
export HOME="$work/home"
mkdir -p "$HOME"

# What a JSON answer says at a dotted path; fails if it isn't what we expect.
expect() { # <json> <path> <want>
  node -e '
    const [json, path, want] = process.argv.slice(1);
    const got = path.split(".").reduce((v, k) => v?.[k], JSON.parse(json));
    if (String(got) !== want) { console.error(`expected ${path} = ${want}, got ${JSON.stringify(got)} in ${json}`); process.exit(1); }
  ' "$1" "$2" "$3"
}

"$harar" edge init --vercel --dir "$work/edge" --log-sink "" </dev/null >/dev/null
node test/serve-node.ts "$work/edge" "$port" >"$work/server.log" 2>&1 &
server=$!
i=0
until curl -fs -o /dev/null "$url/v1/health"; do
  i=$((i + 1)); [ "$i" -lt 50 ] || { cat "$work/server.log"; exit 1; }; sleep 0.2
done

expect "$("$harar" edge pair "$url" --dir "$work/edge" --file-key --name ci)" ok true
[ ! -e "$work/edge/.harar-edge.setup" ] || { echo "pair left the used setup code behind"; exit 1; }
echo "ok  paired with the setup code from init, which is gone now"

expect "$(printf 'sk_live_ci' | "$harar" edge put prod/shop/STRIPE_KEY --secret-stdin)" version 1
printf 'postgres://ci' | "$harar" edge put prod/site/DATABASE_URL --secret-stdin >/dev/null
made="$("$harar" edge token create ci-shop --read 'prod/shop/*')"
token="$(node -e 'console.log(JSON.parse(process.argv[1]).token)' "$made")"
id="$(node -e 'console.log(JSON.parse(process.argv[1]).id)' "$made")"
resolve() {
  curl -s -X POST "$url/v1/resolve" -H "authorization: Bearer $token" -H 'content-type: application/json' -d "{\"refs\":[\"harar://$1\"]}"
}
expect "$(resolve prod/shop/STRIPE_KEY)" values.0 sk_live_ci
expect "$(resolve prod/site/DATABASE_URL)" error not_allowed
echo "ok  a token from the CLI resolves what it may read, and is refused the rest"

expect "$(printf 'sk_live_rotated' | "$harar" edge put prod/shop/STRIPE_KEY --rotate --secret-stdin)" version 2
expect "$(resolve prod/shop/STRIPE_KEY)" values.0 sk_live_rotated
expect "$("$harar" edge token revoke "$id")" revoked "$id"
expect "$(resolve prod/shop/STRIPE_KEY)" error revoked
echo "ok  rotated, then revoked"

log="$("$harar" edge log)"
expect "$log" chain intact
expect "$log" log.length 11
echo "ok  the log: 11 rows, the CLI finds its chain intact"
