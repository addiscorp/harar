#!/bin/sh
# Two members' agents syncing one vault through a running edge (Node,
# node:sqlite, its database in a file): each with its own HOME and file keys.
# A turns sync on and founds the ring, B pairs and asks to join, A approves,
# B gets A's secret. Then both write the same secret with the edge down, and
# once it is back, last write wins on both and both flag the conflict. The
# edge's database never holds a path or a value. Last, unpairing B removes it
# from the ring and rekeys.
#
#   edge/test/sync-e2e.sh <path to the harar binary>
set -eu
harar="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
cd "$(dirname "$0")/.."
work="$(mktemp -d "${TMPDIR:-/tmp}/harar-sync-e2e.XXXXXX")"
port=18797
url="http://127.0.0.1:$port"
server=""
agents=""
cleanup() {
  for pid in $server $agents; do { kill "$pid" && wait "$pid"; } 2>/dev/null || true; done
  find "$work" -mindepth 1 -delete 2>/dev/null || true
  rmdir "$work" 2>/dev/null || true
}
trap cleanup EXIT

expect() { # <json> <path> <want>
  node -e '
    const [json, path, want] = process.argv.slice(1);
    const got = path.split(".").reduce((v, k) => v?.[k], JSON.parse(json));
    if (String(got) !== want) { console.error(`expected ${path} = ${want}, got ${JSON.stringify(got)} in ${json}`); process.exit(1); }
  ' "$1" "$2" "$3"
}
field() { node -e 'console.log(process.argv[2].split(".").reduce((v, k) => v?.[k], JSON.parse(process.argv[1])))' "$1" "$2"; }

# A member: its own HOME (state folder, edges, keys) and runtime folder, a
# file master key, and an agent on a short socket path.
member() { # <name>
  mkdir -p "$work/$1/home" "$work/$1/run"
  chmod 700 "$work/$1/run"
  printf 'a passphrase for %s only' "$1" | as "$1" key init --file-tier --path "$work/$1/master.key" --secret-stdin >/dev/null
  # A simple command, so $! is the agent itself.
  HOME="$work/$1/home" XDG_RUNTIME_DIR="$work/$1/run" "$harar" agent --key "$work/$1/master.key" --socket "$work/$1/s" --ssh-socket "$work/$1/ssh" >"$work/$1/agent.log" 2>&1 &
  agents="$agents $!"
  i=0
  until [ -S "$work/$1/s" ]; do
    i=$((i + 1)); [ "$i" -lt 50 ] || { cat "$work/$1/agent.log"; exit 1; }; sleep 0.1
  done
}
as() { # <name> <harar args…>
  name="$1"; shift
  HOME="$work/$name/home" XDG_RUNTIME_DIR="$work/$name/run" "$harar" "$@"
}
sync_() { # <name> <sync args…>
  name="$1"; shift
  as "$name" edge sync "$@" --socket "$work/$name/s"
}
put() { printf '%s' "$3" | as "$1" put --socket "$work/$1/s" "$2" --secret-stdin >/dev/null; }
get() { field "$(as "$1" get --socket "$work/$1/s" "$2")" value; }

serve() {
  node test/serve-node.ts "$work/serve" "$port" "$work/edge.db" >>"$work/server.log" 2>&1 &
  server=$!
  i=0
  until curl -fs -o /dev/null "$url/v1/health"; do
    i=$((i + 1)); [ "$i" -lt 50 ] || { cat "$work/server.log"; exit 1; }; sleep 0.2
  done
}

"$harar" edge init --vercel --dir "$work/edge" --log-sink "" </dev/null >/dev/null
# pair --dir removes the key and the setup code; the edge reads them from a copy.
mkdir "$work/serve"
cp "$work/edge/.harar-edge.key" "$work/edge/.harar-edge.setup" "$work/serve/"
serve

path=prod/sync/E2E_SECRET_PATH
first=e2e-first-value-plaintext
member a
as a edge pair "$url" --dir "$work/edge" --file-key --name a >/dev/null
on="$(sync_ a on)"
expect "$on" role member
a_id="$(field "$on" device)"
expect "$on" founder "$a_id"
put a "$path" "$first"
expect "$(sync_ a now)" queued 0
echo "ok  A turns sync on: it founds the ring, and its secret goes to the edge"

member b
code="$(field "$(as a edge pairing)" code)"
printf '%s' "$code" | as b edge pair "$url" --file-key --name b --secret-stdin >/dev/null
put b only/on/b "b-own-plaintext"
asked="$(sync_ b on)"
expect "$asked" role requested
b_id="$(field "$asked" device)"
if out="$(as b get --socket "$work/b/s" "$path" 2>&1)"; then echo "B has A's secret before approval: $out"; exit 1; fi
status="$(sync_ a now)"
expect "$status" requests.0.device "$b_id"
b_fp="$(field "$asked" fingerprint)"
expect "$status" requests.0.fingerprint "$b_fp"
if out="$(sync_ a approve "$b_id" 0000-0000-0000-0000-0000-0000-0000-0000 2>&1)"; then echo "approve took a wrong fingerprint: $out"; exit 1; fi
expect "$(sync_ a approve "$b_id" "$b_fp")" approved "$b_id"
# Approved, but B takes no grant until the person pins the ring there.
expect "$(sync_ b now)" role requested
expect "$(sync_ b trust "$(field "$on" ring)")" role member
[ "$(get b "$path")" = "$first" ] || { echo "B didn't get A's secret"; exit 1; }
sync_ a now >/dev/null
[ "$(get a only/on/b)" = "b-own-plaintext" ] || { echo "A didn't get B's own secret"; exit 1; }
echo "ok  B asks to join, A approves it by fingerprint, B pins the ring, and each gets the other's secrets"

# The edge goes down; both write the same secret, B a second later.
{ kill "$server" && wait "$server"; } 2>/dev/null || true
server=""
put a "$path" "from-a-offline-plaintext"
sleep 1
put b "$path" "from-b-offline-plaintext"
if sync_ a now >/dev/null 2>&1; then echo "a sync with the edge down succeeded"; exit 1; fi
expect "$(sync_ a status)" queued 1
serve
sync_ a now >/dev/null
sync_ b now >/dev/null
sync_ a now >/dev/null
for m in a b; do
  [ "$(get "$m" "$path")" = "from-b-offline-plaintext" ] || { echo "$m: the later write didn't win: $(get "$m" "$path")"; exit 1; }
  status="$(sync_ "$m" status)"
  expect "$status" conflicts.length 1
  expect "$status" conflicts.0.path "$path"
  expect "$status" conflicts.0.kept.device "$b_id"
  expect "$status" conflicts.0.lost.device "$a_id"
  expect "$status" queued 0
done
echo "ok  offline writes on both: the later one wins on both, and both flag the conflict"

# Nothing the edge stores names a secret or holds a value, though it holds ops.
node -e '
  const { readFileSync, existsSync } = require("node:fs");
  const { DatabaseSync } = require("node:sqlite");
  const [file, ...plain] = process.argv.slice(1);
  const rows = new DatabaseSync(file).prepare("SELECT * FROM harar_ops").all();
  // A: its member.add, the put, the approval, the offline write; B: its
  // request, its own secret, the offline write.
  if (rows.length !== 7) { console.error(`${rows.length} ops on the edge, not 7`); process.exit(1); }
  // The file as it is, and every op field decoded from base64url.
  const texts = [file, file + "-wal", file + "-journal"].filter(existsSync).map((f) => [f, readFileSync(f).toString("latin1")]);
  for (const r of rows) for (const k of ["key", "sealed", "wrapped_key"]) texts.push([`op ${r.author}:${r.seq} ${k}`, Buffer.from(String(r[k] ?? ""), "base64url").toString("latin1")]);
  for (const [where, text] of texts) for (const p of plain) if (text.includes(p)) { console.error(`${where} holds ${p}`); process.exit(1); }
' "$work/edge.db" "$path" E2E_SECRET_PATH only/on/b "$first" b-own-plaintext from-a-offline-plaintext from-b-offline-plaintext
for m in a b; do
  for f in "$work/$m/home"/.local/state/harar/sync/*.json "$work/$m/home"/Library/"Application Support"/harar/sync/*.json; do
    [ -e "$f" ] || continue
    for p in "$path" "$first" from-a-offline-plaintext from-b-offline-plaintext b-own-plaintext; do
      ! grep -qF "$p" "$f" || { echo "$f holds $p"; exit 1; }
    done
  done
done
echo "ok  the edge's database and the members' sync state hold no path and no value"

# A machine that doesn't sync can't unpair a ring member: it couldn't rekey.
sync_ b off >/dev/null
if out="$(as b edge unpair "$a_id" --socket "$work/b/s" 2>&1)"; then echo "a machine with sync off unpaired a ring member: $out"; exit 1; fi
case "$out" in *"doesn't sync"*) ;; *) echo "unpair refused for the wrong reason: $out"; exit 1 ;; esac
expect "$(sync_ b on)" role member
echo "ok  a machine that doesn't sync refuses to unpair a ring member"

# Unpairing B removes it from the ring and rekeys; A writes on with the new key.
unpaired="$(as a edge unpair "$b_id" --socket "$work/a/s")"
expect "$unpaired" removed "$b_id"
expect "$unpaired" ring.removed "$b_id"
expect "$unpaired" ring.epoch 1
put a after/removal "a-after-removal"
status="$(sync_ a now)"
expect "$status" epoch 1
expect "$status" queued 0
if sync_ b now >/dev/null 2>&1; then echo "an unpaired member still syncs"; exit 1; fi
if out="$(as b get --socket "$work/b/s" after/removal 2>&1)"; then echo "B got a secret written after its removal: $out"; exit 1; fi
echo "ok  unpairing a member removes it from the ring and rekeys"
