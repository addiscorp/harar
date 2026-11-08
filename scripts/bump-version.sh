#!/bin/sh
# Set harar's one version: the server, the crate, and every client share it
# (Promote publishes them all at it). Usage: scripts/bump-version.sh X.Y.Z
# Then commit the result in a PR; the next canary builds at that version.
set -eu
cd "$(dirname "$0")/.."
new="${1:-}"
case "$new" in
  *[!0-9.]* | "" | .* | *. | *..*) echo "usage: scripts/bump-version.sh X.Y.Z" >&2; exit 2 ;;
esac
[ "$(echo "$new" | tr -cd . | wc -c | tr -d ' ')" = 2 ] || { echo "usage: scripts/bump-version.sh X.Y.Z" >&2; exit 2; }
old="$(scripts/version.sh)"
python3 - "$old" "$new" <<'PY'
import re, sys
old, new = sys.argv[1:3]
def bump(path, pattern):
    text = open(path).read()
    out, n = re.subn(pattern, lambda m: m.group(1) + new + m.group(3), text, count=1, flags=re.M)
    if n != 1:
        sys.exit("%s: no version to bump" % path)
    open(path, "w").write(out)
# [workspace.package] version: the binary (server/) and the crate (client/),
# and the server's dependency on that crate.
bump("Cargo.toml", r'(\[workspace\.package\][^\[]*?^version = ")([^"]+)(")')
bump("Cargo.toml", r'(^harar = \{ path = "client", version = ")([^"]+)(")')
# The install line the READMEs show: harar = "X.Y".
minor = ".".join(new.split(".")[:2])
for path in ("README.md", "client/README.md"):
    text = open(path).read()
    out, n = re.subn(r'harar = "\d+\.\d+"', 'harar = "%s"' % minor, text)
    if n != 1:
        sys.exit("%s: expected one harar = \"X.Y\" line, found %d" % (path, n))
    open(path, "w").write(out)
bump("js/package.json", r'(^  "version": ")([^"]+)(")')
bump("python/pyproject.toml", r'(^version = ")([^"]+)(")')
bump("ruby/lib/harar/version.rb", r'(^  VERSION = ")([^"]+)(")')
PY
# Cargo.lock records the workspace's own versions.
cargo update --workspace --offline --quiet
scripts/check-crates.sh
scripts/check-clients.sh
echo "harar ${old} -> ${new}"
