#!/bin/sh
# The workspace publishes exactly one crate, `harar` (client/), at harar's
# release version. Cargo requires a published crate's dependencies to be on
# crates.io, so anything else left publishable would have to be published too
# (APS 3: claim only the name you need). Run by CI and before every publish.
set -eu
cd "$(dirname "$0")/.."
version="$(scripts/version.sh)"
cargo metadata --locked --no-deps --format-version 1 | python3 -c '
import json, sys
version = sys.argv[1]
packages = json.load(sys.stdin)["packages"]
# "publish": null means any registry; [] means publish = false.
publishable = sorted(p["name"] for p in packages if p["publish"] != [])
if publishable != ["harar"]:
    sys.exit("the publishable crates are %s; only harar may be (set publish = false on the rest)" % publishable)
got = next(p["version"] for p in packages if p["name"] == "harar")
if got != version:
    sys.exit("harar is %s but the release version is %s" % (got, version))
print("publishable: harar " + version)
' "$version"
