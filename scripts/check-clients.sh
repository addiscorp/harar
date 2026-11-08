#!/bin/sh
# Every client is at harar's release version, the server's, the one a stable
# release tags and publishes (scripts/bump-version.sh sets them all).
# Packagist takes its version from the tag itself, so composer.json names
# none. Run by CI and before every publish.
set -eu
cd "$(dirname "$0")/.."
version="$(scripts/version.sh)"
python3 - "$version" <<'PY'
import json, re, sys
version = sys.argv[1]
def one(path, pattern):
    found = re.findall(pattern, open(path).read(), re.M)
    if len(found) != 1:
        sys.exit("%s: expected one version, found %s" % (path, found))
    return found[0]
got = {
    "js/package.json": json.load(open("js/package.json"))["version"],
    "python/pyproject.toml": one("python/pyproject.toml", r'^version = "([^"]+)"$'),
    "ruby/lib/harar/version.rb": one("ruby/lib/harar/version.rb", r'^  VERSION = "([^"]+)"$'),
}
wrong = {path: v for path, v in got.items() if v != version}
if wrong:
    sys.exit("harar's release version is %s, but %s" % (version, ", ".join("%s says %s" % kv for kv in wrong.items())))
if "version" in json.load(open("composer.json")):
    sys.exit("composer.json names a version; Packagist takes it from the vX.Y.Z tag")
print("clients: npm harar %s, pypi harar %s, rubygems harar %s, packagist addis/harar from v%s" % (version, version, version, version))
PY
