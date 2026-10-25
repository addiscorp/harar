#!/bin/sh
# Print harar's version, from harar/Cargo.toml. Used by the release workflows.
set -eu
sed -n 's/^version *= *"\([^"]*\)".*/\1/p' "$(dirname "$0")/../harar/Cargo.toml" | head -n 1
