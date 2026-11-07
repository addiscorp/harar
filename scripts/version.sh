#!/bin/sh
# Print harar's version: [workspace.package] in Cargo.toml, shared by the
# binary (server/) and the `harar` crate (client/). Used by the release workflows.
set -eu
awk '
  /^\[/ { in_pkg = ($0 == "[workspace.package]") }
  in_pkg && /^version *= *"/ { sub(/^version *= *"/, ""); sub(/".*/, ""); print; exit }
' "$(dirname "$0")/../Cargo.toml"
