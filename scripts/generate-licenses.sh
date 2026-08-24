#!/usr/bin/env bash
#
# Regenerate THIRD-PARTY-LICENSES.txt - the bundled license texts of every crate
# compiled into the zecd binary. Committed to the repo (not generated at build time)
# so the reproducible StageX/Debian Docker builds stay tooling-free; the packaging
# (build-deb.sh, the release tarball, the Docker runtime image) just ships this file.
#
# cargo-about enriches license data from clearlydefined.io by default, which can pull a
# crate's copyright line from its upstream repo for crates that ship no LICENSE file,
# i.e. a *more complete* bundle, so we keep the network on. The exact text grouping it
# emits is therefore host-dependent, so CI doesn't diff bytes: the `licenses` job in
# ci.yml regenerates and fails only if the *set of crates* covered drifts from the
# committed file (the real staleness signal - a dependency added or removed).
#
# CI runs this same script (with an output path argument) rather than its own
# `cargo about` invocation, so the flags below cannot drift from what is checked.
#
# Requires cargo-about, the version CI pins:
#   cargo install cargo-about --locked --version 0.9.0 --features cli
# (the `cli` feature gates the binary itself, so a plain `cargo install` installs nothing).
# Config: about.toml +
# about.hbs. Run from anywhere; writes to the repo root unless given an output path.
#
# Usage: scripts/generate-licenses.sh [OUTPUT]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

OUTPUT="${1:-$REPO_ROOT/THIRD-PARTY-LICENSES.txt}"

if ! command -v cargo-about >/dev/null 2>&1; then
    echo "error: cargo-about not found. Install it with: cargo install cargo-about --locked" >&2
    exit 1
fi

# The shipped tree: the default features (`server` + `cli`) plus the `mimalloc-secure`
# allocator the static musl release images build with, on the release targets named in
# about.toml. `--all-features` would pull optional deps the artifacts don't carry.
cargo about generate about.hbs \
    --locked \
    --features mimalloc-secure \
    --output-file "$OUTPUT"

echo "Wrote $OUTPUT"
