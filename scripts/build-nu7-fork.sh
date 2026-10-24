#!/usr/bin/env bash
# Build the experimental NU7 testnet wallet against librustzcash PR #3047.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <fresh-build-directory>" >&2
    exit 2
fi

source_root=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
build_root=$(mkdir -p "$1" && cd "$1" && pwd)
if [[ -e "$build_root/zecd" ]]; then
    echo "build directory must not contain zecd" >&2
    exit 2
fi

git -C "$source_root" worktree add --detach "$build_root/zecd" HEAD

cat > "$build_root/pr-3047.toml" <<'PATCH'
[patch.crates-io]
zcash_protocol = { git = "https://github.com/zcash/librustzcash.git", rev = "517047de130ed81059903458c933aab6684b353a" }
PATCH

RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }--cfg zcash_unstable=\"nu7\"" \
    CARGO_TARGET_DIR="$build_root/target" cargo \
    --config "$build_root/pr-3047.toml" \
    build --release --manifest-path "$build_root/zecd/Cargo.toml"

echo "$build_root/target/release/zecd"
