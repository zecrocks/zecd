# Reproducible builds

zecd's release binaries, Docker images, and packages are built so that an independent party
can rebuild them bit-for-bit from the source tree. This page explains why, how each artifact
is made deterministic, and how to verify a release yourself.

## Why

zecd holds spend authority: the daemon has (or can decrypt) the seed that signs transactions.
An operator who runs a prebuilt binary is trusting whoever built it. Reproducible builds
replace that trust with a check: rebuild the same source, compare hashes, and any discrepancy
(a compromised build machine, a tampered artifact, a supply-chain injection between source
and binary) is detectable by anyone. For a wallet daemon this is not a nicety; it is the only
way a third party can confirm that the published binary is the audited source.

Two properties are involved, and zecd's two Docker builds sit at different points:

- **Determinism**: the same inputs always produce the same bytes. Both builds have this.
- **Toolchain trust**: how much you must trust the compiler and base images that produced
  those bytes. Only the amd64 StageX build has the full-source-bootstrap story.

## amd64: the StageX build (`Dockerfile`)

The primary image is a multi-stage build on [StageX](https://stagex.tools) base images:

- Every base image (`stagex/pallet-rust`, `stagex/user-protobuf`, `stagex/user-abseil-cpp`)
  is **full-source-bootstrapped** and **pinned by digest** in the Dockerfile. There is no
  upstream binary toolchain to trust; the toolchain itself is rebuilt from source.
- The binary is **statically linked against musl** (`x86_64-unknown-linux-musl`,
  `-C target-feature=+crt-static`), so the runtime image carries no libc.
- Determinism flags: `SOURCE_DATE_EPOCH=1`, `CARGO_INCREMENTAL=0`,
  `-C codegen-units=1`, and `-C link-arg=-Wl,--build-id=none`. Dependencies are pinned by
  the committed `Cargo.lock` (`cargo fetch --locked`, `cargo install --frozen`).
- The runtime stage is a bare `scratch` image: the static `zecd` binary, empty
  `/var/lib/zecd` and `/tmp` skeleton dirs, user `10001:10001`, nothing else. No CA bundle
  is needed because zecd's only upstream is a [local Zebra node over plaintext
  HTTP](zebra-backend.md); the daemon makes no outbound TLS connections.
- The build enables `--features mimalloc-secure`. musl's default allocator (`malloc-ng`)
  contends under Orchard proving's multi-threaded (rayon) allocation churn: roughly 80x more
  futex syscalls than mimalloc, costing about 10% per shielded send on bare metal and
  several times that in syscall-expensive sandboxes (gVisor, nested virtualization, some
  CI). mimalloc restores glibc-level performance; the `-secure` variant (MI_SECURE: guard
  pages, canary free-lists) adds back the heap-exploitation mitigations that replacing
  `malloc-ng` would otherwise drop, for under 4% on the proving path. Native glibc dev
  builds leave the feature off. Measurements are in
  `benchmarks/orchard-libc-bench/FINDINGS.md`.

`.dockerignore` is an allowlist (`Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `src`,
`vendor`), so the build context, and therefore the build inputs, are exactly the files the
build needs.

### The export stage

Every stage before `runtime` is shared with an `export` stage that contains only the binary
at the image root. Extract it without running a container:

```sh
docker build --target export -o ./out .     # ./out/zecd
```

This is exactly how the release workflow obtains the binaries it publishes (below), so a
local export is directly comparable to a released one.

## arm64: the pinned Alpine build (`Dockerfile.arm64`)

StageX publishes amd64 images only, so the full-source-bootstrapped build is amd64-only for
now. For ARM, `Dockerfile.arm64` produces the same output shape (a static
`aarch64-unknown-linux-musl` binary in a bare `scratch` runtime, same user, datadir, ports,
and entrypoint) from the musl-native `rust:alpine` official image, with everything pinned:

- the base image by digest (`rust:1.96.0-alpine3.24@sha256:...`);
- the C/C++/protoc toolchain to **exact apk versions** (`gcc`, `g++`, `musl-dev`,
  `binutils`, `make`, `protoc`, `protobuf-dev`), so apk cannot silently resolve a newer
  compiler that changes the emitted machine code;
- the Rust toolchain via `RUSTUP_TOOLCHAIN=1.96.0`, overriding `rust-toolchain.toml`'s
  floating `channel = "stable"`;
- the same determinism knobs as amd64 (`SOURCE_DATE_EPOCH=1`, `CARGO_INCREMENTAL=0`,
  `codegen-units=1`, `+crt-static`, `--build-id=none`, fixed build path) and
  `--features mimalloc-secure`.

The result is deterministic and independently rebuildable bit-for-bit. What it is **not** is
StageX-grade trust: the compiler and base image are upstream binary artifacts (a Docker
official image plus Alpine packages), not bootstrapped from source. Released arm64 images
carry `-arm64` suffixed tags on GHCR.

Maintenance caveat: Alpine garbage-collects superseded package versions from its CDN, so the
apk pins go stale. When the arm64 build starts failing with "package not found", the base
image digest and the apk pins must be refreshed together (keeping `RUSTUP_TOOLCHAIN` in
lockstep with the image tag). See the MAINTENANCE note in `Dockerfile.arm64`.

## Release artifacts (`release.yml`)

Pushing a `v*` tag runs the `Release` workflow. For each Linux target
(`x86_64-unknown-linux-musl` via `Dockerfile` on an amd64 runner,
`aarch64-unknown-linux-musl` via `Dockerfile.arm64` natively on an arm64 runner) it:

1. Builds the Dockerfile's `export` stage and extracts the binary. The published binaries
   therefore inherit the reproducible image pipeline; there is no separate `cargo build`
   that could diverge from the images.
2. Packages a reproducible `.tar.gz`: `tar --sort=name --owner=0 --group=0
   --numeric-owner --mtime="@1"`, then `gzip -9n` (no embedded name or timestamp).
3. Builds a reproducible `.deb` via `scripts/build-deb.sh`, which wraps the pre-built binary
   without reintroducing nondeterminism: every file's mtime is clamped to
   `SOURCE_DATE_EPOCH` (1), `dpkg-deb --root-owner-group` pins ownership to root:root, the
   changelog is compressed with `gzip -n`, and dpkg-deb (1.18.11 or later) honors
   `SOURCE_DATE_EPOCH` for the ar member timestamps. The output has been verified
   bit-for-bit across independent builds. The package carries the systemd unit and
   maintainer scripts inline; see the [deployment guide](../guide/deployment.md) for what it
   installs.
4. Writes a `.sha256` sidecar for each artifact and attaches everything to a **draft**
   GitHub release (a human reviews and publishes).

Separate `docker` and `docker-arm64` jobs in the same workflow push the GHCR images (the
amd64 push uses `rewrite-timestamp=true` and forced compression so the pushed layers are
deterministic too, and attaches SBOM and provenance attestations). The workflow also has a
`workflow_dispatch` trigger with a `version` input for dry-running the packaging without a
tag; manual runs skip the GHCR push unless `push_images` is set and always produce a draft
release.

## The vendored `i18n-embed-fl` patch

Reproducibility was validated empirically with clean double-builds, which surfaced one
nondeterministic dependency: the `fl!` localization proc-macro in `i18n-embed-fl` 0.9 (pulled
in by `age`, which encrypts the wallet mnemonic; see [key custody](../security/key-custody.md))
emits fluent message arguments in std `HashMap` iteration order. That order is randomly
seeded per rustc process, so one reachable call site in `age`'s error formatting flipped its
argument order (about 26 bytes of `.text`) on a per-build coin flip.

The fix landed upstream in `i18n-embed-fl` 0.10 (kellpossible/cargo-i18n#151), but `age` (up
to 0.11.3, the latest) requires `0.9`, which cargo cannot bump across semver. So the repo
vendors the released 0.9.4 with that fix backported at `vendor/i18n-embed-fl`, applied via
the repo's only `[patch.crates-io]` entry in `Cargo.toml`. All librustzcash crates stay on
released crates.io versions; this is the single patched dependency, and it is removed once an
`age` release depends on `i18n-embed-fl` 0.10+.

## Verifying a release

To check a published binary against the source it claims to be built from:

```sh
git clone https://github.com/zecrocks/zecd && cd zecd
git checkout v<version>

# amd64
docker build --target export -o ./out .
sha256sum out/zecd

# arm64 (on an arm64 host)
docker build -f Dockerfile.arm64 --target export -o ./out .
sha256sum out/zecd
```

Compare the hash against the binary inside the released `.tar.gz` (whose `.sha256` sidecar
covers the archive itself, so also compare the extracted `zecd`). To verify a `.deb`,
rebuild it from your extracted binary and compare the whole file:

```sh
./scripts/build-deb.sh out/zecd <version> amd64 .
sha256sum zecd_<version>_amd64.deb          # must match the released .deb
```

To verify an image rather than a binary, rebuild the runtime stage and compare the `zecd`
binary it contains (extracted via the export stage as above) against the one in the GHCR
image. The build fetches pinned dependencies from crates.io (`Cargo.lock`), so it needs
network access; everything else (base images, toolchain, flags) is pinned in the Dockerfiles.
Treat any mismatch as a red flag and report it.
