# syntax=docker/dockerfile:1
#
# Reproducible multi-stage build on StageX (https://stagex.tools), mirroring zallet's
# Dockerfile: every base image is full-source-bootstrapped and pinned by digest, the
# binaries are statically linked against musl, and the build is deterministic
# (SOURCE_DATE_EPOCH, codegen-units=1, --build-id=none) so independent builders can
# reproduce the image bit-for-bit. (That requires the vendored i18n-embed-fl patch -
# see [patch.crates-io] in Cargo.toml and the project docs "Gotchas".)
#
#   docker build -t zecd .                      # runtime image (zecd)
#   docker build --target export -o ./out .     # extract the static binaries
#
# Dependencies are released librustzcash crates from crates.io (versions pinned by the
# committed Cargo.lock), so the build needs network access to fetch them.

FROM stagex/pallet-rust:1.91.1@sha256:4062550919db682ebaeea07661551b5b89b3921e3f3a2b0bc665ddea7f6af1ca AS pallet-rust
# protoc (+ the abseil it links) is needed by zcash_client_backend's build script.
FROM stagex/user-protobuf:26.1@sha256:b399bb058216a55130d83abcba4e5271d8630fff55abbb02ed40818b0d96ced1 AS protobuf
FROM stagex/user-abseil-cpp:20240116.2@sha256:183e8aff7b3e8b37ab8e89a20a364a21d99ce506ae624028b92d3bed747d2c06 AS abseil-cpp
FROM stagex/core-ca-certificates:sx2026.05.0@sha256:f5b60a5f79003c039d4994269d7a646cc039d657d5c1503104467381b476f6fa AS ca-certificates

# --- Stage 1: Build with Rust --- (amd64)
FROM pallet-rust AS builder
COPY --from=protobuf . /
COPY --from=abseil-cpp . /

ENV SOURCE_DATE_EPOCH=1
ENV TARGET_ARCH=x86_64-unknown-linux-musl
ENV CFLAGS=-target\ x86_64-unknown-linux-musl
ENV CARGO_HOME=/usr/local/cargo
ENV CARGO_TARGET_DIR="/usr/src/zecd/target"
ENV CARGO_INCREMENTAL=0
ENV RUST_BACKTRACE=1
ENV RUSTFLAGS="\
-C codegen-units=1 \
-C target-feature=+crt-static \
-C linker=clang \
-C link-arg=-fuse-ld=lld \
-C link-arg=-Wl,--allow-multiple-definition \
-C link-arg=-ldl \
-C link-arg=-lm \
-C link-arg=-Wl,--build-id=none"
WORKDIR /usr/src/zecd
COPY . .

# Fetch dependencies
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo fetch \
        --locked \
        --target ${TARGET_ARCH}

# Build the zecd binary
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/src/zecd/target \
    cargo install \
        --frozen \
        --path . \
        --bin zecd \
        --target ${TARGET_ARCH} \
    # Skeleton dirs for the scratch runtime, COPY'd below with --chown so the
    # unprivileged runtime user can write its datadirs (and SQLite its temp files).
    && install -d -m 0755 /rootfs/var/lib/zecd \
    && install -d -m 1777 /rootfs/tmp

# --- Stage 2: layer for local binary extraction ---
FROM scratch AS export

# Binary at the root for easy extraction
COPY --from=builder /usr/local/cargo/bin/zecd /zecd

# --- Stage 3: Minimal runtime with stagex ---
FROM scratch AS runtime
COPY --from=export /zecd /usr/local/bin/zecd
# CA bundle so native TLS roots can validate public lightwalletd endpoints (e.g. zec.rocks).
COPY --from=ca-certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
COPY --from=builder --chown=10001:10001 /rootfs/ /
USER 10001:10001
WORKDIR /var/lib/zecd
# zecd JSON-RPC (mainnet 8232 / testnet 18232) + health (9233).
EXPOSE 8232 18232 9233
ENTRYPOINT ["zecd"]
CMD ["--datadir", "/var/lib/zecd"]
