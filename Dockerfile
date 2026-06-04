# Multi-stage build for zecd.
#
#   docker build -t zecd .
#
# The build fetches the pinned librustzcash revision from GitHub (see Cargo.toml
# [patch.crates-io]), so the build needs network access.

FROM rust:1-bookworm AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release --bin zecd

FROM debian:bookworm-slim
# ca-certificates lets native TLS roots validate public lightwalletd (e.g. zec.rocks).
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -m -d /var/lib/zecd zecd
COPY --from=build /src/target/release/zecd /usr/local/bin/zecd
USER zecd
WORKDIR /var/lib/zecd
# JSON-RPC (mainnet 8232 / testnet 18232) and health (9233).
EXPOSE 8232 18232 9233
ENTRYPOINT ["zecd"]
CMD ["--datadir", "/var/lib/zecd"]
