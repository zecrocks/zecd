# Changelog

All notable changes to zecd are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com), and this
project adheres to [Semantic Versioning](https://semver.org).

## [0.2.0] - 2026-06-18

Initial release: a Bitcoin Core-style JSON-RPC wallet server for Orchard-shielded
Zcash, backed entirely by librustzcash and running as a light client.

### Added
- bitcoind-compatible JSON-RPC server (framing, error codes, Basic and cookie auth, `rpcauth` multi-user credentials).
- Single-writer wallet actor with a background sync loop; reads served from short-lived connections.
- Orchard unified addresses, per-pool balances, shielded sends, and transaction history, with zcashd-style async `z_sendmany` operation tracking.
- Bitcoin-Core-style passphrase wallet encryption; age-encrypted seed at rest.
- Direct-to-zebra chain backend, watch-only wallets via UFVK import, and configurable shielded pools.
- Health and readiness server, structured logging, reproducible Docker and `.deb` builds, and a tag-driven release workflow.
- Extensive regtest end-to-end harness and Bitcoin Core conformance tests.

### Changed
- Slim zecd to zebra-only: remove lightwalletd, cloud-KMS, SOCKS5, and Prometheus.
- `FullPrivacy` now means a single shielded pool.

### Security
- Pre-release audit hardening; refuse to start on mainnet with the placeholder RPC password; enforce a 12-character passphrase minimum.

[0.2.0]: https://github.com/zecrocks/zecd/releases/tag/v0.2.0
