# Changelog

All notable changes to zecd are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com), and this
project adheres to [Semantic Versioning](https://semver.org).

## [0.3.1] - 2026-06-23

### Changed
- Outgoing transaction history is deterministic across a restore from seed.
- Run SQLite `synchronous = NORMAL` on the writer connection (WAL-safe, much faster on networked or encrypted storage).
- Reduce raw-SQL coupling to librustzcash's schema in wallet reads.
- Log the client IP on RPC auth attempts.

### Fixed
- Treat code-less zebra RPC errors as broadcast rejections instead of acceptance.

### Security
- Detect and reject hand-spliced unified addresses across own-address RPCs.
- Refuse to load over-permissive age identity files.

## [0.3.0] - 2026-06-20

### Added
- Make zecd stateless: remove address labels and off-chain state.
- `z_getaddressforaccount` RPC for zcashd-compatible unified-address derivation.
- Orchard proving-key cache to speed up sends.
- mimalloc on musl builds to restore Orchard proving performance.
- Single-instance datadir lock preventing two zecd processes on one directory.
- Bootstrap a wallet from `keys.toml` on an empty data directory.
- Configurable `/readyz` readiness (connected vs fully synced).

### Changed
- Cap the Orchard action count per send to bound memory and proving cost.
- Improve logging (wallet names, RPC auth, zebra connect and disconnect).
- Remove dead code (unused functions, fields, error codes, dependencies).

### Fixed
- Self-payments are no longer hidden from history RPCs.
- Restored wallets correctly detect unfunded addresses as `is_mine`.
- Validate fresh addresses in `listreceivedbyaddress`.

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

[0.3.1]: https://github.com/zecrocks/zecd/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/zecrocks/zecd/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/zecrocks/zecd/releases/tag/v0.2.0
