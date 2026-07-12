# Changelog

All notable changes to zecd are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com), and this
project adheres to [Semantic Versioning](https://semver.org).

## [0.4.3] - 2026-07-12

### Added
- Published on crates.io: install with `cargo install zecd`. Registry builds are not bit-reproducible; the Docker images remain so.

### Changed
- `/readyz` now defaults to "synced" readiness (ready only once the wallet has scanned to near the tip and drained the enhancement backlog) and surfaces a per-wallet `scan_lag`; set `readiness = "connected"` for the old reachability-only behavior.
- The example Docker Compose stack pins `zfnd/zebra:6.0.0`.

### Fixed
- A send that pays a Sapling output is routed to the fused build path, since the cached-proving-key path has no Sapling verifying key.

### Security
- Document that the single-instance datadir lock is host-local (it does not span hosts over a network filesystem) and stamp the lockfile with its holder.

## [0.4.2] - 2026-07-07

### Fixed
- `z_sendmany` with `privacyPolicy=AllowFullyTransparent` no longer rejects a bare transparent recipient; the top privacy rung had been dropped, so the send was wrongly refused as needing `AllowRevealedRecipients`.

### Security
- `getrawtransaction`, `sendrawtransaction`, and the transparent address-index lookups no longer leak the upstream zebra host, port, or cookie-file path to the RPC client; the detail is logged server-side and a generic message is returned.
- The age identity must resolve to a regular file with owner-only permissions; a symlink is followed (so a Kubernetes Secret mount still works) and the resolved target's file type and mode are enforced, with a dangling symlink failing closed.
- Bump `crossbeam-epoch` to 0.9.20 for RUSTSEC-2026-0204.

## [0.4.1] - 2026-07-05

### Added
- `signmessage`/`verifymessage` for transparent addresses.

## [0.4.0] - 2026-07-04

### Added
- Opt-in transparent (t-address) receiving, with restore recovery via a configurable `transparent_gap_limit`.
- Transparent spending: sends can be funded from transparent UTXOs (auto-shielded through the builder) with ZIP-317 coin selection and exact fees.
- `transparent_initial_scan` pre-exposure so a stateless restore rediscovers funds sent to high address indices, derived incrementally so a deep scan never freezes the daemon.
- Transparent mempool and block scanning for transparent receive discovery and 0-conf visibility.
- Regtest end-to-end coverage for fully-transparent and tri-pool `z_sendmany`.

### Changed
- `z_sendmany`'s privacy policy gains a fourth rung, `AllowFullyTransparent`, permitting fully-transparent sends; transparent recipients remain rejected under stricter policies.
- Transparent addresses are always issued as bare t-addresses, never embedded in a unified address.

## [0.3.4] - 2026-07-12

### Added
- Published on crates.io: install with `cargo install zecd`. Registry builds are not bit-reproducible; the Docker images remain so.

### Changed
- `/readyz` now defaults to "synced" readiness (ready only once the wallet has scanned to near the tip and drained the enhancement backlog) and surfaces a per-wallet `scan_lag`; set `readiness = "connected"` for the old reachability-only behavior.
- The example Docker Compose stack pins `zfnd/zebra:6.0.0`.

### Fixed
- A send that pays a Sapling output is routed to the fused build path, since the cached-proving-key path has no Sapling verifying key.

### Security
- Document that the single-instance datadir lock is host-local (it does not span hosts over a network filesystem) and stamp the lockfile with its holder.

## [0.3.3] - 2026-07-06

### Security
- `getrawtransaction` and `sendrawtransaction` errors no longer leak the upstream zebra host, port, or cookie-file path to the RPC client; the detail is logged server-side and a generic message is returned.
- The age identity must resolve to a regular file with owner-only permissions; a symlink is followed (so a Kubernetes Secret mount still works) and the resolved target's file type and mode are enforced, with a dangling symlink failing closed.
- Bump `crossbeam-epoch` to 0.9.20 for RUSTSEC-2026-0204.

## [0.3.2] - 2026-07-03

### Added
- `[spend] pipeline_proving` (default off): prove a send off the single-writer actor so a long send no longer freezes background sync.

### Changed
- Readiness (`synced` mode), `getwalletinfo.scanning`, and `getblockchaininfo.initialblockdownload` now also account for the post-scan transaction-enhancement backlog, surfaced per-wallet as `pending_enhancements`; a wallet is not "ready" until memos have been backfilled.
- `z_sendmany`'s `privacyPolicy` is a three-rung ladder (`FullPrivacy` / `AllowRevealedAmounts` / `AllowRevealedRecipients`); a transparent recipient is now rejected under every policy short of `AllowRevealedRecipients`.
- RPC argument errors follow Bitcoin Core's taxonomy (missing -1, wrong type -3, out of range -8) and enforce arity.

### Fixed
- A wallet no longer reports ready while the post-scan enhancement backlog is still draining (memos temporarily missing with no signal).
- Chain-status RPCs (`getblockchaininfo`, `getblockcount`, `getbestblockhash`, `getblockhash`, `getblockheader`) honor `/wallet/<name>` routing instead of always reporting the default wallet.
- `z_sendmany` accepts zero-valued (memo-only) outputs; the privacy-policy collapse that let stricter policies pay transparent recipients is fixed.
- Already-expired sends sync to the real chain tip before spending.
- `gettransaction` no longer over-reports the received amount by the fee.
- `listsinceblock` no longer wedges permanently after a reorg.
- Bound block-cache metadata growth and harden reorg recovery so the cache cannot grow without limit.
- Bound the full zebra request and response round-trip with the request timeout, so a stalled upstream cannot wedge sync.
- Pace reconnects with the exponential backoff after a post-connection failure, so a reachable-but-degraded upstream can no longer drive a tight reconnect loop that pegs a core.

### Security
- `walletlock` zeroizes the decrypted seed immediately via a fast path that bypasses the actor's command queue, so it takes effect even while the actor is mid-proof on a long send.
- Cap a wallet's in-flight async operations to bound a `z_sendmany` denial-of-service.
- Panic-isolate the block-scan and enhancement paths so hostile chain data cannot kill the single-writer actor.
- Gate credentialed zebra RPC connections behind a locality check, refusing cleartext auth to a globally-routable host unless `[backend] allow_remote_cleartext` is set.
- Bind the wallet database to the account viewing key recorded in `keys.toml`, so a mismatched database or keys file is detected instead of silently used.
- Only an explicit environment variable opts out of seed-memory hardening; an unset value no longer disables it.
- Warn at startup when the RPC password is passed via `--rpcpassword`, since it is visible to local users; prefer the environment variable or `password_file`.
- Bump `anyhow` to 1.0.103 for RUSTSEC-2026-0190.
- Harden config clamping, error disclosure, and SIGTERM shutdown.
- Reject unified addresses carrying a transparent receiver in `is_mine`.
- Harden cookie-file writes against symlink and stale-permission exposure.
- Reject out-of-range zebra responses (a mismatched tree-state height or an oversized per-block transaction count) as transport errors before they reach the scanner.
- Warn when an unencrypted wallet auto-unlocks its seed at startup, and document the assumed deployment posture (trust boundary) in the operations guide.

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

[0.4.3]: https://github.com/zecrocks/zecd/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/zecrocks/zecd/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/zecrocks/zecd/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/zecrocks/zecd/compare/v0.3.2...v0.4.0
[0.3.4]: https://github.com/zecrocks/zecd/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/zecrocks/zecd/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/zecrocks/zecd/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/zecrocks/zecd/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/zecrocks/zecd/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/zecrocks/zecd/releases/tag/v0.2.0
