# Testing & conformance

How zecd is tested, layer by layer, and how to run the conformance suite against your own
instance. The layers run cheapest first: offline unit tests, a wire-format conformance suite,
stdlib smoke scripts, a full regtest end-to-end harness in CI, and manual live testnet.

The coverage bar: **every RPC method in the dispatch table is asserted somewhere in the regtest
tier**, either by `scripts/conformance.py` or by a harness test. Intentional divergences from
Bitcoin Core are listed in [Compatibility](compatibility.md).

## Offline unit and integration tests

```sh
cargo test                        # offline unit + HTTP integration tests (over 200)
cargo test -- --include-ignored   # also the slower ignored tests (actor spawn, prover load)
```

No network required. Coverage: amount conversion (decimal boundaries, no float drift),
auth (Basic, constant-time compare, cookie, bitcoind-style `rpcauth` salted HMAC), JSON-RPC 1.0
framing (single, batch, envelope, id), backend URL resolution, the Zebra client against an
in-process fake zebrad (every RPC mapping, real-block to CompactBlock conversion checked against
block-explorer ground truth, mempool poller dedupe), the full HTTP path via `tower::oneshot`
(401 on bad auth, 404 for method-not-found, batch as a 200 array, 503 when the work queue is
exhausted), and black-box CLI acceptance tests (`tests/cli.rs`).

## Conformance suite: scripts/conformance.py

The "is it identical enough to bitcoind" proof, over 250 wire-format checks. It drives a running daemon
with the same client logic `python-bitcoinrpc`'s `AuthServiceProxy` uses:

- HTTP Basic auth and the JSON-RPC 1.0 envelope (`{"result","error","id"}`)
- amounts decoded as `decimal.Decimal`, asserting exact round-trips with no float drift
- errors raised as `JSONRPCException` with the expected Bitcoin Core code
- batching (one POST, an array of responses)

It runs live in CI on every PR: the Regtest E2E workflow's funded test (`regtest_funded.rs`)
executes it against a real, funded regtest daemon, so conformance additions are exercised
end-to-end without testnet access. The original 49 checks were additionally validated against
the public testnet. With `--passphrase` (the funded e2e supplies its own) it also drives the
lock/unlock state machine (`walletpassphrase`/`walletlock` round-trips), leaving the wallet as
it was found.

## Smoke scripts

`scripts/rpc_smoke.py` is a stdlib-only (no third-party dependencies) end-to-end check of the
wire format, amounts, and error codes over HTTP. `scripts/rpc_send_smoke.py` is a manual
spending smoke test: it needs two wallets with the default one funded, and validates the
`walletlock`/`walletpassphrase` gate, `sendtoaddress`, and `sendmany` by broadcasting real
transactions.

## Regtest end-to-end harness

`regtest-harness/` (a separate crate) brings up a real regtest node and drives the compiled
`zecd` binary over JSON-RPC. The Regtest E2E workflow runs the standard tier on every PR and
push to main as a matrix of node and upstream:

| Leg | Node | zecd's upstream | Tests |
|---|---|---|---|
| `zebra, zecd` | zebrad | the node's JSON-RPC (`zebra://`) | the full list below |
| `zakura, zecd` | zakurad | the node's JSON-RPC (`zebra://`) | the full list below |
| `zebra, zecd-lwd` | zebrad | a lightwalletd in front of it | `regtest_lwd` plus the funded, transparent, shielding and merge binaries rerun in light mode |

Each node runs a pinned image on PRs and pushes; the weekly schedule runs every leg against
both the pinned image and `latest` as an upstream canary. Funding comes from a pinned
released zecd. The same workflow runs `tests/embedded_regtest.rs`, the
[library](library.md) end to end through `Node::call`.

**Standard tier** (always runs):

- `regtest_funded.rs`: the funded flows. 0-conf mempool-stream receive (visible in
  `getunconfirmedbalance`/`listtransactions`/`listunspent minconf=0` before the funding tx
  mines), a received ZIP-302 memo plus a send-memo round-trip, an enhancement guard (a
  from-birthday restore recovers the received memo purely via the enhancement step, since
  compact blocks carry no memos; see [Architecture](design/architecture.md)), `sendtoaddress`
  through confirmation, a two-output `sendmany`, manual `sendrawtransaction`, outage and expiry
  sends with the health endpoints checked through the outage, the encryption state machine, the
  busy-server burst, and finally `conformance.py` against the live daemon.
- `regtest_e2e.rs`, `regtest_binding.rs`, `regtest_sapling.rs`, `regtest_hang.rs`: the base
  receive/spend/confirm cycle, account-to-keys binding, a two-pool (Sapling + Orchard) wallet
  including a tri-pool mixed-recipient `sendmany`, and recovery from an upstream that hangs
  without dying (SIGSTOP).
- `regtest_migration.rs` (the 0.7.0 data-directory layout migration on a funded wallet),
  `regtest_ironwood.rs` (NU6.3 pool structure), and `regtest_orchard_v2_spend.rs` (a note
  received in the Orchard pool before NU6.3 activates and spent after it).
- The transparent binaries (see [Transparent addresses](guide/transparent.md)):
  `regtest_transparent.rs` (0-conf and confirmed t-address receive),
  `regtest_transparent_t2t.rs` (fully-transparent spend under `AllowFullyTransparent`, change
  stays transparent, default policy still refuses with `-6`), `regtest_transparent_gap.rs`
  (gap-limit and `transparent_initial_scan` recovery semantics on a from-seed restore),
  `regtest_transparent_offline_restore.rs` (a restore that never saw a receive and its spend
  live recovers both), `regtest_transparent_preexpose_responsive.rs` (read RPCs stay
  responsive during a deep initial-scan pre-exposure), and
  `regtest_transparent_recovery_window.rs` (beyond-gap issuance policy: warn-only vs
  fail-closed `-4`).
- `regtest_shielding.rs` (`z_sendmany` `fromaddress` coin control and the t->z shielding send),
  `regtest_mergetoaddress.rs` (consolidating a fragmented wallet), `regtest_coinbase.rs`
  (spending transparent and shielded coinbase), and `regtest_fleet.rs` (many view wallets in
  shards, each seeing only its own funds, history and addresses, across a restart).

**Extended tier** (`ZECD_REGTEST_EXTENDED=1`; weekly and on workflow dispatch, skipped in
seconds on PRs): a live reorg (zecd rewinds and follows the replacement chain), multiwallet
(`/wallet/<name>` routing, the removed label methods, one spending wallet alongside watch-only
replicas), watch-only UFVK wallets, graceful `stop` plus `init --restore --birthday` (same
first address, no phantom funds), the larger `z_mergetoaddress` cases, and on the light-mode
leg `regtest_multibackend.rs` (one daemon with a zebra-backed spending wallet beside a
lightwalletd-backed watch-only replica).

**Stress tier** (`ZECD_REGTEST_STRESS=1`; monthly cron or manual dispatch only): builds a large
note-fragmented wallet (default 256 notes) and asserts background sync stays live during a long
send with `pipeline_proving` on.

## Live testnet

The final, manual layer and the only check against the real public network: fund a testnet
wallet's Unified Address with TAZ, then verify the receive, send, and encryption flows as in
the regtest tier, plus a funds-bearing restore (the regtest restore test is fundless; it proves
the mnemonic round-trip via address determinism).

## Running conformance against your own instance

Point the scripts at your daemon's RPC endpoint and credentials:

```sh
# Unit + offline tests (amount conversion, auth, JSON-RPC framing, HTTP status codes):
cargo test

# Also run the slower ignored tests (e.g. actor-spawn tests that load the bundled prover):
cargo test -- --include-ignored

# Conformance suite against a running daemon:
python3 scripts/conformance.py --url http://127.0.0.1:18232/ --user u --password p

# Stdlib-only smoke test of the wire format, amounts, and error codes over HTTP:
python3 scripts/rpc_smoke.py --url http://127.0.0.1:18232/ --user u --password p

# Spending smoke test (manual; needs two wallets, the default one funded):
python3 scripts/rpc_send_smoke.py --send-timeout 180
```

Add `--passphrase <pass>` to `conformance.py` for an encrypted wallet to exercise the
lock/unlock state machine. Exit codes are non-zero on any failed check. See
[RPC overview](rpc/index.md) for the envelope, auth, and error-code contract these scripts
assert.
