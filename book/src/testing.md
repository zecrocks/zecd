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

`regtest-harness/` (a separate crate) brings up a real regtest zebrad and drives the compiled
`zecd` binary over JSON-RPC. The Regtest E2E workflow runs the standard tier on every PR and
push to main; a weekly schedule reruns everything against both the pinned Zebra image and
`zfnd/zebra:latest` as an upstream canary.

**Standard tier** (always runs):

- `regtest_funded.rs`: the funded flows. 0-conf mempool-stream receive (visible in
  `getunconfirmedbalance`/`listtransactions`/`listunspent minconf=0` before the funding tx
  mines), a received ZIP-302 memo plus a send-memo round-trip, an enhancement guard (a
  from-birthday restore recovers the received memo purely via the enhancement step, since
  compact blocks carry no memos; see [Architecture](design/architecture.md)), `sendtoaddress`
  through confirmation, a two-output `sendmany`, manual `sendrawtransaction`, outage and expiry
  sends with the health endpoints checked through the outage, the encryption state machine, the
  busy-server burst, and finally `conformance.py` against the live daemon.
- `regtest_e2e.rs`, `regtest_binding.rs`, `regtest_proving_cache.rs`, `regtest_sapling.rs`,
  `regtest_hang.rs`: the base receive/spend/confirm cycle against the `zebra://` upstream,
  account-to-keys binding, both proving paths, a two-pool (Sapling + Orchard) wallet including
  a tri-pool mixed-recipient `sendmany`, and recovery from an upstream that hangs without dying
  (SIGSTOP).
- The transparent binaries (see [Transparent addresses](guide/transparent.md)):
  `regtest_transparent.rs` (0-conf and confirmed t-address receive),
  `regtest_transparent_t2t.rs` (fully-transparent spend under `AllowFullyTransparent`, change
  stays transparent, default policy still refuses with `-6`),
  `regtest_transparent_sendmany_t2t.rs` (the same spend driven through `sendmany`, two
  transparent recipients in one tx), `regtest_transparent_gap.rs` (gap-limit and
  `transparent_initial_scan` recovery semantics on a from-seed restore),
  `regtest_transparent_preexpose_responsive.rs` (read RPCs stay responsive during a deep
  initial-scan pre-exposure), and `regtest_transparent_recovery_window.rs` (beyond-gap issuance
  policy: warn-only vs fail-closed `-4`).

**Extended tier** (`ZECD_REGTEST_EXTENDED=1`; weekly and on workflow dispatch, skipped in
seconds on PRs): a live reorg (zecd rewinds and follows the replacement chain), multiwallet
(`/wallet/<name>` routing, the removed label methods, one spending wallet alongside watch-only
replicas), watch-only UFVK wallets, and graceful `stop` plus `init --restore --birthday` (same
first address, no phantom funds).

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
