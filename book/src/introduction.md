# Introduction

zecd is a shielded-first Zcash wallet server that speaks Bitcoin Core's JSON-RPC dialect.

## What zecd is

zecd is a wallet daemon for Zcash built on [librustzcash](https://github.com/zcash/librustzcash):
shielded-first (Orchard by default, with opt-in Sapling receivers and opt-in transparent
t-address support), exposed through **bitcoind's RPC dialect**: the same method names, response
shapes, JSON-RPC 1.0 envelope, HTTP Basic/cookie auth, and error codes as Bitcoin Core. An
integration that drives a coin purely through Bitcoin RPC (`getnewaddress`, poll
`listtransactions`/`gettransaction`/`getbalance`, `sendtoaddress`) works against zecd with
little or no change, and existing Bitcoin RPC client libraries (e.g. `python-bitcoinrpc`)
connect as-is.

It is written for integrators and operators: engineers wiring a payment system, exchange, or
service to Zcash, and the SREs who run it. It is a light client: it syncs compact blocks in
the background, never speaks P2P, and never indexes the chain itself.

## Deployment model

zecd sits between your application and a **self-hosted [Zebra](https://github.com/ZcashFoundation/zebra)
full node**, talking to zebrad's JSON-RPC directly:

```text
+----------------------+            +----------------+            +------------------+
|  your app /          |  JSON-RPC  |      zecd      |  JSON-RPC  |      Zebra       |
|  Bitcoin RPC client  | ---------> | wallet server  | ---------> |  (self-hosted    |
|  (python-bitcoinrpc, |  Bitcoin   | keys, scanning,|  zebra://  |   full node)     |
|   curl, existing     |  Core      | proving, RPC   |  host:port | consensus, P2P,  |
|   bitcoind tooling)  |  dialect   | surface        |  (local)   | blocks, mempool  |
+----------------------+            +----------------+            +------------------+
       port 8232 mainnet /               derives compact blocks,      rpc.listen_addr
       18232 testnet                     tree state, and mempool      8234 mainnet /
                                         from the node RPCs itself    18234 testnet
```

The default `[backend] server = "zebra"` is shorthand for `zebra://127.0.0.1:8234` on mainnet
(`:18234` on test/regtest). Point zebrad's `rpc.listen_addr` there; Zebra ships with RPC
disabled. zecd derives compact blocks, tree state, and mempool visibility from the node's
RPCs itself, so there is no lightwalletd and no zaino to operate. See
[A Zebra-only backend](design/zebra-backend.md).

**Run the node yourself.** zecd holds spend authority over real funds, and its entire view of
the chain (balances, confirmations, incoming payments) is whatever Zebra serves it. The
Zebra connection is plaintext HTTP and deliberately local-only: a cleartext-credential gate
refuses to send `[zebra]` RPC credentials to a globally-routable host (loopback and, by
default, private/LAN ranges are allowed).

## Defining properties

- **Bitcoin Core RPC conformance.** Method names, field names/types, the JSON-RPC 1.0
  envelope, Basic/cookie auth, error codes, and HTTP status mapping match Bitcoin Core, and a
  conformance suite drives a live daemon with the same client logic `python-bitcoinrpc` uses
  (see [Testing & conformance](testing.md)). Intentional divergences are enumerated in the
  [compatibility boundary](compatibility.md); the wire format is specified in
  [RPC conventions](rpc/index.md).
- **Shielded-first, transparent opt-in.** The default wallet is Orchard-only; Sapling
  receivers and transparent (t-address) receiving/spending are enabled per wallet via
  `[pools]` config. See [Addresses & shielded pools](guide/addresses.md) and
  [Transparent support](guide/transparent.md).
- **Stateless and seed-recoverable.** zecd persists no off-chain state that a from-seed
  restore couldn't rebuild: there are no address labels, and `zecd init --restore` recovers
  all funds and history from the chain. Shielded funds are recoverable unconditionally;
  transparent funds within the configured gap limit / initial-scan window. See
  [Stateless & recoverable](design/statelessness.md).
- **A single self-hosted Zebra upstream.** One local zebrad over JSON-RPC; no lightwalletd,
  no zaino, no trusted third-party servers. See
  [A Zebra-only backend](design/zebra-backend.md).
- **One spending wallet, any number of watch-only wallets.** At most one loaded wallet holds
  spending keys; watch-only replicas are built from an exported Unified Full Viewing Key and
  addressed bitcoind-style at `/wallet/<name>`. See
  [Watch-only wallets](guide/watch-only.md).
- **Reproducible builds.** The release pipeline produces bit-for-bit reproducible static
  binaries (a full-source-bootstrapped StageX image on amd64, a fully pinned Alpine build on
  arm64) and deterministic `.tar.gz`/`.deb` packages. See
  [Reproducible builds](design/reproducible-builds.md).
- **ZIP-317 fees, ZIP-315 confirmations.** Fees follow the deterministic
  [ZIP 317](https://zips.z.cash/zip-0317) formula and are never client-settable (explicit fee
  parameters are rejected with `-8`). Spendability follows
  [ZIP 315](https://zips.z.cash/zip-0315)'s defaults (3 confirmations for the wallet's own
  change, 10 for third-party payments), configurable via `[spend]`. See
  [Sending](rpc/sending.md).

## What zecd is not

- **Not zcashd-RPC-compatible.** zecd is intentionally not a zcashd clone: it does not
  implement zcashd's `z_*` surface except a small chosen subset (`z_sendmany` plus the
  operation-tracking trio, `z_listtransactions`, `z_getaddressforaccount`). Migrating an
  integration is a concept mapping, not a drop-in; see
  [Migrating from zcashd](migrating-from-zcashd.md).
- **No P2P.** zecd never speaks the Zcash peer-to-peer protocol; Zebra is its only upstream,
  and `getpeerinfo` reports at most that one connection.
- **Not a chain indexer.** It tracks a single account per wallet, not arbitrary addresses or
  xpub derivation schemes, and holds no full-block or address index of its own.
- **No per-address key import.** Every address derives from the wallet seed (diversified
  addresses of one ZIP-32 account); there is no `importprivkey`/`importaddress`, and the only
  import path is a whole account via seed restore or UFVK.

## Where to go next

- **First run:** the [Quickstart](quickstart.md) takes you from a Zebra node to a funded
  wallet answering RPC; the [Configuration](configuration.md) reference covers every TOML key
  and CLI flag.
- **Coming from zcashd:** [Migrating from zcashd](migrating-from-zcashd.md).
- **Building an integration:** [RPC conventions & wire format](rpc/index.md), then the
  [method index](rpc/method-index.md) for the full method-by-method comparison with bitcoind
  and zcashd.
- **Running it in production:** [Deployment](guide/deployment.md) (Docker, `.deb`/systemd,
  release binaries) and the [Operations runbook](guide/operations.md) (backup/restore,
  monitoring, health endpoints).
- **Understanding the design:** [Architecture](design/architecture.md),
  [Stateless & recoverable](design/statelessness.md), the
  [privacy policy ladder](design/privacy.md), and the
  [threat model](security/threat-model.md).
- **Edges and gaps:** the [compatibility boundary](compatibility.md) and
  [known limitations](limitations.md).
