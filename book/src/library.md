# Embedding zecd as a library

Since 0.7.0 zecd is usable as a Rust library: a host process can bring up the wallet actors,
sync, and async operations in-process and dispatch any RPC without an HTTP socket in between.
The crate is published on [crates.io](https://crates.io/crates/zecd).

```toml
[dependencies]
zecd = { version = "0.7", default-features = false }
```

`default-features = false` drops the two feature gates below, so neither axum nor clap enters
your dependency tree. Everything on this page works in that build.

> **Maturity.** The embedding surface is new in 0.7.0 and has so far been exercised only by
> this project's own tests. The **RPC surface is not affected by that caveat**: it is the same
> code path, with the same conformance suite behind it, and has been stable across the whole
> 0.x line. If you are integrating over the network, read [RPC conventions](rpc/index.md)
> instead; this page is for callers who want to skip the socket.

## Cargo features

| Feature | Default | What it gates |
|---|---|---|
| `server` | on | The axum JSON-RPC server and the health server (`/healthz`, `/readyz`, `/status`). |
| `cli` | on | The clap surface, the printing shells around each subcommand, and `daemon::init_tracing`. |

Both are on by default, so the shipped binary, the Docker images, and the release artifacts are
built exactly as they were before the split. A library consumer turns both off.

Two requirements come with the node rather than with the features:

- **A multi-thread tokio runtime.** The scan and proving paths use `block_in_place`, which
  panics on a current-thread runtime.
- **No process-wide policy is installed for you.** The library never sets a tracing subscriber,
  never changes panic behaviour beyond an idempotent hook, and never applies the core-dump and
  ptrace lockdown that `hardening::harden_process` does for the binary. Those are the host
  application's decisions, so make them deliberately.

## The node

`node::NodeBuilder` builds a running node from a resolved configuration; `node::Node` is the
handle. `Node::call` dispatches any RPC in-process with **wire-identical semantics**: the same
method table, the same `[rpc] allowed_methods` safelist, the same arity checks, and the same
Bitcoin Core error codes an HTTP client would get. A worked example ships as
`examples/embedded.rs`.

Resolve configuration without clap via `config::AppConfig::resolve_overrides` and
`config::ConfigOverrides`.

## The typed client

`typed::Client` is one Rust method per RPC, borrowed from a node with `node::Node::wallet` and
bound to that wallet. Every wrapper builds the same positional parameters a JSON caller would
send and rides through `Node::call`, so the typed surface cannot drift away from the wire
contract; a lockstep test fails the build if any dispatched method lacks a wrapper, or if a
wrapper names a method that does not exist.

Two differences from decoding JSON yourself:

- **Amounts are exact zatoshis** (integers), not the decimal-ZEC numbers on the wire. This
  sidesteps the float hazard described under [Amounts](rpc/index.md#amounts) entirely.
- **Response structs are `#[non_exhaustive]`**, so a later release adding a field is not a
  breaking change for you. Match with `..` and construct with the provided constructors.

## Sending

`node::Node::send` with `node::SendOptions` builds, proves, and broadcasts from a
`zip321::TransactionRequest` the caller already holds, instead of rendering one into
`z_sendmany`'s JSON for zecd to parse straight back. Below the entry point it is the RPC send
path unchanged: the same [privacy ladder](design/privacy.md), the same ZIP-317 fee, the same
serialization behaviour described in [Sending](rpc/sending.md).

It accepts **duplicate recipients**, which the RPC refuses by default for zcashd parity, so one
address can be paid by several memo-carrying payments in a single transaction. Over the wire
the same thing is available behind
[`[rpc] allow_duplicate_shielded_recipients`](configuration.md#rpc).

`zip321` and `TxId` are re-exported from the crate root, so requests are built against exactly
the versions zecd links rather than against a second copy that happens to have the same
version number.

## Errors

`error::RpcError` and `error::codes` are the Bitcoin Core taxonomy `call` returns.
`RpcError::details` carries **structured data** for the errors that have it: today
`error::InsufficientFunds` on a `-6`, so a caller reads the shortfall and the value still
awaiting confirmations as numbers rather than parsing them back out of a message string.

This is in-process only. The wire error object stays exactly Bitcoin Core's `code` plus
`message`, and a test pins that, so the amounts never appear on the network. They are also
optional: the change-strategy paths genuinely do not know them, and reporting zero there would
be indistinguishable from a real zero.

The datadir-lock error is downcastable rather than only recognizable by its message text, and
carries the lock path.

## Reading wallet history

`wallet::read` is the read side of the wallet database: `wallet::read::TxQuery` and
`wallet::read::query_transactions`, returning the `wallet::read::TxRecord` and
`wallet::read::TxOutputRecord` shapes that the RPC handlers are themselves built from. It is
for an embedder with its own data model, which would otherwise be reconstructing structs from
JSON that was serialized from these.

`query_transactions` documents the total order its results come in: `(mined_height, txid)`,
with outputs in `(pool, output_index)` order. That order is what a consumer replaying wallet
history as a log needs in order to paginate and resume deterministically. It is the same fix
that made [`listtransactions` paging](rpc/wallet-history.md) stable, and for the same reason:
height alone is not injective, so a page boundary landing inside a same-height tie was
previously resolved arbitrarily.

These functions take an `engine_dir` path. Compute it with `config::engine_dir` or
`config::WalletEntry::engine_dir` and **never by joining the components yourself**, since the
layout is per-coin and per-engine (see [wallet data layout](guide/operations.md#wallet-data-layout)).

## Chain queries before a wallet exists

`chain_probe::account_birthday` and `chain_probe::tip_status` are the two chain queries that
have to happen *before* the wallet they are for exists, which is why no `Node` method can serve
them: a birthday must be chosen before the account is created, and a node needs that account to
start.

`account_birthday` is the same function `zecd init` builds its birthday with, so an embedder
pinning a birthday alongside a seed it generated itself records exactly what `init` would have.

Both take a `chain::ChainSource` the caller supplies, which is what makes them usable over a
transport zecd does not configure: dial a `tonic::Channel` through a SOCKS5 proxy yourself and
wrap it with `chain::lwd::LwdSource::connect`.

`chain_probe::probe` is the same thing the [`zecd chain-info`](configuration.md#subcommands)
subcommand prints, and the only supported way to reach the chain without a wallet at all.

**A narrow, supported slice of `chain`** goes with them: `ChainSource::latest_block`,
`ChainSource::tree_state`, `ChainSource::server_info`, the `ChainTip` and `ServerInfo` return
types, and `lwd::LwdSource::connect`. The **rest** of that trait (block streaming, the mempool,
transparent evidence) stays internal and is reshaped as backends and coins are added. Do not
build on it.

## The CLI cores

Every subcommand is a data-returning function behind its printing shell, so an embedder runs
the same code the command line does without capturing stdout:

| Function | Subcommand |
|---|---|
| `init::init_wallet` | `zecd init` |
| `init::rescan_wallet` | `zecd rescan` |
| `init::export_ufvk_string` | `zecd export-ufvk` |
| `derive_address::derive` | `zecd derive-address` |
| `config_check::check`, `config_check::inspect` | `zecd config check` |
| `config_show::render` | `zecd config show` |
| `chain_probe::probe` | `zecd chain-info` |
| `server::auth::generate_rpcauth` | `zecd rpcauth` |
| `example_config::EXAMPLE_CONFIG` | `zecd example-config` |
| `licenses::THIRD_PARTY_LICENSES` | `zecd licenses` |

## Key material

`wallet::keys::seed_with_identity` and `wallet::keys::pinned_ufvk` return the seed and viewing
key of an on-disk wallet, for protocol-layer key derivation such as an application signing its
own payloads with a BIP 44 child key.

These are deliberately **not** RPCs. zecd exports no key material over the wire, and signing a
caller-supplied digest with a wallet key would be a spend oracle, because that digest can be a
transaction sighash. In-process is a different question: the caller already holds the datadir
and the age identity file, so these add no reach it did not have. They only give it a supported
spelling. See [Key custody](security/key-custody.md).

## Several spending wallets in one process

The daemon enforces **one loaded spending wallet**, because an RPC credential is spend authority
for whichever wallet a request routes to, and two loaded spenders leave no single answer to the
question of which keys a credential can spend.

An embedded node has no RPC credentials. The host application is the authorization boundary and
names the wallet on every call, so the rule has nothing to protect there.
`[keys] allow_multiple_spending_wallets` lifts it for that case. It is off by default and
**refused by the daemon**: `zecd config check` reports it as an error for the binary, naming
what it is for. When it is on, the loaded spenders are written to the `zecd::audit` target.

## Logging when embedded

The library emits events; your subscriber receives them. That includes the `rpc` and `wallet`
spans and the `zecd::audit` target described in the
[operations runbook](guide/operations.md#structured-logging).

Two things belong to `daemon::init_tracing` rather than to the library, so a
`default-features = false` build has neither: the `[log] level` / `[log] format` / `RUST_LOG`
handling, and subscriber installation. Configure your own.
