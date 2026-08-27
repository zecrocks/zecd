//! The library behind the **`zecd`** binary: a Bitcoin-Core-style JSON-RPC server for
//! shielded and transparent Zcash (Ironwood, Orchard, Sapling, plus opt-in t-addresses).
//! The binary is a thin CLI wrapper around [`daemon::run`].
//!
//! # Using zecd as a library
//!
//! Releases are published to crates.io as [`zecd`](https://crates.io/crates/zecd); depend on
//! the released crate rather than on a git revision.
//!
//! The supported embedding surface:
//!
//! - [`node::NodeBuilder`] / [`node::Node`] - build a running node (wallet actors, sync,
//!   async operations) without the HTTP servers, and dispatch any RPC in-process via
//!   [`node::Node::call`] with wire-identical semantics (same method table, same error
//!   codes). See `examples/embedded.rs`.
//! - [`node::Node::send`] + [`node::SendOptions`] - build, prove, and broadcast a send from a
//!   `zip321::TransactionRequest` the caller already holds, instead of rendering one to
//!   `z_sendmany`'s JSON for zecd to parse back. It accepts duplicate recipients (paying one
//!   address from several memo-carrying payments in one transaction), which the RPC refuses by
//!   default for zcashd parity. Everything below it is the RPC send path unchanged.
//! - [`wallet::read`] - the read-side query API over the wallet database: [`wallet::read::TxQuery`]
//!   / [`wallet::read::query_transactions`] and the [`wallet::read::TxRecord`] /
//!   [`wallet::read::TxOutputRecord`] shapes the RPC handlers themselves are built from, for an
//!   embedder with its own data model. [`wallet::read::query_transactions`] documents the total
//!   order its results are in - `(mined_height, txid)`, with outputs in `(pool, output_index)`
//!   order - which is what a consumer replaying wallet history as a log needs in order to
//!   paginate and resume deterministically.
//! - [`config::engine_dir`] and [`config::WalletEntry::engine_dir`] - the only supported way to
//!   compute the `engine_dir` path that [`wallet::read`] takes. A wallet's librustzcash files
//!   live in a per-coin engine subdirectory of its wallet directory, and nothing outside these
//!   helpers should join those path components itself; they are named here so a supported API
//!   is not left taking a path that only internal API can produce.
//! - [`wallet::keys::seed_with_identity`] and [`wallet::keys::pinned_ufvk`] - the seed
//!   and viewing key of an on-disk wallet, for protocol-layer key derivation (an application
//!   signing its own payloads with a BIP 44 child key). Deliberately *not* an RPC: zecd exports
//!   no key material over the wire, and signing a caller-supplied digest with a wallet key would
//!   be a spend oracle (that digest can be a transaction sighash). In-process is different -
//!   the caller already holds the datadir and the age identity file, so these add no reach they
//!   did not have, only a supported spelling for it.
//! - [`config::AppConfig::resolve_overrides`] + [`config::ConfigOverrides`] - resolve the
//!   effective configuration without clap.
//! - [`error::RpcError`] and [`error::codes`] - the Bitcoin Core error taxonomy `call`
//!   returns. [`error::RpcError::details`] carries structured amounts for the errors that have
//!   them - today [`error::InsufficientFunds`] on a `-6`, so a caller reads the shortfall and
//!   the value awaiting confirmations as numbers instead of parsing the message. It is
//!   in-process only: the wire error object stays exactly Bitcoin Core's `code` + `message`.
//! - [`typed`] - one Rust method per RPC, on a wallet-bound [`typed::Client`] obtained from
//!   [`node::Node::wallet`]. Every wrapper builds the same positional params a JSON caller
//!   sends and rides through [`node::Node::call`], so the typed surface cannot drift from the
//!   wire contract; response structs are `#[non_exhaustive]` and use exact-zatoshi amounts.
//! - The CLI cores, one data-returning function per subcommand: [`init::init_wallet`],
//!   [`init::rescan_wallet`], [`init::export_ufvk_string`], [`derive_address::derive`],
//!   [`config_check::check`] (and [`config_check::inspect`]), [`config_show::render`],
//!   [`chain_probe::probe`], [`example_config::EXAMPLE_CONFIG`],
//!   [`licenses::THIRD_PARTY_LICENSES`], and [`server::auth::generate_rpcauth`].
//! - [`chain_probe::account_birthday`] and [`chain_probe::tip_status`] - the two chain queries
//!   that have to happen *before* the wallet they are for exists, so no [`node::Node`] method
//!   can serve them: a birthday must be chosen before `create_account` runs, and a node needs
//!   that account to start. `account_birthday` is the same function `init` builds its birthday
//!   with, so an embedder that pins one records what `init` would have. Both take a
//!   [`chain::ChainSource`] the caller supplies, which is what makes them usable over a
//!   transport zecd does not configure (a SOCKS5 proxy, say) via
//!   [`chain::lwd::LwdSource::connect`].
//! - A narrow, supported slice of [`chain`]: the read queries
//!   [`chain::ChainSource::latest_block`], [`chain::ChainSource::tree_state`] and
//!   [`chain::ChainSource::server_info`], their return types [`chain::ChainTip`] and
//!   [`chain::ServerInfo`], and [`chain::lwd::LwdSource::connect`], which wraps a
//!   caller-dialed `tonic::Channel`. These are enough to answer everything above without a
//!   wallet. The **rest** of the trait - block streaming, the mempool, transparent evidence -
//!   stays internal and is reshaped as backends and coins are added; do not build on it.
//! - [`chain_probe::probe`] specifically, because it fills a gap the other two leave: it is the
//!   only supported way to reach the chain *without* a wallet. [`config_check::check`] is
//!   deliberately offline, and a node needs a wallet to start, so "is the backend reachable?"
//!   and "what height is the chain at right now?" were unanswerable before
//!   [`init::init_wallet`] had run. It reports [`init::fresh_wallet_birthday`] for the tip it
//!   saw, so a caller pinning a birthday alongside a seed it generated itself records the same
//!   height `init` would.
//!
//! Cargo features: `server` (the axum JSON-RPC + health servers) and `cli` (the clap
//! surface, the printing subcommand shells, and `daemon::init_tracing`); both are default so
//! the binary and release images are unchanged, and a library consumer builds with
//! `default-features = false`. A multi-thread tokio runtime is required (the scan and
//! proving paths use `block_in_place`), and the node deliberately never installs process-wide
//! policy: tracing subscribers, panic behavior beyond an idempotent hook, and
//! [`hardening::harden_process`] (core-dump/ptrace lockdown) stay the binary's business.
//!
//! Logging follows from that: the embedder's own subscriber receives every event, including
//! the `rpc` and `wallet` spans and the `zecd::audit` target (see the README's "Logging when
//! embedded"). Two things belong to `daemon::init_tracing` rather than to the library, so a
//! `default-features = false` build has neither - `[log] level`/`[log] format`/`RUST_LOG`
//! (which still parse, and still appear in [`config_show::render`], but are read only there),
//! and the `log` -> `tracing` bridge that carries `zcash_client_sqlite`'s `schemerz` migration
//! records (an embedder wanting them installs `tracing_log::LogTracer` and filters `schemerz`
//! themselves).
//!
//! One startup side effect an embedder should know about: like the daemon,
//! [`node::NodeBuilder::start`] takes the exclusive datadir lock and, under it, migrates a data
//! directory laid out by an older zecd - librustzcash's databases move from a wallet
//! directory's root into `<wallet>/zec/lrz/`, leaving `keys.toml` where it is (see
//! [`migrate`]). Each file is renamed, it runs before any wallet is opened, and it is a no-op
//! on a data directory this build created. Two helpers there are supported for embedders that
//! need to reason about the layout without starting a node: [`migrate::awaits_migration`]
//! (whether a wallet directory still holds an old-layout database, so a host can warn or
//! schedule the lock-taking start itself) and [`migrate::engine_dir_for_reading`] (the engine
//! directory to read *without* migrating, which is how `export-ufvk` reads an un-migrated
//! wallet in place).
//!
//! Every other public item exists because the binary and its tests are built from this crate;
//! treat it as internal API with no stability promise across commits. Worth naming explicitly,
//! because they look inviting and are the ones embedders have asked about: [`chain`] (the
//! `ChainSource` trait and its zebra/lightwalletd implementations) is the multi-backend seam
//! and is reshaped as backends and coins are added; [`wallet::actor`] is the single-writer
//! actor's command protocol, which every wallet feature extends; and [`wallet::open`] /
//! [`wallet::store`] are the on-disk layout, whose invariants [`node::NodeBuilder`] exists to
//! uphold (datadir lock, binding verification, the single-spending-wallet rule) and which a
//! direct caller would have to re-uphold by hand.
//!
//! Supported items keep their names and semantics; they may gain fields and variants, so match
//! non-exhaustively and construct option structs with `..Default::default()`. One caveat
//! inherent to this surface: [`node::Node::send`] takes a `zip321::TransactionRequest` and
//! [`node::SendOptions`] carries a [`config::SendPrivacy`], so a semver bump of `zip321` is
//! visible here. That coupling is deliberate - it is the same type `z_sendmany` parses into,
//! and hiding it behind a zecd-owned mirror would mean a second type to keep in lockstep with
//! librustzcash for no gain.
//!
//! # Running several writable wallets
//!
//! By default at most one loaded wallet may hold spending keys (per coin), enforced at `init`
//! and again at startup. That is a custody line, not a technical limit, and the reason is
//! specifically about RPC: a credential is spend authority for whichever wallet a request
//! routes to, so with several spenders loaded "which key can this compromised credential
//! spend?" stops having a one-word answer, and one datadir's compromise reaches every seed in
//! it.
//!
//! That reasoning does not apply to an embedded node, which has no RPC credentials - the host
//! application is the authorization boundary and names the wallet explicitly on every
//! [`node::Node::call`] / [`node::Node::send`]. So an application managing several independent
//! writable stores in one process can set `[keys] allow_multiple_spending_wallets`, which
//! [`node::NodeBuilder`] honors and the `zecd` daemon **refuses to start on**
//! ([`config::reject_multiple_spenders_in_daemon`]); that asymmetry is the whole mechanism by
//! which the option stays library-only. The additional spenders are logged to the
//! `zecd::audit` target at startup, so the loosened posture is in the record rather than
//! silent.
//!
//! Leaving it off, the alternative is **one node per store** - separate datadirs (each with
//! its own lock, so a collision fails loudly at startup rather than corrupting a wallet
//! database), separate ports if the HTTP servers are in play. That is the shape zecd's own
//! regtest harness runs, with the funder and the wallet under test as sibling daemons, and it
//! is the only option under the daemon. Note that `server::run` is public: an embedder that
//! puts the HTTP server in front of a node with this option set re-creates exactly the
//! situation the daemon refuses, and owns that decision.
//!
//! Watch-only replicas are unrestricted either way and can be loaded anywhere, including
//! alongside the spender they mirror.

// Re-exports of the third-party types that appear on the supported surface, so an embedder
// depends on the same versions zecd does rather than pinning them independently - where a
// mismatch surfaces as a type error naming two identical-looking paths. `zip321` and `TxId`
// are `node::Node::send`'s parameter and return types.
pub use zcash_protocol::TxId;
pub use zip321;

pub mod address;
pub mod amount;
pub mod backend;
pub mod backoff;
pub mod chain;
pub mod chain_probe;
pub mod coin;
pub mod config;
pub mod config_check;
pub mod config_show;
pub mod daemon;
pub mod derive_address;
pub mod error;
pub mod example_config;
pub mod fleet;
pub mod hardening;
#[cfg(feature = "server")]
pub mod health;
pub mod init;
pub mod licenses;
pub mod lock;
pub mod migrate;
pub mod network;
pub mod node;
pub mod operations;
pub mod pools;
pub mod progress;
pub mod rpc;
pub mod server;
pub mod socks;
pub mod state;
pub mod sync;
pub mod typed;
pub mod wallet;
