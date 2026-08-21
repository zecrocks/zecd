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
//!   returns.
//! - The CLI cores, one data-returning function per subcommand: [`init::init_wallet`],
//!   [`init::rescan_wallet`], [`init::export_ufvk_string`], [`derive_address::derive`],
//!   [`config_check::check`] (and [`config_check::inspect`]), [`config_show::render`],
//!   [`example_config::EXAMPLE_CONFIG`], and [`server::auth::generate_rpcauth`].
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
//! on a data directory this build created.
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
//! At most one loaded wallet may hold spending keys (per coin), enforced at `init` and again at
//! startup. It is a custody line, not a technical limit: with several spenders in one node,
//! "which key can this RPC credential spend?" stops having a one-word answer, and one datadir's
//! compromise reaches every seed in it. An application managing several independent writable
//! stores runs **one node per store** - separate datadirs (each with its own lock, so a
//! collision fails loudly at startup rather than corrupting a wallet database), separate ports
//! if the HTTP servers are in play. That is the shape zecd's own regtest harness runs, with the
//! funder and the wallet under test as sibling daemons. Watch-only replicas are unrestricted
//! and can be loaded anywhere, including alongside the spender they mirror.

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
pub mod coin;
pub mod config;
pub mod config_check;
pub mod config_show;
pub mod daemon;
pub mod derive_address;
pub mod error;
pub mod example_config;
pub mod hardening;
#[cfg(feature = "server")]
pub mod health;
pub mod init;
pub mod lock;
pub mod migrate;
pub mod network;
pub mod node;
pub mod operations;
pub mod pools;
pub mod progress;
pub mod rpc;
pub mod server;
pub mod state;
pub mod sync;
pub mod typed;
pub mod wallet;
