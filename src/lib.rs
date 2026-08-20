//! The library behind the **`zecd`** binary: a Bitcoin-Core-style JSON-RPC server for
//! shielded and transparent Zcash (Ironwood, Orchard, Sapling, plus opt-in t-addresses).
//! The binary is a thin CLI wrapper around [`daemon::run`].
//!
//! # Using zecd as a library
//!
//! The supported embedding surface:
//!
//! - [`node::NodeBuilder`] / [`node::Node`] - build a running node (wallet actors, sync,
//!   async operations) without the HTTP servers, and dispatch any RPC in-process via
//!   [`node::Node::call`] with wire-identical semantics (same method table, same error
//!   codes). See `examples/embedded.rs`.
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
//! Every other public item exists because the binary and its tests are built from this crate;
//! treat it as internal API with no stability promise across commits.

pub mod address;
pub mod amount;
pub mod backend;
pub mod backoff;
pub mod chain;
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
pub mod network;
pub mod node;
pub mod operations;
pub mod pools;
pub mod rpc;
pub mod server;
pub mod state;
pub mod sync;
pub mod typed;
pub mod wallet;
