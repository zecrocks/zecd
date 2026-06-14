//! The shared library behind two binaries:
//!
//! - **`zecd`** - a Bitcoin-Core-style JSON-RPC server for Orchard-only Zcash.
//! - **`tparty`** - transparent deposit addresses that auto-shield into the same seed's
//!   shielded pool as soon as deposits confirm.
//!
//! Both binaries are thin CLI wrappers around [`daemon::run`]; they differ only in their RPC
//! dispatch table ([`state::Dispatcher`]) and the wallet actor's auto-shield configuration.

pub mod address;
pub mod amount;
pub mod backoff;
pub mod chain;
pub mod config;
pub mod daemon;
pub mod error;
pub mod hardening;
pub mod health;
pub mod init;
pub mod keystore;
pub mod lightwalletd;
pub mod network;
pub mod rewrap;
pub mod rpc;
pub mod server;
pub mod socks;
pub mod state;
pub mod sync;
pub mod wallet;
