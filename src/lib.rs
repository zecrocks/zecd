//! The library behind the **`zecd`** binary: a Bitcoin-Core-style JSON-RPC server for
//! Orchard-only Zcash. The binary is a thin CLI wrapper around [`daemon::run`].

pub mod address;
pub mod amount;
pub mod backend;
pub mod backoff;
pub mod chain;
pub mod config;
pub mod daemon;
pub mod error;
pub mod hardening;
pub mod health;
pub mod init;
pub mod keystore;
pub mod network;
pub mod operations;
pub mod rewrap;
pub mod rpc;
pub mod server;
pub mod socks;
pub mod state;
pub mod sync;
pub mod wallet;
