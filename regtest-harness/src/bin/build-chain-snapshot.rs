//! Build a funded regtest chain once and archive it, so the funded test binaries can restore it
//! instead of each building their own.
//!
//! Every binary that calls `start_funded_chain` needs the same starting state: a chain whose
//! funder holds a spendable shielded balance. Producing it means mining past the 100-block
//! coinbase maturity (consensus - it cannot be shortened), starting the funder, shielding its
//! coinbase, and ageing the note. That measured ~89s, and 12 binaries on the zebra leg each paid
//! it for an identical result.
//!
//! This is a separate binary rather than lazy build-on-first-use inside the harness because
//! `run-tests.sh` starts many binaries at once: with build-on-use they would all find no snapshot
//! and all build one, racing over the same directory. Building once, up front, has no such
//! window.
//!
//! Usage:  build-chain-snapshot <dest-dir>        (or set ZECD_REGTEST_CHAIN_SNAPSHOT)
//!
//! The node binary comes from `ZEBRAD_BIN`/`ZAKURAD_BIN` as usual, and the funder from
//! `ZECD_FUNDER_BIN`. A snapshot is only valid for the binaries that built it, so CI keys its
//! cache on the node and funder images plus the NU6.3 activation height.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use zecd_regtest_harness::{
    resolve_node_bin, save_chain_snapshot, start_funded_chain_live, RegtestNode,
};

#[tokio::main]
async fn main() -> Result<()> {
    let dest: PathBuf = match std::env::args().nth(1) {
        Some(a) => PathBuf::from(a),
        None => match std::env::var("ZECD_REGTEST_CHAIN_SNAPSHOT") {
            Ok(v) if !v.trim().is_empty() => PathBuf::from(v),
            _ => {
                bail!("usage: build-chain-snapshot <dest-dir> (or set ZECD_REGTEST_CHAIN_SNAPSHOT)")
            }
        },
    };
    let node_bin = resolve_node_bin().ok_or_else(|| {
        anyhow::anyhow!(
            "set {} to the node binary to build a chain snapshot",
            RegtestNode::from_env().bin_env()
        )
    })?;

    // Deliberately the *live* path: this binary is what produces the snapshot, so it must never
    // restore one, even when ZECD_REGTEST_CHAIN_SNAPSHOT points at an existing (stale) archive.
    let (zebrad, funder) = start_funded_chain_live(&node_bin)
        .await
        .context("build the funded chain to archive")?;
    save_chain_snapshot(&node_bin, zebrad, funder, &dest)
        .await
        .context("archive the funded chain")?;
    Ok(())
}
