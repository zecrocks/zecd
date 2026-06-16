//! JSON-RPC method dispatch.

pub mod blockchain;
pub mod control;
pub mod network;
pub mod rawtx;
pub mod tparty_methods;
pub mod util;
pub mod wallet_methods;

use serde_json::Value;

use crate::error::RpcError;
use crate::server::jsonrpc::RpcRequest;
use crate::state::{AppState, Dispatcher};

/// Every RPC method name implemented by either binary, used to validate the
/// `[rpc] allowed_methods` safelist at startup. This is the *union* of both dispatch tables:
/// a name served by only one binary (tparty's `getshieldinginfo`/`shieldfunds`, or zecd's
/// `sendtoaddress`/`sendmany`) is still a valid safelist entry - it is simply inert for the
/// binary that does not serve it, which lets one shared config file lock down a paired
/// zecd+tparty deployment. Keep this in lockstep with `dispatch_zecd` and
/// `tparty_methods::dispatch`; the `all_methods_matches_dispatch_tables` test enforces it.
pub const ALL_METHODS: &[&str] = &[
    // Control
    "stop",
    "uptime",
    "help",
    "getrpcinfo",
    // Network
    "getnetworkinfo",
    "getconnectioncount",
    "getpeerinfo",
    "ping",
    // Blockchain
    "getblockchaininfo",
    "getblockcount",
    "getbestblockhash",
    "getblockhash",
    "getblockheader",
    // Utility
    "validateaddress",
    "settxfee",
    "estimatesmartfee",
    "estimatefee",
    "getmempoolinfo",
    // Raw transactions
    "getrawtransaction",
    "sendrawtransaction",
    // Wallet - reads
    "getbalance",
    "getbalances",
    "getunconfirmedbalance",
    "getwalletinfo",
    "getaddressinfo",
    "getaddressesbylabel",
    "listlabels",
    "listtransactions",
    "z_listtransactions",
    "listsinceblock",
    "gettransaction",
    "listunspent",
    "getreceivedbyaddress",
    "listreceivedbyaddress",
    "getreceivedbylabel",
    "listreceivedbylabel",
    "listwallets",
    "setlabel",
    // Wallet - writes / async
    "getnewaddress",
    "sendtoaddress",
    "sendmany",
    "encryptwallet",
    "walletpassphrase",
    "walletpassphrasechange",
    "walletlock",
    // tparty only
    "getshieldinginfo",
    "shieldfunds",
];

/// Whether `name` is an RPC method implemented by either binary (see [`ALL_METHODS`]).
pub fn is_known_method(name: &str) -> bool {
    ALL_METHODS.contains(&name)
}

/// Route a parsed request to the method table of the binary being served (`zecd` or
/// `tparty`). `wallet` is the wallet name from a `/wallet/<name>` path (or `None` for the
/// default wallet).
pub(crate) async fn dispatch(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    // RPC method safelist: when `[rpc] allowed_methods` is non-empty, ONLY those methods are
    // served. A blocked method is rejected exactly like one that does not exist (-32601 →
    // HTTP 404), so a locked-down server discloses nothing about the surface it has disabled.
    // An empty safelist (the default) imposes no restriction. The gate runs ahead of the
    // per-binary table so it applies uniformly to zecd and tparty.
    let safelist = &state.config.rpc.allowed_methods;
    if !safelist.is_empty() && !safelist.iter().any(|m| m == &req.method) {
        return Err(RpcError::method_not_found(&req.method));
    }
    match state.dispatcher {
        Dispatcher::Zecd => dispatch_zecd(state, wallet, req).await,
        Dispatcher::Tparty => tparty_methods::dispatch(state, wallet, req).await,
    }
}

/// zecd's method table.
async fn dispatch_zecd(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    match req.method.as_str() {
        // Control
        "stop" => control::stop(state),
        "uptime" => control::uptime(state),
        "help" => control::help(),
        "getrpcinfo" => control::getrpcinfo(state),

        // Network
        "getnetworkinfo" => network::getnetworkinfo(state),
        "getconnectioncount" => network::getconnectioncount(state),
        "getpeerinfo" => network::getpeerinfo(state),
        "ping" => network::ping(),

        // Blockchain
        "getblockchaininfo" => blockchain::getblockchaininfo(state),
        "getblockcount" => blockchain::getblockcount(state),
        "getbestblockhash" => blockchain::getbestblockhash(state),
        "getblockhash" => blockchain::getblockhash(state, req),
        "getblockheader" => blockchain::getblockheader(state, req),

        // Utility
        "validateaddress" => util::validateaddress(state, req),
        "settxfee" => util::settxfee(req),
        "estimatesmartfee" => util::estimatesmartfee(req),
        "estimatefee" => util::estimatefee(req),
        "getmempoolinfo" => util::getmempoolinfo(),

        // Raw transactions (served via the wallet's lightwalletd connection)
        "getrawtransaction" => rawtx::getrawtransaction(state, wallet, req).await,
        "sendrawtransaction" => rawtx::sendrawtransaction(state, wallet, req).await,

        // Wallet - reads
        "getbalance" => wallet_methods::getbalance(state, wallet, req),
        "getbalances" => wallet_methods::getbalances(state, wallet),
        "getunconfirmedbalance" => wallet_methods::getunconfirmedbalance(state, wallet),
        "getwalletinfo" => wallet_methods::getwalletinfo(state, wallet),
        "getaddressinfo" => wallet_methods::getaddressinfo(state, wallet, req),
        "getaddressesbylabel" => wallet_methods::getaddressesbylabel(state, wallet, req),
        "listlabels" => wallet_methods::listlabels(state, wallet),
        "listtransactions" => wallet_methods::listtransactions(state, wallet, req),
        "z_listtransactions" => wallet_methods::z_listtransactions(state, wallet, req),
        "listsinceblock" => wallet_methods::listsinceblock(state, wallet, req),
        "gettransaction" => wallet_methods::gettransaction(state, wallet, req).await,
        "listunspent" => wallet_methods::listunspent(state, wallet, req),
        "getreceivedbyaddress" => wallet_methods::getreceivedbyaddress(state, wallet, req),
        "listreceivedbyaddress" => wallet_methods::listreceivedbyaddress(state, wallet, req),
        "getreceivedbylabel" => wallet_methods::getreceivedbylabel(state, wallet, req),
        "listreceivedbylabel" => wallet_methods::listreceivedbylabel(state, wallet, req),
        "listwallets" => wallet_methods::listwallets(state),
        "setlabel" => wallet_methods::setlabel(state, wallet, req),

        // Wallet - writes / async
        "getnewaddress" => wallet_methods::getnewaddress(state, wallet, req).await,
        "sendtoaddress" => wallet_methods::sendtoaddress(state, wallet, req).await,
        "sendmany" => wallet_methods::sendmany(state, wallet, req).await,
        "encryptwallet" => wallet_methods::encryptwallet(state, wallet, req).await,
        "walletpassphrase" => wallet_methods::walletpassphrase(state, wallet, req).await,
        "walletpassphrasechange" => {
            wallet_methods::walletpassphrasechange(state, wallet, req).await
        }
        "walletlock" => wallet_methods::walletlock(state, wallet).await,

        other => Err(RpcError::method_not_found(other)),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    /// Extract the method names from a dispatch `match` by scanning the non-test source for
    /// `"name" =>` arms - the only place either dispatch module uses that shape. Splitting at
    /// `#[cfg(test)]` keeps this test's own string literals out of the result.
    fn dispatch_arms(src: &str) -> BTreeSet<String> {
        let code = src.split("#[cfg(test)]").next().unwrap_or(src);
        let mut out = BTreeSet::new();
        for line in code.lines() {
            if let Some(rest) = line.trim_start().strip_prefix('"') {
                if let Some(end) = rest.find('"') {
                    if rest[end + 1..].trim_start().starts_with("=>") {
                        out.insert(rest[..end].to_string());
                    }
                }
            }
        }
        out
    }

    /// `ALL_METHODS` must be exactly the union of the two dispatch tables - no stale entries
    /// (a safelist would reject a real method) and nothing missing (a real method couldn't be
    /// safelisted). This pins the list to the source of truth without probing dispatch (which
    /// has side effects, e.g. `stop`).
    #[test]
    fn all_methods_matches_dispatch_tables() {
        let mut from_tables = dispatch_arms(include_str!("mod.rs"));
        from_tables.extend(dispatch_arms(include_str!("tparty_methods.rs")));
        let declared: BTreeSet<String> = super::ALL_METHODS.iter().map(|s| s.to_string()).collect();
        assert_eq!(
            from_tables, declared,
            "ALL_METHODS is out of sync with the dispatch tables (zecd + tparty union)"
        );
        // No duplicates in the declared slice (the set would silently absorb them otherwise).
        assert_eq!(
            super::ALL_METHODS.len(),
            declared.len(),
            "ALL_METHODS contains duplicate method names"
        );
    }
}
