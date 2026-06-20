//! JSON-RPC method dispatch.

pub mod blockchain;
pub mod control;
pub mod network;
pub mod rawtx;
pub mod util;
pub mod wallet_methods;

use serde_json::Value;

use crate::error::RpcError;
use crate::server::jsonrpc::RpcRequest;
use crate::state::AppState;

/// Every RPC method name zecd implements, used to validate the `[rpc] allowed_methods`
/// safelist at startup. Keep this in lockstep with the `dispatch` table; the
/// `all_methods_matches_dispatch_tables` test enforces it.
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
    "listtransactions",
    "z_listtransactions",
    "listsinceblock",
    "gettransaction",
    "listunspent",
    "getreceivedbyaddress",
    "listreceivedbyaddress",
    "listwallets",
    // Wallet - writes / async
    "getnewaddress",
    "sendtoaddress",
    "sendmany",
    "walletpassphrase",
    "walletlock",
    // Wallet - async operations (zcashd-style)
    "z_sendmany",
    "z_getoperationstatus",
    "z_getoperationresult",
    "z_listoperationids",
    // Wallet - address derivation (zcashd-style)
    "z_getaddressforaccount",
];

/// Whether `name` is an RPC method zecd implements (see [`ALL_METHODS`]).
pub fn is_known_method(name: &str) -> bool {
    ALL_METHODS.contains(&name)
}

/// Route a parsed request to zecd's method table. `wallet` is the wallet name from a
/// `/wallet/<name>` path (or `None` for the default wallet).
pub(crate) async fn dispatch(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    // RPC method safelist: when `[rpc] allowed_methods` is non-empty, ONLY those methods are
    // served. A blocked method is rejected exactly like one that does not exist (-32601 →
    // HTTP 404), so a locked-down server discloses nothing about the surface it has disabled.
    // An empty safelist (the default) imposes no restriction.
    let safelist = &state.config.rpc.allowed_methods;
    if !safelist.is_empty() && !safelist.iter().any(|m| m == &req.method) {
        return Err(RpcError::method_not_found(&req.method));
    }
    dispatch_zecd(state, wallet, req).await
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
        "listtransactions" => wallet_methods::listtransactions(state, wallet, req),
        "z_listtransactions" => wallet_methods::z_listtransactions(state, wallet, req),
        "listsinceblock" => wallet_methods::listsinceblock(state, wallet, req),
        "gettransaction" => wallet_methods::gettransaction(state, wallet, req).await,
        "listunspent" => wallet_methods::listunspent(state, wallet, req),
        "getreceivedbyaddress" => wallet_methods::getreceivedbyaddress(state, wallet, req),
        "listreceivedbyaddress" => wallet_methods::listreceivedbyaddress(state, wallet, req),
        "listwallets" => wallet_methods::listwallets(state),

        // Wallet - writes / async
        "getnewaddress" => wallet_methods::getnewaddress(state, wallet, req).await,
        "sendtoaddress" => wallet_methods::sendtoaddress(state, wallet, req).await,
        "sendmany" => wallet_methods::sendmany(state, wallet, req).await,
        "walletpassphrase" => wallet_methods::walletpassphrase(state, wallet, req).await,
        "walletlock" => wallet_methods::walletlock(state, wallet).await,

        // Wallet - async operations (zcashd-style; the send itself runs on a background task)
        "z_sendmany" => wallet_methods::z_sendmany(state, wallet, req),
        "z_getoperationstatus" => wallet_methods::z_getoperationstatus(state, wallet, req),
        "z_getoperationresult" => wallet_methods::z_getoperationresult(state, wallet, req),
        "z_listoperationids" => wallet_methods::z_listoperationids(state, wallet, req),

        // Wallet - address derivation (zcashd-style; exact-or-next diversified UA)
        "z_getaddressforaccount" => {
            wallet_methods::z_getaddressforaccount(state, wallet, req).await
        }

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

    /// `ALL_METHODS` must be exactly the set of methods in the dispatch table - no stale
    /// entries (a safelist would reject a real method) and nothing missing (a real method
    /// couldn't be safelisted). This pins the list to the source of truth without probing
    /// dispatch (which has side effects, e.g. `stop`).
    #[test]
    fn all_methods_matches_dispatch_tables() {
        let from_tables = dispatch_arms(include_str!("mod.rs"));
        let declared: BTreeSet<String> = super::ALL_METHODS.iter().map(|s| s.to_string()).collect();
        assert_eq!(
            from_tables, declared,
            "ALL_METHODS is out of sync with the dispatch table"
        );
        // No duplicates in the declared slice (the set would silently absorb them otherwise).
        assert_eq!(
            super::ALL_METHODS.len(),
            declared.len(),
            "ALL_METHODS contains duplicate method names"
        );
    }
}
