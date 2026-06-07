//! JSON-RPC method dispatch.

pub mod blockchain;
pub mod control;
pub mod network;
pub mod util;
pub mod wallet_methods;

use serde_json::Value;

use crate::error::RpcError;
use crate::network::ZNetwork;
use crate::server::jsonrpc::RpcRequest;
use crate::state::AppState;

pub(crate) fn net_name(network: ZNetwork) -> &'static str {
    network.name()
}

/// Route a parsed request to its handler. `wallet` is the wallet name from a `/wallet/<name>`
/// path (or `None` for the default wallet).
pub async fn dispatch(
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

        // Utility
        "validateaddress" => util::validateaddress(state, req),
        "estimatesmartfee" => util::estimatesmartfee(req),
        "estimatefee" => util::estimatefee(req),
        "getmempoolinfo" => util::getmempoolinfo(),

        // Wallet - reads
        "getbalance" => wallet_methods::getbalance(state, wallet),
        "getunconfirmedbalance" => wallet_methods::getunconfirmedbalance(state, wallet),
        "getwalletinfo" => wallet_methods::getwalletinfo(state, wallet),
        "getaddressinfo" => wallet_methods::getaddressinfo(state, wallet, req),
        "getaddressesbylabel" => wallet_methods::getaddressesbylabel(state, wallet, req),
        "listlabels" => wallet_methods::listlabels(state, wallet),
        "listtransactions" => wallet_methods::listtransactions(state, wallet, req),
        "gettransaction" => wallet_methods::gettransaction(state, wallet, req).await,
        "listunspent" => wallet_methods::listunspent(state, wallet, req),
        "listwallets" => wallet_methods::listwallets(state),
        "setlabel" => wallet_methods::setlabel(state, wallet, req),

        // Wallet - writes / async
        "getnewaddress" => wallet_methods::getnewaddress(state, wallet, req).await,
        "sendtoaddress" => wallet_methods::sendtoaddress(state, wallet, req).await,
        "sendmany" => wallet_methods::sendmany(state, wallet, req).await,
        "walletpassphrase" => wallet_methods::walletpassphrase(state, wallet, req).await,
        "walletlock" => wallet_methods::walletlock(state, wallet).await,

        other => Err(RpcError::method_not_found(other)),
    }
}
