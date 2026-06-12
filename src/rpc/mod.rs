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
use crate::network::ZNetwork;
use crate::server::jsonrpc::RpcRequest;
use crate::state::{AppState, Dispatcher};

pub(crate) fn net_name(network: ZNetwork) -> &'static str {
    network.name()
}

/// Route a parsed request to the method table of the binary being served (`zecd` or
/// `tparty`). `wallet` is the wallet name from a `/wallet/<name>` path (or `None` for the
/// default wallet).
pub async fn dispatch(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
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
        "walletpassphrasechange" => wallet_methods::walletpassphrasechange(state, wallet, req).await,
        "walletlock" => wallet_methods::walletlock(state, wallet).await,

        other => Err(RpcError::method_not_found(other)),
    }
}
