//! The typed client: one Rust method per RPC, layered strictly on [`crate::node::Node::call`].
//!
//! Every wrapper builds the same positional parameters a JSON-RPC caller would send and
//! deserializes the `Value` the dispatch table returned, so the typed API rides *through* the
//! wire contract rather than beside it - error codes, arity checks, and the
//! `[rpc] allowed_methods` safelist all still apply, and the typed layer cannot drift from
//! what conformance pins. Response structs are `#[non_exhaustive]` and tolerate unknown wire
//! fields, so adding a field to a response is never a breaking change here.
//!
//! Style rule (load-bearing for the lockstep test in this module): every wrapper's body
//! contains exactly one `call_typed("<method>", ...)` with the method name as a string
//! literal on that line, and each method name appears in exactly one wrapper.
//!
//! Amounts are [`crate::amount::Amount`]/[`crate::amount::SignedAmount`] - exact zatoshi
//! values that never round-trip through `f64`. Txids and block hashes are display-order hex
//! `String`s (a `Txid` newtype is future work). Heights are `u32`.

pub mod blockchain;
pub mod control;
pub mod network;
pub mod util;
pub mod wallet;

use serde_json::Value;

use crate::error::RpcError;
use crate::node::Node;

/// Error from a typed call: the server-side [`RpcError`] (exactly what the wire returns), or
/// a client-side decode failure - which means zecd's response shape and the typed struct
/// disagree, i.e. a zecd bug worth reporting, never a user error.
#[derive(Debug)]
pub enum ClientError {
    Rpc(RpcError),
    Decode {
        method: &'static str,
        source: serde_json::Error,
    },
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Rpc(e) => write!(f, "RPC error {}: {}", e.code, e.message),
            ClientError::Decode { method, source } => write!(
                f,
                "decoding the {method} response failed (zecd's response shape and the typed \
                 struct disagree - please report this): {source}"
            ),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ClientError::Rpc(_) => None,
            ClientError::Decode { source, .. } => Some(source),
        }
    }
}

impl From<RpcError> for ClientError {
    fn from(e: RpcError) -> ClientError {
        ClientError::Rpc(e)
    }
}

impl ClientError {
    /// The server-side error code, when this is an [`ClientError::Rpc`] (`None` for a decode
    /// failure) - the ergonomic form of matching on the variant for callers that branch on
    /// Bitcoin Core codes (`-6` insufficient funds, `-8` invalid parameter, ...).
    pub fn code(&self) -> Option<i32> {
        match self {
            ClientError::Rpc(e) => Some(e.code),
            ClientError::Decode { .. } => None,
        }
    }
}

/// A wallet-bound typed client borrowed from a [`Node`]. `node.wallet(None)` targets the
/// default wallet; `node.wallet(Some("w2"))` mirrors the HTTP `/wallet/w2` routing.
pub struct Client<'a> {
    node: &'a Node,
    wallet: Option<&'a str>,
}

impl Node {
    /// A typed client for `wallet` (`None` = the default wallet, like the HTTP root path).
    pub fn wallet<'a>(&'a self, name: Option<&'a str>) -> Client<'a> {
        Client {
            node: self,
            wallet: name,
        }
    }
}

impl Client<'_> {
    /// Dispatch one call through [`Node::call`] and deserialize the result.
    async fn call_typed<T: serde::de::DeserializeOwned>(
        &self,
        method: &'static str,
        params: Vec<Value>,
    ) -> Result<T, ClientError> {
        let value = self.node.call(self.wallet, method, params).await?;
        serde_json::from_value(value).map_err(|source| ClientError::Decode { method, source })
    }

    /// Assemble positional parameters from optional arguments: trailing `None`s are omitted
    /// (exactly as a positional JSON caller skips trailing arguments) and interior `None`s
    /// become `null` (the wire spelling for "defaulted, but a later argument is present").
    fn positional(args: Vec<Option<Value>>) -> Vec<Value> {
        let mut out: Vec<Value> = args.into_iter().map(|a| a.unwrap_or(Value::Null)).collect();
        while out.last() == Some(&Value::Null) {
            out.pop();
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::{json, Value};

    use super::Client;

    /// Extract every `call_typed("name"` method literal from a typed source file, skipping
    /// its `#[cfg(test)]` tail - the same source-scanning technique as
    /// `rpc::tests::all_methods_matches_dispatch_tables`. Whitespace-tolerant between the
    /// call and its first argument, so a rustfmt line break inside the call cannot hide a
    /// wrapper from the lockstep check.
    fn typed_methods(src: &str) -> Vec<String> {
        let code = src.split("#[cfg(test)]").next().unwrap_or(src);
        let mut out = Vec::new();
        for chunk in code.split("call_typed(").skip(1) {
            let rest = chunk.trim_start();
            if let Some(rest) = rest.strip_prefix('"') {
                if let Some(end) = rest.find('"') {
                    out.push(rest[..end].to_string());
                }
            }
        }
        out
    }

    /// The lockstep guard: the typed client wraps exactly the dispatch surface - every
    /// method in `rpc::ALL_METHODS` has a wrapper, no wrapper names an unknown method, and
    /// no method is wrapped twice. Adding a dispatch arm without a typed wrapper (or the
    /// reverse) fails here.
    #[test]
    fn typed_client_covers_all_methods_exactly() {
        let mut all: Vec<String> = Vec::new();
        for src in [
            include_str!("blockchain.rs"),
            include_str!("control.rs"),
            include_str!("network.rs"),
            include_str!("util.rs"),
            include_str!("wallet.rs"),
        ] {
            all.extend(typed_methods(src));
        }
        let unique: BTreeSet<&str> = all.iter().map(|s| s.as_str()).collect();
        assert_eq!(
            unique.len(),
            all.len(),
            "a method is wrapped more than once: {all:?}"
        );
        let declared: BTreeSet<&str> = crate::rpc::ALL_METHODS.iter().copied().collect();
        assert_eq!(
            unique, declared,
            "typed wrappers out of sync with rpc::ALL_METHODS"
        );
    }

    /// End-to-end typed round trips through `Node::call` against a walletless node: the
    /// utility methods answer typed, and the typed layer surfaces dispatch's own errors
    /// (never inventing client-side validation).
    #[tokio::test]
    async fn typed_calls_round_trip_through_dispatch() {
        let node = crate::node::testutil::walletless_node();
        let c = node.wallet(None);

        assert!(c.uptime().await.is_ok());
        assert!(c.ping().await.is_ok());
        assert!(c.help(None).await.unwrap().contains("zecd"));
        assert!(c.get_rpc_info().await.unwrap().logpath.is_empty());
        let info = c.get_network_info().await.unwrap();
        assert_eq!(info.relayfee.zatoshis(), 1000);
        assert!(c.get_peer_info().await.unwrap().is_empty());
        assert_eq!(c.get_connection_count().await.unwrap(), 0);
        let fee = c.estimate_smart_fee(Some(3)).await.unwrap();
        assert_eq!(fee.feerate.zatoshis(), 1000);
        assert_eq!(fee.blocks, 3);
        assert_eq!(c.estimate_fee().await.unwrap().zatoshis(), 1000);
        assert!(c.get_mempool_info().await.unwrap().loaded);
        let v = c
            .validate_address("tmGqwWtL7RsbxikDSN26gsbicxVr2xJNe86")
            .await
            .unwrap();
        assert!(v.isvalid);

        // Server-side errors come back as ClientError::Rpc with the wire code intact.
        let err = c
            .set_tx_fee(crate::amount::Amount::from_zatoshis(1000))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Some(crate::error::codes::RPC_INVALID_PARAMETER));
        let err = c.get_balance(None).await.unwrap_err();
        assert_eq!(err.code(), Some(crate::error::codes::RPC_WALLET_NOT_FOUND));
        // z_waitforoperation resolves the wallet before parsing the opid, so the walletless
        // state surfaces -18 here (the malformed-opid -8 is pinned by the HTTP tests).
        let err = c
            .z_wait_for_operation("not-an-opid", Some(0))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Some(crate::error::codes::RPC_WALLET_NOT_FOUND));
    }

    /// Trailing omitted arguments vanish; interior ones become explicit nulls.
    #[test]
    fn positional_trims_trailing_and_nulls_interior() {
        assert_eq!(Client::positional(vec![]), Vec::<Value>::new());
        assert_eq!(
            Client::positional(vec![Some(json!(1)), None, Some(json!(3)), None]),
            vec![json!(1), Value::Null, json!(3)]
        );
        assert_eq!(Client::positional(vec![None, None]), Vec::<Value>::new());
    }
}
