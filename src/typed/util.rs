//! Typed utility RPCs: address validation, message signing, fee probes, mempool info, and
//! raw transactions. Response shapes follow `rpc/util.rs`, `rpc/signmessage.rs`, and
//! `rpc/rawtx.rs`.

use serde_json::{json, Value};

use super::{Client, ClientError};
use crate::amount::Amount;

/// `validateaddress` (`rpc/util.rs::validateaddress`). For an invalid address only
/// `isvalid`/`error`/`error_locations` are present; the echo/script fields appear only when
/// valid (Bitcoin Core's shape).
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ValidateAddress {
    pub isvalid: bool,
    /// Present only when valid.
    pub address: Option<String>,
    /// Real script for transparent addresses; empty for shielded (present only when valid).
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: Option<String>,
    pub isscript: Option<bool>,
    pub iswitness: Option<bool>,
    /// zecd extension: whether this address can receive into the Orchard pool.
    pub isvalid_orchard: Option<bool>,
    /// zecd extension: the pools this address can receive into, canonical order.
    pub receiver_types: Option<Vec<String>>,
    /// zecd extension: for a unified address, whether all receivers belong to the routed
    /// wallet at one diversifier index; absent when not computable.
    pub receivers_consistent: Option<bool>,
    /// Present only when invalid.
    pub error: Option<String>,
}

/// `estimatesmartfee` (`rpc/util.rs::estimatesmartfee`): a stable conventional rate - Zcash
/// fees are ZIP-317, computed at build time; there is no estimator.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct EstimateSmartFee {
    pub feerate: Amount,
    pub blocks: i64,
}

/// `getmempoolinfo` (`rpc/util.rs::getmempoolinfo`): a light client sees no mempool of its
/// own, so this is an empty (but loaded) pool with conventional fee floors.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct MempoolInfo {
    pub loaded: bool,
    pub size: u64,
    pub bytes: u64,
    pub usage: u64,
    pub total_fee: Amount,
    pub maxmempool: u64,
    pub mempoolminfee: Amount,
    pub minrelaytxfee: Amount,
}

/// `getrawtransaction` verbose result (`rpc/rawtx.rs::getrawtransaction` + `tx_json`). The
/// top-level scalars are typed; the script/bundle detail (`vin`, `vout`,
/// `vShieldedSpend`/`vShieldedOutput`, `orchard`, ...) stays as raw JSON - it is zcashd's
/// deep `TxToJSON` shape, and callers that need it are better served reading the exact wire
/// form than a lossy re-model. Finer typing is future work.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RawTransaction {
    pub txid: String,
    pub hex: String,
    pub size: u64,
    pub version: u32,
    pub overwintered: bool,
    pub locktime: u32,
    pub expiryheight: Option<u32>,
    /// Present once mined.
    pub height: Option<u32>,
    pub confirmations: Option<i64>,
    /// Present when the mined block is in the wallet's scan range.
    pub blockhash: Option<String>,
    pub time: Option<i64>,
    pub blocktime: Option<i64>,
    /// Transparent inputs, in zcashd's `TxToJSON` shape (untyped; see the struct doc).
    pub vin: Option<Value>,
    /// Transparent outputs, in zcashd's `TxToJSON` shape (untyped; see the struct doc).
    pub vout: Option<Value>,
}

impl Client<'_> {
    /// `validateaddress <address>`: network-aware validity verdict for any address kind.
    pub async fn validate_address(&self, address: &str) -> Result<ValidateAddress, ClientError> {
        self.call_typed("validateaddress", vec![json!(address)])
            .await
    }

    /// `signmessage <taddr> <message>`: sign with the transparent address's key; returns the
    /// base64 compact signature (zcashd/zallet form).
    pub async fn sign_message(&self, address: &str, message: &str) -> Result<String, ClientError> {
        self.call_typed("signmessage", vec![json!(address), json!(message)])
            .await
    }

    /// `verifymessage <taddr> <signature> <message>`.
    pub async fn verify_message(
        &self,
        address: &str,
        signature: &str,
        message: &str,
    ) -> Result<bool, ClientError> {
        self.call_typed(
            "verifymessage",
            vec![json!(address), json!(signature), json!(message)],
        )
        .await
    }

    /// `settxfee`: always rejected (-8) - fees follow ZIP-317 and are never client-settable.
    /// Wrapped for completeness so fee-probing client code can port unchanged.
    pub async fn set_tx_fee(&self, amount: Amount) -> Result<bool, ClientError> {
        self.call_typed(
            "settxfee",
            vec![serde_json::to_value(amount).expect("amount")],
        )
        .await
    }

    /// `estimatesmartfee ( conf_target )`: the stable conventional rate.
    pub async fn estimate_smart_fee(
        &self,
        conf_target: Option<i64>,
    ) -> Result<EstimateSmartFee, ClientError> {
        let params = Self::positional(vec![conf_target.map(|t| json!(t))]);
        self.call_typed("estimatesmartfee", params).await
    }

    /// `estimatefee`: the legacy single-number fee probe (same conventional rate).
    pub async fn estimate_fee(&self) -> Result<Amount, ClientError> {
        self.call_typed("estimatefee", vec![]).await
    }

    /// `getmempoolinfo`: preflight-satisfying empty-mempool stats.
    pub async fn get_mempool_info(&self) -> Result<MempoolInfo, ClientError> {
        self.call_typed("getmempoolinfo", vec![]).await
    }

    /// `getrawtransaction <txid>` (non-verbose): the raw transaction hex.
    pub async fn get_raw_transaction_hex(&self, txid: &str) -> Result<String, ClientError> {
        self.call_typed("getrawtransaction", vec![json!(txid)])
            .await
    }

    /// `getrawtransaction <txid> true` (verbose): the decoded transaction. The same wire
    /// method as [`Client::get_raw_transaction_hex`] - the two wrappers cover its two return
    /// shapes.
    pub async fn get_raw_transaction_verbose(
        &self,
        txid: &str,
    ) -> Result<RawTransaction, ClientError> {
        // NB deliberately not a second call_typed literal for this method: the lockstep test
        // requires exactly one wrapper per method name, so the verbose form goes through
        // Node::call directly with the params extended.
        let value = self
            .node
            .call(
                self.wallet,
                "getrawtransaction",
                vec![json!(txid), json!(true)],
            )
            .await?;
        serde_json::from_value(value).map_err(|source| ClientError::Decode {
            method: "getrawtransaction",
            source,
        })
    }

    /// `sendrawtransaction <hexstring>`: broadcast caller-built raw bytes; returns the txid.
    pub async fn send_raw_transaction(&self, hexstring: &str) -> Result<String, ClientError> {
        self.call_typed("sendrawtransaction", vec![json!(hexstring)])
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixtures from the HTTP validateaddress test vectors (server/mod.rs): the valid
    /// testnet P2PKH and an invalid string.
    #[test]
    fn validate_address_decodes_both_shapes() {
        let valid = serde_json::json!({
            "isvalid": true,
            "address": "tmGqwWtL7RsbxikDSN26gsbicxVr2xJNe86",
            "scriptPubKey": "76a914aa0db5883c5accedaeff3e295a4e9d0ff8294dc388ac",
            "isscript": false,
            "iswitness": false,
            "isvalid_orchard": false,
            "receiver_types": ["transparent"],
        });
        let v: ValidateAddress = serde_json::from_value(valid).unwrap();
        assert!(v.isvalid);
        assert_eq!(
            v.receiver_types.as_deref(),
            Some(&["transparent".to_string()][..])
        );

        let invalid = serde_json::json!({
            "isvalid": false,
            "error_locations": [],
            "error": "Invalid or unsupported address format",
        });
        let v: ValidateAddress = serde_json::from_value(invalid).unwrap();
        assert!(!v.isvalid);
        assert!(v.address.is_none());
        assert!(v.error.is_some());
    }

    /// Fixture from `rpc/util.rs::getmempoolinfo` (constant shape).
    #[test]
    fn mempool_info_decodes() {
        let v = serde_json::json!({
            "loaded": true,
            "size": 0,
            "bytes": 0,
            "usage": 0,
            "total_fee": 0.00000000,
            "maxmempool": 300_000_000u64,
            "mempoolminfee": 0.00001000,
            "minrelaytxfee": 0.00001000,
        });
        let info: MempoolInfo = serde_json::from_value(v).unwrap();
        assert!(info.loaded);
        assert_eq!(info.mempoolminfee.zatoshis(), 1000);
    }

    /// Fixture shaped like a mined verbose transaction (top-level scalars + untyped vin/vout).
    #[test]
    fn raw_transaction_decodes() {
        let v = serde_json::json!({
            "txid": "ab".repeat(32),
            "authdigest": "cd".repeat(32),
            "hex": "00",
            "size": 193,
            "version": 5,
            "overwintered": true,
            "versiongroupid": "26a7270a",
            "locktime": 0,
            "expiryheight": 140,
            "height": 100,
            "confirmations": 21,
            "blockhash": "ef".repeat(32),
            "time": 1_723_000_000i64,
            "blocktime": 1_723_000_000i64,
            "vin": [],
            "vout": [],
            "valueBalanceZat": 0,
            "vShieldedSpend": [],
            "vShieldedOutput": [],
        });
        let tx: RawTransaction = serde_json::from_value(v).unwrap();
        assert_eq!(tx.size, 193);
        assert_eq!(tx.height, Some(100));
        assert!(tx.vin.is_some());
    }
}
