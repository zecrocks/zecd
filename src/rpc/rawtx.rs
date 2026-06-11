//! Raw-transaction RPCs: `getrawtransaction` and `sendrawtransaction`.
//!
//! The verbose `getrawtransaction` response is zcashd's `TxToJSON` shape (the same shape
//! Zallet produces): Bitcoin Core's core fields (`hex`, `txid`, `size`, `version`,
//! `locktime`, `vin`, `vout`, `blockhash`, `confirmations`, `time`, `blocktime`) plus the
//! additive Zcash fields (`authdigest`, `overwintered`, `versiongroupid`, `expiryheight`,
//! `valueBalance`, `vShieldedSpend`/`vShieldedOutput`, `orchard`), and without the
//! segwit-only fields (`hash`/`vsize`/`weight`), which have no Zcash equivalent.

use serde_json::{json, Map, Value};

use zcash_keys::encoding::AddressCodec;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId};
use zcash_protocol::TxId;
use zcash_script::script::Asm as _;

use crate::amount::{signed_zats_to_value, zats_to_value};
use crate::error::{codes, RpcError};
use crate::server::jsonrpc::RpcRequest;
use crate::state::AppState;
use crate::wallet::read;

/// Byte-reversed hex, the display encoding zcashd uses for txids, block hashes, and most
/// shielded component fields ("legacy reasons").
fn rev_hex(bytes: &[u8]) -> String {
    let mut b = bytes.to_vec();
    b.reverse();
    hex::encode(b)
}

/// Parse a display-hex txid parameter with Bitcoin Core's `ParseHashV` error messages (-8).
fn parse_txid_param(s: &str) -> Result<TxId, RpcError> {
    if s.len() != 64 {
        return Err(RpcError::invalid_parameter(format!(
            "parameter 1 must be of length 64 (not {}, for '{s}')",
            s.len()
        )));
    }
    let mut bytes = hex::decode(s).map_err(|_| {
        RpcError::invalid_parameter(format!("parameter 1 must be hexadecimal string (not '{s}')"))
    })?;
    bytes.reverse();
    Ok(TxId::from_bytes(bytes.try_into().expect("32 bytes")))
}

/// `getrawtransaction <txid> [verbose] [blockhash]` - fetch any transaction by txid:
/// wallet-stored raw bytes when available, otherwise via lightwalletd's `GetTransaction`.
pub async fn getrawtransaction(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let txid_str = req
        .param(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("getrawtransaction requires a txid"))?;
    // `verbose` is a bool in Bitcoin Core and an int in zcashd; accept both.
    let verbose = match req.param(1) {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(v) => match v.as_i64() {
            Some(n) => n != 0,
            None => return Err(RpcError::type_error("verbose must be a boolean or integer")),
        },
    };
    // A light client has no block index to scope the lookup to (same restriction as Zallet).
    if req.param(2).filter(|v| !v.is_null()).is_some() {
        return Err(RpcError::invalid_parameter(
            "blockhash argument must be unset (for now).",
        ));
    }
    let txid = parse_txid_param(txid_str)?;

    let handle = state.registry.get(wallet)?.clone();
    let st = handle.status();
    // Wallet-known txs carry their mined height/time locally; anything else comes from
    // lightwalletd, which reports the mined height alongside the raw bytes.
    let rec = read::get_transaction(&handle.dir, txid_str).ok().flatten();
    let rec_height = rec.as_ref().and_then(|r| r.mined_height);
    let (data, mined_height) = match rec.as_ref().and_then(|r| r.raw.clone()) {
        Some(raw) => (raw, rec_height),
        None => match handle.get_raw_tx(txid).await? {
            Some(raw) => {
                let height = rec_height.or(raw.mined_height);
                (raw.data, height)
            }
            None => {
                return Err(RpcError::invalid_address_or_key(
                    "No such mempool or blockchain transaction",
                ))
            }
        },
    };

    if !verbose {
        return Ok(Value::String(hex::encode(&data)));
    }

    // The consensus branch ID only tags pre-v5 parses (v5 embeds its own); for an unmined tx
    // assume the next block's branch.
    let branch_height = mined_height
        .or(st.chain_tip.map(|t| t.saturating_add(1)))
        .unwrap_or(u32::MAX);
    let branch = BranchId::for_height(&handle.network, BlockHeight::from_u32(branch_height));
    let tx = Transaction::read(&data[..], branch).map_err(|e| {
        RpcError::new(codes::RPC_DESERIALIZATION_ERROR, format!("TX decode failed: {e}"))
    })?;

    let mut obj = tx_json(&handle.network, &tx, data.len());
    obj.insert("hex".into(), json!(hex::encode(&data)));
    if let Some(h) = mined_height {
        obj.insert("height".into(), json!(h));
        obj.insert("confirmations".into(), json!(st.confirmations(Some(h))));
        // Block hash/time come from the wallet's scanned-blocks table; omitted (like
        // Zallet omits them) when the block isn't in the wallet's scan range.
        if let Ok(Some((hash, time))) = read::block_info_at(&handle.dir, h) {
            let time = rec.as_ref().and_then(|r| r.block_time).unwrap_or(time);
            obj.insert("blockhash".into(), json!(hash));
            obj.insert("time".into(), json!(time));
            obj.insert("blocktime".into(), json!(time));
        }
    }
    Ok(Value::Object(obj))
}

/// `sendrawtransaction <hexstring> [maxfeerate]` - broadcast caller-built raw transaction
/// bytes through lightwalletd. `maxfeerate` is accepted and ignored: fees are ZIP-317 and a
/// shielded transaction's fee is not computable from its serialization alone.
pub async fn sendrawtransaction(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let hexstr = req
        .param(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("sendrawtransaction requires a hex string"))?;
    let data = hex::decode(hexstr)
        .map_err(|_| RpcError::new(codes::RPC_DESERIALIZATION_ERROR, "TX decode failed"))?;
    let handle = state.registry.get(wallet)?.clone();
    // Parse before broadcasting: an undecodable tx is -22 (and parsing yields the txid to
    // return, which lightwalletd's SendTransaction response does not reliably provide).
    let branch_height = handle
        .status()
        .chain_tip
        .map(|t| t.saturating_add(1))
        .unwrap_or(u32::MAX);
    let branch = BranchId::for_height(&handle.network, BlockHeight::from_u32(branch_height));
    let tx = Transaction::read(&data[..], branch)
        .map_err(|_| RpcError::new(codes::RPC_DESERIALIZATION_ERROR, "TX decode failed"))?;
    let txid = tx.txid();
    handle.broadcast(data).await?;
    Ok(Value::String(txid.to_string()))
}

/// zcashd's `TxToJSON` (sans block fields, which the callers append): every field of the
/// parsed transaction, shielded bundles included.
fn tx_json(network: &crate::network::ZNetwork, tx: &Transaction, size: usize) -> Map<String, Value> {
    let version = tx.version();
    let overwintered = version.has_overwinter();

    let mut obj = Map::new();
    obj.insert("txid".into(), json!(tx.txid().to_string()));
    obj.insert(
        "authdigest".into(),
        json!(rev_hex(tx.auth_commitment().as_bytes())),
    );
    obj.insert("size".into(), json!(size));
    obj.insert("overwintered".into(), json!(overwintered));
    obj.insert("version".into(), json!(version.header() & 0x7FFF_FFFF));
    if overwintered {
        obj.insert(
            "versiongroupid".into(),
            json!(format!("{:08x}", version.version_group_id())),
        );
    }
    obj.insert("locktime".into(), json!(tx.lock_time()));
    if overwintered {
        obj.insert("expiryheight".into(), json!(u32::from(tx.expiry_height())));
    }

    let (vin, vout) = match tx.transparent_bundle() {
        Some(bundle) => {
            let coinbase = bundle.is_coinbase();
            (
                bundle.vin.iter().map(|txin| vin_json(txin, coinbase)).collect(),
                bundle
                    .vout
                    .iter()
                    .enumerate()
                    .map(|(n, txout)| vout_json(network, txout, n))
                    .collect(),
            )
        }
        None => (Vec::new(), Vec::new()),
    };
    obj.insert("vin".into(), Value::Array(vin));
    obj.insert("vout".into(), Value::Array(vout));

    if let Some(bundle) = tx.sapling_bundle() {
        let vb = i64::from(*bundle.value_balance());
        obj.insert("valueBalance".into(), signed_zats_to_value(vb));
        obj.insert("valueBalanceZat".into(), json!(vb));
        obj.insert(
            "vShieldedSpend".into(),
            json!(bundle
                .shielded_spends()
                .iter()
                .map(sapling_spend_json)
                .collect::<Vec<_>>()),
        );
        obj.insert(
            "vShieldedOutput".into(),
            json!(bundle
                .shielded_outputs()
                .iter()
                .map(sapling_output_json)
                .collect::<Vec<_>>()),
        );
        obj.insert(
            "bindingSig".into(),
            json!(hex::encode(<[u8; 64]>::from(
                bundle.authorization().binding_sig,
            ))),
        );
    } else if version.has_sapling() {
        // Present-but-empty for v4+ without a Sapling bundle (zcashd shape); omitted below v4.
        obj.insert("valueBalance".into(), signed_zats_to_value(0));
        obj.insert("valueBalanceZat".into(), json!(0));
        obj.insert("vShieldedSpend".into(), json!([]));
        obj.insert("vShieldedOutput".into(), json!([]));
    }

    if version.has_orchard() {
        obj.insert("orchard".into(), orchard_json(tx.orchard_bundle()));
    }

    obj
}

fn vin_json(
    txin: &zcash_transparent::bundle::TxIn<zcash_transparent::bundle::Authorized>,
    coinbase: bool,
) -> Value {
    let code = &txin.script_sig().0;
    if coinbase {
        json!({
            "coinbase": hex::encode(&code.0),
            "sequence": txin.sequence(),
        })
    } else {
        json!({
            "txid": TxId::from_bytes(*txin.prevout().hash()).to_string(),
            "vout": txin.prevout().n(),
            "scriptSig": {
                // `true`: scriptSig pushes that are valid signatures render with their
                // sighash type decoded (`<sig>[ALL]`), as zcashd does.
                "asm": code.to_asm(true),
                "hex": hex::encode(&code.0),
            },
            "sequence": txin.sequence(),
        })
    }
}

fn vout_json(
    network: &crate::network::ZNetwork,
    txout: &zcash_transparent::bundle::TxOut,
    n: usize,
) -> Value {
    let code = &txout.script_pubkey().0;
    let value = u64::from(txout.value());
    let mut spk = Map::new();
    spk.insert("asm".into(), json!(code.to_asm(false)));
    spk.insert("hex".into(), json!(hex::encode(&code.0)));
    let (kind, req_sigs, addresses) = script::classify(code);
    if let Some(req_sigs) = req_sigs {
        spk.insert("reqSigs".into(), json!(req_sigs));
    }
    spk.insert("type".into(), json!(kind));
    if !addresses.is_empty() {
        spk.insert(
            "addresses".into(),
            json!(addresses.iter().map(|a| a.encode(network)).collect::<Vec<_>>()),
        );
    }
    json!({
        "value": zats_to_value(value),
        "valueZat": value,
        "valueSat": value,
        "n": n,
        "scriptPubKey": Value::Object(spk),
    })
}

fn sapling_spend_json(spend: &sapling::bundle::SpendDescription<sapling::bundle::Authorized>) -> Value {
    json!({
        "cv": rev_hex(&spend.cv().to_bytes()),
        "anchor": rev_hex(&spend.anchor().to_bytes()),
        "nullifier": rev_hex(&spend.nullifier().0),
        "rk": rev_hex(&<[u8; 32]>::from(*spend.rk())),
        "proof": hex::encode(spend.zkproof()),
        "spendAuthSig": hex::encode(<[u8; 64]>::from(*spend.spend_auth_sig())),
    })
}

fn sapling_output_json(
    output: &sapling::bundle::OutputDescription<sapling::bundle::GrothProofBytes>,
) -> Value {
    json!({
        "cv": rev_hex(&output.cv().to_bytes()),
        "cmu": rev_hex(&output.cmu().to_bytes()),
        "ephemeralKey": rev_hex(&output.ephemeral_key().0),
        "encCiphertext": hex::encode(output.enc_ciphertext()),
        "outCiphertext": hex::encode(output.out_ciphertext()),
        "proof": hex::encode(output.zkproof()),
    })
}

fn orchard_json(
    bundle: Option<&orchard::Bundle<orchard::bundle::Authorized, zcash_protocol::value::ZatBalance>>,
) -> Value {
    let Some(bundle) = bundle else {
        return json!({
            "actions": [],
            "valueBalance": signed_zats_to_value(0),
            "valueBalanceZat": 0,
        });
    };
    let actions: Vec<Value> = bundle
        .actions()
        .iter()
        .map(|action| {
            json!({
                "cv": hex::encode(action.cv_net().to_bytes()),
                "nullifier": hex::encode(action.nullifier().to_bytes()),
                "rk": hex::encode(<[u8; 32]>::from(action.rk())),
                "cmx": hex::encode(action.cmx().to_bytes()),
                "ephemeralKey": hex::encode(action.encrypted_note().epk_bytes),
                "encCiphertext": hex::encode(action.encrypted_note().enc_ciphertext),
                "outCiphertext": hex::encode(action.encrypted_note().out_ciphertext),
                "spendAuthSig": hex::encode(<[u8; 64]>::from(action.authorization())),
            })
        })
        .collect();
    let vb = i64::from(*bundle.value_balance());
    json!({
        "actions": actions,
        "valueBalance": signed_zats_to_value(vb),
        "valueBalanceZat": vb,
        "flags": {
            "enableSpends": bundle.flags().spends_enabled(),
            "enableOutputs": bundle.flags().outputs_enabled(),
        },
        "anchor": hex::encode(bundle.anchor().to_bytes()),
        "proof": hex::encode(bundle.authorization().proof()),
        "bindingSig": hex::encode(<[u8; 64]>::from(bundle.authorization().binding_signature())),
    })
}
/// Transparent-script classification for `scriptPubKey.type`/`reqSigs`/`addresses` -
/// zcashd's standard-script `Solver` subset, via the `zcash_script` solver (the same path
/// Zallet uses; asm rendering comes from `zcash_script`'s `ScriptToAsmStr` port directly).
mod script {
    use zcash_script::script::Code;
    use zcash_script::solver::{self, ScriptKind};
    use zcash_transparent::address::TransparentAddress;

    fn hash160(data: &[u8]) -> [u8; 20] {
        use ripemd::Ripemd160;
        use sha2::{Digest, Sha256};
        let mut out = [0u8; 20];
        out.copy_from_slice(&Ripemd160::digest(Sha256::digest(data)));
        out
    }

    /// `(type, reqSigs, addresses)` for a scriptPubKey. `reqSigs`/`addresses` are absent for
    /// `nulldata` and `nonstandard` scripts (no extractable destinations), matching zcashd's
    /// `ScriptPubKeyToJSON`.
    pub fn classify(code: &Code) -> (&'static str, Option<u8>, Vec<TransparentAddress>) {
        let Some(kind) = code
            .to_component()
            .ok()
            .and_then(|c| c.refine().ok())
            .and_then(|c| solver::standard(&c))
        else {
            return ("nonstandard", None, Vec::new());
        };
        let addresses = match &kind {
            ScriptKind::PubKeyHash { hash } => vec![TransparentAddress::PublicKeyHash(*hash)],
            ScriptKind::ScriptHash { hash } => vec![TransparentAddress::ScriptHash(*hash)],
            ScriptKind::PubKey { data } => {
                vec![TransparentAddress::PublicKeyHash(hash160(data.as_slice()))]
            }
            ScriptKind::MultiSig { pubkeys, .. } => pubkeys
                .iter()
                .map(|pk| TransparentAddress::PublicKeyHash(hash160(pk.as_slice())))
                .collect(),
            ScriptKind::NullData { .. } => Vec::new(),
        };
        match kind {
            ScriptKind::NullData { .. } => ("nulldata", None, Vec::new()),
            _ => (kind.as_str(), Some(kind.req_sigs()), addresses),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use zcash_script::script::Asm as _;

        fn asm(hex_script: &str, sighash_decode: bool) -> String {
            Code(hex::decode(hex_script).unwrap()).to_asm(sighash_decode)
        }

        fn classify_hex(hex_script: &str) -> (&'static str, Option<u8>, Vec<TransparentAddress>) {
            classify(&Code(hex::decode(hex_script).unwrap()))
        }

        /// Test vectors from zcashd `qa/rpc-tests/decodescript.py` (via Zallet's tests).
        #[test]
        fn asm_numeric_opcodes_match_zcashd() {
            // '5100' (OP_1 OP_0) renders as '1 0'; OP_1NEGATE renders as '-1'.
            assert_eq!(asm("5100", false), "1 0");
            assert_eq!(asm("4f", false), "-1");
        }

        #[test]
        fn asm_multisig_matches_zcashd() {
            // 2-of-3 multisig renders with bare numbers for OP_2/OP_3.
            let public_key = "03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2";
            let script = format!("5221{public_key}21{public_key}21{public_key}53ae");
            assert_eq!(
                asm(&script, false),
                format!("2 {public_key} {public_key} {public_key} 3 OP_CHECKMULTISIG")
            );
            let (kind, req_sigs, addresses) = classify_hex(&script);
            assert_eq!(kind, "multisig");
            assert_eq!(req_sigs, Some(2));
            assert_eq!(addresses.len(), 3);
        }

        /// P2PKH scriptSig sighash decode (vector from zcashd `decodescript.py`).
        #[test]
        fn scriptsig_asm_decodes_sighash() {
            let scriptsig = "47304402207174775824bec6c2700023309a168231ec80b82c6069282f5133e6f11cbb04460220570edc55c7c5da2ca687ebd0372d3546ebc3f810516a002350cac72dfe192dfb014104d3f898e6487787910a690410b7a917ef198905c27fb9d3b0a42da12aceae0544fc7088d239d9a48f2828a15a09e84043001f27cc80d162cb95404e1210161536";
            assert_eq!(
                asm(scriptsig, true),
                "304402207174775824bec6c2700023309a168231ec80b82c6069282f5133e6f11cbb04460220570edc55c7c5da2ca687ebd0372d3546ebc3f810516a002350cac72dfe192dfb[ALL] 04d3f898e6487787910a690410b7a917ef198905c27fb9d3b0a42da12aceae0544fc7088d239d9a48f2828a15a09e84043001f27cc80d162cb95404e1210161536"
            );
            // scriptPubKey rendering never decodes sighash suffixes.
            assert!(!asm(scriptsig, false).contains("[ALL]"));
        }

        #[test]
        fn truncated_push_renders_error() {
            // OP_DUP then a 5-byte push with only 2 bytes present.
            assert_eq!(asm("7605abcd", false), "OP_DUP [error]");
        }

        #[test]
        fn classify_standard_scripts() {
            let p2pkh = classify_hex("76a9140389035a9225b3839e2bbf32d826a1e222031fd888ac");
            assert_eq!((p2pkh.0, p2pkh.1), ("pubkeyhash", Some(1)));
            assert_eq!(p2pkh.2.len(), 1);

            let p2sh = classify_hex("a9140389035a9225b3839e2bbf32d826a1e222031fd887");
            assert_eq!((p2sh.0, p2sh.1), ("scripthash", Some(1)));

            let p2pk = classify_hex(
                "2103b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2ac",
            );
            assert_eq!((p2pk.0, p2pk.1), ("pubkey", Some(1)));
            assert_eq!(p2pk.2.len(), 1);

            let nulldata = classify_hex("6a0474657374");
            assert_eq!((nulldata.0, nulldata.1), ("nulldata", None));
            assert!(nulldata.2.is_empty());

            assert_eq!(classify_hex("51").0, "nonstandard");
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::ZNetwork;

    /// A v1 (pre-Overwinter) Bitcoin-style transaction (vector shared with Zallet's tests):
    /// one P2PKH input, one 1.0-coin P2PKH output.
    const V1_TX_HEX: &str = "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000";

    #[test]
    fn v1_tx_json_shape() {
        let data = hex::decode(V1_TX_HEX).unwrap();
        let tx = Transaction::read(&data[..], BranchId::Sprout).unwrap();
        let obj = tx_json(&ZNetwork::Main, &tx, data.len());

        assert_eq!(obj["size"], json!(193));
        assert_eq!(obj["version"], json!(1));
        assert_eq!(obj["overwintered"], json!(false));
        assert_eq!(obj["locktime"], json!(0));
        // Pre-Overwinter: no version group, expiry, sapling, or orchard sections.
        assert!(obj.get("versiongroupid").is_none());
        assert!(obj.get("expiryheight").is_none());
        assert!(obj.get("valueBalance").is_none());
        assert!(obj.get("orchard").is_none());

        let vin = obj["vin"].as_array().unwrap();
        assert_eq!(vin.len(), 1);
        assert!(vin[0]["scriptSig"]["asm"].as_str().unwrap().contains("[ALL]"));
        assert_eq!(vin[0]["vout"], json!(1));

        let vout = obj["vout"].as_array().unwrap();
        assert_eq!(vout.len(), 1);
        assert_eq!(vout[0]["n"], json!(0));
        assert_eq!(vout[0]["value"].to_string(), "1.00000000");
        assert_eq!(vout[0]["valueZat"], json!(100_000_000u64));
        let spk = &vout[0]["scriptPubKey"];
        assert_eq!(spk["type"], json!("pubkeyhash"));
        assert_eq!(spk["reqSigs"], json!(1));
        let addrs = spk["addresses"].as_array().unwrap();
        assert_eq!(addrs.len(), 1);
        // Mainnet transparent P2PKH addresses are base58 with a "t1" prefix.
        assert!(addrs[0].as_str().unwrap().starts_with("t1"), "{addrs:?}");
    }

    #[test]
    fn txid_param_errors_match_parse_hash_v() {
        let err = parse_txid_param("abcd").unwrap_err();
        assert_eq!(err.code, codes::RPC_INVALID_PARAMETER);
        assert!(err.message.contains("must be of length 64"));
        let err = parse_txid_param(&"zz".repeat(32)).unwrap_err();
        assert_eq!(err.code, codes::RPC_INVALID_PARAMETER);
        assert!(err.message.contains("must be hexadecimal"));
        assert!(parse_txid_param(&"ab".repeat(32)).is_ok());
    }
}
