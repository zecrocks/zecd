//! Typed wallet RPCs: balances, history, unspent notes, address issuance, sends, and the
//! zcashd-style async operations. Response shapes follow `rpc/wallet_methods.rs` (each struct
//! names its source function) and `operations.rs` for the operation status objects.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::{Client, ClientError};
use crate::amount::{Amount, SignedAmount};

/// The `mine` object of `getbalances` (`rpc/wallet_methods.rs::getbalances`).
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct BalancesMine {
    /// Spendable under the wallet's confirmations policy.
    pub trusted: Amount,
    pub untrusted_pending: Amount,
    pub immature: Amount,
    /// zecd extension: the mature-transparent-coinbase subset of `trusted`, spendable only
    /// via `z_shieldcoinbase`.
    pub coinbase: Amount,
}

/// The block a balance snapshot is anchored to (Bitcoin Core 26+'s `lastprocessedblock`).
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct LastProcessedBlock {
    pub hash: String,
    pub height: u32,
}

/// `getbalances` (`rpc/wallet_methods.rs::getbalances`).
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Balances {
    pub mine: BalancesMine,
    /// Present once a scanned block anchors the balances.
    pub lastprocessedblock: Option<LastProcessedBlock>,
}

/// `getwalletinfo.scanning`: an object while scanning (or draining the enhancement backlog),
/// the literal `false` when idle - Bitcoin Core's shape, kept faithfully typed.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(untagged)]
pub enum Scanning {
    /// The in-progress form: `{ duration, progress }`.
    Active { duration: u64, progress: f64 },
    /// The idle form (always `false`).
    Idle(bool),
}

impl Scanning {
    /// Whether a scan (or enhancement drain) is in progress.
    pub fn is_scanning(&self) -> bool {
        matches!(self, Scanning::Active { .. })
    }
}

/// `getwalletinfo.transparent.initial_sync` (A18 pre-exposure progress).
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct TransparentInitialSync {
    pub exposed: u32,
    pub total: u32,
    pub complete: bool,
}

/// `getwalletinfo.transparent` - the transparent receiving configuration and restore-coverage
/// windows (zecd extension; present only when transparent receiving is enabled). There are two
/// of them: the lookahead follows issuance, the recovery horizon bounds a from-seed restore, and
/// `restorable` compares them for you.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct TransparentInfo {
    pub enabled: bool,
    #[serde(rename = "default")]
    pub is_default: bool,
    pub gap_limit: u32,
    /// Mature coinbase awaiting `z_shieldcoinbase` (same number as `getbalances.mine.coinbase`).
    pub coinbase_balance: Amount,
    pub recovery_horizon: Option<u32>,
    /// Inclusive lookahead window bounds; absent until the matcher is first built.
    pub lookahead_from: Option<u32>,
    pub lookahead_through: Option<u32>,
    /// False when an address has been exposed at or beyond the recovery horizon.
    pub restorable: Option<bool>,
    pub initial_sync: Option<TransparentInitialSync>,
}

/// `getwalletinfo` (`rpc/wallet_methods.rs::getwalletinfo`).
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct WalletInfo {
    pub walletname: String,
    pub walletversion: u64,
    pub format: String,
    pub balance: Amount,
    pub unconfirmed_balance: Amount,
    pub immature_balance: Amount,
    pub txcount: u64,
    pub keypoolsize: u64,
    pub keypoolsize_hd_internal: u64,
    pub paytxfee: Amount,
    /// False for a watch-only (UFVK) wallet.
    pub private_keys_enabled: bool,
    pub avoid_reuse: bool,
    pub scanning: Scanning,
    pub descriptors: bool,
    /// Present only for passphrase-encrypted wallets: unix relock time, or 0 while locked.
    pub unlocked_until: Option<i64>,
    /// Present only when transparent receiving is enabled.
    pub transparent: Option<TransparentInfo>,
}

/// `getaddressinfo` (`rpc/wallet_methods.rs::addressinfo_json`).
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct AddressInfo {
    pub address: String,
    /// Real script for transparent addresses; empty for shielded.
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: String,
    pub ismine: bool,
    pub solvable: bool,
    /// Deprecated in Bitcoin Core master; always false.
    pub iswatchonly: bool,
    pub isscript: bool,
    pub iswitness: bool,
    /// zecd extension: Orchard-receiver capability.
    pub isvalid_orchard: bool,
    /// zecd extension: the pools this address can receive into, canonical order.
    pub receiver_types: Vec<String>,
    /// Always empty (zecd keeps no labels).
    pub labels: Vec<String>,
    /// zecd extension; present only when computable for a unified address.
    pub receivers_consistent: Option<bool>,
    /// BIP 44 path of an own transparent address (absent for a UFVK watch-only account,
    /// which records no ZIP 32 derivation).
    pub hdkeypath: Option<String>,
    pub ischange: Option<bool>,
    /// zecd extension: the bare BIP 44 child index (what `z_getaddressforaccount` takes).
    pub address_index: Option<u32>,
}

/// One `listtransactions`/`listsinceblock` entry (`rpc/wallet_methods.rs::tx_entries` +
/// `push_wallet_tx_fields`). Sends are negative `amount`s; a self-transfer appears as a
/// send + receive pair.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct TransactionEntry {
    pub address: String,
    /// `"send"` or `"receive"`.
    pub category: String,
    pub amount: SignedAmount,
    /// Always empty (zecd keeps no labels).
    pub label: String,
    pub vout: u32,
    /// -1 for an expired unmined transaction (it can never confirm).
    pub confirmations: i64,
    pub txid: String,
    #[serde(rename = "bip125-replaceable")]
    pub bip125_replaceable: String,
    /// Send entries only.
    pub abandoned: Option<bool>,
    /// Send entries only; negative, like Bitcoin Core's.
    pub fee: Option<SignedAmount>,
    /// Shielded memo extensions (zcashd's names): raw ZIP-302 bytes in hex, decoded text.
    pub memo: Option<String>,
    #[serde(rename = "memoStr")]
    pub memo_str: Option<String>,
    /// Mined transactions carry the block fields...
    pub blockhash: Option<String>,
    pub blockheight: Option<u32>,
    pub blockindex: Option<u32>,
    pub blocktime: Option<i64>,
    /// ...unmined ones carry `trusted` instead.
    pub trusted: Option<bool>,
    pub walletconflicts: Vec<Value>,
    pub time: i64,
    pub timereceived: i64,
}

/// One `z_listtransactions` entry (`rpc/wallet_methods.rs::z_tx_entries`): per-output history
/// in zcashd's `z_*` vocabulary.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ZTransactionEntry {
    pub txid: String,
    /// zcashd's per-transaction status: `"mined"`, `"expired"`, or `"waiting"`.
    pub status: String,
    pub confirmations: i64,
    pub time: i64,
    pub walletconflicts: Vec<Value>,
    /// `"transparent"` / `"sapling"` / `"orchard"` / `"ironwood"`.
    pub pool: String,
    pub category: String,
    pub amount: SignedAmount,
    #[serde(rename = "amountZat")]
    pub amount_zat: i64,
    pub address: String,
    pub outindex: u32,
    pub change: bool,
    pub outgoing: bool,
    pub blockhash: Option<String>,
    pub blockheight: Option<u32>,
    pub blockindex: Option<u32>,
    pub blocktime: Option<i64>,
    /// Present when non-zero.
    pub expiryheight: Option<u32>,
    pub fee: Option<SignedAmount>,
    #[serde(rename = "feeZat")]
    pub fee_zat: Option<i64>,
    pub memo: Option<String>,
    #[serde(rename = "memoStr")]
    pub memo_str: Option<String>,
}

/// `listsinceblock` (`rpc/wallet_methods.rs::listsinceblock`). `removed` is always empty
/// (reorged-away transactions are rescanned and re-reported, not tracked separately);
/// `lastblock` is the cursor to feed back into the next call.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ListSinceBlock {
    pub transactions: Vec<TransactionEntry>,
    pub removed: Vec<Value>,
    pub lastblock: String,
}

/// One `gettransaction.details` entry (`rpc/wallet_methods.rs::gettransaction_details`).
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct TransactionDetail {
    pub address: String,
    pub category: String,
    pub amount: SignedAmount,
    pub vout: u32,
    pub label: String,
    pub abandoned: Option<bool>,
    pub fee: Option<SignedAmount>,
    pub memo: Option<String>,
    #[serde(rename = "memoStr")]
    pub memo_str: Option<String>,
}

/// `gettransaction` (`rpc/wallet_methods.rs::gettransaction`). `amount` is fee-exclusive
/// (the fee rides separately in `fee`, sends only), matching Bitcoin Core.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct GetTransaction {
    pub amount: SignedAmount,
    /// Only on transactions the wallet funded; negative.
    pub fee: Option<SignedAmount>,
    pub confirmations: i64,
    pub txid: String,
    #[serde(rename = "bip125-replaceable")]
    pub bip125_replaceable: String,
    pub details: Vec<TransactionDetail>,
    /// Raw bytes hex; empty when unavailable (upstream unreachable for a compact-only tx).
    pub hex: String,
    pub blockhash: Option<String>,
    pub blockheight: Option<u32>,
    pub blockindex: Option<u32>,
    pub blocktime: Option<i64>,
    pub trusted: Option<bool>,
    pub walletconflicts: Vec<Value>,
    pub time: i64,
    pub timereceived: i64,
}

/// One `listunspent` entry (`rpc/wallet_methods.rs::unspent_json`). Shielded notes carry
/// synthesized `(txid, vout)` outpoints; `pool` is the zecd extension naming the pool.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Unspent {
    pub txid: String,
    pub vout: u32,
    /// The receiving diversified address when recorded; empty for change/internal notes.
    pub address: String,
    pub amount: Amount,
    pub confirmations: i64,
    pub spendable: bool,
    pub solvable: bool,
    pub safe: bool,
    /// `"transparent"` / `"sapling"` / `"orchard"` / `"ironwood"`.
    pub pool: String,
    /// Transparent entries only: true iff produced by a coinbase transaction.
    pub generated: Option<bool>,
}

/// `listunspent` filters (all optional; the wire defaults apply when unset).
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub struct ListUnspentOptions {
    pub minconf: Option<i64>,
    pub maxconf: Option<i64>,
    pub addresses: Option<Vec<String>>,
    pub include_unsafe: Option<bool>,
}

/// One `listreceivedbyaddress` entry (`rpc/wallet_methods.rs::listreceivedbyaddress`).
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ReceivedByAddress {
    pub address: String,
    pub amount: Amount,
    /// Confirmations of the least-confirmed contributing transaction (0 when none).
    pub confirmations: i64,
    pub label: String,
    pub txids: Vec<String>,
}

/// `z_getaddressforaccount` (`rpc/wallet_methods.rs::z_getaddressforaccount`).
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ZAddressForAccount {
    pub account: u64,
    pub diversifier_index: u64,
    pub receiver_types: Vec<String>,
    pub address: String,
}

/// The state string of an async operation (`operations.rs::OperationState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OperationState {
    Queued,
    Executing,
    Cancelled,
    Failed,
    Success,
    /// Forward compatibility: a state string this client predates.
    #[serde(other)]
    Unknown,
}

impl OperationState {
    /// Whether the operation has reached a terminal state.
    pub fn is_finished(self) -> bool {
        matches!(
            self,
            OperationState::Cancelled | OperationState::Failed | OperationState::Success
        )
    }
}

/// A failed operation's error (`operations.rs::OperationError`): the send's own RPC error
/// (e.g. -6 insufficient funds), carried in the status object.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct OperationError {
    pub code: i64,
    pub message: String,
}

/// A successful operation's result: the sends all return `{ "txid": ... }`.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct OperationResult {
    pub txid: String,
}

/// One async-operation status object (`operations.rs::OperationStatus`, zcashd's shape).
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Operation {
    /// `opid-<uuid>`.
    pub id: String,
    pub status: OperationState,
    /// Seconds since the Unix epoch.
    pub creation_time: u64,
    pub method: Option<String>,
    pub params: Option<Value>,
    /// Present on failed operations.
    pub error: Option<OperationError>,
    /// Present on successful operations.
    pub result: Option<OperationResult>,
    /// Wall-clock execution seconds of a successful operation.
    pub execution_secs: Option<u64>,
}

/// `z_waitforoperation` (`rpc/wallet_methods.rs::z_waitforoperation`): the status object plus
/// the load-bearing `finished` flag - `false` means the *wait* gave up (timeout) while `true`
/// with `status: Failed` means the operation ended in failure. Neither is an error on this
/// call, so callers never enumerate terminal status strings.
///
/// Deliberately not `#[serde(flatten)]` over [`Operation`]: `flatten` buffers through serde's
/// private content type, which interacts badly with `serde_json`'s `arbitrary_precision`
/// numbers, so the fields are spelled out.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct WaitedOperation {
    pub finished: bool,
    pub id: String,
    pub status: OperationState,
    pub creation_time: u64,
    pub method: Option<String>,
    pub params: Option<Value>,
    pub error: Option<OperationError>,
    pub result: Option<OperationResult>,
    pub execution_secs: Option<u64>,
}

/// `z_shieldcoinbase`'s immediate response (`rpc/wallet_methods.rs::z_shieldcoinbase`):
/// selection statistics fixed at call time, plus the opid tracking the prove/broadcast.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ZShieldCoinbase {
    #[serde(rename = "remainingUTXOs")]
    pub remaining_utxos: u64,
    #[serde(rename = "remainingValue")]
    pub remaining_value: Amount,
    #[serde(rename = "shieldingUTXOs")]
    pub shielding_utxos: u64,
    #[serde(rename = "shieldingValue")]
    pub shielding_value: Amount,
    pub opid: String,
}

/// `z_mergetoaddress`'s immediate response (`rpc/wallet_methods.rs::z_mergetoaddress`): the
/// selection statistics fixed at call time, plus the opid tracking the prove/broadcast. The
/// `remaining*` figures say what a follow-up call would pick up, so a caller repeats the
/// sweep until they reach zero.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ZMergeToAddress {
    #[serde(rename = "remainingUTXOs")]
    pub remaining_utxos: u64,
    #[serde(rename = "remainingTransparentValue")]
    pub remaining_transparent_value: Amount,
    #[serde(rename = "remainingNotes")]
    pub remaining_notes: u64,
    #[serde(rename = "remainingShieldedValue")]
    pub remaining_shielded_value: Amount,
    #[serde(rename = "mergingUTXOs")]
    pub merging_utxos: u64,
    #[serde(rename = "mergingTransparentValue")]
    pub merging_transparent_value: Amount,
    #[serde(rename = "mergingNotes")]
    pub merging_notes: u64,
    #[serde(rename = "mergingShieldedValue")]
    pub merging_shielded_value: Amount,
    pub opid: String,
}

/// One `z_sendmany` recipient. `amount` serializes as the exact 8-dp number; `memo` is the
/// hex-encoded ZIP-302 memo (shielded recipients only), zcashd's convention.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ZRecipient {
    pub address: String,
    pub amount: Amount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
}

/// Optional trailing arguments of `sendtoaddress` (the useful subset: the metadata comments
/// and zecd's trailing `memo` extension; the money-semantics parameters Bitcoin Core defines
/// there are rejected by zecd and so not offered).
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub struct SendToAddressOptions {
    pub comment: Option<String>,
    pub comment_to: Option<String>,
    /// Hex-encoded ZIP-302 memo for a shielded recipient (zecd extension, wire param 11).
    pub memo: Option<String>,
}

impl Client<'_> {
    /// `getnewaddress ( "" address_type )`: issue the next receiving address. The label must
    /// stay empty (zecd keeps no labels - a non-empty one is -8), so only the type is exposed:
    /// `unified`, `transparent`, `orchard`, `sapling,orchard`, ... (`None` = wallet default).
    pub async fn get_new_address(&self, address_type: Option<&str>) -> Result<String, ClientError> {
        let params = Self::positional(vec![
            address_type.is_some().then(|| json!("")),
            address_type.map(|t| json!(t)),
        ]);
        self.call_typed("getnewaddress", params).await
    }

    /// `z_getaddressforaccount 0 ( receiver_types diversifier_index )`: derive the address at
    /// an explicit index. `receiver_types` in zcashd's tokens (e.g. `["p2pkh"]` for the bare
    /// t-address at BIP 44 child `diversifier_index`).
    pub async fn z_get_address_for_account(
        &self,
        account: u32,
        receiver_types: Option<&[&str]>,
        diversifier_index: Option<u64>,
    ) -> Result<ZAddressForAccount, ClientError> {
        let params = Self::positional(vec![
            Some(json!(account)),
            receiver_types.map(|t| json!(t)),
            diversifier_index.map(|i| json!(i)),
        ]);
        self.call_typed("z_getaddressforaccount", params).await
    }

    /// `getbalance ( "*" minconf )`: the spendable balance (an explicit `minconf` overrides
    /// the wallet's confirmations policy symmetrically).
    pub async fn get_balance(&self, minconf: Option<i64>) -> Result<Amount, ClientError> {
        let params = Self::positional(vec![
            minconf.is_some().then(|| json!("*")),
            minconf.map(|m| json!(m)),
        ]);
        self.call_typed("getbalance", params).await
    }

    /// `getbalances`: the modern balance triple (+ zecd's `coinbase` subset).
    pub async fn get_balances(&self) -> Result<Balances, ClientError> {
        self.call_typed("getbalances", vec![]).await
    }

    /// `getunconfirmedbalance`: received but not yet spendable (0-conf receives included).
    pub async fn get_unconfirmed_balance(&self) -> Result<Amount, ClientError> {
        self.call_typed("getunconfirmedbalance", vec![]).await
    }

    /// `getwalletinfo`.
    pub async fn get_wallet_info(&self) -> Result<WalletInfo, ClientError> {
        self.call_typed("getwalletinfo", vec![]).await
    }

    /// `getaddressinfo <address>` (invalid addresses are -5, like the wire).
    pub async fn get_address_info(&self, address: &str) -> Result<AddressInfo, ClientError> {
        self.call_typed("getaddressinfo", vec![json!(address)])
            .await
    }

    /// `listtransactions ( "*" count from )`: the most recent history entries, oldest first
    /// within the window.
    pub async fn list_transactions(
        &self,
        count: Option<u32>,
        from: Option<u32>,
    ) -> Result<Vec<TransactionEntry>, ClientError> {
        let params = Self::positional(vec![
            (count.is_some() || from.is_some()).then(|| json!("*")),
            count.map(|c| json!(c)),
            from.map(|f| json!(f)),
        ]);
        self.call_typed("listtransactions", params).await
    }

    /// `z_listtransactions ( count from )`: per-output history in zcashd's vocabulary
    /// (zecd extension method).
    pub async fn z_list_transactions(
        &self,
        count: Option<u32>,
        from: Option<u32>,
    ) -> Result<Vec<ZTransactionEntry>, ClientError> {
        let params = Self::positional(vec![count.map(|c| json!(c)), from.map(|f| json!(f))]);
        self.call_typed("z_listtransactions", params).await
    }

    /// `listsinceblock ( blockhash target_confirmations )`: the restart-safe payment poller.
    pub async fn list_since_block(
        &self,
        blockhash: Option<&str>,
        target_confirmations: Option<u32>,
    ) -> Result<ListSinceBlock, ClientError> {
        let params = Self::positional(vec![
            blockhash.map(|h| json!(h)),
            target_confirmations.map(|t| json!(t)),
        ]);
        self.call_typed("listsinceblock", params).await
    }

    /// `gettransaction <txid>`: one wallet transaction in detail.
    pub async fn get_transaction(&self, txid: &str) -> Result<GetTransaction, ClientError> {
        self.call_typed("gettransaction", vec![json!(txid)]).await
    }

    /// `listunspent ( minconf maxconf addresses include_unsafe )`: unspent notes/UTXOs.
    pub async fn list_unspent(
        &self,
        opts: &ListUnspentOptions,
    ) -> Result<Vec<Unspent>, ClientError> {
        let params = Self::positional(vec![
            opts.minconf.map(|m| json!(m)),
            opts.maxconf.map(|m| json!(m)),
            opts.addresses.as_ref().map(|a| json!(a)),
            opts.include_unsafe.map(|b| json!(b)),
        ]);
        self.call_typed("listunspent", params).await
    }

    /// `getreceivedbyaddress <address> ( minconf )`: total received by one own address.
    pub async fn get_received_by_address(
        &self,
        address: &str,
        minconf: Option<i64>,
    ) -> Result<Amount, ClientError> {
        let params = Self::positional(vec![Some(json!(address)), minconf.map(|m| json!(m))]);
        self.call_typed("getreceivedbyaddress", params).await
    }

    /// `listreceivedbyaddress ( minconf include_empty )`: per-address received totals.
    pub async fn list_received_by_address(
        &self,
        minconf: Option<i64>,
        include_empty: Option<bool>,
    ) -> Result<Vec<ReceivedByAddress>, ClientError> {
        let params = Self::positional(vec![
            minconf.map(|m| json!(m)),
            include_empty.map(|b| json!(b)),
        ]);
        self.call_typed("listreceivedbyaddress", params).await
    }

    /// `listwallets`: the loaded wallet names.
    pub async fn list_wallets(&self) -> Result<Vec<String>, ClientError> {
        self.call_typed("listwallets", vec![]).await
    }

    /// `sendtoaddress <address> <amount> ...`: pay one recipient; returns the txid. Fees are
    /// ZIP-317 (never settable), so none of Bitcoin Core's fee knobs are offered.
    pub async fn send_to_address(
        &self,
        address: &str,
        amount: Amount,
        opts: &SendToAddressOptions,
    ) -> Result<String, ClientError> {
        let params = Self::positional(vec![
            Some(json!(address)),
            Some(serde_json::to_value(amount).expect("amount serializes")),
            opts.comment.as_ref().map(|c| json!(c)),
            opts.comment_to.as_ref().map(|c| json!(c)),
            None, // subtractfeefromamount (rejected when engaged)
            None, // replaceable
            None, // conf_target
            None, // estimate_mode
            None, // avoid_reuse
            None, // fee_rate (rejected when engaged)
            None, // verbose
            opts.memo.as_ref().map(|m| json!(m)),
        ]);
        self.call_typed("sendtoaddress", params).await
    }

    /// `sendmany "" {address: amount, ...}`: pay several recipients in one transaction
    /// (one ZIP-317 fee, one anchor); returns the txid.
    pub async fn send_many(
        &self,
        amounts: &BTreeMap<String, Amount>,
    ) -> Result<String, ClientError> {
        let obj: serde_json::Map<String, Value> = amounts
            .iter()
            .map(|(addr, amt)| {
                (
                    addr.clone(),
                    serde_json::to_value(*amt).expect("amount serializes"),
                )
            })
            .collect();
        self.call_typed("sendmany", vec![json!(""), Value::Object(obj)])
            .await
    }

    /// `walletpassphrase <passphrase> <timeout_secs>`: unlock a passphrase-encrypted wallet.
    pub async fn wallet_passphrase(
        &self,
        passphrase: &str,
        timeout_secs: i64,
    ) -> Result<(), ClientError> {
        self.call_typed(
            "walletpassphrase",
            vec![json!(passphrase), json!(timeout_secs)],
        )
        .await
    }

    /// `walletlock`: drop the decrypted seed immediately.
    pub async fn wallet_lock(&self) -> Result<(), ClientError> {
        self.call_typed("walletlock", vec![]).await
    }

    /// `z_sendmany <fromaddress> [recipients] ( minconf null privacyPolicy )`: zcashd's
    /// asynchronous send; returns the opid immediately. `from_address` is input-side coin
    /// control (own shielded/unified address, own t-address, or `ANY_TADDR`); an explicit fee
    /// is never offered (ZIP-317).
    pub async fn z_send_many(
        &self,
        from_address: &str,
        recipients: &[ZRecipient],
        minconf: Option<u32>,
        privacy_policy: Option<&str>,
    ) -> Result<String, ClientError> {
        let params = Self::positional(vec![
            Some(json!(from_address)),
            Some(serde_json::to_value(recipients).expect("recipients serialize")),
            minconf.map(|m| json!(m)),
            None, // fee: ZIP-317 only; an explicit fee is rejected on the wire
            privacy_policy.map(|p| json!(p)),
        ]);
        self.call_typed("z_sendmany", params).await
    }

    /// `z_shieldcoinbase <fromaddress|*> <toaddress> ( null limit memo privacyPolicy )`:
    /// sweep mature transparent coinbase into a shielded address; the prove/broadcast runs
    /// under the returned opid.
    pub async fn z_shield_coinbase(
        &self,
        from_address: &str,
        to_address: &str,
        limit: Option<u64>,
        memo: Option<&str>,
        privacy_policy: Option<&str>,
    ) -> Result<ZShieldCoinbase, ClientError> {
        let params = Self::positional(vec![
            Some(json!(from_address)),
            Some(json!(to_address)),
            None, // fee: ZIP-317 only
            limit.map(|l| json!(l)),
            memo.map(|m| json!(m)),
            privacy_policy.map(|p| json!(p)),
        ]);
        self.call_typed("z_shieldcoinbase", params).await
    }

    /// `z_mergetoaddress [fromaddresses] <toaddress> ( null transparent_limit shielded_limit
    /// memo privacyPolicy )`: zcashd's amountless consolidation sweep - merge many UTXOs
    /// and/or notes into ONE output at `to_address`, paying `inputs - fee` with no change.
    /// Sources are one class per call (`ANY_TADDR` / wallet t-addresses, or `ANY_SAPLING` /
    /// `ANY_ORCHARD` / a wallet shielded address); the privacy ladder gates the revealing
    /// shapes as for `z_sendmany`. Returns the selection stats plus the tracking opid; repeat
    /// while the `remaining*` figures are non-zero. An explicit fee is never offered (ZIP-317).
    pub async fn z_merge_to_address(
        &self,
        from_addresses: &[&str],
        to_address: &str,
        transparent_limit: Option<u64>,
        shielded_limit: Option<u64>,
        memo: Option<&str>,
        privacy_policy: Option<&str>,
    ) -> Result<ZMergeToAddress, ClientError> {
        let params = Self::positional(vec![
            Some(json!(from_addresses)),
            Some(json!(to_address)),
            None, // fee: ZIP-317 only; an explicit fee is rejected on the wire
            transparent_limit.map(|l| json!(l)),
            shielded_limit.map(|l| json!(l)),
            memo.map(|m| json!(m)),
            privacy_policy.map(|p| json!(p)),
        ]);
        self.call_typed("z_mergetoaddress", params).await
    }

    /// `z_getoperationstatus ( [opids] )`: status objects, non-destructive.
    pub async fn z_get_operation_status(
        &self,
        opids: Option<&[&str]>,
    ) -> Result<Vec<Operation>, ClientError> {
        let params = Self::positional(vec![opids.map(|ids| json!(ids))]);
        self.call_typed("z_getoperationstatus", params).await
    }

    /// `z_getoperationresult ( [opids] )`: finished operations only, and DESTRUCTIVE - each
    /// returned result is reaped (zcashd semantics).
    pub async fn z_get_operation_result(
        &self,
        opids: Option<&[&str]>,
    ) -> Result<Vec<Operation>, ClientError> {
        let params = Self::positional(vec![opids.map(|ids| json!(ids))]);
        self.call_typed("z_getoperationresult", params).await
    }

    /// `z_listoperationids ( status )`: this wallet's operation ids, optionally filtered by
    /// status string.
    pub async fn z_list_operation_ids(
        &self,
        status: Option<&str>,
    ) -> Result<Vec<String>, ClientError> {
        let params = Self::positional(vec![status.map(|s| json!(s))]);
        self.call_typed("z_listoperationids", params).await
    }

    /// `z_waitforoperation <opid> ( timeout_secs )`: block until the operation finishes.
    /// Timeout in SECONDS (unlike the `waitfor*` family's milliseconds): `0` is an immediate
    /// single-operation read, and `None` waits the server-side default (clamped to 3600).
    /// See [`WaitedOperation`] for the timeout-vs-failure distinction.
    pub async fn z_wait_for_operation(
        &self,
        opid: &str,
        timeout_secs: Option<u64>,
    ) -> Result<WaitedOperation, ClientError> {
        let params = Self::positional(vec![Some(json!(opid)), timeout_secs.map(|t| json!(t))]);
        self.call_typed("z_waitforoperation", params).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixture from a funded regtest wallet's `getbalances` (post-funding, pre-send).
    #[test]
    fn balances_decode() {
        let v = serde_json::json!({
            "mine": {
                "trusted": 5.00000000,
                "untrusted_pending": 0.12500000,
                "immature": 0.00000000,
                "coinbase": 0.00000000,
            },
            "lastprocessedblock": { "hash": "ab".repeat(32), "height": 120 },
        });
        let b: Balances = serde_json::from_value(v).unwrap();
        assert_eq!(b.mine.trusted.zatoshis(), 500_000_000);
        assert_eq!(b.mine.untrusted_pending.zatoshis(), 12_500_000);
        assert_eq!(b.lastprocessedblock.unwrap().height, 120);
    }

    /// Fixtures for both `scanning` shapes and the optional blocks of `getwalletinfo`
    /// (encrypted + transparent-enabled vs the plain default).
    #[test]
    fn wallet_info_decodes_both_shapes() {
        let scanning = serde_json::json!({
            "walletname": "default",
            "walletversion": 169900,
            "format": "sqlite",
            "balance": 1.00000000,
            "unconfirmed_balance": 0.00000000,
            "immature_balance": 0.00000000,
            "txcount": 3,
            "keypoolsize": 1,
            "keypoolsize_hd_internal": 0,
            "paytxfee": 0.00000000,
            "private_keys_enabled": true,
            "avoid_reuse": false,
            "scanning": { "duration": 0, "progress": 0.25 },
            "descriptors": false,
            "unlocked_until": 0,
            "transparent": {
                "enabled": true,
                "default": false,
                "gap_limit": 20,
                "coinbase_balance": 0.00000000,
                "recovery_horizon": 20,
                "lookahead_from": 1,
                "lookahead_through": 20,
                "restorable": true,
            },
        });
        let w: WalletInfo = serde_json::from_value(scanning).unwrap();
        assert!(w.scanning.is_scanning());
        let t = w.transparent.unwrap();
        assert!(t.restorable.unwrap());
        assert!(!t.is_default);
        assert_eq!(w.unlocked_until, Some(0));

        let idle = serde_json::json!({
            "walletname": "default",
            "walletversion": 169900,
            "format": "sqlite",
            "balance": 0.00000000,
            "unconfirmed_balance": 0.00000000,
            "immature_balance": 0.00000000,
            "txcount": 0,
            "keypoolsize": 1,
            "keypoolsize_hd_internal": 0,
            "paytxfee": 0.00000000,
            "private_keys_enabled": true,
            "avoid_reuse": false,
            "scanning": false,
            "descriptors": false,
        });
        let w: WalletInfo = serde_json::from_value(idle).unwrap();
        assert!(!w.scanning.is_scanning());
        assert!(w.transparent.is_none() && w.unlocked_until.is_none());
    }

    /// Fixture shaped like `regtest_funded`'s memo receive: a mined receive entry with the
    /// memo extensions, plus an unmined send entry carrying `trusted` and `fee`.
    #[test]
    fn transaction_entries_decode() {
        let mined_receive = serde_json::json!({
            "address": "utest1...",
            "category": "receive",
            "amount": 1.25000000,
            "label": "",
            "vout": 0,
            "confirmations": 3,
            "txid": "ab".repeat(32),
            "bip125-replaceable": "no",
            "memo": "f600",
            "memoStr": "hello",
            "blockhash": "cd".repeat(32),
            "blockheight": 100,
            "blockindex": 1,
            "blocktime": 1_723_000_000i64,
            "walletconflicts": [],
            "time": 1_723_000_000i64,
            "timereceived": 1_723_000_000i64,
        });
        let e: TransactionEntry = serde_json::from_value(mined_receive).unwrap();
        assert_eq!(e.amount.zatoshis(), 125_000_000);
        assert_eq!(e.memo_str.as_deref(), Some("hello"));
        assert_eq!(e.blockheight, Some(100));

        let unmined_send = serde_json::json!({
            "address": "tmGqwWtL7RsbxikDSN26gsbicxVr2xJNe86",
            "category": "send",
            "amount": -0.50010000,
            "label": "",
            "vout": 0,
            "confirmations": 0,
            "txid": "ef".repeat(32),
            "bip125-replaceable": "no",
            "abandoned": false,
            "fee": -0.00010000,
            "trusted": true,
            "walletconflicts": [],
            "time": 1_723_000_050i64,
            "timereceived": 1_723_000_050i64,
        });
        let e: TransactionEntry = serde_json::from_value(unmined_send).unwrap();
        assert_eq!(e.amount.zatoshis(), -50_010_000);
        assert_eq!(e.fee.unwrap().zatoshis(), -10_000);
        assert_eq!(e.trusted, Some(true));
        assert!(e.blockheight.is_none());
    }

    /// Fixture from a shielded `listunspent` entry (ironwood note) and a transparent
    /// coinbase one.
    #[test]
    fn unspent_decodes() {
        let shielded = serde_json::json!({
            "txid": "ab".repeat(32),
            "vout": 0,
            "address": "utest1...",
            "amount": 2.00000000,
            "confirmations": 5,
            "spendable": true,
            "solvable": true,
            "safe": true,
            "pool": "ironwood",
        });
        let u: Unspent = serde_json::from_value(shielded).unwrap();
        assert_eq!(u.pool, "ironwood");
        assert!(u.generated.is_none());

        let coinbase = serde_json::json!({
            "txid": "cd".repeat(32),
            "vout": 0,
            "address": "tmGqwWtL7RsbxikDSN26gsbicxVr2xJNe86",
            "amount": 6.25000000,
            "confirmations": 101,
            "spendable": true,
            "solvable": true,
            "safe": true,
            "pool": "transparent",
            "generated": true,
        });
        let u: Unspent = serde_json::from_value(coinbase).unwrap();
        assert_eq!(u.generated, Some(true));
    }

    /// Operation status fixtures: executing, success (with result + execution_secs), and
    /// failed (the send's own -6 in `error`) - plus the z_waitforoperation timeout shape.
    #[test]
    fn operations_decode() {
        let executing = serde_json::json!({
            "id": "opid-11111111-2222-3333-4444-555555555555",
            "status": "executing",
            "creation_time": 1_723_000_000u64,
            "method": "z_sendmany",
        });
        let op: Operation = serde_json::from_value(executing).unwrap();
        assert_eq!(op.status, OperationState::Executing);
        assert!(!op.status.is_finished());

        let success = serde_json::json!({
            "id": "opid-11111111-2222-3333-4444-555555555555",
            "status": "success",
            "creation_time": 1_723_000_000u64,
            "method": "z_sendmany",
            "result": { "txid": "ab".repeat(32) },
            "execution_secs": 2,
        });
        let op: Operation = serde_json::from_value(success).unwrap();
        assert!(op.status.is_finished());
        assert_eq!(op.result.unwrap().txid.len(), 64);

        let failed = serde_json::json!({
            "id": "opid-11111111-2222-3333-4444-555555555555",
            "status": "failed",
            "creation_time": 1_723_000_000u64,
            "error": { "code": -6, "message": "Insufficient funds: 0 spendable" },
        });
        let op: Operation = serde_json::from_value(failed).unwrap();
        assert_eq!(op.error.as_ref().unwrap().code, -6);

        // A timed-out wait: finished=false with a non-terminal status, not an error.
        let waited = serde_json::json!({
            "finished": false,
            "id": "opid-11111111-2222-3333-4444-555555555555",
            "status": "executing",
            "creation_time": 1_723_000_000u64,
        });
        let w: WaitedOperation = serde_json::from_value(waited).unwrap();
        assert!(!w.finished);
        assert!(!w.status.is_finished());
    }

    /// Fixture from `regtest_coinbase`'s shield step.
    #[test]
    fn shield_coinbase_decodes() {
        let v = serde_json::json!({
            "remainingUTXOs": 15,
            "remainingValue": 93.75000000,
            "shieldingUTXOs": 5,
            "shieldingValue": 31.25000000,
            "opid": "opid-11111111-2222-3333-4444-555555555555",
        });
        let s: ZShieldCoinbase = serde_json::from_value(v).unwrap();
        assert_eq!(s.shielding_utxos, 5);
        assert_eq!(s.shielding_value.zatoshis(), 3_125_000_000);
    }

    /// Fixture shaped like a transparent-source `z_mergetoaddress` sweep: the merging side
    /// carries the selected UTXOs, the shielded counters are zero, and the `remaining*`
    /// figures are what a follow-up call would pick up.
    #[test]
    fn merge_to_address_decodes() {
        let v = serde_json::json!({
            "remainingUTXOs": 3,
            "remainingTransparentValue": 0.30000000,
            "remainingNotes": 0,
            "remainingShieldedValue": 0.00000000,
            "mergingUTXOs": 50,
            "mergingTransparentValue": 5.00000000,
            "mergingNotes": 0,
            "mergingShieldedValue": 0.00000000,
            "opid": "opid-11111111-2222-3333-4444-555555555555",
        });
        let m: ZMergeToAddress = serde_json::from_value(v).unwrap();
        assert_eq!(m.merging_utxos, 50);
        assert_eq!(m.merging_transparent_value.zatoshis(), 500_000_000);
        assert_eq!(m.remaining_utxos, 3);
        assert_eq!(m.remaining_transparent_value.zatoshis(), 30_000_000);
        assert_eq!(m.merging_notes, 0);
        assert!(m.opid.starts_with("opid-"));
    }

    /// ZRecipient serializes in z_sendmany's wire shape, amount as the exact 8-dp number.
    #[test]
    fn z_recipient_serializes() {
        let r = ZRecipient {
            address: "utest1x".into(),
            amount: Amount::from_zatoshis(150_000_000),
            memo: None,
        };
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            r#"{"address":"utest1x","amount":1.50000000}"#
        );
        let r = ZRecipient {
            memo: Some("f600".into()),
            ..r
        };
        assert!(serde_json::to_string(&r)
            .unwrap()
            .contains("\"memo\":\"f600\""));
    }
}
