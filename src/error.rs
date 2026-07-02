//! Bitcoin-Core-compatible RPC error type and error codes.
//!
//! Codes mirror Bitcoin Core's `rpc/protocol.h` so that standard Bitcoin RPC client
//! libraries surface the errors they expect (e.g. insufficient funds == -6).

use std::fmt;

/// Standard JSON-RPC 2.0 / Bitcoin Core error codes.
///
/// We reuse the exact integer values Bitcoin Core uses; clients such as
/// `python-bitcoinrpc` and `bitcoincore-rpc` match on these.
#[allow(dead_code)]
pub mod codes {
    // JSON-RPC 2.0 transport-level errors. NB: `RPC_INVALID_PARAMS` (-32602) is a framing-level
    // code that Bitcoin Core never emits from a method handler - a missing argument raises the
    // help text (`RPC_MISC_ERROR`, -1) and a wrong-typed one raises `RPC_TYPE_ERROR` (-3). zecd
    // follows suit: handlers use [`RpcError::missing_param`]/[`RpcError::type_error`], never this.
    pub const RPC_INVALID_REQUEST: i32 = -32600;
    pub const RPC_METHOD_NOT_FOUND: i32 = -32601;
    pub const RPC_INVALID_PARAMS: i32 = -32602;
    pub const RPC_PARSE_ERROR: i32 = -32700;

    // General application errors. (Bitcoin Core's `protocol.h` defines more - including a P2P
    // client block - but a shielded light wallet has no occasion to emit them; only the codes
    // zecd actually returns are kept. Clients still match on the numeric values.)
    pub const RPC_MISC_ERROR: i32 = -1;
    pub const RPC_TYPE_ERROR: i32 = -3;
    pub const RPC_INVALID_ADDRESS_OR_KEY: i32 = -5;
    pub const RPC_INVALID_PARAMETER: i32 = -8;
    pub const RPC_DATABASE_ERROR: i32 = -20;
    pub const RPC_DESERIALIZATION_ERROR: i32 = -22;
    pub const RPC_VERIFY_REJECTED: i32 = -26;
    pub const RPC_VERIFY_ALREADY_IN_UTXO_SET: i32 = -27;
    pub const RPC_METHOD_DEPRECATED: i32 = -32;

    // Wallet errors. NB: these are Bitcoin Core's `protocol.h` numbers; `-11` (invalid label)
    // and `-18` (wallet not found) differ in *meaning* from zcashd's `protocol.h` (where they are
    // "accounts unsupported" / "backup required"). The collision is harmless - those codes are only
    // emitted by the label/multiwallet methods zcashd lacks - so don't "reconcile" the numbers: the
    // Bitcoin Core values are the conformance target.
    pub const RPC_WALLET_ERROR: i32 = -4;
    pub const RPC_WALLET_INSUFFICIENT_FUNDS: i32 = -6;
    pub const RPC_WALLET_INVALID_LABEL_NAME: i32 = -11;
    pub const RPC_WALLET_UNLOCK_NEEDED: i32 = -13;
    pub const RPC_WALLET_PASSPHRASE_INCORRECT: i32 = -14;
    pub const RPC_WALLET_WRONG_ENC_STATE: i32 = -15;
    pub const RPC_WALLET_NOT_FOUND: i32 = -18;
}

/// Map an RPC error code to the HTTP status Bitcoin Core uses (`httprpc.cpp` `JSONErrorReply`):
/// `RPC_INVALID_REQUEST` → 400, `RPC_METHOD_NOT_FOUND` → 404, everything else → 500.
pub fn http_status_for_code(code: i32) -> u16 {
    match code {
        codes::RPC_INVALID_REQUEST => 400,
        codes::RPC_METHOD_NOT_FOUND => 404,
        _ => 500,
    }
}

/// The concrete error type returned by `propose_transfer` / `create_proposed_transactions`
/// for our `WalletDb`. Naming it pins the otherwise-unconstrained commitment-tree error
/// parameter so `map_err` closures can infer their argument type (mirrors zcash-devtool's
/// `WalletErrorT`).
pub type ProposalError = zcash_client_backend::data_api::error::Error<
    zcash_client_sqlite::error::SqliteClientError,
    zcash_client_sqlite::wallet::commitment_tree::Error,
    zcash_client_backend::data_api::wallet::input_selection::GreedyInputSelectorError,
    zcash_primitives::transaction::fees::zip317::FeeError,
    zcash_primitives::transaction::fees::zip317::FeeError,
    zcash_client_sqlite::ReceivedNoteId,
>;

/// A Bitcoin-Core-style RPC error carrying a numeric `code` and human `message`.
#[derive(Debug, Clone)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

impl RpcError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        RpcError {
            code,
            message: message.into(),
        }
    }

    pub fn misc(message: impl Into<String>) -> Self {
        Self::new(codes::RPC_MISC_ERROR, message)
    }

    /// A required parameter was omitted. Bitcoin Core answers a missing argument with the
    /// method's help text under `RPC_MISC_ERROR` (-1); zecd carries a short description instead
    /// of a full help page. Never `RPC_INVALID_PARAMS` (-32602), which Core reserves for framing.
    pub fn missing_param(message: impl Into<String>) -> Self {
        Self::new(codes::RPC_MISC_ERROR, message)
    }

    pub fn invalid_parameter(message: impl Into<String>) -> Self {
        Self::new(codes::RPC_INVALID_PARAMETER, message)
    }

    pub fn type_error(message: impl Into<String>) -> Self {
        Self::new(codes::RPC_TYPE_ERROR, message)
    }

    pub fn invalid_address_or_key(message: impl Into<String>) -> Self {
        Self::new(codes::RPC_INVALID_ADDRESS_OR_KEY, message)
    }

    pub fn method_not_found(method: &str) -> Self {
        Self::new(
            codes::RPC_METHOD_NOT_FOUND,
            format!("Method not found: {method}"),
        )
    }

    pub fn wallet(message: impl Into<String>) -> Self {
        Self::new(codes::RPC_WALLET_ERROR, message)
    }

    pub fn insufficient_funds(message: impl Into<String>) -> Self {
        Self::new(codes::RPC_WALLET_INSUFFICIENT_FUNDS, message)
    }

    pub fn database(message: impl Into<String>) -> Self {
        Self::new(codes::RPC_DATABASE_ERROR, message)
    }

    /// Wallet-database failure from an internal error. The detail is logged server-side only:
    /// rusqlite/`zcash_client_sqlite` messages can embed filesystem paths, which RPC clients
    /// have no business seeing.
    pub fn database_internal(e: impl fmt::Display) -> Self {
        tracing::warn!("wallet database error: {e}");
        Self::database("Database error")
    }

    pub fn wallet_not_found(message: impl Into<String>) -> Self {
        Self::new(codes::RPC_WALLET_NOT_FOUND, message)
    }

    pub fn unlock_needed() -> Self {
        Self::new(
            codes::RPC_WALLET_UNLOCK_NEEDED,
            "Error: Please enter the wallet passphrase with walletpassphrase first.",
        )
    }
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (code {})", self.message, self.code)
    }
}

impl std::error::Error for RpcError {}

// anyhow errors that bubble up from the wallet/sync layers without a more specific
// classification become generic RPC errors. Call sites should prefer the specific
// constructors above where the failure mode is known (e.g. insufficient funds).
//
// The detail is logged server-side only and never placed in `message`: an unclassified
// anyhow error can embed filesystem paths, database internals, or other host state that RPC
// clients have no business seeing (mirrors `database_internal`). Clients get a generic string.
impl From<anyhow::Error> for RpcError {
    fn from(e: anyhow::Error) -> Self {
        tracing::warn!("internal RPC error: {e:#}");
        RpcError::misc("Internal error")
    }
}

impl From<rusqlite::Error> for RpcError {
    fn from(e: rusqlite::Error) -> Self {
        RpcError::database_internal(e)
    }
}
