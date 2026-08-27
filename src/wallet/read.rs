//! Read-only wallet queries served from short-lived connections, so they never block on the
//! sync writer (SQLite WAL gives consistent snapshots).

use std::collections::HashMap;
use std::path::Path;

use anyhow::anyhow;
use rusqlite::{named_params, Connection, OptionalExtension};
use uuid::Uuid;
use zcash_client_backend::data_api::wallet::input_selection::LockFilter;
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
use zcash_client_backend::data_api::{Account as _, InputSource, WalletRead};
use zcash_keys::address::{Address, UnifiedAddress};
use zcash_keys::encoding::AddressCodec as _;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::builder::DEFAULT_TX_EXPIRY_DELTA;
use zcash_protocol::{ShieldedPool, TxId};
use zcash_transparent::keys::TransparentKeyScope;
use zip32::{DiversifierIndex, Scope};

use zcash_client_sqlite::AccountUuid;

use crate::network::ZNetwork;
use crate::wallet::open::{data_db_path, open_read};

/// Which account in a wallet database a read applies to.
///
/// One `WalletDb` can hold several accounts - that is how a fleet of watch-only wallets is
/// scanned once instead of once each, so every query that reports a *wallet's own* money,
/// history or addresses has to name the account it means. The database
/// already carries the column everywhere it is needed: `v_transactions.account_uuid`,
/// `v_tx_outputs.from_account_uuid`/`to_account_uuid`, and an `account_id` foreign key on the
/// received-note and transparent-output tables.
///
/// Chain-level reads (`blocks`, block hashes, median time past) are deliberately *not* scoped:
/// they describe the chain the database has scanned, which every account in it shares. Neither
/// are the actor's own maintenance reads (the rebroadcast set, the transparent spend-watch set),
/// which must cover every account the actor scans for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AccountScope {
    /// Every account in the database. The pre-fleet behaviour, and what a wallet whose account
    /// does not exist yet (an encrypted wallet awaiting its first `walletpassphrase`, so the
    /// bootstrap has not run) necessarily uses. Identical to [`AccountScope::Only`] whenever the
    /// database holds exactly one account, which is what makes this scoping a no-op for the
    /// single-wallet layout.
    #[default]
    Any,
    /// Exactly one account.
    Only(AccountUuid),
}

impl AccountScope {
    /// The value bound to `:scope_account`: the account's UUID, or `NULL` for
    /// [`AccountScope::Any`].
    ///
    /// The predicates below are written so that a `NULL` here matches everything, which is what
    /// lets the SQL stay a single constant string per query instead of being assembled per
    /// variant - no conditional fragments, no conditional parameter lists, and no way for the
    /// two to disagree.
    fn param(&self) -> Option<Uuid> {
        match self {
            AccountScope::Any => None,
            AccountScope::Only(account) => Some(account.expose_uuid()),
        }
    }

    /// True when this scope names an account that `account` is not. For the few reads whose rows
    /// come from librustzcash's own API rather than SQL written here, so the filter is applied in
    /// Rust instead.
    fn excludes(&self, account: AccountUuid) -> bool {
        matches!(self, AccountScope::Only(only) if *only != account)
    }
}

/// A SQL predicate restricting an account **UUID** column to the bound [`AccountScope`].
/// Unscoped reads bind `NULL`, which the `IS NULL` arm turns into "every account".
fn scope_by_uuid(column: &str) -> String {
    format!("(:scope_account IS NULL OR {column} = :scope_account)")
}

/// The accounts a read applies to: every account the database holds, or just the scoped one.
/// For the reads whose rows come from librustzcash's own API (balances, spendable notes, address
/// lists) rather than SQL written here.
fn scoped_account_ids(
    db: &crate::wallet::open::ReadDb,
    scope: AccountScope,
) -> anyhow::Result<Vec<AccountUuid>> {
    Ok(db
        .get_account_ids()?
        .into_iter()
        .filter(|account| !scope.excludes(*account))
        .collect())
}

/// A SQL predicate matching a `v_tx_outputs` row that belongs to the scoped account on *either*
/// side: a received output names it in `to_account_uuid`, a sent one in `from_account_uuid`.
fn scope_by_output_account() -> String {
    "(:scope_account IS NULL OR to_account_uuid = :scope_account \
      OR from_account_uuid = :scope_account)"
        .to_string()
}

/// As [`scope_by_uuid`], for an account **id** column - the integer foreign key the note and
/// transparent-output tables carry. Resolved through `accounts` so callers only ever hold the
/// stable UUID.
fn scope_by_id(column: &str) -> String {
    format!(
        "(:scope_account IS NULL OR {column} = \
         (SELECT id FROM accounts WHERE uuid = :scope_account))"
    )
}

/// Spendable / pending balances aggregated across the wallet's accounts (in zatoshis).
#[derive(Debug, Default, Clone)]
pub struct BalanceInfo {
    pub orchard_spendable: u64,
    pub sapling_spendable: u64,
    /// Ironwood (NU6.3, Orchard V3) spendable value. Read from `AccountBalance::ironwood_balance()`,
    /// which the pinned scan-model librustzcash rev surfaces (the same API devtool reads). 0 until
    /// NU6.3 activates and the wallet holds ironwood notes - so 0 on mainnet, and on testnet until
    /// NU6.3 activates at height 4_134_000.
    pub ironwood_spendable: u64,
    /// Spendable transparent (unshielded) value. Spendable here means "usable as an input": zecd
    /// spends transparent UTXOs by auto-shielding them into a shielded send.
    pub transparent_spendable: u64,
    pub total_spendable: u64,
    /// Value received but not yet spendable (needs more confirmations).
    pub pending: u64,
    /// Change awaiting confirmation.
    pub immature: u64,
    /// Unspent, **mature** transparent coinbase value - a subset of [`Self::transparent_spendable`]
    /// (and so of [`Self::total_spendable`]), broken out because it is spendable only via
    /// `z_shieldcoinbase`: consensus requires a transaction spending a transparent coinbase
    /// output to have an empty `vout`, so the regular send paths exclude coinbase from selection
    /// outright. Surfaced as `getbalances.mine.coinbase` and
    /// `getwalletinfo.transparent.coinbase_balance` so a caller can tell how much of `trusted`
    /// needs shielding before it can move. Always 0 for shielded (ZIP-213) coinbase, which has
    /// no maturity or spend restriction.
    pub mature_coinbase: u64,
}

/// Coinbase maturity depth in blocks: consensus forbids spending a transparent coinbase output
/// with fewer than this many confirmations (and even then only into a fully-shielded
/// transaction - see `z_shieldcoinbase`). The single source for the maturity clause: the
/// balance/listunspent SQL here and the received-by aggregations in `rpc/wallet_methods.rs`
/// all key on it, mirroring the clause in `zcash_client_sqlite`'s
/// `get_spendable_transparent_outputs`. Shielded coinbase (ZIP-213) has no maturity rule.
pub const COINBASE_MATURITY: u32 = 100;

/// Aggregate balances via `get_wallet_summary` (mirrors devtool's `balance.rs`), under the
/// given confirmations policy. Callers pass the wallet's configured policy
/// (`handle.confirmations`; ZIP-315 trusted-3/untrusted-10 by default) - never
/// `ConfirmationsPolicy::default()` directly - so balances agree with what a send can spend;
/// `getbalance` maps an explicit `minconf` onto a symmetric override.
pub fn balance(
    network: ZNetwork,
    engine_dir: &Path,
    scope: AccountScope,
    policy: ConfirmationsPolicy,
) -> anyhow::Result<BalanceInfo> {
    let db = open_read(network, engine_dir)?;
    let mut info = BalanceInfo::default();
    if let Some(summary) = db.get_wallet_summary(policy)? {
        let target_height = u32::from(summary.chain_tip_height()) + 1;
        // `get_wallet_summary` reports every account in the database, so the scope is applied
        // here rather than pushed down: a fleet shard holds many wallets' accounts, and summing
        // them all would report each wallet the whole shard's money.
        for (account, bal) in summary.account_balances() {
            if scope.excludes(*account) {
                continue;
            }
            info.orchard_spendable += bal.orchard_balance().spendable_value().into_u64();
            info.sapling_spendable += bal.sapling_balance().spendable_value().into_u64();
            // Transparent (unshielded) value, spendable as an input (`z_shieldcoinbase` /
            // fully-transparent send). NB the upstream buckets apply no coinbase-maturity rule
            // (`add_transparent_account_balances` has no `tx_index` clause), so an immature
            // coinbase UTXO lands in `spendable_value` here despite being unspendable for 100
            // blocks; the reclassification below moves that value into the `immature` bucket,
            // matching Bitcoin Core (`getbalance` excludes it, `getwalletinfo.immature_balance`
            // carries it).
            info.transparent_spendable += bal.unshielded_balance().spendable_value().into_u64();
            info.pending += bal
                .orchard_balance()
                .value_pending_spendability()
                .into_u64()
                + bal
                    .sapling_balance()
                    .value_pending_spendability()
                    .into_u64()
                + bal
                    .unshielded_balance()
                    .value_pending_spendability()
                    .into_u64();
            info.immature += bal
                .orchard_balance()
                .change_pending_confirmation()
                .into_u64()
                + bal
                    .sapling_balance()
                    .change_pending_confirmation()
                    .into_u64()
                + bal
                    .unshielded_balance()
                    .change_pending_confirmation()
                    .into_u64();
            // Ironwood (Orchard V3) balance. The pinned librustzcash ironwood line (the
            // `dw/ironwood-scan-model` rev zcash-devtool builds against) rolls received ironwood
            // notes into `AccountBalance::ironwood_balance()`, exactly as devtool's `balance.rs`
            // reads it; sum it into the spendable/pending/immature buckets like the other pools.
            // (0 pre-NU6.3, so a no-op on mainnet / pre-activation testnet.)
            info.ironwood_spendable += bal.ironwood_balance().spendable_value().into_u64();
            info.pending += bal
                .ironwood_balance()
                .value_pending_spendability()
                .into_u64();
            info.immature += bal
                .ironwood_balance()
                .change_pending_confirmation()
                .into_u64();
        }
        // Reclassify immature coinbase value out of the upstream buckets (see above) into
        // `immature`, where Bitcoin Core reports coinbase value until it matures. Upstream
        // (since 0.24.0-rc.4) already applies the maturity rule to the *spendable* bucket -
        // immature coinbase rides in `value_pending_spendability` - so drain the
        // immature-coinbase total from `pending` first and touch `transparent_spendable` only
        // as a clamped fallback (it holds no immature coinbase on the current upstream; the
        // fallback guards against the bucketing shifting again across upstream releases, which
        // it already did once between 0.24.0-rc.1 and 0.24.0-rc.4).
        let immature_coinbase = immature_coinbase_zats(engine_dir, scope, target_height)?;
        let from_pending = immature_coinbase.min(info.pending);
        let from_spendable = (immature_coinbase - from_pending).min(info.transparent_spendable);
        info.pending -= from_pending;
        info.transparent_spendable -= from_spendable;
        info.immature += from_spendable + from_pending;
        // The mature-coinbase breakout (see the field docs). Clamped to the transparent bucket
        // so it is a subset of `trusted` by construction even if the upstream bucketing shifts.
        info.mature_coinbase =
            mature_coinbase_zats(engine_dir, scope, target_height)?.min(info.transparent_spendable);
        info.total_spendable = info.orchard_spendable
            + info.sapling_spendable
            + info.transparent_spendable
            + info.ironwood_spendable;
    }
    Ok(info)
}

/// Unspent, mined, **immature** coinbase value (`tx_index == 0`, fewer than
/// [`COINBASE_MATURITY`] confirmations at `target_height`). Mirrors the coinbase-maturity
/// clause of `zcash_client_sqlite`'s `get_spendable_transparent_outputs` (which the balance
/// queries lack) so `balance` can reclassify the immature value.
fn immature_coinbase_zats(
    engine_dir: &Path,
    scope: AccountScope,
    target_height: u32,
) -> anyhow::Result<u64> {
    coinbase_zats(engine_dir, scope, target_height, false)
}

/// Unspent, mined, **mature** coinbase value - the other side of the maturity split. Backs
/// [`BalanceInfo::mature_coinbase`] and the actor's `-6` enrichment (the "spendable only via
/// z_shieldcoinbase" hint), so the number a failed send reports is the same one `getbalances`
/// shows.
pub fn mature_coinbase_zats(
    engine_dir: &Path,
    scope: AccountScope,
    target_height: u32,
) -> anyhow::Result<u64> {
    coinbase_zats(engine_dir, scope, target_height, true)
}

/// Sum unspent, mined coinbase value on the requested side of the [`COINBASE_MATURITY`]
/// boundary. An output is coinbase iff its tx's recorded block index is 0 (`IFNULL(tx_index,
/// 1)` - unknown defaults to *non*-coinbase, so a bare UTXO row can't masquerade as coinbase),
/// and it is suppressed by a spend only while the spending tx is still live (mined or
/// unexpired), mirroring the `listunspent` query below.
fn coinbase_zats(
    engine_dir: &Path,
    scope: AccountScope,
    target_height: u32,
    mature: bool,
) -> anyhow::Result<u64> {
    let conn = open_conn(engine_dir)?;
    let unexpired_stx = tx_unexpired_sql("stx");
    let maturity_cmp = if mature { ">=" } else { "<" };
    let account = scope_by_id("txo.account_id");
    let sql = format!(
        "SELECT IFNULL(SUM(txo.value_zat), 0)
         FROM transparent_received_outputs txo
         JOIN transactions t ON t.id_tx = txo.transaction_id
         WHERE t.mined_height IS NOT NULL
           AND IFNULL(t.tx_index, 1) == 0
           AND :target_height - t.mined_height {maturity_cmp} {COINBASE_MATURITY}
           AND {account}
           AND txo.id NOT IN (
               SELECT s.transparent_received_output_id
               FROM transparent_received_output_spends s
               JOIN transactions stx ON stx.id_tx = s.transaction_id
               WHERE {unexpired_stx}
           )"
    );
    let total: i64 = conn.query_row(
        &sql,
        named_params! {
            ":target_height": target_height,
            ":scope_account": scope.param(),
        },
        |r| r.get(0),
    )?;
    Ok(u64::try_from(total).unwrap_or(0))
}

/// Number of transactions in the wallet (for `getwalletinfo.txcount`).
pub fn tx_count(engine_dir: &Path, scope: AccountScope) -> anyhow::Result<u64> {
    let conn = open_conn(engine_dir)?;
    let account = scope_by_uuid("account_uuid");
    let n: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM v_transactions WHERE {account}"),
        named_params! { ":scope_account": scope.param() },
        |r| r.get(0),
    )?;
    Ok(n as u64)
}

/// `v_tx_outputs.recipient_key_scope` for an output received on one of the wallet's own
/// *external* (user-facing) addresses - the ZIP-32 external scope. Internal/change is `1`,
/// imported is `-1`, and a pure send (no wallet receive) or an unlinked address is `NULL`.
pub const EXTERNAL_KEY_SCOPE: i64 = 0;

/// One output row from `v_tx_outputs`.
/// `#[non_exhaustive]`: a returned shape that gains fields as the wallet does.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TxOutputRecord {
    /// `v_tx_outputs.output_pool`: 0 = transparent, 2 = Sapling, 3 = Orchard, 4 = Ironwood.
    /// Post-NU6.3 an ordinary shielded output is 4, not 3, so a `match` on this that stops at
    /// Orchard silently skips the common case rather than failing to compile.
    pub pool: i64,
    pub output_index: u32,
    pub from_account: Option<Uuid>,
    pub to_account: Option<Uuid>,
    pub to_address: Option<String>,
    pub value: i64,
    pub is_change: bool,
    /// `v_tx_outputs.recipient_key_scope`: the ZIP-32 scope of the address this output was
    /// received on - [`EXTERNAL_KEY_SCOPE`] (`0`) external, `1` internal/change, `-1` imported,
    /// `None` when the output isn't a wallet receive (a pure send) or its address isn't linked.
    /// This - not [`Self::is_change`] - is the reliable "is this internal change" signal:
    /// librustzcash marks an output `is_change` whenever the *receiving* account also spent in
    /// the same transaction (scanning's `find_received`), so a deliberate payment to one of the
    /// wallet's own user-facing addresses lands with `is_change = true` despite being received
    /// on an external-scope address. See [`Self::is_internal_change`].
    pub recipient_key_scope: Option<i64>,
    /// The output's ZIP-302 memo bytes, when the wallet decrypted/stored one.
    pub memo: Option<Vec<u8>>,
}

impl TxOutputRecord {
    /// Whether this output is internal change that the history/detail RPCs hide. An output received
    /// on a **non-external** scope (internal/imported) is change: the BIP-32 internal chain is the
    /// change chain and is never handed out as a receive address, so an output landing there is
    /// change by construction. This is the reliable signal for **transparent** change, where
    /// librustzcash records `is_change = 0` unconditionally (so only the recipient *key scope*
    /// distinguishes change from a self-send); for shielded change the recorded scope is internal
    /// too, so the same rule hides it. A payment to one of the wallet's *own* user-facing
    /// (**external**) addresses is a deliberate self-send and stays visible - Bitcoin Core surfaces
    /// such a self-payment as a send+receive pair (and so its memo stays reachable). Filtering on
    /// raw `is_change` would wrongly hide it, because librustzcash flags self-payments `is_change`
    /// too; conversely it would wrongly *show* transparent change, which never carries `is_change`.
    pub fn is_internal_change(&self) -> bool {
        match self.recipient_key_scope {
            // External scope (a user-facing receive address): never hidden - a self-send here is a
            // deliberate, visible payment.
            Some(EXTERNAL_KEY_SCOPE) => false,
            // Internal/imported scope: change by construction (covers transparent change, whose
            // `is_change` flag is always 0, and shielded change alike).
            Some(_) => true,
            // No recorded scope (a pure send with no own receiver): fall back to `is_change`.
            None => self.is_change,
        }
    }
}

/// One transaction row from `v_transactions`, plus its outputs.
/// `#[non_exhaustive]`: this is a returned shape that gains fields as the wallet does, so
/// destructure it non-exhaustively.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TxRecord {
    pub mined_height: Option<u32>,
    pub txid_hex: String,
    pub expiry_height: Option<u32>,
    pub account_balance_delta: i64,
    pub fee_paid: Option<u64>,
    pub block_time: Option<i64>,
    pub expired_unmined: bool,
    /// Position of the transaction within its block, when known (`blockindex`).
    pub tx_index: Option<u32>,
    /// Display-hex hash of the mining block, when scanned (`blockhash`).
    pub block_hash: Option<String>,
    /// Unix time the wallet created the transaction (librustzcash sets `created` only for
    /// wallet-authored sends); the unmined-tx `time`/`timereceived` fallback.
    pub created_time: Option<i64>,
    pub outputs: Vec<TxOutputRecord>,
    /// Raw serialized transaction bytes, when available (populated by `get_transaction`).
    pub raw: Option<Vec<u8>>,
}

/// An unspent Orchard note, for `listunspent`.
#[derive(Debug, Clone)]
pub struct UnspentNote {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub mined_height: Option<u32>,
    /// Whether this wallet authored the transaction that created the note (it spent from the
    /// account). Bitcoin Core's `listunspent.safe` analog: an *own* unconfirmed note (change)
    /// is trusted, a foreign unconfirmed note is not.
    pub trusted: bool,
    /// The diversified address the note was received on, when the wallet recorded one
    /// (change/internal notes have none).
    pub address: Option<String>,
    /// The shielded pool the note is in, as a `v_tx_outputs.output_pool` code: 2 = Sapling,
    /// 3 = Orchard, 4 = ironwood (NU6.3). Sourced from `v_tx_outputs.output_pool` (the
    /// `ironwood_pool_code_views` migration tags ironwood outputs 4). Ironwood is a first-class pool
    /// in the pinned librustzcash line: a received ironwood note lives in `ironwood_received_notes`
    /// and comes back from `select_unspent_notes` in `ReceivedNotes::ironwood()` (a separate
    /// accessor from `orchard()`), so `list_unspent` must request `ShieldedPool::Ironwood` and read
    /// that accessor to surface it. Surfaced as `listunspent`'s `pool`.
    pub pool: i64,
    /// Whether the output was produced by a coinbase transaction (`transactions.tx_index == 0`),
    /// zcashd `listunspent`'s `generated` flag. Always `false` for shielded notes (a shielded
    /// coinbase note spends like any other note, so nothing hinges on labeling it). Immature
    /// coinbase UTXOs (< 100 confirmations) are excluded from the listing entirely, matching
    /// Bitcoin Core/zcashd (`AvailableCoins` skips them); their value shows as `immature`
    /// balance until they mature.
    pub generated: bool,
}

fn open_conn(engine_dir: &Path) -> anyhow::Result<Connection> {
    let conn = Connection::open(data_db_path(engine_dir))?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(conn)
}

/// Convert internal txid bytes to conventional (reversed) display hex.
fn txid_display(bytes: &[u8]) -> String {
    let mut b = bytes.to_vec();
    b.reverse();
    hex::encode(b)
}

/// Convert a display-hex txid back to internal byte order for lookups.
fn txid_internal(display_hex: &str) -> Option<Vec<u8>> {
    let mut b = hex::decode(display_hex).ok()?;
    if b.len() != 32 {
        return None;
    }
    b.reverse();
    Some(b)
}

/// SQL predicate that the transaction aliased `alias` is *unexpired*, a faithful port of
/// librustzcash's `zcash_client_sqlite::wallet::common::tx_unexpired_condition` - the canonical
/// rule that `select_unspent_notes`/`spent_notes_clause` and the balance queries use. We
/// reproduce it because there is no public API for the unmined/mempool notes and rebroadcast set
/// the raw queries below supplement; centralizing it (rather than open-coding a simpler expiry
/// test, as earlier copies did) keeps `listunspent minconf=0` and `unmined_raw_txs` in lockstep
/// with `getbalance` - including the `min_observed_height + DEFAULT_TX_EXPIRY_DELTA` staleness
/// branch (a tx with unknown expiry is treated as unexpired only while recently observed). The
/// caller must bind `:target_height` to the next-to-be-mined height (chain tip + 1). Keep this in
/// sync with upstream on every `zcash_client_sqlite` bump.
fn tx_unexpired_sql(alias: &str) -> String {
    format!(
        "{alias}.mined_height < :target_height
         OR {alias}.expiry_height = 0
         OR {alias}.expiry_height >= :target_height
         OR ({alias}.expiry_height IS NULL
             AND {alias}.min_observed_height + {DEFAULT_TX_EXPIRY_DELTA} >= :target_height)"
    )
}

/// Loads a transaction's outputs from `v_tx_outputs`.
///
/// A received transparent output is reported at the transparent receiver itself: since
/// `zcash_client_sqlite` 0.22.0-rc.6 the view's received arm resolves pool 0 through
/// `addresses.cached_transparent_receiver_address` rather than the enclosing unified address,
/// and prefers the recipient recorded at construction time for outputs the wallet created. So
/// `to_address` is already the address observably paid on chain, and zecd does no rewriting of
/// its own (it used to map the unified encoding back to the t-address here).
/// The statement [`load_outputs`] runs. Ordered by `(output_pool, output_index)`, the
/// within-transaction half of the total order documented on [`query_transactions`]: a
/// transaction can hold outputs in more than one pool, and `output_index` is the index within
/// that pool's bundle, so the pool must lead for the pair to be a well-defined key. Named so
/// the ordering tests exercise this exact text rather than a transcription of it.
///
/// The account predicate is written into the constant rather than formatted in, so the ordering
/// test still runs character-for-character what the caller runs. It is the same predicate
/// [`scope_by_output_account`] builds for the queries that must assemble their SQL.
const LOAD_OUTPUTS_SQL: &str = "SELECT output_pool, output_index, from_account_uuid,
                to_account_uuid, to_address, value, is_change, recipient_key_scope, memo
         FROM v_tx_outputs
         WHERE txid = :txid
           AND (:scope_account IS NULL OR to_account_uuid = :scope_account
                OR from_account_uuid = :scope_account)
         ORDER BY output_pool ASC, output_index ASC";

/// Outputs come back ordered by `(output_pool, output_index)` - see [`LOAD_OUTPUTS_SQL`].
fn load_outputs(
    conn: &Connection,
    scope: AccountScope,
    txid: &[u8],
) -> anyhow::Result<Vec<TxOutputRecord>> {
    let mut stmt = conn.prepare(LOAD_OUTPUTS_SQL)?;
    let rows = stmt.query_map(
        named_params! {":txid": txid, ":scope_account": scope.param()},
        |row| {
            Ok(TxOutputRecord {
                pool: row.get("output_pool")?,
                output_index: row.get("output_index")?,
                from_account: row.get::<_, Option<Uuid>>("from_account_uuid")?,
                to_account: row.get::<_, Option<Uuid>>("to_account_uuid")?,
                to_address: row.get("to_address")?,
                value: row.get("value")?,
                is_change: row.get("is_change")?,
                recipient_key_scope: row.get::<_, Option<i64>>("recipient_key_scope")?,
                memo: row.get("memo")?,
            })
        },
    )?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// The column list shared by [`list_transactions`] and [`get_transaction`]: `v_transactions`
/// joined with the mining block's hash and the raw `transactions` row's `created` timestamp
/// (set only for wallet-authored sends; stored as `yyyy-MM-dd HH:mm:ss.fffffffzzz`, which
/// SQLite's date parser understands).
const TX_COLS: &str = "v.mined_height, v.txid, v.expiry_height, v.account_balance_delta,
            v.fee_paid, v.block_time,
            v.expired_unmined, v.tx_index,
            b.hash AS block_hash,
            CAST(strftime('%s', t.created) AS INTEGER) AS created_time";

/// The matching source clause for [`TX_COLS`].
const TX_FROM: &str = "FROM v_transactions v
     LEFT JOIN blocks b ON b.height = v.mined_height
     LEFT JOIN transactions t ON t.txid = v.txid";

/// Parse one [`TX_COLS`] row into `(internal txid, TxRecord)` (outputs filled by callers).
fn tx_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<(Vec<u8>, TxRecord)> {
    let txid: Vec<u8> = row.get("txid")?;
    Ok((
        txid.clone(),
        TxRecord {
            mined_height: row.get("mined_height")?,
            txid_hex: txid_display(&txid),
            expiry_height: row.get("expiry_height")?,
            account_balance_delta: row.get("account_balance_delta")?,
            fee_paid: row.get::<_, Option<i64>>("fee_paid")?.map(|v| v as u64),
            block_time: row.get("block_time")?,
            expired_unmined: row.get("expired_unmined")?,
            tx_index: row.get("tx_index")?,
            block_hash: row
                .get::<_, Option<Vec<u8>>>("block_hash")?
                .map(|h| txid_display(&h)),
            created_time: row.get("created_time")?,
            outputs: Vec::new(),
            raw: None,
        },
    ))
}

/// Filter/pagination for [`query_transactions`], mirroring zcashd's height-range and
/// count/from arguments. The history/received-by RPCs push their windowing through this so
/// neither memory nor the per-tx [`load_outputs`] query scales with the whole wallet.
/// `#[non_exhaustive]`: new filter/pagination fields are additive, so build one with
/// [`Default::default`] and assign the fields you need (field assignment stays available to
/// external callers; only struct-literal syntax is not).
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct TxQuery {
    /// Lowest mined height to include (inclusive); `None` imposes no lower bound. Unmined txs
    /// are included only when `end_height` is also `None` (matching zcashd's predicate, which
    /// keeps unmined txs in an open-ended range but drops them once an upper bound is set).
    pub start_height: Option<u32>,
    /// Exclusive upper mined-height bound; `None` imposes no upper bound (and admits unmined).
    pub end_height: Option<u32>,
    /// Rows to skip after ordering (`LIMIT ... OFFSET`).
    pub offset: u32,
    /// Maximum rows to return; `None` means all (`LIMIT -1`).
    pub limit: Option<u32>,
    /// Order newest-first (`sort_height DESC NULLS FIRST`) instead of oldest-first.
    pub newest_first: bool,
}

/// The statement [`query_transactions`] runs, for the requested direction. Extracted (with
/// [`LOAD_OUTPUTS_SQL`]) so the ordering tests run this exact text against a fixture schema;
/// the ordering contract is documented on [`query_transactions`].
///
/// The `txid` tiebreak follows `sort_height`'s direction, so reversing the query reverses the
/// whole transaction-level order rather than interleaving a descending height with an ascending
/// txid.
fn tx_query_sql(newest_first: bool) -> String {
    let account = scope_by_uuid("v.account_uuid");
    let order = if newest_first {
        "ORDER BY sort_height DESC NULLS FIRST, v.txid DESC"
    } else {
        "ORDER BY sort_height ASC NULLS LAST, v.txid ASC"
    };
    format!(
        "SELECT {TX_COLS},
            COALESCE(
                v.mined_height,
                CASE WHEN v.expiry_height == 0 THEN NULL ELSE v.expiry_height END
            ) AS sort_height
         {TX_FROM}
         WHERE (:start_height IS NULL OR v.mined_height >= :start_height
                OR (v.mined_height IS NULL AND :end_height IS NULL))
           AND (:end_height IS NULL OR v.mined_height < :end_height)
           AND {account}
         {order}
         LIMIT :limit OFFSET :offset"
    )
}

/// Transactions matching `q`, each with its outputs. The WHERE clause mirrors zcashd's
/// height predicate (`rpcwallet.cpp` `listsinceblock`/`listreceivedbyaddress` range), and the
/// `sort_height` ordering (mined height, else a non-zero expiry height) matches what
/// [`list_transactions`] used before pagination moved into SQL. [`load_outputs`] stays per-tx
/// but is now bounded by `limit`, not the whole wallet.
///
/// # Ordering
///
/// Rows come back in a **total** order: `sort_height`, then `txid`, with each transaction's
/// outputs ordered by `(output_pool, output_index)` ([`load_outputs`]). Both tiebreaks are part
/// of the contract, not incidental: `sort_height` alone is not injective (blocks hold many
/// wallet transactions), so without the `txid` key two transactions at one height came back in
/// whatever order SQLite happened to produce, and a `LIMIT`/`OFFSET` page boundary landing
/// inside such a tie could repeat or skip a transaction between adjacent pages. The `txid`
/// comparison is over the stored internal (little-endian) bytes - an arbitrary but stable
/// permutation of display order, which is all a tiebreak needs to be.
///
/// Consumers replaying wallet history as a log therefore get a stable
/// `(mined_height, txid, pool, output_index)` sequence, and can resume from the last
/// `(height, txid, output_index)` they processed. `newest_first` reverses the transaction-level
/// keys together; the within-transaction output order is unaffected.
pub fn query_transactions(
    engine_dir: &Path,
    scope: AccountScope,
    q: &TxQuery,
) -> anyhow::Result<Vec<TxRecord>> {
    let conn = open_conn(engine_dir)?;
    let mut stmt = conn.prepare(&tx_query_sql(q.newest_first))?;
    let rows = stmt.query_map(
        named_params! {
            ":start_height": q.start_height,
            ":end_height": q.end_height,
            ":scope_account": scope.param(),
            // LIMIT -1 means "no limit" in SQLite.
            ":limit": q.limit.map(i64::from).unwrap_or(-1),
            ":offset": q.offset,
        },
        tx_from_row,
    )?;
    let mut pending: Vec<(Vec<u8>, TxRecord)> = Vec::new();
    for r in rows {
        pending.push(r?);
    }
    let mut records = Vec::with_capacity(pending.len());
    for (txid, mut rec) in pending {
        rec.outputs = load_outputs(&conn, scope, &txid)?;
        records.push(rec);
    }
    Ok(records)
}

/// All transactions, oldest first (callers apply skip/count). Mirrors `list_tx.rs`. A thin
/// wrapper over [`query_transactions`] with no filtering, kept for callers that genuinely
/// want the whole history (`gettransaction.details` aggregation, tests).
pub fn list_transactions(engine_dir: &Path, scope: AccountScope) -> anyhow::Result<Vec<TxRecord>> {
    query_transactions(engine_dir, scope, &TxQuery::default())
}

/// A lightweight data source for the received-by aggregations
/// (`getreceivedbyaddress`/`listreceivedbyaddress`),
/// avoiding [`list_transactions`]'s N+1 [`load_outputs`] and its per-tx memo/raw/block-hash
/// overhead. One flat query joins `v_transactions` to `v_tx_outputs`; the rows are grouped
/// into [`TxRecord`]s carrying only the fields the aggregation reads (`mined_height`,
/// `expired_unmined`, and each output's `to_account`/`to_address`/`value`/`is_change`), so the
/// existing - and tested - `received_by_address` logic produces identical output.
///
/// `address_filter` (display encoding) is pushed into SQL for `getreceivedbyaddress`, which
/// asks about a single address: only its outputs are loaded. It is compared against
/// `v_tx_outputs.to_address` as given - a received transparent output is stored under its bare
/// t-address (see [`load_outputs`]), so a t-address filter matches the stored rows directly.
pub fn received_tx_records(
    engine_dir: &Path,
    scope: AccountScope,
    address_filter: Option<&str>,
) -> anyhow::Result<Vec<TxRecord>> {
    let conn = open_conn(engine_dir)?;
    let account = scope_by_uuid("v.account_uuid");
    // Order by the same `sort_height` (oldest-first) as `list_transactions`, so the per-address
    // `txids` list `listreceivedbyaddress` emits is in the identical order it was before this
    // flat path replaced the full N+1 load.
    let mut stmt = conn.prepare(&format!(
        "SELECT v.txid, v.mined_height, v.expired_unmined,
                o.to_address, o.value, o.is_change, o.to_account_uuid, o.output_pool,
                o.recipient_key_scope, v.tx_index
         FROM v_transactions v
         JOIN v_tx_outputs o ON o.txid = v.txid
         WHERE (:addr IS NULL OR o.to_address = :addr)
           AND {account}
         ORDER BY COALESCE(
                v.mined_height,
                CASE WHEN v.expiry_height == 0 THEN NULL ELSE v.expiry_height END
            ) ASC NULLS LAST,
            v.txid ASC, o.output_pool ASC, o.output_index ASC"
    ))?;
    let rows = stmt.query_map(
        named_params! { ":addr": address_filter, ":scope_account": scope.param() },
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Option<u32>>(1)?,
                row.get::<_, bool>(2)?,
                // `tx_index` identifies a coinbase tx (block index 0), which the aggregation needs
                // for the transparent coinbase-maturity exclusion.
                row.get::<_, Option<u32>>(9)?,
                TxOutputRecord {
                    // `output_index`/`from_account`/`memo` are unused by the aggregation; `pool`
                    // is carried through so the record is the same shape [`load_outputs`] produces.
                    pool: row.get(7)?,
                    output_index: 0,
                    from_account: None,
                    to_account: row.get::<_, Option<Uuid>>(6)?,
                    to_address: row.get(3)?,
                    value: row.get(4)?,
                    is_change: row.get(5)?,
                    recipient_key_scope: row.get::<_, Option<i64>>(8)?,
                    memo: None,
                },
            ))
        },
    )?;
    // Group outputs back under their transaction, preserving first-seen txid order.
    let mut order: Vec<Vec<u8>> = Vec::new();
    let mut by_txid: HashMap<Vec<u8>, TxRecord> = HashMap::new();
    for r in rows {
        let (txid, mined_height, expired_unmined, tx_index, out) = r?;
        let rec = by_txid.entry(txid.clone()).or_insert_with(|| {
            order.push(txid.clone());
            TxRecord {
                mined_height,
                txid_hex: txid_display(&txid),
                expiry_height: None,
                account_balance_delta: 0,
                fee_paid: None,
                block_time: None,
                expired_unmined,
                tx_index,
                block_hash: None,
                created_time: None,
                outputs: Vec::new(),
                raw: None,
            }
        });
        rec.outputs.push(out);
    }
    Ok(order
        .into_iter()
        .map(|txid| by_txid.remove(&txid).expect("inserted above"))
        .collect())
}

/// A single transaction by its display-hex txid.
pub fn get_transaction(
    network: ZNetwork,
    engine_dir: &Path,
    scope: AccountScope,
    txid_hex: &str,
) -> anyhow::Result<Option<TxRecord>> {
    let Some(internal) = txid_internal(txid_hex) else {
        return Ok(None);
    };
    let conn = open_conn(engine_dir)?;
    let account = scope_by_uuid("v.account_uuid");
    let mut stmt = conn.prepare(&format!(
        "SELECT {TX_COLS} {TX_FROM} WHERE v.txid = :txid AND {account}"
    ))?;
    let mut rows =
        stmt.query(named_params! {":txid": internal, ":scope_account": scope.param()})?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let (txid, mut rec) = tx_from_row(row)?;
    drop(rows);
    rec.outputs = load_outputs(&conn, scope, &txid)?;
    // Fetch the raw transaction bytes for `gettransaction.hex` via the public `WalletRead` API
    // (mirroring the actor's `do_get_raw_tx`) instead of reading librustzcash's internal
    // `transactions.raw` column directly: this yields the canonical consensus serialization off
    // the documented interface. `None` when the tx is unknown or its raw data isn't stored -
    // exactly the contract of the column read it replaces.
    rec.raw = <[u8; 32]>::try_from(internal)
        .ok()
        .and_then(|bytes| raw_tx_bytes(network, engine_dir, TxId::from_bytes(bytes)));
    Ok(Some(rec))
}

/// Serialized bytes of a wallet-known transaction, via the public `WalletRead::get_transaction`.
/// `None` if the txid is unknown to the wallet or its raw data hasn't been stored yet.
fn raw_tx_bytes(network: ZNetwork, engine_dir: &Path, txid: TxId) -> Option<Vec<u8>> {
    let db = open_read(network, engine_dir).ok()?;
    let tx = db.get_transaction(txid).ok()??;
    let mut buf = Vec::new();
    tx.write(&mut buf).ok()?;
    Some(buf)
}

/// Whether the wallet database has a row for this transaction (display-hex txid). The actor
/// uses this to record first-seen times only for transactions that concern the wallet.
pub fn tx_exists(engine_dir: &Path, txid_hex: &str) -> bool {
    let Some(internal) = txid_internal(txid_hex) else {
        return false;
    };
    let Ok(conn) = open_conn(engine_dir) else {
        return false;
    };
    conn.query_row(
        "SELECT 1 FROM transactions WHERE txid = :txid",
        named_params! {":txid": internal},
        |_| Ok(()),
    )
    .optional()
    .ok()
    .flatten()
    .is_some()
}

/// The rebroadcast-set query, factored out so a test can run it against a schema without
/// standing up a whole wallet directory. Bind `:target_height` to the next-to-be-mined height.
///
/// Unexpired is the shared [`tx_unexpired_sql`] predicate (the same rule the selector uses), so
/// the rebroadcast set never diverges from what the wallet considers live; `expiry_height >=
/// tip + 1` is exactly the old `expiry > tip`.
fn unmined_raw_txs_sql() -> String {
    let unexpired = tx_unexpired_sql("t");
    format!(
        "SELECT txid, raw FROM transactions t
         WHERE mined_height IS NULL AND raw IS NOT NULL
         AND ({unexpired})
         AND (EXISTS (SELECT 1 FROM orchard_received_note_spends s
                      WHERE s.transaction_id = t.id_tx)
              OR EXISTS (SELECT 1 FROM sapling_received_note_spends s
                         WHERE s.transaction_id = t.id_tx)
              OR EXISTS (SELECT 1 FROM ironwood_received_note_spends s
                         WHERE s.transaction_id = t.id_tx)
              OR EXISTS (SELECT 1 FROM transparent_received_output_spends s
                         WHERE s.transaction_id = t.id_tx))"
    )
}

/// Wallet transactions that are still unmined and unexpired at `tip` - candidates for
/// rebroadcast. Returns `(display_txid, raw_bytes)`; `raw` is only present for txs the
/// wallet created or has enhanced. An expiry height of 0 means "never expires".
///
/// Only transactions that spend this wallet's notes or transparent outputs qualify (nobody
/// else can spend them, so such a tx was necessarily authored here). The actor's mempool
/// stream also stores *foreign* incoming txs as unmined rows with raw bytes, and those are
/// the sender's to retransmit, not ours.
///
/// **Every** shielded pool must be listed in that ownership test, ironwood included: a spend of
/// an ironwood note is recorded in `ironwood_received_note_spends`, not in the orchard table, so
/// omitting it silently excludes the transaction from the rebroadcast set. Post-NU6.3 a wallet's
/// shielded funds *are* ironwood notes, so the omission meant no send could ever be retried - a
/// send whose broadcast failed (upstream briefly down) was simply never retransmitted, and sat
/// unmined until it expired. Pre-NU6.3 the tables are empty, so this reads as a no-op there.
pub fn unmined_raw_txs(engine_dir: &Path, tip: u32) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    let conn = open_conn(engine_dir)?;
    let mut stmt = conn.prepare(&unmined_raw_txs_sql())?;
    let rows = stmt.query_map(named_params! { ":target_height": tip + 1 }, |row| {
        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    let mut out = Vec::new();
    for r in rows {
        let (txid, raw) = r?;
        out.push((txid_display(&txid), raw));
    }
    Ok(out)
}

/// Every transparent output the wallet holds and has not yet seen spent, as
/// `(funding txid, output index)` outpoints - the membership set the block scan tests each
/// block's transparent inputs against to discover spends.
///
/// Deliberately unfiltered by maturity or confirmations: this answers "could a spend of this
/// output show up in a block", not "may we spend it". Unmined (0-conf) receives are included so
/// a spend of one is caught as soon as it is mined, and immature coinbase is included because a
/// spend of it is still a spend the wallet must record. An output is dropped as soon as any
/// spend of it is recorded, which is what keeps the set shrinking as spends are found.
pub fn unspent_transparent_outpoints(
    engine_dir: &Path,
) -> anyhow::Result<std::collections::HashSet<(TxId, u32)>> {
    let conn = Connection::open(data_db_path(engine_dir))?;
    let mut stmt = conn.prepare(
        "SELECT t.txid, txo.output_index
         FROM transparent_received_outputs txo
         JOIN transactions t ON t.id_tx = txo.transaction_id
         WHERE txo.id NOT IN (
             SELECT s.transparent_received_output_id
             FROM transparent_received_output_spends s
         )",
    )?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, u32>(1)?)))?;
    let mut out = std::collections::HashSet::new();
    for row in rows {
        let (txid_bytes, index) = row?;
        let Ok(bytes) = <[u8; 32]>::try_from(txid_bytes.as_slice()) else {
            continue;
        };
        out.insert((TxId::from_bytes(bytes), index));
    }
    Ok(out)
}

/// Display-hex txids of every wallet transaction that is still unmined (`mined_height` NULL),
/// including foreign incoming txs the mempool stream stored. Used to prune the actor's transient
/// in-memory first-seen map (which only ever matters for unmined txs).
pub fn unmined_txids(engine_dir: &Path) -> anyhow::Result<Vec<String>> {
    let conn = open_conn(engine_dir)?;
    let mut stmt = conn.prepare("SELECT txid FROM transactions WHERE mined_height IS NULL")?;
    let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(txid_display(&r?));
    }
    Ok(out)
}

/// The `(display-hex hash, unix time)` of a block the wallet has scanned, from the wallet's
/// `blocks` table. Hashes are stored in internal byte order and displayed reversed, like txids.
pub fn block_info_at(engine_dir: &Path, height: u32) -> anyhow::Result<Option<(String, i64)>> {
    let conn = open_conn(engine_dir)?;
    let row = conn
        .query_row(
            "SELECT hash, time FROM blocks WHERE height = :height",
            named_params! {":height": height},
            |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?)),
        )
        .optional()?;
    Ok(row.map(|(hash, time)| (txid_display(&hash), time)))
}

/// The earliest block the wallet has scanned, as `(height, display-hex hash)` - the lowest
/// cursor `listsinceblock` can hand out when the requested depth predates the wallet.
pub fn first_scanned_block(engine_dir: &Path) -> anyhow::Result<Option<(u32, String)>> {
    let conn = open_conn(engine_dir)?;
    let row = conn
        .query_row(
            "SELECT height, hash FROM blocks ORDER BY height ASC LIMIT 1",
            [],
            |r| Ok((r.get::<_, u32>(0)?, r.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    Ok(row.map(|(h, hash)| (h, txid_display(&hash))))
}

/// Whether `display_hash` is a syntactically valid block-hash string (64 hex chars -> 32
/// bytes). `listsinceblock` uses this to tell a reorged-away cursor (well-formed, whose
/// `blocks` row `perform_rewind` deleted - worth surviving) from a malformed client argument
/// (still `-5`).
pub fn is_block_hash_wellformed(display_hash: &str) -> bool {
    txid_internal(display_hash).is_some()
}

/// The height of a wallet-scanned block, looked up by its display-hex hash (for
/// `listsinceblock`). Hashes are stored in internal byte order, displayed reversed.
pub fn block_height_by_hash(engine_dir: &Path, display_hash: &str) -> anyhow::Result<Option<u32>> {
    let Some(internal) = txid_internal(display_hash) else {
        return Ok(None);
    };
    let conn = open_conn(engine_dir)?;
    let h = conn
        .query_row(
            "SELECT height FROM blocks WHERE hash = :hash",
            named_params! {":hash": internal},
            |r| r.get::<_, u32>(0),
        )
        .optional()?;
    Ok(h)
}

/// The median-time-past at `height`: the median of the (up to) 11 scanned block times ending
/// at `height` inclusive - the consensus MTP rule, for `getblockchaininfo.mediantime`.
pub fn median_time_past(engine_dir: &Path, height: u32) -> anyhow::Result<Option<i64>> {
    let conn = open_conn(engine_dir)?;
    let mut stmt = conn
        .prepare("SELECT time FROM blocks WHERE height <= :height ORDER BY height DESC LIMIT 11")?;
    let rows = stmt.query_map(named_params! {":height": height}, |r| r.get::<_, i64>(0))?;
    let mut times: Vec<i64> = rows.collect::<Result<_, _>>()?;
    if times.is_empty() {
        return Ok(None);
    }
    times.sort_unstable();
    Ok(Some(times[times.len() / 2]))
}

/// List unspent Orchard notes for `listunspent` (with mined height for confirmations).
pub fn list_unspent(
    network: ZNetwork,
    engine_dir: &Path,
    scope: AccountScope,
) -> anyhow::Result<Vec<UnspentNote>> {
    let db = open_read(network, engine_dir)?;
    let Some(chain_height) = db.chain_height()? else {
        return Ok(vec![]);
    };
    let target_height = (chain_height + 1).into();

    // Map txid (display hex) -> (mined height, authored-by-us) for confirmations and trust.
    // A negative balance delta means the wallet spent notes in the tx, i.e. it authored it.
    let mut tx_meta: HashMap<String, (Option<u32>, bool)> = HashMap::new();
    // Map (txid, output index) -> receiving address for the shielded outputs the wallet recorded
    // one for (change/internal notes have none), plus -> shielded pool code for every shielded
    // output (2 = Sapling, 3 = Orchard, 4 = ironwood). The pool map is keyed off
    // `v_tx_outputs.output_pool` (the valar fork's `ironwood_pool_code_views` migration tags
    // ironwood 4) rather than the note's protocol, so an ironwood (Orchard V3) note - which
    // librustzcash returns in `ReceivedNotes::ironwood()` (its own accessor) - is labelled ironwood.
    let mut out_addr: HashMap<(String, u32), String> = HashMap::new();
    let mut out_pool: HashMap<(String, u32), i64> = HashMap::new();
    {
        let conn = open_conn(engine_dir)?;
        let tx_account = scope_by_uuid("account_uuid");
        let mut stmt = conn.prepare(&format!(
            "SELECT txid, mined_height, account_balance_delta FROM v_transactions
             WHERE {tx_account}"
        ))?;
        let rows = stmt.query_map(named_params! { ":scope_account": scope.param() }, |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Option<u32>>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        for row in rows {
            let (txid, mh, delta) = row?;
            tx_meta.insert(txid_display(&txid), (mh, delta < 0));
        }
        let out_account = scope_by_output_account();
        let mut stmt = conn.prepare(&format!(
            "SELECT txid, output_index, output_pool, to_address FROM v_tx_outputs
             WHERE output_pool IN (2, 3, 4) AND {out_account}"
        ))?;
        let rows = stmt.query_map(named_params! { ":scope_account": scope.param() }, |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, u32>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        })?;
        for row in rows {
            let (txid, idx, pool, addr) = row?;
            let txid = txid_display(&txid);
            out_pool.insert((txid.clone(), idx), pool);
            if let Some(addr) = addr {
                out_addr.insert((txid, idx), addr);
            }
        }
    }

    let mut out = Vec::new();
    // All shielded pools zecd supports; a note only exists if the wallet received it, so querying
    // every pool is safe regardless of which pools are enabled in config.
    #[allow(unused_mut)]
    let mut protocols: Vec<ShieldedPool> = crate::pools::Receiver::SUPPORTED
        .iter()
        .filter_map(|p| p.shielded_protocol())
        .collect();
    // Ironwood (NU6.3, Orchard V3) is a first-class pool in the pinned librustzcash line: its notes
    // live in the separate `ironwood_received_notes` table and are returned by
    // `SpendableNotes::ironwood()`, *not* folded into `orchard()`. `select_unspent_notes` only
    // queries a pool when it appears in `sources`, so an ironwood receive is invisible to
    // `listunspent` unless we ask for it here (and read `notes.ironwood()` below). It is not a
    // `Receiver::SUPPORTED` member (ironwood has no UA receiver - see `pools.rs`), so add it explicitly.
    // Harmless pre-NU6.3: the ironwood note table is simply empty on mainnet / pre-activation testnet.
    protocols.push(ShieldedPool::Ironwood);
    for account in scoped_account_ids(&db, scope)? {
        let notes = db.select_unspent_notes(
            account,
            &protocols,
            target_height,
            &[],
            LockFilter::Unfiltered,
        )?;
        // Both `notes.sapling()` and `notes.orchard()` yield `ReceivedNote`s with the same
        // `txid`/`output_index`/`note_value` surface; collect each into the shared output list.
        // `default_pool` is the note's protocol pool (2 Sapling / 3 Orchard); the per-output
        // `out_pool` map overrides it so an ironwood (Orchard V3) note is labelled 4.
        let mut push = |txid: String, vout: u32, value: u64, default_pool: i64| {
            let (mined_height, trusted) = tx_meta.get(&txid).copied().unwrap_or((None, false));
            let key = (txid.clone(), vout);
            let address = out_addr.get(&key).cloned();
            let pool = out_pool.get(&key).copied().unwrap_or(default_pool);
            out.push(UnspentNote {
                vout,
                txid,
                value,
                mined_height,
                trusted,
                address,
                pool,
                generated: false,
            });
        };
        for note in notes.sapling() {
            let value = note
                .note_value()
                .map_err(|e| anyhow!("note value: {e:?}"))?
                .into_u64();
            push(
                note.txid().to_string(),
                note.output_index() as u32,
                value,
                2,
            );
        }
        for note in notes.orchard() {
            let value = note
                .note_value()
                .map_err(|e| anyhow!("note value: {e:?}"))?
                .into_u64();
            push(
                note.txid().to_string(),
                note.output_index() as u32,
                value,
                3,
            );
        }
        // Ironwood notes are Orchard-shaped (`ReceivedNote<_, orchard::note::Note>`) but returned in
        // their own `ironwood()` accessor; label them pool code 4 (the `out_pool` map overrides this
        // with the recorded `v_tx_outputs.output_pool` when present, which is also 4).
        for note in notes.ironwood() {
            let value = note
                .note_value()
                .map_err(|e| anyhow!("note value: {e:?}"))?
                .into_u64();
            push(
                note.txid().to_string(),
                note.output_index() as u32,
                value,
                4,
            );
        }
    }

    // Mempool-received notes are invisible to `select_unspent_notes`: a note stored by
    // trial-decrypting an *unmined* transaction carries no nullifier (upstream's
    // `DecryptedOutput::nullifier()` is `None`; nf/position are filled in when the tx is later
    // scanned in a block) and the selector requires `nf IS NOT NULL`. bitcoind's
    // `listunspent minconf=0` lists unconfirmed wallet outputs, so supplement with a direct
    // query per shielded pool for unmined, unexpired, unspent notes. A spend only suppresses a
    // note while its spending tx is mined or unexpired - mirroring `spent_notes_clause` - so an
    // expired spend releases the note again.
    {
        let conn = open_conn(engine_dir)?;
        let seen: std::collections::HashSet<(String, u32)> =
            out.iter().map(|u| (u.txid.clone(), u.vout)).collect();
        let target = u32::from(chain_height) + 1;
        // Per-pool table/column names differ only in three identifiers (note table, spend table,
        // FK column, and the output-index column), so run the same query shape for each pool.
        #[allow(unused_mut)]
        let mut pools: Vec<(&str, &str, &str, &str, i64)> = vec![
            (
                "sapling_received_notes",
                "sapling_received_note_spends",
                "sapling_received_note_id",
                "output_index",
                2,
            ),
            (
                "orchard_received_notes",
                "orchard_received_note_spends",
                "orchard_received_note_id",
                "action_index",
                3,
            ),
        ];
        // An unmined ironwood note is stored in its own `ironwood_received_notes` table (not
        // `orchard_received_notes`), so a 0-conf ironwood receive from the mempool stream is only
        // visible if we query that table too. Same query shape; pool code 4. Empty pre-NU6.3.
        pools.push((
            "ironwood_received_notes",
            "ironwood_received_note_spends",
            "ironwood_received_note_id",
            "action_index",
            4,
        ));
        // Both the note's own creating tx and any spending tx are gated by the shared
        // `tx_unexpired_sql` predicate, so this supplement and the rebroadcast set agree with the
        // selector/balances on exactly what "unexpired" means (incl. the unknown-expiry staleness
        // branch). A note is shown only if its creating tx is unmined and unexpired, and isn't
        // suppressed by a spend whose tx is still live (mined or unexpired) - an expired spend
        // releases the note again.
        let unexpired_t = tx_unexpired_sql("t");
        let unexpired_stx = tx_unexpired_sql("stx");
        for (note_table, spend_table, fk_col, index_col, default_pool) in &pools {
            let sql = format!(
                "SELECT t.txid, rn.{index_col}, rn.value
                 FROM {note_table} rn
                 JOIN transactions t ON t.id_tx = rn.transaction_id
                 WHERE t.mined_height IS NULL
                   AND ({unexpired_t})
                   AND rn.id NOT IN (
                       SELECT rns.{fk_col}
                       FROM {spend_table} rns
                       JOIN transactions stx ON stx.id_tx = rns.transaction_id
                       WHERE {unexpired_stx}
                   )"
            );
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(named_params! { ":target_height": target }, |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, u32>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?;
            for row in rows {
                let (txid, vout, value) = row?;
                let txid = txid_display(&txid);
                if seen.contains(&(txid.clone(), vout)) {
                    continue;
                }
                let (mined_height, trusted) = tx_meta.get(&txid).copied().unwrap_or((None, false));
                let key = (txid.clone(), vout);
                let address = out_addr.get(&key).cloned();
                // An unmined ironwood note may not yet have its v_tx_outputs row, so fall back to
                // the note table's protocol pool (Orchard); it relabels to ironwood once mined.
                let pool = out_pool.get(&key).copied().unwrap_or(*default_pool);
                out.push(UnspentNote {
                    vout,
                    txid,
                    value: u64::try_from(value).unwrap_or(0),
                    mined_height,
                    trusted,
                    address,
                    pool,
                    generated: false,
                });
            }
        }

        // Transparent UTXOs. Unlike shielded notes there's no `select_unspent_notes` path, so list
        // all unspent received transparent outputs here (mined and unmined alike), with real
        // bitcoin-style `(txid, vout)` outpoints and the bare t-address. An output is shown if its
        // creating tx is mined or unmined-and-unexpired, and isn't suppressed by a spend whose tx
        // is still live (mined or unexpired) - mirroring the shielded suppression above. Real
        // outpoints don't collide with the shielded synthesized ones, so this isn't deduped
        // against `seen`.
        let unexpired_t = tx_unexpired_sql("t");
        let unexpired_stx = tx_unexpired_sql("stx");
        // Coinbase handling mirrors `zcash_client_sqlite`'s spendability SQL: an output is
        // coinbase iff its tx's recorded block index is 0 (`IFNULL(tx_index, 1)` - unknown
        // defaults to non-coinbase), and an *immature* coinbase output (fewer than
        // `COINBASE_MATURITY` confirmations at the target height) is excluded from the listing,
        // matching Bitcoin Core/zcashd's `AvailableCoins`. Mature coinbase outputs are listed
        // with `generated = true`.
        let sql = format!(
            "SELECT t.txid, txo.output_index, txo.value_zat, txo.address,
                    (IFNULL(t.tx_index, 1) == 0) AS generated
             FROM transparent_received_outputs txo
             JOIN transactions t ON t.id_tx = txo.transaction_id
             WHERE (t.mined_height IS NOT NULL OR ({unexpired_t}))
               AND NOT (
                   IFNULL(t.tx_index, 1) == 0
                   AND :target_height - t.mined_height < {COINBASE_MATURITY}
               )
               AND txo.id NOT IN (
                   SELECT s.transparent_received_output_id
                   FROM transparent_received_output_spends s
                   JOIN transactions stx ON stx.id_tx = s.transaction_id
                   WHERE {unexpired_stx}
               )"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(named_params! { ":target_height": target }, |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, u32>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, bool>(4)?,
            ))
        })?;
        for row in rows {
            let (txid, vout, value, address, generated) = row?;
            let txid = txid_display(&txid);
            let (mined_height, trusted) = tx_meta.get(&txid).copied().unwrap_or((None, false));
            out.push(UnspentNote {
                vout,
                txid,
                value: u64::try_from(value).unwrap_or(0),
                mined_height,
                trusted,
                address: Some(address),
                pool: 0, // transparent
                generated,
            });
        }
    }
    Ok(out)
}

/// Every address the wallet has generated, encoded for the network (for
/// `listreceivedbyaddress` with `include_empty`). Includes the wallet's exposed transparent
/// receivers as base58 t-addresses (a no-op for zecd wallets, which never expose any).
pub fn all_addresses(network: ZNetwork, engine_dir: &Path, scope: AccountScope) -> Vec<String> {
    let Ok(db) = open_read(network, engine_dir) else {
        return Vec::new();
    };
    let Ok(ids) = scoped_account_ids(&db, scope) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for account in ids {
        if let Ok(list) = db.list_addresses(account) {
            out.extend(list.iter().map(|info| info.address().encode(&network)));
        }
        if let Ok(receivers) = db.get_transparent_receivers(account, false, false) {
            out.extend(receivers.keys().map(|t| t.encode(&network)));
        }
    }
    out
}

/// Whether `addr` is an address one of this wallet's accounts can produce - for
/// `getaddressinfo.ismine`.
///
/// Two layers, cheapest first:
///
/// 1. **Recorded-address match.** An exact hit against `list_addresses`: addresses the wallet
///    handed out and persisted, plus any recovered from a received note during a scan. No crypto,
///    no decode.
/// 2. **Cryptographic attribution.** Failing that, decode the address and ask the account's
///    Unified Incoming Viewing Key whether it derived any *shielded* receiver, via
///    [`UnifiedIncomingViewingKey::decrypt_diversifiers`]. For each receiver that recovers a
///    diversifier index it is one FF1 decrypt of the diversifier plus one address
///    re-derivation/`pk_d` comparison - O(1) per receiver, never an index search. This is what
///    recognizes an address the wallet *generated but never recorded*: e.g. one issued before a
///    stateless (or any) from-seed restore that was never funded, so the scan never re-added it
///    to the `addresses` table.
///
/// Both shielded pools zecd supports - Sapling and Orchard - are covered. A multi-receiver
/// Unified Address is attributed as ours **only when *every* shielded receiver is ours at one
/// diversifier index** (the [`UaReceivers::MineConsistent`] verdict), not when merely one
/// receiver matches: see the threat-model note in the body - a UA that pairs the wallet's
/// receiver with a stranger's would otherwise read `ismine: true` while a sender pays the
/// stranger. A single-receiver UA (and a bare Sapling address) is tested directly. A bare
/// transparent address the wallet handed out is recognized via the recorded-receiver fast path
/// (layer 1b, its `cached_transparent_receiver_address`); the cryptographic path never attributes
/// transparent receivers - an unrecorded one can't be attributed to a viewing key without a
/// gap-limit derivation scan (a funded one is re-recorded by the scan, so it then matches layer 1b).
/// A transparent receiver **inside a UA** is still disqualifying: zecd hands out transparent only as
/// a bare t-address, never mixed into a UA, so a UA that carries one can only be a splice (a
/// transparent-only sender would pay the attacker), rejected even when a shielded receiver alongside
/// it genuinely is the wallet's.
pub fn is_mine(network: ZNetwork, engine_dir: &Path, scope: AccountScope, addr: &str) -> bool {
    let Ok(db) = open_read(network, engine_dir) else {
        return false;
    };
    let Ok(ids) = scoped_account_ids(&db, scope) else {
        return false;
    };
    // Decode once for the crypto path; `None` (unparseable / wrong network) just skips it.
    let decoded = crate::address::decode_on_network(&network, addr);
    for account in ids {
        // (1) Recorded-address fast path.
        if let Ok(list) = db.list_addresses(account) {
            if list
                .iter()
                .any(|info| info.address().encode(&network) == addr)
            {
                return true;
            }
        }
        // (1b) Recorded transparent receiver: a bare t-address the wallet handed out (its
        // `cached_transparent_receiver_address`). The crypto path below can't attribute transparent
        // receivers, so this recorded match is how `getaddressinfo.ismine` recognizes own t-addrs.
        if let Ok(receivers) = db.get_transparent_receivers(account, false, false) {
            if receivers.keys().any(|t| t.encode(&network) == addr) {
                return true;
            }
        }
        // (2) Cryptographic attribution against the account's viewing key.
        let Some(decoded) = decoded.as_ref() else {
            continue;
        };
        let Ok(Some(acct)) = db.get_account(account) else {
            continue;
        };
        let Some(ufvk) = acct.ufvk() else {
            continue;
        };
        let uivk = ufvk.to_unified_incoming_viewing_key();
        let mine = match decoded {
            // THREAT MODEL - the "unexpected receiver" UA splice. A naive "any one receiver is
            // mine ⇒ the address is mine" rule lets an attacker hand the wallet a UA that pairs
            // *their* Orchard receiver with the victim's Sapling receiver: attribution says
            // "yours", but a ZIP-316 sender prefers Orchard and pays the attacker (and a
            // Sapling-only sender pays the attacker too if the foreign receiver sits in the only
            // pool it supports). Any foreign receiver is therefore disqualifying. So a UA with two
            // shielded receivers is ours ONLY when every receiver is ours at a single diversifier
            // index (`MineConsistent`) - never when it mixes in a stranger's receiver or staples
            // our own receivers from different indices. A UA with a single shielded receiver has
            // nothing to splice, so the plain viewing-key membership test stands (this is what
            // still recognizes a wallet-generated-but-unrecorded address after a restore).
            Address::Unified(ua) if ua.transparent().is_some() => {
                // A transparent receiver is itself a splice zecd can never have issued: zecd
                // receives only into shielded pools, so it never puts a transparent receiver in a
                // UA it hands out. An attacker can therefore staple *their* transparent receiver
                // onto the victim's Orchard/Sapling receiver - the shielded receiver is genuinely
                // the wallet's, but a transparent-only (or transparent-preferring) sender pays the
                // attacker. Since the count-shielded-receivers test below sees only one shielded
                // receiver, that UA would slip through the single-receiver membership check; so a
                // transparent receiver is unconditionally disqualifying here, exactly as a foreign
                // shielded receiver is in the two-shielded case.
                false
            }
            Address::Unified(ua) => {
                let two_shielded =
                    u8::from(ua.sapling().is_some()) + u8::from(ua.orchard().is_some()) >= 2;
                if two_shielded {
                    classify_receivers_with_ufvk(ufvk, ua) == UaReceivers::MineConsistent
                } else {
                    // decrypt_diversifiers runs Sapling decrypt_diversifier + Orchard
                    // diversifier_index; non-empty ⇒ the sole shielded receiver is ours.
                    !uivk.decrypt_diversifiers(ua).is_empty()
                }
            }
            // A bare Sapling address: the same membership test on the Sapling receiver alone.
            Address::Sapling(pa) => uivk
                .sapling()
                .as_ref()
                .and_then(|ivk| ivk.decrypt_diversifier(pa))
                .is_some(),
            // Transparent / TEX: intentionally unsupported (see the doc comment).
            Address::Transparent(_) | Address::Tex(_) => false,
        };
        if mine {
            return true;
        }
    }
    false
}

/// How a unified address's shielded receivers relate to *this wallet's* account key - the basis
/// for rejecting hand-spliced UAs (receivers stapled together from different diversifier indices,
/// or a mix of this wallet's receiver and a stranger's). A diversifier *index* is key-relative
/// (`FF1⁻¹(dk, d)` under the viewing key), so this is only computable against the wallet's own
/// keys; a UA whose receivers are all someone else's is simply [`UaReceivers::Foreign`].
#[derive(Debug, PartialEq, Eq)]
pub enum UaReceivers {
    /// Not a unified address, or a UA with at most one shielded receiver: nothing to cross-check
    /// (a single receiver cannot disagree with itself).
    NotApplicable,
    /// No shielded receiver derives from this wallet's account key(s).
    Foreign,
    /// Every shielded receiver derives from this wallet at the *same* (index, scope) - a
    /// well-formed address this wallet could itself have issued.
    MineConsistent,
    /// The receivers disagree: at least one belongs to this wallet and at least one does not, or
    /// they derive at *different* diversifier indices/scopes. A UA this wallet issued can never
    /// look like this, so it indicates receivers spliced together by hand.
    Inconsistent(String),
}

impl UaReceivers {
    /// An informational tri-state for inspection RPCs (`validateaddress`/`getaddressinfo`):
    /// `Some(true)` when every receiver is ours at one index, `Some(false)` when the receivers
    /// are spliced, and `None` when consistency is not computable/meaningful (a foreign UA - the
    /// index is the owner's secret - or a single-receiver address with nothing to cross-check).
    pub fn consistent_flag(&self) -> Option<bool> {
        match self {
            UaReceivers::MineConsistent => Some(true),
            UaReceivers::Inconsistent(_) => Some(false),
            UaReceivers::Foreign | UaReceivers::NotApplicable => None,
        }
    }
}

/// Recover an Orchard receiver's diversifier index (and scope) under a full viewing key, trying
/// both scopes. `None` if the receiver does not belong to the key.
fn orchard_receiver_index(
    fvk: &orchard::keys::FullViewingKey,
    addr: &orchard::Address,
) -> Option<(DiversifierIndex, Scope)> {
    [Scope::External, Scope::Internal]
        .into_iter()
        .find_map(|scope| {
            fvk.to_ivk(scope)
                .diversifier_index(addr)
                .map(|j| (j, scope))
        })
}

/// Classify a unified address's receivers against a single account's UFVK. Pure (no I/O) so it
/// can be unit-tested directly without a wallet DB.
fn classify_receivers_with_ufvk(ufvk: &UnifiedFullViewingKey, ua: &UnifiedAddress) -> UaReceivers {
    // For each present shielded receiver, recover its (index, scope) under this key. The outer
    // `Option` is presence; the inner is whether it belongs to this key.
    let recovered: [Option<Option<(DiversifierIndex, Scope)>>; 2] = [
        ua.sapling()
            .map(|a| ufvk.sapling().and_then(|dfvk| dfvk.decrypt_diversifier(a))),
        ua.orchard().map(|a| {
            ufvk.orchard()
                .and_then(|fvk| orchard_receiver_index(fvk, a))
        }),
    ];

    let mut resolved: Vec<(DiversifierIndex, Scope)> = Vec::new();
    let mut has_foreign_receiver = false;
    for slot in recovered.into_iter().flatten() {
        match slot {
            Some(found) => resolved.push(found),
            None => has_foreign_receiver = true,
        }
    }

    if resolved.is_empty() {
        return UaReceivers::Foreign; // none of the present receivers are ours
    }
    if has_foreign_receiver {
        return UaReceivers::Inconsistent(
            "unified address combines a receiver owned by this wallet with one that is not".into(),
        );
    }
    // Every present receiver resolved under this key; require a single (index, scope).
    let (first_idx, first_scope) = resolved[0];
    if resolved
        .iter()
        .all(|(j, s)| j.as_bytes() == first_idx.as_bytes() && *s == first_scope)
    {
        UaReceivers::MineConsistent
    } else {
        UaReceivers::Inconsistent(
            "unified address combines this wallet's receivers from different diversifier indices"
                .into(),
        )
    }
}

/// Classify a unified address's receivers against the wallet's own account key(s) - see
/// [`UaReceivers`]. Non-unified addresses and UAs carrying fewer than two shielded receivers are
/// [`UaReceivers::NotApplicable`]. Best-effort: storage errors degrade to `NotApplicable` rather
/// than erroring, so callers fall back to their existing (byte-exact) ownership checks.
pub fn classify_unified_receivers(
    network: ZNetwork,
    engine_dir: &Path,
    scope: AccountScope,
    addr: &str,
) -> UaReceivers {
    let Some(Address::Unified(ua)) = Address::decode(&network, addr) else {
        return UaReceivers::NotApplicable;
    };
    // Only meaningful when there are two shielded receivers to cross-check; zecd's shielded pools
    // are Sapling and Orchard, so that is exactly {sapling, orchard}.
    if u8::from(ua.sapling().is_some()) + u8::from(ua.orchard().is_some()) < 2 {
        return UaReceivers::NotApplicable;
    }
    let Ok(db) = open_read(network, engine_dir) else {
        return UaReceivers::NotApplicable;
    };
    let Ok(ids) = scoped_account_ids(&db, scope) else {
        return UaReceivers::NotApplicable;
    };
    // A shard database holds several wallets' accounts, so the scope decides which key the
    // receivers are checked against; within one wallet's accounts the first non-`Foreign`
    // verdict wins.
    for id in ids {
        let Ok(Some(account)) = db.get_account(id) else {
            continue;
        };
        let Some(ufvk) = account.ufvk() else {
            continue;
        };
        match classify_receivers_with_ufvk(ufvk, &ua) {
            UaReceivers::Foreign => {}
            other => return other,
        }
    }
    UaReceivers::Foreign
}

/// Where a transparent address the wallet owns sits in its BIP 44 derivation - the answer to
/// "which index did `getnewaddress "" "transparent"` just hand me?", which is otherwise
/// unanswerable (the RPC returns a bare string, and zecd persists no off-chain issuance log).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransparentDerivation {
    /// The ZIP 32 account index the address derives from, when the account records its
    /// derivation (`None` on a watch-only wallet imported from a UFVK, which has no seed path).
    pub account_index: Option<u32>,
    /// The BIP 44 change level: `0` external (receiving), `1` internal (change).
    pub scope: u32,
    /// The BIP 44 non-hardened child index within that scope.
    pub address_index: u32,
}

impl TransparentDerivation {
    /// Whether this is an internal (change) address - Bitcoin Core's `getaddressinfo.ischange`.
    pub fn is_change(&self) -> bool {
        self.scope != 0
    }

    /// The BIP 44 path, in Bitcoin Core's `getaddressinfo.hdkeypath` format
    /// (`m/44'/<coin_type>'/<account>'/<scope>/<index>`), or `None` when the account's own
    /// derivation is unknown so the path cannot be stated in full.
    pub fn hd_keypath(&self, network: ZNetwork) -> Option<String> {
        use zcash_protocol::consensus::NetworkConstants as _;
        let account = self.account_index?;
        let coin_type = network.coin_type();
        Some(format!(
            "m/44'/{coin_type}'/{account}'/{}/{}",
            self.scope, self.address_index
        ))
    }
}

/// The BIP 44 derivation of a transparent address this wallet owns, or `None` when the address
/// is not a transparent address, is not one of ours, or was imported without derivation metadata.
///
/// Covers both scopes: an external (receiving) address handed out by `getnewaddress` /
/// `z_getaddressforaccount`, and an internal one used for transparent change. Best-effort like
/// the other read helpers - storage errors degrade to `None`.
pub fn transparent_derivation(
    network: ZNetwork,
    engine_dir: &Path,
    scope: AccountScope,
    addr: &str,
) -> Option<TransparentDerivation> {
    let taddr = match Address::decode(&network, addr)? {
        Address::Transparent(t) => t,
        _ => return None,
    };
    let db = open_read(network, engine_dir).ok()?;
    for id in scoped_account_ids(&db, scope).ok()? {
        let Ok(Some(meta)) = db.get_transparent_address_metadata(id, &taddr) else {
            continue;
        };
        // `scope()`/`address_index()` are `None` for a standalone (imported-key) address, which
        // has no derivation path to report.
        let (Some(scope), Some(index)) = (meta.scope(), meta.address_index()) else {
            continue;
        };
        let Some(scope) = transparent_scope_index(scope) else {
            continue;
        };
        let account_index = db.get_account(id).ok().flatten().and_then(|a| {
            a.source()
                .key_derivation()
                .map(|d| d.account_index().into())
        });
        return Some(TransparentDerivation {
            account_index,
            scope,
            address_index: index.index(),
        });
    }
    None
}

/// The BIP 44 `change` path element for a transparent key scope: 0 external, 1 internal,
/// 2 ephemeral (ZIP-320). [`TransparentKeyScope`] exposes no accessor for its raw value, so the
/// standard scopes are mapped explicitly; a custom scope has no standard path element to report
/// and yields `None`.
fn transparent_scope_index(scope: TransparentKeyScope) -> Option<u32> {
    match scope {
        s if s == TransparentKeyScope::EXTERNAL => Some(0),
        s if s == TransparentKeyScope::INTERNAL => Some(1),
        s if s == TransparentKeyScope::EPHEMERAL => Some(2),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in for the columns [`tx_query_sql`] and [`LOAD_OUTPUTS_SQL`] read. The real
    /// `v_transactions`/`v_tx_outputs` are librustzcash views over a dozen tables, and
    /// materializing a wallet whose *views* yield a same-height txid tie means minting real
    /// notes; the ordering under test is a property of the query text alone, so the fixture
    /// supplies the view columns directly and the tests run the production SQL over it.
    fn ordering_fixture() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE v_transactions (
                 mined_height INTEGER, txid BLOB, expiry_height INTEGER,
                 account_balance_delta INTEGER, fee_paid INTEGER, block_time INTEGER,
                 expired_unmined BOOLEAN, tx_index INTEGER,
                 -- Read by the [`AccountScope`] predicate the production SQL carries; the
                 -- ordering tests bind `NULL` for it, which is the unscoped arm.
                 account_uuid BLOB
             );
             CREATE TABLE v_tx_outputs (
                 txid BLOB, output_pool INTEGER, output_index INTEGER,
                 from_account_uuid BLOB, to_account_uuid BLOB, to_address TEXT,
                 value INTEGER, is_change BOOLEAN, recipient_key_scope INTEGER, memo BLOB
             );
             CREATE TABLE blocks (height INTEGER, hash BLOB);
             CREATE TABLE transactions (txid BLOB, created TEXT);",
        )
        .unwrap();
        conn
    }

    /// Insert a transaction whose txid is `byte` repeated, at `mined_height`.
    fn put_tx(conn: &rusqlite::Connection, byte: u8, mined_height: Option<u32>) {
        conn.execute(
            "INSERT INTO v_transactions
                 (mined_height, txid, expiry_height, account_balance_delta, fee_paid,
                  block_time, expired_unmined, tx_index, account_uuid)
             VALUES (?1, ?2, 0, 0, NULL, NULL, 0, NULL, NULL)",
            rusqlite::params![mined_height, vec![byte; 32]],
        )
        .unwrap();
    }

    fn query_order(conn: &rusqlite::Connection, newest_first: bool) -> Vec<u8> {
        let mut stmt = conn.prepare(&tx_query_sql(newest_first)).unwrap();
        stmt.query_map(
            named_params! {
                ":start_height": None::<u32>,
                ":end_height": None::<u32>,
                ":scope_account": None::<Uuid>,
                ":limit": -1i64,
                ":offset": 0u32,
            },
            |row| Ok(row.get::<_, Vec<u8>>("txid")?[0]),
        )
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
    }

    /// Transactions sharing a `sort_height` must come back in a deterministic txid order, in
    /// both directions - the tie is what an incidental-order query leaves unpinned, and what
    /// makes a `LIMIT`/`OFFSET` page boundary inside the tie unstable.
    #[test]
    fn same_height_transactions_are_ordered_by_txid() {
        let conn = ordering_fixture();
        // Inserted in an order that matches neither ascending nor descending txid, so passing
        // cannot be an artifact of the fixture's insertion order.
        put_tx(&conn, 0x02, Some(100));
        put_tx(&conn, 0x03, Some(100));
        put_tx(&conn, 0x01, Some(100));

        assert_eq!(query_order(&conn, false), vec![0x01, 0x02, 0x03]);
        // `newest_first` reverses the height and txid keys together.
        assert_eq!(query_order(&conn, true), vec![0x03, 0x02, 0x01]);
    }

    /// The txid key is strictly *secondary*: height still decides, and unmined transactions
    /// keep their NULLS LAST / NULLS FIRST placement rather than sorting among mined ones.
    #[test]
    fn txid_tiebreak_does_not_disturb_height_ordering() {
        let conn = ordering_fixture();
        put_tx(&conn, 0xFF, Some(100));
        put_tx(&conn, 0x01, Some(200));
        put_tx(&conn, 0x05, None);

        assert_eq!(query_order(&conn, false), vec![0xFF, 0x01, 0x05]);
        assert_eq!(query_order(&conn, true), vec![0x05, 0x01, 0xFF]);
    }

    /// Pagination across a height tie must compose: consecutive `LIMIT 1` pages walking a
    /// three-way tie visit each transaction exactly once. Without the txid key each page is
    /// independently free to reorder the tie, so a row can repeat on one page and be skipped
    /// on the next - silent duplication/loss for a paginating consumer.
    #[test]
    fn pagination_across_a_height_tie_visits_each_transaction_once() {
        let conn = ordering_fixture();
        put_tx(&conn, 0x02, Some(100));
        put_tx(&conn, 0x03, Some(100));
        put_tx(&conn, 0x01, Some(100));

        let mut stmt = conn.prepare(&tx_query_sql(false)).unwrap();
        let mut seen = Vec::new();
        for offset in 0..3u32 {
            let page: Vec<u8> = stmt
                .query_map(
                    named_params! {
                        ":start_height": None::<u32>,
                        ":end_height": None::<u32>,
                        ":limit": 1i64,
                        ":offset": offset,
                    },
                    |row| Ok(row.get::<_, Vec<u8>>("txid")?[0]),
                )
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
            seen.extend(page);
        }
        assert_eq!(seen, vec![0x01, 0x02, 0x03]);
    }

    /// A transaction with outputs in more than one pool must come back ordered by
    /// `(output_pool, output_index)`. `output_index` is the index within the pool's bundle, so
    /// it is not unique across pools and cannot order the set on its own.
    #[test]
    fn outputs_are_ordered_by_pool_then_index() {
        let conn = ordering_fixture();
        let txid: Vec<u8> = vec![0x07; 32];
        for (pool, index) in [(4i64, 1u32), (2, 1), (4, 0), (2, 0)] {
            conn.execute(
                "INSERT INTO v_tx_outputs
                     (txid, output_pool, output_index, from_account_uuid, to_account_uuid,
                      to_address, value, is_change, recipient_key_scope, memo)
                 VALUES (?1, ?2, ?3, NULL, NULL, NULL, 0, 0, NULL, NULL)",
                rusqlite::params![txid, pool, index],
            )
            .unwrap();
        }

        let mut stmt = conn.prepare(LOAD_OUTPUTS_SQL).unwrap();
        let got: Vec<(i64, u32)> = stmt
            .query_map(
                named_params! {":txid": txid, ":scope_account": None::<Uuid>},
                |row| Ok((row.get("output_pool")?, row.get("output_index")?)),
            )
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(got, vec![(2, 0), (2, 1), (4, 0), (4, 1)]);
    }

    /// The `created_time` expression in [`super::TX_COLS`] must parse rusqlite's
    /// `OffsetDateTime` encoding (`yyyy-MM-dd HH:mm:ss.fffffffzzz`, what librustzcash stores
    /// in `transactions.created`), honoring the offset, and yield NULL for NULL input.
    #[test]
    fn sqlite_parses_created_timestamp_format() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let parse = |s: Option<&str>| -> Option<i64> {
            conn.query_row(
                "SELECT CAST(strftime('%s', ?1) AS INTEGER)",
                rusqlite::params![s],
                |r| r.get(0),
            )
            .unwrap()
        };
        assert_eq!(
            parse(Some("2026-06-11 09:31:53.1234567+00:00")),
            Some(1_781_170_313)
        );
        // A non-UTC offset is normalized to the same UTC epoch.
        assert_eq!(
            parse(Some("2026-06-11 09:31:53.1234567+02:00")),
            Some(1_781_163_113)
        );
        assert_eq!(parse(None), None);
    }

    /// The receiver-consistency classifier must accept a UA the wallet could itself issue (all
    /// receivers at one index), flag a UA spliced from receivers at *different* indices, and treat
    /// a UA built from a different key as foreign - so a hand-crafted address can't masquerade as
    /// the wallet's own across `getreceivedbyaddress`/`getaddressinfo`/`z_sendmany`.
    #[test]
    fn classify_receivers_detects_spliced_unified_address() {
        use zcash_keys::address::UnifiedAddress;
        use zcash_keys::keys::{ReceiverRequirement::*, UnifiedAddressRequest, UnifiedSpendingKey};
        use zcash_protocol::consensus::Network;
        use zip32::{AccountId, DiversifierIndex};

        let net = Network::MainNetwork;
        let account = AccountId::ZERO;
        // Two shielded receivers (Sapling + Orchard), no transparent.
        let request = UnifiedAddressRequest::unsafe_custom(Require, Require, Omit);

        let ufvk = UnifiedSpendingKey::from_seed(&net, &[7u8; 32], account)
            .unwrap()
            .to_unified_full_viewing_key();

        // Two of *our own* addresses at clearly different diversifier indices.
        let (ua_low, _) = ufvk.find_address(DiversifierIndex::new(), request).unwrap();
        let mut j = DiversifierIndex::new();
        for _ in 0..5000 {
            j.increment().unwrap();
        }
        let (ua_high, _) = ufvk.find_address(j, request).unwrap();
        assert_ne!(
            ua_low.encode(&net),
            ua_high.encode(&net),
            "the two indices must yield distinct addresses"
        );

        // A legitimately-issued address: every receiver at one index.
        assert_eq!(
            classify_receivers_with_ufvk(&ufvk, &ua_low),
            UaReceivers::MineConsistent
        );

        // Splice: our Sapling receiver from one index with our Orchard receiver from another.
        let spliced = UnifiedAddress::from_receivers(
            ua_high.orchard().cloned(),
            ua_low.sapling().cloned(),
            None,
        )
        .unwrap();
        assert!(
            matches!(
                classify_receivers_with_ufvk(&ufvk, &spliced),
                UaReceivers::Inconsistent(_)
            ),
            "receivers from different indices must be Inconsistent"
        );

        // Mix our Orchard receiver with a *stranger's* Sapling receiver.
        let other = UnifiedSpendingKey::from_seed(&net, &[9u8; 32], account)
            .unwrap()
            .to_unified_full_viewing_key();
        let (other_ua, _) = other
            .find_address(DiversifierIndex::new(), request)
            .unwrap();
        let mixed = UnifiedAddress::from_receivers(
            ua_low.orchard().cloned(),
            other_ua.sapling().cloned(),
            None,
        )
        .unwrap();
        assert!(
            matches!(
                classify_receivers_with_ufvk(&ufvk, &mixed),
                UaReceivers::Inconsistent(_)
            ),
            "one of our receivers mixed with a stranger's must be Inconsistent"
        );

        // A UA entirely from a different key is foreign, not an error.
        assert_eq!(
            classify_receivers_with_ufvk(&ufvk, &other_ua),
            UaReceivers::Foreign
        );
    }

    /// [`super::tx_unexpired_sql`] must reproduce librustzcash's `tx_unexpired_condition` across
    /// every branch: a mined tx (never "expired"), the never-expires (`expiry_height = 0`) case,
    /// expiry at/after vs strictly before the target, and the unknown-expiry staleness window
    /// (`min_observed_height + DEFAULT_TX_EXPIRY_DELTA`). This is the canonical spentness/expiry
    /// rule that our `listunspent minconf=0` supplement and `unmined_raw_txs` share with the
    /// selector and balances; this test pins the exact semantics (including the staleness branch
    /// our earlier hand-rolled copies dropped) so a `zcash_client_sqlite` bump that changes the
    /// rule is caught here. Thresholds are derived from `DEFAULT_TX_EXPIRY_DELTA` so the test
    /// tracks upstream if the constant moves.
    #[test]
    fn tx_unexpired_sql_matches_upstream_branches() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE tx(mined_height INTEGER, expiry_height INTEGER,
                             min_observed_height INTEGER NOT NULL);",
        )
        .unwrap();
        let pred = super::tx_unexpired_sql("tx");
        let target: i64 = 100;
        let delta = i64::from(super::DEFAULT_TX_EXPIRY_DELTA);
        // (mined_height, expiry_height, min_observed_height) -> expected "unexpired".
        let cases: &[(Option<i64>, Option<i64>, i64, bool)] = &[
            (Some(50), Some(80), 50, true), // mined (mined < target): never treated as expired
            (None, Some(0), 50, true),      // expiry 0 => never expires
            (None, Some(target), 50, true), // expiry == target => unexpired
            (None, Some(target + 5), 50, true), // expiry > target => unexpired
            (None, Some(target - 1), 50, false), // expiry < target => expired
            (None, None, target - delta, true), // unknown expiry, boundary: mo + delta == target
            (None, None, target - delta + 1, true), // unknown expiry, recently observed
            (None, None, target - delta - 1, false), // unknown expiry, stale => expired
        ];
        for (i, (m, e, mo, expected)) in cases.iter().enumerate() {
            conn.execute("DELETE FROM tx", []).unwrap();
            conn.execute(
                "INSERT INTO tx(mined_height, expiry_height, min_observed_height)
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![m, e, mo],
            )
            .unwrap();
            let got: bool = conn
                .query_row(
                    &format!("SELECT EXISTS(SELECT 1 FROM tx WHERE {pred})"),
                    rusqlite::named_params! { ":target_height": target },
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(got, *expected, "case {i}: ({m:?}, {e:?}, {mo})");
        }
    }

    /// The immature/mature coinbase split must partition unspent coinbase value exactly at the
    /// `COINBASE_MATURITY` boundary (`target_height - mined_height >= 100` is mature), default
    /// an unknown `tx_index` to non-coinbase, and suppress spent outputs - the invariants the
    /// balance reclassification, the `getbalances.mine.coinbase` extension, and the actor's
    /// `-6` hint all ride on.
    #[test]
    fn coinbase_zats_splits_on_the_maturity_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let conn =
            rusqlite::Connection::open(crate::wallet::open::data_db_path(dir.path())).unwrap();
        // The minimal slice of the zcash_client_sqlite schema the query touches.
        conn.execute_batch(
            "CREATE TABLE transactions(
                 id_tx INTEGER PRIMARY KEY,
                 mined_height INTEGER,
                 tx_index INTEGER,
                 expiry_height INTEGER,
                 min_observed_height INTEGER);
             CREATE TABLE transparent_received_outputs(
                 id INTEGER PRIMARY KEY,
                 transaction_id INTEGER,
                 account_id INTEGER,
                 value_zat INTEGER);
             CREATE TABLE transparent_received_output_spends(
                 transparent_received_output_id INTEGER,
                 transaction_id INTEGER);
             CREATE TABLE accounts(id INTEGER PRIMARY KEY, uuid BLOB NOT NULL);",
        )
        .unwrap();
        let target: u32 = 200;
        // (id, mined_height, tx_index, value): a coinbase exactly at the boundary (mature), one
        // confirmation short of it (immature), a non-coinbase, an unknown-index tx (defaults to
        // non-coinbase), an unmined coinbase (ignored), and a spent mature coinbase (suppressed).
        let m = i64::from(target) - i64::from(super::COINBASE_MATURITY);
        let rows: &[(i64, Option<i64>, Option<i64>, i64)] = &[
            (1, Some(m), Some(0), 1_000),      // mature: conf == COINBASE_MATURITY
            (2, Some(m + 1), Some(0), 200),    // immature: one short
            (3, Some(1), Some(1), 40_000),     // non-coinbase: never counted
            (4, Some(1), None, 5_000),         // unknown tx_index: defaults to non-coinbase
            (5, None, Some(0), 600_000),       // unmined: never counted
            (6, Some(m - 50), Some(0), 7_000), // mature but spent below: suppressed
        ];
        for (id, mined, tx_index, value) in rows {
            conn.execute(
                "INSERT INTO transactions(id_tx, mined_height, tx_index, expiry_height,
                                          min_observed_height)
                 VALUES (?1, ?2, ?3, 0, 1)",
                rusqlite::params![id, mined, tx_index],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO transparent_received_outputs(id, transaction_id, account_id,
                                                          value_zat)
                 VALUES (?1, ?1, 1, ?2)",
                rusqlite::params![id, value],
            )
            .unwrap();
        }
        // A second account in the same database - a fleet shard's shape - holding its own mature
        // coinbase. Nothing about it may show up in the first account's totals.
        conn.execute(
            "INSERT INTO transactions(id_tx, mined_height, tx_index, expiry_height,
                                      min_observed_height)
             VALUES (7, ?1, 0, 0, 1)",
            rusqlite::params![m],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO transparent_received_outputs(id, transaction_id, account_id, value_zat)
             VALUES (7, 7, 2, 9_000_000)",
            [],
        )
        .unwrap();
        let (account_a, account_b) = (uuid::Uuid::from_u128(0xaa), uuid::Uuid::from_u128(0xbb));
        conn.execute(
            "INSERT INTO accounts(id, uuid) VALUES (1, ?1), (2, ?2)",
            rusqlite::params![account_a, account_b],
        )
        .unwrap();
        // Spend output 6 with a mined (live) tx, so it is suppressed from both sides.
        conn.execute(
            "INSERT INTO transactions(id_tx, mined_height, tx_index, expiry_height,
                                      min_observed_height)
             VALUES (100, ?1, 1, 0, 1)",
            rusqlite::params![m - 40],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO transparent_received_output_spends(transparent_received_output_id,
                                                            transaction_id)
             VALUES (6, 100)",
            [],
        )
        .unwrap();
        drop(conn);

        let only_a = AccountScope::Only(AccountUuid::from_uuid(account_a));
        let only_b = AccountScope::Only(AccountUuid::from_uuid(account_b));
        assert_eq!(
            super::mature_coinbase_zats(dir.path(), only_a, target).unwrap(),
            1_000,
            "mature = the boundary coinbase only (spent one suppressed)"
        );
        assert_eq!(
            super::immature_coinbase_zats(dir.path(), only_a, target).unwrap(),
            200,
            "immature = the one-short coinbase only"
        );
        // The scope is what keeps a shard's wallets apart: account B's 9M-zat coinbase must not
        // reach account A's total, and vice versa.
        assert_eq!(
            super::mature_coinbase_zats(dir.path(), only_b, target).unwrap(),
            9_000_000,
            "account B sees its own coinbase and none of A's"
        );
        // Unscoped is the pre-fleet behaviour: everything the database holds.
        assert_eq!(
            super::mature_coinbase_zats(dir.path(), AccountScope::Any, target).unwrap(),
            9_001_000,
            "AccountScope::Any sums every account, as it always did"
        );
    }

    /// The rebroadcast set must include a transaction that spends an **ironwood** note.
    ///
    /// Post-NU6.3 a wallet's shielded funds are ironwood notes, and a spend of one is recorded in
    /// `ironwood_received_note_spends` - a different table from the orchard one. While the
    /// ownership test in [`super::unmined_raw_txs_sql`] listed only sapling/orchard/transparent,
    /// every post-NU6.3 send was silently excluded from the rebroadcast set: a send whose
    /// broadcast failed was never retransmitted and sat unmined until it expired. Regtest caught
    /// it as an outage-recovery send that never confirmed.
    ///
    /// Runs the real query against a minimal schema, so it fails if the ironwood arm is dropped.
    #[test]
    fn rebroadcast_set_includes_ironwood_spends() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE transactions (
                 id_tx INTEGER PRIMARY KEY, txid BLOB, raw BLOB,
                 mined_height INTEGER, expiry_height INTEGER, min_observed_height INTEGER
             );
             CREATE TABLE sapling_received_note_spends (transaction_id INTEGER);
             CREATE TABLE orchard_received_note_spends (transaction_id INTEGER);
             CREATE TABLE ironwood_received_note_spends (transaction_id INTEGER);
             CREATE TABLE transparent_received_output_spends (transaction_id INTEGER);
             -- An unmined, unexpired transaction that spends one ironwood note and nothing else.
             INSERT INTO transactions (id_tx, txid, raw, mined_height, expiry_height)
                 VALUES (1, X'0011', X'beef', NULL, 500);
             INSERT INTO ironwood_received_note_spends (transaction_id) VALUES (1);",
        )
        .unwrap();

        let mut stmt = conn.prepare(&super::unmined_raw_txs_sql()).unwrap();
        let rows: Vec<Vec<u8>> = stmt
            .query_map(rusqlite::named_params! { ":target_height": 100u32 }, |r| {
                r.get::<_, Vec<u8>>(1)
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(
            rows,
            vec![vec![0xbeu8, 0xef]],
            "an ironwood-spending tx is a rebroadcast candidate; without the ironwood arm in the \
             ownership test it is silently dropped and the send is never retried"
        );
    }
}
