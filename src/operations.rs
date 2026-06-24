//! In-memory registry of asynchronous RPC operations (zcashd-style `z_*` async ops),
//! scoped to the send-many flow.
//!
//! Ported from Zallet's `asyncop.rs`, adapted to zecd's [`RpcError`], `std::sync::Mutex`
//! (every critical section is a short, non-`.await` map/struct update, mirroring
//! [`crate::state::ActiveCommands`]), and `tokio::spawn`. Operations are transient and held
//! only in memory - like zcashd's - so they are lost on restart. A send that was already
//! committed to the wallet DB still broadcasts via the rebroadcast loop even if its operation
//! status is gone.
//!
//! Each operation is tagged with the owning wallet, so the tracking RPCs
//! (`z_getoperationstatus` / `z_getoperationresult` / `z_listoperationids`) only ever observe
//! the operations of the wallet they are called on - preserving zecd's multiwallet isolation.
//!
//! ## Lifecycle, reaping, and the two caps (read before changing the limits)
//!
//! `z_getoperationresult` is **destructive and one-shot**, exactly as in zcashd/Zallet: it
//! returns each finished operation's status *once* and removes it. After that the result is
//! gone - a second `z_getoperationresult` for the same opid returns nothing. Use
//! `z_getoperationstatus` (non-destructive) to poll without consuming. Reaping is the client's
//! responsibility, but it is an **optimization, not a requirement**: a client that never reaps
//! cannot wedge the daemon, because of how the two caps are arranged.
//!
//! - [`MAX_OPERATIONS`] bounds *retained* operations. Past it, the oldest **finished** results
//!   are auto-evicted (oldest-first). So unreaped finished results are reclaimed automatically;
//!   the only consequence of never reaping is that old results may be discarded before they are
//!   read (the underlying transactions still broadcast - only the status object is lost). When
//!   this happens it is logged at WARN so an operator notices a runaway unreaped backlog.
//! - [`MAX_INFLIGHT_OPERATIONS_PER_WALLET`] bounds a wallet's **unfinished** (queued + executing)
//!   operations. An in-flight operation owns a real pending send and *cannot* be evicted, so once
//!   a wallet hits this cap new `z_sendmany` calls are rejected with `-4` (back-pressure) until
//!   some finish. Reaping does not affect this cap (finished ops never count toward it).

use std::collections::HashMap;
use std::future::Future;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Serialize, Serializer};
use serde_json::Value;
use uuid::Uuid;

use crate::error::RpcError;

/// Cap on retained operations. On overflow the oldest *finished* operations are evicted, so a
/// client that fires `z_sendmany` and never reaps results cannot grow the registry without
/// bound. A queued or executing operation is never evicted (its result is still pending).
const MAX_OPERATIONS: usize = 1024;

/// Cap on a single wallet's *unfinished* (queued + executing) operations. Unlike a finished
/// operation, an in-flight one cannot be evicted - it owns a pending send (a spawned task, the
/// `TransactionRequest`, and a slot contending for the single-writer actor's channel). So the
/// only safe response to a flood is back-pressure: reject the new operation rather than let an
/// authenticated client grow unfinished work without bound (memory + tasks + actor backlog).
/// The bound is per-wallet so one wallet's burst can't starve another's. Generous versus any
/// legitimate concurrency - sends are serialized by the actor regardless, so a handful in flight
/// is already the practical ceiling.
const MAX_INFLIGHT_OPERATIONS_PER_WALLET: usize = 16;

/// An async operation ID: `opid-{uuid-v4}` (identical to zcashd/Zallet).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OperationId(String);

impl OperationId {
    fn new() -> Self {
        Self(format!("opid-{}", Uuid::new_v4()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for OperationId {
    type Err = RpcError;

    /// Parse and validate an opid string. A malformed id is `-8`, matching Zallet's
    /// `InvalidParameter` - the tracking RPCs reject malformed ids rather than silently
    /// ignoring them (a *well-formed but unknown* id is silently skipped instead).
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let uuid = value
            .strip_prefix("opid-")
            .ok_or_else(|| RpcError::invalid_parameter("Invalid operation ID"))?;
        Uuid::try_parse(uuid).map_err(|_| RpcError::invalid_parameter("Invalid operation ID"))?;
        Ok(Self(value.to_string()))
    }
}

/// The lifecycle states of an async operation. Serializes to the exact zcashd strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationState {
    Ready,
    Executing,
    Cancelled,
    Failed,
    Success,
}

impl OperationState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "queued",
            Self::Executing => "executing",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
            Self::Success => "success",
        }
    }

    /// A finished operation: eligible for `z_getoperationresult` reaping and cap eviction.
    fn is_finished(self) -> bool {
        matches!(self, Self::Cancelled | Self::Failed | Self::Success)
    }
}

impl Serialize for OperationState {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

/// Optional method/params context echoed back in the status object (zcashd's `method`/`params`).
pub struct ContextInfo {
    method: &'static str,
    params: Value,
}

impl ContextInfo {
    pub fn new(method: &'static str, params: Value) -> Self {
        Self { method, params }
    }
}

/// The mutable state of an async operation, updated by the background task.
struct OperationData {
    state: OperationState,
    start_time: Option<SystemTime>,
    end_time: Option<SystemTime>,
    result: Option<Result<Value, RpcError>>,
}

/// An async operation launched by an RPC call.
pub struct AsyncOperation {
    operation_id: OperationId,
    context: Option<ContextInfo>,
    creation_time: SystemTime,
    data: Arc<Mutex<OperationData>>,
}

impl AsyncOperation {
    /// Launch a new async operation: spawns a detached task that drives `f`
    /// Ready → Executing → Success/Failed, recording start/end time and the result.
    pub fn new<T, F>(context: Option<ContextInfo>, f: F) -> Self
    where
        T: Serialize + Send + 'static,
        F: Future<Output = Result<T, RpcError>> + Send + 'static,
    {
        let creation_time = SystemTime::now();
        let data = Arc::new(Mutex::new(OperationData {
            state: OperationState::Ready,
            start_time: None,
            end_time: None,
            result: None,
        }));

        let handle = data.clone();
        tokio::spawn(async move {
            // Transition to Executing. The guard is dropped before `.await` below (a
            // `std::sync::MutexGuard` is `!Send`), keeping the spawned future `Send`.
            {
                let mut d = handle.lock().expect("operation lock poisoned");
                if matches!(d.state, OperationState::Cancelled) {
                    return;
                }
                d.state = OperationState::Executing;
                d.start_time = Some(SystemTime::now());
            }

            let res = f.await;
            let end_time = SystemTime::now();

            // Map the typed value into JSON without holding the lock across serialization.
            let res = res.map(|ret| {
                serde_json::to_value(&ret)
                    .expect("async return values should be serializable to JSON")
            });

            let mut d = handle.lock().expect("operation lock poisoned");
            d.state = if res.is_ok() {
                OperationState::Success
            } else {
                OperationState::Failed
            };
            d.end_time = Some(end_time);
            d.result = Some(res);
        });

        Self {
            operation_id: OperationId::new(),
            context,
            creation_time,
            data,
        }
    }

    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    fn state(&self) -> OperationState {
        self.data.lock().expect("operation lock poisoned").state
    }

    /// Build the current status object (the JSON element returned by `z_getoperationstatus`).
    fn to_status(&self) -> OperationStatus {
        let d = self.data.lock().expect("operation lock poisoned");

        let (method, params) = match &self.context {
            Some(ctx) => (Some(ctx.method), Some(ctx.params.clone())),
            None => (None, None),
        };

        let creation_time = self
            .creation_time
            .duration_since(UNIX_EPOCH)
            .map(|x| x.as_secs())
            .unwrap_or(0);

        let (error, result, execution_secs) = match &d.result {
            None => (None, None, None),
            Some(Err(e)) => (
                Some(OperationError {
                    code: e.code,
                    message: e.message.clone(),
                }),
                None,
                None,
            ),
            Some(Ok(v)) => (
                None,
                Some(v.clone()),
                d.end_time.zip(d.start_time).map(|(end, start)| {
                    end.duration_since(start).map(|x| x.as_secs()).unwrap_or(0)
                }),
            ),
        };

        OperationStatus {
            id: self.operation_id.0.clone(),
            method,
            params,
            status: d.state,
            creation_time,
            error,
            result,
            execution_secs,
        }
    }
}

/// The status of an async operation, serialized to the zcashd-shaped JSON object.
#[derive(Debug, Serialize)]
pub struct OperationStatus {
    id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<&'static str>,

    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<Value>,

    status: OperationState,

    /// Creation time, in seconds since the Unix epoch.
    creation_time: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<OperationError>,

    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,

    /// Wall-clock execution time of a successful operation, in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    execution_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
struct OperationError {
    code: i32,
    message: String,
}

/// A registry entry: an operation plus the wallet that owns it.
struct OperationEntry {
    wallet: String,
    op: AsyncOperation,
}

/// An in-memory, wallet-scoped registry of async operations. Shared via `AppState` behind an
/// `Arc`; cloning shares the one registry so every handler sees the same operations.
#[derive(Clone, Default)]
pub struct OperationRegistry {
    inner: Arc<Mutex<HashMap<OperationId, OperationEntry>>>,
}

impl OperationRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Launch an operation for `wallet` and insert it, subject to the per-wallet in-flight cap.
    ///
    /// The cap check, the spawn, and the insert all happen under one lock acquisition, so
    /// concurrent `z_sendmany` calls can't race past the limit. When the wallet already has
    /// [`MAX_INFLIGHT_OPERATIONS_PER_WALLET`] unfinished operations the new one is **not**
    /// spawned and an `-4` error is returned - back-pressure, since an in-flight operation owns
    /// a real pending send and cannot be safely discarded. Finished operations never count
    /// toward this cap (they are reaped on `z_getoperationresult` and auto-evicted past
    /// [`MAX_OPERATIONS`]), so a client that simply forgets to reap results is never blocked.
    pub fn try_insert<T, F>(
        &self,
        wallet: &str,
        context: Option<ContextInfo>,
        f: F,
    ) -> Result<String, RpcError>
    where
        T: Serialize + Send + 'static,
        F: Future<Output = Result<T, RpcError>> + Send + 'static,
    {
        let mut map = self.inner.lock().expect("operation registry poisoned");

        let inflight = map
            .values()
            .filter(|e| e.wallet == wallet && !e.op.state().is_finished())
            .count();
        if inflight >= MAX_INFLIGHT_OPERATIONS_PER_WALLET {
            tracing::warn!(
                wallet,
                inflight,
                cap = MAX_INFLIGHT_OPERATIONS_PER_WALLET,
                "rejecting z_sendmany: too many unfinished async operations in flight (the \
                 wallet actor may be backed up or the upstream may be unreachable)"
            );
            return Err(RpcError::wallet(format!(
                "Too many operations already in progress ({inflight}); the limit is \
                 {MAX_INFLIGHT_OPERATIONS_PER_WALLET}. Wait for in-flight operations to finish \
                 before starting another."
            )));
        }

        // Spawn only now that capacity is confirmed; `AsyncOperation::new` starts the task but
        // `tokio::spawn` does not await, so doing it under the std `Mutex` is fine.
        let op = AsyncOperation::new(context, f);
        Ok(Self::insert_op(&mut map, wallet, op))
    }

    /// Raw insertion: record `op` under `wallet` and evict finished overflow. Shared by
    /// [`Self::try_insert`] and the tests; does **not** enforce the in-flight cap.
    fn insert_op(
        map: &mut HashMap<OperationId, OperationEntry>,
        wallet: &str,
        op: AsyncOperation,
    ) -> String {
        let id = op.operation_id().clone();
        let opid = id.0.clone();
        map.insert(
            id,
            OperationEntry {
                wallet: wallet.to_string(),
                op,
            },
        );
        Self::evict_if_over_cap(map);
        opid
    }

    /// Status objects for this wallet's operations. `ids == None` returns all of the wallet's
    /// operations; otherwise only the listed ones. Unknown / wrong-wallet ids are silently
    /// skipped (zcashd behavior). Sorted by creation time ascending. Non-destructive.
    pub fn status(&self, wallet: &str, ids: Option<&[OperationId]>) -> Vec<OperationStatus> {
        let map = self.inner.lock().expect("operation registry poisoned");
        Self::collect(&map, wallet, ids, |_| true)
    }

    /// Finished operations (success/failed/cancelled) for this wallet, returned as status
    /// objects AND removed from the registry. `ids == None` reaps all of the wallet's finished
    /// operations. Sorted by creation time ascending.
    pub fn take_results(&self, wallet: &str, ids: Option<&[OperationId]>) -> Vec<OperationStatus> {
        let mut map = self.inner.lock().expect("operation registry poisoned");
        let statuses = Self::collect(&map, wallet, ids, |op| op.state().is_finished());
        let returned: std::collections::HashSet<&str> =
            statuses.iter().map(|s| s.id.as_str()).collect();
        map.retain(|id, _| !returned.contains(id.0.as_str()));
        statuses
    }

    /// All opid strings for this wallet, optionally filtered by state string. An unrecognized
    /// filter yields an empty list - it never equals any state string, matching zcashd's
    /// `z_listoperationids`. Sorted by creation time ascending.
    pub fn list_ids(&self, wallet: &str, status_filter: Option<&str>) -> Vec<String> {
        let map = self.inner.lock().expect("operation registry poisoned");
        let mut out: Vec<(SystemTime, String)> = map
            .values()
            .filter(|e| e.wallet == wallet)
            .filter(|e| match status_filter {
                None => true,
                Some(f) => e.op.state().as_str() == f,
            })
            .map(|e| (e.op.creation_time, e.op.operation_id.0.clone()))
            .collect();
        out.sort_by_key(|(t, _)| *t);
        out.into_iter().map(|(_, id)| id).collect()
    }

    fn collect(
        map: &HashMap<OperationId, OperationEntry>,
        wallet: &str,
        ids: Option<&[OperationId]>,
        extra: impl Fn(&AsyncOperation) -> bool,
    ) -> Vec<OperationStatus> {
        let mut statuses: Vec<(SystemTime, OperationStatus)> = map
            .values()
            .filter(|e| e.wallet == wallet)
            .filter(|e| match ids {
                None => true,
                Some(ids) => ids.contains(e.op.operation_id()),
            })
            .filter(|e| extra(&e.op))
            .map(|e| (e.op.creation_time, e.op.to_status()))
            .collect();
        statuses.sort_by_key(|(t, _)| *t);
        statuses.into_iter().map(|(_, s)| s).collect()
    }

    /// Evict the oldest finished operations once the map exceeds [`MAX_OPERATIONS`]. Never
    /// evicts a queued or executing operation.
    fn evict_if_over_cap(map: &mut HashMap<OperationId, OperationEntry>) {
        if map.len() <= MAX_OPERATIONS {
            return;
        }
        let mut finished: Vec<(SystemTime, OperationId)> = map
            .iter()
            .filter(|(_, e)| e.op.state().is_finished())
            .map(|(id, e)| (e.op.creation_time, id.clone()))
            .collect();
        finished.sort_by_key(|(t, _)| *t);
        let excess = map.len() - MAX_OPERATIONS;
        let mut evicted = 0;
        for (_, id) in finished.into_iter().take(excess) {
            map.remove(&id);
            evicted += 1;
        }
        if evicted > 0 {
            // These are finished results the client never read with z_getoperationresult; they
            // are gone now. The transactions themselves still broadcast (see the module docs) -
            // only the status objects are discarded - but loudly flag the unreaped backlog.
            tracing::warn!(
                evicted,
                retained = MAX_OPERATIONS,
                "evicting unreaped finished async operations to stay under the cap; reap results \
                 with z_getoperationresult to avoid silently discarding them"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    impl OperationRegistry {
        /// Insert a pre-built operation directly, bypassing the in-flight cap. Lets the tests
        /// seed the registry with synchronously-constructed (non-spawning) operations in a
        /// chosen state. Production code goes through [`OperationRegistry::try_insert`].
        fn insert(&self, wallet: &str, op: AsyncOperation) -> String {
            let mut map = self.inner.lock().expect("operation registry poisoned");
            Self::insert_op(&mut map, wallet, op)
        }
    }

    impl AsyncOperation {
        /// Build an already-finished operation synchronously (no spawn) so the registry's
        /// logic can be tested deterministically, without racing a background task.
        fn finished(context: Option<ContextInfo>, result: Result<Value, RpcError>) -> Self {
            let now = SystemTime::now();
            let state = if result.is_ok() {
                OperationState::Success
            } else {
                OperationState::Failed
            };
            Self {
                operation_id: OperationId::new(),
                context,
                creation_time: now,
                data: Arc::new(Mutex::new(OperationData {
                    state,
                    start_time: Some(now),
                    end_time: Some(now),
                    result: Some(result),
                })),
            }
        }

        /// Build an operation still in the `Ready` (queued) state with no result, for testing
        /// eviction's protection of in-flight operations without spawning a task.
        fn pending() -> Self {
            let now = SystemTime::now();
            Self {
                operation_id: OperationId::new(),
                context: None,
                creation_time: now,
                data: Arc::new(Mutex::new(OperationData {
                    state: OperationState::Ready,
                    start_time: None,
                    end_time: None,
                    result: None,
                })),
            }
        }
    }

    #[test]
    fn opid_parsing_validates_format() {
        let good = OperationId::new();
        assert!(good.as_str().starts_with("opid-"));
        // Round-trips.
        assert_eq!(good.as_str().parse::<OperationId>().unwrap(), good);
        // Missing prefix and a non-UUID body are both -8.
        for bad in ["not-an-opid", "opid-notauuid", ""] {
            let err = bad.parse::<OperationId>().unwrap_err();
            assert_eq!(err.code, crate::error::codes::RPC_INVALID_PARAMETER);
        }
    }

    #[test]
    fn status_then_take_results_removes() {
        let reg = OperationRegistry::new();
        let opid = reg.insert(
            "w",
            AsyncOperation::finished(None, Ok(json!({"txid": "ab"}))),
        );

        // Non-destructive status sees it.
        let st = reg.status("w", None);
        assert_eq!(st.len(), 1);
        assert_eq!(st[0].id, opid);
        assert_eq!(st[0].status.as_str(), "success");
        assert_eq!(st[0].result, Some(json!({"txid": "ab"})));

        // take_results returns the finished op once and removes it.
        let res = reg.take_results("w", None);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].id, opid);
        assert!(reg.status("w", None).is_empty());
        assert!(reg.take_results("w", None).is_empty());
    }

    #[test]
    fn operations_are_wallet_scoped() {
        let reg = OperationRegistry::new();
        let a = reg.insert("a", AsyncOperation::finished(None, Ok(json!(1))));
        let b = reg.insert("b", AsyncOperation::finished(None, Ok(json!(2))));

        assert_eq!(reg.list_ids("a", None), vec![a.clone()]);
        assert_eq!(reg.list_ids("b", None), vec![b]);

        // Wallet "a" cannot observe wallet "b"'s op even when naming its id explicitly.
        let b_id: OperationId = reg.list_ids("b", None)[0].parse().unwrap();
        assert!(reg.status("a", Some(&[b_id])).is_empty());
        assert_eq!(reg.status("a", None).len(), 1);
        assert_eq!(reg.status("a", None)[0].id, a);
    }

    #[test]
    fn list_ids_filters_by_status() {
        let reg = OperationRegistry::new();
        let ok = reg.insert("w", AsyncOperation::finished(None, Ok(json!(1))));
        reg.insert(
            "w",
            AsyncOperation::finished(None, Err(RpcError::insufficient_funds("nope"))),
        );

        assert_eq!(reg.list_ids("w", Some("success")), vec![ok]);
        assert_eq!(reg.list_ids("w", Some("failed")).len(), 1);
        assert!(reg.list_ids("w", Some("queued")).is_empty());
        // An unrecognized filter matches nothing.
        assert!(reg.list_ids("w", Some("bogus")).is_empty());
        // No filter returns both.
        assert_eq!(reg.list_ids("w", None).len(), 2);
    }

    #[test]
    fn failed_op_serializes_error_not_result() {
        let reg = OperationRegistry::new();
        reg.insert(
            "w",
            AsyncOperation::finished(None, Err(RpcError::insufficient_funds("broke"))),
        );
        let st = reg.status("w", None);
        let v = serde_json::to_value(&st[0]).unwrap();
        assert_eq!(v["status"], "failed");
        assert_eq!(
            v["error"]["code"],
            crate::error::codes::RPC_WALLET_INSUFFICIENT_FUNDS
        );
        assert_eq!(v["error"]["message"], "broke");
        assert!(v.get("result").is_none(), "no result on a failed op");
        assert!(v.get("execution_secs").is_none());
    }

    #[test]
    fn eviction_caps_finished_and_protects_pending() {
        let reg = OperationRegistry::new();
        // Two in-flight (queued) ops, then a full cap's worth of finished ops.
        reg.insert("w", AsyncOperation::pending());
        reg.insert("w", AsyncOperation::pending());
        for _ in 0..MAX_OPERATIONS {
            reg.insert("w", AsyncOperation::finished(None, Ok(json!(1))));
        }
        // Eviction pins the registry at the cap, dropping only the oldest *finished* ops...
        assert_eq!(reg.list_ids("w", None).len(), MAX_OPERATIONS);
        // ...and never evicts a queued op, even though they are the oldest entries.
        assert_eq!(reg.list_ids("w", Some("queued")).len(), 2);
    }

    #[test]
    fn eviction_never_drops_unfinished_even_over_cap() {
        let reg = OperationRegistry::new();
        for _ in 0..(MAX_OPERATIONS + 5) {
            reg.insert("w", AsyncOperation::pending());
        }
        // Nothing is finished, so the soft cap can evict nothing - every op survives.
        assert_eq!(reg.list_ids("w", None).len(), MAX_OPERATIONS + 5);
    }

    #[tokio::test]
    async fn inflight_cap_rejects_over_limit_and_is_per_wallet() {
        let reg = OperationRegistry::new();

        // Fill the wallet to its in-flight cap with operations that never complete.
        for _ in 0..MAX_INFLIGHT_OPERATIONS_PER_WALLET {
            let opid = reg
                .try_insert("w", None, std::future::pending::<Result<Value, RpcError>>())
                .expect("inserts succeed up to the cap");
            assert!(opid.starts_with("opid-"));
        }

        // One past the cap is rejected with -4 (not spawned).
        let err = reg
            .try_insert("w", None, std::future::pending::<Result<Value, RpcError>>())
            .unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_WALLET_ERROR);
        assert_eq!(
            reg.list_ids("w", None).len(),
            MAX_INFLIGHT_OPERATIONS_PER_WALLET
        );

        // The cap is per-wallet: a different wallet is unaffected.
        assert!(reg
            .try_insert(
                "other",
                None,
                std::future::pending::<Result<Value, RpcError>>()
            )
            .is_ok());
    }

    #[tokio::test]
    async fn finished_operations_do_not_count_toward_the_inflight_cap() {
        let reg = OperationRegistry::new();
        // Pile on far more than the in-flight cap, all finished - they never block new work.
        for _ in 0..MAX_INFLIGHT_OPERATIONS_PER_WALLET * 4 {
            reg.insert("w", AsyncOperation::finished(None, Ok(json!(1))));
        }
        assert!(reg
            .try_insert("w", None, std::future::pending::<Result<Value, RpcError>>())
            .is_ok());
    }

    /// Bounded-poll a real spawned operation to a terminal state.
    async fn drive_to_finish(op: &AsyncOperation) {
        for _ in 0..1000 {
            if op.state().is_finished() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        panic!("operation did not finish within the deadline");
    }

    #[tokio::test]
    async fn spawn_drives_success() {
        let op = AsyncOperation::new(None, async { Ok(json!({ "txid": "ab" })) });
        drive_to_finish(&op).await;
        let v = serde_json::to_value(op.to_status()).unwrap();
        assert_eq!(v["status"], "success");
        assert_eq!(v["result"], json!({ "txid": "ab" }));
        assert!(
            v.get("execution_secs").is_some(),
            "a successful op reports execution_secs: {v}"
        );
        assert!(v.get("error").is_none());
    }

    #[tokio::test]
    async fn spawn_drives_failure() {
        let op = AsyncOperation::new(None, async {
            Err::<Value, _>(RpcError::insufficient_funds("broke"))
        });
        drive_to_finish(&op).await;
        let v = serde_json::to_value(op.to_status()).unwrap();
        assert_eq!(v["status"], "failed");
        assert_eq!(
            v["error"]["code"],
            crate::error::codes::RPC_WALLET_INSUFFICIENT_FUNDS
        );
        assert_eq!(v["error"]["message"], "broke");
        assert!(v.get("result").is_none());
        assert!(v.get("execution_secs").is_none());
    }
}
