//! Shared application state handed to every RPC handler.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::{watch, Semaphore};

use crate::config::AppConfig;
use crate::wallet::WalletRegistry;

/// Transport-independent node state: everything RPC dispatch and the handlers need. HTTP-only
/// concerns (the auth gate) live in [`crate::server::HttpState`] instead, so an embedded node
/// (`crate::node::Node`) never constructs an `Authenticator` - whose config path writes a
/// cookie file as a side effect.
#[derive(Clone)]
pub struct AppState {
    /// The `[spend]` values a SIGHUP reload can change while the daemon runs, shared with every
    /// wallet actor. Everything else in `config` is fixed for the process's life; these are
    /// here because an operator needs to change them while a wallet is stuck, not at the next
    /// restart. See [`crate::config::SpendLimits`] for why the channel is a signal and not an
    /// RPC.
    pub spend_limits: crate::config::SpendLimits,
    pub config: Arc<AppConfig>,
    pub registry: Arc<WalletRegistry>,
    pub started_at: Instant,
    /// Broadcasts `stop`/Ctrl-C to every shutdown waiter (RPC server, health server, wallet
    /// actors). A `watch` channel - not `Notify` - so all waiters wake and a trigger that
    /// races a late subscriber is never lost (`wait_for` checks the current value first).
    pub shutdown_tx: watch::Sender<bool>,
    /// Set once shutdown has been requested; new requests are then rejected with 503.
    pub shutting_down: Arc<AtomicBool>,
    /// Bounds concurrent in-flight requests (Bitcoin Core's `-rpcworkqueue`); excess → 503.
    pub work_queue: Arc<Semaphore>,
    /// Currently-executing commands, for `getrpcinfo.active_commands`.
    pub active: ActiveCommands,
    /// In-memory registry of async `z_*` operations (transient, like zcashd's), scoped per
    /// wallet. Shared across handlers; populated by `z_sendmany`, read by
    /// `z_getoperationstatus`/`z_getoperationresult`/`z_listoperationids`.
    pub operations: Arc<crate::operations::OperationRegistry>,
    /// Runtime onboarding for the fleet: what `createwallet` needs to place a view wallet into a
    /// shard and start serving it without a restart. `None` when this node has no fleet
    /// configured, which is every pre-fleet deployment - the management RPCs then say so rather
    /// than pretending to work.
    pub fleet: Option<Arc<crate::fleet::FleetManager>>,
}

impl AppState {
    /// Request graceful shutdown: flag first (so in-flight new requests get 503), then wake
    /// every waiter.
    ///
    /// Async operations (`z_sendmany`/`z_shieldcoinbase`/`z_mergetoaddress`) are the one class
    /// of work shutdown can lose silently: a command still queued for the actor is dropped, and
    /// every status object is in-memory only. Name them once here so the loss is diagnosable -
    /// this is a log line, not a drain (a send already stored still rebroadcasts on restart).
    pub fn trigger_shutdown(&self) {
        let unfinished = self.operations.unfinished();
        if !unfinished.is_empty() {
            // The wallet actors finish the sends they have already accepted before stopping
            // (`WalletActor::finish_accepted_sends`), so these operations are expected to
            // complete rather than be dropped. What does not survive is their *status objects*:
            // the registry is in-memory, so after the restart a client must resolve fate by
            // txid on chain. Note that at INFO, not WARN - it is the documented contract, not a
            // fault; anything actually abandoned is warned about by the actor that drops it.
            tracing::info!(
                count = unfinished.len(),
                operations = ?unfinished,
                "async operations in flight at shutdown; the sends are being finished, but \
                 their status objects are in-memory only - resolve fate by txid after restart"
            );
        }
        self.shutting_down.store(true, Ordering::Relaxed);
        self.shutdown_tx.send_replace(true);
    }

    /// A future that resolves once shutdown has been requested. Race-free: it also resolves
    /// immediately when shutdown was triggered before the call (or the sender is gone).
    pub fn shutdown_signal(&self) -> impl std::future::Future<Output = ()> + Send + 'static {
        let mut rx = self.shutdown_tx.subscribe();
        async move {
            let _ = rx.wait_for(|stop| *stop).await;
        }
    }
}

/// RAII tracker of in-flight RPC commands (mirrors Bitcoin Core's `RPCCommandExecution`).
#[derive(Clone, Default)]
pub struct ActiveCommands {
    inner: Arc<Mutex<HashMap<u64, (String, Instant)>>>,
    next_id: Arc<AtomicU64>,
}

impl ActiveCommands {
    /// Register a command as active; it is removed when the returned guard is dropped.
    pub(crate) fn begin(&self, method: &str) -> CommandGuard {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut map) = self.inner.lock() {
            map.insert(id, (method.to_string(), Instant::now()));
        }
        CommandGuard {
            inner: self.inner.clone(),
            id,
        }
    }

    /// `(method, duration_micros)` for each currently-executing command.
    pub fn snapshot(&self) -> Vec<(String, u128)> {
        self.inner
            .lock()
            .map(|map| {
                map.values()
                    .map(|(name, start)| (name.clone(), start.elapsed().as_micros()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Removes its command from [`ActiveCommands`] on drop.
pub(crate) struct CommandGuard {
    inner: Arc<Mutex<HashMap<u64, (String, Instant)>>>,
    id: u64,
}

impl Drop for CommandGuard {
    fn drop(&mut self) {
        if let Ok(mut map) = self.inner.lock() {
            map.remove(&self.id);
        }
    }
}
