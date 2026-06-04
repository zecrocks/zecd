//! Shared application state handed to every RPC handler.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::{Notify, Semaphore};

use crate::config::AppConfig;
use crate::server::auth::Authenticator;
use crate::wallet::WalletRegistry;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub auth: Authenticator,
    pub registry: Arc<WalletRegistry>,
    pub started_at: Instant,
    /// Notified by `stop`/Ctrl-C to trigger graceful shutdown.
    pub shutdown: Arc<Notify>,
    /// Set once shutdown has been requested; new requests are then rejected with 503.
    pub shutting_down: Arc<AtomicBool>,
    /// Bounds concurrent in-flight requests (Bitcoin Core's `-rpcworkqueue`); excess → 503.
    pub work_queue: Arc<Semaphore>,
    /// Currently-executing commands, for `getrpcinfo.active_commands`.
    pub active: ActiveCommands,
}

/// RAII tracker of in-flight RPC commands (mirrors Bitcoin Core's `RPCCommandExecution`).
#[derive(Clone, Default)]
pub struct ActiveCommands {
    inner: Arc<Mutex<HashMap<u64, (String, Instant)>>>,
    next_id: Arc<AtomicU64>,
}

impl ActiveCommands {
    /// Register a command as active; it is removed when the returned guard is dropped.
    pub fn begin(&self, method: &str) -> CommandGuard {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut map) = self.inner.lock() {
            map.insert(id, (method.to_string(), Instant::now()));
        }
        CommandGuard { inner: self.inner.clone(), id }
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

pub struct CommandGuard {
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
