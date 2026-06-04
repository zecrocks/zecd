//! Shared application state handed to every RPC handler.

use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Notify;

use crate::config::AppConfig;
use crate::server::auth::Authenticator;
use crate::wallet::WalletRegistry;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub auth: Authenticator,
    pub registry: Arc<WalletRegistry>,
    pub started_at: Instant,
    /// Notified by the `stop` RPC to trigger graceful shutdown.
    pub shutdown: Arc<Notify>,
}
