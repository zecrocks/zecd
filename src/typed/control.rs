//! Typed control RPCs: `stop`, `uptime`, `help`, `getrpcinfo`. Response shapes follow
//! `rpc/control.rs`.

use serde_json::json;

use super::{Client, ClientError};

/// One currently-executing command, from `getrpcinfo.active_commands`
/// (`rpc/control.rs::getrpcinfo`).
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ActiveCommand {
    pub method: String,
    /// Elapsed execution time so far, in microseconds (Bitcoin Core's unit).
    pub duration: u64,
}

/// `getrpcinfo` (`rpc/control.rs::getrpcinfo`).
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RpcInfo {
    pub active_commands: Vec<ActiveCommand>,
    /// Always empty: zecd logs to stderr/tracing, not a debug.log file.
    pub logpath: String,
}

impl Client<'_> {
    /// `stop`: request graceful shutdown. Regtest-only (elsewhere it reads as
    /// method-not-found, -32601) and it stops THIS node, embedded or not.
    pub async fn stop(&self) -> Result<String, ClientError> {
        self.call_typed("stop", vec![]).await
    }

    /// `uptime`: seconds since the node started.
    pub async fn uptime(&self) -> Result<u64, ClientError> {
        self.call_typed("uptime", vec![]).await
    }

    /// `help ( command )`: a short orientation string (zecd has no per-method help pages).
    pub async fn help(&self, command: Option<&str>) -> Result<String, ClientError> {
        let params = Self::positional(vec![command.map(|c| json!(c))]);
        self.call_typed("help", params).await
    }

    /// `getrpcinfo`: the currently-executing commands (embedded calls included).
    pub async fn get_rpc_info(&self) -> Result<RpcInfo, ClientError> {
        self.call_typed("getrpcinfo", vec![]).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixture captured from a live `getrpcinfo` during a conformance run (one in-flight
    /// command, as the busy-server phase sees it).
    #[test]
    fn rpc_info_decodes() {
        let v = serde_json::json!({
            "active_commands": [ { "method": "getrpcinfo", "duration": 42 } ],
            "logpath": "",
        });
        let info: RpcInfo = serde_json::from_value(v).unwrap();
        assert_eq!(info.active_commands.len(), 1);
        assert_eq!(info.active_commands[0].method, "getrpcinfo");
        assert_eq!(info.active_commands[0].duration, 42);
        assert!(info.logpath.is_empty());
    }
}
