//! Typed network RPCs: `getnetworkinfo`, `getconnectioncount`, `getpeerinfo`, `ping`.
//! Response shapes follow `rpc/network.rs`.

use serde_json::Value;

use super::{Client, ClientError};
use crate::amount::Amount;

/// `getnetworkinfo` (`rpc/network.rs::getnetworkinfo`). `connections` counts the single
/// upstream (1 when connected).
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct NetworkInfo {
    /// zecd's version in Bitcoin Core's numeric encoding (major*10000 + minor*100 + patch).
    pub version: u64,
    /// `/zecd:<version>/`.
    pub subversion: String,
    pub protocolversion: u64,
    pub localservices: String,
    pub localservicesnames: Vec<Value>,
    pub localrelay: bool,
    pub timeoffset: i64,
    pub networkactive: bool,
    pub connections: u32,
    pub connections_in: u32,
    pub connections_out: u32,
    pub networks: Vec<Value>,
    pub relayfee: Amount,
    pub incrementalfee: Amount,
    pub localaddresses: Vec<Value>,
    pub warnings: String,
}

/// One entry of `getpeerinfo` - zecd's single "peer" is the active upstream
/// (`rpc/network.rs::getpeerinfo`; the list is empty while disconnected).
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PeerInfo {
    pub id: u64,
    pub addr: String,
    pub inbound: bool,
    /// zecd extension: the upstream connection state (`down`/`syncing`/`ready`).
    pub conn_state: String,
    /// zecd extension: true while scanning or draining the enhancement backlog.
    pub syncing: bool,
}

impl Client<'_> {
    /// `getnetworkinfo`: daemon version/identity in Bitcoin Core's shape.
    pub async fn get_network_info(&self) -> Result<NetworkInfo, ClientError> {
        self.call_typed("getnetworkinfo", vec![]).await
    }

    /// `getconnectioncount`: 1 while the upstream is reachable, else 0.
    pub async fn get_connection_count(&self) -> Result<u32, ClientError> {
        self.call_typed("getconnectioncount", vec![]).await
    }

    /// `getpeerinfo`: the active upstream as the single peer (empty while disconnected).
    pub async fn get_peer_info(&self) -> Result<Vec<PeerInfo>, ClientError> {
        self.call_typed("getpeerinfo", vec![]).await
    }

    /// `ping`: liveness no-op (there is no P2P peer to ping).
    pub async fn ping(&self) -> Result<(), ClientError> {
        // The wire result is JSON null, which deserializes into the unit type.
        self.call_typed("ping", vec![]).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixture captured from a walletless test node's `getnetworkinfo` (the same state the
    /// HTTP tests drive); the amounts must land as exact zatoshis.
    #[test]
    fn network_info_decodes() {
        let v = serde_json::json!({
            "version": 100,
            "subversion": "/zecd:0.1.0/",
            "protocolversion": 170100,
            "localservices": "0000000000000000",
            "localservicesnames": [],
            "localrelay": false,
            "timeoffset": 0,
            "networkactive": true,
            "connections": 1,
            "connections_in": 0,
            "connections_out": 1,
            "networks": [],
            "relayfee": 0.00001000,
            "incrementalfee": 0.00001000,
            "localaddresses": [],
            "warnings": "",
        });
        let info: NetworkInfo = serde_json::from_value(v).unwrap();
        assert_eq!(info.relayfee.zatoshis(), 1000);
        assert_eq!(info.connections, 1);
        assert!(info.subversion.contains("zecd"));
    }

    /// Fixture from a connected wallet's `getpeerinfo`.
    #[test]
    fn peer_info_decodes() {
        let v = serde_json::json!([{
            "id": 0,
            "addr": "zebra://127.0.0.1:18234",
            "inbound": false,
            "conn_state": "ready",
            "syncing": false,
        }]);
        let peers: Vec<PeerInfo> = serde_json::from_value(v).unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].conn_state, "ready");
        assert!(!peers[0].syncing);
    }
}
