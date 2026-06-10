//! Network RPCs: getnetworkinfo, getconnectioncount, ping, getpeerinfo.

use serde_json::{json, Value};

use crate::amount::zats_to_value;
use crate::error::RpcError;
use crate::state::AppState;

fn connected(state: &AppState) -> bool {
    state
        .registry
        .get(None)
        .map(|w| w.status().connected)
        .unwrap_or(false)
}

/// zecd's own version in Bitcoin Core's numeric encoding (major*10000 + minor*100 + patch),
/// derived from Cargo.toml so it can't drift from the crate version.
fn version_number() -> u64 {
    let mut parts = env!("CARGO_PKG_VERSION")
        .split('.')
        .map(|p| p.parse::<u64>().unwrap_or(0));
    let major = parts.next().unwrap_or(0);
    let minor = parts.next().unwrap_or(0);
    let patch = parts.next().unwrap_or(0);
    major * 10000 + minor * 100 + patch
}

pub fn getnetworkinfo(state: &AppState) -> Result<Value, RpcError> {
    let up = connected(state);
    Ok(json!({
        "version": version_number(),
        "subversion": format!("/zecd:{}/", env!("CARGO_PKG_VERSION")),
        "protocolversion": 170100,
        "localservices": "0000000000000000",
        "localservicesnames": [],
        "localrelay": false,
        "timeoffset": 0,
        "networkactive": true,
        "connections": if up { 1 } else { 0 },
        "connections_in": 0,
        "connections_out": if up { 1 } else { 0 },
        "networks": [],
        "relayfee": zats_to_value(1000),
        "incrementalfee": zats_to_value(1000),
        "localaddresses": [],
        "warnings": ""
    }))
}

pub fn getconnectioncount(state: &AppState) -> Result<Value, RpcError> {
    Ok(json!(if connected(state) { 1 } else { 0 }))
}

pub fn getpeerinfo(state: &AppState) -> Result<Value, RpcError> {
    // zecd's single "peer" is the active lightwalletd upstream. Report it (with its connection
    // state) when connected; otherwise an empty peer list, as bitcoind does with no peers.
    let Ok(w) = state.registry.get(None) else {
        return Ok(Value::Array(vec![]));
    };
    let st = w.status();
    if !st.connected {
        return Ok(Value::Array(vec![]));
    }
    Ok(json!([{
        "id": 0,
        "addr": st.server.clone().unwrap_or_default(),
        "inbound": false,
        "conn_state": st.conn_state.as_str(),
        "syncing": st.scanning,
    }]))
}

pub fn ping() -> Result<Value, RpcError> {
    Ok(Value::Null)
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_number_encodes_cargo_version() {
        let v = super::version_number();
        assert!(v > 0, "version must encode to a nonzero number");
        // 0.1.0 -> 100, 1.2.3 -> 10203; sanity-check the arithmetic shape.
        assert_eq!(v % 100, env!("CARGO_PKG_VERSION").split('.').nth(2).unwrap().parse::<u64>().unwrap());
    }
}
