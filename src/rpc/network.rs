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

pub fn getnetworkinfo(state: &AppState) -> Result<Value, RpcError> {
    let up = connected(state);
    Ok(json!({
        "version": 240000,
        "subversion": "/zecd:0.1.0/",
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

pub fn getpeerinfo() -> Result<Value, RpcError> {
    Ok(Value::Array(vec![]))
}

pub fn ping() -> Result<Value, RpcError> {
    Ok(Value::Null)
}
