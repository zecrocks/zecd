//! Bitcoin-Core-compatible JSON-RPC framing.
//!
//! Bitcoin Core speaks a JSON-RPC 1.0-ish dialect: every response carries both `result`
//! and `error` keys (one of them null), the `id` is echoed verbatim, and a single request
//! that errors is returned with HTTP status 500 (the body still holds the error object).
//! Batches are JSON arrays and always return HTTP 200.
#![allow(dead_code)] // params_raw is retained for object-style param support

use serde_json::{json, Value};

use crate::error::RpcError;

/// A single parsed JSON-RPC request.
#[derive(Debug, Clone)]
pub struct RpcRequest {
    pub id: Value,
    pub method: String,
    /// Positional params as a vector (Bitcoin Core uses positional arrays). An object or
    /// missing `params` yields an empty vector here; object params are uncommon for the
    /// methods we implement.
    pub params: Vec<Value>,
    /// Raw params, preserved for the rare object-style call.
    pub params_raw: Value,
}

impl RpcRequest {
    /// Validate a raw JSON value into an `RpcRequest`. The `id` (possibly null) is returned
    /// in the `Err` case too so the caller can build a correctly-addressed error response.
    pub fn from_value(v: Value) -> Result<RpcRequest, (Value, RpcError)> {
        let id = v.get("id").cloned().unwrap_or(Value::Null);

        let method = match v.get("method").and_then(|m| m.as_str()) {
            Some(m) => m.to_string(),
            None => {
                return Err((
                    id,
                    RpcError::new(
                        crate::error::codes::RPC_INVALID_REQUEST,
                        "Missing or invalid 'method'",
                    ),
                ))
            }
        };

        let params_raw = v.get("params").cloned().unwrap_or(Value::Null);
        let params = match &params_raw {
            Value::Null => Vec::new(),
            Value::Array(arr) => arr.clone(),
            // Object params: keep raw; positional accessors will see an empty vec.
            Value::Object(_) => Vec::new(),
            other => {
                return Err((
                    id,
                    RpcError::new(
                        crate::error::codes::RPC_INVALID_REQUEST,
                        format!("'params' must be an array or object, got {other}"),
                    ),
                ))
            }
        };

        Ok(RpcRequest { id, method, params, params_raw })
    }

    /// Positional parameter accessor.
    pub fn param(&self, i: usize) -> Option<&Value> {
        self.params.get(i)
    }
}

/// Build a success response envelope.
pub fn success(id: Value, result: Value) -> Value {
    json!({ "result": result, "error": Value::Null, "id": id })
}

/// Build an error response envelope.
pub fn error(id: Value, err: &RpcError) -> Value {
    json!({
        "result": Value::Null,
        "error": { "code": err.code, "message": err.message },
        "id": id,
    })
}

/// The parsed top-level request body: a single call or a batch.
pub enum Body {
    Single(Value),
    Batch(Vec<Value>),
}

/// Parse the raw HTTP body into a [`Body`]. A non-array, non-object top level, or invalid
/// JSON, is a parse error.
pub fn parse_body(bytes: &[u8]) -> Result<Body, RpcError> {
    let v: Value = serde_json::from_slice(bytes)
        .map_err(|e| RpcError::new(crate::error::codes::RPC_PARSE_ERROR, format!("Parse error: {e}")))?;
    match v {
        Value::Array(arr) => {
            if arr.is_empty() {
                return Err(RpcError::new(
                    crate::error::codes::RPC_INVALID_REQUEST,
                    "Empty batch",
                ));
            }
            Ok(Body::Batch(arr))
        }
        obj @ Value::Object(_) => Ok(Body::Single(obj)),
        _ => Err(RpcError::new(
            crate::error::codes::RPC_INVALID_REQUEST,
            "Top-level request must be an object or array",
        )),
    }
}
