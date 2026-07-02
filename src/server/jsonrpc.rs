//! Bitcoin-Core-compatible JSON-RPC framing.
//!
//! Bitcoin Core speaks a JSON-RPC 1.0-ish dialect: every response carries both `result`
//! and `error` keys (one of them null), the `id` is echoed verbatim, and a single request
//! that errors is returned with HTTP status 500 (the body still holds the error object).
//! Batches are JSON arrays and always return HTTP 200.

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

        Ok(RpcRequest { id, method, params })
    }

    /// Positional parameter accessor.
    pub fn param(&self, i: usize) -> Option<&Value> {
        self.params.get(i)
    }

    /// A required string parameter, with Bitcoin Core's argument-error taxonomy: a missing
    /// (absent or `null`) argument raises `msg` under `RPC_MISC_ERROR` (-1, Core's help path),
    /// while a present-but-non-string argument is a `RPC_TYPE_ERROR` (-3). Core never emits
    /// `RPC_INVALID_PARAMS` (-32602) from a handler, so neither does this. Centralizes the most
    /// common param-parsing idiom in the handlers.
    pub fn require_str(&self, i: usize, msg: &str) -> Result<&str, RpcError> {
        match self.param(i) {
            None | Some(Value::Null) => Err(RpcError::missing_param(msg)),
            Some(v) => v
                .as_str()
                .ok_or_else(|| RpcError::type_error(format!("{msg} (expected a string)"))),
        }
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
#[derive(Debug)]
pub enum Body {
    Single(Value),
    Batch(Vec<Value>),
}

/// Parse the raw HTTP body into a [`Body`]. A non-array, non-object top level, or invalid
/// JSON, is a parse error.
pub fn parse_body(bytes: &[u8]) -> Result<Body, RpcError> {
    let v: Value = serde_json::from_slice(bytes).map_err(|e| {
        RpcError::new(
            crate::error::codes::RPC_PARSE_ERROR,
            format!("Parse error: {e}"),
        )
    })?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::codes;

    #[test]
    fn parses_single_and_batch() {
        assert!(matches!(
            parse_body(br#"{"method":"getblockcount","id":1}"#),
            Ok(Body::Single(_))
        ));
        assert!(matches!(
            parse_body(br#"[{"method":"a","id":1},{"method":"b","id":2}]"#),
            Ok(Body::Batch(v)) if v.len() == 2
        ));
    }

    #[test]
    fn parse_errors() {
        // Invalid JSON -> parse error.
        assert_eq!(
            parse_body(b"not json").unwrap_err().code,
            codes::RPC_PARSE_ERROR
        );
        // Wrong top-level type.
        assert_eq!(
            parse_body(b"5").unwrap_err().code,
            codes::RPC_INVALID_REQUEST
        );
        // Empty batch.
        assert_eq!(
            parse_body(b"[]").unwrap_err().code,
            codes::RPC_INVALID_REQUEST
        );
    }

    #[test]
    fn request_from_value_ok_and_missing_method() {
        let v: Value =
            serde_json::from_str(r#"{"method":"sendtoaddress","id":"x","params":["addr",1.5]}"#)
                .unwrap();
        let req = RpcRequest::from_value(v).unwrap();
        assert_eq!(req.method, "sendtoaddress");
        assert_eq!(req.id, Value::String("x".into()));
        assert_eq!(req.params.len(), 2);
        assert_eq!(req.param(0).unwrap().as_str(), Some("addr"));

        // Missing method preserves the id in the error tuple.
        let v: Value = serde_json::from_str(r#"{"id":7}"#).unwrap();
        let (id, err) = RpcRequest::from_value(v).unwrap_err();
        assert_eq!(id, serde_json::json!(7));
        assert_eq!(err.code, codes::RPC_INVALID_REQUEST);
    }

    #[test]
    fn envelopes_match_bitcoind_shape() {
        let ok = success(serde_json::json!(1), serde_json::json!("done"));
        assert_eq!(ok["result"], serde_json::json!("done"));
        assert_eq!(ok["error"], Value::Null);
        assert_eq!(ok["id"], serde_json::json!(1));

        let err = error(serde_json::json!(2), &RpcError::method_not_found("foo"));
        assert_eq!(err["result"], Value::Null);
        assert_eq!(
            err["error"]["code"],
            serde_json::json!(codes::RPC_METHOD_NOT_FOUND)
        );
        assert!(err["error"]["message"].is_string());
        assert_eq!(err["id"], serde_json::json!(2));
    }
}
