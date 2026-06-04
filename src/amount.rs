//! Conversion between Zcash zatoshis and the decimal ZEC amounts Bitcoin Core's RPC
//! uses on the wire.
//!
//! Bitcoin Core serializes amounts as JSON numbers with exactly 8 decimal places
//! (`ValueFromAmount`) and parses incoming amounts allowing at most 8 decimals
//! (`AmountFromValue`). Zcash uses the same 1 ZEC = 100,000,000 zatoshi scale, so the
//! mapping is 1:1. We rely on `serde_json`'s `arbitrary_precision` feature so amounts
//! round-trip as exact decimals rather than through `f64`.

use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use serde_json::Value;
use zcash_protocol::value::{Zatoshis, COIN};

use crate::error::RpcError;

/// Render an unsigned zatoshi amount as a JSON number with 8 decimal places.
pub fn zats_to_value(zats: u64) -> Value {
    let s = format!("{}.{:08}", zats / COIN, zats % COIN);
    // Under `arbitrary_precision`, parsing a numeric string yields a `Number` that
    // preserves the exact decimal representation.
    serde_json::from_str(&s).expect("formatted amount is valid JSON number")
}

/// Render a signed zatoshi balance (e.g. a transaction's net delta) as a JSON number.
/// Sends are negative, receives positive - matching Bitcoin Core's `listtransactions`.
pub fn signed_zats_to_value(zats: i64) -> Value {
    let neg = zats < 0;
    let abs = zats.unsigned_abs();
    let s = format!("{}{}.{:08}", if neg { "-" } else { "" }, abs / COIN, abs % COIN);
    serde_json::from_str(&s).expect("formatted amount is valid JSON number")
}

fn decimal_from_value(v: &Value) -> Result<Decimal, RpcError> {
    match v {
        // With `arbitrary_precision`, `Number`'s Display preserves the original literal.
        Value::Number(n) => n
            .to_string()
            .parse::<Decimal>()
            .map_err(|_| RpcError::type_error("Invalid amount")),
        // Some clients send amounts as strings; accept those too.
        Value::String(s) => s
            .parse::<Decimal>()
            .map_err(|_| RpcError::type_error("Invalid amount")),
        _ => Err(RpcError::type_error("Amount is not a number")),
    }
}

/// Parse a Bitcoin-Core-style decimal ZEC amount into `Zatoshis`.
///
/// Rejects negative amounts, amounts with more than 8 decimal places, and amounts
/// outside the valid money range - mirroring `AmountFromValue`.
pub fn value_to_zats(v: &Value) -> Result<Zatoshis, RpcError> {
    let dec = decimal_from_value(v)?;
    if dec.is_sign_negative() {
        return Err(RpcError::type_error("Amount out of range"));
    }
    let scaled = dec * Decimal::from(COIN);
    if !scaled.fract().is_zero() {
        return Err(RpcError::type_error(
            "Invalid amount (too many decimal places; max 8)",
        ));
    }
    let zats = scaled
        .to_u64()
        .ok_or_else(|| RpcError::type_error("Amount out of range"))?;
    Zatoshis::from_u64(zats).map_err(|_| RpcError::type_error("Amount out of range"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_basic() {
        assert_eq!(zats_to_value(150_000_000).to_string(), "1.50000000");
        assert_eq!(zats_to_value(1).to_string(), "0.00000001");
        assert_eq!(zats_to_value(0).to_string(), "0.00000000");
        assert_eq!(zats_to_value(COIN).to_string(), "1.00000000");
    }

    #[test]
    fn signed_formatting() {
        assert_eq!(signed_zats_to_value(-150_000_000).to_string(), "-1.50000000");
        assert_eq!(signed_zats_to_value(150_000_000).to_string(), "1.50000000");
    }

    #[test]
    fn parse_number_and_string() {
        let n: Value = serde_json::from_str("1.5").unwrap();
        assert_eq!(value_to_zats(&n).unwrap().into_u64(), 150_000_000);
        let s = Value::String("0.00000001".to_string());
        assert_eq!(value_to_zats(&s).unwrap().into_u64(), 1);
    }

    #[test]
    fn reject_too_many_decimals() {
        let n: Value = serde_json::from_str("0.000000001").unwrap(); // 9 dp
        assert!(value_to_zats(&n).is_err());
    }

    #[test]
    fn reject_negative() {
        let n: Value = serde_json::from_str("-1.0").unwrap();
        assert!(value_to_zats(&n).is_err());
    }

    #[test]
    fn reject_over_max_money() {
        let n: Value = serde_json::from_str("21000001").unwrap(); // > 21M ZEC
        assert!(value_to_zats(&n).is_err());
    }
}
