//! Conversion between Zcash zatoshis and the decimal ZEC amounts Bitcoin Core's RPC
//! uses on the wire.
//!
//! Bitcoin Core serializes amounts as JSON numbers with exactly 8 decimal places
//! (`ValueFromAmount`) and parses incoming amounts with `ParseFixedPoint` via
//! `AmountFromValue`. Zcash uses the same 1 ZEC = 100,000,000 zatoshi scale, so the
//! mapping is 1:1. We rely on `serde_json`'s `arbitrary_precision` feature so amounts
//! round-trip as exact decimal literals rather than through `f64`.

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
    let s = format!(
        "{}{}.{:08}",
        if neg { "-" } else { "" },
        abs / COIN,
        abs % COIN
    );
    serde_json::from_str(&s).expect("formatted amount is valid JSON number")
}

/// Parse a Bitcoin-Core-style decimal ZEC amount into `Zatoshis`, mirroring
/// `AmountFromValue`: accept a JSON number or string, parse with [`parse_fixed_point`],
/// then range-check (negative or above `MAX_MONEY` → "Amount out of range").
pub fn value_to_zats(v: &Value) -> Result<Zatoshis, RpcError> {
    let literal = match v {
        // With `arbitrary_precision`, `Number`'s Display preserves the original literal.
        Value::Number(n) => n.to_string(),
        // Some clients send amounts as strings; bitcoind accepts those too.
        Value::String(s) => s.clone(),
        _ => return Err(RpcError::type_error("Amount is not a number or string")),
    };
    let zats =
        parse_fixed_point(&literal, 8).ok_or_else(|| RpcError::type_error("Invalid amount"))?;
    Zatoshis::from_nonnegative_i64(zats).map_err(|_| RpcError::type_error("Amount out of range"))
}

/// Largest arbitrary-decimal mantissa that fits in an `i64`: 10^18 - 1. Larger integers
/// cannot consist of arbitrary combinations of 0-9 without risking overflow.
const UPPER_BOUND: i64 = 1_000_000_000_000_000_000 - 1;

/// Helper for [`parse_fixed_point`]: fold one mantissa digit, deferring runs of zeros so
/// trailing zeros never overflow the mantissa. Returns `false` on overflow.
fn process_mantissa_digit(ch: char, mantissa: &mut i64, mantissa_tzeros: &mut i64) -> bool {
    if ch == '0' {
        *mantissa_tzeros += 1;
    } else {
        for _ in 0..=*mantissa_tzeros {
            if *mantissa > (UPPER_BOUND / 10) {
                return false; // overflow
            }
            *mantissa *= 10;
        }
        *mantissa += i64::from(ch.to_digit(10).expect("caller checked this"));
        *mantissa_tzeros = 0;
    }
    true
}

/// Exact port of Bitcoin Core's [`ParseFixedPoint`] (the parser behind `AmountFromValue`),
/// returning the value scaled by 10^`decimals` zatoshis. A decimal-library parse is not a
/// substitute: `rust_decimal` silently truncates sub-representable mantissas to zero, so
/// e.g. `0.0…01e+68` (= 1 zatoshi) or a 64-zero mantissa meaning 1 ZEC would parse as 0.
///
/// [`ParseFixedPoint`]: https://github.com/bitcoin/bitcoin/blob/master/src/util/strencodings.cpp
fn parse_fixed_point(mut val: &str, decimals: i64) -> Option<i64> {
    let mut mantissa = 0i64;
    let mut exponent = 0i64;
    let mut mantissa_tzeros = 0i64;
    let mut exponent_sign = false;
    let mut point_ofs = 0;

    let mantissa_sign = match val.split_at_checked(1) {
        Some(("-", rest)) => {
            val = rest;
            true
        }
        _ => false,
    };
    match val.split_at_checked(1) {
        Some(("0", rest)) => val = rest, // pass single 0
        Some(("1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9", _)) => {
            let mut chars = val.char_indices();
            loop {
                match chars.next() {
                    Some((_, ch)) if ch.is_ascii_digit() => {
                        if !process_mantissa_digit(ch, &mut mantissa, &mut mantissa_tzeros) {
                            return None; // overflow
                        }
                    }
                    Some((i, _)) => {
                        val = val.split_at(i).1;
                        break;
                    }
                    None => {
                        val = "";
                        break;
                    }
                }
            }
        }
        Some(_) => return None, // missing expected digit
        None => return None,    // empty string or lone '-'
    }
    if let Some((".", rest)) = val.split_at_checked(1) {
        val = rest;
        match val.split_at_checked(1) {
            Some(("0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9", _)) => {
                let mut chars = val.char_indices();
                loop {
                    match chars.next() {
                        Some((_, ch)) if ch.is_ascii_digit() => {
                            if !process_mantissa_digit(ch, &mut mantissa, &mut mantissa_tzeros) {
                                return None; // overflow
                            }
                            point_ofs += 1;
                        }
                        Some((i, _)) => {
                            val = val.split_at(i).1;
                            break;
                        }
                        None => {
                            val = "";
                            break;
                        }
                    }
                }
            }
            _ => return None, // missing expected digit
        }
    }
    if let Some(("e" | "E", rest)) = val.split_at_checked(1) {
        val = rest;
        match val.split_at_checked(1) {
            Some(("+", rest)) => val = rest,
            Some(("-", rest)) => {
                exponent_sign = true;
                val = rest;
            }
            _ => (),
        }
        match val.split_at_checked(1) {
            Some(("0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9", _)) => {
                let mut chars = val.char_indices();
                loop {
                    match chars.next() {
                        Some((_, ch)) if ch.is_ascii_digit() => {
                            if exponent > (UPPER_BOUND / 10) {
                                return None; // overflow
                            }
                            exponent = exponent * 10 + i64::from(ch.to_digit(10).expect("checked"));
                        }
                        Some((i, _)) => {
                            val = val.split_at(i).1;
                            break;
                        }
                        None => {
                            val = "";
                            break;
                        }
                    }
                }
            }
            _ => return None, // missing expected digit
        }
    }
    if !val.is_empty() {
        return None; // trailing garbage
    }

    // finalize exponent
    if exponent_sign {
        exponent = -exponent;
    }
    exponent = exponent - point_ofs + mantissa_tzeros;

    // finalize mantissa
    if mantissa_sign {
        mantissa = -mantissa;
    }

    // convert to one 64-bit fixed-point value
    exponent += decimals;
    if exponent < 0 {
        return None; // cannot represent values smaller than 10^-decimals
    }
    if exponent >= 18 {
        return None; // cannot represent values larger than or equal to 10^(18-decimals)
    }

    for _ in 0..exponent {
        if !(-(UPPER_BOUND / 10)..=(UPPER_BOUND / 10)).contains(&mantissa) {
            return None; // overflow
        }
        mantissa *= 10;
    }
    if !(-UPPER_BOUND..=UPPER_BOUND).contains(&mantissa) {
        return None; // overflow
    }

    Some(mantissa)
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
        assert_eq!(
            signed_zats_to_value(-150_000_000).to_string(),
            "-1.50000000"
        );
        assert_eq!(signed_zats_to_value(150_000_000).to_string(), "1.50000000");
    }

    /// `ValueFromAmount` vectors from zcashd `src/test/rpc_tests.cpp`
    /// (`rpc_format_monetary_values`), via zallet.
    #[test]
    fn format_monetary_values_match_bitcoind() {
        let f = |zats: u64| zats_to_value(zats).to_string();

        assert_eq!(f(0), "0.00000000");
        assert_eq!(f(1), "0.00000001");
        assert_eq!(f(17_622_195), "0.17622195");
        assert_eq!(f(50_000_000), "0.50000000");
        assert_eq!(f(89_898_989), "0.89898989");
        assert_eq!(f(100_000_000), "1.00000000");
        assert_eq!(f(2_099_999_999_999_990), "20999999.99999990");
        assert_eq!(f(2_099_999_999_999_999), "20999999.99999999");
        assert_eq!(f((COIN / 10_000) * 123_456_789), "12345.67890000");

        assert_eq!(f(COIN * 10_000_000), "10000000.00000000");
        assert_eq!(f(COIN * 1_000_000), "1000000.00000000");
        assert_eq!(f(COIN * 100_000), "100000.00000000");
        assert_eq!(f(COIN * 10_000), "10000.00000000");
        assert_eq!(f(COIN * 1_000), "1000.00000000");
        assert_eq!(f(COIN * 100), "100.00000000");
        assert_eq!(f(COIN * 10), "10.00000000");
        assert_eq!(f(COIN), "1.00000000");
        assert_eq!(f(COIN / 10), "0.10000000");
        assert_eq!(f(COIN / 100), "0.01000000");
        assert_eq!(f(COIN / 1_000), "0.00100000");
        assert_eq!(f(COIN / 10_000), "0.00010000");
        assert_eq!(f(COIN / 100_000), "0.00001000");
        assert_eq!(f(COIN / 1_000_000), "0.00000100");
        assert_eq!(f(COIN / 10_000_000), "0.00000010");
        assert_eq!(f(COIN / 100_000_000), "0.00000001");

        let s = |zats: i64| signed_zats_to_value(zats).to_string();
        let coin = i64::try_from(COIN).expect("fits");
        assert_eq!(s(-coin), "-1.00000000");
        assert_eq!(s(-coin / 10), "-0.10000000");
    }

    #[test]
    fn parse_number_and_string() {
        let n: Value = serde_json::from_str("1.5").unwrap();
        assert_eq!(value_to_zats(&n).unwrap().into_u64(), 150_000_000);
        let s = Value::String("0.00000001".to_string());
        assert_eq!(value_to_zats(&s).unwrap().into_u64(), 1);
    }

    /// `AmountFromValue` vectors from zcashd `src/test/rpc_tests.cpp`
    /// (`rpc_parse_monetary_values`), via zallet. JSON-number and string forms must agree.
    #[test]
    fn parse_monetary_values_match_bitcoind() {
        let parse = |s: &str| {
            let from_str = value_to_zats(&Value::String(s.to_string()));
            // Every vector here is also a valid JSON number literal; the two input
            // forms must behave identically.
            let v: Value = serde_json::from_str(s).expect("vector is a valid JSON number");
            let from_num = value_to_zats(&v);
            assert_eq!(
                from_str.is_ok(),
                from_num.is_ok(),
                "string and number forms disagree for {s}"
            );
            from_num.ok().map(|z| z.into_u64())
        };
        let zat = |v: u64| Some(v);

        assert!(parse("-0.00000001").is_none());
        assert_eq!(parse("0"), zat(0));
        assert_eq!(parse("0.00000000"), zat(0));
        assert_eq!(parse("0.00000001"), zat(1));
        assert_eq!(parse("0.17622195"), zat(17_622_195));
        assert_eq!(parse("0.5"), zat(50_000_000));
        assert_eq!(parse("0.50000000"), zat(50_000_000));
        assert_eq!(parse("0.89898989"), zat(89_898_989));
        assert_eq!(parse("1.00000000"), zat(100_000_000));
        assert_eq!(parse("20999999.9999999"), zat(2_099_999_999_999_990));
        assert_eq!(parse("20999999.99999999"), zat(2_099_999_999_999_999));

        assert_eq!(parse("1e-8"), zat(COIN / 100_000_000));
        assert_eq!(parse("0.1e-7"), zat(COIN / 100_000_000));
        assert_eq!(parse("0.01e-6"), zat(COIN / 100_000_000));
        assert_eq!(
            parse(
                "0.0000000000000000000000000000000000000000000000000000000000000000000000000001e+68"
            ),
            zat(COIN / 100_000_000)
        );
        assert_eq!(
            parse("10000000000000000000000000000000000000000000000000000000000000000e-64"),
            zat(COIN)
        );
        assert_eq!(
            parse(
                "0.000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000e64"
            ),
            zat(COIN)
        );

        assert!(parse("1e-9").is_none()); // sub-zatoshi
        assert!(parse("0.000000019").is_none()); // sub-zatoshi
        assert_eq!(parse("0.00000001000000"), zat(1)); // trailing zeros cut
        assert!(parse("19e-9").is_none()); // sub-zatoshi
        assert_eq!(parse("0.19e-6"), zat(19)); // leading 0 is present

        assert!(parse("92233720368.54775808").is_none()); // overflow
        assert!(parse("1e+11").is_none()); // overflow
        assert!(parse("1e11").is_none()); // overflow, signless
        assert!(parse("93e+9").is_none()); // overflow
    }

    /// `ParseFixedPoint` vectors from zcashd `src/test/util_tests.cpp`
    /// (`util_ParseFixedPoint`), via zallet. Exercises the raw signed parser, including
    /// syntax forms (`.1`, `--0.1`, leading zeros) that never reach `value_to_zats`.
    #[test]
    fn test_parse_fixed_point() {
        assert_eq!(parse_fixed_point("0", 8), Some(0));
        assert_eq!(parse_fixed_point("1", 8), Some(100_000_000));
        assert_eq!(parse_fixed_point("0.0", 8), Some(0));
        assert_eq!(parse_fixed_point("-0.1", 8), Some(-10_000_000));
        assert_eq!(parse_fixed_point("1.1", 8), Some(110_000_000));
        assert_eq!(
            parse_fixed_point("1.10000000000000000", 8),
            Some(110_000_000)
        );
        assert_eq!(parse_fixed_point("1.1e1", 8), Some(1_100_000_000));
        assert_eq!(parse_fixed_point("1.1e-1", 8), Some(11_000_000));
        assert_eq!(parse_fixed_point("1000", 8), Some(100_000_000_000));
        assert_eq!(parse_fixed_point("-1000", 8), Some(-100_000_000_000));
        assert_eq!(parse_fixed_point("0.00000001", 8), Some(1));
        assert_eq!(parse_fixed_point("0.0000000100000000", 8), Some(1));
        assert_eq!(parse_fixed_point("-0.00000001", 8), Some(-1));
        assert_eq!(
            parse_fixed_point("1000000000.00000001", 8),
            Some(100_000_000_000_000_001)
        );
        assert_eq!(
            parse_fixed_point("9999999999.99999999", 8),
            Some(999_999_999_999_999_999)
        );
        assert_eq!(
            parse_fixed_point("-9999999999.99999999", 8),
            Some(-999_999_999_999_999_999)
        );

        assert_eq!(parse_fixed_point("", 8), None);
        assert_eq!(parse_fixed_point("-", 8), None);
        assert_eq!(parse_fixed_point("a-1000", 8), None);
        assert_eq!(parse_fixed_point("-a1000", 8), None);
        assert_eq!(parse_fixed_point("-1000a", 8), None);
        assert_eq!(parse_fixed_point("-01000", 8), None);
        assert_eq!(parse_fixed_point("00.1", 8), None);
        assert_eq!(parse_fixed_point(".1", 8), None);
        assert_eq!(parse_fixed_point("--0.1", 8), None);
        assert_eq!(parse_fixed_point("0.000000001", 8), None);
        assert_eq!(parse_fixed_point("-0.000000001", 8), None);
        assert_eq!(parse_fixed_point("0.00000001000000001", 8), None);
        assert_eq!(parse_fixed_point("-10000000000.00000000", 8), None);
        assert_eq!(parse_fixed_point("10000000000.00000000", 8), None);
        assert_eq!(parse_fixed_point("-10000000000.00000001", 8), None);
        assert_eq!(parse_fixed_point("10000000000.00000001", 8), None);
        assert_eq!(parse_fixed_point("-10000000000.00000009", 8), None);
        assert_eq!(parse_fixed_point("10000000000.00000009", 8), None);
        assert_eq!(parse_fixed_point("-99999999999.99999999", 8), None);
        assert_eq!(parse_fixed_point("99999909999.09999999", 8), None);
        assert_eq!(parse_fixed_point("92233720368.54775807", 8), None);
        assert_eq!(parse_fixed_point("92233720368.54775808", 8), None);
        assert_eq!(parse_fixed_point("-92233720368.54775808", 8), None);
        assert_eq!(parse_fixed_point("-92233720368.54775809", 8), None);
        assert_eq!(parse_fixed_point("1.1e", 8), None);
        assert_eq!(parse_fixed_point("1.1e-", 8), None);
        assert_eq!(parse_fixed_point("1.", 8), None);
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

    #[test]
    fn accepts_scientific_notation() {
        // Bitcoin Core's ParseFixedPoint accepts exponent form; these exercise
        // parse_fixed_point's exponent handling end to end.
        let n: Value = serde_json::from_str("1e-5").unwrap(); // 0.00001 ZEC = 1000 zats
        assert_eq!(value_to_zats(&n).unwrap().into_u64(), 1_000);
        let n: Value = serde_json::from_str("1E-8").unwrap(); // 1 zatoshi
        assert_eq!(value_to_zats(&n).unwrap().into_u64(), 1);
        let n: Value = serde_json::from_str("1.5e2").unwrap(); // 150 ZEC
        assert_eq!(value_to_zats(&n).unwrap().into_u64(), 150 * COIN);
        // As a string, too.
        let s = Value::String("2e-3".to_string()); // 0.002 ZEC = 200_000 zats
        assert_eq!(value_to_zats(&s).unwrap().into_u64(), 200_000);
    }

    #[test]
    fn scientific_still_enforces_8dp_and_range() {
        let n: Value = serde_json::from_str("1e-9").unwrap(); // 9 dp -> too fine
        assert!(value_to_zats(&n).is_err());
        let n: Value = serde_json::from_str("1e9").unwrap(); // 1e9 ZEC > 21M cap
        assert!(value_to_zats(&n).is_err());
    }
}
