//! `signmessage` / `verifymessage` - Bitcoin-Core-style message signing with a **transparent**
//! (t-address) key, ported from zallet's implementation so the two agree byte-for-byte.
//!
//! The signed digest is zcashd's: each of the magic string `"Zcash Signed Message:\n"` and the
//! caller's message is CompactSize-length-prefixed, concatenated, and double-SHA256 hashed
//! (`zcash/zcash` `rpc/misc.cpp`). The signature is a recoverable ECDSA signature over that digest
//! serialized as a 65-byte `[header][r||s]` blob (header `31 + recovery_id`, the compressed-pubkey
//! form; `zcash/zcash` `pubkey.cpp`) and base64-encoded.
//!
//! `signmessage` needs the address's private key, which lives in the actor's [`SeedKeeper`], so the
//! RPC handler validates the address and then routes the derive-and-sign to the wallet actor (like
//! a send). `verifymessage` is stateless - it recovers the signer's public key from the signature
//! and compares the resulting transparent address - so it runs entirely at the RPC layer.
//!
//! [`SeedKeeper`]: crate::wallet::keys::SeedKeeper

use std::io::Write as _;

use base64::Engine as _;
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message, Secp256k1,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zcash_encoding::CompactSize;
use zcash_keys::encoding::AddressCodec;
use zcash_protocol::consensus::Parameters;
use zcash_transparent::address::TransparentAddress;

use crate::error::RpcError;
use crate::server::jsonrpc::RpcRequest;
use crate::state::AppState;

/// The magic prefix zcashd/zecd/zallet mix into every signed message so a signature over user text
/// can never be replayed as a signature over a transaction (`zcash/zcash` `main.cpp`).
const MESSAGE_MAGIC: &str = "Zcash Signed Message:\n";

/// The message digest that is signed/verified: `CompactSize(magic) || magic || CompactSize(msg) ||
/// msg`, double-SHA256 hashed. Byte-identical to zcashd's `rpc/misc.cpp` and zallet.
pub(crate) fn message_hash(message: &str) -> [u8; 32] {
    let mut preimage: Vec<u8> = Vec::new();

    CompactSize::write(&mut preimage, MESSAGE_MAGIC.len()).expect("write to Vec is infallible");
    preimage
        .write_all(MESSAGE_MAGIC.as_bytes())
        .expect("write to Vec is infallible");

    CompactSize::write(&mut preimage, message.len()).expect("write to Vec is infallible");
    preimage
        .write_all(message.as_bytes())
        .expect("write to Vec is infallible");

    let first = Sha256::digest(&preimage);
    let second = Sha256::digest(first);
    second.into()
}

/// Sign `message` with `secret_key`, returning the base64-encoded 65-byte recoverable signature
/// (header byte `31 + recovery_id`, then the 64-byte compact `r||s`). The signature is
/// deterministic (RFC 6979), so a given (key, message) always yields the same string.
pub(crate) fn sign_message_with_key(secret_key: &secp256k1::SecretKey, message: &str) -> String {
    let hash = message_hash(message);
    let secp = Secp256k1::new();
    let msg = Message::from_digest_slice(&hash).expect("message_hash always returns 32 bytes");

    let recoverable_sig = secp.sign_ecdsa_recoverable(&msg, secret_key);
    let (recovery_id, sig_bytes) = recoverable_sig.serialize_compact();

    // Header byte is 31 + recovery_id for compressed-pubkey signatures.
    // <https://github.com/zcash/zcash/blob/v6.11.0/src/pubkey.cpp#L227>
    let header = 31 + recovery_id.to_i32() as u8;
    let mut signature = [0u8; 65];
    signature[0] = header;
    signature[1..65].copy_from_slice(&sig_bytes);

    base64::engine::general_purpose::STANDARD.encode(signature)
}

/// Verify that `signature` (base64) is a valid message signature for the transparent address
/// `zcashaddress` over `message`. Returns `Ok(true)`/`Ok(false)` for a well-formed check, or an
/// `RpcError` for a malformed address/signature - matching zallet's error contract.
pub(crate) fn verify_message<P: Parameters>(
    params: &P,
    zcashaddress: &str,
    signature: &str,
    message: &str,
) -> Result<bool, RpcError> {
    let transparent_addr = TransparentAddress::decode(params, zcashaddress)
        .map_err(|_| RpcError::type_error("Invalid address"))?;

    if matches!(transparent_addr, TransparentAddress::ScriptHash(_)) {
        return Err(RpcError::type_error("Address does not refer to key"));
    }

    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature)
        .map_err(|_| RpcError::invalid_address_or_key("Malformed base64 encoding"))?;

    if sig_bytes.len() != 65 {
        return Ok(false);
    }

    // Signature header byte (zcashd `pubkey.cpp`): 27-30 = uncompressed pubkey, 31-34 = compressed.
    let header = sig_bytes[0];
    if (27..=30).contains(&header) {
        return Err(RpcError::type_error(
            "Uncompressed key signatures are not supported.",
        ));
    }
    if !(31..=34).contains(&header) {
        return Ok(false);
    }
    let recovery_id = ((header - 27) & 3) as i32;

    let hash = message_hash(message);
    let secp = Secp256k1::new();

    let Ok(recid) = RecoveryId::from_i32(recovery_id) else {
        return Ok(false);
    };
    let Ok(recoverable_sig) = RecoverableSignature::from_compact(&sig_bytes[1..65], recid) else {
        return Ok(false);
    };
    let Ok(msg) = Message::from_digest_slice(&hash) else {
        return Ok(false);
    };
    let Ok(recovered_pubkey) = secp.recover_ecdsa(&msg, &recoverable_sig) else {
        return Ok(false);
    };

    let recovered_addr = TransparentAddress::from_pubkey(&recovered_pubkey);
    Ok(recovered_addr == transparent_addr)
}

/// `signmessage "t-address" "message"` - sign `message` with the private key of a transparent
/// address the wallet owns, returning the base64 signature (Bitcoin Core's shape). Requires an
/// unlocked, spending wallet: a locked wallet returns `-13`, a watch-only wallet `-4`, and an
/// address the wallet doesn't own `-4`.
pub(crate) async fn signmessage(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let t_addr = req.require_str(0, "signmessage requires a transparent address")?;
    let message = req.require_str(1, "signmessage requires a message")?;

    let handle = state.registry.get(wallet)?.clone();

    // Validate the address up front (network-aware), so a bad address is `-5`/`-3` regardless of
    // wallet lock state - before the seed is ever touched.
    let addr = TransparentAddress::decode(&handle.network, t_addr)
        .map_err(|_| RpcError::invalid_address_or_key("Invalid Zcash transparent address"))?;
    if matches!(addr, TransparentAddress::ScriptHash(_)) {
        return Err(RpcError::type_error("Address does not refer to key"));
    }

    let signature = handle.sign_message(addr, message.to_string()).await?;
    Ok(Value::String(signature))
}

/// `verifymessage "t-address" "signature" "message"` - check a message signature against a
/// transparent address. Stateless (no wallet key material needed); only the wallet's network
/// parameters are used to decode the address.
pub(crate) fn verifymessage(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let address = req.require_str(0, "verifymessage requires a transparent address")?;
    let signature = req.require_str(1, "verifymessage requires a signature")?;
    let message = req.require_str(2, "verifymessage requires a message")?;

    let handle = state.registry.get(wallet)?;
    let verified = verify_message(&handle.network, address, signature, message)?;
    Ok(Value::Bool(verified))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::codes;
    use crate::network::ZNetwork;

    fn mainnet() -> ZNetwork {
        ZNetwork::Main
    }

    // A real signed message found on the Zcash Community Forum - the same vector zallet pins for
    // its `verifymessage` test.
    const TEST_ADDRESS: &str = "t1VydNnkjBzfL1iAMyUbwGKJAF7PgvuCfMY";
    const TEST_SIGNATURE: &str =
        "H3RY+6ZfWUbzaaXxK8I42thf+f3tOrwKP2elphxAxq8tKypwJG4+V7EGR+sTWMZ5MFyvTQW8ZIV0yGU+93JTioA=";
    const TEST_MESSAGE: &str =
        "20251117: 1 Yay; 2 Yay; 3 Yay; 4 Yay; 5 Nay; 6 Nay; 7 Yay; 8 Yay; 9 Nay";

    /// A random secp256k1 keypair, for the sign→verify round-trips.
    fn test_keypair() -> (secp256k1::SecretKey, secp256k1::PublicKey) {
        use rand::RngCore;
        let secp = Secp256k1::new();
        let mut secret_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret_bytes);
        let secret_key = secp256k1::SecretKey::from_slice(&secret_bytes)
            .expect("32 random bytes should be a valid secret key");
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
        (secret_key, public_key)
    }

    // ---- verify_message against the real forum vector (mirrors zallet's verify_message tests) ----

    #[test]
    fn verify_valid_signature() {
        let verified = verify_message(&mainnet(), TEST_ADDRESS, TEST_SIGNATURE, TEST_MESSAGE)
            .expect("verification should succeed");
        assert!(verified, "Valid signature should verify successfully");
    }

    #[test]
    fn verify_wrong_message_fails() {
        let verified = verify_message(&mainnet(), TEST_ADDRESS, TEST_SIGNATURE, "wrongmessage")
            .expect("verification call should succeed");
        assert!(!verified, "Wrong message should fail verification");
    }

    #[test]
    fn verify_wrong_address_fails() {
        let verified = verify_message(
            &mainnet(),
            "t1VtArtnn1dGPiD2WFfMXYXW5mHM3q1GpgV",
            TEST_SIGNATURE,
            TEST_MESSAGE,
        )
        .expect("verification call should succeed");
        assert!(!verified, "Wrong address should fail verification");
    }

    #[test]
    fn verify_invalid_address_returns_error() {
        let err = verify_message(
            &mainnet(),
            "t1VtArtnn1dGPiD2WFfMXYXW5mHM3q1Gpg",
            TEST_SIGNATURE,
            TEST_MESSAGE,
        )
        .expect_err("an undecodable address is an error");
        assert_eq!(err.code, codes::RPC_TYPE_ERROR);
        assert_eq!(err.message, "Invalid address");
    }

    #[test]
    fn verify_malformed_base64_returns_error() {
        let err = verify_message(&mainnet(), TEST_ADDRESS, "not_base64!!!", TEST_MESSAGE)
            .expect_err("malformed base64 is an error");
        assert_eq!(err.code, codes::RPC_INVALID_ADDRESS_OR_KEY);
        assert_eq!(err.message, "Malformed base64 encoding");
    }

    #[test]
    fn verify_script_address_returns_error() {
        let err = verify_message(
            &mainnet(),
            "t3Vz22vK5z2LcKEdg16Yv4FFneEL1zg9ojd",
            TEST_SIGNATURE,
            TEST_MESSAGE,
        )
        .expect_err("a P2SH address does not refer to a key");
        assert_eq!(err.code, codes::RPC_TYPE_ERROR);
        assert_eq!(err.message, "Address does not refer to key");
    }

    #[test]
    fn verify_uncompressed_key_returns_error() {
        let mut sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(TEST_SIGNATURE)
            .unwrap();
        sig_bytes[0] = 27;
        let uncompressed_sig = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);

        let err = verify_message(&mainnet(), TEST_ADDRESS, &uncompressed_sig, TEST_MESSAGE)
            .expect_err("uncompressed-key signatures are rejected");
        assert_eq!(err.code, codes::RPC_TYPE_ERROR);
        assert_eq!(
            err.message,
            "Uncompressed key signatures are not supported."
        );
    }

    #[test]
    fn verify_wrong_signature_length_returns_false() {
        // Valid base64 but the wrong length (too short) verifies false, not an error.
        let verified = verify_message(&mainnet(), TEST_ADDRESS, "AAAA", TEST_MESSAGE)
            .expect("call should succeed");
        assert!(!verified, "Wrong signature length should return false");
    }

    // ---- sign_message_with_key round-trips (mirrors zallet's sign_message tests) ----

    #[test]
    fn sign_and_verify_roundtrip() {
        let (secret_key, public_key) = test_keypair();
        let address = TransparentAddress::from_pubkey(&public_key).encode(&mainnet());

        let message = "Test message for signing";
        let signature = sign_message_with_key(&secret_key, message);

        let verified =
            verify_message(&mainnet(), &address, &signature, message).expect("verify should run");
        assert!(verified, "a freshly-signed message should verify");
    }

    #[test]
    fn sign_verify_wrong_message_fails() {
        let (secret_key, public_key) = test_keypair();
        let address = TransparentAddress::from_pubkey(&public_key).encode(&mainnet());

        let signature = sign_message_with_key(&secret_key, "Original message");
        let verified = verify_message(&mainnet(), &address, &signature, "Different message")
            .expect("verify should run");
        assert!(
            !verified,
            "signature should not verify against a different message"
        );
    }

    #[test]
    fn sign_verify_wrong_address_fails() {
        let (secret_key, _public_key) = test_keypair();
        let (_other_secret, other_public) = test_keypair();
        let wrong_address = TransparentAddress::from_pubkey(&other_public).encode(&mainnet());

        let signature = sign_message_with_key(&secret_key, "Test message");
        let verified = verify_message(&mainnet(), &wrong_address, &signature, "Test message")
            .expect("verify should run");
        assert!(
            !verified,
            "signature should not verify against a different address"
        );
    }

    /// The signature is deterministic (RFC 6979): signing the same message with the same key twice
    /// yields byte-identical output. This is what lets a caller reproduce a published signature.
    #[test]
    fn signing_is_deterministic() {
        let (secret_key, _public_key) = test_keypair();
        let a = sign_message_with_key(&secret_key, TEST_MESSAGE);
        let b = sign_message_with_key(&secret_key, TEST_MESSAGE);
        assert_eq!(a, b);
        // 65 bytes base64-encodes to 88 characters (one '=' pad).
        assert_eq!(a.len(), 88);
    }
}
