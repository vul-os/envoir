//! Algorithm suites & crypto-agility — spec §1.1, §16.7.
//!
//! Every signed/encrypted object carries a `suite` identifier. Implementations MUST reject
//! unknown suites (**fail closed**) and never guess. `suites` on an [`crate::identity::Identity`]
//! is a *set* (§1.3), so an identity can hold classical and PQ keys simultaneously during
//! migration.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A DMTAP algorithm suite (spec §1.1).
///
/// | `suite` | Sign | KEM | AEAD | Hash | Status |
/// |--------:|------|-----|------|------|--------|
/// | `0x01`  | Ed25519 | X25519 (HPKE) | ChaCha20-Poly1305 | BLAKE3-256 | v0 REQUIRED |
/// | `0x02`  | Ed25519+ML-DSA-65 | X-Wing (X25519+ML-KEM-768) | ChaCha20-Poly1305 | BLAKE3-256 | RESERVED (PQ) |
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Suite {
    /// v0 REQUIRED: Ed25519 sign, HPKE DHKEM(X25519)/HKDF-SHA256/ChaCha20-Poly1305.
    Classical = 0x01,
    /// RESERVED (PQ): Ed25519+ML-DSA-65 sign, X-Wing (X25519 + ML-KEM-768) KEM.
    ///
    /// The signing/KEM primitives for this suite are not implemented in the reference core;
    /// verification of a `0x02`-only object therefore fails closed (see
    /// [`crate::identity::Identity::verify`]).
    PqHybrid = 0x02,
}

impl Suite {
    /// Decode a suite byte, **failing closed** on any unknown value (spec §1.1).
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Suite::Classical),
            0x02 => Some(Suite::PqHybrid),
            _ => None, // unknown suite — reject, never guess
        }
    }

    /// The on-the-wire byte for this suite.
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Whether the reference core can actually validate signatures for this suite.
    /// `0x02` (PQ) is reserved and unimplemented, so it returns `false` (fail closed).
    pub fn is_supported(self) -> bool {
        matches!(self, Suite::Classical)
    }
}

// Serialize as a single CBOR unsigned integer (the suite byte), and fail closed on decode.
impl Serialize for Suite {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u8(self.as_u8())
    }
}

impl<'de> Deserialize<'de> for Suite {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let b = u8::deserialize(d)?;
        Suite::from_u8(b).ok_or_else(|| serde::de::Error::custom(format!("unknown suite 0x{b:02x}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_u8_fails_closed() {
        assert_eq!(Suite::from_u8(0x01), Some(Suite::Classical));
        assert_eq!(Suite::from_u8(0x02), Some(Suite::PqHybrid));
        // Every other byte MUST be rejected.
        for b in [0x00u8, 0x03, 0x7f, 0xff] {
            assert_eq!(Suite::from_u8(b), None, "byte 0x{b:02x} must fail closed");
        }
    }

    #[test]
    fn cbor_rejects_unknown_suite() {
        // A CBOR integer 0x05 must not deserialize into a Suite.
        let mut buf = Vec::new();
        ciborium::into_writer(&5u8, &mut buf).unwrap();
        let r: Result<Suite, _> = ciborium::from_reader(&buf[..]);
        assert!(r.is_err(), "unknown suite byte must fail closed on decode");
    }

    #[test]
    fn only_classical_is_supported() {
        assert!(Suite::Classical.is_supported());
        assert!(!Suite::PqHybrid.is_supported());
    }
}
