//! Content addressing — spec §2.2.
//!
//! A content address is a **1-byte multihash-style algorithm prefix** followed by the digest.
//! v0 default is **BLAKE3-256**; the agility prefix lets an implementation migrate to
//! SHA-256/SHA-3 where compliance requires it without changing the address format
//! (spec §2.2). Content addressing gives dedup, integrity, and cacheability for free —
//! identical ciphertext shares an `id`.

use serde::{Deserialize, Serialize};

/// Multihash-style algorithm code for BLAKE3 (256-bit output). Matches the multiformats
/// registry value for `blake3`.
pub const MH_BLAKE3_256: u8 = 0x1e;

/// A content address: a 1-byte hash-algorithm prefix followed by the digest (spec §2.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentId(#[serde(with = "serde_bytes")] pub Vec<u8>);

// `serde_bytes` shim: encode `Vec<u8>` as a CBOR byte string (not an array of ints), so
// content ids are compact and round-trip byte-for-byte.
mod serde_bytes {
    use serde::{Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a byte string")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
                Ok(v.to_vec())
            }
            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(v)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut a: A) -> Result<Vec<u8>, A::Error> {
                let mut out = Vec::new();
                while let Some(b) = a.next_element::<u8>()? {
                    out.push(b);
                }
                Ok(out)
            }
        }
        d.deserialize_bytes(V)
    }
}

impl ContentId {
    /// Compute the v0 content address of `bytes`: `[0x1e] || BLAKE3-256(bytes)` (spec §2.2).
    pub fn of(bytes: &[u8]) -> ContentId {
        let digest = blake3::hash(bytes); // 32-byte BLAKE3-256
        let mut v = Vec::with_capacity(33);
        v.push(MH_BLAKE3_256);
        v.extend_from_slice(digest.as_bytes());
        ContentId(v)
    }

    /// The multihash algorithm-prefix byte, or `None` if the id is empty.
    pub fn algorithm(&self) -> Option<u8> {
        self.0.first().copied()
    }

    /// The digest (everything after the 1-byte prefix).
    pub fn digest(&self) -> &[u8] {
        self.0.get(1..).unwrap_or(&[])
    }

    /// Verify that this id is the content address of `bytes`. **Fails closed** on an unknown
    /// algorithm prefix or a wrong-length digest rather than guessing (spec §2.2).
    pub fn verify(&self, bytes: &[u8]) -> bool {
        match self.algorithm() {
            Some(MH_BLAKE3_256) if self.digest().len() == 32 => {
                blake3::hash(bytes).as_bytes() == self.digest()
            }
            _ => false, // unknown/other hash algorithm not supported by v0 — fail closed
        }
    }

    /// Raw bytes of the content id (prefix + digest).
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_verifies_and_detects_tamper() {
        let data = b"the atomic unit of DMTAP";
        let id = ContentId::of(data);
        assert_eq!(id.algorithm(), Some(MH_BLAKE3_256));
        assert_eq!(id.digest().len(), 32);
        assert!(id.verify(data));
        assert!(!id.verify(b"tampered"), "any change must fail verification");
    }

    #[test]
    fn identical_bytes_share_an_id() {
        assert_eq!(ContentId::of(b"dup"), ContentId::of(b"dup"));
        assert_ne!(ContentId::of(b"a"), ContentId::of(b"b"));
    }

    #[test]
    fn unknown_prefix_fails_closed() {
        let mut bad = ContentId::of(b"x");
        bad.0[0] = 0x99; // unknown algorithm prefix
        assert!(!bad.verify(b"x"), "unknown hash prefix must fail closed");
    }
}
