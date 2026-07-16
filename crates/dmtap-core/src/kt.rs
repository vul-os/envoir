//! Key-transparency objects — spec §3.5, §18.4.9 / §18.4.10 / §18.4.11, §18.9.13.
//!
//! DMTAP's KT is an **RFC 6962-profiled** append-only Merkle log. This module models its three
//! wire objects:
//!
//! - [`SignedTreeHead`] — the signed tree head (STH) a verifier fetches, gossips, and freshness-
//!   checks. It is signed **by the log's own key** (`log_id`, field 2), not by any DMTAP identity
//!   (§18.9.13, DS-tag `DMTAP-v0/kt-sth`).
//! - [`InclusionProof`] — an RFC 6962 Merkle audit path proving a `leaf_hash` sits at `leaf_index`
//!   of the tree an STH commits to. **Unsigned** — verified arithmetically against the STH root.
//! - [`ConsistencyProof`] — an RFC 6962 consistency proof that one STH's tree is an append-only
//!   prefix of a later STH's. **Unsigned.**
//!
//! The **Identity-entry leaf-hash rule** (§18.4.9) is [`identity_leaf_hash`]: a leaf commits to the
//! *exact* `[name, ik, version, identity_id]` tuple so the log **indexes** bindings, never
//! redefines them. All objects are integer-keyed canonical CBOR (§18.1.2).

use crate::cbor::{self, as_array, as_bytes, as_u64, as_u8, CborError, Cv, Fields};
use crate::id::{ContentId, MH_BLAKE3_256};
use crate::identity::{verify_domain, IdentityError, IdentityKey};
use crate::suite::Suite;
use crate::TimestampMs;

/// §18.9.13 domain-separation tag (ASCII ‖ trailing `0x00`; `sign_domain` prepends it).
pub const KT_STH_DS: &[u8] = b"DMTAP-v0/kt-sth\x00";

fn suite_from_cv(cv: Cv) -> Result<Suite, CborError> {
    let b = as_u8(cv)?;
    Suite::from_u8(b).ok_or(CborError::UnknownSuite(b))
}

/// The Identity-entry **leaf-hash** (§18.4.9 / §18.9.13):
/// `0x1e ‖ BLAKE3-256( 0x00 ‖ det_cbor([ name, ik, version, identity_id ]) )`, using the RFC 6962
/// leaf prefix `0x00`. A verifier recomputes this from the pinned/resolved `Identity` and MUST
/// reject a proof whose committed leaf differs (`ERR_KT_LEAF_HASH_MISMATCH`, `0x0117`).
/// `RecoveryPolicy`/`KeyRotation`/`MoveRecord` leaves use the same rule with their own content
/// address in place of `identity_id`.
pub fn identity_leaf_hash(
    name: &str,
    ik: &[u8],
    version: u64,
    identity_id: &ContentId,
) -> ContentId {
    let leaf_data = cbor::encode(&Cv::Array(vec![
        Cv::Text(name.to_owned()),
        Cv::Bytes(ik.to_vec()),
        Cv::U64(version),
        Cv::Bytes(identity_id.as_bytes().to_vec()),
    ]));
    let mut buf = Vec::with_capacity(1 + leaf_data.len());
    buf.push(0x00); // RFC 6962 leaf prefix
    buf.extend_from_slice(&leaf_data);
    let digest = blake3::hash(&buf);
    let mut v = Vec::with_capacity(33);
    v.push(MH_BLAKE3_256);
    v.extend_from_slice(digest.as_bytes());
    ContentId(v)
}

// --- SignedTreeHead (§18.4.9) --------------------------------------------------------------

/// The signed tree head of a KT log (§18.4.9). Signed by the log's own key (`log_id`), versioned
/// by `tree_size` (§18.9.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTreeHead {
    pub suite: Suite,          // key 1
    pub log_id: Vec<u8>,       // key 2 — the log's public signing key (the log IS its key)
    pub tree_size: u64,        // key 3 — number of log entries (RFC 6962 tree size)
    pub timestamp: TimestampMs, // key 4 — STH issuance time (freshness / MMD)
    pub root_hash: ContentId,  // key 5 — RFC 6962 Merkle Tree Hash (prefix ‖ digest)
    pub sig: Vec<u8>,          // key 6 — §18.9.13, over det_cbor(STH ∖ {6}) under log_id
}

impl SignedTreeHead {
    /// Integer-keyed canonical map (§18.4.9). `include_sig=false` omits key 6 for the §18.9.13
    /// signing body.
    fn to_cv(&self, include_sig: bool) -> Cv {
        let mut m = vec![
            (1u64, Cv::U64(self.suite.as_u8() as u64)),
            (2, Cv::Bytes(self.log_id.clone())),
            (3, Cv::U64(self.tree_size)),
            (4, Cv::U64(self.timestamp)),
            (5, Cv::Bytes(self.root_hash.as_bytes().to_vec())),
        ];
        if include_sig {
            m.push((6, Cv::Bytes(self.sig.clone())));
        }
        Cv::Map(m)
    }

    /// The exact wire bytes: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(true))
    }

    /// The §18.9.13 signing body: deterministic CBOR of the STH with `sig` (key 6) omitted.
    pub fn signing_body(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(false))
    }

    /// Decode an STH (§18.4.9), failing closed on any violation.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let suite = suite_from_cv(f.req(1)?)?;
        let log_id = as_bytes(f.req(2)?)?;
        let tree_size = as_u64(f.req(3)?)?;
        let timestamp = as_u64(f.req(4)?)?;
        let root_hash = ContentId(as_bytes(f.req(5)?)?);
        let sig = as_bytes(f.req(6)?)?;
        f.deny_unknown()?;
        Ok(SignedTreeHead { suite, log_id, tree_size, timestamp, root_hash, sig })
    }

    /// Sign an STH with the log's key (§18.9.13); `log_id` is set from the signer.
    pub fn issue(
        log_key: &IdentityKey,
        tree_size: u64,
        timestamp: TimestampMs,
        root_hash: ContentId,
    ) -> SignedTreeHead {
        let mut s = SignedTreeHead {
            suite: Suite::Classical,
            log_id: log_key.public(),
            tree_size,
            timestamp,
            root_hash,
            sig: Vec::new(),
        };
        s.sig = log_key.sign_domain(KT_STH_DS, &s.signing_body());
        s
    }

    /// Verify the STH signature under `log_id` (§18.9.13). Failure ⇒ `ERR_KT_PROOF_INVALID`.
    pub fn verify(&self) -> Result<(), IdentityError> {
        if !self.suite.is_supported() {
            return Err(IdentityError::UnsupportedSuite(self.suite.as_u8()));
        }
        verify_domain(&self.log_id, KT_STH_DS, &self.signing_body(), &self.sig)
    }
}

// --- InclusionProof (§18.4.10) -------------------------------------------------------------

/// An RFC 6962 Merkle audit path (§18.4.10). **Unsigned** — verified against an STH `root_hash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    pub tree_size: u64,          // key 1 — the STH tree_size this path reconstructs to
    pub leaf_index: u64,         // key 2 — 0-based index of the leaf (< tree_size)
    pub leaf_hash: ContentId,    // key 3 — the leaf being proven (§18.4.9 rule)
    pub audit_path: Vec<ContentId>, // key 4 — sibling hashes bottom-to-top; MAY be empty
}

impl InclusionProof {
    fn to_cv(&self) -> Cv {
        Cv::Map(vec![
            (1, Cv::U64(self.tree_size)),
            (2, Cv::U64(self.leaf_index)),
            (3, Cv::Bytes(self.leaf_hash.as_bytes().to_vec())),
            (4, Cv::Array(self.audit_path.iter().map(|h| Cv::Bytes(h.as_bytes().to_vec())).collect())),
        ])
    }

    /// The exact wire bytes: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv())
    }

    /// Decode an inclusion proof (§18.4.10), failing closed on any violation.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let tree_size = as_u64(f.req(1)?)?;
        let leaf_index = as_u64(f.req(2)?)?;
        let leaf_hash = ContentId(as_bytes(f.req(3)?)?);
        let audit_path = as_array(f.req(4)?)?
            .into_iter()
            .map(|c| as_bytes(c).map(ContentId))
            .collect::<Result<_, _>>()?;
        f.deny_unknown()?;
        Ok(InclusionProof { tree_size, leaf_index, leaf_hash, audit_path })
    }
}

// --- ConsistencyProof (§18.4.11) -----------------------------------------------------------

/// An RFC 6962 consistency proof that an earlier STH's tree is a prefix of a later one's
/// (§18.4.11). **Unsigned** — verified against the two STH roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsistencyProof {
    pub first_size: u64,          // key 1 — earlier tree size (≤ second_size)
    pub second_size: u64,         // key 2 — later tree size
    pub proof_path: Vec<ContentId>, // key 3 — RFC 6962 consistency nodes; MAY be empty
}

impl ConsistencyProof {
    fn to_cv(&self) -> Cv {
        Cv::Map(vec![
            (1, Cv::U64(self.first_size)),
            (2, Cv::U64(self.second_size)),
            (3, Cv::Array(self.proof_path.iter().map(|h| Cv::Bytes(h.as_bytes().to_vec())).collect())),
        ])
    }

    /// The exact wire bytes: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv())
    }

    /// Decode a consistency proof (§18.4.11), failing closed on any violation.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let first_size = as_u64(f.req(1)?)?;
        let second_size = as_u64(f.req(2)?)?;
        let proof_path = as_array(f.req(3)?)?
            .into_iter()
            .map(|c| as_bytes(c).map(ContentId))
            .collect::<Result<_, _>>()?;
        f.deny_unknown()?;
        Ok(ConsistencyProof { first_size, second_size, proof_path })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> IdentityKey {
        IdentityKey::from_seed(&[seed; 32])
    }

    #[test]
    fn sth_signs_verifies_and_round_trips() {
        let sth = SignedTreeHead::issue(
            &key(0x11),
            7,
            1_700_000_000_000,
            ContentId::of(b"kt-root"),
        );
        assert!(sth.verify().is_ok());
        let bytes = sth.det_cbor();
        assert_eq!(bytes[0] & 0xe0, 0xa0, "STH is a CBOR map");
        assert_eq!(bytes[1], 0x01, "first key is integer 1 (suite), not a text key");
        let back = SignedTreeHead::from_det_cbor(&bytes).unwrap();
        assert_eq!(sth, back);
        assert_eq!(bytes, back.det_cbor());
        assert!(back.verify().is_ok());
    }

    #[test]
    fn tampered_sth_fails_signature() {
        let mut sth = SignedTreeHead::issue(&key(0x11), 7, 1, ContentId::of(b"kt-root"));
        sth.tree_size = 8; // signed field changed
        assert_eq!(sth.verify(), Err(IdentityError::BadSignature));
    }

    #[test]
    fn inclusion_proof_round_trips() {
        let p = InclusionProof {
            tree_size: 5,
            leaf_index: 2,
            leaf_hash: ContentId::of(b"leaf"),
            audit_path: vec![ContentId::of(b"s0"), ContentId::of(b"s1")],
        };
        let bytes = p.det_cbor();
        let back = InclusionProof::from_det_cbor(&bytes).unwrap();
        assert_eq!(p, back);
        assert_eq!(bytes, back.det_cbor());
    }

    #[test]
    fn consistency_proof_round_trips_including_empty_path() {
        let p = ConsistencyProof { first_size: 3, second_size: 7, proof_path: vec![] };
        let bytes = p.det_cbor();
        let back = ConsistencyProof::from_det_cbor(&bytes).unwrap();
        assert_eq!(p, back);
        assert_eq!(bytes, back.det_cbor());
    }

    #[test]
    fn identity_leaf_hash_is_prefixed_and_deterministic() {
        let ik = key(0x22).public();
        let id = ContentId::of(b"the-identity");
        let a = identity_leaf_hash("alice@abc.com", &ik, 3, &id);
        let b = identity_leaf_hash("alice@abc.com", &ik, 3, &id);
        assert_eq!(a, b, "leaf hash is a pure function of the tuple");
        assert_eq!(a.algorithm(), Some(MH_BLAKE3_256));
        assert_eq!(a.digest().len(), 32);
        // Any change to the tuple changes the leaf.
        assert_ne!(a, identity_leaf_hash("alice@abc.com", &ik, 4, &id));
    }
}
