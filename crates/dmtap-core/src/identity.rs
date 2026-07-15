//! Identity lifecycle — spec §1.
//!
//! Key is identity; domain/IP/provider are replaceable pointers. Every lifecycle operation
//! ([`Identity`], [`DeviceCert`], [`RecoveryPolicy`], [`MoveRecord`]) is a **signed, versioned
//! object** (§1.7). This module implements the classical suite (`0x01`, Ed25519). The
//! `Identity` object holds `suites` as a *set* with a per-suite key map and a per-suite
//! signature list (§1.3), so it is shaped for the PQ transition even though the reference core
//! only validates the classical suite (the PQ suite `0x02` fails closed in [`Identity::verify`],
//! per §1.3's "reject rather than fall back silently").

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::id::ContentId;
use crate::suite::Suite;
use crate::TimestampMs;

/// Domain-separation label mixed into every signature this module produces, so a signature
/// over one object type can never be replayed as another.
const SIG_CONTEXT: &[u8] = b"dmtap-identity-v0";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdentityError {
    #[error("signature verification failed")]
    BadSignature,
    #[error("hash chain is broken or inconsistent with the pinned anchor")]
    BrokenChain,
    #[error("suite {0:#04x} is not supported by this implementation (fail closed)")]
    UnsupportedSuite(u8),
    #[error("identity is malformed: {0}")]
    Malformed(&'static str),
    #[error("key or signature had the wrong length")]
    BadKeyLength,
}

// --- low-level Ed25519 helpers -------------------------------------------------------------

fn verifying_key(bytes: &[u8]) -> Result<VerifyingKey, IdentityError> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| IdentityError::BadKeyLength)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| IdentityError::BadKeyLength)
}

fn signature(bytes: &[u8]) -> Result<Signature, IdentityError> {
    let arr: [u8; 64] = bytes.try_into().map_err(|_| IdentityError::BadKeyLength)?;
    Ok(Signature::from_bytes(&arr))
}

/// Sign `msg` (with the module's domain-separation context) under `sk`, returning raw bytes.
fn ed25519_sign(sk: &SigningKey, msg: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIG_CONTEXT.len() + msg.len());
    m.extend_from_slice(SIG_CONTEXT);
    m.extend_from_slice(msg);
    sk.sign(&m).to_bytes().to_vec()
}

fn ed25519_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), IdentityError> {
    let vk = verifying_key(pk)?;
    let sig = signature(sig)?;
    let mut m = Vec::with_capacity(SIG_CONTEXT.len() + msg.len());
    m.extend_from_slice(SIG_CONTEXT);
    m.extend_from_slice(msg);
    vk.verify(&m, &sig).map_err(|_| IdentityError::BadSignature)
}

fn cbor(value: &impl Serialize) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).expect("CBOR serialization is infallible for these types");
    buf
}

// --- Root identity key (classical) ---------------------------------------------------------

/// A classical (suite `0x01`) root identity key `IK` (spec §1.2) — an Ed25519 signing keypair.
///
/// In production `IK` is offline/cold-custody and used rarely; day-to-day signing uses device
/// subkeys ([`DeviceCert`]). This wrapper keeps the reference API ergonomic.
pub struct IdentityKey {
    signing: SigningKey,
}

impl IdentityKey {
    /// Generate a fresh `IK` from the OS CSPRNG.
    pub fn generate() -> Self {
        IdentityKey { signing: SigningKey::generate(&mut OsRng) }
    }

    /// Reconstruct from a 32-byte Ed25519 seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        IdentityKey { signing: SigningKey::from_bytes(seed) }
    }

    /// The public half — the stable DMTAP address key correspondents pin (§1.2).
    pub fn public(&self) -> Vec<u8> {
        self.signing.verifying_key().to_bytes().to_vec()
    }

    /// The 32-byte public key as an array.
    pub fn public_array(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    fn signing(&self) -> &SigningKey {
        &self.signing
    }

    /// Sign `msg` under this key with an explicit domain-separation label. Used by the MOTE
    /// layer for `Payload.sig` and (via an ephemeral key) the envelope `sender_sig` (§2).
    pub fn sign_domain(&self, domain: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut m = Vec::with_capacity(domain.len() + msg.len());
        m.extend_from_slice(domain);
        m.extend_from_slice(msg);
        self.signing.sign(&m).to_bytes().to_vec()
    }
}

/// Verify an Ed25519 signature produced with [`IdentityKey::sign_domain`] under public key
/// `pk`. Fails closed on any malformed key/signature or a bad signature.
pub fn verify_domain(pk: &[u8], domain: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), IdentityError> {
    let vk = verifying_key(pk)?;
    let sig = signature(sig)?;
    let mut m = Vec::with_capacity(domain.len() + msg.len());
    m.extend_from_slice(domain);
    m.extend_from_slice(msg);
    vk.verify(&m, &sig).map_err(|_| IdentityError::BadSignature)
}

// --- Device capabilities & certs -----------------------------------------------------------

/// Device capabilities (spec §1.2). `caps` gates what a device *may participate in*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Cap {
    Send,
    Recv,
    Relay,
    Mix,
    Gateway,
    /// Elevated, but never sufficient alone to rewrite recovery policy (§1.2).
    Admin,
}

/// A per-device signing subkey, signed by the root identity key (spec §1.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCert {
    pub suite: Suite,
    pub ik: Vec<u8>,         // root identity public key
    pub device_key: Vec<u8>, // device signing public key
    pub label: String,       // "phone", "home-box", ...
    pub created: TimestampMs,
    pub expires: Option<TimestampMs>,
    pub caps: Vec<Cap>,
    #[serde(default)]
    pub sig: Vec<u8>, // IK over the CBOR-encoded fields above
}

impl DeviceCert {
    /// Bytes signed by `IK`: the whole cert with `sig` cleared.
    fn signing_bytes(&self) -> Vec<u8> {
        let mut c = self.clone();
        c.sig = Vec::new();
        cbor(&c)
    }

    /// Issue a device cert: `IK` signs the (suite, ik, device_key, label, …) tuple (§1.2).
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        ik: &IdentityKey,
        device_key: Vec<u8>,
        label: impl Into<String>,
        created: TimestampMs,
        expires: Option<TimestampMs>,
        caps: Vec<Cap>,
    ) -> DeviceCert {
        let mut cert = DeviceCert {
            suite: Suite::Classical,
            ik: ik.public(),
            device_key,
            label: label.into(),
            created,
            expires,
            caps,
            sig: Vec::new(),
        };
        cert.sig = ed25519_sign(ik.signing(), &cert.signing_bytes());
        cert
    }

    /// Verify the cert's signature under its own `ik` (spec §1.2).
    pub fn verify(&self) -> Result<(), IdentityError> {
        if !self.suite.is_supported() {
            return Err(IdentityError::UnsupportedSuite(self.suite.as_u8()));
        }
        ed25519_verify(&self.ik, &self.signing_bytes(), &self.sig)
    }
}

// --- The published Identity object ---------------------------------------------------------

/// The current public identity (spec §1.3) — a signed, versioned object whose hash is the
/// anchor everyone pins. `suites` is a preference-ordered *set*; `iks` maps each suite to its
/// public key; `sig` carries one signature per suite (multi-suite, §1.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub suites: Vec<Suite>,          // algorithm suites this identity supports (preference order)
    pub iks: BTreeMap<u8, Vec<u8>>,  // identity public key per suite
    pub version: u64,                // monotonically increasing
    pub devices: Vec<DeviceCert>,
    pub keypkgs: ContentId,          // location+hash of the current KeyPackage bundle (§5.3)
    pub recovery: ContentId,         // hash of the current RecoveryPolicy (§1.4)
    pub names: Vec<String>,          // canonical human name(s), e.g. "abc@def.com" (§3)
    pub prev: Option<ContentId>,     // hash of the previous Identity version (hash chain)
    pub ts: TimestampMs,
    #[serde(default)]
    pub sig: Vec<Vec<u8>>, // one signature per suite in `suites`, over all of the above
}

impl Identity {
    /// Bytes signed by every suite key: the whole object with `sig` cleared.
    fn signing_bytes(&self) -> Vec<u8> {
        let mut c = self.clone();
        c.sig = Vec::new();
        cbor(&c)
    }

    /// Build and sign a single-suite (classical) `Identity` (spec §1.3). This is the v0 path;
    /// multi-suite objects are constructed by adding more `(suite, key)` entries and one
    /// signature per suite, which the PQ suite would populate once implemented.
    #[allow(clippy::too_many_arguments)]
    pub fn create_classical(
        ik: &IdentityKey,
        version: u64,
        devices: Vec<DeviceCert>,
        keypkgs: ContentId,
        recovery: ContentId,
        names: Vec<String>,
        prev: Option<ContentId>,
        ts: TimestampMs,
    ) -> Identity {
        let mut iks = BTreeMap::new();
        iks.insert(Suite::Classical.as_u8(), ik.public());
        let mut id = Identity {
            suites: vec![Suite::Classical],
            iks,
            version,
            devices,
            keypkgs,
            recovery,
            names,
            prev,
            ts,
            sig: Vec::new(),
        };
        let signing_bytes = id.signing_bytes();
        id.sig = vec![ed25519_sign(ik.signing(), &signing_bytes)];
        id
    }

    /// Content address of this identity (spec §2.2) — the value contacts pin (§3.4).
    pub fn content_id(&self) -> ContentId {
        ContentId::of(&cbor(self))
    }

    /// Verify the identity (spec §1.3, §3.4):
    ///
    /// 1. Every suite in `suites` must have a key in `iks` and an index-aligned entry in `sig`.
    /// 2. **Fail closed** on any suite the implementation cannot validate — the reference core
    ///    only validates `0x01`, so a `0x02`-bearing identity is rejected rather than
    ///    silently downgraded (§1.3).
    /// 3. Each signature must verify under the corresponding suite key.
    /// 4. Hash-chain sanity: `version == 0` ⇒ no `prev`; `version > 0` ⇒ `prev` present, and if
    ///    a `pinned` previous-version id is supplied it must equal `prev` (§1.3, §3.4).
    pub fn verify(&self, pinned: Option<&ContentId>) -> Result<(), IdentityError> {
        if self.suites.is_empty() {
            return Err(IdentityError::Malformed("empty suite set"));
        }
        if self.sig.len() != self.suites.len() {
            return Err(IdentityError::Malformed("sig count != suite count"));
        }
        let signing_bytes = self.signing_bytes();
        for (i, suite) in self.suites.iter().enumerate() {
            // Fail closed on any suite we cannot validate (no silent downgrade, §1.3).
            if !suite.is_supported() {
                return Err(IdentityError::UnsupportedSuite(suite.as_u8()));
            }
            let key = self
                .iks
                .get(&suite.as_u8())
                .ok_or(IdentityError::Malformed("missing key for a declared suite"))?;
            ed25519_verify(key, &signing_bytes, &self.sig[i])?;
        }
        // Hash-chain sanity.
        match (self.version, &self.prev) {
            (0, Some(_)) => return Err(IdentityError::BrokenChain),
            (v, None) if v > 0 => return Err(IdentityError::BrokenChain),
            _ => {}
        }
        if let (Some(p), Some(prev)) = (pinned, &self.prev) {
            if p != prev {
                return Err(IdentityError::BrokenChain);
            }
        }
        Ok(())
    }
}

// --- Recovery policy (§1.4) ----------------------------------------------------------------

/// A recovery method (spec §1.4). Rotating a method out MUST re-key the underlying secret;
/// this type only carries the *published* material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryMethod {
    /// Key derived from a SLIP-0039 mnemonic (preferred over hand-rolled BIP39+Shamir).
    Phrase { recovery_key: Vec<u8> },
    Device { device_key: Vec<u8>, label: String },
    /// Prefer VSS (Feldman/Pedersen) over plain Shamir; guardian change is redistribution.
    /// Consider FROST (RFC 9591) so the secret is never reassembled in one place.
    Social { guardians: Vec<Vec<u8>>, threshold: u8 },
}

/// A threshold predicate over recovery methods (e.g. "1 phrase OR 2 devices OR 2 guardians").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Threshold {
    pub any_of: Vec<MethodPredicate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MethodPredicate {
    Phrase,
    Devices(u8),
    Guardians(u8),
    Ik,
}

/// The recovery policy (spec §1.4). Invariant: `rotate_threshold` MUST be at least as strong as
/// `recover_threshold`, so no single compromised factor can rewrite the policy and lock the
/// owner out (§1.4 rule 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryPolicy {
    pub suite: Suite,
    pub ik: Vec<u8>,
    pub version: u64,
    pub methods: Vec<RecoveryMethod>,
    pub recover_threshold: Threshold,
    pub rotate_threshold: Threshold,
    pub prev: Option<ContentId>,
    pub ts: TimestampMs,
    #[serde(default)]
    pub sig: Vec<u8>, // by IK, or by a satisfied rotate_threshold quorum (reactive)
}

impl RecoveryPolicy {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut c = self.clone();
        c.sig = Vec::new();
        cbor(&c)
    }

    /// Sign a policy version proactively with `IK` (spec §1.4 "proactive rotation").
    pub fn sign(&mut self, ik: &IdentityKey) {
        self.sig = ed25519_sign(ik.signing(), &self.signing_bytes());
    }

    /// Verify the policy signature under `ik`. Does not itself evaluate the (reactive) quorum
    /// path — that lives in the recovery flow (§1.4). Also fails closed if the structural
    /// invariant `rotate_threshold ⊇ recover_threshold` is obviously violated (empty rotate).
    pub fn verify(&self) -> Result<(), IdentityError> {
        if !self.suite.is_supported() {
            return Err(IdentityError::UnsupportedSuite(self.suite.as_u8()));
        }
        if self.rotate_threshold.any_of.is_empty() {
            return Err(IdentityError::Malformed("rotate_threshold must not be empty"));
        }
        ed25519_verify(&self.ik, &self.signing_bytes(), &self.sig)
    }
}

// --- Name migration (§1.6) -----------------------------------------------------------------

/// Rebinds the human name while preserving the key (spec §1.6). Contacts route by key and
/// verify this against `IK`, so they follow automatically and cannot be redirected by a forgery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveRecord {
    pub suite: Suite,
    pub ik: Vec<u8>,
    pub from: String,
    pub to: String,
    pub ts: TimestampMs,
    pub prev: Option<ContentId>,
    #[serde(default)]
    pub sig: Vec<u8>, // by IK
}

impl MoveRecord {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut c = self.clone();
        c.sig = Vec::new();
        cbor(&c)
    }

    /// Create a signed MoveRecord (spec §1.6).
    pub fn create(
        ik: &IdentityKey,
        from: impl Into<String>,
        to: impl Into<String>,
        ts: TimestampMs,
        prev: Option<ContentId>,
    ) -> MoveRecord {
        let mut m = MoveRecord {
            suite: Suite::Classical,
            ik: ik.public(),
            from: from.into(),
            to: to.into(),
            ts,
            prev,
            sig: Vec::new(),
        };
        m.sig = ed25519_sign(ik.signing(), &m.signing_bytes());
        m
    }

    /// Verify the record is signed by its declared `IK` (spec §1.6).
    pub fn verify(&self) -> Result<(), IdentityError> {
        if !self.suite.is_supported() {
            return Err(IdentityError::UnsupportedSuite(self.suite.as_u8()));
        }
        ed25519_verify(&self.ik, &self.signing_bytes(), &self.sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(b: &[u8]) -> ContentId {
        ContentId::of(b)
    }

    #[test]
    fn identity_signs_and_verifies() {
        let ik = IdentityKey::generate();
        let id = Identity::create_classical(
            &ik,
            0,
            vec![],
            cid(b"keypkgs"),
            cid(b"recovery"),
            vec!["alice@example.com".into()],
            None,
            1_700_000_000_000,
        );
        assert!(id.verify(None).is_ok(), "a freshly signed identity must verify");
    }

    #[test]
    fn tampered_identity_fails_signature() {
        let ik = IdentityKey::generate();
        let mut id = Identity::create_classical(
            &ik,
            0,
            vec![],
            cid(b"kp"),
            cid(b"rec"),
            vec!["a@b.com".into()],
            None,
            1,
        );
        // Tamper with a signed field; the signature must no longer verify.
        id.names.push("evil@attacker.com".into());
        assert_eq!(id.verify(None), Err(IdentityError::BadSignature));
    }

    #[test]
    fn pq_only_identity_fails_closed() {
        // Hand-build a 0x02-only identity; the reference core cannot validate it and MUST
        // reject rather than silently downgrade (§1.3).
        let mut iks = BTreeMap::new();
        iks.insert(Suite::PqHybrid.as_u8(), vec![0u8; 32]);
        let id = Identity {
            suites: vec![Suite::PqHybrid],
            iks,
            version: 0,
            devices: vec![],
            keypkgs: cid(b"kp"),
            recovery: cid(b"rec"),
            names: vec![],
            prev: None,
            ts: 0,
            sig: vec![vec![0u8; 64]],
        };
        assert_eq!(id.verify(None), Err(IdentityError::UnsupportedSuite(0x02)));
    }

    #[test]
    fn device_cert_roundtrips_and_verifies() {
        let ik = IdentityKey::generate();
        let dev = IdentityKey::generate();
        let cert = DeviceCert::issue(
            &ik,
            dev.public(),
            "home-box",
            1,
            None,
            vec![Cap::Send, Cap::Recv, Cap::Relay],
        );
        assert!(cert.verify().is_ok());

        // CBOR round-trip.
        let mut buf = Vec::new();
        ciborium::into_writer(&cert, &mut buf).unwrap();
        let back: DeviceCert = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(cert, back);
        assert!(back.verify().is_ok());

        // A forged cert (wrong IK) must fail.
        let mut forged = cert.clone();
        forged.ik = dev.public();
        assert_eq!(forged.verify(), Err(IdentityError::BadSignature));
    }

    #[test]
    fn recovery_policy_and_move_record_sign_verify() {
        let ik = IdentityKey::generate();
        let mut policy = RecoveryPolicy {
            suite: Suite::Classical,
            ik: ik.public(),
            version: 1,
            methods: vec![RecoveryMethod::Phrase { recovery_key: vec![1, 2, 3] }],
            recover_threshold: Threshold { any_of: vec![MethodPredicate::Phrase] },
            rotate_threshold: Threshold {
                any_of: vec![MethodPredicate::Ik, MethodPredicate::Guardians(2)],
            },
            prev: None,
            ts: 1,
            sig: vec![],
        };
        policy.sign(&ik);
        assert!(policy.verify().is_ok());

        let mv = MoveRecord::create(&ik, "a@old.com", "a@new.com", 2, None);
        assert!(mv.verify().is_ok());
        let mut forged = mv.clone();
        forged.to = "a@evil.com".into();
        assert_eq!(forged.verify(), Err(IdentityError::BadSignature));
    }
}
