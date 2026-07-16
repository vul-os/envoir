//! Delegated capability objects — spec §13.5 / §13.5.1, §18.7.3, §18.9.14.
//!
//! A [`CapabilityToken`] is a **profile of UCAN v1.0**: a signed, offline-verifiable, *attenuable*
//! grant of a specific least-privilege right from an issuer key (`iss`) to an audience key (`aud`),
//! chainable via `prnt` so each link may only **narrow** its parent. A [`Capability`] is one
//! `(resource, ability, caveats)` grant. A [`CapabilityRevocation`] is the separately published,
//! KT-logged object that revokes a token (and its descendants).
//!
//! Both signed objects sign under the **issuer** key with the general §18.9.14 rule
//! (`Sign(sk_iss, DS-tag ‖ 0x00 ‖ det_cbor(object ∖ {sig}))`). The `Capability` sub-map carries no
//! signature of its own — it is covered by the enclosing token's `sig`. All are integer-keyed
//! canonical CBOR (§18.1.2); `Capability.caveats` is the one text-keyed sub-map (an `ext-value`
//! map, §18.3.6), so its values are restricted to the deterministic-safe CBOR subset the strict
//! codec already enforces.

use crate::cbor::{self, as_array, as_bytes, as_text, as_u64, as_u8, CborError, Cv, Fields};
use crate::id::ContentId;
use crate::identity::{verify_domain, IdentityError, IdentityKey};
use crate::suite::Suite;
use crate::TimestampMs;

/// §18.9.14 domain-separation tags (ASCII ‖ trailing `0x00`; `sign_domain` prepends them).
pub const CAP_TOKEN_DS: &[u8] = b"DMTAP-v0/cap-token\x00";
pub const CAP_REVOCATION_DS: &[u8] = b"DMTAP-v0/cap-revocation\x00";

fn suite_from_cv(cv: Cv) -> Result<Suite, CborError> {
    let b = as_u8(cv)?;
    Suite::from_u8(b).ok_or(CborError::UnknownSuite(b))
}

// --- Capability (§18.7.3) ------------------------------------------------------------------

/// One granted capability (§18.7.3): a scoped `resource`, a permitted `ability`, and OPTIONAL
/// attenuating `caveats`. Caveats are a text-keyed `{ * tstr => ext-value }` map preserved
/// verbatim (as a canonical [`Cv::TextMap`]) so the enclosing token's signature reproduces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub resource: String,        // key 1 — e.g. "mailbox:calendar"
    pub ability: String,         // key 2 — the verb, e.g. "read"
    pub caveats: Option<Cv>,     // key 3 — Cv::TextMap of attenuating conditions; None ⇒ absent
}

impl Capability {
    pub(crate) fn to_cv(&self) -> Cv {
        let mut m = vec![
            (1u64, Cv::Text(self.resource.clone())),
            (2, Cv::Text(self.ability.clone())),
        ];
        if let Some(c) = &self.caveats {
            m.push((3, c.clone()));
        }
        Cv::Map(m)
    }

    pub(crate) fn from_cv(cv: Cv) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cv)?;
        let resource = as_text(f.req(1)?)?;
        let ability = as_text(f.req(2)?)?;
        // caveats (key 3) is a text-keyed ext-value map; require the map shape and reject any
        // other CBOR type fail-closed (a non-map caveats field is malformed).
        let caveats = match f.take(3) {
            Some(c @ Cv::TextMap(_)) => Some(c),
            // An empty caveats map decodes as Cv::Map([]) (variant-neutral); accept it as no caveats.
            Some(Cv::Map(m)) if m.is_empty() => Some(Cv::TextMap(Vec::new())),
            Some(_) => return Err(CborError::TypeMismatch),
            None => None,
        };
        f.deny_unknown()?;
        Ok(Capability { resource, ability, caveats })
    }
}

// --- CapabilityToken (§18.7.3) -------------------------------------------------------------

/// A signed, attenuable delegation token (§18.7.3) — a profile of UCAN v1.0. Verified offline;
/// `prnt` chains it to a parent whose `aud` MUST equal this token's `iss`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityToken {
    pub suite: Suite,             // key 1
    pub iss: Vec<u8>,             // key 2 — issuer (delegator) key
    pub aud: Vec<u8>,             // key 3 — audience (delegatee) key
    pub caps: Vec<Capability>,    // key 4 — granted capabilities (≥ 1)
    pub nbf: u64,                 // key 5 — not-before (ms epoch)
    pub exp: u64,                 // key 6 — expiry (ms epoch); MUST be present
    pub nonce: Vec<u8>,           // key 7 — uniqueness / anti-replay salt
    pub prnt: Option<ContentId>,  // key 8 — content-addr of the PARENT token; absent ⇒ rooted at iss
    pub sig: Vec<u8>,             // key 9 — §18.9.14, over det_cbor(token ∖ {9}) under iss
}

impl CapabilityToken {
    /// Integer-keyed canonical map (§18.7.3). `include_sig=false` omits key 9 for the §18.9.14
    /// signing body.
    fn to_cv(&self, include_sig: bool) -> Cv {
        let mut m = vec![
            (1u64, Cv::U64(self.suite.as_u8() as u64)),
            (2, Cv::Bytes(self.iss.clone())),
            (3, Cv::Bytes(self.aud.clone())),
            (4, Cv::Array(self.caps.iter().map(Capability::to_cv).collect())),
            (5, Cv::U64(self.nbf)),
            (6, Cv::U64(self.exp)),
            (7, Cv::Bytes(self.nonce.clone())),
        ];
        if let Some(p) = &self.prnt {
            m.push((8, Cv::Bytes(p.as_bytes().to_vec())));
        }
        if include_sig {
            m.push((9, Cv::Bytes(self.sig.clone())));
        }
        Cv::Map(m)
    }

    /// The exact wire bytes: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(true))
    }

    /// The §18.9.14 signing body: deterministic CBOR of the token with `sig` (key 9) omitted.
    pub fn signing_body(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(false))
    }

    /// Decode a capability token (§18.7.3), failing closed on any violation (including an empty
    /// `caps` — `[+ Capability]` requires ≥ 1).
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let suite = suite_from_cv(f.req(1)?)?;
        let iss = as_bytes(f.req(2)?)?;
        let aud = as_bytes(f.req(3)?)?;
        let caps: Vec<Capability> = as_array(f.req(4)?)?
            .into_iter()
            .map(Capability::from_cv)
            .collect::<Result<_, _>>()?;
        if caps.is_empty() {
            return Err(CborError::TypeMismatch); // [+ Capability] requires ≥ 1
        }
        let nbf = as_u64(f.req(5)?)?;
        let exp = as_u64(f.req(6)?)?;
        let nonce = as_bytes(f.req(7)?)?;
        let prnt = f.take(8).map(as_bytes).transpose()?.map(ContentId);
        let sig = as_bytes(f.req(9)?)?;
        f.deny_unknown()?;
        Ok(CapabilityToken { suite, iss, aud, caps, nbf, exp, nonce, prnt, sig })
    }

    /// Mint (sign) a token with the issuer key (§18.9.14); `iss` is set from the signer.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        iss: &IdentityKey,
        aud: Vec<u8>,
        caps: Vec<Capability>,
        nbf: u64,
        exp: u64,
        nonce: Vec<u8>,
        prnt: Option<ContentId>,
    ) -> CapabilityToken {
        let mut t = CapabilityToken {
            suite: Suite::Classical,
            iss: iss.public(),
            aud,
            caps,
            nbf,
            exp,
            nonce,
            prnt,
            sig: Vec::new(),
        };
        t.sig = iss.sign_domain(CAP_TOKEN_DS, &t.signing_body());
        t
    }

    /// Verify the token's own signature under `iss` (§18.9.14). Does **not** walk the delegation
    /// chain or check attenuation/revocation — the caller does (§18.7.3 verification steps).
    pub fn verify(&self) -> Result<(), IdentityError> {
        if !self.suite.is_supported() {
            return Err(IdentityError::UnsupportedSuite(self.suite.as_u8()));
        }
        verify_domain(&self.iss, CAP_TOKEN_DS, &self.signing_body(), &self.sig)
    }
}

// --- CapabilityRevocation (§18.7.3) --------------------------------------------------------

/// A published, KT-logged revocation of a previously issued token (§18.7.3). Signed by the token's
/// `iss` (or an ancestor issuer in its chain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityRevocation {
    pub suite: Suite,      // key 1
    pub iss: Vec<u8>,      // key 2 — the revoker (token's iss or an ancestor)
    pub token: ContentId,  // key 3 — content-addr of the revoked CapabilityToken
    pub ts: TimestampMs,   // key 4 — revocation time
    pub sig: Vec<u8>,      // key 5 — §18.9.14, over det_cbor(revocation ∖ {5}) under iss
}

impl CapabilityRevocation {
    fn to_cv(&self, include_sig: bool) -> Cv {
        let mut m = vec![
            (1u64, Cv::U64(self.suite.as_u8() as u64)),
            (2, Cv::Bytes(self.iss.clone())),
            (3, Cv::Bytes(self.token.as_bytes().to_vec())),
            (4, Cv::U64(self.ts)),
        ];
        if include_sig {
            m.push((5, Cv::Bytes(self.sig.clone())));
        }
        Cv::Map(m)
    }

    /// The exact wire bytes: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(true))
    }

    /// The §18.9.14 signing body: deterministic CBOR of the revocation with `sig` (key 5) omitted.
    pub fn signing_body(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(false))
    }

    /// Decode a revocation (§18.7.3), failing closed on any violation.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let suite = suite_from_cv(f.req(1)?)?;
        let iss = as_bytes(f.req(2)?)?;
        let token = ContentId(as_bytes(f.req(3)?)?);
        let ts = as_u64(f.req(4)?)?;
        let sig = as_bytes(f.req(5)?)?;
        f.deny_unknown()?;
        Ok(CapabilityRevocation { suite, iss, token, ts, sig })
    }

    /// Sign a revocation with the issuer key (§18.9.14); `iss` is set from the signer.
    pub fn issue(iss: &IdentityKey, token: ContentId, ts: TimestampMs) -> CapabilityRevocation {
        let mut r = CapabilityRevocation {
            suite: Suite::Classical,
            iss: iss.public(),
            token,
            ts,
            sig: Vec::new(),
        };
        r.sig = iss.sign_domain(CAP_REVOCATION_DS, &r.signing_body());
        r
    }

    /// Verify the revocation signature under `iss` (§18.9.14).
    pub fn verify(&self) -> Result<(), IdentityError> {
        if !self.suite.is_supported() {
            return Err(IdentityError::UnsupportedSuite(self.suite.as_u8()));
        }
        verify_domain(&self.iss, CAP_REVOCATION_DS, &self.signing_body(), &self.sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> IdentityKey {
        IdentityKey::from_seed(&[seed; 32])
    }

    fn sample_caps() -> Vec<Capability> {
        vec![
            Capability {
                resource: "mailbox:calendar".into(),
                ability: "read".into(),
                caveats: Some(Cv::TextMap(vec![("before".into(), Cv::U64(1_800_000_000_000))])),
            },
            Capability { resource: "domain:abc.com/members".into(), ability: "directory/write".into(), caveats: None },
        ]
    }

    #[test]
    fn token_signs_verifies_and_round_trips() {
        let t = CapabilityToken::issue(
            &key(0x11),
            key(0x22).public(),
            sample_caps(),
            1_700_000_000_000,
            1_700_000_600_000,
            b"nonce-01".to_vec(),
            Some(ContentId::of(b"parent-token")),
        );
        assert!(t.verify().is_ok());
        let bytes = t.det_cbor();
        assert_eq!(bytes[0] & 0xe0, 0xa0, "token is a CBOR map");
        assert_eq!(bytes[1], 0x01, "first key is integer 1 (suite), not a text key");
        let back = CapabilityToken::from_det_cbor(&bytes).unwrap();
        assert_eq!(t, back);
        assert_eq!(bytes, back.det_cbor());
        assert!(back.verify().is_ok());
    }

    #[test]
    fn tampered_token_fails_signature() {
        let mut t = CapabilityToken::issue(
            &key(0x11), key(0x22).public(), sample_caps(), 1, 2, b"n".to_vec(), None,
        );
        t.exp = 3; // signed field changed
        assert_eq!(t.verify(), Err(IdentityError::BadSignature));
    }

    #[test]
    fn empty_caps_fails_closed() {
        let mut t = CapabilityToken::issue(
            &key(0x11), key(0x22).public(), sample_caps(), 1, 2, b"n".to_vec(), None,
        );
        t.caps.clear();
        t.sig.clear();
        let bytes = t.det_cbor();
        assert_eq!(CapabilityToken::from_det_cbor(&bytes), Err(CborError::TypeMismatch));
    }

    #[test]
    fn revocation_signs_verifies_and_round_trips() {
        let r = CapabilityRevocation::issue(&key(0x11), ContentId::of(b"revoked-token"), 1_700_000_000_000);
        assert!(r.verify().is_ok());
        let bytes = r.det_cbor();
        let back = CapabilityRevocation::from_det_cbor(&bytes).unwrap();
        assert_eq!(r, back);
        assert_eq!(bytes, back.det_cbor());
        assert!(back.verify().is_ok());
    }
}
