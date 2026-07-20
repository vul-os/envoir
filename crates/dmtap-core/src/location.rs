//! The `key → location` DHT record — spec §4.2, §18.5.1.
//!
//! A [`LocationRecord`] is how one identity key becomes *dialable*: a self-certifying **value
//! record** (IPNS pattern) stored in the DHT under `multihash(ik)`, carrying the peer id and
//! current reachability hints, signed by a device key, and defended against rollback by a
//! monotonic `seq` plus a `ttl`/`ts` freshness bound.
//!
//! Like [`crate::mixnet`], this is an **integer-keyed canonical CBOR** map (§18.1.2) with serde
//! deliberately not derived (text keys are not the wire form), and signing follows the §18.9.9
//! general rule `Sign(sk, DS-tag ‖ 0x00 ‖ det_cbor(object ∖ {sig}))`.
//!
//! ## What signing does and does not buy you (§4.2 CAUTION)
//!
//! Verification here authenticates record **content**, not **routing**. Because a libp2p PeerId
//! is `hash(pubkey)`, an attacker can cheaply generate ids closest to a target key, fill honest
//! routing tables, and control every lookup for that key — returning nothing, or an *old but
//! still validly-signed* record. That is an eclipse/Sybil attack at the routing layer and no
//! signature check can detect it in isolation. The defenses this module can actually provide are
//! the two it does provide:
//!
//! - [`LocationTracker`] enforces the **monotonic-`seq` rule** (§4.2, §16.2), so a replayed older
//!   record is rejected (`ERR_LOCATION_STALE`, `0x0302`) and the newer cached record retained.
//! - [`LocationRecord::check_fresh`] enforces the **TTL bound**, so an expired record is not
//!   dialed even if its signature is perfect.
//!
//! The rest of the mitigation — S/Kademlia disjoint-path lookups, IP-diversity caps per k-bucket,
//! and above all the **resolution order** (cached direct addresses → relay-reservation/rendezvous
//! → DHT strictly as fallback) — belongs to the transport, not to this type. The DHT is one
//! discovery mechanism, never the root of trust; the root of trust is the user's long-term keypair.

use crate::cbor::{self, as_array, as_bytes, as_text, as_u64, as_u8, CborError, Cv, Fields};
use crate::id::ContentId;
use crate::identity::{verify_domain, IdentityError, IdentityKey};
use crate::TimestampMs;
use std::collections::HashMap;

/// §18.9.9 domain-separation tag (ASCII ‖ trailing `0x00`; `sign_domain` prepends it).
pub const LOCATION_RECORD_DS: &[u8] = b"DMTAP-v0/location-record\x00";

/// The v0 default transport substrate — libp2p (§4.1, §21.24). An absent `substrate` field means
/// exactly this value; it is omitted on the wire rather than encoded (§18.1.1: absent optionals
/// are omitted, never `null`).
pub const SUBSTRATE_LIBP2P: u8 = 0x01;

/// Default record lifetime, in **seconds** (§16.2 v0 default: 2 h).
pub const DEFAULT_TTL_SECS: u64 = 2 * 60 * 60;

/// Default republish cadence, in **seconds** (§16.2 v0 default: 45 min). DHT record lifetimes are
/// short and staleness is a real failure mode, so a publisher republishes well before expiry.
pub const DEFAULT_REPUBLISH_SECS: u64 = 45 * 60;

/// A signed `key → location` value record (spec §4.2, §18.5.1).
///
/// Field-to-CBOR-key mapping is fixed by §18.5.1: `ik`=1, `peer_id`=2, `addrs`=3, `seq`=4,
/// `ttl`=5, `ts`=6, `sig`=7, `substrate`=8 (OPTIONAL). Note that `sig` (7) sorts *before*
/// `substrate` (8) by key even though it is written last in the struct — [`Self::to_cv`] emits
/// keys in ascending order, as §18.1.1 rule 2 requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocationRecord {
    /// key 1 — the identity key this record locates. The DHT key is [`Self::dht_key`].
    pub ik: Vec<u8>,
    /// key 2 — node id, interpreted per `substrate` (v0: a libp2p PeerId). MAY be a per-epoch,
    /// unlinkable id to decouple node from identity (§6.4).
    pub peer_id: Vec<u8>,
    /// key 3 — reachability hints as multiaddr strings. MAY be empty (a node reachable only via a
    /// rendezvous introduction publishes no dialable hint). **Order is preference.**
    pub addrs: Vec<String>,
    /// key 4 — monotonic sequence number; a resolver MUST reject older-or-equal (§4.2, §16.2).
    pub seq: u64,
    /// key 5 — record lifetime in **seconds**.
    pub ttl: u64,
    /// key 6 — publication time (ms since epoch, the crate-wide [`TimestampMs`] convention).
    pub ts: TimestampMs,
    /// key 7 — §18.9.9 signature by a device key authorized in the current `Identity`.
    pub sig: Vec<u8>,
    /// key 8 — OPTIONAL transport-substrate tag (§21.24); absent ⇒ [`SUBSTRATE_LIBP2P`].
    pub substrate: Option<u8>,
}

impl LocationRecord {
    /// The effective substrate: the tag if present, else the v0 default (§18.5.1).
    pub fn substrate(&self) -> u8 {
        self.substrate.unwrap_or(SUBSTRATE_LIBP2P)
    }

    /// The DHT key this record is stored under: `multihash(ik)` (§4.2, §18.5.1).
    ///
    /// Reuses the crate's §2.2 content-address construction, so the key is
    /// `[0x1e] ‖ BLAKE3-256(ik)` — a multihash-prefixed digest, algorithm-agile by the same
    /// 1-byte prefix as every other DMTAP address.
    pub fn dht_key(ik: &[u8]) -> Vec<u8> {
        ContentId::of(ik).0
    }

    /// Integer-keyed canonical map (§18.5.1). `include_sig=false` omits key 7 for the §18.9.9
    /// signing body — note this still covers `substrate` (key 8) when present, as §18.5.1 requires.
    fn to_cv(&self, include_sig: bool) -> Cv {
        let mut m = vec![
            (1u64, Cv::Bytes(self.ik.clone())),
            (2, Cv::Bytes(self.peer_id.clone())),
            (3, Cv::Array(self.addrs.iter().map(|a| Cv::Text(a.clone())).collect())),
            (4, Cv::U64(self.seq)),
            (5, Cv::U64(self.ttl)),
            (6, Cv::U64(self.ts)),
        ];
        if include_sig {
            m.push((7, Cv::Bytes(self.sig.clone())));
        }
        if let Some(s) = self.substrate {
            m.push((8, Cv::U64(s as u64)));
        }
        Cv::Map(m)
    }

    /// The exact wire bytes: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(true))
    }

    /// The §18.9.9 signing body: deterministic CBOR of the record with `sig` (key 7) omitted.
    pub fn signing_body(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(false))
    }

    /// Decode a record (§18.5.1), failing closed on any violation.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let ik = as_bytes(f.req(1)?)?;
        let peer_id = as_bytes(f.req(2)?)?;
        let addrs = as_array(f.req(3)?)?
            .into_iter()
            .map(as_text)
            .collect::<Result<_, _>>()?;
        let seq = as_u64(f.req(4)?)?;
        let ttl = as_u64(f.req(5)?)?;
        let ts = as_u64(f.req(6)?)?;
        let sig = as_bytes(f.req(7)?)?;
        let substrate = f.take(8).map(as_u8).transpose()?;
        f.deny_unknown()?;
        Ok(LocationRecord { ik, peer_id, addrs, seq, ttl, ts, sig, substrate })
    }

    /// Issue (sign) a record with the publisher's `IK` (§18.9.9); `ik` is set from the signer.
    ///
    /// The reference signs with the `IK` itself (an `IK` is trivially `IK`-authorized); the spec
    /// permits any `IK`-authorized device key, which is what a multi-device publisher would use so
    /// that a roaming device can republish without the root key being present (§18.5.1 `sig`).
    pub fn issue(
        ik: &IdentityKey,
        peer_id: Vec<u8>,
        addrs: Vec<String>,
        seq: u64,
        ttl: u64,
        ts: TimestampMs,
        substrate: Option<u8>,
    ) -> LocationRecord {
        let mut r = LocationRecord {
            ik: ik.public(),
            peer_id,
            addrs,
            seq,
            ttl,
            ts,
            sig: Vec::new(),
            substrate,
        };
        r.sig = ik.sign_domain(LOCATION_RECORD_DS, &r.signing_body());
        r
    }

    /// Verify the record's signature under its own `ik` (§18.9.9), failing closed with
    /// `ERR_LOCATION_SIG_INVALID` (`0x0301`) semantics.
    ///
    /// This is *only* the content check. A caller resolving from the DHT MUST additionally run
    /// [`LocationTracker::accept`] (rollback) and [`Self::check_fresh`] (TTL) — a validly-signed
    /// record is exactly what an eclipsing attacker replays (§4.2 CAUTION).
    pub fn verify(&self) -> Result<(), IdentityError> {
        verify_domain(&self.ik, LOCATION_RECORD_DS, &self.signing_body(), &self.sig)
    }

    /// TTL freshness (§4.2, §16.2), failing closed with [`LocationError::Expired`].
    ///
    /// The record is live over `[ts, ts + ttl)`. `ttl` is in **seconds** while `ts` and `now` are
    /// **milliseconds** (§18.5.1 vs. the crate-wide [`TimestampMs`]), so the bound is converted
    /// here rather than at each call site — getting that unit mismatch wrong is precisely how a
    /// record ends up honored ~1000× longer than its publisher intended.
    ///
    /// Expiry is fail-closed at the boundary (`now == ts + ttl` is expired), and a record whose
    /// `ts` lies in the future beyond `skew_ms` is rejected too: a publisher cannot mint a record
    /// that outlives its stated lifetime by post-dating it.
    pub fn check_fresh(&self, now: TimestampMs, skew_ms: u64) -> Result<(), LocationError> {
        if now.saturating_add(skew_ms) < self.ts {
            return Err(LocationError::Expired); // post-dated beyond tolerated clock skew
        }
        let expires_at = self.ts.saturating_add(self.ttl.saturating_mul(1_000));
        if now >= expires_at {
            return Err(LocationError::Expired);
        }
        Ok(())
    }

    /// Whether a publisher should republish by `now` (§16.2): the record is past its republish
    /// cadence, so a fresh, higher-`seq` record is due before the current one expires.
    pub fn needs_republish(&self, now: TimestampMs, republish_secs: u64) -> bool {
        now >= self.ts.saturating_add(republish_secs.saturating_mul(1_000))
    }

    /// Full fail-closed acceptance of a record *as received from the DHT*, in the order the spec
    /// demands: signature (§18.9.9), then freshness (§16.2), then substrate support (§21.24).
    ///
    /// `supported` lists the substrate tags this resolver can actually dial. A record tagged with
    /// a substrate outside that set is [`LocationError::Unreachable`] (`0x0303`) — **never** a
    /// parse error (§18.5.1): introducing a new substrate is an additive migration, and treating
    /// an unknown one as malformed would turn that migration into a flag day.
    ///
    /// The rollback check is deliberately **not** folded in here — it needs the per-key history
    /// held by [`LocationTracker`], which owns that decision.
    pub fn validate(
        &self,
        now: TimestampMs,
        skew_ms: u64,
        supported: &[u8],
    ) -> Result<(), LocationError> {
        self.verify().map_err(|_| LocationError::SigInvalid)?;
        self.check_fresh(now, skew_ms)?;
        if !supported.contains(&self.substrate()) {
            return Err(LocationError::Unreachable);
        }
        Ok(())
    }
}

/// Fail-closed outcomes of location resolution (§21.5 `0x0301`–`0x0303`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LocationError {
    /// Signature fails to validate under the claimed key — discard the record.
    #[error(
        "location record signature is invalid (ERR_LOCATION_SIG_INVALID, §21.5 0x0301)"
    )]
    SigInvalid,
    /// `seq` is older-or-equal to a record already seen for this key — a rollback/censorship
    /// replay. Retain the newer cached record.
    #[error(
        "location record sequence number is older-or-equal to one already seen — rollback \
         replay (ERR_LOCATION_STALE, §21.5 0x0302)"
    )]
    Stale,
    /// The record's TTL has elapsed (or it is post-dated beyond tolerated skew). Folded into
    /// `0x0303`: an expired record yields no dialable peer.
    #[error("location record has expired (ERR_LOCATION_UNREACHABLE, §21.5 0x0303)")]
    Expired,
    /// No record found, no dialable address, or a substrate this resolver does not implement.
    #[error(
        "no usable location for this key — absent, undialable, or an unimplemented transport \
         substrate (ERR_LOCATION_UNREACHABLE, §21.5 0x0303)"
    )]
    Unreachable,
}

impl LocationError {
    /// The normative DMTAP wire error code (§21.5).
    pub fn code(&self) -> u16 {
        match self {
            LocationError::SigInvalid => 0x0301,
            LocationError::Stale => 0x0302,
            LocationError::Expired | LocationError::Unreachable => 0x0303,
        }
    }

    /// Whether the sender's delivery state machine (§4.7) may retry this outcome.
    ///
    /// A bad signature or a rollback replay is terminal for *that record* — retrying the same
    /// bytes cannot help. An absent/undialable location is transient: fall down the reachability
    /// ladder (§4.3) and try again.
    pub fn retryable(&self) -> bool {
        matches!(self, LocationError::Expired | LocationError::Unreachable)
    }
}

/// Per-key anti-rollback state: the highest `seq` accepted for each identity key (§4.2, §16.2).
///
/// This is the piece that makes a signed record safe to act on. An eclipsing attacker cannot forge
/// a record, but it can *withhold* the current one and serve an older, still-validly-signed record
/// to pin a victim to a peer id the attacker still controls. Rejecting older-or-equal `seq` is the
/// defense, and it must be **persisted across restarts** by the caller — a tracker that resets to
/// empty on restart accepts the attacker's stale record exactly once per restart, which is the
/// same weakness the node's journal exists to prevent for delivery state.
#[derive(Debug, Clone, Default)]
pub struct LocationTracker {
    /// `ik` → highest `seq` accepted so far.
    seen: HashMap<Vec<u8>, u64>,
}

impl LocationTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// The highest `seq` accepted for `ik`, if any.
    pub fn highest_seq(&self, ik: &[u8]) -> Option<u64> {
        self.seen.get(ik).copied()
    }

    /// Rebuild a tracker from persisted `(ik, seq)` high-water marks (restart safety, see the type
    /// docs). Later duplicates keep the higher `seq` rather than the last one written.
    pub fn from_high_water_marks(marks: impl IntoIterator<Item = (Vec<u8>, u64)>) -> Self {
        let mut t = LocationTracker::new();
        for (ik, seq) in marks {
            let e = t.seen.entry(ik).or_insert(seq);
            *e = (*e).max(seq);
        }
        t
    }

    /// The persistable high-water marks, for journaling alongside the rest of the node snapshot.
    pub fn high_water_marks(&self) -> impl Iterator<Item = (&[u8], u64)> {
        self.seen.iter().map(|(k, v)| (k.as_slice(), *v))
    }

    /// Accept a record if and only if it is strictly newer than everything seen for its key
    /// (§4.2: "reject older-or-equal"), recording the new high-water mark on success.
    ///
    /// This performs **only** the rollback check; run [`LocationRecord::validate`] first, since
    /// admitting an unverified record's `seq` would let an attacker burn the sequence space with a
    /// forged `seq = u64::MAX` and lock out every genuine future record.
    pub fn accept(&mut self, rec: &LocationRecord) -> Result<(), LocationError> {
        match self.seen.get(&rec.ik) {
            Some(&prev) if rec.seq <= prev => Err(LocationError::Stale),
            _ => {
                self.seen.insert(rec.ik.clone(), rec.seq);
                Ok(())
            }
        }
    }

    /// The full resolver-side gate: content validity, freshness, substrate support, *then*
    /// rollback. Returns the record's dialable addresses in preference order on success.
    ///
    /// Ordering matters: validation precedes `accept` so an unverified `seq` is never recorded.
    pub fn admit<'a>(
        &mut self,
        rec: &'a LocationRecord,
        now: TimestampMs,
        skew_ms: u64,
        supported: &[u8],
    ) -> Result<&'a [String], LocationError> {
        rec.validate(now, skew_ms, supported)?;
        self.accept(rec)?;
        Ok(&rec.addrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: TimestampMs = 1_700_000_000_000;
    const SKEW: u64 = 5_000;
    const SUPPORTED: &[u8] = &[SUBSTRATE_LIBP2P];

    fn key() -> IdentityKey {
        IdentityKey::from_seed(&[7u8; 32])
    }

    fn rec(ik: &IdentityKey, seq: u64) -> LocationRecord {
        LocationRecord::issue(
            ik,
            b"peer-id-bytes".to_vec(),
            vec!["/ip4/198.51.100.7/tcp/4001".into(), "/ip4/198.51.100.7/udp/4001/quic-v1".into()],
            seq,
            DEFAULT_TTL_SECS,
            NOW,
            None,
        )
    }

    #[test]
    fn round_trips_byte_exactly_through_canonical_cbor() {
        let r = rec(&key(), 1);
        let bytes = r.det_cbor();
        let back = LocationRecord::from_det_cbor(&bytes).expect("decodes");
        assert_eq!(r, back);
        assert_eq!(back.det_cbor(), bytes, "re-encode must be byte-identical");
    }

    #[test]
    fn round_trips_with_an_explicit_substrate_tag() {
        let mut r = rec(&key(), 1);
        r.substrate = Some(0x02);
        r.sig = key().sign_domain(LOCATION_RECORD_DS, &r.signing_body());
        let back = LocationRecord::from_det_cbor(&r.det_cbor()).expect("decodes");
        assert_eq!(back.substrate, Some(0x02));
        assert_eq!(back.substrate(), 0x02);
        back.verify().expect("signature covers the substrate tag");
    }

    #[test]
    fn absent_substrate_means_libp2p_and_is_omitted_from_the_wire() {
        let r = rec(&key(), 1);
        assert_eq!(r.substrate, None);
        assert_eq!(r.substrate(), SUBSTRATE_LIBP2P);
        // §18.1.1: an absent optional is omitted, never encoded as null.
        let mut f = Fields::from_cv(cbor::decode(&r.det_cbor()).unwrap()).unwrap();
        assert!(f.take(8).is_none(), "key 8 must be absent, not null");
    }

    #[test]
    fn issued_record_verifies_and_a_tampered_one_does_not() {
        let ik = key();
        let r = rec(&ik, 1);
        r.verify().expect("freshly issued record verifies");

        // Flip a reachability hint: the signature covers the whole body, so this must fail.
        let mut tampered = r.clone();
        tampered.addrs[0] = "/ip4/203.0.113.9/tcp/4001".into();
        assert!(tampered.verify().is_err());
        assert_eq!(
            tampered.validate(NOW, SKEW, SUPPORTED).unwrap_err(),
            LocationError::SigInvalid
        );
    }

    #[test]
    fn signature_covers_the_substrate_tag() {
        let ik = key();
        let mut r = rec(&ik, 1);
        r.substrate = Some(0x02);
        r.sig = ik.sign_domain(LOCATION_RECORD_DS, &r.signing_body());
        r.verify().expect("signed with the tag present");

        // Stripping the tag downgrades the record to the libp2p default — it must not verify.
        let mut stripped = r.clone();
        stripped.substrate = None;
        assert!(stripped.verify().is_err(), "substrate tag must be signature-covered");
    }

    #[test]
    fn dht_key_is_the_multihash_of_the_identity_key() {
        let ik = key();
        let k = LocationRecord::dht_key(&ik.public());
        assert_eq!(k, ContentId::of(&ik.public()).0);
        assert_eq!(k.len(), 33, "1-byte multihash prefix + 32-byte BLAKE3 digest");
        assert_eq!(k[0], crate::id::MH_BLAKE3_256);
    }

    #[test]
    fn ttl_is_seconds_while_ts_is_milliseconds() {
        let r = rec(&key(), 1);
        // Live just before expiry, dead exactly at it (fail-closed at the boundary).
        let expiry = NOW + DEFAULT_TTL_SECS * 1_000;
        r.check_fresh(expiry - 1, SKEW).expect("live one ms before expiry");
        assert_eq!(r.check_fresh(expiry, SKEW).unwrap_err(), LocationError::Expired);
        // Had the unit conversion been missed, the record would still look live here.
        assert_eq!(r.check_fresh(NOW + DEFAULT_TTL_SECS + 1, SKEW), Ok(()));
    }

    #[test]
    fn a_post_dated_record_is_rejected_beyond_tolerated_skew() {
        let ik = key();
        let mut r = rec(&ik, 1);
        r.ts = NOW + SKEW + 1;
        r.sig = ik.sign_domain(LOCATION_RECORD_DS, &r.signing_body());
        assert_eq!(r.check_fresh(NOW, SKEW).unwrap_err(), LocationError::Expired);

        // Within skew it is accepted — clocks genuinely do disagree by a little.
        r.ts = NOW + SKEW - 1;
        r.sig = ik.sign_domain(LOCATION_RECORD_DS, &r.signing_body());
        r.check_fresh(NOW, SKEW).expect("tolerates a small forward skew");
    }

    #[test]
    fn an_unimplemented_substrate_is_unreachable_not_a_parse_error() {
        let ik = key();
        let mut r = rec(&ik, 1);
        r.substrate = Some(0x7f); // some future substrate this resolver cannot dial
        r.sig = ik.sign_domain(LOCATION_RECORD_DS, &r.signing_body());

        // It must still DECODE cleanly — an additive migration, not a flag day (§18.5.1).
        let back = LocationRecord::from_det_cbor(&r.det_cbor()).expect("unknown substrate decodes");
        assert_eq!(back.substrate, Some(0x7f));
        assert_eq!(
            back.validate(NOW, SKEW, SUPPORTED).unwrap_err(),
            LocationError::Unreachable
        );
        assert_eq!(LocationError::Unreachable.code(), 0x0303);
    }

    #[test]
    fn rollback_replay_is_rejected_and_the_newer_record_retained() {
        let ik = key();
        let mut t = LocationTracker::new();

        let newer = rec(&ik, 9);
        t.admit(&newer, NOW, SKEW, SUPPORTED).expect("first record accepted");
        assert_eq!(t.highest_seq(&ik.public()), Some(9));

        // The classic eclipse move: serve an OLDER but perfectly-signed record.
        let older = rec(&ik, 4);
        older.verify().expect("the stale record's signature is genuinely valid");
        assert_eq!(t.admit(&older, NOW, SKEW, SUPPORTED).unwrap_err(), LocationError::Stale);

        // Equal seq is rejected too ("older-or-equal", §4.2).
        assert_eq!(t.admit(&rec(&ik, 9), NOW, SKEW, SUPPORTED).unwrap_err(), LocationError::Stale);

        // The high-water mark is unmoved, so the newer record is what stays cached.
        assert_eq!(t.highest_seq(&ik.public()), Some(9));
        t.admit(&rec(&ik, 10), NOW, SKEW, SUPPORTED).expect("strictly newer is accepted");
    }

    #[test]
    fn an_invalid_record_never_advances_the_sequence_high_water_mark() {
        let ik = key();
        let mut t = LocationTracker::new();
        t.admit(&rec(&ik, 3), NOW, SKEW, SUPPORTED).unwrap();

        // Forge a maximal seq. If validation did not gate `accept`, this would burn the sequence
        // space and lock out every genuine future record.
        let mut forged = rec(&ik, u64::MAX);
        forged.sig = vec![0u8; 64];
        assert_eq!(t.admit(&forged, NOW, SKEW, SUPPORTED).unwrap_err(), LocationError::SigInvalid);
        assert_eq!(t.highest_seq(&ik.public()), Some(3), "high-water mark must not move");

        t.admit(&rec(&ik, 4), NOW, SKEW, SUPPORTED).expect("genuine successor still accepted");
    }

    #[test]
    fn an_expired_record_never_advances_the_sequence_high_water_mark() {
        let ik = key();
        let mut t = LocationTracker::new();
        t.admit(&rec(&ik, 3), NOW, SKEW, SUPPORTED).unwrap();

        let later = NOW + DEFAULT_TTL_SECS * 1_000;
        assert_eq!(t.admit(&rec(&ik, 99), later, SKEW, SUPPORTED).unwrap_err(), LocationError::Expired);
        assert_eq!(t.highest_seq(&ik.public()), Some(3));
    }

    #[test]
    fn tracker_survives_a_restart_through_persisted_high_water_marks() {
        let ik = key();
        let mut t = LocationTracker::new();
        t.admit(&rec(&ik, 12), NOW, SKEW, SUPPORTED).unwrap();

        // Simulate a restart: journal the marks, rebuild, and confirm the stale record is STILL
        // rejected. A tracker that reset to empty here would accept it once per restart.
        let marks: Vec<(Vec<u8>, u64)> =
            t.high_water_marks().map(|(k, v)| (k.to_vec(), v)).collect();
        let mut reopened = LocationTracker::from_high_water_marks(marks);
        assert_eq!(reopened.highest_seq(&ik.public()), Some(12));
        assert_eq!(
            reopened.admit(&rec(&ik, 5), NOW, SKEW, SUPPORTED).unwrap_err(),
            LocationError::Stale
        );
    }

    #[test]
    fn high_water_marks_keep_the_higher_seq_on_duplicate_keys() {
        let ik = key().public();
        let t = LocationTracker::from_high_water_marks(vec![(ik.clone(), 9), (ik.clone(), 4)]);
        assert_eq!(t.highest_seq(&ik), Some(9), "must not regress to the last-written value");
    }

    #[test]
    fn republish_is_due_before_expiry() {
        let r = rec(&key(), 1);
        assert!(!r.needs_republish(NOW, DEFAULT_REPUBLISH_SECS));
        let due = NOW + DEFAULT_REPUBLISH_SECS * 1_000;
        assert!(r.needs_republish(due, DEFAULT_REPUBLISH_SECS));
        // The whole point of the cadence: republish falls due while the record is still live.
        r.check_fresh(due, SKEW).expect("still live when republish falls due");
    }

    #[test]
    fn empty_addrs_is_legal() {
        // A node reachable only via a rendezvous introduction publishes no dialable hint.
        let ik = key();
        let r = LocationRecord::issue(&ik, b"pid".to_vec(), vec![], 1, DEFAULT_TTL_SECS, NOW, None);
        let back = LocationRecord::from_det_cbor(&r.det_cbor()).expect("decodes");
        assert!(back.addrs.is_empty());
        back.validate(NOW, SKEW, SUPPORTED).expect("valid, just not directly dialable");
    }

    #[test]
    fn error_codes_match_the_normative_registry() {
        assert_eq!(LocationError::SigInvalid.code(), 0x0301);
        assert_eq!(LocationError::Stale.code(), 0x0302);
        assert_eq!(LocationError::Unreachable.code(), 0x0303);
        assert_eq!(LocationError::Expired.code(), 0x0303);
        // Retry policy per §21.5: content failures terminal, reachability failures retryable.
        assert!(!LocationError::SigInvalid.retryable());
        assert!(!LocationError::Stale.retryable());
        assert!(LocationError::Unreachable.retryable());
    }

    #[test]
    fn unknown_map_keys_are_rejected() {
        let r = rec(&key(), 1);
        let Cv::Map(mut m) = r.to_cv(true) else { unreachable!() };
        m.push((99, Cv::U64(1)));
        let bytes = cbor::encode(&Cv::Map(m));
        assert!(LocationRecord::from_det_cbor(&bytes).is_err(), "deny_unknown must fail closed");
    }

    #[test]
    fn every_required_field_is_required() {
        let r = rec(&key(), 1);
        for missing in 1..=7u64 {
            let Cv::Map(m) = r.to_cv(true) else { unreachable!() };
            let kept: Vec<_> = m.into_iter().filter(|(k, _)| *k != missing).collect();
            let bytes = cbor::encode(&Cv::Map(kept));
            assert!(
                LocationRecord::from_det_cbor(&bytes).is_err(),
                "key {missing} is MUST per §18.5.1 but decoded without it"
            );
        }
    }
}
