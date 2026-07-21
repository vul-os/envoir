//! DMTAP-PUBSUB (spec §25) — the distributed pub/sub extension over §22.
//!
//! §22 gives a publisher a signed, content-addressed feed that anyone may serve and anyone may
//! pull. What it does not give is any artifact for the other side of the relationship: "following a
//! feed" leaves nothing a publisher can point to, audit, or expire, so a subscriber list is
//! whatever bookkeeping each implementation invents. §25 supplies the missing objects:
//!
//! - [`Subscription`] (§25.4) — a **signed, self-verifying, bounded-lifetime capability** for one
//!   `(feed, topic)` pair. Bounded lifetime is a MUST, not a default: every entry in a publisher's
//!   hint list carries a hard expiry in the very capability that put it there, so an abandoned
//!   subscription self-extinguishes even if no revoke is ever sent.
//! - [`SubscriptionRevoke`] (§25.5) — withdrawal, signed by the subscriber that granted it.
//! - [`FeedHint`] (§25.6.2) — an **advisory** "something changed, go check" notice, carried as
//!   ordinary `Payload.body` in a sealed envelope (`kind = 0x41`), which is what buys it §2.6
//!   deliver/ack/retry and sealed sender for free.
//!
//! **Everything here is additive.** No core wire object changes, and no new transport: a
//! `feed_subscribe` is an ordinary MOTE arriving at the publisher, which is why it is already
//! subject to the §9 cold-sender gate without inventing a bespoke registration path.
//!
//! ## The one thing to get right about `FeedHint`
//!
//! A hint is **a reason to check, never a fact checked**. `seq`/`tip` MUST NOT advance a
//! subscriber's accepted-`seq` watermark and MUST NOT be treated as evidence of delivery — the
//! signed `FeedHead`/`FeedEntry` chain and the content address remain the only authority (§25.6.2).
//! That is why `FeedHint` carries no signature of its own: it is authenticated by the enclosing
//! `Payload.sig` as an ordinary sender would be, and giving it a signature of its own would invite
//! exactly the mistake of treating it as authoritative. This module therefore offers no
//! `FeedHint::verify` — there is nothing it could honestly verify, and a function named `verify`
//! would imply the hint can be trusted once it returns `Ok`.
//!
//! ## Scope
//!
//! Quotas (§25.7.1 `0x0912`, §25.7.2 `0x0913`) are **policy**, not wire objects: their codes exist
//! in [`PubError`] so a holder can report them, but the budgets themselves are a node's own
//! configuration and are deliberately not modelled here.

use crate::cbor::{self, as_bytes, as_text, as_u64, as_u8, Cv, Fields};
use crate::id::ContentId;
use crate::identity::{verify_domain, DeviceCert, IdentityKey};
use crate::pubobj::{pub_suite, PubError, PUB_V0};
use crate::suite::Suite;

/// `DMTAP-PUB-v0/subscription\x00` — the [`Subscription`] signing-preimage prefix (§25.4.1).
pub const PUB_SUBSCRIPTION_DS: &[u8] = b"DMTAP-PUB-v0/subscription\x00";
/// `DMTAP-PUB-v0/subscription-revoke\x00` — the [`SubscriptionRevoke`] prefix (§25.5.1).
pub const PUB_SUBSCRIPTION_REVOKE_DS: &[u8] = b"DMTAP-PUB-v0/subscription-revoke\x00";

/// §25.4.1: `nonce` MUST be at least 16 bytes. It is the uniqueness source that keeps two
/// subscriptions issued by the same subscriber, for the same `(feed, topic)`, in the same
/// millisecond, content-addressing distinctly.
pub const SUBSCRIPTION_NONCE_MIN: usize = 16;

// ── Subscription (§25.4.1) ───────────────────────────────────────────────────────────────────

/// A subscriber's signed request to receive [`FeedHint`]s for one `(feed, topic)` pair (§25.4.1).
///
/// Self-signed rather than relying on the enclosing MOTE, for the same reason `PubAnnounce` and
/// `PushSubscription` are: it must stay verifiable **after** it leaves the envelope that carried
/// it. A publisher may delegate hint-pushing to another holder by handing over the accepted
/// records, and that holder re-verifies each one itself rather than trusting the publisher's
/// bookkeeping — which only works if the object stands alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    /// key 1 — PUBSUB object version; MUST be [`PUB_V0`] in v0.
    pub v: u8,
    /// key 2 — signature/hash suite (§18.1.4).
    pub suite: Suite,
    /// key 3 — the subscriber's root identity key `IK`; the delivery target for hints.
    pub subscriber: Vec<u8>,
    /// key 4 — the feed author's `IK` (`FeedHead.pub`, §22.4.1) being subscribed to.
    pub feed: Vec<u8>,
    /// key 5 — topic label (§25.3); `""` names the default/untopiced feed.
    pub topic: String,
    /// key 6 — creation time (ms epoch).
    pub issued: u64,
    /// key 7 — absolute expiry (ms epoch). **Required**: there is no indefinite subscription.
    pub expires: u64,
    /// key 8 — ≥ [`SUBSCRIPTION_NONCE_MIN`] bytes of uniqueness for `subscription_id`.
    pub nonce: Vec<u8>,
    /// key 9 — operational key that produced `sig`; a `DeviceCert` chains it to `subscriber`.
    pub signer: Vec<u8>,
    /// key 10 — `signer` over `DMTAP-PUB-v0/subscription ‖ 0x00 ‖ det_cbor(Subscription ∖ {10})`.
    pub sig: Vec<u8>,
}

impl Subscription {
    fn to_cv(&self, include_sig: bool) -> Cv {
        let mut m = vec![
            (1u64, Cv::U64(self.v as u64)),
            (2, Cv::U64(self.suite.as_u8() as u64)),
            (3, Cv::Bytes(self.subscriber.clone())),
            (4, Cv::Bytes(self.feed.clone())),
            (5, Cv::Text(self.topic.clone())),
            (6, Cv::U64(self.issued)),
            (7, Cv::U64(self.expires)),
            (8, Cv::Bytes(self.nonce.clone())),
            (9, Cv::Bytes(self.signer.clone())),
        ];
        if include_sig {
            m.push((10, Cv::Bytes(self.sig.clone())));
        }
        Cv::Map(m)
    }

    /// The §25.4.1 signing-preimage body: `det_cbor(Subscription ∖ {10})`.
    pub fn signing_preimage(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(false))
    }

    /// The exact wire bytes of the complete, signed object.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(true))
    }

    /// `subscription_id = 0x1e ‖ BLAKE3-256(det_cbor(Subscription))` over the **complete, signed**
    /// object — the derived-anchor rule (§18.9.4): a field cannot contain its own hash.
    pub fn subscription_id(&self) -> ContentId {
        ContentId::of(&self.det_cbor())
    }

    /// Sign with `signer_key`, which the caller is responsible for matching to `self.signer`.
    pub fn sign(&mut self, signer_key: &IdentityKey) {
        self.sig = signer_key.sign_domain(PUB_SUBSCRIPTION_DS, &self.signing_preimage());
    }

    /// Verify a `Subscription` whose `signer` is the subscriber's own `IK` (§25.4.1).
    ///
    /// Structural validity only — **not** liveness. Whether it is currently honorable also depends
    /// on the clock and on revocation, which are [`check_active`](Subscription::check_active) and
    /// [`SubscriptionRevoke`]; keeping them separate is deliberate, because a verifier that has no
    /// trustworthy clock can still establish that the object is genuine.
    pub fn verify(&self) -> Result<(), PubError> {
        self.verify_signature()?;
        // An operational signer needs a DeviceCert; a bare object whose signer ≠ subscriber has
        // presented no authorization at all, so it fails closed here rather than being accepted on
        // the strength of a signature by a key nothing has tied to the subscriber.
        if self.signer != self.subscriber {
            return Err(PubError::SubscriptionSigInvalid);
        }
        Ok(())
    }

    /// Like [`verify`](Subscription::verify), but authorizing an operational `signer` through a
    /// [`DeviceCert`] chaining it to `subscriber` (§25.4.1, §1.2) — the same check §22.3.3 step 4
    /// applies to a `PubAnnounce`'s signer.
    pub fn verify_with_cert(&self, cert: &DeviceCert) -> Result<(), PubError> {
        self.verify_signature()?;
        if self.signer == self.subscriber {
            return Ok(());
        }
        cert.verify().map_err(|_| PubError::SubscriptionSigInvalid)?;
        if cert.ik != self.subscriber || cert.device_key != self.signer {
            return Err(PubError::SubscriptionSigInvalid);
        }
        Ok(())
    }

    fn verify_signature(&self) -> Result<(), PubError> {
        if self.v != PUB_V0 || !self.suite.is_supported() {
            return Err(PubError::UnsupportedVersion);
        }
        verify_domain(&self.signer, PUB_SUBSCRIPTION_DS, &self.signing_preimage(), &self.sig)
            .map_err(|_| PubError::SubscriptionSigInvalid)
    }

    /// §25.4.2: a `Subscription` is honorable only while `now <= expires`. A holder MUST NOT push a
    /// hint under an expired subscription (`ERR_PUB_SUBSCRIPTION_EXPIRED`, `0x090F`).
    ///
    /// This is the backstop that bounds the cooperative-revocation residual (§25.5.2): a holder
    /// that never learns of a revoke stops anyway, when the expiry lapses.
    pub fn check_active(&self, now: u64) -> Result<(), PubError> {
        if now > self.expires {
            return Err(PubError::SubscriptionExpired);
        }
        Ok(())
    }

    /// Decode a `Subscription` (§25.4.1), fail-closed on every violation.
    ///
    /// `expires` absent is **malformed**, not "non-expiring" (§25.4.2) — it is decoded with `req`
    /// for exactly that reason. Treating an absent bound as an unbounded one is the failure mode
    /// the MUST exists to prevent.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, PubError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let v = as_u8(f.req(1)?)?;
        if v != PUB_V0 {
            return Err(PubError::UnsupportedVersion);
        }
        let suite = pub_suite(f.req(2)?)?;
        let subscriber = as_bytes(f.req(3)?)?;
        let feed = as_bytes(f.req(4)?)?;
        let topic = as_text(f.req(5)?)?;
        let issued = as_u64(f.req(6)?)?;
        let expires = as_u64(f.req(7)?)?;
        let nonce = as_bytes(f.req(8)?)?;
        if nonce.len() < SUBSCRIPTION_NONCE_MIN {
            return Err(PubError::Cbor(cbor::CborError::TypeMismatch));
        }
        let signer = as_bytes(f.req(9)?)?;
        let sig = as_bytes(f.req(10)?)?;
        f.deny_unknown()?;
        Ok(Subscription {
            v,
            suite,
            subscriber,
            feed,
            topic,
            issued,
            expires,
            nonce,
            signer,
            sig,
        })
    }
}

// ── SubscriptionRevoke (§25.5.1) ─────────────────────────────────────────────────────────────

/// A subscriber's signed withdrawal of one [`Subscription`] (§25.5.1).
///
/// Needs no content address of its own — nothing ever points *at* a revoke — but is self-signed for
/// the same portability reason as [`Subscription`]: a delegated holder can honor a revoke it never
/// saw travel through the original transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionRevoke {
    /// key 1 — the `subscription_id` (§25.4.1) being revoked.
    pub subscription: ContentId,
    /// key 2 — revocation time (ms epoch).
    pub ts: u64,
    /// key 3 — MUST be the target `Subscription.subscriber`, or an authorized device thereof.
    pub signer: Vec<u8>,
    /// key 4 — `signer` over `DMTAP-PUB-v0/subscription-revoke ‖ 0x00 ‖ det_cbor(∖ {4})`.
    pub sig: Vec<u8>,
}

impl SubscriptionRevoke {
    fn to_cv(&self, include_sig: bool) -> Cv {
        let mut m = vec![
            (1u64, Cv::Bytes(self.subscription.as_bytes().to_vec())),
            (2, Cv::U64(self.ts)),
            (3, Cv::Bytes(self.signer.clone())),
        ];
        if include_sig {
            m.push((4, Cv::Bytes(self.sig.clone())));
        }
        Cv::Map(m)
    }

    /// The §25.5.1 signing-preimage body: `det_cbor(SubscriptionRevoke ∖ {4})`.
    pub fn signing_preimage(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(false))
    }

    /// The exact wire bytes of the complete, signed object.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(true))
    }

    /// Sign with `signer_key`, which the caller is responsible for matching to `self.signer`.
    pub fn sign(&mut self, signer_key: &IdentityKey) {
        self.sig = signer_key.sign_domain(PUB_SUBSCRIPTION_REVOKE_DS, &self.signing_preimage());
    }

    /// Verify this revoke **against the subscription it names** (§25.5.1).
    ///
    /// Both halves matter and neither is sufficient alone: the signature must verify, AND `signer`
    /// must be the target's `subscriber` (or a certified device of it), AND the named
    /// `subscription_id` must actually be this subscription's. Only the subscriber who granted a
    /// subscription may withdraw it — a cross-subscriber revoke would otherwise let anyone
    /// unsubscribe anyone, which is why the target is a parameter rather than something the caller
    /// is trusted to have matched up beforehand.
    pub fn verify_for(
        &self,
        target: &Subscription,
        cert: Option<&DeviceCert>,
    ) -> Result<(), PubError> {
        if self.subscription != target.subscription_id() {
            return Err(PubError::SubscriptionRevokeInvalid);
        }
        verify_domain(&self.signer, PUB_SUBSCRIPTION_REVOKE_DS, &self.signing_preimage(), &self.sig)
            .map_err(|_| PubError::SubscriptionRevokeInvalid)?;
        if self.signer == target.subscriber {
            return Ok(());
        }
        // An operational device may revoke, but only on a chain to the SUBSCRIBER — not to the
        // feed, and not to whoever happens to be holding the record.
        let cert = cert.ok_or(PubError::SubscriptionRevokeInvalid)?;
        cert.verify().map_err(|_| PubError::SubscriptionRevokeInvalid)?;
        if cert.ik != target.subscriber || cert.device_key != self.signer {
            return Err(PubError::SubscriptionRevokeInvalid);
        }
        Ok(())
    }

    /// Decode a `SubscriptionRevoke` (§25.5.1), fail-closed on every violation.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, PubError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let subscription = ContentId(as_bytes(f.req(1)?)?);
        let ts = as_u64(f.req(2)?)?;
        let signer = as_bytes(f.req(3)?)?;
        let sig = as_bytes(f.req(4)?)?;
        f.deny_unknown()?;
        Ok(SubscriptionRevoke { subscription, ts, signer, sig })
    }
}

// ── FeedHint (§25.6.2) ───────────────────────────────────────────────────────────────────────

/// An **advisory** notice that a feed changed (§25.6.2), carried as ordinary `Payload.body` in a
/// sealed envelope with `Envelope.kind = 0x41`.
///
/// `seq` and `tip` MUST NOT advance a subscriber's accepted-`seq` watermark and MUST NOT be treated
/// as evidence of delivery. A conformant subscriber performs (or schedules) an independently
/// verified `feed_head`/`feed_range` fetch — or verifies an inlined [`announce`](FeedHint::announce)
/// exactly as a pulled `PubAnnounce` — before accepting any change in feed state.
///
/// There is deliberately **no `verify` method**: a hint carries no authority of its own, so any
/// function of that name would be a lie the type system would then be endorsing. Authentication of
/// the *sender* comes from the enclosing `Payload.sig`, and authority over *content* comes only
/// from the signed feed chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedHint {
    /// key 1 — the feed author identity (`FeedHead.pub`) this hint concerns.
    pub feed: Vec<u8>,
    /// key 2 — topic label (§25.3); `""` = the default feed.
    pub topic: String,
    /// key 3 — the publisher's belief about the new tip `seq`. **Advisory only.**
    pub seq: u64,
    /// key 4 — the publisher's belief about the new `FeedHead.tip`. **Advisory only.**
    pub tip: Option<ContentId>,
    /// key 5 — an optional inlined `det_cbor(PubAnnounce)` for the entry at `seq` (§25.6.3). A
    /// bounded convenience, never a trust shortcut: it is verified exactly as a pulled announce.
    pub announce: Option<Vec<u8>>,
}

impl FeedHint {
    fn to_cv(&self) -> Cv {
        let mut m = vec![
            (1u64, Cv::Bytes(self.feed.clone())),
            (2, Cv::Text(self.topic.clone())),
            (3, Cv::U64(self.seq)),
        ];
        if let Some(t) = &self.tip {
            m.push((4, Cv::Bytes(t.as_bytes().to_vec())));
        }
        if let Some(a) = &self.announce {
            m.push((5, Cv::Bytes(a.clone())));
        }
        Cv::Map(m)
    }

    /// The exact wire bytes of this hint, as they appear in `Payload.body`.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv())
    }

    /// Decode a `FeedHint` (§25.6.2), fail-closed on every violation.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, PubError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let feed = as_bytes(f.req(1)?)?;
        let topic = as_text(f.req(2)?)?;
        let seq = as_u64(f.req(3)?)?;
        let tip = f.take(4).map(as_bytes).transpose()?.map(ContentId);
        let announce = f.take(5).map(as_bytes).transpose()?;
        f.deny_unknown()?;
        Ok(FeedHint { feed, topic, seq, tip, announce })
    }
}

// ── Fan-out bounds (§25.7) ───────────────────────────────────────────────────────────────────

/// A holder's **aggregate** subscriber-admission bound (§25.7.1) — the DMTAP-PUBSUB analogue of
/// [`crate::pubobj::ServePolicy`]'s quota half.
///
/// §25.4.3 notes why this is needed on top of the cold-sender gate: a per-message gate stops any one
/// stranger from imposing themselves for free, but says nothing about how large the resulting list
/// is allowed to grow. A popular feed may clear that gate thousands of times.
///
/// Like `ServePolicy`, the decision is stateless and the counting is the caller's — the bound is
/// node configuration, not a spec constant, so this type holds the policy and not the ledger.
#[derive(Debug, Clone, Default)]
pub struct SubscribePolicy {
    /// Maximum aggregate active `Subscription`s honored per `(feed, topic)`, or `None` for no bound.
    pub max_active_per_topic: Option<u64>,
    /// Maximum active `Subscription`s honored per subscriber identity, or `None` for no bound.
    pub max_active_per_subscriber: Option<u64>,
}

impl SubscribePolicy {
    /// Admit one more `Subscription` given the currently-active counts. Exceeding either bound is
    /// [`PubError::SubscribeQuota`] (`0x0912`, DENY_POLICY) — a policy deny at the holder, never a
    /// security or crypto gate, and never a silent drop.
    pub fn admit(&self, active_for_topic: u64, active_for_subscriber: u64) -> Result<(), PubError> {
        if let Some(max) = self.max_active_per_topic {
            if active_for_topic.saturating_add(1) > max {
                return Err(PubError::SubscribeQuota);
            }
        }
        if let Some(max) = self.max_active_per_subscriber {
            if active_for_subscriber.saturating_add(1) > max {
                return Err(PubError::SubscribeQuota);
            }
        }
        Ok(())
    }
}

/// A subscriber's own inbound [`FeedHint`] budget, per publisher or per `(feed, topic)` (§25.7.2).
///
/// This is deliberately the SUBSCRIBER's limiter, enforced independently of whatever the publisher
/// applies — the same dual-ended discipline §4.9.4 gives Wake. Subscribing once does not entitle a
/// publisher to an unbounded claim on a subscriber's battery or bandwidth, and a compromised or
/// merely misconfigured publisher key must not be able to convert that into a flood.
///
/// Excess is `DROP_SILENT` (§25.7.2): [`PubError::HintRateLimited`] (`0x0913`) tells the *node* why
/// it dropped, and is not something to surface to the user — a hint asserts nothing the subscriber
/// must act on, so a dropped one costs nothing but the check it would have prompted.
#[derive(Debug, Clone)]
pub struct HintBudget {
    /// Maximum hints admitted per window.
    pub max_per_window: u32,
    /// Window length in milliseconds.
    pub window_ms: u64,
    window_start: u64,
    used: u32,
}

impl HintBudget {
    /// A budget of `max_per_window` hints per `window_ms`, starting at `now`.
    pub fn new(max_per_window: u32, window_ms: u64, now: u64) -> Self {
        HintBudget { max_per_window, window_ms, window_start: now, used: 0 }
    }

    /// Admit one inbound hint at `now`, refilling if the window has rolled over. Over budget is
    /// [`PubError::HintRateLimited`] (`0x0913`).
    ///
    /// The clock is an explicit parameter: this core never reads a wall clock (§16.1), so a caller
    /// cannot be surprised by a limiter that behaves differently under test than in production.
    pub fn admit(&mut self, now: u64) -> Result<(), PubError> {
        if now.saturating_sub(self.window_start) >= self.window_ms {
            self.window_start = now;
            self.used = 0;
        }
        if self.used >= self.max_per_window {
            return Err(PubError::HintRateLimited);
        }
        self.used += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{Cap, DeviceCert};

    fn sub(ik: &IdentityKey, feed: &[u8], expires: u64) -> Subscription {
        let mut s = Subscription {
            v: PUB_V0,
            suite: Suite::Classical,
            subscriber: ik.public(),
            feed: feed.to_vec(),
            topic: "news".into(),
            issued: 1_000,
            expires,
            nonce: vec![7u8; SUBSCRIPTION_NONCE_MIN],
            signer: ik.public(),
            sig: vec![],
        };
        s.sign(ik);
        s
    }

    #[test]
    fn subscription_round_trips_and_verifies() {
        let ik = IdentityKey::generate();
        let s = sub(&ik, &[9u8; 32], 9_000);
        assert_eq!(Subscription::from_det_cbor(&s.det_cbor()).unwrap(), s);
        s.verify().unwrap();
        assert_eq!(s.subscription_id(), Subscription::from_det_cbor(&s.det_cbor()).unwrap().subscription_id());
    }

    #[test]
    fn tampering_any_signed_field_invalidates_the_signature() {
        let ik = IdentityKey::generate();
        let mut s = sub(&ik, &[9u8; 32], 9_000);
        s.topic = "other".into(); // the topic is inside the preimage
        assert_eq!(s.verify().unwrap_err(), PubError::SubscriptionSigInvalid);
        assert_eq!(s.verify().unwrap_err().code(), 0x090E);
    }

    /// §25.4.2: absent `expires` is MALFORMED, not "never expires". The distinction is the whole
    /// point of the MUST — a decoder that defaulted it to unbounded would create exactly the
    /// indefinite subscription the section forbids.
    #[test]
    fn expires_absent_is_malformed_not_unbounded() {
        let ik = IdentityKey::generate();
        let s = sub(&ik, &[9u8; 32], 9_000);
        let Cv::Map(mut pairs) = cbor::decode(&s.det_cbor()).unwrap() else { panic!("not a map") };
        pairs.retain(|(k, _)| *k != 7);
        let err = Subscription::from_det_cbor(&cbor::encode(&Cv::Map(pairs))).unwrap_err();
        assert_eq!(err, PubError::Cbor(cbor::CborError::MissingKey(7)));
    }

    #[test]
    fn short_nonce_is_rejected() {
        let ik = IdentityKey::generate();
        let mut s = sub(&ik, &[9u8; 32], 9_000);
        s.nonce = vec![1u8; SUBSCRIPTION_NONCE_MIN - 1];
        s.sign(&ik);
        assert!(Subscription::from_det_cbor(&s.det_cbor()).is_err());
    }

    #[test]
    fn expiry_is_enforced_at_the_boundary() {
        let ik = IdentityKey::generate();
        let s = sub(&ik, &[9u8; 32], 9_000);
        s.check_active(9_000).unwrap(); // `now == expires` is still active
        let err = s.check_active(9_001).unwrap_err();
        assert_eq!(err, PubError::SubscriptionExpired);
        assert_eq!(err.code(), 0x090F);
    }

    /// §25.4.1: an unrecognized `v` OR an unsupported `suite` is rejected at DECODE, not merely at
    /// verification. `Suite::from_u8` answers "is this a code point I can name", which is not the
    /// same question — a `PqHybrid` object decoded cleanly on a build that cannot verify it, and was
    /// only refused later. Fail closed before anything is believed about the bytes.
    #[test]
    fn unknown_version_and_unsupported_suite_fail_closed() {
        let ik = IdentityKey::generate();
        let mut s = sub(&ik, &[9u8; 32], 9_000);
        s.v = 1;
        s.sign(&ik);
        assert_eq!(Subscription::from_det_cbor(&s.det_cbor()).unwrap_err(), PubError::UnsupportedVersion);
        assert_eq!(s.verify().unwrap_err(), PubError::UnsupportedVersion);

        let mut bad_suite = sub(&ik, &[9u8; 32], 9_000);
        bad_suite.suite = Suite::PqHybrid; // a KNOWN code point this build does not support
        bad_suite.sign(&ik);
        assert!(!Suite::PqHybrid.is_supported(), "premise: this build cannot verify PqHybrid");
        assert_eq!(
            Subscription::from_det_cbor(&bad_suite.det_cbor()).unwrap_err(),
            PubError::UnsupportedVersion,
            "a known-but-unsupported suite must be refused at decode, not just at verify"
        );
    }

    #[test]
    fn an_operational_signer_needs_a_devicecert() {
        let ik = IdentityKey::generate();
        let device = IdentityKey::generate();
        let mut s = sub(&ik, &[9u8; 32], 9_000);
        s.signer = device.public();
        s.sign(&device);
        // Signature is valid, but nothing ties `device` to the subscriber yet.
        assert_eq!(s.verify().unwrap_err(), PubError::SubscriptionSigInvalid);

        let cert = DeviceCert::issue(&ik, device.public(), "phone", 0, None, vec![Cap::Send]);
        s.verify_with_cert(&cert).unwrap();

        // A cert for a DIFFERENT identity must not authorize this signer.
        let other = IdentityKey::generate();
        let wrong = DeviceCert::issue(&other, device.public(), "phone", 0, None, vec![Cap::Send]);
        assert_eq!(s.verify_with_cert(&wrong).unwrap_err(), PubError::SubscriptionSigInvalid);
    }

    #[test]
    fn revoke_round_trips_and_verifies_against_its_target() {
        let ik = IdentityKey::generate();
        let s = sub(&ik, &[9u8; 32], 9_000);
        let mut r = SubscriptionRevoke {
            subscription: s.subscription_id(),
            ts: 2_000,
            signer: ik.public(),
            sig: vec![],
        };
        r.sign(&ik);
        assert_eq!(SubscriptionRevoke::from_det_cbor(&r.det_cbor()).unwrap(), r);
        r.verify_for(&s, None).unwrap();
    }

    /// §25.5.1: only the subscriber who granted a subscription may withdraw it. A revoke signed by
    /// anyone else — including the feed author, who is the party that benefits from ignoring it —
    /// is rejected.
    #[test]
    fn a_cross_subscriber_revoke_is_rejected() {
        let ik = IdentityKey::generate();
        let attacker = IdentityKey::generate();
        let s = sub(&ik, &[9u8; 32], 9_000);
        let mut r = SubscriptionRevoke {
            subscription: s.subscription_id(),
            ts: 2_000,
            signer: attacker.public(),
            sig: vec![],
        };
        r.sign(&attacker);
        let err = r.verify_for(&s, None).unwrap_err();
        assert_eq!(err, PubError::SubscriptionRevokeInvalid);
        assert_eq!(err.code(), 0x0911);
    }

    /// A revoke that is perfectly valid for one subscription must not be honored against another.
    /// Without binding the target, a subscriber could revoke one subscription and have the object
    /// replayed to cancel every other subscription they hold.
    #[test]
    fn a_revoke_does_not_transfer_to_another_subscription() {
        let ik = IdentityKey::generate();
        let s1 = sub(&ik, &[9u8; 32], 9_000);
        let mut s2 = s1.clone();
        s2.nonce = vec![8u8; SUBSCRIPTION_NONCE_MIN];
        s2.sign(&ik);
        assert_ne!(s1.subscription_id(), s2.subscription_id());

        let mut r = SubscriptionRevoke {
            subscription: s1.subscription_id(),
            ts: 2_000,
            signer: ik.public(),
            sig: vec![],
        };
        r.sign(&ik);
        r.verify_for(&s1, None).unwrap();
        assert_eq!(r.verify_for(&s2, None).unwrap_err(), PubError::SubscriptionRevokeInvalid);
    }

    #[test]
    fn feed_hint_round_trips_with_and_without_optional_fields() {
        let bare = FeedHint {
            feed: vec![3u8; 32],
            topic: String::new(), // the default/untopiced feed
            seq: 42,
            tip: None,
            announce: None,
        };
        assert_eq!(FeedHint::from_det_cbor(&bare.det_cbor()).unwrap(), bare);

        let full = FeedHint {
            feed: vec![3u8; 32],
            topic: "news".into(),
            seq: 43,
            tip: Some(ContentId::of(b"tip")),
            announce: Some(vec![0xA1, 0x01, 0x02]),
        };
        assert_eq!(FeedHint::from_det_cbor(&full.det_cbor()).unwrap(), full);
    }

    #[test]
    fn subscribe_policy_bounds_the_aggregate_not_just_the_message() {
        let p = SubscribePolicy { max_active_per_topic: Some(2), max_active_per_subscriber: Some(1) };
        p.admit(0, 0).unwrap();
        p.admit(1, 0).unwrap();
        // The topic bound is aggregate: the third subscriber is refused even though each one
        // individually passed the cold-sender gate.
        let err = p.admit(2, 0).unwrap_err();
        assert_eq!(err, PubError::SubscribeQuota);
        assert_eq!(err.code(), 0x0912);
        // The per-subscriber bound is independent of the topic one.
        assert_eq!(p.admit(0, 1).unwrap_err(), PubError::SubscribeQuota);
        // No bounds configured = no deny.
        SubscribePolicy::default().admit(9_999, 9_999).unwrap();
    }

    #[test]
    fn hint_budget_bounds_the_window_and_refills() {
        let mut b = HintBudget::new(2, 1_000, 0);
        b.admit(0).unwrap();
        b.admit(10).unwrap();
        let err = b.admit(20).unwrap_err();
        assert_eq!(err, PubError::HintRateLimited);
        assert_eq!(err.code(), 0x0913);
        // Next window: the budget refills rather than staying latched shut.
        b.admit(1_000).unwrap();
        b.admit(1_100).unwrap();
        assert_eq!(b.admit(1_200).unwrap_err(), PubError::HintRateLimited);
    }

    #[test]
    fn unknown_keys_are_rejected_in_every_pubsub_object() {
        let ik = IdentityKey::generate();
        let s = sub(&ik, &[9u8; 32], 9_000);
        let Cv::Map(mut pairs) = cbor::decode(&s.det_cbor()).unwrap() else { panic!("not a map") };
        pairs.push((99, Cv::U64(1)));
        assert!(Subscription::from_det_cbor(&cbor::encode(&Cv::Map(pairs))).is_err());

        let hint = FeedHint { feed: vec![3u8; 32], topic: String::new(), seq: 1, tip: None, announce: None };
        let Cv::Map(mut hp) = cbor::decode(&hint.det_cbor()).unwrap() else { panic!("not a map") };
        hp.push((99, Cv::U64(1)));
        assert!(FeedHint::from_det_cbor(&cbor::encode(&Cv::Map(hp))).is_err());
    }
}
