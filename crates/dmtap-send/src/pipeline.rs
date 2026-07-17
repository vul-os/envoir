//! The send pipeline — API key → sealed MOTE → transport.
//!
//! [`SendService::send`] is the reusable core of the Envoir Send service. It:
//! 1. **verifies** the API key ([`SendService::verify_key`]) — fail-closed on unknown/expired/
//!    revoked/foreign;
//! 2. **enforces scope** — the request's `from` address must be authorized by the key's
//!    [`SendScope`] (a domain-scoped key cannot send from another domain), else
//!    [`SendError::OutOfScope`];
//! 3. **charges the rate ceiling** — the key's signed `rate_per_min` caveat
//!    ([`SendService::charge_rate`]);
//! 4. **resolves** the recipient via the [`Resolver`] seam to its routing + KEM keys;
//! 5. **builds + seals a real MOTE** to the recipient key ([`dmtap_core::mote::build_mote`]): the
//!    payload is signed under the owner identity and HPKE-sealed (suite `0x01`) to the recipient's
//!    X25519 key, then content-addressed and envelope-signed under a fresh ephemeral key;
//! 6. **delivers** it via the [`Delivery`] seam (native mesh or legacy gateway) and returns a
//!    [`SendReceipt`] carrying the MOTE content-address.

use dmtap_core::identity::IdentityKey;
use dmtap_core::mote::{build_mote, Envelope, Headers, Kind, MoteDraft};
use dmtap_core::{ContentId, TimestampMs};

use serde::Deserialize;

use crate::key::{SendError, SendService};
use crate::seam::{Delivery, DeliveryReceipt, Resolver};

/// The parameters of one send. Deserialized from the `POST /v1/send` JSON body (§clients).
#[derive(Debug, Clone, Deserialize)]
pub struct SendRequest {
    /// The sending address (e.g. `hello@example.com`). MUST be authorized by the key's scope.
    pub from: String,
    /// The recipient address/name, resolved by the [`Resolver`] seam.
    pub to: String,
    /// The mail subject (§2.4 header).
    #[serde(default)]
    pub subject: String,
    /// The message body (UTF-8 text). Sealed inside the MOTE payload (§2.4).
    #[serde(default)]
    pub body: String,
    /// Optional MIME type of the body (defaults to unset ⇒ `text/plain` by convention).
    #[serde(default)]
    pub mime: Option<String>,
}

impl SendRequest {
    /// A minimal request.
    pub fn new(from: impl Into<String>, to: impl Into<String>, subject: impl Into<String>, body: impl Into<String>) -> Self {
        SendRequest { from: from.into(), to: to.into(), subject: subject.into(), body: body.into(), mime: None }
    }
}

/// The result of a successful send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendReceipt {
    /// The MOTE content-address (`Envelope.id`, §2.2) — the message id the caller persists.
    pub message_id: ContentId,
    /// The sealed MOTE itself, for inspection/persistence.
    pub envelope: Envelope,
    /// The transport receipt.
    pub delivery: DeliveryReceipt,
    /// Whether it went native (`true`) or via the legacy gateway (`false`).
    pub native: bool,
}

impl SendService {
    /// Run the full send pipeline for one request. See the module docs for the ordered steps. Every
    /// failure is a fail-closed [`SendError`].
    pub fn send<R: Resolver, D: Delivery>(
        &mut self,
        resolver: &R,
        delivery: &D,
        api_key: &str,
        now: TimestampMs,
        req: &SendRequest,
    ) -> Result<SendReceipt, SendError> {
        // 1. Verify the key (fail-closed on unknown/expired/revoked/foreign/attenuation).
        let auth = self.verify_key(api_key, now)?;

        // 2. Enforce scope: the `from` must be authorized by the key's least-privilege grant.
        if !auth.scope.authorizes_from(&req.from) {
            return Err(SendError::OutOfScope);
        }

        // 3. Charge the per-key rate ceiling (a signed caveat), if any.
        self.charge_rate(&auth.key_hash, now)?;

        // 4. Resolve the recipient to its routing + KEM keys.
        let recipient = resolver.resolve(&req.to).map_err(|e| SendError::Resolve(e.0))?;

        // 5. Build + seal a REAL MOTE to the resolved recipient key.
        let ephemeral = IdentityKey::generate();
        let draft = MoteDraft {
            kind: Kind::Mail,
            ts: now,
            headers: Headers {
                thread: None,
                subject: if req.subject.is_empty() { None } else { Some(req.subject.clone()) },
                mime: req.mime.clone(),
                cc: Vec::new(),
            },
            body: req.body.clone().into_bytes(),
            refs: Vec::new(),
            attach: Vec::new(),
            expires: None,
            epoch: None,
            keypkg: None,
            challenge: None,
        };
        let envelope = build_mote(
            self.sealer(),
            self.signer(),
            &ephemeral,
            &recipient.ik,
            &recipient.seal_pub,
            draft,
        )
        .map_err(|e| SendError::Build(e.to_string()))?;

        // 6. Hand the sealed MOTE to the transport seam.
        let receipt = delivery.deliver(&envelope, &recipient).map_err(|e| SendError::Delivery(e.0))?;

        Ok(SendReceipt {
            message_id: envelope.id.clone(),
            native: recipient.is_native,
            delivery: receipt,
            envelope,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::{Environment, SendScope};
    use crate::seam::{CapturingDelivery, ResolvedRecipient, StaticResolver};
    use dmtap_core::mote::{validate, Hpke, Outcome, RecipientCtx, SealKeypair};

    const YEAR: u64 = 365 * 24 * 60 * 60 * 1000;

    fn owner() -> IdentityKey {
        IdentityKey::from_seed(&[0x42; 32])
    }

    // A resolver holding one recipient, returning the seal secret + ik so a test can decrypt the
    // MOTE the pipeline produced.
    fn resolver_with(address: &str, native: bool) -> (StaticResolver, IdentityKey, SealKeypair) {
        let rik = IdentityKey::generate();
        let seal = SealKeypair::generate();
        let mut r = StaticResolver::new();
        r.insert(
            address,
            ResolvedRecipient {
                address: address.to_string(),
                ik: rik.public(),
                seal_pub: seal.public().to_vec(),
                is_native: native,
            },
        );
        (r, rik, seal)
    }

    #[test]
    fn scoped_send_builds_a_real_sealed_mote_to_the_resolved_key() {
        let mut svc = SendService::new(owner());
        let now = 1_700_000_000_000;
        let key = svc.issue_key(SendScope::domain("example.com", Environment::Prod), now, YEAR);
        let (resolver, rik, seal) = resolver_with("bob@peer.example", true);
        let delivery = CapturingDelivery::new();

        let req = SendRequest::new("hello@example.com", "bob@peer.example", "hi", "hello dmtap");
        let receipt = svc.send(&resolver, &delivery, key.secret(), now, &req).unwrap();

        // A real MOTE was delivered, content-addressed, native path.
        assert!(receipt.native);
        assert_eq!(delivery.count(), 1);
        assert_eq!(receipt.message_id, receipt.envelope.id);
        assert_eq!(receipt.delivery.transport, "native-mesh");

        // The recipient can actually open + validate the sealed MOTE (real crypto end-to-end).
        let ctx = RecipientCtx { our_ik: &rik.public(), seal_secret: seal.secret(), sender_is_known: true };
        match validate(&Hpke, &receipt.envelope, &ctx).unwrap() {
            Outcome::Accepted(p) => {
                assert_eq!(p.body, b"hello dmtap");
                assert_eq!(p.headers.subject.as_deref(), Some("hi"));
                // The payload is authenticated as being from the service owner identity.
                assert_eq!(p.from, svc.owner_identity());
            }
            Outcome::Deferred => panic!("a known-contact MOTE must be accepted"),
        }
    }

    #[test]
    fn out_of_scope_from_is_rejected() {
        let mut svc = SendService::new(owner());
        let now = 1_700_000_000_000;
        // Key scoped to example.com only.
        let key = svc.issue_key(SendScope::domain("example.com", Environment::Prod), now, YEAR);
        let (resolver, _rik, _seal) = resolver_with("bob@peer.example", true);
        let delivery = CapturingDelivery::new();

        // Try to send FROM a different domain — out of scope.
        let req = SendRequest::new("evil@other.com", "bob@peer.example", "x", "y");
        assert_eq!(svc.send(&resolver, &delivery, key.secret(), now, &req), Err(SendError::OutOfScope));
        assert_eq!(delivery.count(), 0, "no MOTE is built for an out-of-scope request");
    }

    #[test]
    fn revoked_key_cannot_send() {
        let mut svc = SendService::new(owner());
        let now = 1_700_000_000_000;
        let key = svc.issue_key(SendScope::account(Environment::Prod), now, YEAR);
        svc.revoke_key(key.secret(), now).unwrap();
        let (resolver, _rik, _seal) = resolver_with("bob@peer.example", true);
        let delivery = CapturingDelivery::new();
        let req = SendRequest::new("hello@example.com", "bob@peer.example", "x", "y");
        assert_eq!(svc.send(&resolver, &delivery, key.secret(), now + 1, &req), Err(SendError::Revoked));
    }

    #[test]
    fn expired_key_cannot_send() {
        let mut svc = SendService::new(owner());
        let now = 1_000_000;
        let key = svc.issue_key(SendScope::account(Environment::Prod), now, 60_000);
        let (resolver, _rik, _seal) = resolver_with("bob@peer.example", true);
        let delivery = CapturingDelivery::new();
        let req = SendRequest::new("hello@example.com", "bob@peer.example", "x", "y");
        assert_eq!(
            svc.send(&resolver, &delivery, key.secret(), now + 60_000, &req),
            Err(SendError::Expired)
        );
    }

    #[test]
    fn rate_ceiling_is_enforced_per_key() {
        let mut svc = SendService::new(owner());
        let now = 1_700_000_000_000; // start of a fresh minute window
        let key = svc.issue_key(SendScope::account(Environment::Prod).with_rate_per_min(2), now, YEAR);
        let (resolver, _rik, _seal) = resolver_with("bob@peer.example", true);
        let delivery = CapturingDelivery::new();
        let req = SendRequest::new("hello@example.com", "bob@peer.example", "x", "y");

        assert!(svc.send(&resolver, &delivery, key.secret(), now, &req).is_ok());
        assert!(svc.send(&resolver, &delivery, key.secret(), now + 1, &req).is_ok());
        // Third send in the same 60s window is rate limited.
        assert_eq!(svc.send(&resolver, &delivery, key.secret(), now + 2, &req), Err(SendError::RateLimited));
        // A send in the NEXT window is allowed again.
        assert!(svc.send(&resolver, &delivery, key.secret(), now + 60_000, &req).is_ok());
        assert_eq!(delivery.count(), 3);
    }

    #[test]
    fn unresolvable_recipient_fails_closed() {
        let mut svc = SendService::new(owner());
        let now = 1_700_000_000_000;
        let key = svc.issue_key(SendScope::account(Environment::Prod), now, YEAR);
        let resolver = StaticResolver::new(); // empty
        let delivery = CapturingDelivery::new();
        let req = SendRequest::new("hello@example.com", "ghost@nowhere", "x", "y");
        assert!(matches!(
            svc.send(&resolver, &delivery, key.secret(), now, &req),
            Err(SendError::Resolve(_))
        ));
    }

    #[test]
    fn gateway_recipient_uses_gateway_transport() {
        let mut svc = SendService::new(owner());
        let now = 1_700_000_000_000;
        let key = svc.issue_key(SendScope::account(Environment::Prod), now, YEAR);
        let (resolver, _rik, _seal) = resolver_with("legacy@gmail.com", false);
        let delivery = CapturingDelivery::new();
        let req = SendRequest::new("hello@example.com", "legacy@gmail.com", "x", "y");
        let receipt = svc.send(&resolver, &delivery, key.secret(), now, &req).unwrap();
        assert!(!receipt.native);
        assert_eq!(receipt.delivery.transport, "smtp-gateway");
    }
}
