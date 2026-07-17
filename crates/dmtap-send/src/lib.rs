//! # dmtap-send — Envoir Send
//!
//! A **Resend-style programmatic send API, built on DMTAP capabilities** — a sovereign / private
//! Resend. Where Resend hands you an opaque API key backed by a vendor's account, Envoir Send makes
//! the API key a real, signed, offline-verifiable **capability token** (spec §13.5.1 / §18.7.3)
//! rooted at *your* DMTAP identity, and makes a "send" build and seal a real **MOTE** (spec §2) to
//! the recipient's key. You run it; you hold the key; the API keys are scoped, revocable delegations
//! of the right to trigger sends.
//!
//! This crate is the **reusable library core** of that service. Real crypto throughout (capability
//! tokens, MOTE sealing) via [`dmtap_core`]; the transport and HTTP surfaces are honest seams.
//!
//! ## The API key = a capability
//! An API key is a [`dmtap_core::capability::CapabilityToken`] granting one least-privilege
//! [`SendScope`] — *"send mail on behalf of the owner, optionally within one domain, at a rate
//! ceiling"*. The bearer string is a high-entropy secret; the service stores only its
//! content-address → the backing token. See [`SendService`]:
//! - [`SendService::issue_key`] — mint a scoped root key (many per identity: prod/test/per-service);
//! - [`SendService::attenuate_key`] — sub-delegate to a narrower scope (a real attenuated chain;
//!   widening is rejected);
//! - [`SendService::rotate_key`] — mint a replacement + revoke the old;
//! - [`SendService::revoke_key`] — revoke locally + emit a signed [`CapabilityRevocation`];
//! - [`SendService::verify_key`] — resolve a secret to an [`Authorization`], fail-closed on
//!   unknown/expired/revoked/foreign/out-of-attenuation.
//!
//! ## The send pipeline
//! [`SendService::send`] verifies the key → enforces scope + the rate caveat → resolves the
//! recipient ([`Resolver`] seam) → builds + HPKE-seals a real MOTE to the recipient key
//! ([`dmtap_core::mote::build_mote`]) → hands it to the [`Delivery`] seam (native mesh or legacy
//! gateway). See [`SendRequest`] / [`SendReceipt`].
//!
//! ## The HTTP surface
//! A thin, framework-free adapter maps `POST /v1/send` (Bearer auth, JSON body) onto
//! [`SendService::send`] — see [`http::handle_send`]. Wire it behind any server.
//!
//! ## Real vs. seam
//! - **Real:** capability issue/rotate/revoke/verify (Ed25519, §18.7.3), attenuation + revocation
//!   enforcement, MOTE build + HPKE sealing to the recipient key (§2). All deterministic — clocks
//!   are `now` parameters, never wall-clock reads (§16.1).
//! - **Seam:** recipient resolution ([`Resolver`]), MOTE delivery ([`Delivery`]), and the HTTP glue.
//!   The crate ships in-memory reference impls for tests/local; production supplies real ones.

#![forbid(unsafe_code)]

pub mod http;
pub mod key;
pub mod pipeline;
pub mod scope;
pub mod seam;

pub use dmtap_core::capability::CapabilityRevocation;
pub use key::{ApiKey, Authorization, SendError, SendService};
pub use pipeline::{SendReceipt, SendRequest};
pub use scope::{Environment, ScopeError, SendScope};
pub use seam::{
    CapturingDelivery, Delivery, DeliveryError, DeliveryReceipt, ResolveError, ResolvedRecipient,
    Resolver, StaticResolver,
};

#[cfg(test)]
mod tests {
    //! An end-to-end walkthrough exercising the whole public surface together.
    use super::*;
    use dmtap_core::identity::IdentityKey;
    use dmtap_core::mote::{validate, Hpke, Outcome, RecipientCtx, SealKeypair};

    const YEAR: u64 = 365 * 24 * 60 * 60 * 1000;

    #[test]
    fn end_to_end_issue_scope_attenuate_send_rotate_revoke() {
        let now = 1_700_000_000_000;
        let mut svc = SendService::new(IdentityKey::from_seed(&[7; 32]));

        // Issue a prod account key, then attenuate it to a single domain with a rate ceiling.
        let root = svc.issue_key(SendScope::account(Environment::Prod), now, YEAR);
        let scoped = svc
            .attenuate_key(root.secret(), SendScope::domain("example.com", Environment::Prod).with_rate_per_min(5), now, YEAR)
            .unwrap();

        // A resolvable native recipient.
        let rik = IdentityKey::generate();
        let seal = SealKeypair::generate();
        let mut resolver = StaticResolver::new();
        resolver.insert(
            "bob@peer.example",
            ResolvedRecipient { address: "bob@peer.example".into(), ik: rik.public(), seal_pub: seal.public().to_vec(), is_native: true },
        );
        let delivery = CapturingDelivery::new();

        // Send with the attenuated key; the recipient decrypts + validates a real MOTE.
        let req = SendRequest::new("hello@example.com", "bob@peer.example", "subject", "body-bytes");
        let receipt = svc.send(&resolver, &delivery, scoped.secret(), now, &req).unwrap();
        let ctx = RecipientCtx { our_ik: &rik.public(), seal_secret: seal.secret(), sender_is_known: true };
        assert!(matches!(validate(&Hpke, &receipt.envelope, &ctx).unwrap(), Outcome::Accepted(_)));

        // Rotate the attenuated key: old stops working, new works (and stays domain-scoped).
        let rotated = svc.rotate_key(scoped.secret(), now + 1, YEAR).unwrap();
        assert_eq!(svc.verify_key(scoped.secret(), now + 2), Err(SendError::Revoked));
        let auth = svc.verify_key(rotated.secret(), now + 2).unwrap();
        assert_eq!(auth.scope.domain.as_deref(), Some("example.com"));

        // Revoking the root revokes the (rotated) descendant too.
        svc.revoke_key(root.secret(), now + 3).unwrap();
        assert_eq!(svc.verify_key(rotated.secret(), now + 4), Err(SendError::Revoked));
        assert!(!svc.published_revocations().is_empty());
    }
}
