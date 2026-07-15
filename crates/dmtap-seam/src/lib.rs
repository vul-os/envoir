//! # dmtap-seam — the DMTAP operator seam
//!
//! This crate is the clean boundary between the **open-source** node/gateway and any
//! **operator** that hosts them (self-host or a commercial control-plane like `envoir-cloud`).
//!
//! The seam is a small set of traits the OSS calls at well-defined points:
//!
//! - [`Metering`] — emit usage events for billing.
//! - [`Provisioning`] — create/suspend accounts and `@`-addresses (onboarding tiers A/B/C).
//! - [`Policy`] — quotas & entitlements (storage caps, send caps, rate limits).
//! - [`GatewayAuthz`] — authorize legacy egress with per-identity accountability.
//!
//! ## The self-host-default philosophy
//!
//! Every seam trait ships a **self-host default** that is unlimited / no-op ([`NullMetering`],
//! [`SelfHostProvisioning`], [`UnlimitedPolicy`], [`OpenGatewayAuthz`]). So the OSS is a
//! **fully functional, unrestricted product on its own** — you can self-host and owe nothing,
//! nothing is gated. A hosted operator supplies real implementations to add billing, quotas,
//! and multi-tenant management **without forking or patching the protocol**.
//!
//! ## The inviolable rule
//!
//! **Privacy, cryptography, metadata-privacy, and recovery are NEVER behind this seam.** The
//! seam meters and gates *operations* (hosting, storage, legacy egress) and *organizational*
//! concerns (accounts, quotas) — never protection. There is no seam hook that can disable
//! encryption, weaken the mixnet, or lock a user out of their own keys. See `CONTRACT.md`.
//!
//! ## In-process and out-of-process
//!
//! A self-host binary embeds this crate and uses the default impls directly. A hosted operator
//! (e.g. `envoir-cloud`, possibly written in another language) implements the **same contract**
//! out-of-process over HTTP/events; see `CONTRACT.md`. The OSS treats an unreachable operator
//! by **failing open to the self-host defaults** for functionality (never breaking mail) while
//! **failing closed for billing** (unmetered rather than free-forever-uncounted is an operator
//! policy choice documented in the contract).

pub mod metering;
pub mod provisioning;
pub mod policy;
pub mod gateway_authz;

pub use metering::{Metering, NullMetering, UsageEvent, UsageKind};
pub use provisioning::{
    Account, AddressTier, ProvisionRequest, ProvisionResult, Provisioning, SelfHostProvisioning,
};
pub use policy::{Policy, PolicyDecision, Quota, UnlimitedPolicy};
pub use gateway_authz::{GatewayAuthz, GatewayDecision, OpenGatewayAuthz, SendCredential};

/// An opaque account/tenant identifier at the seam boundary.
/// Self-host uses a single fixed id ([`SELF_HOST_ACCOUNT`]).
pub type AccountId = String;

/// The account id used in self-host mode (one local owner, no tenancy).
pub const SELF_HOST_ACCOUNT: &str = "self-host";

/// Milliseconds since the Unix epoch, passed explicitly (the OSS never assumes the operator's
/// clock). Callers supply the timestamp so this crate needs no clock dependency.
pub type TimestampMs = u64;

/// A bundle of the four seam implementations an operator provides. Self-host constructs this
/// with all defaults via [`Seam::self_host`].
pub struct Seam {
    pub metering: Box<dyn Metering>,
    pub provisioning: Box<dyn Provisioning>,
    pub policy: Box<dyn Policy>,
    pub gateway_authz: Box<dyn GatewayAuthz>,
}

impl Seam {
    /// The fully-functional, unlimited, no-billing self-host configuration.
    pub fn self_host() -> Self {
        Seam {
            metering: Box::new(NullMetering),
            provisioning: Box::new(SelfHostProvisioning),
            policy: Box::new(UnlimitedPolicy),
            gateway_authz: Box::new(OpenGatewayAuthz),
        }
    }
}

impl Default for Seam {
    fn default() -> Self {
        Seam::self_host()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_host_seam_is_fully_functional_and_unmetered() {
        let seam = Seam::self_host();
        // metering is a no-op
        seam.metering.record(UsageEvent {
            account: SELF_HOST_ACCOUNT.into(),
            kind: UsageKind::MessagesSent,
            amount: 1,
            ts_ms: 0,
        });
        // policy allows everything
        assert!(matches!(
            seam.policy
                .check(&SELF_HOST_ACCOUNT.to_string(), &Quota::StorageBytes(u64::MAX)),
            PolicyDecision::Allow
        ));
        // gateway authorizes everything
        assert!(matches!(
            seam.gateway_authz
                .authorize(&SendCredential::none(SELF_HOST_ACCOUNT)),
            GatewayDecision::Allow
        ));
    }
}
