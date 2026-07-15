//! Provisioning seam — create/suspend/lookup accounts and `@`-addresses across the three
//! onboarding tiers (spec §3.8). Self-host default ([`SelfHostProvisioning`]) is a single
//! local owner that always succeeds.

use crate::AccountId;

/// The onboarding tier for an address (spec §3.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressTier {
    /// Tier A: key-only, no domain, no DNS.
    KeyOnly,
    /// Tier B: `name@<gateway-domain>` — operator owns the domain; zero user DNS.
    GatewayDomain,
    /// Tier C: vanity `name@yourbrand.com` — operator auto-configures the domain's DNS.
    VanityDomain,
}

/// A provisioned account/tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub id: AccountId,
    /// The identity public key (base64url), the durable identity (spec §1).
    pub ik: String,
    pub address: Option<String>,
    pub tier: AddressTier,
    pub suspended: bool,
}

/// A request to provision (or look up) an address for an identity.
#[derive(Debug, Clone)]
pub struct ProvisionRequest {
    pub ik: String,
    pub desired_name: Option<String>,
    pub tier: AddressTier,
}

/// The result of provisioning.
#[derive(Debug, Clone)]
pub enum ProvisionResult {
    Provisioned(Account),
    /// The desired name is taken (tier B) or the domain is not yet verified (tier C).
    Unavailable { reason: String },
    /// Tier C only: DNS/DKIM/DMARC auto-config is pending operator/registrar action.
    PendingDomainSetup { account: Account, instructions: String },
}

/// Account/address lifecycle. Implemented by an operator; the OSS calls it during onboarding
/// and administration.
pub trait Provisioning: Send + Sync {
    fn provision(&self, req: ProvisionRequest) -> ProvisionResult;
    fn lookup(&self, account: &str) -> Option<Account>;
    fn suspend(&self, account: &str) -> bool;
    fn resume(&self, account: &str) -> bool;
}

/// Self-host default: one local owner, everything succeeds, no tenancy. The self-hoster owns
/// their domain and DNS out-of-band, so provisioning is a no-op that just echoes success.
#[derive(Debug, Default, Clone, Copy)]
pub struct SelfHostProvisioning;

impl Provisioning for SelfHostProvisioning {
    fn provision(&self, req: ProvisionRequest) -> ProvisionResult {
        ProvisionResult::Provisioned(Account {
            id: crate::SELF_HOST_ACCOUNT.to_string(),
            ik: req.ik,
            address: req.desired_name,
            tier: req.tier,
            suspended: false,
        })
    }
    fn lookup(&self, _account: &str) -> Option<Account> {
        None // self-host does not maintain an account directory
    }
    fn suspend(&self, _account: &str) -> bool {
        false // self-host never suspends itself
    }
    fn resume(&self, _account: &str) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_host_always_provisions() {
        let p = SelfHostProvisioning;
        let r = p.provision(ProvisionRequest {
            ik: "ik123".into(),
            desired_name: Some("me@gw.example".into()),
            tier: AddressTier::GatewayDomain,
        });
        assert!(matches!(r, ProvisionResult::Provisioned(_)));
    }

    #[test]
    fn self_host_never_suspends() {
        assert!(!SelfHostProvisioning.suspend("self-host"));
    }
}
