//! Policy / entitlements seam — quotas and limits per account. Self-host default
//! ([`UnlimitedPolicy`]) allows everything.
//!
//! Policy gates *operations and organizational limits only* — storage caps, monthly gateway
//! send caps, domain counts, rate limits. It MUST NOT gate privacy or crypto: there is no
//! `Quota` for "encryption" or "metadata privacy", by design.

use crate::AccountId;

/// A quota dimension being checked, carrying the requested amount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quota {
    /// Requested total stored bytes.
    StorageBytes(u64),
    /// Requested count of legacy gateway sends this period.
    GatewaySends(u64),
    /// Requested number of managed vanity domains.
    Domains(u32),
    /// Requested send-rate (messages per minute).
    SendRate(u32),
}

/// The outcome of a policy check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    /// Allowed, but the operator reports the remaining headroom (for UI/warnings).
    AllowWithRemaining(u64),
    /// Denied; `reason` is safe to surface to the user (e.g. "storage limit reached").
    Deny { reason: String },
}

/// Per-account entitlements. Implemented by an operator; the OSS consults it before performing
/// a metered/limited operation.
pub trait Policy: Send + Sync {
    fn check(&self, account: &AccountId, quota: &Quota) -> PolicyDecision;
}

/// Self-host default: unlimited. Everything is allowed — the self-hoster's resources are their
/// own concern, and the OSS imposes no artificial limits.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnlimitedPolicy;

impl Policy for UnlimitedPolicy {
    fn check(&self, _account: &AccountId, _quota: &Quota) -> PolicyDecision {
        PolicyDecision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlimited_allows_all() {
        let p = UnlimitedPolicy;
        assert_eq!(
            p.check(&"a".to_string(), &Quota::StorageBytes(u64::MAX)),
            PolicyDecision::Allow
        );
        assert_eq!(
            p.check(&"a".to_string(), &Quota::GatewaySends(1_000_000)),
            PolicyDecision::Allow
        );
    }
}
