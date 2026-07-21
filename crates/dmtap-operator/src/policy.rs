//! Flat quota policy — a reference implementation of `dmtap-seam`'s [`dmtap_seam::Policy`]: one
//! configured limit per dimension, applied to every account alike. No plans, no pricing, no
//! per-account entitlement table — an operator that needs any of that implements [`Policy`]
//! directly (or attaches whatever billing/entitlement system they use, at the seam boundary);
//! this is the smallest useful, genuinely load-bearing thing.
//!
//! Quota gates *operations and organizational limits only* — see `dmtap-seam`'s crate docs for the
//! inviolable rule this inherits unchanged: there is no `Quota` variant for privacy or crypto.

use dmtap_seam::{AccountId, Policy, PolicyDecision, Quota};

/// A single flat quota configuration, applied uniformly to every account this policy is asked
/// about. `0` means "no allowance" for that dimension (every request over it is denied); use
/// `u64::MAX` / `u32::MAX` for effectively unlimited.
#[derive(Debug, Clone, Copy)]
pub struct StaticQuotas {
    pub storage_bytes: u64,
    pub gateway_sends: u64,
    pub domains: u32,
    pub send_rate: u32,
}

impl StaticQuotas {
    /// Every dimension unlimited — equivalent in effect to [`dmtap_seam::UnlimitedPolicy`], but
    /// going through this type's per-dimension configuration (useful as a base to narrow from).
    pub fn unlimited() -> Self {
        StaticQuotas { storage_bytes: u64::MAX, gateway_sends: u64::MAX, domains: u32::MAX, send_rate: u32::MAX }
    }

    fn decide(requested: u64, limit: u64) -> PolicyDecision {
        if requested > limit {
            PolicyDecision::Deny { reason: "operator quota exceeded".into() }
        } else {
            PolicyDecision::AllowWithRemaining(limit - requested)
        }
    }
}

impl Policy for StaticQuotas {
    fn check(&self, _account: &AccountId, quota: &Quota) -> PolicyDecision {
        match *quota {
            Quota::StorageBytes(req) => Self::decide(req, self.storage_bytes),
            Quota::GatewaySends(req) => Self::decide(req, self.gateway_sends),
            Quota::Domains(req) => Self::decide(req as u64, self.domains as u64),
            Quota::SendRate(req) => Self::decide(req as u64, self.send_rate as u64),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quotas() -> StaticQuotas {
        StaticQuotas { storage_bytes: 1_000_000, gateway_sends: 100, domains: 1, send_rate: 60 }
    }

    #[test]
    fn under_allowance_allows_with_remaining() {
        let acct: AccountId = "a".into();
        assert_eq!(quotas().check(&acct, &Quota::StorageBytes(0)), PolicyDecision::AllowWithRemaining(1_000_000));
        assert_eq!(quotas().check(&acct, &Quota::GatewaySends(40)), PolicyDecision::AllowWithRemaining(60));
    }

    #[test]
    fn exactly_at_allowance_allows_with_zero_remaining() {
        let acct: AccountId = "a".into();
        assert_eq!(quotas().check(&acct, &Quota::StorageBytes(1_000_000)), PolicyDecision::AllowWithRemaining(0));
        assert_eq!(quotas().check(&acct, &Quota::GatewaySends(100)), PolicyDecision::AllowWithRemaining(0));
        assert_eq!(quotas().check(&acct, &Quota::Domains(1)), PolicyDecision::AllowWithRemaining(0));
    }

    #[test]
    fn one_over_allowance_denies() {
        let acct: AccountId = "a".into();
        assert!(matches!(quotas().check(&acct, &Quota::StorageBytes(1_000_001)), PolicyDecision::Deny { .. }));
        assert!(matches!(quotas().check(&acct, &Quota::GatewaySends(101)), PolicyDecision::Deny { .. }));
        assert!(matches!(quotas().check(&acct, &Quota::Domains(2)), PolicyDecision::Deny { .. }));
        assert!(matches!(quotas().check(&acct, &Quota::SendRate(61)), PolicyDecision::Deny { .. }));
    }

    #[test]
    fn same_limits_apply_to_every_account() {
        let q = quotas();
        assert_eq!(
            q.check(&"a".to_string(), &Quota::Domains(1)),
            q.check(&"b".to_string(), &Quota::Domains(1)),
        );
    }

    #[test]
    fn unlimited_allows_everything() {
        let q = StaticQuotas::unlimited();
        let acct: AccountId = "a".into();
        assert_eq!(q.check(&acct, &Quota::StorageBytes(u64::MAX)), PolicyDecision::AllowWithRemaining(0));
        assert_eq!(q.check(&acct, &Quota::GatewaySends(1_000_000)), PolicyDecision::AllowWithRemaining(u64::MAX - 1_000_000));
    }

    #[test]
    fn zero_limit_denies_any_nonzero_request() {
        let q = StaticQuotas { storage_bytes: 0, gateway_sends: 0, domains: 0, send_rate: 0 };
        let acct: AccountId = "a".into();
        assert!(matches!(q.check(&acct, &Quota::StorageBytes(1)), PolicyDecision::Deny { .. }));
        assert_eq!(q.check(&acct, &Quota::StorageBytes(0)), PolicyDecision::AllowWithRemaining(0));
    }

    #[test]
    fn policy_check_never_has_a_quota_variant_for_privacy_or_crypto() {
        // Structural assertion, not a runtime one: Quota's four variants are exactly the
        // operational ones from CONTRACT.md. Exhaustive match with no wildcard arm means this
        // test fails to COMPILE if a fifth variant is ever added without updating this proof.
        fn _exhaustive(q: Quota) -> &'static str {
            match q {
                Quota::StorageBytes(_) => "storage_bytes",
                Quota::GatewaySends(_) => "gateway_sends",
                Quota::Domains(_) => "domains",
                Quota::SendRate(_) => "send_rate",
            }
        }
    }
}
