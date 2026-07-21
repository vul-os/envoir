//! Gateway authorization — a fail-closed reference implementation of `dmtap-seam`'s
//! [`dmtap_seam::GatewayAuthz`], ported bit-for-bit (logic unchanged) from an earlier, retired
//! control-plane prototype. This module never computes a price and never references billing —
//! accountability and quota are separate concerns (see [`crate::policy`] for quota).
//!
//! This ties to the fairness/accountability model (spec §7.7, §9): a gateway attributes abuse to
//! an anonymous-but-accountable credential (ARC token / postage / attested operator identity and
//! measured reputation) rather than an IP, which is what makes a shared or open gateway
//! economically viable. Self-host imposes none of this (`dmtap_seam::OpenGatewayAuthz` allows
//! everything — you are your own gateway).
//!
//! ## The two paths, and why they differ (spec §12.2)
//!
//! [`authorize_gateway`] is the **online** path: the operator (or an in-process check) is
//! reachable, so an anonymous ARC `token` can be validated/rate-limited against the operator's
//! registry. [`fallback_on_operator_unreachable`] is the **safe default** an out-of-process
//! operator's own HTTP adapter MUST fall back to when the operator cannot be reached at all —
//! and it is intentionally **stricter**: a bare token is not honored there, because validating one
//! requires the very operator that is unreachable. This is the one seam decision that MUST NOT
//! fail open to a generic "allow" (see `CONTRACT.md` §12.2).

use dmtap_seam::gateway_authz::{GatewayAuthz, GatewayDecision, SendCredential};

/// Minimum proof-of-work difficulty (bits) treated as self-contained, operator-independent
/// accountability — verifiable by the receiving node/gateway alone, with no operator round-trip.
/// Used identically by both [`authorize_gateway`] (online) and
/// [`fallback_on_operator_unreachable`] (offline) so the two paths never silently diverge on what
/// counts as "sufficient" proof.
pub const MIN_SELF_CONTAINED_POW_BITS: u32 = 20;

/// Authorize legacy egress **while the operator is reachable** (the normal, online path): a
/// known/hosted account is authorized (whether it is *permitted to proceed under its quota* is a
/// separate question — see [`crate::policy`]); an anonymous ARC-token/postage/PoW sender is
/// authorized if the accountability check passes (a token can be validated online). Abuse is
/// attributed to the token, never to a decrypted identity (spec §9).
///
/// Contrast with [`fallback_on_operator_unreachable`]: that function runs *without* the
/// operator's registry available, so it cannot trust a bare `token` (validating one requires the
/// operator) and is intentionally stricter.
pub fn authorize_gateway(cred: &SendCredential) -> GatewayDecision {
    if cred.account.is_some() {
        // A known/hosted sender: accountability is established by the account itself. Whether
        // this specific send is within any configured limit is a `Policy` question, not this one.
        GatewayDecision::Allow
    } else if cred.token.is_some() || cred.postage > 0 || cred.pow_bits >= MIN_SELF_CONTAINED_POW_BITS {
        // Anonymous but accountable (ARC token / postage / PoW). Authorized; a Policy/rate-limit
        // check by token is the caller's separate concern.
        GatewayDecision::Allow
    } else {
        GatewayDecision::Deny { reason: "cold sender: attach a token, postage, or proof-of-work".into() }
    }
}

/// Facts a conformant OSS node can establish **locally**, without the operator, about a
/// would-be legacy-egress recipient — used only by [`fallback_on_operator_unreachable`].
#[derive(Debug, Clone, Copy, Default)]
pub struct EgressContext {
    /// This node has previously exchanged mail with the recipient (an "already-established
    /// contact", per dmtap §12.2) — a fact the node itself can determine from its own history,
    /// with no operator round-trip.
    pub established_contact: bool,
}

/// §12.2, normative: the safe default `GatewayAuthz` MUST fall back to when the operator is
/// **unreachable**. This is the one seam decision that MUST NOT fail open to a generic "allow" —
/// unlike a quota/[`crate::policy`] fallback, because unattributable legacy egress is exactly the
/// open-relay failure mode (spec §7.7) accountability (§9) exists to prevent.
///
/// Permits legacy egress only to:
///   1. already-established contacts (`ctx.established_contact`), or
///   2. senders carrying **self-contained** proof verifiable *without* the operator: postage or
///      sufficient proof-of-work. A bare `token` (ARC) is deliberately **not** honored here —
///      validating/rate-limiting a token requires the operator's registry, so it cannot
///      authorize offline; that is exactly the distinction from [`authorize_gateway`]'s online
///      path, where a token IS honored because the operator can check it.
///
/// Everything else — cold, unproven, unestablished — is denied for the outage window.
pub fn fallback_on_operator_unreachable(cred: &SendCredential, ctx: &EgressContext) -> GatewayDecision {
    if ctx.established_contact {
        return GatewayDecision::Allow;
    }
    if cred.postage > 0 || cred.pow_bits >= MIN_SELF_CONTAINED_POW_BITS {
        return GatewayDecision::Allow;
    }
    GatewayDecision::Deny { reason: "operator unreachable: cold/unproven legacy egress denied (dmtap §12.2)".into() }
}

/// The single entry point an out-of-process operator's own HTTP adapter should call: dispatches to
/// the online or offline path depending on whether the operator itself could be reached for this
/// request. In-process operators that are never "unreachable" from their own point of view
/// typically only need [`authorize_gateway`] directly (see [`StaticGatewayAuthz`]).
pub fn authorize(operator_reachable: bool, cred: &SendCredential, ctx: &EgressContext) -> GatewayDecision {
    if operator_reachable {
        authorize_gateway(cred)
    } else {
        fallback_on_operator_unreachable(cred, ctx)
    }
}

/// An in-process reference [`GatewayAuthz`]: always "reachable" (there is no network hop to an
/// out-of-process operator), so it is exactly [`authorize_gateway`] wrapped in the trait. An
/// operator wiring a remote/out-of-process implementation should instead call
/// [`authorize`]/[`fallback_on_operator_unreachable`] directly from their own adapter, where they
/// can observe transport failures and establish [`EgressContext`].
#[derive(Debug, Default, Clone, Copy)]
pub struct StaticGatewayAuthz;

impl GatewayAuthz for StaticGatewayAuthz {
    fn authorize(&self, cred: &SendCredential) -> GatewayDecision {
        authorize_gateway(cred)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- online gateway authorization (operator reachable) ----

    #[test]
    fn cold_anonymous_sender_denied_without_accountability() {
        let cred = SendCredential { account: None, token: None, postage: 0, pow_bits: 0 };
        assert!(matches!(authorize_gateway(&cred), GatewayDecision::Deny { .. }));
    }

    #[test]
    fn anonymous_with_postage_allowed() {
        let cred = SendCredential { account: None, token: None, postage: 5, pow_bits: 0 };
        assert_eq!(authorize_gateway(&cred), GatewayDecision::Allow);
    }

    #[test]
    fn anonymous_with_token_allowed_online() {
        let cred = SendCredential { account: None, token: Some("arc-token".into()), postage: 0, pow_bits: 0 };
        assert_eq!(authorize_gateway(&cred), GatewayDecision::Allow);
    }

    #[test]
    fn known_account_allowed() {
        let cred = SendCredential::none("a");
        assert_eq!(authorize_gateway(&cred), GatewayDecision::Allow);
    }

    // ---- §12.2 safe-default fallback (operator UNREACHABLE) ----

    #[test]
    fn fallback_denies_cold_sender_with_no_established_contact_and_no_proof() {
        let cred = SendCredential { account: None, token: None, postage: 0, pow_bits: 0 };
        let ctx = EgressContext { established_contact: false };
        assert!(matches!(fallback_on_operator_unreachable(&cred, &ctx), GatewayDecision::Deny { .. }));
    }

    #[test]
    fn fallback_allows_already_established_contact() {
        let cred = SendCredential { account: None, token: None, postage: 0, pow_bits: 0 };
        let ctx = EgressContext { established_contact: true };
        assert_eq!(fallback_on_operator_unreachable(&cred, &ctx), GatewayDecision::Allow);
    }

    #[test]
    fn fallback_allows_self_contained_postage_without_established_contact() {
        let cred = SendCredential { account: None, token: None, postage: 1, pow_bits: 0 };
        let ctx = EgressContext { established_contact: false };
        assert_eq!(fallback_on_operator_unreachable(&cred, &ctx), GatewayDecision::Allow);
    }

    #[test]
    fn fallback_allows_sufficient_pow_without_established_contact() {
        let cred = SendCredential { account: None, token: None, postage: 0, pow_bits: 22 };
        let ctx = EgressContext { established_contact: false };
        assert_eq!(fallback_on_operator_unreachable(&cred, &ctx), GatewayDecision::Allow);
    }

    #[test]
    fn fallback_does_not_honor_a_bare_token_unlike_the_online_path() {
        // This is the crux of §12.2: a token alone is NOT self-contained proof (validating it
        // needs the operator), so it must NOT authorize egress during an outage, even though
        // `authorize_gateway` (the online path) does honor it.
        let cred = SendCredential { account: None, token: Some("arc-token".into()), postage: 0, pow_bits: 0 };
        let ctx = EgressContext { established_contact: false };
        assert!(matches!(fallback_on_operator_unreachable(&cred, &ctx), GatewayDecision::Deny { .. }));
        // Contrast: the SAME credential is allowed online.
        assert_eq!(authorize_gateway(&cred), GatewayDecision::Allow);
    }

    #[test]
    fn fallback_never_fails_open_to_a_generic_allow() {
        // Sweep a battery of "nothing established, nothing provable" credentials and assert
        // every single one denies — i.e. there is no path to a bare "allow" fallback.
        for pow in [0u32, 5, 19] {
            let cred = SendCredential { account: None, token: None, postage: 0, pow_bits: pow };
            let ctx = EgressContext { established_contact: false };
            assert!(matches!(fallback_on_operator_unreachable(&cred, &ctx), GatewayDecision::Deny { .. }));
        }
    }

    // ---- the dispatcher ----

    #[test]
    fn dispatcher_routes_to_online_when_reachable() {
        let cred = SendCredential { account: None, token: Some("t".into()), postage: 0, pow_bits: 0 };
        let ctx = EgressContext::default();
        assert_eq!(authorize(true, &cred, &ctx), GatewayDecision::Allow);
    }

    #[test]
    fn dispatcher_routes_to_fallback_when_unreachable() {
        let cred = SendCredential { account: None, token: Some("t".into()), postage: 0, pow_bits: 0 };
        let ctx = EgressContext::default();
        assert!(matches!(authorize(false, &cred, &ctx), GatewayDecision::Deny { .. }));
    }

    // ---- StaticGatewayAuthz (in-process trait impl) ----

    #[test]
    fn static_gateway_authz_matches_authorize_gateway() {
        let g = StaticGatewayAuthz;
        let cred = SendCredential::none("a");
        assert_eq!(g.authorize(&cred), authorize_gateway(&cred));
    }

    // ---- pow-bits boundary, both paths ----

    #[test]
    fn pow_boundary_online_path() {
        let below = SendCredential { account: None, token: None, postage: 0, pow_bits: MIN_SELF_CONTAINED_POW_BITS - 1 };
        let at = SendCredential { account: None, token: None, postage: 0, pow_bits: MIN_SELF_CONTAINED_POW_BITS };
        assert!(matches!(authorize_gateway(&below), GatewayDecision::Deny { .. }));
        assert_eq!(authorize_gateway(&at), GatewayDecision::Allow);
    }

    #[test]
    fn pow_boundary_fallback_path() {
        let ctx = EgressContext { established_contact: false };
        let below = SendCredential { account: None, token: None, postage: 0, pow_bits: MIN_SELF_CONTAINED_POW_BITS - 1 };
        let at = SendCredential { account: None, token: None, postage: 0, pow_bits: MIN_SELF_CONTAINED_POW_BITS };
        assert!(matches!(fallback_on_operator_unreachable(&below, &ctx), GatewayDecision::Deny { .. }));
        assert_eq!(fallback_on_operator_unreachable(&at, &ctx), GatewayDecision::Allow);
    }

    // ---- full decision matrix: fallback must never allow anything the online path denies, and
    // must never allow more than its two blessed conditions (established contact / self-contained
    // proof) regardless of what combination of fields is set. ----

    #[test]
    fn fallback_decision_matrix_is_a_strict_subset_of_online_allow_and_never_fails_open() {
        let bools = [false, true];
        let pow_values = [0u32, MIN_SELF_CONTAINED_POW_BITS - 1, MIN_SELF_CONTAINED_POW_BITS, MIN_SELF_CONTAINED_POW_BITS + 5];
        let postages = [0u64, 1, 100];

        for &has_token in &bools {
            for &postage in &postages {
                for &pow in &pow_values {
                    for &established in &bools {
                        let cred = SendCredential {
                            account: None,
                            token: if has_token { Some("arc-token".into()) } else { None },
                            postage,
                            pow_bits: pow,
                        };
                        let ctx = EgressContext { established_contact: established };
                        let fb = fallback_on_operator_unreachable(&cred, &ctx);

                        let should_allow = established || postage > 0 || pow >= MIN_SELF_CONTAINED_POW_BITS;
                        assert_eq!(
                            fb == GatewayDecision::Allow,
                            should_allow,
                            "mismatch for token={} postage={} pow={} established={}",
                            has_token, postage, pow, established
                        );

                        // Never-fail-open property: whenever the fallback allows *on
                        // self-contained credential proof* (postage/PoW — the dimension
                        // `authorize_gateway` can also evaluate), the online path must allow too.
                        // `established_contact` is deliberately excluded from this check: it is
                        // local history `authorize_gateway`'s signature has no way to see, not a
                        // credential property, so the two functions are incomparable on that axis.
                        if fb == GatewayDecision::Allow && !established {
                            assert_eq!(authorize_gateway(&cred), GatewayDecision::Allow);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn online_path_is_strictly_more_permissive_than_fallback_via_bare_token() {
        // The one case where online allows but fallback (with no established contact) denies:
        // a bare ARC token with no postage/PoW. This is the precise gap §12.2 requires.
        let cred = SendCredential { account: None, token: Some("t".into()), postage: 0, pow_bits: 0 };
        assert_eq!(authorize_gateway(&cred), GatewayDecision::Allow);
        let ctx = EgressContext { established_contact: false };
        assert!(matches!(fallback_on_operator_unreachable(&cred, &ctx), GatewayDecision::Deny { .. }));
    }
}
