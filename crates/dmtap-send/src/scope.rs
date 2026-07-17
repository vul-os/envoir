//! The **send scope** — the least-privilege right an Envoir Send API key carries.
//!
//! An API key is not an opaque string of permissions: it is a DMTAP **capability token**
//! ([`dmtap_core::capability::CapabilityToken`], spec §13.5.1) granting exactly one
//! [`Capability`] — *"send mail on behalf of the owner identity"* — optionally attenuated to a
//! single sending domain and/or a rate ceiling. [`SendScope`] is the typed reference form of that
//! one `(resource, ability, caveats)` grant; [`SendScope::to_capability`] projects it onto the wire
//! `Capability` and [`SendScope::from_capability`] recovers it, so the scope is carried *inside the
//! signed, offline-verifiable token* rather than trusted out of band.
//!
//! ## The grant
//! - `resource` — `"mail:send"` for the whole account, or `"mail:send/<domain>"` narrowed to one
//!   sending domain. The `/`-delimited sub-scope is exactly the covering relation the core's
//!   attenuation invariant (§18.7.3) uses, so a domain-scoped child key is a valid narrowing of a
//!   whole-account parent.
//! - `ability` — always `"send"`.
//! - `caveats` — a text-keyed attenuating map (§18.3.6): the `env` (prod/test) the key belongs to,
//!   and an optional `rate_per_min` ceiling the service enforces per key.

use dmtap_core::capability::Capability;
use dmtap_core::cbor::Cv;

/// The capability resource prefix for the send right (§13.5.1 least-privilege naming).
pub const SEND_RESOURCE: &str = "mail:send";
/// The capability ability (verb) for the send right.
pub const SEND_ABILITY: &str = "send";

/// The prod/test partition of an API key (Resend/Stripe convention). Prod keys carry the
/// `envoir_live_` secret prefix; test keys carry `envoir_test_`. The environment is a signed
/// caveat, so a test key can never be replayed as a prod key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    /// Live sends against real recipients.
    Prod,
    /// Sandbox sends (the [`crate::seam::Delivery`] transport MAY route these to a sink).
    Test,
}

impl Environment {
    /// The `env` caveat value.
    pub fn as_str(self) -> &'static str {
        match self {
            Environment::Prod => "prod",
            Environment::Test => "test",
        }
    }

    /// The API-key secret prefix (so a leaked key's environment is visible at a glance).
    pub fn secret_prefix(self) -> &'static str {
        match self {
            Environment::Prod => "envoir_live_",
            Environment::Test => "envoir_test_",
        }
    }

    /// Parse an `env` caveat value, failing closed on anything unrecognized.
    #[allow(clippy::should_implement_trait)] // fallible inherent parse mirroring dmtap_core::identity::Cap::from_str
    pub fn from_str(s: &str) -> Result<Environment, ScopeError> {
        match s {
            "prod" => Ok(Environment::Prod),
            "test" => Ok(Environment::Test),
            _ => Err(ScopeError::UnknownEnvironment),
        }
    }
}

/// A failure projecting a [`Capability`] back to a [`SendScope`] — a capability whose shape is not a
/// send grant this service understands. Fail closed rather than guess a broader scope.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ScopeError {
    /// The capability's `ability` is not [`SEND_ABILITY`].
    #[error("capability is not a send grant (ability != \"send\")")]
    NotSend,
    /// The capability's `resource` is not `mail:send` or `mail:send/<domain>`.
    #[error("capability resource is not a mail:send scope")]
    BadResource,
    /// The `caveats` map is missing/malformed or lacks the required `env` caveat.
    #[error("capability caveats are missing or malformed")]
    BadCaveats,
    /// The `env` caveat value is not `prod`/`test`.
    #[error("capability env caveat is not prod/test")]
    UnknownEnvironment,
}

/// The typed send grant an API key carries — the reference form of its one [`Capability`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendScope {
    /// `None` = the whole account (all sending domains); `Some(d)` = narrowed to domain `d`.
    pub domain: Option<String>,
    /// The prod/test partition this key belongs to.
    pub environment: Environment,
    /// An optional per-key send ceiling, in messages per minute, enforced by the service.
    pub rate_per_min: Option<u64>,
}

impl SendScope {
    /// A whole-account prod scope with no rate ceiling.
    pub fn account(environment: Environment) -> Self {
        SendScope { domain: None, environment, rate_per_min: None }
    }

    /// A scope narrowed to a single sending domain.
    pub fn domain(domain: impl Into<String>, environment: Environment) -> Self {
        SendScope { domain: Some(domain.into()), environment, rate_per_min: None }
    }

    /// Builder: attach a per-minute rate ceiling.
    pub fn with_rate_per_min(mut self, rate: u64) -> Self {
        self.rate_per_min = Some(rate);
        self
    }

    /// The capability `resource` string this scope maps to.
    pub fn resource(&self) -> String {
        match &self.domain {
            Some(d) => format!("{SEND_RESOURCE}/{d}"),
            None => SEND_RESOURCE.to_string(),
        }
    }

    /// Project this scope onto the wire [`Capability`] (§18.7.3): a `(resource, ability, caveats)`
    /// grant carried inside the signed token. Caveats are the deterministic-safe text-keyed subset.
    pub fn to_capability(&self) -> Capability {
        let mut caveats = vec![("env".to_string(), Cv::Text(self.environment.as_str().to_string()))];
        if let Some(n) = self.rate_per_min {
            caveats.push(("rate_per_min".to_string(), Cv::U64(n)));
        }
        Capability {
            resource: self.resource(),
            ability: SEND_ABILITY.to_string(),
            caveats: Some(Cv::TextMap(caveats)),
        }
    }

    /// Recover a [`SendScope`] from a verified [`Capability`], failing closed on any grant that is
    /// not a recognizable send scope.
    pub fn from_capability(cap: &Capability) -> Result<SendScope, ScopeError> {
        if cap.ability != SEND_ABILITY {
            return Err(ScopeError::NotSend);
        }
        let domain = if cap.resource == SEND_RESOURCE {
            None
        } else if let Some(d) = cap.resource.strip_prefix(&format!("{SEND_RESOURCE}/")) {
            if d.is_empty() {
                return Err(ScopeError::BadResource);
            }
            Some(d.to_string())
        } else {
            return Err(ScopeError::BadResource);
        };
        let pairs = match &cap.caveats {
            Some(Cv::TextMap(p)) => p,
            _ => return Err(ScopeError::BadCaveats),
        };
        let env_str = pairs
            .iter()
            .find(|(k, _)| k == "env")
            .and_then(|(_, v)| match v {
                Cv::Text(s) => Some(s.as_str()),
                _ => None,
            })
            .ok_or(ScopeError::BadCaveats)?;
        let environment = Environment::from_str(env_str)?;
        let rate_per_min = pairs.iter().find(|(k, _)| k == "rate_per_min").and_then(|(_, v)| match v {
            Cv::U64(n) => Some(*n),
            _ => None,
        });
        Ok(SendScope { domain, environment, rate_per_min })
    }

    /// Whether this scope authorizes sending as the given `from` address (spec §13.5.1
    /// least-privilege): a whole-account scope authorizes any `from`; a domain-scoped one requires
    /// the `from` address's domain (the part after `@`) to equal the scoped domain. Fail closed on a
    /// `from` with no `@`.
    pub fn authorizes_from(&self, from: &str) -> bool {
        match &self.domain {
            None => from.contains('@'),
            Some(d) => from.rsplit_once('@').map(|(_, dom)| dom == d).unwrap_or(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_round_trips() {
        let scope = SendScope::domain("example.com", Environment::Prod).with_rate_per_min(60);
        let cap = scope.to_capability();
        assert_eq!(cap.resource, "mail:send/example.com");
        assert_eq!(cap.ability, "send");
        let back = SendScope::from_capability(&cap).unwrap();
        assert_eq!(scope, back);
    }

    #[test]
    fn account_scope_round_trips_without_rate() {
        let scope = SendScope::account(Environment::Test);
        let back = SendScope::from_capability(&scope.to_capability()).unwrap();
        assert_eq!(scope, back);
        assert_eq!(scope.resource(), "mail:send");
    }

    #[test]
    fn from_capability_fails_closed_on_wrong_shape() {
        let mut cap = SendScope::account(Environment::Prod).to_capability();
        cap.ability = "read".into();
        assert_eq!(SendScope::from_capability(&cap), Err(ScopeError::NotSend));

        let mut cap = SendScope::account(Environment::Prod).to_capability();
        cap.resource = "files:read".into();
        assert_eq!(SendScope::from_capability(&cap), Err(ScopeError::BadResource));

        let mut cap = SendScope::account(Environment::Prod).to_capability();
        cap.caveats = None;
        assert_eq!(SendScope::from_capability(&cap), Err(ScopeError::BadCaveats));
    }

    #[test]
    fn authorizes_from_respects_domain_narrowing() {
        let acct = SendScope::account(Environment::Prod);
        assert!(acct.authorizes_from("anyone@anywhere.com"));
        assert!(!acct.authorizes_from("no-at-sign"));

        let scoped = SendScope::domain("example.com", Environment::Prod);
        assert!(scoped.authorizes_from("hello@example.com"));
        assert!(!scoped.authorizes_from("hello@other.com"));
        assert!(!scoped.authorizes_from("example.com")); // no @, fail closed
    }

    #[test]
    fn environment_prefixes_are_distinct() {
        assert_eq!(Environment::Prod.secret_prefix(), "envoir_live_");
        assert_eq!(Environment::Test.secret_prefix(), "envoir_test_");
        assert_eq!(Environment::from_str("prod").unwrap(), Environment::Prod);
        assert_eq!(Environment::from_str("nonsense"), Err(ScopeError::UnknownEnvironment));
    }
}
