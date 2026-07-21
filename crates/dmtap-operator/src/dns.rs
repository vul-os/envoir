//! **DNS onboarding automation seam + the single Cloudflare implementation.**
//!
//! When a gateway operator brings a vanity domain (Tier C, spec §3.8) online, something has to
//! publish — automatically, never by hand-editing — the record set that makes `name@domain`
//! deliverable from and to the legacy world through that gateway:
//!
//! | Record | Purpose |
//! |--------|---------|
//! | **A** `mail.<domain>` → gateway IPv4 | the gateway's mail host |
//! | **MX** `<domain>` → `mail.<domain>` | inbound legacy mail routes to the gateway (§7.2) |
//! | **TXT SPF** `<domain>` | authorizes the gateway IP to send for the domain |
//! | **TXT DKIM** `<selector>._domainkey.<domain>` | the gateway's **delegated** DKIM public key (§3.8, §7.3) |
//! | **TXT DMARC** `_dmarc.<domain>` | alignment policy so Gmail/Outlook accept the mail |
//! | **TXT DMTAP** `<local>._dmtap.<domain>` | the §3.2 `v=dmtap1; …; ik=…` discovery record |
//!
//! plus the **reverse-DNS (PTR)** for the gateway IP, which is not a forward-zone record and is a
//! separate, provider-specific operation this crate does not automate (an operator requests it
//! from whoever they lease the IP from — a hosting-provider VM provisioner is exactly the kind of
//! commercial, single-vendor machinery this crate deliberately does not include; see the crate
//! docs).
//!
//! The record-set *generation* ([`gateway_zone_records`]) is pure and fully unit-tested; the
//! network sits behind [`crate::http::HttpTransport`], so the Cloudflare API *shaping* (zone
//! lookup, upsert, delete) and every fail-closed path are tested offline against canned Cloudflare
//! JSON. The one live call is real only behind the non-default `net` feature. **Fail-closed:** a
//! Cloudflare `success:false` envelope or a non-2xx status is a [`DnsError`], never a partially-
//! published zone reported as done. Credentials come from env
//! ([`CloudflareConfig::from_env`] reads `CLOUDFLARE_API_TOKEN`), never hardcoded. This automates
//! only *operational* records — it never touches, gates, or is required by any privacy/crypto
//! feature; a self-hoster who never brings a vanity domain online never uses this module.
//!
//! Ported from an earlier, retired control-plane prototype (`envoir-cloud`) — this module was
//! already billing-free (DNS record shape has no notion of price), so nothing besides the license
//! header and this note changed.

use serde_json::Value;

use crate::http::{HttpMethod, HttpRequest, HttpTransport};

/// Cloudflare API v4 base.
pub const CLOUDFLARE_API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// Env var the Cloudflare API token is read from. Never compiled in.
pub const CLOUDFLARE_TOKEN_ENV: &str = "CLOUDFLARE_API_TOKEN";

/// Default TTL for the onboarding records (1 hour). A tunable, kept here not in the record logic.
pub const DEFAULT_TTL: u32 = 3600;

/// The record types the onboarding set uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecordType {
    A,
    Mx,
    Txt,
}

impl DnsRecordType {
    /// The Cloudflare/`dig` wire token (`"A"`, `"MX"`, `"TXT"`).
    pub fn as_str(self) -> &'static str {
        match self {
            DnsRecordType::A => "A",
            DnsRecordType::Mx => "MX",
            DnsRecordType::Txt => "TXT",
        }
    }
}

/// One DNS record to publish. `priority` is `Some` only for MX.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    /// Fully-qualified record name, e.g. `mail.example.com`, `example.com`, `_dmarc.example.com`.
    pub name: String,
    pub rtype: DnsRecordType,
    pub content: String,
    pub ttl: u32,
    pub priority: Option<u16>,
}

impl DnsRecord {
    /// An `A` record.
    pub fn a(name: impl Into<String>, ipv4: impl Into<String>, ttl: u32) -> Self {
        DnsRecord { name: name.into(), rtype: DnsRecordType::A, content: ipv4.into(), ttl, priority: None }
    }
    /// An `MX` record (with priority).
    pub fn mx(name: impl Into<String>, mail_host: impl Into<String>, priority: u16, ttl: u32) -> Self {
        DnsRecord { name: name.into(), rtype: DnsRecordType::Mx, content: mail_host.into(), ttl, priority: Some(priority) }
    }
    /// A `TXT` record.
    pub fn txt(name: impl Into<String>, content: impl Into<String>, ttl: u32) -> Self {
        DnsRecord { name: name.into(), rtype: DnsRecordType::Txt, content: content.into(), ttl, priority: None }
    }
}

/// Everything [`gateway_zone_records`] needs to build the full onboarding record set for one domain.
/// Pure data; the caller assembles it from the account (the DMTAP identity fields) and the gateway
/// it was assigned (host/IP/DKIM selector).
#[derive(Debug, Clone)]
pub struct GatewayZoneInputs {
    /// The domain being onboarded, e.g. `yourbrand.com`.
    pub domain: String,
    /// The local part for the `_dmtap` record, e.g. `alice` in `alice@yourbrand.com`.
    pub local_part: String,
    /// The gateway's mail host label under the domain (e.g. `mail`), yielding `mail.<domain>`.
    pub mail_host_label: String,
    /// The gateway's public IPv4.
    pub gateway_ipv4: String,
    /// The delegated DKIM selector the gateway signs with, e.g. `envoir1`.
    pub dkim_selector: String,
    /// The DKIM public key (base64), published verbatim in the `p=` tag.
    pub dkim_public_key: String,
    /// DKIM key algorithm tag (`"rsa"` or `"ed25519"`). Gateway's choice; `rsa` maximises legacy
    /// acceptance.
    pub dkim_key_type: String,
    /// DMARC aggregate-report address (the `rua=mailto:` target).
    pub dmarc_rua: String,
    /// DMARC policy (`"none"` / `"quarantine"` / `"reject"`).
    pub dmarc_policy: String,
    // ---- DMTAP `_dmtap` record fields (§3.2) ----
    /// Suite governing the `ik` (§1.1); v0 default `1` (classical Ed25519).
    pub dmtap_suite: u8,
    /// Base64url identity public key.
    pub dmtap_ik: String,
    /// Base64url content-id of the current `Identity` (§1.3).
    pub dmtap_id: String,
    /// KT log anchor URLs (comma-joined in the record).
    pub dmtap_kt: Vec<String>,
    /// KeyPackage bundle locator (§5.3).
    pub dmtap_keypkgs: String,
    /// TTL for every generated record.
    pub ttl: u32,
}

impl GatewayZoneInputs {
    /// The gateway mail host FQDN (`<mail_host_label>.<domain>`).
    pub fn mail_host(&self) -> String {
        format!("{}.{}", self.mail_host_label, self.domain)
    }
}

/// Build the full legacy-interop + DMTAP-discovery record set for one domain (§3.2, §3.8, §7). Pure:
/// no I/O, deterministic order, so it is exhaustively unit-tested and identical every run (records
/// self-update on key rotation by regenerating from the new identity fields).
pub fn gateway_zone_records(inp: &GatewayZoneInputs) -> Vec<DnsRecord> {
    let mail_host = inp.mail_host();
    let ttl = inp.ttl;

    // A: the gateway mail host → gateway IPv4.
    let a = DnsRecord::a(&mail_host, &inp.gateway_ipv4, ttl);

    // MX: the domain routes inbound legacy mail to the gateway host.
    let mx = DnsRecord::mx(&inp.domain, &mail_host, 10, ttl);

    // SPF: authorize the gateway IP to send for the domain; `-all` hard-fails everything else.
    let spf = DnsRecord::txt(&inp.domain, format!("v=spf1 ip4:{} -all", inp.gateway_ipv4), ttl);

    // DKIM: the gateway's delegated selector public key (the gateway signs d=<domain>; §7.3).
    let dkim = DnsRecord::txt(
        format!("{}._domainkey.{}", inp.dkim_selector, inp.domain),
        format!("v=DKIM1; k={}; p={}", inp.dkim_key_type, inp.dkim_public_key),
        ttl,
    );

    // DMARC: alignment policy so authenticated gateway mail is accepted (adkim/aspf strict).
    let dmarc = DnsRecord::txt(
        format!("_dmarc.{}", inp.domain),
        format!("v=DMARC1; p={}; rua=mailto:{}; adkim=s; aspf=s", inp.dmarc_policy, inp.dmarc_rua),
        ttl,
    );

    // DMTAP `_dmtap` discovery record (§3.2): the stable name→key pointer + KT anchor + keypkgs.
    let dmtap = DnsRecord::txt(
        format!("{}._dmtap.{}", inp.local_part, inp.domain),
        format!(
            "v=dmtap1; suite={}; ik={}; id={}; kt={}; keypkgs={}",
            inp.dmtap_suite,
            inp.dmtap_ik,
            inp.dmtap_id,
            inp.dmtap_kt.join(","),
            inp.dmtap_keypkgs,
        ),
        ttl,
    );

    vec![a, mx, spf, dkim, dmarc, dmtap]
}

/// A fail-closed DNS error. No variant is interpreted as "published anyway".
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DnsError {
    #[error("dns config error: {0}")]
    Config(String),
    #[error("dns transport error: {0}")]
    Transport(String),
    /// A Cloudflare `success:false` envelope or a non-2xx status; carries the first Cloudflare error.
    #[error("dns API error (status {status}): {code}: {message}")]
    Api { status: u16, code: String, message: String },
    /// A 2xx `success:true` body was not the shape we expected (no zone found, no record id, …).
    #[error("dns returned a malformed/absent result: {0}")]
    Malformed(String),
}

impl From<crate::http::TransportError> for DnsError {
    fn from(e: crate::http::TransportError) -> Self {
        DnsError::Transport(e.to_string())
    }
}

/// **The DNS onboarding seam.** One provider (Cloudflare) implements it today; the trait is the
/// boundary a future Route53/registrar-API impl would satisfy.
pub trait DnsProvider {
    /// Publish (create-or-update) every record in `records` under `zone`, idempotently: re-running
    /// with the same set is a no-op-equivalent (each record is replaced in place). Fail-closed — any
    /// single record that cannot be written aborts with an `Err` rather than a partial zone.
    fn upsert_records(&self, zone: &str, records: &[DnsRecord]) -> Result<(), DnsError>;

    /// Delete the records matching `records` (by name + type) under `zone`. A record already absent
    /// is not an error (idempotent teardown).
    fn delete_records(&self, zone: &str, records: &[DnsRecord]) -> Result<(), DnsError>;
}

/// Configuration for the Cloudflare DNS provider. The token is a secret from env/config.
#[derive(Debug, Clone)]
pub struct CloudflareConfig {
    pub token: String,
    pub api_base: String,
}

impl CloudflareConfig {
    /// Build from an explicit token. Fails closed on an empty token.
    pub fn new(token: impl Into<String>) -> Result<Self, DnsError> {
        let token = token.into();
        if token.trim().is_empty() {
            return Err(DnsError::Config("Cloudflare API token is empty".into()));
        }
        Ok(CloudflareConfig { token, api_base: CLOUDFLARE_API_BASE.to_string() })
    }

    /// Read the token from `CLOUDFLARE_API_TOKEN`. Fail-closed if unset/empty.
    pub fn from_env() -> Result<Self, DnsError> {
        let token = std::env::var(CLOUDFLARE_TOKEN_ENV)
            .map_err(|_| DnsError::Config(format!("{CLOUDFLARE_TOKEN_ENV} is not set")))?;
        Self::new(token)
    }

    /// Builder: override the API base (staging/tests).
    pub fn with_api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into();
        self
    }
}

/// The single [`DnsProvider`] implementation: Cloudflare v4 over the injectable [`HttpTransport`].
#[derive(Debug, Clone)]
pub struct CloudflareDns<T: HttpTransport> {
    pub(crate) transport: T,
    config: CloudflareConfig,
}

impl<T: HttpTransport> CloudflareDns<T> {
    pub fn new(transport: T, config: CloudflareConfig) -> Self {
        CloudflareDns { transport, config }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.config.api_base, path)
    }

    /// Send a request and unwrap Cloudflare's `{success, errors, result}` envelope, returning
    /// `result` on success or a fail-closed [`DnsError`] otherwise.
    fn call(&self, method: HttpMethod, path: &str, body: Option<Value>) -> Result<Value, DnsError> {
        let body_bytes = body.map(|v| v.to_string().into_bytes());
        let req = HttpRequest::json(method, self.url(path), &self.config.token, body_bytes);
        let resp = self.transport.send(&req)?;
        let parsed = serde_json::from_slice::<Value>(&resp.body);

        // Non-2xx: read the Cloudflare error envelope if we can.
        if !resp.is_success() {
            return Err(self.api_error(resp.status, parsed.ok().as_ref()));
        }
        let parsed = parsed.map_err(|e| DnsError::Malformed(format!("invalid JSON body: {e}")))?;
        // A 2xx must still carry success:true — Cloudflare can 200 with success:false on some paths.
        if parsed.get("success").and_then(Value::as_bool) != Some(true) {
            return Err(self.api_error(resp.status, Some(&parsed)));
        }
        Ok(parsed.get("result").cloned().unwrap_or(Value::Null))
    }

    /// Extract the first `{code,message}` from a Cloudflare `errors` array.
    fn api_error(&self, status: u16, body: Option<&Value>) -> DnsError {
        let (code, message) = body
            .and_then(|v| v.get("errors"))
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .map(|e| {
                let code = e.get("code").map(|c| c.to_string()).unwrap_or_else(|| "unknown".into());
                let message = e.get("message").and_then(Value::as_str).unwrap_or("").to_string();
                (code, message)
            })
            .unwrap_or_else(|| ("unknown".to_string(), String::new()));
        DnsError::Api { status, code, message }
    }

    /// Resolve a zone name to its Cloudflare zone id (fail-closed if the zone is not in the account).
    fn zone_id(&self, zone: &str) -> Result<String, DnsError> {
        let result = self.call(HttpMethod::Get, &format!("/zones?name={zone}"), None)?;
        result
            .as_array()
            .and_then(|a| a.iter().find(|z| z.get("name").and_then(Value::as_str) == Some(zone)))
            .and_then(|z| z.get("id").and_then(Value::as_str))
            .map(str::to_string)
            .ok_or_else(|| DnsError::Malformed(format!("zone `{zone}` not found in the Cloudflare account")))
    }

    /// Find an existing record id by name + type under a zone (`None` if absent).
    fn existing_record_id(&self, zone_id: &str, rec: &DnsRecord) -> Result<Option<String>, DnsError> {
        let path = format!("/zones/{}/dns_records?type={}&name={}", zone_id, rec.rtype.as_str(), rec.name);
        let result = self.call(HttpMethod::Get, &path, None)?;
        Ok(result
            .as_array()
            .and_then(|a| a.first())
            .and_then(|r| r.get("id").and_then(Value::as_str))
            .map(str::to_string))
    }

    /// The Cloudflare record body for create/update.
    fn record_body(rec: &DnsRecord) -> Value {
        let mut body = serde_json::json!({
            "type": rec.rtype.as_str(),
            "name": rec.name,
            "content": rec.content,
            "ttl": rec.ttl,
        });
        if let Some(prio) = rec.priority {
            body["priority"] = Value::from(prio);
        }
        body
    }
}

impl<T: HttpTransport> DnsProvider for CloudflareDns<T> {
    fn upsert_records(&self, zone: &str, records: &[DnsRecord]) -> Result<(), DnsError> {
        let zid = self.zone_id(zone)?;
        for rec in records {
            let body = Self::record_body(rec);
            match self.existing_record_id(&zid, rec)? {
                Some(id) => {
                    // Replace in place (PUT) — idempotent re-publish, and self-updating on rotation.
                    self.call(HttpMethod::Put, &format!("/zones/{zid}/dns_records/{id}"), Some(body))?;
                }
                None => {
                    self.call(HttpMethod::Post, &format!("/zones/{zid}/dns_records"), Some(body))?;
                }
            }
        }
        Ok(())
    }

    fn delete_records(&self, zone: &str, records: &[DnsRecord]) -> Result<(), DnsError> {
        let zid = self.zone_id(zone)?;
        for rec in records {
            if let Some(id) = self.existing_record_id(&zid, rec)? {
                self.call(HttpMethod::Delete, &format!("/zones/{zid}/dns_records/{id}"), None)?;
            }
            // Absent already → nothing to do (idempotent teardown).
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::MockTransport;

    fn inputs() -> GatewayZoneInputs {
        GatewayZoneInputs {
            domain: "yourbrand.com".into(),
            local_part: "alice".into(),
            mail_host_label: "mail".into(),
            gateway_ipv4: "203.0.113.7".into(),
            dkim_selector: "envoir1".into(),
            dkim_public_key: "MIIBIjANBg...".into(),
            dkim_key_type: "rsa".into(),
            dmarc_rua: "dmarc@yourbrand.com".into(),
            dmarc_policy: "quarantine".into(),
            dmtap_suite: 1,
            dmtap_ik: "aWtiYXNlNjR1cmw".into(),
            dmtap_id: "aWRiYXNlNjR1cmw".into(),
            dmtap_kt: vec!["https://kt.envoir.org".into(), "https://kt2.envoir.org".into()],
            dmtap_keypkgs: "https://kp.envoir.org/alice".into(),
            ttl: DEFAULT_TTL,
        }
    }

    fn cfg() -> CloudflareConfig {
        CloudflareConfig::new("cf-token").unwrap().with_api_base("https://cf.test/client/v4")
    }

    // ---- pure record-set generation ----

    #[test]
    fn generates_the_full_six_record_set() {
        let recs = gateway_zone_records(&inputs());
        assert_eq!(recs.len(), 6);
        let types: Vec<_> = recs.iter().map(|r| (r.name.as_str(), r.rtype)).collect();
        assert!(types.contains(&("mail.yourbrand.com", DnsRecordType::A)));
        assert!(types.contains(&("yourbrand.com", DnsRecordType::Mx)));
        assert!(types.contains(&("yourbrand.com", DnsRecordType::Txt))); // SPF
        assert!(types.contains(&("envoir1._domainkey.yourbrand.com", DnsRecordType::Txt)));
        assert!(types.contains(&("_dmarc.yourbrand.com", DnsRecordType::Txt)));
        assert!(types.contains(&("alice._dmtap.yourbrand.com", DnsRecordType::Txt)));
    }

    #[test]
    fn a_record_points_at_the_gateway_ip() {
        let recs = gateway_zone_records(&inputs());
        let a = recs.iter().find(|r| r.rtype == DnsRecordType::A).unwrap();
        assert_eq!(a.name, "mail.yourbrand.com");
        assert_eq!(a.content, "203.0.113.7");
    }

    #[test]
    fn mx_points_at_the_mail_host_with_priority() {
        let recs = gateway_zone_records(&inputs());
        let mx = recs.iter().find(|r| r.rtype == DnsRecordType::Mx).unwrap();
        assert_eq!(mx.name, "yourbrand.com");
        assert_eq!(mx.content, "mail.yourbrand.com");
        assert_eq!(mx.priority, Some(10));
    }

    #[test]
    fn spf_authorizes_the_gateway_ip_and_hard_fails_the_rest() {
        let recs = gateway_zone_records(&inputs());
        let spf = recs.iter().find(|r| r.rtype == DnsRecordType::Txt && r.name == "yourbrand.com").unwrap();
        assert_eq!(spf.content, "v=spf1 ip4:203.0.113.7 -all");
    }

    #[test]
    fn dkim_publishes_the_delegated_selector_key() {
        let recs = gateway_zone_records(&inputs());
        let dkim = recs.iter().find(|r| r.name == "envoir1._domainkey.yourbrand.com").unwrap();
        assert_eq!(dkim.content, "v=DKIM1; k=rsa; p=MIIBIjANBg...");
    }

    #[test]
    fn dmarc_carries_policy_and_rua_with_strict_alignment() {
        let recs = gateway_zone_records(&inputs());
        let dmarc = recs.iter().find(|r| r.name == "_dmarc.yourbrand.com").unwrap();
        assert_eq!(dmarc.content, "v=DMARC1; p=quarantine; rua=mailto:dmarc@yourbrand.com; adkim=s; aspf=s");
    }

    #[test]
    fn dmtap_record_matches_the_spec_3_2_format() {
        let recs = gateway_zone_records(&inputs());
        let d = recs.iter().find(|r| r.name == "alice._dmtap.yourbrand.com").unwrap();
        assert_eq!(
            d.content,
            "v=dmtap1; suite=1; ik=aWtiYXNlNjR1cmw; id=aWRiYXNlNjR1cmw; kt=https://kt.envoir.org,https://kt2.envoir.org; keypkgs=https://kp.envoir.org/alice"
        );
    }

    #[test]
    fn every_record_uses_the_requested_ttl() {
        let mut inp = inputs();
        inp.ttl = 120;
        for r in gateway_zone_records(&inp) {
            assert_eq!(r.ttl, 120);
        }
    }

    // ---- config fail-closed ----

    #[test]
    fn config_rejects_empty_token() {
        assert!(matches!(CloudflareConfig::new(""), Err(DnsError::Config(_))));
        assert!(matches!(CloudflareConfig::new("   "), Err(DnsError::Config(_))));
    }

    #[test]
    fn env_var_name_is_the_documented_one() {
        assert_eq!(CLOUDFLARE_TOKEN_ENV, "CLOUDFLARE_API_TOKEN");
    }

    // ---- Cloudflare API shaping: upsert create + update ----

    #[test]
    fn upsert_creates_a_record_when_absent() {
        // 1) zone lookup, 2) existing-record lookup (empty → create), 3) POST create.
        let mock = MockTransport::new(vec![
            Ok(crate::http::HttpResponse { status: 200, body: br#"{"success":true,"errors":[],"result":[{"id":"zone123","name":"yourbrand.com"}]}"#.to_vec() }),
            Ok(crate::http::HttpResponse { status: 200, body: br#"{"success":true,"errors":[],"result":[]}"#.to_vec() }),
            Ok(crate::http::HttpResponse { status: 200, body: br#"{"success":true,"errors":[],"result":{"id":"rec1"}}"#.to_vec() }),
        ]);
        let dns = CloudflareDns::new(mock, cfg());
        let rec = DnsRecord::a("mail.yourbrand.com", "203.0.113.7", 3600);
        dns.upsert_records("yourbrand.com", std::slice::from_ref(&rec)).unwrap();

        let reqs = dns.transport.requests.borrow();
        assert_eq!(reqs.len(), 3);
        assert_eq!(reqs[0].method, HttpMethod::Get);
        assert_eq!(reqs[0].url, "https://cf.test/client/v4/zones?name=yourbrand.com");
        assert!(reqs[0].headers.iter().any(|(k, v)| k == "authorization" && v == "Bearer cf-token"));
        // Third call is the create POST with the record body.
        assert_eq!(reqs[2].method, HttpMethod::Post);
        assert_eq!(reqs[2].url, "https://cf.test/client/v4/zones/zone123/dns_records");
        let sent: Value = serde_json::from_slice(reqs[2].body.as_ref().unwrap()).unwrap();
        assert_eq!(sent["type"], "A");
        assert_eq!(sent["name"], "mail.yourbrand.com");
        assert_eq!(sent["content"], "203.0.113.7");
    }

    #[test]
    fn upsert_updates_a_record_when_present() {
        // zone lookup → existing lookup returns an id → PUT update.
        let mock = MockTransport::new(vec![
            Ok(crate::http::HttpResponse { status: 200, body: br#"{"success":true,"result":[{"id":"z","name":"yourbrand.com"}]}"#.to_vec() }),
            Ok(crate::http::HttpResponse { status: 200, body: br#"{"success":true,"result":[{"id":"existing-rec"}]}"#.to_vec() }),
            Ok(crate::http::HttpResponse { status: 200, body: br#"{"success":true,"result":{"id":"existing-rec"}}"#.to_vec() }),
        ]);
        let dns = CloudflareDns::new(mock, cfg());
        let rec = DnsRecord::mx("yourbrand.com", "mail.yourbrand.com", 10, 3600);
        dns.upsert_records("yourbrand.com", std::slice::from_ref(&rec)).unwrap();

        let reqs = dns.transport.requests.borrow();
        assert_eq!(reqs[2].method, HttpMethod::Put);
        assert_eq!(reqs[2].url, "https://cf.test/client/v4/zones/z/dns_records/existing-rec");
        let sent: Value = serde_json::from_slice(reqs[2].body.as_ref().unwrap()).unwrap();
        assert_eq!(sent["priority"], 10);
    }

    // ---- Cloudflare API shaping: fail-closed ----

    #[test]
    fn upsert_fails_closed_when_zone_absent() {
        let mock = MockTransport::ok_json(r#"{"success":true,"result":[]}"#);
        let dns = CloudflareDns::new(mock, cfg());
        let rec = DnsRecord::a("mail.yourbrand.com", "203.0.113.7", 3600);
        assert!(matches!(dns.upsert_records("yourbrand.com", &[rec]), Err(DnsError::Malformed(_))));
    }

    #[test]
    fn call_fails_closed_on_success_false_envelope() {
        // A 200 with success:false (Cloudflare's auth/validation failures) must not be treated as ok.
        let mock = MockTransport::status(200, r#"{"success":false,"errors":[{"code":10000,"message":"Authentication error"}],"result":null}"#);
        let dns = CloudflareDns::new(mock, cfg());
        let rec = DnsRecord::a("mail.yourbrand.com", "203.0.113.7", 3600);
        match dns.upsert_records("yourbrand.com", &[rec]) {
            Err(DnsError::Api { status, code, message }) => {
                assert_eq!(status, 200);
                assert_eq!(code, "10000");
                assert_eq!(message, "Authentication error");
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    #[test]
    fn call_fails_closed_on_non_2xx() {
        let mock = MockTransport::status(403, r#"{"success":false,"errors":[{"code":9109,"message":"Unauthorized"}]}"#);
        let dns = CloudflareDns::new(mock, cfg());
        let rec = DnsRecord::a("mail.yourbrand.com", "203.0.113.7", 3600);
        assert!(matches!(dns.upsert_records("yourbrand.com", &[rec]), Err(DnsError::Api { status: 403, .. })));
    }

    #[test]
    fn transport_failure_is_fail_closed() {
        let mock = MockTransport::new(vec![Err(crate::http::TransportError::Request("timeout".into()))]);
        let dns = CloudflareDns::new(mock, cfg());
        let rec = DnsRecord::a("mail.yourbrand.com", "203.0.113.7", 3600);
        assert!(matches!(dns.upsert_records("yourbrand.com", &[rec]), Err(DnsError::Transport(_))));
    }

    // ---- delete ----

    #[test]
    fn delete_removes_present_records_and_ignores_absent() {
        // zone lookup, then for the one record: existing lookup returns id, then DELETE.
        let mock = MockTransport::new(vec![
            Ok(crate::http::HttpResponse { status: 200, body: br#"{"success":true,"result":[{"id":"z","name":"yourbrand.com"}]}"#.to_vec() }),
            Ok(crate::http::HttpResponse { status: 200, body: br#"{"success":true,"result":[{"id":"rec-to-del"}]}"#.to_vec() }),
            Ok(crate::http::HttpResponse { status: 200, body: br#"{"success":true,"result":{"id":"rec-to-del"}}"#.to_vec() }),
        ]);
        let dns = CloudflareDns::new(mock, cfg());
        let rec = DnsRecord::a("mail.yourbrand.com", "203.0.113.7", 3600);
        dns.delete_records("yourbrand.com", std::slice::from_ref(&rec)).unwrap();
        let reqs = dns.transport.requests.borrow();
        assert_eq!(reqs.last().unwrap().method, HttpMethod::Delete);
        assert_eq!(reqs.last().unwrap().url, "https://cf.test/client/v4/zones/z/dns_records/rec-to-del");
    }

    #[test]
    fn delete_of_absent_record_is_a_noop_success() {
        let mock = MockTransport::new(vec![
            Ok(crate::http::HttpResponse { status: 200, body: br#"{"success":true,"result":[{"id":"z","name":"yourbrand.com"}]}"#.to_vec() }),
            Ok(crate::http::HttpResponse { status: 200, body: br#"{"success":true,"result":[]}"#.to_vec() }),
        ]);
        let dns = CloudflareDns::new(mock, cfg());
        let rec = DnsRecord::a("mail.yourbrand.com", "203.0.113.7", 3600);
        assert!(dns.delete_records("yourbrand.com", &[rec]).is_ok());
        // No DELETE was issued (only the two lookups).
        assert_eq!(dns.transport.requests.borrow().len(), 2);
    }
}
