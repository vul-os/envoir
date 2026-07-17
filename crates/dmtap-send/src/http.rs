//! The HTTP surface — a thin, framework-free adapter for `POST /v1/send`.
//!
//! This is deliberately a *seam*, not a server: [`HttpRequest`]/[`HttpResponse`] are plain structs,
//! and [`handle_send`] maps one HTTP request onto [`SendService::send`] and back. Wire it behind any
//! server (hyper, a CGI shim, a serverless handler) — the crate stays the reusable core and pulls in
//! no web framework. The Resend-shaped contract:
//!
//! ```text
//! POST /v1/send
//! Authorization: Bearer <api-key>
//! Content-Type: application/json
//! { "from": "...", "to": "...", "subject": "...", "body": "...", "mime": "..." }
//! ```
//!
//! Responses are JSON: `200 { "id": "<hex message-id>", "native": true }` on success, or
//! `<status> { "error": "...", "detail": "..." }` on failure (status from [`SendError::http_status`]).

use dmtap_core::TimestampMs;
use serde_json::json;

use crate::key::{SendError, SendService};
use crate::pipeline::{SendRequest, SendReceipt};
use crate::seam::{Delivery, Resolver};

/// A minimal HTTP request: method, path, the `Authorization` header, and the raw JSON body.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub authorization: Option<String>,
    pub body: Vec<u8>,
}

/// A minimal HTTP response: a status code and a JSON body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl HttpResponse {
    fn json(status: u16, value: serde_json::Value) -> Self {
        HttpResponse { status, body: serde_json::to_vec(&value).unwrap_or_default() }
    }

    fn error(status: u16, error: &str, detail: Option<String>) -> Self {
        HttpResponse::json(status, json!({ "error": error, "detail": detail }))
    }
}

/// The `/v1/send` route the adapter serves.
const SEND_PATH: &str = "/v1/send";

/// Map one HTTP request onto the send pipeline. `now` is supplied by the caller's clock (the core
/// never reads a wall clock, §16.1). Returns the JSON [`HttpResponse`] to write back.
pub fn handle_send<R: Resolver, D: Delivery>(
    service: &mut SendService,
    resolver: &R,
    delivery: &D,
    req: &HttpRequest,
    now: TimestampMs,
) -> HttpResponse {
    // Route: only POST /v1/send.
    if req.path != SEND_PATH {
        return HttpResponse::error(404, "not_found", Some(format!("no route {}", req.path)));
    }
    if req.method != "POST" {
        return HttpResponse::error(405, "method_not_allowed", Some(req.method.clone()));
    }

    // Bearer token.
    let bearer = match req.authorization.as_deref().and_then(parse_bearer) {
        Some(b) => b,
        None => return HttpResponse::error(401, "unauthorized", Some("missing Bearer token".into())),
    };

    // Parse the JSON body into a SendRequest.
    let send_req: SendRequest = match serde_json::from_slice(&req.body) {
        Ok(r) => r,
        Err(e) => return HttpResponse::error(400, "bad_request", Some(e.to_string())),
    };

    match service.send(resolver, delivery, bearer, now, &send_req) {
        Ok(receipt) => ok_response(&receipt),
        Err(e) => HttpResponse::error(e.http_status(), error_slug(&e), Some(e.to_string())),
    }
}

/// The `200` success body: the MOTE content-address (hex) + the transport class.
fn ok_response(receipt: &SendReceipt) -> HttpResponse {
    HttpResponse::json(
        200,
        json!({
            "id": hex(&receipt.message_id.0),
            "native": receipt.native,
            "transport": receipt.delivery.transport,
        }),
    )
}

/// Extract the token from an `Authorization: Bearer <token>` header value.
fn parse_bearer(header: &str) -> Option<&str> {
    header.strip_prefix("Bearer ").map(str::trim).filter(|t| !t.is_empty())
}

/// A stable machine-readable error slug for each failure.
fn error_slug(e: &SendError) -> &'static str {
    match e {
        SendError::Unauthorized => "unauthorized",
        SendError::Revoked => "revoked",
        SendError::Expired => "expired",
        SendError::NotYetValid => "not_yet_valid",
        SendError::WrongIssuer => "wrong_issuer",
        SendError::Capability(_) => "capability_invalid",
        SendError::OutOfScope => "out_of_scope",
        SendError::RateLimited => "rate_limited",
        SendError::Resolve(_) => "unresolvable_recipient",
        SendError::Delivery(_) => "delivery_failed",
        SendError::Build(_) => "build_failed",
    }
}

/// Lowercase hex (no extra crate).
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::{Environment, SendScope};
    use crate::seam::{CapturingDelivery, ResolvedRecipient, StaticResolver};
    use dmtap_core::identity::IdentityKey;
    use dmtap_core::mote::SealKeypair;

    const YEAR: u64 = 365 * 24 * 60 * 60 * 1000;
    const NOW: u64 = 1_700_000_000_000;

    fn setup() -> (SendService, StaticResolver, CapturingDelivery, String) {
        let mut svc = SendService::new(IdentityKey::from_seed(&[0x42; 32]));
        let key = svc.issue_key(SendScope::account(Environment::Prod), NOW, YEAR);
        let seal = SealKeypair::generate();
        let mut resolver = StaticResolver::new();
        resolver.insert(
            "bob@peer.example",
            ResolvedRecipient {
                address: "bob@peer.example".into(),
                ik: IdentityKey::generate().public(),
                seal_pub: seal.public().to_vec(),
                is_native: true,
            },
        );
        (svc, resolver, CapturingDelivery::new(), key.secret().to_string())
    }

    fn post(secret: Option<&str>, path: &str, body: &str) -> HttpRequest {
        HttpRequest {
            method: "POST".into(),
            path: path.into(),
            authorization: secret.map(|s| format!("Bearer {s}")),
            body: body.as_bytes().to_vec(),
        }
    }

    fn body(from: &str) -> String {
        json!({ "from": from, "to": "bob@peer.example", "subject": "hi", "body": "hello" }).to_string()
    }

    #[test]
    fn valid_post_sends_and_returns_200() {
        let (mut svc, resolver, delivery, secret) = setup();
        let req = post(Some(&secret), "/v1/send", &body("hello@example.com"));
        let resp = handle_send(&mut svc, &resolver, &delivery, &req, NOW);
        assert_eq!(resp.status, 200);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["id"].as_str().unwrap().len() == 66); // 33-byte content-id in hex
        assert_eq!(v["native"], true);
        assert_eq!(delivery.count(), 1);
    }

    #[test]
    fn missing_bearer_is_401() {
        let (mut svc, resolver, delivery, _secret) = setup();
        let req = post(None, "/v1/send", &body("hello@example.com"));
        let resp = handle_send(&mut svc, &resolver, &delivery, &req, NOW);
        assert_eq!(resp.status, 401);
    }

    #[test]
    fn wrong_path_is_404_and_wrong_method_is_405() {
        let (mut svc, resolver, delivery, secret) = setup();
        let r404 = handle_send(&mut svc, &resolver, &delivery, &post(Some(&secret), "/v1/nope", "{}"), NOW);
        assert_eq!(r404.status, 404);
        let mut get = post(Some(&secret), "/v1/send", "{}");
        get.method = "GET".into();
        let r405 = handle_send(&mut svc, &resolver, &delivery, &get, NOW);
        assert_eq!(r405.status, 405);
    }

    #[test]
    fn malformed_json_is_400() {
        let (mut svc, resolver, delivery, secret) = setup();
        let req = post(Some(&secret), "/v1/send", "{not json");
        let resp = handle_send(&mut svc, &resolver, &delivery, &req, NOW);
        assert_eq!(resp.status, 400);
    }

    #[test]
    fn out_of_scope_from_is_403() {
        let mut svc = SendService::new(IdentityKey::from_seed(&[0x42; 32]));
        let key = svc.issue_key(SendScope::domain("example.com", Environment::Prod), NOW, YEAR);
        let seal = SealKeypair::generate();
        let mut resolver = StaticResolver::new();
        resolver.insert(
            "bob@peer.example",
            ResolvedRecipient {
                address: "bob@peer.example".into(),
                ik: IdentityKey::generate().public(),
                seal_pub: seal.public().to_vec(),
                is_native: true,
            },
        );
        let delivery = CapturingDelivery::new();
        let req = post(Some(key.secret()), "/v1/send", &body("evil@other.com"));
        let resp = handle_send(&mut svc, &resolver, &delivery, &req, NOW);
        assert_eq!(resp.status, 403);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["error"], "out_of_scope");
    }

    #[test]
    fn revoked_key_is_401() {
        let (mut svc, resolver, delivery, secret) = setup();
        svc.revoke_key(&secret, NOW).unwrap();
        let req = post(Some(&secret), "/v1/send", &body("hello@example.com"));
        let resp = handle_send(&mut svc, &resolver, &delivery, &req, NOW + 1);
        assert_eq!(resp.status, 401);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["error"], "revoked");
    }

    #[test]
    fn rate_limited_key_is_429() {
        let mut svc = SendService::new(IdentityKey::from_seed(&[0x42; 32]));
        let key = svc.issue_key(SendScope::account(Environment::Prod).with_rate_per_min(1), NOW, YEAR);
        let seal = SealKeypair::generate();
        let mut resolver = StaticResolver::new();
        resolver.insert(
            "bob@peer.example",
            ResolvedRecipient {
                address: "bob@peer.example".into(),
                ik: IdentityKey::generate().public(),
                seal_pub: seal.public().to_vec(),
                is_native: true,
            },
        );
        let delivery = CapturingDelivery::new();
        let req = post(Some(key.secret()), "/v1/send", &body("hello@example.com"));
        assert_eq!(handle_send(&mut svc, &resolver, &delivery, &req, NOW).status, 200);
        assert_eq!(handle_send(&mut svc, &resolver, &delivery, &req, NOW + 1).status, 429);
    }
}
