//! The **injectable outbound HTTP transport** — the one place [`crate::dns`]'s DNS onboarding
//! automation touches the network.
//!
//! Everything above this seam (shaping a Cloudflare `dns_records` upsert, decoding its JSON
//! envelope) is pure and offline-testable; the transport is abstracted behind [`HttpTransport`] so
//! unit tests inject canned bytes and never open a socket. This mirrors the sibling
//! `dmtap-namechain-rpc` crate's `HttpTransport`/`UreqTransport` split (and the retired
//! `envoir-cloud` prototype this module was ported from) exactly. The sole real implementation,
//! [`UreqTransport`], is a small blocking rustls client behind the non-default `net` feature; the
//! offline build ships only the trait + the pure shaping.
//!
//! **Fail-closed.** A non-2xx status is surfaced as [`TransportError`] via the caller reading the
//! response body (see [`crate::dns`]); a network/TLS error is [`TransportError::Request`]. Neither
//! is ever silently treated as success.

/// Hard cap on any single response body. A DNS record list is kilobytes; 4 MiB is generous
/// headroom while still refusing an endpoint that tries to stream an unbounded body to exhaust
/// memory.
pub const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;

/// The HTTP verbs the Cloudflare DNS API needs (create = POST, replace a record = PUT, delete a
/// record = DELETE, read = GET).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
}

impl HttpMethod {
    /// The uppercase wire token (`"GET"`, `"POST"`, …).
    pub fn as_str(self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
        }
    }
}

/// One outbound request: method + absolute URL + headers (auth, content-type) + an optional JSON
/// body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: String,
    /// Ordered `(name, value)` header pairs — the `Authorization: Bearer …` credential lives
    /// here, never hardcoded in this module.
    pub headers: Vec<(String, String)>,
    /// The request body (already-serialized JSON). `None` for GET/DELETE with no payload.
    pub body: Option<Vec<u8>>,
}

impl HttpRequest {
    /// A bearer-authenticated JSON request. `body` is `Some` for POST/PUT, `None` otherwise.
    pub fn json(method: HttpMethod, url: impl Into<String>, bearer: &str, body: Option<Vec<u8>>) -> Self {
        let mut headers = vec![("authorization".to_string(), format!("Bearer {bearer}"))];
        if body.is_some() {
            headers.push(("content-type".to_string(), "application/json".to_string()));
        }
        HttpRequest { method, url: url.into(), headers, body }
    }
}

/// A raw HTTP response: the status code and the (capped) body bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// True for a 2xx status.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// A transport-layer failure. Callers treat every variant as fail-closed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TransportError {
    /// The request could not be completed (DNS/connect/TLS/read error, or the response body
    /// exceeded [`MAX_RESPONSE_BYTES`]). Carries a short reason.
    #[error("http request failed: {0}")]
    Request(String),
}

/// A minimal blocking HTTP client the DNS layer calls.
///
/// Implementors MUST NOT follow a redirect to a non-HTTPS scheme, SHOULD apply a sane timeout, and
/// MUST cap the response body. A non-2xx status is returned as a successful [`HttpResponse`] with
/// that status (so callers can read the provider's typed error body); only a genuine
/// network/TLS/limit failure is a [`TransportError`].
pub trait HttpTransport {
    /// Execute `req`, returning the status + body. See the trait docs for the fail-closed contract.
    fn send(&self, req: &HttpRequest) -> Result<HttpResponse, TransportError>;
}

// -------------------------------------------------------------------------------------------------
// The one real implementation — behind the non-default `net` feature.
// -------------------------------------------------------------------------------------------------

/// The real blocking-HTTPS transport: [`ureq`] on rustls (same client the `dmtap-namechain-rpc`
/// crate uses). Kept deliberately small — no async runtime, no SDK — because DNS onboarding is a
/// handful of request/response round-trips.
#[cfg(feature = "net")]
#[derive(Debug, Clone, Default)]
pub struct UreqTransport {
    _priv: (),
}

#[cfg(feature = "net")]
impl UreqTransport {
    /// A transport with library-default timeouts.
    pub fn new() -> Self {
        UreqTransport { _priv: () }
    }
}

#[cfg(feature = "net")]
impl HttpTransport for UreqTransport {
    fn send(&self, req: &HttpRequest) -> Result<HttpResponse, TransportError> {
        let mut r = ureq::request(req.method.as_str(), &req.url);
        for (k, v) in &req.headers {
            r = r.set(k, v);
        }
        let resp = match &req.body {
            Some(b) => r.send_bytes(b),
            None => r.call(),
        };
        // ureq surfaces a non-2xx as `Error::Status`; we want the status + body, not an error, so
        // a caller can read the provider's typed error message and fail closed with a good reason.
        let resp = match resp {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => return Err(TransportError::Request(e.to_string())),
        };
        let status = resp.status();
        // Cap the body: a hostile endpoint could otherwise stream a multi-GB response to OOM us.
        // Read one byte past the cap so we can distinguish "at the limit" from "over it".
        let mut buf = Vec::new();
        let mut limited = std::io::Read::take(resp.into_reader(), MAX_RESPONSE_BYTES + 1);
        std::io::Read::read_to_end(&mut limited, &mut buf)
            .map_err(|e| TransportError::Request(e.to_string()))?;
        if buf.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(TransportError::Request("response body exceeds cap".into()));
        }
        Ok(HttpResponse { status, body: buf })
    }
}

// -------------------------------------------------------------------------------------------------
// The scripted transport for offline tests.
// -------------------------------------------------------------------------------------------------

/// A scripted transport for offline unit tests: each call pops the next canned response and
/// records the request that was made, so a test can assert on the exact REST traffic the shaping
/// produced.
#[cfg(test)]
pub(crate) struct MockTransport {
    responses: std::cell::RefCell<std::collections::VecDeque<Result<HttpResponse, TransportError>>>,
    /// Every request sent, in call order — a test asserts on method/url/headers/body.
    pub requests: std::cell::RefCell<Vec<HttpRequest>>,
}

#[cfg(test)]
impl MockTransport {
    /// A transport that answers calls, in order, with `responses` (then errors once exhausted).
    pub fn new(responses: Vec<Result<HttpResponse, TransportError>>) -> Self {
        MockTransport {
            responses: std::cell::RefCell::new(responses.into_iter().collect()),
            requests: std::cell::RefCell::new(Vec::new()),
        }
    }

    /// Convenience: a single `200 OK` with this JSON body.
    pub fn ok_json(body: &str) -> Self {
        Self::new(vec![Ok(HttpResponse { status: 200, body: body.as_bytes().to_vec() })])
    }

    /// Convenience: a single response with an arbitrary status + body (for fail-closed tests).
    pub fn status(code: u16, body: &str) -> Self {
        Self::new(vec![Ok(HttpResponse { status: code, body: body.as_bytes().to_vec() })])
    }

    fn next(&self) -> Result<HttpResponse, TransportError> {
        self.responses
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::Request("mock exhausted".into())))
    }
}

#[cfg(test)]
impl HttpTransport for MockTransport {
    fn send(&self, req: &HttpRequest) -> Result<HttpResponse, TransportError> {
        self.requests.borrow_mut().push(req.clone());
        self.next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_json_request_sets_auth_and_content_type() {
        let req = HttpRequest::json(HttpMethod::Post, "https://api/x", "secret-token", Some(b"{}".to_vec()));
        assert!(req.headers.iter().any(|(k, v)| k == "authorization" && v == "Bearer secret-token"));
        assert!(req.headers.iter().any(|(k, v)| k == "content-type" && v == "application/json"));
    }

    #[test]
    fn bodyless_request_has_no_content_type() {
        let req = HttpRequest::json(HttpMethod::Delete, "https://api/x/1", "t", None);
        assert!(!req.headers.iter().any(|(k, _)| k == "content-type"));
        assert_eq!(req.body, None);
    }

    #[test]
    fn method_wire_tokens() {
        assert_eq!(HttpMethod::Get.as_str(), "GET");
        assert_eq!(HttpMethod::Post.as_str(), "POST");
        assert_eq!(HttpMethod::Put.as_str(), "PUT");
        assert_eq!(HttpMethod::Delete.as_str(), "DELETE");
    }

    #[test]
    fn response_success_range() {
        assert!(HttpResponse { status: 200, body: vec![] }.is_success());
        assert!(HttpResponse { status: 299, body: vec![] }.is_success());
        assert!(!HttpResponse { status: 300, body: vec![] }.is_success());
        assert!(!HttpResponse { status: 199, body: vec![] }.is_success());
    }

    #[test]
    fn mock_records_and_replays_in_order() {
        let mock = MockTransport::new(vec![
            Ok(HttpResponse { status: 201, body: b"a".to_vec() }),
            Ok(HttpResponse { status: 204, body: vec![] }),
        ]);
        let r1 = mock.send(&HttpRequest::json(HttpMethod::Post, "u1", "t", Some(b"{}".to_vec()))).unwrap();
        let r2 = mock.send(&HttpRequest::json(HttpMethod::Delete, "u2", "t", None)).unwrap();
        assert_eq!(r1.status, 201);
        assert_eq!(r2.status, 204);
        assert_eq!(mock.requests.borrow().len(), 2);
        assert_eq!(mock.requests.borrow()[0].url, "u1");
    }

    #[test]
    fn mock_errors_once_exhausted() {
        let mock = MockTransport::new(vec![]);
        assert!(matches!(
            mock.send(&HttpRequest::json(HttpMethod::Get, "u", "t", None)),
            Err(TransportError::Request(_))
        ));
    }
}
