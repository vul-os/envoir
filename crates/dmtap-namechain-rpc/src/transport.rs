//! The **injectable HTTP transport** — the one place this crate touches the network (§6.6 seam).
//!
//! Everything above [`HttpTransport`] (namehash, ABI, PDA, record decode, JSON-RPC shaping) is pure
//! and offline-testable; the transport is abstracted so tests inject canned bytes and never open a
//! socket. The sole real implementation, [`UreqTransport`], is a small blocking rustls client behind
//! the default `net` feature.

/// A transport-layer failure (network, TLS, or a non-2xx HTTP status). Read-only name-chain lookups
/// treat every transport failure as fail-closed (§3.12.5(c)): the binding is simply not discovered.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TransportError {
    /// The request could not be completed (DNS/connect/TLS/read error). Carries a short reason.
    #[error("http request failed: {0}")]
    Request(String),

    /// The server answered with a non-success HTTP status.
    #[error("http status {0}")]
    Status(u16),
}

/// A minimal blocking HTTP client the RPC layer calls. Two verbs suffice for name-chain RPC:
/// `post_json` for JSON-RPC (`eth_call` / `getAccountInfo`) and `get` for a CCIP-Read gateway
/// (ENSIP-10 / EIP-3668) fetched with the URL template already expanded.
///
/// Implementors MUST NOT follow redirects to a non-HTTPS scheme and SHOULD apply a sane timeout; the
/// resolver above treats any [`TransportError`] as "record not found" and fails closed.
pub trait HttpTransport {
    /// POST `body` as `application/json` to `url`, returning the raw response body bytes.
    fn post_json(&self, url: &str, body: &[u8]) -> Result<Vec<u8>, TransportError>;

    /// GET `url` (used for a CCIP-Read gateway request), returning the raw response body bytes.
    fn get(&self, url: &str) -> Result<Vec<u8>, TransportError>;
}

/// The real blocking-HTTPS transport: [`ureq`] on rustls (the workspace already builds rustls 0.23).
/// Kept deliberately small — no async runtime, no web3 stack — because name-chain resolution is a
/// couple of request/response round-trips.
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

    fn run(req: ureq::Request, body: Option<&[u8]>) -> Result<Vec<u8>, TransportError> {
        let resp = match body {
            Some(b) => req.send_bytes(b),
            None => req.call(),
        };
        let resp = match resp {
            Ok(r) => r,
            // ureq surfaces non-2xx as `Error::Status`; map it to our typed status, else a reason.
            Err(ureq::Error::Status(code, _)) => return Err(TransportError::Status(code)),
            Err(e) => return Err(TransportError::Request(e.to_string())),
        };
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut resp.into_reader(), &mut buf)
            .map_err(|e| TransportError::Request(e.to_string()))?;
        Ok(buf)
    }
}

#[cfg(feature = "net")]
impl HttpTransport for UreqTransport {
    fn post_json(&self, url: &str, body: &[u8]) -> Result<Vec<u8>, TransportError> {
        let req = ureq::post(url).set("content-type", "application/json");
        Self::run(req, Some(body))
    }

    fn get(&self, url: &str) -> Result<Vec<u8>, TransportError> {
        Self::run(ureq::get(url), None)
    }
}

/// A scripted transport for offline tests: each call pops the next canned response and records the
/// request that was made, so a test can assert on the exact JSON-RPC / gateway traffic.
#[cfg(test)]
pub(crate) struct MockTransport {
    responses: std::cell::RefCell<std::collections::VecDeque<Result<Vec<u8>, TransportError>>>,
    /// Recorded `(url, body?)` in call order; `None` body marks a GET.
    pub requests: std::cell::RefCell<Vec<(String, Option<Vec<u8>>)>>,
}

#[cfg(test)]
impl MockTransport {
    /// A transport that will answer calls, in order, with `responses`.
    pub fn new(responses: Vec<Result<Vec<u8>, TransportError>>) -> Self {
        MockTransport {
            responses: std::cell::RefCell::new(responses.into_iter().collect()),
            requests: std::cell::RefCell::new(Vec::new()),
        }
    }

    /// Convenience: a transport that answers every call with one canned success body.
    pub fn ok(body: Vec<u8>) -> Self {
        Self::new(vec![Ok(body)])
    }

    fn next(&self) -> Result<Vec<u8>, TransportError> {
        self.responses
            .borrow_mut()
            .pop_front()
            .unwrap_or(Err(TransportError::Request("mock exhausted".into())))
    }
}

#[cfg(test)]
impl HttpTransport for MockTransport {
    fn post_json(&self, url: &str, body: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.requests
            .borrow_mut()
            .push((url.to_owned(), Some(body.to_vec())));
        self.next()
    }

    fn get(&self, url: &str) -> Result<Vec<u8>, TransportError> {
        self.requests.borrow_mut().push((url.to_owned(), None));
        self.next()
    }
}
