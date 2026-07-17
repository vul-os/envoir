//! SNS (`.sol`) resolution over **Solana JSON-RPC** — spec §3.12.5, Bonfida SPL Name Service.
//!
//! ## Resolution path
//! 1. Normalize the DMTAP name to a `.sol` domain label (`toly@.sol` and bare `toly.sol` → `toly`).
//! 2. Derive the domain's **name-registry account** — a Program Derived Address (PDA) of the SPL Name
//!    Service program (see [`domain_key`]) — entirely offline.
//! 3. `getAccountInfo` on that PDA; a null account is an unregistered name ([`None`]).
//! 4. Decode the DMTAP `IK` from the account payload (convention below).
//!
//! ## The DMTAP record convention (this crate defines it)
//! A Bonfida name-registry account begins with a **96-byte header** — `parent_name(32) ‖ owner(32) ‖
//! class(32)` (`NameRegistryState`) — followed by the record's free-form data. DMTAP publishes the
//! owner's **classical `IK`** as the **first 32 bytes** of that post-header payload. (Bonfida
//! "records V2" store typed subkeys in their own child PDAs; anchoring the `IK` in the root domain's
//! own account keeps the lookup a single `getAccountInfo` and is the documented DMTAP layout here.)
//!
//! ## What is real vs. a seam
//! The PDA derivation is **fully real**: `create_program_address` / `find_program_address` including
//! the genuine Ed25519 **off-curve** test (a PDA must *not* be a valid curve point), verified offline
//! against the canonical `bonfida.sol` account. Subdomains (a label with an inner `.`) use a
//! different parent PDA and are a documented seam — rejected here rather than mis-derived.

use sha2::{Digest, Sha256};

use dmtap_naming::namechain::NameChainClient;
use dmtap_naming::restype::Chain;

use crate::rpc::get_account_info;
use crate::transport::HttpTransport;
use crate::NamechainError;

/// SPL Name Service program id (`namesLPneVptA9Z5rqUDD9tMTWEJwofgaYwp8cawRkX`), the PDA program.
pub const SPL_NAME_PROGRAM_ID: [u8; 32] = [
    11, 173, 81, 244, 19, 193, 243, 169, 148, 96, 217, 0, 216, 191, 46, 214, 146, 126, 202, 52,
    215, 183, 132, 43, 248, 16, 169, 115, 8, 45, 30, 220,
];

/// The `.sol` TLD authority (`58PwtjSDuFHuUkYjH9BYnnQKHfwo9reZhC2zMJv9JPkx`) — the name-parent seed
/// under which every top-level `.sol` domain account is derived.
pub const SOL_TLD_AUTHORITY: [u8; 32] = [
    61, 83, 194, 75, 56, 54, 14, 211, 129, 58, 35, 223, 178, 223, 216, 32, 171, 88, 33, 203, 121,
    41, 163, 141, 46, 170, 178, 82, 232, 56, 37, 149,
];

/// The `getHashedName` prefix Bonfida hashes every label with.
const HASH_PREFIX: &str = "SPL Name Service";

/// The suffix Solana appends before hashing a PDA candidate.
const PDA_MARKER: &[u8] = b"ProgramDerivedAddress";

/// The Bonfida `NameRegistryState` header length: `parent_name(32) ‖ owner(32) ‖ class(32)`.
pub const NAME_REGISTRY_HEADER_LEN: usize = 96;

/// A real, network-backed SNS `NameChainClient` (§3.12.5): resolves `.sol` names to a DMTAP `IK` over
/// Solana JSON-RPC via an injected [`HttpTransport`].
#[derive(Debug, Clone)]
pub struct SnsClient<T: HttpTransport> {
    transport: T,
    endpoint: String,
}

impl<T: HttpTransport> SnsClient<T> {
    /// Build a client against the Solana JSON-RPC `endpoint`.
    pub fn new(transport: T, endpoint: impl Into<String>) -> Self {
        SnsClient {
            transport,
            endpoint: endpoint.into(),
        }
    }

    /// Resolve with full error detail (the trait's `resolve` collapses any error to `None`).
    pub fn resolve_result(&self, name: &str) -> Result<Vec<u8>, NamechainError> {
        let domain = sns_domain_from_dmtap(name)?;
        let account = domain_key(&domain)
            .ok_or(NamechainError::MalformedRecord("no PDA bump found for domain"))?;
        let base58 = bs58::encode(account).into_string();
        let data = get_account_info(&self.transport, &self.endpoint, &base58)?
            .ok_or(NamechainError::NotFound)?;
        parse_registry_record(&data)
    }
}

impl<T: HttpTransport> NameChainClient for SnsClient<T> {
    fn chain(&self) -> Chain {
        Chain::Sns
    }

    fn resolve(&self, name: &str) -> Option<Vec<u8>> {
        // Fail closed: any RPC error / malformed record / miss → no discovered record (§3.12.5).
        self.resolve_result(name).ok()
    }
}

/// `getHashedName(name)` = `sha256(HASH_PREFIX ‖ name)` (Bonfida), the first PDA seed.
pub fn hashed_name(name: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(HASH_PREFIX.as_bytes());
    h.update(name.as_bytes());
    h.finalize().into()
}

/// Derive a top-level `.sol` domain's **name-registry account** (its PDA). Seeds are
/// `[getHashedName(domain), name_class = 0², name_parent = SOL_TLD_AUTHORITY]`.
pub fn domain_key(domain: &str) -> Option<[u8; 32]> {
    let hashed = hashed_name(domain);
    let class = [0u8; 32];
    let seeds: [&[u8]; 3] = [&hashed, &class, &SOL_TLD_AUTHORITY];
    find_program_address(&seeds, &SPL_NAME_PROGRAM_ID).map(|(k, _bump)| k)
}

/// Solana `create_program_address`: `sha256(seeds ‖ program_id ‖ "ProgramDerivedAddress")`, valid
/// **only if** the result is *not* a valid Ed25519 curve point. `None` means "on curve → not a PDA".
pub fn create_program_address(seeds: &[&[u8]], program_id: &[u8; 32]) -> Option<[u8; 32]> {
    let mut h = Sha256::new();
    for s in seeds {
        h.update(s);
    }
    h.update(program_id);
    h.update(PDA_MARKER);
    let hash: [u8; 32] = h.finalize().into();
    if is_on_curve(&hash) {
        None
    } else {
        Some(hash)
    }
}

/// Solana `find_program_address`: the highest bump (255→0) whose `create_program_address` is a valid
/// (off-curve) PDA. Returns `(address, bump)`.
pub fn find_program_address(seeds: &[&[u8]], program_id: &[u8; 32]) -> Option<([u8; 32], u8)> {
    let mut bump = 255u8;
    loop {
        let bump_seed = [bump];
        let mut all: Vec<&[u8]> = seeds.to_vec();
        all.push(&bump_seed);
        if let Some(pda) = create_program_address(&all, program_id) {
            return Some((pda, bump));
        }
        if bump == 0 {
            return None;
        }
        bump -= 1;
    }
}

/// The real Ed25519 on-curve test Solana uses: does this 32-byte value decompress to a valid Edwards
/// point? A PDA must be **off** the curve (so no private key can exist for it).
pub fn is_on_curve(bytes: &[u8; 32]) -> bool {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    match CompressedEdwardsY::from_slice(bytes) {
        Ok(c) => c.decompress().is_some(),
        Err(_) => false,
    }
}

/// Map a DMTAP name to its `.sol` domain label. `local@.sol` → `local`; bare `foo.sol` → `foo`.
/// A label with an inner `.` (an SNS subdomain) is rejected as a documented seam.
pub fn sns_domain_from_dmtap(name: &str) -> Result<String, NamechainError> {
    let name = name.trim().to_ascii_lowercase();
    let domain = if let Some((local, ns)) = name.split_once('@') {
        if ns != ".sol" {
            return Err(NamechainError::MalformedName("not a .sol name-chain name"));
        }
        local.to_owned()
    } else if let Some(label) = name.strip_suffix(".sol") {
        label.to_owned()
    } else {
        return Err(NamechainError::MalformedName("not a .sol name"));
    };
    if domain.is_empty() {
        return Err(NamechainError::MalformedName("empty .sol domain label"));
    }
    if domain.contains('.') {
        return Err(NamechainError::MalformedName(
            "SNS subdomains are not supported (seam)",
        ));
    }
    Ok(domain)
}

/// Decode the classical `IK` from a name-registry account: skip the 96-byte header, take 32 bytes.
fn parse_registry_record(data: &[u8]) -> Result<Vec<u8>, NamechainError> {
    let ik = data
        .get(NAME_REGISTRY_HEADER_LEN..NAME_REGISTRY_HEADER_LEN + 32)
        .ok_or(NamechainError::MalformedRecord(
            "account too small to hold a 32-byte ik after the header",
        ))?;
    if ik.iter().all(|b| *b == 0) {
        // An all-zero payload is an empty record, not a key.
        return Err(NamechainError::NotFound);
    }
    Ok(ik.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::MockTransport;
    use base64::Engine;

    #[test]
    fn program_ids_roundtrip_base58() {
        assert_eq!(
            bs58::encode(SPL_NAME_PROGRAM_ID).into_string(),
            "namesLPneVptA9Z5rqUDD9tMTWEJwofgaYwp8cawRkX"
        );
        assert_eq!(
            bs58::encode(SOL_TLD_AUTHORITY).into_string(),
            "58PwtjSDuFHuUkYjH9BYnnQKHfwo9reZhC2zMJv9JPkx"
        );
    }

    #[test]
    fn hashed_name_kat() {
        assert_eq!(
            hex::encode(hashed_name("bonfida")),
            "8ee2d25c3d2b2a83a1fc209b90377aed03dc2539e8e238355edda8d1b2edab98"
        );
    }

    // ---- PDA derivation known-answer vectors (the canonical .sol accounts) ----
    #[test]
    fn domain_key_kat_bonfida() {
        let key = domain_key("bonfida").unwrap();
        assert_eq!(
            bs58::encode(key).into_string(),
            "Crf8hzfthWGbGbLTVCiqRqV5MVnbpHB1L9KQMd6gsinb"
        );
    }

    #[test]
    fn domain_key_kat_toly() {
        let key = domain_key("toly").unwrap();
        assert_eq!(
            bs58::encode(key).into_string(),
            "FX1APjKbFu6M8GKb3dGXcZLXjxX4fGaYwvHqb5Vaee8q"
        );
    }

    #[test]
    fn find_program_address_reports_expected_bump() {
        let hashed = hashed_name("bonfida");
        let class = [0u8; 32];
        let seeds: [&[u8]; 3] = [&hashed, &class, &SOL_TLD_AUTHORITY];
        let (_key, bump) = find_program_address(&seeds, &SPL_NAME_PROGRAM_ID).unwrap();
        assert_eq!(bump, 252, "bonfida.sol canonical bump");
    }

    #[test]
    fn on_curve_basepoint_true_pda_false() {
        // The Ed25519 basepoint is a valid curve point.
        let bp = curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED.to_bytes();
        assert!(is_on_curve(&bp));
        // A derived PDA must be OFF the curve.
        let pda = domain_key("bonfida").unwrap();
        assert!(!is_on_curve(&pda));
    }

    #[test]
    fn domain_normalization() {
        assert_eq!(sns_domain_from_dmtap("toly@.sol").unwrap(), "toly");
        assert_eq!(sns_domain_from_dmtap("BONFIDA.sol").unwrap(), "bonfida");
        assert!(sns_domain_from_dmtap("alice@.eth").is_err());
        assert!(sns_domain_from_dmtap("plain").is_err());
        assert!(sns_domain_from_dmtap("sub.domain.sol").is_err()); // subdomain seam
        assert!(sns_domain_from_dmtap("@.sol").is_err());
    }

    /// Build a getAccountInfo success body whose account data is `header ‖ ik ‖ trailing`.
    fn account_info_body(ik: &[u8; 32]) -> Vec<u8> {
        let mut data = vec![0u8; NAME_REGISTRY_HEADER_LEN];
        data.extend_from_slice(ik);
        data.extend_from_slice(b"trailing bonfida record bytes");
        let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{\"value\":{{\"data\":[\"{b64}\",\"base64\"],\"lamports\":1}}}}}}"
        )
        .into_bytes()
    }

    #[test]
    fn resolve_happy_path_returns_ik() {
        let ik = [0x5au8; 32];
        let mock = MockTransport::ok(account_info_body(&ik));
        let client = SnsClient::new(mock, "https://api.mainnet-beta.solana.com");
        assert_eq!(client.resolve_result("bonfida@.sol").unwrap(), ik.to_vec());
        // And via the trait, with a fresh single-use mock.
        let client2 = SnsClient::new(MockTransport::ok(account_info_body(&ik)), "https://sol");
        assert_eq!(client2.resolve("bonfida@.sol"), Some(ik.to_vec()));
    }

    #[test]
    fn resolve_targets_the_derived_pda() {
        let ik = [0x01u8; 32];
        let mock = MockTransport::ok(account_info_body(&ik));
        let client = SnsClient::new(mock, "https://sol");
        let _ = client.resolve_result("bonfida.sol").unwrap();
        let reqs = client_requests(&client);
        let sent: serde_json::Value = serde_json::from_slice(reqs[0].1.as_ref().unwrap()).unwrap();
        assert_eq!(sent["method"], "getAccountInfo");
        assert_eq!(sent["params"][0], "Crf8hzfthWGbGbLTVCiqRqV5MVnbpHB1L9KQMd6gsinb");
    }

    /// Peek at a client's mock transport request log (test-only helper).
    fn client_requests(client: &SnsClient<MockTransport>) -> Vec<(String, Option<Vec<u8>>)> {
        client.transport.requests.borrow().clone()
    }

    #[test]
    fn resolve_null_account_is_none() {
        let mock = MockTransport::ok(
            br#"{"jsonrpc":"2.0","id":1,"result":{"value":null}}"#.to_vec(),
        );
        let client = SnsClient::new(mock, "https://sol");
        assert!(matches!(
            client.resolve_result("ghost.sol"),
            Err(NamechainError::NotFound)
        ));
        assert_eq!(client.resolve("ghost.sol"), None);
    }

    #[test]
    fn resolve_short_account_fails_closed() {
        // 96-byte header but no room for the ik.
        let b64 = base64::engine::general_purpose::STANDARD.encode(vec![0u8; NAME_REGISTRY_HEADER_LEN]);
        let body = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{\"value\":{{\"data\":[\"{b64}\",\"base64\"]}}}}}}"
        )
        .into_bytes();
        let client = SnsClient::new(MockTransport::ok(body), "https://sol");
        assert!(matches!(
            client.resolve_result("short.sol"),
            Err(NamechainError::MalformedRecord(_))
        ));
    }
}
