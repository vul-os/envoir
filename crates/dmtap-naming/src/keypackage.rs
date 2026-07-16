//! Async-join KeyPackage fetch — spec §5.3, §18.4.3.
//!
//! To message an identity whose devices are all offline, DMTAP uses MLS's own async join: each
//! device pre-publishes signed **KeyPackages**, located via `Identity.keypkgs` (a
//! [`KeyPackageBundleRef`], §1.3). This module is the **fetch seam** for that bundle: a
//! [`KeyPackageSource`] trait plus an in-memory implementation for tests, with a real mesh/relay
//! fetch as a thin later layer.
//!
//! The one security-load-bearing rule lives here: a fetched bundle is **content-addressed**
//! (§2.2), so [`KeyPackageSource::fetch_bundle`] MUST verify the returned bytes against the ref's
//! `id` and fail closed on a mismatch — a relay cannot substitute KeyPackages under a locator.

use dmtap_core::identity::{Identity, KeyPackageBundleRef};

use crate::error::ResolveError;

/// The KeyPackage bundle fetch seam (§5.3). Given the [`KeyPackageBundleRef`] published in an
/// `Identity`, return the bundle's raw bytes — after verifying they content-address to the ref's
/// `id`. A real implementation dials the mesh/relay locator; the in-memory one serves from a map.
pub trait KeyPackageSource {
    /// Fetch and content-verify the bundle for `bundle_ref`. MUST return
    /// [`ResolveError::KeyPackage`] if the locator is unknown or the bytes do not match
    /// `bundle_ref.id` (§2.2 fail-closed).
    fn fetch_bundle(&self, bundle_ref: &KeyPackageBundleRef) -> Result<Vec<u8>, ResolveError>;

    /// Convenience: fetch the KeyPackage bundle an `Identity` currently advertises (§1.3).
    fn fetch_for(&self, identity: &Identity) -> Result<Vec<u8>, ResolveError> {
        self.fetch_bundle(&identity.keypkgs)
    }
}

/// An in-memory [`KeyPackageSource`] for tests: a locator → bytes map. On fetch it re-checks the
/// content address, so it exercises the same fail-closed path a real fetch must implement.
#[derive(Debug, Default)]
pub struct InMemoryKeyPackages {
    by_loc: std::collections::HashMap<String, Vec<u8>>,
}

impl InMemoryKeyPackages {
    /// An empty store.
    pub fn new() -> Self {
        InMemoryKeyPackages { by_loc: std::collections::HashMap::new() }
    }

    /// Publish `bytes` under `loc`; returns the [`KeyPackageBundleRef`] (`loc` + content address)
    /// an `Identity` would carry to point at them.
    pub fn publish(&mut self, loc: impl Into<String>, bytes: Vec<u8>) -> KeyPackageBundleRef {
        let loc = loc.into();
        let id = dmtap_core::ContentId::of(&bytes);
        self.by_loc.insert(loc.clone(), bytes);
        KeyPackageBundleRef::new(loc, id)
    }
}

impl KeyPackageSource for InMemoryKeyPackages {
    fn fetch_bundle(&self, bundle_ref: &KeyPackageBundleRef) -> Result<Vec<u8>, ResolveError> {
        let bytes = self
            .by_loc
            .get(&bundle_ref.loc)
            .ok_or(ResolveError::KeyPackage("no bundle at locator"))?;
        // Content-address check (§2.2): the fetched bytes MUST match the pinned ref id.
        if !bundle_ref.id.verify(bytes) {
            return Err(ResolveError::KeyPackage("bundle content-address mismatch"));
        }
        Ok(bytes.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmtap_core::ContentId;

    #[test]
    fn fetch_returns_content_verified_bytes() {
        let mut store = InMemoryKeyPackages::new();
        let bundle = b"a signed KeyPackage bundle".to_vec();
        let bref = store.publish("/mesh/kp/alice", bundle.clone());
        assert_eq!(store.fetch_bundle(&bref).unwrap(), bundle);
    }

    #[test]
    fn unknown_locator_fails_closed() {
        let store = InMemoryKeyPackages::new();
        let bref = KeyPackageBundleRef::new("/nope", ContentId::of(b"x"));
        assert!(matches!(
            store.fetch_bundle(&bref),
            Err(ResolveError::KeyPackage(_))
        ));
    }

    #[test]
    fn tampered_bundle_fails_content_address() {
        let mut store = InMemoryKeyPackages::new();
        let _bref = store.publish("/mesh/kp/bob", b"original".to_vec());
        // Forge a ref that points at the same locator but pins a different content address.
        let forged = KeyPackageBundleRef::new("/mesh/kp/bob", ContentId::of(b"different"));
        assert!(matches!(
            store.fetch_bundle(&forged),
            Err(ResolveError::KeyPackage("bundle content-address mismatch"))
        ));
    }
}
