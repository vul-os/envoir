//! Transport seams — recipient **resolution** and MOTE **delivery**.
//!
//! Envoir Send builds and seals a real MOTE (spec §2); *getting the recipient's keys* and *moving
//! the sealed object* are the node/gateway's job, so they are trait seams here, not baked in:
//!
//! - [`Resolver`] maps a recipient address/name to its DMTAP routing key + X25519 KEM key (the
//!   payload is sealed to it) and whether it is a native DMTAP peer or a legacy address reached via
//!   the SMTP gateway (§7). In production this is DNS/KT + KeyPackage lookup (§3, §5.3).
//! - [`Delivery`] hands the sealed [`Envelope`] to a transport — the native mesh (§4) or the
//!   legacy-SMTP gateway (§7) — and returns a receipt. Real delivery is out of scope for this crate.
//!
//! The crate ships small in-memory reference implementations ([`StaticResolver`],
//! [`CapturingDelivery`]) used by tests and local runs; production supplies its own.

use std::cell::RefCell;
use std::collections::HashMap;

use dmtap_core::mote::Envelope;

/// A recipient resolved to the key material a MOTE is built/sealed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRecipient {
    /// The address/name that was resolved (echoed back for receipts).
    pub address: String,
    /// The recipient's DMTAP identity/routing key (the MOTE `to` tag, §2.2a).
    pub ik: Vec<u8>,
    /// The recipient's X25519 KEM public key the payload is sealed to (§2.4).
    pub seal_pub: Vec<u8>,
    /// `true` for a native DMTAP peer; `false` for a legacy address reached via the gateway (§7).
    pub is_native: bool,
}

/// A recipient-resolution failure (unknown/unroutable address).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{0}")]
pub struct ResolveError(pub String);

/// A delivery-transport failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{0}")]
pub struct DeliveryError(pub String);

/// A delivery receipt from the transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryReceipt {
    /// Which path carried it — e.g. `"native-mesh"` or `"smtp-gateway"`.
    pub transport: String,
    /// Whether the transport accepted the object for delivery.
    pub accepted: bool,
    /// An optional transport-specific detail (queue id, remote MTA response, …).
    pub detail: Option<String>,
}

/// Resolve a recipient address/name to its DMTAP key material. Production impl: DNS/KT + KeyPackage
/// lookup (§3, §5.3).
pub trait Resolver {
    fn resolve(&self, address: &str) -> Result<ResolvedRecipient, ResolveError>;
}

/// Hand a sealed MOTE to a transport (native mesh or legacy gateway). Production impl: the node's
/// mixnet/relay client (§4) or the SMTP bridge (§7). `&self` — an impl uses interior mutability if
/// it needs to record state.
pub trait Delivery {
    fn deliver(&self, mote: &Envelope, recipient: &ResolvedRecipient) -> Result<DeliveryReceipt, DeliveryError>;
}

// --- Reference (in-memory) seam implementations for tests / local runs ---------------------

/// A static in-memory [`Resolver`]: an address → [`ResolvedRecipient`] table. Reference/test only.
#[derive(Debug, Default, Clone)]
pub struct StaticResolver {
    table: HashMap<String, ResolvedRecipient>,
}

impl StaticResolver {
    /// An empty table.
    pub fn new() -> Self {
        StaticResolver { table: HashMap::new() }
    }

    /// Register a resolved recipient for `address`.
    pub fn insert(&mut self, address: impl Into<String>, recipient: ResolvedRecipient) {
        self.table.insert(address.into(), recipient);
    }
}

impl Resolver for StaticResolver {
    fn resolve(&self, address: &str) -> Result<ResolvedRecipient, ResolveError> {
        self.table
            .get(address)
            .cloned()
            .ok_or_else(|| ResolveError(format!("no route for recipient {address}")))
    }
}

/// A [`Delivery`] that records every sealed MOTE it is handed and always accepts, tagging the
/// transport by the recipient's native/gateway class. Reference/test only.
#[derive(Debug, Default)]
pub struct CapturingDelivery {
    sent: RefCell<Vec<Envelope>>,
}

impl CapturingDelivery {
    /// A fresh capturing sink.
    pub fn new() -> Self {
        CapturingDelivery { sent: RefCell::new(Vec::new()) }
    }

    /// The number of MOTEs delivered so far.
    pub fn count(&self) -> usize {
        self.sent.borrow().len()
    }

    /// The most recently delivered MOTE, if any.
    pub fn last(&self) -> Option<Envelope> {
        self.sent.borrow().last().cloned()
    }
}

impl Delivery for CapturingDelivery {
    fn deliver(&self, mote: &Envelope, recipient: &ResolvedRecipient) -> Result<DeliveryReceipt, DeliveryError> {
        self.sent.borrow_mut().push(mote.clone());
        Ok(DeliveryReceipt {
            transport: if recipient.is_native { "native-mesh".into() } else { "smtp-gateway".into() },
            accepted: true,
            detail: None,
        })
    }
}
