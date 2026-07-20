//! Location discovery over Kademlia — spec §4.2, §4.3.
//!
//! [`crate::Libp2pTransport`] can dial a peer only once its DMTAP address is mapped to a libp2p
//! `PeerId` + a dialable `Multiaddr`. Until now that map was populated **by hand**
//! ([`Libp2pTransport::add_peer`]) — fine for tests, useless on a real mesh, where a node has
//! never met the peer it is about to write to.
//!
//! This module closes that: [`Libp2pTransport::publish_location`] mints a signed
//! [`LocationRecord`] from this node's own peer id + bound listen addresses and PUTs it under
//! `multihash(ik)`, and [`Libp2pTransport::resolve_location`] GETs a peer's record, puts it
//! through the full fail-closed gate (signature → freshness → substrate → rollback), and only
//! then teaches the route book how to reach it.
//!
//! ## Where this sits on the reachability ladder (§4.3) — and why it is last
//!
//! §4.2 is explicit that the DHT is **one discovery mechanism, not the root of trust**, and fixes
//! the resolution order: (1) cached direct addresses, (2) relay-reservation / rendezvous ("home
//! relay") addresses, (3) DHT strictly as fallback. This module implements rung 3 only.
//!
//! That ordering is deliberately reflected in the API shape: [`Transport::send`] is **not** made
//! to transparently fall back to a DHT lookup on an unknown peer. Two reasons, and neither is
//! stylistic:
//!
//! - `send` is non-blocking and drives the §20.1 retry machine. A DHT GET blocks for up to
//!   [`crate::KAD_TIMEOUT`]; burying one inside `send` would stall the delivery loop on every
//!   write to an unknown peer, and an eclipsing attacker who simply withholds records could pin
//!   the sender there indefinitely.
//! - Silently resolving would make the DHT the *default* path rather than the fallback, inverting
//!   the §4.2 order. A caller that has a cached address or a rendezvous introduction should use
//!   it; reaching for the hostile public DHT is a decision, so it is an explicit call.
//!
//! So the intended loop is: `send` → `Unreachable` → caller resolves (cache, then rendezvous,
//! then [`resolve_location`]) → retry. That is exactly what the §4.7 delivery state machine
//! already does with a `RETRY`.
//!
//! ## What this cannot defend against
//!
//! Everything here authenticates record *content*. Eclipse is a *routing* attack (§4.2 CAUTION):
//! an attacker generating peer ids close to a target key can control its lookups and return
//! nothing, or an old-but-validly-signed record. The rollback half is defended —
//! [`LocationTracker`] rejects older-or-equal `seq` and this crate keeps one tracker per transport
//! so the high-water marks persist for the process lifetime. Withholding is **not** defended here
//! and cannot be at this layer; that needs S/Kademlia disjoint-path lookups and per-bucket
//! IP-diversity caps, which libp2p's `kad` does not currently expose. A caller who needs that
//! guarantee today should use a rendezvous introduction (rung 2), not the DHT.

use std::time::Duration;

use dmtap_core::identity::IdentityKey;
use dmtap_core::location::{
    LocationError, LocationRecord, DEFAULT_TTL_SECS, SUBSTRATE_LIBP2P,
};
use dmtap_core::TimestampMs;
use libp2p::{Multiaddr, PeerId};

use crate::Libp2pTransport;

/// Substrates this transport can actually dial. A record tagged with anything else resolves to
/// [`LocationError::Unreachable`] (`0x0303`), never a parse error (§18.5.1) — that is what makes a
/// future substrate an additive migration rather than a flag day.
pub const SUPPORTED_SUBSTRATES: &[u8] = &[SUBSTRATE_LIBP2P];

/// Clock skew tolerated when judging a record's freshness (§16.2). Two minutes: generous enough
/// for unsynchronized consumer clocks, far short of the 2 h default TTL.
pub const DEFAULT_SKEW_MS: u64 = 2 * 60 * 1_000;

/// Why a location lookup produced no dialable route.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    /// The record failed the §4.2 gate (bad signature, expired, rolled back, or an unimplemented
    /// substrate). Carries the normative [`LocationError`] so the caller can consult
    /// [`LocationError::code`] / [`LocationError::retryable`].
    #[error("location record rejected: {0}")]
    Rejected(#[from] LocationError),
    /// A record was found and is valid, but its `peer_id` is not a well-formed libp2p `PeerId`.
    /// Treated as unreachable rather than malformed: on the libp2p substrate this is a peer we
    /// cannot dial, which is precisely `0x0303`.
    #[error("location record carries an unparseable libp2p peer id (0x0303)")]
    BadPeerId,
    /// The record decoded as CBOR but violates §18.5.1.
    #[error("location record is not conformant §18.5.1 CBOR (0x0303)")]
    Malformed,
}

impl ResolveError {
    /// The normative DMTAP wire error code (§21.5).
    pub fn code(&self) -> u16 {
        match self {
            ResolveError::Rejected(e) => e.code(),
            ResolveError::BadPeerId | ResolveError::Malformed => 0x0303,
        }
    }

    /// Whether the §4.7 delivery state machine may retry.
    pub fn retryable(&self) -> bool {
        match self {
            ResolveError::Rejected(e) => e.retryable(),
            // A malformed or undialable record is not going to improve on re-fetch of the same
            // bytes, but a *later* lookup may find a republished one, so this stays retryable —
            // the retry budget (§4.7), not this flag, is what bounds the attempt.
            ResolveError::BadPeerId | ResolveError::Malformed => true,
        }
    }
}

/// The outcome of a successful resolution: the verified record plus what it taught the route book.
#[derive(Debug, Clone)]
pub struct ResolvedLocation {
    /// The verified, fresh, non-rolled-back record as published.
    pub record: LocationRecord,
    /// The peer id parsed from `record.peer_id`.
    pub peer_id: PeerId,
    /// The subset of `record.addrs` that parsed as multiaddrs, in the record's preference order.
    /// Unparseable hints are skipped, not fatal: `addrs` is a hint list from a possibly-newer
    /// publisher, and one unrecognized entry must not discard the ones we *can* dial.
    pub dialable: Vec<Multiaddr>,
}

impl Libp2pTransport {
    /// Mint and PUT this node's own signed [`LocationRecord`] (§4.2), advertising its peer id and
    /// currently-bound listen addresses under `multihash(ik.public())`.
    ///
    /// `seq` MUST strictly increase across republishes from this identity — resolvers reject
    /// older-or-equal (§4.2), so a publisher that restarts its counter makes itself unreachable to
    /// everyone who already cached a higher `seq`. Persist it alongside the node's identity; do
    /// not derive it from an in-memory counter.
    ///
    /// Returns whether the PUT was stored on at least one peer. `false` is not necessarily fatal —
    /// a node with no DHT peers yet is the normal bootstrap state — but a node that *never*
    /// succeeds is undiscoverable, and republishing (§16.2, every 45 min by default) is what keeps
    /// the record alive against the DHT's short record lifetimes.
    pub fn publish_location(
        &self,
        ik: &IdentityKey,
        seq: u64,
        ttl_secs: u64,
        now: TimestampMs,
        substrate: Option<u8>,
    ) -> bool {
        let addrs: Vec<String> = self.listeners().iter().map(|m| m.to_string()).collect();
        let record = LocationRecord::issue(
            ik,
            self.peer_id().to_bytes(),
            addrs,
            seq,
            ttl_secs,
            now,
            substrate,
        );
        self.kad_put(&LocationRecord::dht_key(&ik.public()), &record.det_cbor())
    }

    /// Publish with the §16.2 defaults (2 h TTL, libp2p substrate) — the ordinary case.
    pub fn publish_location_default(
        &self,
        ik: &IdentityKey,
        seq: u64,
        now: TimestampMs,
    ) -> bool {
        self.publish_location(ik, seq, DEFAULT_TTL_SECS, now, None)
    }

    /// Wait up to `timeout` for at least one bound listen address, then publish (§16.2 defaults).
    ///
    /// A `:0` bind resolves its real port asynchronously, so publishing immediately after
    /// construction would advertise an **empty** `addrs` list — a technically-valid record that
    /// nobody can dial. This is the ordering trap that makes a freshly-started node silently
    /// unreachable, so the convenience wrapper exists to make the correct sequence the easy one.
    pub fn publish_location_when_listening(
        &self,
        ik: &IdentityKey,
        seq: u64,
        now: TimestampMs,
        timeout: Duration,
    ) -> bool {
        self.wait_for_listener(timeout);
        self.publish_location_default(ik, seq, now)
    }

    /// GET, verify, and adopt the location of the identity `ik_pub` (§4.2).
    ///
    /// On success the route book has learned `ik_pub → peer_id` and the swarm has been seeded with
    /// every dialable address, so the next [`Transport::send`](envoir_node::transport::Transport::send)
    /// to `ik_pub` can dial rather than returning `Unreachable`.
    ///
    /// The gate runs in the order §4.2 requires — signature, freshness, substrate, *then* rollback
    /// — and nothing is written to the route book or the rollback tracker until all four pass. In
    /// particular an unverified record can never advance the `seq` high-water mark, which would
    /// otherwise let a forged `seq = u64::MAX` lock the victim out of every genuine future record.
    pub fn resolve_location(
        &self,
        ik_pub: &[u8],
        now: TimestampMs,
    ) -> Result<ResolvedLocation, ResolveError> {
        let bytes = self
            .kad_get(&LocationRecord::dht_key(ik_pub))
            .ok_or(ResolveError::Rejected(LocationError::Unreachable))?;
        self.adopt_location_bytes(ik_pub, &bytes, now)
    }

    /// The verify-and-adopt half of [`resolve_location`], split out so a record obtained by some
    /// *other* means — a rendezvous introduction, a contact card, a cached blob replayed after
    /// restart (§4.3 rungs 1 and 2) — goes through the identical fail-closed gate.
    ///
    /// The higher rungs of the ladder are the ones a security-conscious caller should prefer, so
    /// it would be a poor trade if they were also the ones that bypassed validation.
    pub fn adopt_location_bytes(
        &self,
        ik_pub: &[u8],
        bytes: &[u8],
        now: TimestampMs,
    ) -> Result<ResolvedLocation, ResolveError> {
        let record = LocationRecord::from_det_cbor(bytes).map_err(|_| ResolveError::Malformed)?;

        // Bind the record to the key we asked for. Without this a DHT that returns *someone
        // else's* validly-signed record would have it accepted on its own merits and installed as
        // the route for `ik_pub` — the signature proves who minted it, never who it is for.
        if record.ik != ik_pub {
            return Err(ResolveError::Rejected(LocationError::Unreachable));
        }

        let peer_id = PeerId::from_bytes(&record.peer_id).map_err(|_| ResolveError::BadPeerId)?;

        // Signature → freshness → substrate, then the rollback check under the tracker lock. The
        // lock spans both so two concurrent resolutions of the same key cannot interleave and
        // admit the older one.
        let mut tracker = self.location_tracker.lock().unwrap();
        tracker.admit(&record, now, DEFAULT_SKEW_MS, SUPPORTED_SUBSTRATES)?;
        drop(tracker);

        // Skip hints we cannot parse rather than failing the whole record (see `dialable`).
        let dialable: Vec<Multiaddr> =
            record.addrs.iter().filter_map(|a| a.parse::<Multiaddr>().ok()).collect();

        // Only now teach the route book. `add_peer` maps the DMTAP address to the peer id and
        // seeds Kademlia with each dialable address.
        let handle = self.handle();
        if dialable.is_empty() {
            // A valid record with no dialable hint: the peer is reachable only via a rendezvous /
            // relay introduction (§4.3 rung 2). Record the identity → peer-id mapping anyway, so a
            // circuit address learned later completes the route.
            handle.add_peer_id_only(ik_pub.to_vec(), peer_id);
        } else {
            for addr in &dialable {
                handle.add_peer(ik_pub.to_vec(), peer_id, addr.clone());
            }
        }

        Ok(ResolvedLocation { record, peer_id, dialable })
    }

    /// The highest `seq` this transport has accepted for `ik_pub`, if any (§4.2 rollback state).
    ///
    /// Persist these across restarts and restore with
    /// [`Libp2pTransport::restore_location_high_water_marks`]: a tracker that starts empty accepts
    /// an attacker's stale record exactly once per restart.
    pub fn location_high_water_mark(&self, ik_pub: &[u8]) -> Option<u64> {
        self.location_tracker.lock().unwrap().highest_seq(ik_pub)
    }

    /// All persisted-shaped `(ik, seq)` high-water marks, for journaling with the node snapshot.
    pub fn location_high_water_marks(&self) -> Vec<(Vec<u8>, u64)> {
        self.location_tracker
            .lock()
            .unwrap()
            .high_water_marks()
            .map(|(k, v)| (k.to_vec(), v))
            .collect()
    }

    /// Restore rollback high-water marks captured before a restart. Merges with anything already
    /// seen, keeping the higher `seq` per key — restoring must never *lower* a mark.
    pub fn restore_location_high_water_marks(
        &self,
        marks: impl IntoIterator<Item = (Vec<u8>, u64)>,
    ) {
        let mut tracker = self.location_tracker.lock().unwrap();
        // `admit` is the only public mutator and it (correctly) demands a full record, so merge
        // through the constructor — which itself keeps the higher `seq` on duplicate keys — and
        // swap the rebuilt tracker in once.
        let mut merged: Vec<(Vec<u8>, u64)> =
            tracker.high_water_marks().map(|(k, v)| (k.to_vec(), v)).collect();
        merged.extend(marks);
        *tracker = dmtap_core::location::LocationTracker::from_high_water_marks(merged);
    }
}
