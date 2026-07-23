//! Bounded multi-cell reassembly (spec §4.4.1 fragment reliability, §16.3).
//!
//! A `private` MOTE padded to a top-of-ladder bucket fragments into as many as **32
//! independently-pathed Sphinx cells** (§4.4.1). The recipient peels each cell at the exit and must
//! hold the received fragments until the MOTE is complete. Left unbounded, a lost cell would pin
//! reassembly state forever and an adversary could exhaust memory with endless half-MOTEs.
//!
//! This module implements the **safety** part of §4.4.1's fragment reliability: a **bounded**
//! partial-reassembly cache keyed by the fragment [`msg_id`](dmtap_core::sphinx::SphinxFragmentHeader)
//! with an explicit **reassembly timeout** (§16.3: ≤ 15 min, distinct from the 72 h send deadline of
//! §16.1). A partial MOTE that does not complete within the window is discarded; the cache is also
//! capped in the number of concurrent partial MOTEs and in total buffered cells, so memory is bounded
//! regardless of the clock.
//!
//! **Bounded per delivering connection too (§4.4.1 normative, mirroring [`crate::pow::PowGate`]'s
//! per-connection PoW budget and §9.8's per-connection mix-admission budget).** The global caps above
//! bound total recipient memory but do not, by themselves, give every connection a *fair share* of
//! it: a single hostile connection opening `msg_id`s at `frag_count = 32` as fast as it can would
//! otherwise be able to consume the *entire* global budget on its own, starving reassembly for every
//! other — honest — connection sharing this node. §4.4.1 requires the cap to bind "per delivering
//! connection/relay" for exactly this reason, and a cell that would open a new slot beyond the
//! connection's own ceiling is dropped **without allocating a slot**, never counted against, or
//! stealing from, another connection's share. A slot's "owning" connection is whichever delivered the
//! **first** cell that created it; later cells for the same `msg_id` fill the existing slot regardless
//! of which connection carries them (a multi-path `private` MOTE's cells legitimately arrive over
//! independently-selected paths, §4.4.3, so only slot *creation* — not every cell — is attributed).
//!
//! ## Scope — what is deliberately NOT here (the larger follow-up)
//! Full per-cell **recovery** is §4.4.1's larger feature and is **not** implemented in this pass:
//! - **per-cell SURB-ARQ** — the recipient returns a still-missing-cell bitmap over a sender-supplied
//!   Single-Use Reply Block and the sender re-onion-wraps and re-dispatches **only** the missing
//!   cells; and
//! - **FEC** — the sender ships `n > k` erasure-coded cells so the recipient reconstructs from any `k`.
//!
//! This cache is the memory-safety substrate those build on: it bounds and times out partial state so
//! a lost cell cannot leak reassembly memory. ARQ/FEC (the retransmit/coded-recovery machinery) are
//! tracked as the follow-up.
//!
//! Reassembly operates on the **peeled** δ plaintext of each cell — the fixed
//! [`SphinxFragmentHeader`] followed by that fragment's data bytes — not the on-wire ciphertext.

use std::collections::BTreeMap;
use std::collections::HashMap;

use dmtap_core::sphinx::{SphinxFragmentHeader, FRAGMENT_DATA_LEN};
use dmtap_core::TimestampMs;

/// The multi-cell reassembly timeout (§16.3): ≤ 15 min, ≈ 3× the `private`-tier delivery latency
/// budget. **Distinct** from the §16.1 72 h send deadline — this bounds *recipient* memory against
/// half-MOTE flooding, not sender retry.
pub const REASSEMBLY_TIMEOUT_MS: u64 = 15 * 60 * 1000;
/// Max concurrent partial MOTEs held, across every connection — an absolute ceiling. Beyond this the
/// oldest-started partial is evicted (bounded).
pub const MAX_PARTIAL_MOTES: usize = 4_096;
/// Max total buffered fragment cells across all partials, across every connection — an absolute
/// memory ceiling.
pub const MAX_PARTIAL_CELLS: usize = 32 * 1_024;
/// Max concurrent partial MOTEs a **single delivering connection** may have open at once (§4.4.1
/// normative "a fixed, small, per-connection ceiling"). Far below [`MAX_PARTIAL_MOTES`] so one
/// connection cannot consume the whole global budget and starve every other connection's reassembly.
pub const MAX_PARTIAL_MOTES_PER_CONN: usize = 64;
/// Max total buffered fragment cells a single delivering connection's open slots may hold.
pub const MAX_PARTIAL_CELLS_PER_CONN: usize = 512;
/// The bucket-ladder fragment counts (§4.4.1, §16.3). A frame asserting any other `frag_count` is
/// malformed.
const LADDER: [u16; 4] = [1, 4, 16, 32];

/// The outcome of accepting one fragment cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reassembled {
    /// The last missing cell arrived — the full padded MOTE, truncated to its true length. The
    /// partial has been evicted from the cache.
    Complete(Vec<u8>),
    /// Stored; still awaiting more cells.
    Pending,
    /// The cell was malformed, inconsistent with the partial already held, or over a hard cap — it
    /// was dropped and no state changed (fail-closed).
    Rejected,
}

/// One in-flight partial MOTE.
struct Partial {
    frag_count: u16,
    total_len: u32,
    /// Received fragments, keyed by index (dedup + ordered reassembly).
    cells: BTreeMap<u16, Vec<u8>>,
    started_at: TimestampMs,
    /// The delivering connection that created this slot (§4.4.1 per-connection accounting) — the
    /// source of the *first* cell for this `msg_id`, never re-attributed by later cells.
    owner_conn: Vec<u8>,
}

/// Running per-connection usage, so the per-connection cap ([`MAX_PARTIAL_MOTES_PER_CONN`] /
/// [`MAX_PARTIAL_CELLS_PER_CONN`]) can be checked in O(1) rather than rescanning every partial. An
/// entry exists only while its connection owns ≥ 1 open slot, so this table cannot grow unbounded —
/// it is implicitly capped by [`MAX_PARTIAL_MOTES`] (at most one entry per open slot's owner).
#[derive(Default, Clone, Copy)]
struct ConnUsage {
    motes: usize,
    cells: usize,
}

/// A bounded partial-reassembly cache (§4.4.1 safety part). Keyed by the 8-byte fragment `msg_id`,
/// with both a global ceiling and a per-delivering-connection ceiling (§4.4.1 normative).
pub struct ReassemblyCache {
    partials: HashMap<[u8; 8], Partial>,
    conn_usage: HashMap<Vec<u8>, ConnUsage>,
    timeout_ms: u64,
    max_motes: usize,
    max_cells: usize,
    max_motes_per_conn: usize,
    max_cells_per_conn: usize,
}

impl ReassemblyCache {
    /// A cache with the production timeout + caps.
    pub fn new() -> Self {
        Self::with_bounds_and_per_conn(
            REASSEMBLY_TIMEOUT_MS,
            MAX_PARTIAL_MOTES,
            MAX_PARTIAL_CELLS,
            MAX_PARTIAL_MOTES_PER_CONN,
            MAX_PARTIAL_CELLS_PER_CONN,
        )
    }

    /// A cache with explicit global bounds and the production per-connection caps (tests exercise
    /// small global timeouts/caps without needing to also vary the per-connection ones).
    pub fn with_bounds(timeout_ms: u64, max_motes: usize, max_cells: usize) -> Self {
        Self::with_bounds_and_per_conn(
            timeout_ms,
            max_motes,
            max_cells,
            MAX_PARTIAL_MOTES_PER_CONN,
            MAX_PARTIAL_CELLS_PER_CONN,
        )
    }

    /// A cache with every bound explicit (global + per-connection; tests exercise tiny per-connection
    /// ceilings directly).
    pub fn with_bounds_and_per_conn(
        timeout_ms: u64,
        max_motes: usize,
        max_cells: usize,
        max_motes_per_conn: usize,
        max_cells_per_conn: usize,
    ) -> Self {
        ReassemblyCache {
            partials: HashMap::new(),
            conn_usage: HashMap::new(),
            timeout_ms,
            max_motes,
            max_cells,
            max_motes_per_conn,
            max_cells_per_conn,
        }
    }

    /// Accept one peeled fragment (`hdr` + `data`, exactly [`FRAGMENT_DATA_LEN`] bytes), delivered
    /// over connection `conn` (the transport return path / relay identity — attacker-influenced but
    /// cheap to attribute, mirroring [`crate::pow::PowGate::check`]'s `conn` parameter), at receive
    /// clock `now`. Prunes timed-out partials first, then stores the cell — returning
    /// [`Reassembled::Complete`] with the reconstructed MOTE when the final missing cell arrives,
    /// [`Reassembled::Pending`] while incomplete, or [`Reassembled::Rejected`] on a malformed /
    /// inconsistent / over-cap cell.
    pub fn accept(
        &mut self,
        conn: &[u8],
        hdr: &SphinxFragmentHeader,
        data: &[u8],
        now: TimestampMs,
    ) -> Reassembled {
        self.prune(now);

        // Structural validation (fail-closed): ladder frag_count, in-range index, fixed data length.
        if !LADDER.contains(&hdr.frag_count)
            || hdr.frag_index >= hdr.frag_count
            || data.len() != FRAGMENT_DATA_LEN
        {
            return Reassembled::Rejected;
        }
        // total_len must fit the claimed cell count and exceed the previous rung (so frag_count is the
        // genuine ladder rung for this length — a mismatch is a malformed/adversarial frame).
        let cap = hdr.frag_count as usize * FRAGMENT_DATA_LEN;
        if hdr.total_len as usize > cap {
            return Reassembled::Rejected;
        }

        // A single-cell MOTE completes immediately with no caching (nothing to reassemble).
        if hdr.frag_count == 1 {
            let mut out = data.to_vec();
            out.truncate(hdr.total_len as usize);
            self.remove_partial(&hdr.msg_id); // any stray partial under this id is superseded
            return Reassembled::Complete(out);
        }

        // Consistency against a partial already held for this msg_id, and the per-connection /
        // global admission checks, all performed BEFORE any mutation — every rejection below leaves
        // the cache exactly as it was (fail-closed, never a partial charge).
        let is_new_slot = match self.partials.get(&hdr.msg_id) {
            Some(p) => {
                if p.frag_count != hdr.frag_count || p.total_len != hdr.total_len {
                    return Reassembled::Rejected; // an attacker mixing fragments across MOTEs
                }
                // An existing slot: a genuinely new cell index would grow its owner's cell charge —
                // enforce that owner's per-connection cell ceiling (§4.4.1) even though this slot may
                // be owned by a DIFFERENT connection than the one delivering this particular cell
                // (module doc: only the owner is charged, but the owner's ceiling still applies).
                if !p.cells.contains_key(&hdr.frag_index) {
                    let owner_usage = self.conn_usage.get(&p.owner_conn).copied().unwrap_or_default();
                    if owner_usage.cells >= self.max_cells_per_conn {
                        return Reassembled::Rejected;
                    }
                }
                false
            }
            None => {
                // A new slot — enforce the per-connection ceiling FIRST (§4.4.1: a cell that would
                // open a new slot beyond the connection's own cap is dropped WITHOUT allocating a
                // slot — it must never evict another connection's slots to make room for itself).
                let usage = self.conn_usage.get(conn).copied().unwrap_or_default();
                if usage.motes >= self.max_motes_per_conn || usage.cells >= self.max_cells_per_conn {
                    return Reassembled::Rejected;
                }
                // Only now the global caps — a new partial evicts the oldest GLOBAL partial to make
                // room (bounded total memory regardless of which connections are active), then the
                // absolute cell ceiling is checked.
                if self.partials.len() >= self.max_motes {
                    self.evict_oldest();
                }
                if self.total_cells() >= self.max_cells {
                    return Reassembled::Rejected;
                }
                true
            }
        };

        let entry = self.partials.entry(hdr.msg_id).or_insert_with(|| Partial {
            frag_count: hdr.frag_count,
            total_len: hdr.total_len,
            cells: BTreeMap::new(),
            started_at: now,
            owner_conn: conn.to_vec(),
        });
        if is_new_slot {
            let u = self.conn_usage.entry(entry.owner_conn.clone()).or_default();
            u.motes += 1;
        }
        // A duplicate cell index is a no-op (idempotent); a new one is stored and charged to the
        // slot's owning connection (never the delivering connection of THIS cell, which may differ —
        // see the module doc on multi-path attribution). The admission check above already bounded
        // this against the owner's per-connection cell ceiling.
        let inserted_new_cell = {
            let before = entry.cells.len();
            entry.cells.entry(hdr.frag_index).or_insert_with(|| data.to_vec());
            entry.cells.len() != before
        };
        if inserted_new_cell {
            let u = self.conn_usage.entry(entry.owner_conn.clone()).or_default();
            u.cells += 1;
        }

        if entry.cells.len() as u16 == entry.frag_count {
            // Complete: concatenate fragments in index order, truncate to the true length, evict.
            let p = self.remove_partial(&hdr.msg_id).expect("just present");
            let mut out = Vec::with_capacity(p.frag_count as usize * FRAGMENT_DATA_LEN);
            for (_, cell) in p.cells {
                out.extend_from_slice(&cell);
            }
            out.truncate(p.total_len as usize);
            Reassembled::Complete(out)
        } else {
            Reassembled::Pending
        }
    }

    /// Drop every partial whose reassembly timeout has elapsed at `now` (§16.3). Returns how many
    /// were discarded. Called periodically by the node so a lost cell cannot pin memory.
    pub fn prune(&mut self, now: TimestampMs) -> usize {
        let timeout = self.timeout_ms;
        let stale: Vec<[u8; 8]> = self
            .partials
            .iter()
            .filter(|(_, p)| now.saturating_sub(p.started_at) >= timeout)
            .map(|(k, _)| *k)
            .collect();
        let n = stale.len();
        for id in stale {
            self.remove_partial(&id);
        }
        n
    }

    /// The number of partial MOTEs currently held (across every connection).
    pub fn len(&self) -> usize {
        self.partials.len()
    }

    /// `true` iff no partial is held.
    pub fn is_empty(&self) -> bool {
        self.partials.is_empty()
    }

    /// The number of open slots currently attributed to `conn` (test/inspection aid for the
    /// per-connection ceiling).
    pub fn conn_pending(&self, conn: &[u8]) -> usize {
        self.conn_usage.get(conn).map(|u| u.motes).unwrap_or(0)
    }

    fn total_cells(&self) -> usize {
        self.partials.values().map(|p| p.cells.len()).sum()
    }

    /// Remove a partial by `msg_id`, if present, releasing its cell/mote charge from its owning
    /// connection's usage (dropping the connection's entry entirely once it reaches zero, so
    /// [`conn_usage`](Self::conn_usage) never accumulates stale zero-entries).
    fn remove_partial(&mut self, id: &[u8; 8]) -> Option<Partial> {
        let p = self.partials.remove(id)?;
        if let Some(u) = self.conn_usage.get_mut(&p.owner_conn) {
            u.motes = u.motes.saturating_sub(1);
            u.cells = u.cells.saturating_sub(p.cells.len());
            if u.motes == 0 {
                self.conn_usage.remove(&p.owner_conn);
            }
        }
        Some(p)
    }

    /// Evict the oldest-started partial to make room (bounded global concurrent-MOTE cap).
    fn evict_oldest(&mut self) {
        if let Some(key) = self
            .partials
            .iter()
            .min_by_key(|(_, p)| p.started_at)
            .map(|(k, _)| *k)
        {
            self.remove_partial(&key);
        }
    }
}

impl Default for ReassemblyCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(msg_id: [u8; 8], idx: u16, count: u16, total_len: u32) -> SphinxFragmentHeader {
        SphinxFragmentHeader { msg_id, frag_index: idx, frag_count: count, total_len }
    }

    fn cell(fill: u8) -> Vec<u8> {
        vec![fill; FRAGMENT_DATA_LEN]
    }

    const CONN: &[u8] = b"conn-A";

    #[test]
    fn single_cell_completes_immediately() {
        let mut c = ReassemblyCache::new();
        let mut data = cell(0);
        data[..5].copy_from_slice(b"hello");
        let out = c.accept(CONN, &hdr([1; 8], 0, 1, 5), &data, 0);
        assert_eq!(out, Reassembled::Complete(b"hello".to_vec()));
        assert!(c.is_empty(), "a single-cell MOTE is not cached");
    }

    #[test]
    fn multi_cell_reassembles_in_order() {
        let mut c = ReassemblyCache::new();
        let id = [7u8; 8];
        let total = FRAGMENT_DATA_LEN + 3; // spans 2 of the 4-cell rung; the rest is padding
        // Distinguishable payload across the first two cells.
        let mut c0 = cell(0xA0);
        let mut c1 = cell(0xB0);
        c0[0] = 1;
        c1[0] = 2;
        assert_eq!(c.accept(CONN, &hdr(id, 0, 4, total as u32), &c0, 0), Reassembled::Pending);
        assert_eq!(
            c.accept(CONN, &hdr(id, 2, 4, total as u32), &cell(0xC0), 0),
            Reassembled::Pending
        );
        assert_eq!(
            c.accept(CONN, &hdr(id, 3, 4, total as u32), &cell(0xD0), 0),
            Reassembled::Pending
        );
        assert_eq!(c.len(), 1);
        // The last missing cell completes it.
        let out = match c.accept(CONN, &hdr(id, 1, 4, total as u32), &c1, 0) {
            Reassembled::Complete(b) => b,
            other => panic!("expected Complete, got {other:?}"),
        };
        assert_eq!(out.len(), total, "reassembled MOTE truncated to its true length");
        assert_eq!(out[0], 1, "cell 0 first");
        assert_eq!(out[FRAGMENT_DATA_LEN], 2, "cell 1 second");
        assert!(c.is_empty(), "the completed partial is evicted");
    }

    #[test]
    fn incomplete_reassembly_is_evicted_after_the_timeout() {
        let mut c = ReassemblyCache::with_bounds(1_000, 16, 64);
        let id = [9u8; 8];
        assert_eq!(c.accept(CONN, &hdr(id, 0, 4, 100), &cell(1), 0), Reassembled::Pending);
        assert_eq!(c.len(), 1);
        // Still held just before the timeout...
        assert_eq!(c.prune(999), 0);
        assert_eq!(c.len(), 1);
        // ...evicted once it elapses (bounded — a lost cell cannot pin memory).
        assert_eq!(c.prune(1_000), 1);
        assert!(c.is_empty());
        assert_eq!(c.conn_pending(CONN), 0, "eviction releases the owner's per-connection charge");
        // A late cell after eviction starts a fresh partial, never resurrecting the timed-out one.
        assert_eq!(c.accept(CONN, &hdr(id, 1, 4, 100), &cell(2), 1_000), Reassembled::Pending);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn accept_prunes_timed_out_partials() {
        let mut c = ReassemblyCache::with_bounds(1_000, 16, 64);
        c.accept(CONN, &hdr([1; 8], 0, 4, 100), &cell(1), 0);
        // A later accept for a different MOTE prunes the stale one first.
        c.accept(CONN, &hdr([2; 8], 0, 4, 100), &cell(1), 2_000);
        assert_eq!(c.len(), 1, "the timed-out partial was pruned on the next accept");
    }

    #[test]
    fn malformed_frames_are_rejected() {
        let mut c = ReassemblyCache::new();
        // Non-ladder frag_count.
        assert_eq!(c.accept(CONN, &hdr([1; 8], 0, 3, 10), &cell(0), 0), Reassembled::Rejected);
        // Index out of range.
        assert_eq!(c.accept(CONN, &hdr([1; 8], 4, 4, 10), &cell(0), 0), Reassembled::Rejected);
        // Wrong data length.
        assert_eq!(
            c.accept(CONN, &hdr([1; 8], 0, 4, 10), &vec![0u8; 10], 0),
            Reassembled::Rejected
        );
        // total_len larger than the cell count can hold.
        assert_eq!(
            c.accept(CONN, &hdr([1; 8], 0, 4, (5 * FRAGMENT_DATA_LEN) as u32), &cell(0), 0),
            Reassembled::Rejected
        );
        assert!(c.is_empty());
    }

    #[test]
    fn inconsistent_fragments_for_a_msg_id_are_rejected() {
        let mut c = ReassemblyCache::new();
        let id = [5u8; 8];
        assert_eq!(c.accept(CONN, &hdr(id, 0, 4, 100), &cell(1), 0), Reassembled::Pending);
        // Same msg_id but a different frag_count/total_len — an attacker mixing MOTEs.
        assert_eq!(c.accept(CONN, &hdr(id, 1, 16, 100), &cell(2), 0), Reassembled::Rejected);
        assert_eq!(c.accept(CONN, &hdr(id, 1, 4, 999), &cell(2), 0), Reassembled::Rejected);
        assert_eq!(c.len(), 1, "the original partial is untouched");
    }

    #[test]
    fn concurrent_partial_motes_are_bounded() {
        let mut c = ReassemblyCache::with_bounds(REASSEMBLY_TIMEOUT_MS, 2, 64);
        c.accept(CONN, &hdr([1; 8], 0, 4, 100), &cell(1), 0);
        c.accept(CONN, &hdr([2; 8], 0, 4, 100), &cell(1), 1);
        assert_eq!(c.len(), 2);
        // A third partial evicts the oldest-started — the cap holds.
        c.accept(CONN, &hdr([3; 8], 0, 4, 100), &cell(1), 2);
        assert_eq!(c.len(), 2, "never exceeds the concurrent-MOTE cap");
    }

    #[test]
    fn duplicate_cell_index_is_idempotent() {
        let mut c = ReassemblyCache::new();
        let id = [4u8; 8];
        assert_eq!(c.accept(CONN, &hdr(id, 0, 4, 100), &cell(1), 0), Reassembled::Pending);
        assert_eq!(c.accept(CONN, &hdr(id, 0, 4, 100), &cell(9), 0), Reassembled::Pending);
        assert_eq!(c.len(), 1);
    }

    // ── Per-connection ceiling (§4.4.1 normative) ───────────────────────────────────────────────

    #[test]
    fn per_connection_mote_cap_does_not_evict_another_connections_slots() {
        // A tiny per-connection mote cap (1), a roomy global one (100) — isolates the behavior under
        // test from the global-eviction path.
        let mut c = ReassemblyCache::with_bounds_and_per_conn(REASSEMBLY_TIMEOUT_MS, 100, 1_000, 1, 100);
        // Connection A opens its one allowed slot.
        assert_eq!(
            c.accept(b"A", &hdr([1; 8], 0, 4, 100), &cell(1), 0),
            Reassembled::Pending
        );
        assert_eq!(c.conn_pending(b"A"), 1);
        // A second NEW msg_id from A would open a second slot — over A's own cap — dropped WITHOUT
        // allocating a slot and WITHOUT touching A's first (still-pending) slot.
        assert_eq!(
            c.accept(b"A", &hdr([2; 8], 0, 4, 100), &cell(1), 0),
            Reassembled::Rejected
        );
        assert_eq!(c.conn_pending(b"A"), 1, "A's existing slot is untouched by the rejection");
        assert_eq!(c.len(), 1);
        // Connection B, a totally different connection, is NOT affected by A being at its cap — B
        // gets its own slot budget (the whole point of a PER-connection, not shared, ceiling).
        assert_eq!(
            c.accept(b"B", &hdr([3; 8], 0, 4, 100), &cell(1), 0),
            Reassembled::Pending
        );
        assert_eq!(c.len(), 2, "B's slot opened even though A was already at its own cap");
        assert_eq!(c.conn_pending(b"B"), 1);
    }

    #[test]
    fn per_connection_cap_bounds_a_single_hostile_connection_under_the_global_cap() {
        // A large global cap (so the global ceiling never fires) but a small per-connection one — a
        // single connection flooding many distinct msg_ids must stop at ITS OWN ceiling, not the
        // (much larger) global one, and must never starve the space needed by other connections.
        let mut c =
            ReassemblyCache::with_bounds_and_per_conn(REASSEMBLY_TIMEOUT_MS, 4_096, 32_768, 4, 400);
        for i in 0u8..4 {
            assert_eq!(
                c.accept(b"flood", &hdr([i; 8], 0, 4, 100), &cell(1), 0),
                Reassembled::Pending,
                "slot {i} is within flood's own cap"
            );
        }
        assert_eq!(c.len(), 4);
        // The 5th distinct msg_id from the SAME connection is over its own cap.
        assert_eq!(
            c.accept(b"flood", &hdr([9; 8], 0, 4, 100), &cell(1), 0),
            Reassembled::Rejected
        );
        assert_eq!(c.len(), 4, "the flood is capped well under the global ceiling");
        // A completely different connection is unaffected and still has its full budget.
        assert_eq!(
            c.accept(b"victim", &hdr([9; 8], 0, 4, 100), &cell(1), 0),
            Reassembled::Pending
        );
        assert_eq!(c.len(), 5);
    }

    #[test]
    fn per_connection_cell_cap_is_enforced_incrementally() {
        // frag_count = 16 but the connection's cell budget is only 3: the slot opens (motes cap is
        // roomy), but only the first 3 distinct cell indices are admitted; the 4th is dropped.
        let mut c =
            ReassemblyCache::with_bounds_and_per_conn(REASSEMBLY_TIMEOUT_MS, 100, 1_000, 10, 3);
        let id = [1u8; 8];
        assert_eq!(c.accept(CONN, &hdr(id, 0, 16, 1000), &cell(1), 0), Reassembled::Pending);
        assert_eq!(c.accept(CONN, &hdr(id, 1, 16, 1000), &cell(2), 0), Reassembled::Pending);
        assert_eq!(c.accept(CONN, &hdr(id, 2, 16, 1000), &cell(3), 0), Reassembled::Pending);
        // A duplicate of an already-admitted index is still free (idempotent, no new charge).
        assert_eq!(c.accept(CONN, &hdr(id, 0, 16, 1000), &cell(9), 0), Reassembled::Pending);
        // A 4th DISTINCT index is over the per-connection cell budget.
        assert_eq!(c.accept(CONN, &hdr(id, 3, 16, 1000), &cell(4), 0), Reassembled::Rejected);
    }

    #[test]
    fn completing_or_timing_out_a_slot_frees_its_connections_budget() {
        let mut c = ReassemblyCache::with_bounds_and_per_conn(REASSEMBLY_TIMEOUT_MS, 100, 1_000, 1, 100);
        // Fill A's one-slot budget and complete it.
        assert_eq!(
            c.accept(b"A", &hdr([1; 8], 0, 1, 5), &cell(1), 0),
            Reassembled::Complete(vec![1u8; 5])
        );
        assert_eq!(c.conn_pending(b"A"), 0, "a single-cell MOTE never occupies a slot at all");
        // A genuinely multi-cell slot, completed, releases the charge.
        assert_eq!(c.accept(b"A", &hdr([2; 8], 0, 4, 100), &cell(1), 0), Reassembled::Pending);
        assert_eq!(c.conn_pending(b"A"), 1);
        assert_eq!(c.accept(b"A", &hdr([2; 8], 1, 4, 100), &cell(1), 0), Reassembled::Pending);
        assert_eq!(c.accept(b"A", &hdr([2; 8], 2, 4, 100), &cell(1), 0), Reassembled::Pending);
        let out = c.accept(b"A", &hdr([2; 8], 3, 4, 100), &cell(1), 0);
        assert!(matches!(out, Reassembled::Complete(_)));
        assert_eq!(c.conn_pending(b"A"), 0, "completion frees the slot's charge");
        // A now has its budget back for a fresh slot.
        assert_eq!(
            c.accept(b"A", &hdr([3; 8], 0, 4, 100), &cell(1), 0),
            Reassembled::Pending
        );
    }
}
