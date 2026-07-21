//! Usage-ingest queue — decoupling high-volume usage ingest from aggregation.
//!
//! Metering events ([`dmtap_seam::UsageEvent`]) arrive from many OSS nodes/gateways in bursts;
//! aggregating them must not happen on that hot path, or a spike of sends would stall the senders.
//! This module is the buffer between the two: a **bounded FIFO** that accepts events cheaply
//! (O(1)) and is drained, in batches, into a [`UsageSink`] by a separate worker. [`Accumulator`] is
//! the reference sink: it sums usage per `(account, kind)` and can hand the running totals to a
//! [`dmtap_seam::BillingSink`] — no-op by default, Patala's eventual attachment point — whenever an
//! operator wants to.
//!
//! Usage tracking and quota enforcement (see [`crate::policy`]) work identically whether or not
//! any billing system is ever attached; this module has no notion of price, period, or invoice.
//!
//! ## Scale properties
//!
//! - **Batching.** [`MeteringQueue::drain_batch`] pulls up to `max` events at once, so the
//!   aggregation side amortizes per-batch overhead instead of paying it per event.
//! - **Idempotency / dedup.** Every event has a dedup key — its explicit `id`, or the
//!   `(account, kind, ts_ms, amount)` tuple (matching `dmtap-seam/CONTRACT.md`). A key already
//!   seen is counted **once**; a retried or double-delivered event never double-counts. Reported as
//!   [`Enqueued::Duplicate`], not an error.
//! - **Backpressure, never silent loss.** At capacity, [`enqueue`](MeteringQueue::enqueue) returns
//!   [`EnqueueError::Full`] **handing the event back** to the caller to retry/shed/spill. The queue
//!   never drops an accepted event on the floor without signaling.
//!
//! ## Ordering guarantee
//!
//! The queue itself is strict FIFO for the drain worker. But usage events can *arrive* out of
//! timestamp order (independent senders, retries), and that is fine: aggregation is additive and
//! commutative, so the final per-account/per-kind totals do **not** depend on drain order. Only
//! dedup depends on having seen a key before — which is order-independent too.
//!
//! ## What is stubbed
//!
//! In-memory only. A production deployment puts a durable broker (Redis Streams / Kafka / SQS)
//! behind this exact [`MeteringQueue`] surface: `enqueue` becomes a producer append, `drain_batch`
//! a consumer-group read + ack, and the dedup set a durable idempotency store (e.g. Redis `SETNX`
//! keyed on the dedup key with a retention window). The trait boundaries here are chosen so that
//! swap needs no change to [`Accumulator`] or anything downstream of it.

use dmtap_seam::{AccountId, TimestampMs, UsageEvent as SeamUsageEvent, UsageKind};
use std::collections::{HashMap, HashSet, VecDeque};

// =============================================================================================
// Usage event + dedup key
// =============================================================================================

/// A usage event flowing through the queue. Mirrors [`dmtap_seam::UsageEvent`] but carries an
/// optional explicit idempotency `id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedUsage {
    /// Optional explicit idempotency key. When `None`, the dedup key is derived from the tuple
    /// `(account, kind, ts_ms, amount)`, per `dmtap-seam/CONTRACT.md`.
    pub id: Option<String>,
    /// The account/tenant this usage belongs to.
    pub account: AccountId,
    /// Which metered dimension.
    pub kind: UsageKind,
    /// The quantity (bytes, sends, count).
    pub amount: u64,
    /// Event time, ms since the Unix epoch (UTC).
    pub ts_ms: TimestampMs,
}

impl QueuedUsage {
    /// The value used for idempotency: the explicit `id` if present, else the content tuple.
    pub fn dedup_key(&self) -> DedupKey {
        match &self.id {
            Some(id) => DedupKey::Id(id.clone()),
            None => DedupKey::Content(self.account.clone(), self.kind, self.ts_ms, self.amount),
        }
    }
}

/// From a seam [`SeamUsageEvent`] (no explicit id; dedup falls back to the content tuple — the
/// same tuple the seam's own contract dedups on).
impl From<&SeamUsageEvent> for QueuedUsage {
    fn from(e: &SeamUsageEvent) -> Self {
        Self { id: None, account: e.account.clone(), kind: e.kind, amount: e.amount, ts_ms: e.ts_ms }
    }
}

/// A queue-wide idempotency key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DedupKey {
    /// An explicit event id supplied by the producer.
    Id(String),
    /// The `(account, kind, ts_ms, amount)` content tuple, per CONTRACT.md.
    Content(AccountId, UsageKind, TimestampMs, u64),
}

// =============================================================================================
// Sink (drain target)
// =============================================================================================

/// Where drained events are aggregated. The queue is transport; the sink decides what to do with
/// the total. Implemented by [`Accumulator`] (the reference sink) or an operator's own.
pub trait UsageSink {
    /// Record one event into the aggregate.
    fn record(&mut self, event: &QueuedUsage);
}

/// The reference [`UsageSink`]: sums usage per `(account, kind)` in memory. [`Accumulator::export_to`]
/// hands each running total to a [`dmtap_seam::BillingSink`] — [`dmtap_seam::NullBillingSink`] by
/// default, so exporting with nothing attached is a documented no-op, not an error.
#[derive(Debug, Default)]
pub struct Accumulator {
    totals: HashMap<(AccountId, UsageKind), u64>,
}

impl UsageSink for Accumulator {
    fn record(&mut self, event: &QueuedUsage) {
        *self.totals.entry((event.account.clone(), event.kind)).or_insert(0) += event.amount;
    }
}

impl Accumulator {
    /// The running total for one account/kind (`0` if nothing has been recorded).
    pub fn total(&self, account: &AccountId, kind: UsageKind) -> u64 {
        self.totals.get(&(account.clone(), kind)).copied().unwrap_or(0)
    }

    /// Number of distinct `(account, kind)` pairs with a nonzero recorded total.
    pub fn len(&self) -> usize {
        self.totals.len()
    }

    /// True if nothing has been recorded yet.
    pub fn is_empty(&self) -> bool {
        self.totals.is_empty()
    }

    /// Hand every running total to `sink` as a [`dmtap_seam::UsageTotal`]. TODO(patala): this is
    /// the call site Patala's `BillingSink` impl would be wired into; today only
    /// `NullBillingSink` exists, so this is a documented, tested no-op path.
    pub fn export_to(&self, sink: &dyn dmtap_seam::BillingSink) {
        for ((account, kind), amount) in &self.totals {
            sink.export(dmtap_seam::UsageTotal { account: account.clone(), kind: *kind, amount: *amount });
        }
    }
}

// =============================================================================================
// The queue
// =============================================================================================

/// The outcome of a successful [`MeteringQueue::enqueue`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enqueued {
    /// A new event was buffered.
    Accepted,
    /// The event's dedup key was already seen; it was counted once and not buffered again.
    Duplicate,
}

/// Backpressure signal: the queue is at capacity. The rejected event is handed back so the caller
/// can retry later, spill to a durable store, or shed load — the queue never silently drops it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnqueueError {
    /// At capacity. Carries the event back to the caller.
    Full(QueuedUsage),
}

/// A bounded in-memory FIFO of usage events with idempotent enqueue and batched drain.
///
/// Not thread-safe on its own (no interior locking) — a real deployment either wraps it in a lock
/// or, more likely, replaces it wholesale with a broker behind the same methods. Kept single
/// responsibility: buffer + dedup + hand off.
#[derive(Debug)]
pub struct MeteringQueue {
    capacity: usize,
    buf: VecDeque<QueuedUsage>,
    seen: HashSet<DedupKey>,
    duplicates_suppressed: u64,
    rejected_full: u64,
}

impl MeteringQueue {
    /// A new empty queue holding at most `capacity` un-drained events.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            buf: VecDeque::with_capacity(capacity),
            seen: HashSet::new(),
            duplicates_suppressed: 0,
            rejected_full: 0,
        }
    }

    /// Number of events currently buffered (not yet drained).
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Whether the buffer is at capacity (the next distinct enqueue will apply backpressure).
    pub fn is_full(&self) -> bool {
        self.buf.len() >= self.capacity
    }

    /// The configured capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Total distinct duplicates suppressed over this queue's lifetime (idempotency metric).
    pub fn duplicates_suppressed(&self) -> u64 {
        self.duplicates_suppressed
    }

    /// Total enqueues rejected for backpressure over this queue's lifetime.
    pub fn rejected_full(&self) -> u64 {
        self.rejected_full
    }

    /// Buffer an event.
    ///
    /// - Returns `Ok(`[`Enqueued::Duplicate`]`)` and buffers nothing if the dedup key was already
    ///   seen — the event is idempotently counted once.
    /// - Returns `Err(`[`EnqueueError::Full`]`)` **with the event** if the buffer is at capacity
    ///   (backpressure) — dedup state is *not* mutated, so a later retry still dedups correctly.
    /// - Otherwise buffers it and returns `Ok(`[`Enqueued::Accepted`]`)`.
    pub fn enqueue(&mut self, event: QueuedUsage) -> Result<Enqueued, EnqueueError> {
        let key = event.dedup_key();
        if self.seen.contains(&key) {
            self.duplicates_suppressed += 1;
            return Ok(Enqueued::Duplicate);
        }
        if self.is_full() {
            self.rejected_full += 1;
            return Err(EnqueueError::Full(event));
        }
        self.seen.insert(key);
        self.buf.push_back(event);
        Ok(Enqueued::Accepted)
    }

    /// Drain up to `max` events in FIFO order into `sink`, returning how many were handed off.
    /// The aggregation cost is paid here, off the ingest hot path.
    pub fn drain_batch(&mut self, max: usize, sink: &mut impl UsageSink) -> usize {
        let n = max.min(self.buf.len());
        for _ in 0..n {
            let ev = self.buf.pop_front().expect("len checked");
            sink.record(&ev);
        }
        n
    }

    /// Drain everything currently buffered, in `batch_size` chunks, into `sink`. Models the
    /// background worker's steady-state loop; returns the total number of events drained.
    pub fn drain_all(&mut self, batch_size: usize, sink: &mut impl UsageSink) -> usize {
        let batch = batch_size.max(1);
        let mut total = 0;
        while !self.buf.is_empty() {
            total += self.drain_batch(batch, sink);
        }
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trivial counting sink for exercising the queue in isolation from [`Accumulator`].
    #[derive(Default)]
    struct CountingSink {
        recorded: Vec<QueuedUsage>,
    }
    impl UsageSink for CountingSink {
        fn record(&mut self, event: &QueuedUsage) {
            self.recorded.push(event.clone());
        }
    }

    fn ev(account: &str, amount: u64, ts_ms: u64) -> QueuedUsage {
        QueuedUsage { id: None, account: account.into(), kind: UsageKind::GatewaySend, amount, ts_ms }
    }

    #[test]
    fn enqueue_and_drain_preserves_fifo_order() {
        let mut q = MeteringQueue::with_capacity(10);
        for i in 0..5 {
            assert_eq!(q.enqueue(ev("a", i, i)).unwrap(), Enqueued::Accepted);
        }
        let mut sink = CountingSink::default();
        assert_eq!(q.drain_all(2, &mut sink), 5);
        let amounts: Vec<u64> = sink.recorded.iter().map(|e| e.amount).collect();
        assert_eq!(amounts, vec![0, 1, 2, 3, 4]); // FIFO
        assert!(q.is_empty());
    }

    #[test]
    fn drain_batch_respects_max_and_leaves_the_rest() {
        let mut q = MeteringQueue::with_capacity(10);
        for i in 0..5 {
            q.enqueue(ev("a", i, i)).unwrap();
        }
        let mut sink = CountingSink::default();
        assert_eq!(q.drain_batch(3, &mut sink), 3);
        assert_eq!(q.len(), 2);
        assert_eq!(q.drain_batch(3, &mut sink), 2); // only 2 remain
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn duplicate_by_content_tuple_counted_once() {
        let mut q = MeteringQueue::with_capacity(10);
        assert_eq!(q.enqueue(ev("a", 5, 1000)).unwrap(), Enqueued::Accepted);
        assert_eq!(q.enqueue(ev("a", 5, 1000)).unwrap(), Enqueued::Duplicate); // same tuple
        assert_eq!(q.len(), 1);
        assert_eq!(q.duplicates_suppressed(), 1);
    }

    #[test]
    fn duplicate_by_explicit_id_counted_once_even_if_content_differs() {
        let mut q = MeteringQueue::with_capacity(10);
        let a = QueuedUsage { id: Some("evt-1".into()), account: "a".into(), kind: UsageKind::GatewaySend, amount: 5, ts_ms: 1 };
        let b = QueuedUsage { id: Some("evt-1".into()), account: "a".into(), kind: UsageKind::StorageBytes, amount: 99, ts_ms: 2 };
        assert_eq!(q.enqueue(a).unwrap(), Enqueued::Accepted);
        assert_eq!(q.enqueue(b).unwrap(), Enqueued::Duplicate); // same explicit id wins
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn distinct_events_are_not_deduped() {
        let mut q = MeteringQueue::with_capacity(10);
        assert_eq!(q.enqueue(ev("a", 5, 1000)).unwrap(), Enqueued::Accepted);
        assert_eq!(q.enqueue(ev("a", 6, 1000)).unwrap(), Enqueued::Accepted); // different amount
        assert_eq!(q.enqueue(ev("b", 5, 1000)).unwrap(), Enqueued::Accepted); // different account
        assert_eq!(q.enqueue(ev("a", 5, 2000)).unwrap(), Enqueued::Accepted); // different ts
        assert_eq!(q.len(), 4);
    }

    #[test]
    fn backpressure_returns_the_event_and_never_drops_silently() {
        let mut q = MeteringQueue::with_capacity(2);
        q.enqueue(ev("a", 1, 1)).unwrap();
        q.enqueue(ev("a", 2, 2)).unwrap();
        assert!(q.is_full());
        let rejected = ev("a", 3, 3);
        match q.enqueue(rejected.clone()) {
            Err(EnqueueError::Full(returned)) => assert_eq!(returned, rejected), // handed back
            other => panic!("expected Full, got {:?}", other),
        }
        assert_eq!(q.len(), 2); // unchanged
        assert_eq!(q.rejected_full(), 1);
    }

    #[test]
    fn backpressure_does_not_pollute_dedup_state() {
        // A rejected (full) event must still be enqueueable after space frees up — i.e. being
        // rejected must NOT mark it as "seen".
        let mut q = MeteringQueue::with_capacity(1);
        q.enqueue(ev("a", 1, 1)).unwrap();
        let e = ev("a", 2, 2);
        assert!(matches!(q.enqueue(e.clone()), Err(EnqueueError::Full(_))));
        let mut sink = CountingSink::default();
        q.drain_all(10, &mut sink); // free space
        assert_eq!(q.enqueue(e).unwrap(), Enqueued::Accepted); // now accepted, not "duplicate"
    }

    #[test]
    fn high_volume_burst_enqueues_fast_then_drains_in_batches() {
        // Simulate a burst far larger than a single batch; ingest all, then aggregate separately.
        let mut q = MeteringQueue::with_capacity(100_000);
        let n = 50_000u64;
        for i in 0..n {
            // distinct ts so nothing dedups
            q.enqueue(ev("a", 1, i)).unwrap();
        }
        assert_eq!(q.len(), n as usize);
        let mut sink = CountingSink::default();
        let drained = q.drain_all(1000, &mut sink); // batched aggregation
        assert_eq!(drained, n as usize);
        assert_eq!(sink.recorded.len(), n as usize);
        assert!(q.is_empty());
    }

    #[test]
    fn dedup_survives_a_replayed_burst() {
        // Re-delivering the exact same burst must add nothing (idempotency at scale).
        let mut q = MeteringQueue::with_capacity(100_000);
        let n = 10_000u64;
        for i in 0..n {
            q.enqueue(ev("a", 1, i)).unwrap();
        }
        let mut replay_dups = 0u64;
        for i in 0..n {
            if q.enqueue(ev("a", 1, i)).unwrap() == Enqueued::Duplicate {
                replay_dups += 1;
            }
        }
        assert_eq!(replay_dups, n);
        assert_eq!(q.len(), n as usize); // no growth from the replay
        assert_eq!(q.duplicates_suppressed(), n);
    }

    #[test]
    fn from_seam_usage_event_uses_content_dedup() {
        let m = SeamUsageEvent { account: "a".into(), kind: UsageKind::StorageBytes, amount: 42, ts_ms: 1234 };
        let e: QueuedUsage = (&m).into();
        assert_eq!(e.id, None);
        assert_eq!(e.account, "a");
        assert_eq!(e.amount, 42);
        assert_eq!(e.ts_ms, 1234);
        assert_eq!(e.dedup_key(), DedupKey::Content("a".into(), UsageKind::StorageBytes, 1234, 42));
    }

    // ---- concurrent usage ingest: the documented "wrap it in a lock" deployment pattern,
    // exercised with REAL OS threads (not just single-threaded sequencing) — proves the queue's
    // dedup and count invariants hold under actual concurrent ingest, not just the theoretical
    // order-independence argument in the module docs. ----

    #[test]
    fn concurrent_enqueue_from_many_threads_drains_exactly_once_each() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let queue = Arc::new(Mutex::new(MeteringQueue::with_capacity(100_000)));
        const THREADS: u64 = 8;
        const PER_THREAD: u64 = 2_000;

        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let q = Arc::clone(&queue);
                thread::spawn(move || {
                    for i in 0..PER_THREAD {
                        // Every event has a globally distinct ts_ms, so nothing dedups —
                        // this test is about safe concurrent access, not idempotency.
                        let e = ev("acct", 1, t * PER_THREAD + i);
                        q.lock().unwrap().enqueue(e).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        let mut sink = CountingSink::default();
        let drained = queue.lock().unwrap().drain_all(500, &mut sink);
        assert_eq!(drained, (THREADS * PER_THREAD) as usize);
        assert_eq!(sink.recorded.len(), (THREADS * PER_THREAD) as usize);
    }

    #[test]
    fn concurrent_enqueue_of_the_same_dedup_key_from_many_threads_accepts_it_exactly_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};
        use std::thread;

        let queue = Arc::new(Mutex::new(MeteringQueue::with_capacity(1_000)));
        let accepted = Arc::new(AtomicUsize::new(0));
        const THREADS: usize = 16;

        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let q = Arc::clone(&queue);
                let accepted = Arc::clone(&accepted);
                thread::spawn(move || {
                    // Every thread races to enqueue the IDENTICAL event (same explicit id) —
                    // a real-world race between two retried gateway POSTs arriving concurrently.
                    let e = QueuedUsage {
                        id: Some("shared-idempotency-key".into()),
                        account: "acct".into(),
                        kind: UsageKind::GatewaySend,
                        amount: 1,
                        ts_ms: 1,
                    };
                    if q.lock().unwrap().enqueue(e).unwrap() == Enqueued::Accepted {
                        accepted.fetch_add(1, Ordering::SeqCst);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(accepted.load(Ordering::SeqCst), 1, "exactly one racer's enqueue must win as Accepted");
        assert_eq!(queue.lock().unwrap().len(), 1, "the queue must hold exactly one copy of the event");
    }

    #[test]
    fn empty_queue_drain_is_a_noop() {
        let mut q = MeteringQueue::with_capacity(4);
        let mut sink = CountingSink::default();
        assert_eq!(q.drain_batch(10, &mut sink), 0);
        assert_eq!(q.drain_all(10, &mut sink), 0);
    }

    // ---- Accumulator: the reference sink that feeds BillingSink ----

    #[test]
    fn accumulator_sums_per_account_and_kind() {
        let mut q = MeteringQueue::with_capacity(10);
        q.enqueue(ev("a", 5, 1)).unwrap();
        q.enqueue(ev("a", 7, 2)).unwrap();
        q.enqueue(ev("b", 3, 3)).unwrap();
        let mut acc = Accumulator::default();
        q.drain_all(10, &mut acc);
        assert_eq!(acc.total(&"a".to_string(), UsageKind::GatewaySend), 12);
        assert_eq!(acc.total(&"b".to_string(), UsageKind::GatewaySend), 3);
        assert_eq!(acc.total(&"a".to_string(), UsageKind::StorageBytes), 0);
        assert_eq!(acc.len(), 2);
    }

    #[test]
    fn accumulator_export_to_null_sink_is_a_documented_noop() {
        let mut q = MeteringQueue::with_capacity(10);
        q.enqueue(ev("a", 5, 1)).unwrap();
        let mut acc = Accumulator::default();
        q.drain_all(10, &mut acc);
        // No billing system attached — exporting must not panic and must not be an error.
        acc.export_to(&dmtap_seam::NullBillingSink);
    }

    #[test]
    fn accumulator_export_to_reaches_every_recorded_total() {
        use std::sync::Mutex;

        struct RecordingSink(Mutex<Vec<dmtap_seam::UsageTotal>>);
        impl dmtap_seam::BillingSink for RecordingSink {
            fn export(&self, total: dmtap_seam::UsageTotal) {
                self.0.lock().unwrap().push(total);
            }
        }

        let mut q = MeteringQueue::with_capacity(10);
        q.enqueue(ev("a", 5, 1)).unwrap();
        q.enqueue(ev("b", 9, 2)).unwrap();
        let mut acc = Accumulator::default();
        q.drain_all(10, &mut acc);

        let sink = RecordingSink(Mutex::new(Vec::new()));
        acc.export_to(&sink);
        let exported = sink.0.into_inner().unwrap();
        assert_eq!(exported.len(), 2);
        assert!(exported.iter().any(|t| t.account == "a" && t.amount == 5));
        assert!(exported.iter().any(|t| t.account == "b" && t.amount == 9));
    }
}
