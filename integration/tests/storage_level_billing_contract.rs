//! The storage-metering contract across the operator seam — **this test is about money.**
//!
//! Two real components meet here, and nowhere else in this workspace:
//!
//! * the **node** side (`dmtap::usage`, i.e. `node/src/usage.rs`), which emits per-accept
//!   [`UsageEvent`] *deltas* and offers [`StoredBytesLevel`] to turn them into a *level*;
//! * the **operator** side (`dmtap_operator::queue`), whose [`MeteringQueue`] + [`Accumulator`] are
//!   the reference rater — and which **sums** the `amount` of every event it receives for an
//!   `(account, kind)` pair.
//!
//! A hosted-storage meter is a LEVEL. A summing rater ADDS. Those two are compatible for exactly one
//! reporting cadence: **once per billing period**. Any faster and the bill is multiplied by the
//! number of samples — a nightly bridge against a 30-day period charges ~30× the storage actually
//! held. That failure is silent: every event is individually well-formed, the totals are plausible
//! integers, and nothing errors.
//!
//! The node deliberately depends on neither `dmtap-seam` nor `dmtap-operator` (it links no billing
//! code, §12.2), so this cross-seam property cannot be asserted from either crate's own tests. It is
//! asserted here, against the real types on both sides, so that:
//!
//! 1. a bridge implementor has an executable statement of the contract, not only a doc comment;
//! 2. flipping the rater to last-write-wins, or dropping the node-side once-per-period guard, breaks
//!    a test instead of quietly re-pricing every customer.

use dmtap::usage::{CountingUsageMeter, LevelReport, NodeUsageMeter, StoredBytesLevel, UsageEvent};
use dmtap_operator::queue::{Accumulator, MeteringQueue, QueuedUsage};
use dmtap_seam::UsageKind;

/// Nights in the billing period a naive bridge samples across.
const NIGHTS: u64 = 30;
/// The billing-period ordinal under test (`year * 12 + month`, an arbitrary monotone choice).
const PERIOD: u64 = 2026 * 12 + 7;

const ACCOUNT: &[u8] = b"account-under-test";
/// The `dmtap-seam` account id the bridge maps `ACCOUNT` onto.
const SEAM_ACCOUNT: &str = "account-under-test";

/// The level the events below leave behind: 4 MiB + 8 MiB − 2 MiB.
const EXPECTED_LEVEL: u64 = 10 * 1024 * 1024;

/// Build the node-side event stream a month of real mailbox activity produces: some accepts, one
/// eviction. The level it ends on is what a GB-month sample must carry.
fn a_months_node_events() -> Vec<UsageEvent> {
    vec![
        UsageEvent::Stored { account: ACCOUNT.to_vec(), delta_bytes: 4 * 1024 * 1024, at: 1 },
        UsageEvent::MessageAccepted { account: ACCOUNT.to_vec(), at: 2 },
        UsageEvent::Stored { account: ACCOUNT.to_vec(), delta_bytes: 8 * 1024 * 1024, at: 3 },
        UsageEvent::Evicted { account: ACCOUNT.to_vec(), delta_bytes: 2 * 1024 * 1024, at: 4 },
    ]
}

/// The level after folding [`a_months_node_events`], ready to report.
fn a_months_level() -> StoredBytesLevel {
    let mut level = StoredBytesLevel::new(ACCOUNT.to_vec());
    for e in a_months_node_events() {
        level.observe(&e);
    }
    level
}

/// Feed one storage-level report into the real operator-side pipeline (queue → summing accumulator),
/// exactly as a bridge would. `ts_ms` must differ per report: the queue dedups by content, so equal
/// timestamps would collapse the reports and hide the very multiplication under test.
fn report_to_operator(queue: &mut MeteringQueue, account: &str, level_bytes: u64, ts_ms: u64) {
    let event = QueuedUsage {
        id: None,
        account: account.to_string(),
        kind: UsageKind::StorageBytes,
        amount: level_bytes,
        ts_ms,
    };
    queue.enqueue(event).expect("the queue has capacity for this test's reports");
}

/// The node's own meter and the level reporter must agree on what the level IS, or the rest of this
/// file is testing the wrong number.
#[test]
fn the_node_meter_and_the_level_reporter_see_the_same_level() {
    let meter = CountingUsageMeter::new();
    let mut level = StoredBytesLevel::new(ACCOUNT.to_vec());
    for e in a_months_node_events() {
        meter.record(&e);
        assert!(level.observe(&e), "every event in this stream is for the account under test");
    }

    assert_eq!(meter.stored_bytes(ACCOUNT), EXPECTED_LEVEL as i64);
    assert_eq!(level.level(), EXPECTED_LEVEL as i64);
}

/// THE BUG THIS FILE EXISTS FOR. A bridge that samples the level nightly and emits an event per
/// sample bills the period 30× over, because the rater sums. Proven against the real rater, not a
/// model of it.
#[test]
fn sampling_a_level_more_often_than_once_per_period_multiplies_the_bill() {
    let level = a_months_level();
    let mut queue = MeteringQueue::with_capacity(64);

    // The naive bridge: read the level, send it, every night. It bypasses the once-per-period guard
    // by reading `level()` directly instead of asking `report_for_period`.
    for night in 0..NIGHTS {
        report_to_operator(&mut queue, SEAM_ACCOUNT, level.level() as u64, night * 86_400_000);
    }

    let mut acc = Accumulator::default();
    let drained = queue.drain_all(NIGHTS as usize, &mut acc);
    assert_eq!(drained, NIGHTS as usize, "all 30 samples really reached the rater (none deduped)");

    let billed = acc.total(&SEAM_ACCOUNT.to_string(), UsageKind::StorageBytes);
    assert_eq!(
        billed,
        EXPECTED_LEVEL * NIGHTS,
        "the operator-side rater SUMS StorageBytes events, so nightly level samples bill 30x the \
         storage actually held. This assertion documents the defect, it does not endorse it — see \
         the next test for the correct cadence."
    );
}

/// THE GUARD. The same nightly cron, but reporting through [`StoredBytesLevel::report_for_period`],
/// bills the level exactly once — so the level meter and the summing rater agree.
#[test]
fn reporting_through_the_guard_bills_the_level_exactly_once_per_period() {
    let mut level = a_months_level();
    let mut queue = MeteringQueue::with_capacity(64);
    let mut reports = 0usize;

    // Same nightly cadence as the over-billing test above — the guard, not the schedule, is what
    // makes this correct. A bridge does not have to be clever about when it wakes up.
    for night in 0..NIGHTS {
        if let Some(bytes) = level.report_for_period(PERIOD).bytes_to_report() {
            report_to_operator(&mut queue, SEAM_ACCOUNT, bytes, night * 86_400_000);
            reports += 1;
        }
    }
    assert_eq!(reports, 1, "the guard emitted once for the period despite 30 wake-ups");

    let mut acc = Accumulator::default();
    queue.drain_all(NIGHTS as usize, &mut acc);
    assert_eq!(
        acc.total(&SEAM_ACCOUNT.to_string(), UsageKind::StorageBytes),
        EXPECTED_LEVEL,
        "one report per period means the summed total IS the level"
    );
}

/// Across periods the level must be billed again — bytes held for two months cost two months. The
/// guard must not degenerate into "report once, ever".
#[test]
fn each_period_bills_the_level_that_period_ends_on() {
    let mut level = a_months_level();
    let mut queue = MeteringQueue::with_capacity(64);

    let first = level.report_for_period(PERIOD);
    assert_eq!(first, LevelReport::Report(EXPECTED_LEVEL));
    report_to_operator(&mut queue, SEAM_ACCOUNT, first.bytes_to_report().unwrap(), 1);

    // Nothing new stored; the same bytes are still held into the next period.
    let second = level.report_for_period(PERIOD + 1);
    assert_eq!(second, LevelReport::Report(EXPECTED_LEVEL));
    report_to_operator(&mut queue, SEAM_ACCOUNT, second.bytes_to_report().unwrap(), 2);

    let mut acc = Accumulator::default();
    queue.drain_all(8, &mut acc);
    assert_eq!(
        acc.total(&SEAM_ACCOUNT.to_string(), UsageKind::StorageBytes),
        EXPECTED_LEVEL * 2,
        "two periods of holding the same bytes is two periods of storage — that is the level meter \
         working, not the 30x defect"
    );
}

/// A restart mid-period must not re-report a period that was already reported: the crash-loop
/// version of the 30× bug.
#[test]
fn a_bridge_restart_does_not_re_report_the_current_period() {
    let level = a_months_level();
    let mut queue = MeteringQueue::with_capacity(64);
    let mut sent = 0usize;

    // Ten restarts inside one period, each resuming from the persisted (level, last_reported_period).
    let mut persisted = (level.level(), level.last_reported_period());
    for restart in 0..10u64 {
        let mut resumed = StoredBytesLevel::resume(ACCOUNT.to_vec(), persisted.0, persisted.1);
        if let Some(bytes) = resumed.report_for_period(PERIOD).bytes_to_report() {
            report_to_operator(&mut queue, SEAM_ACCOUNT, bytes, restart * 3_600_000 + 1);
            sent += 1;
        }
        persisted = (resumed.level(), resumed.last_reported_period());
    }
    assert_eq!(sent, 1, "ten restarts in one period send one report");

    let mut acc = Accumulator::default();
    queue.drain_all(16, &mut acc);
    assert_eq!(acc.total(&SEAM_ACCOUNT.to_string(), UsageKind::StorageBytes), EXPECTED_LEVEL);
}

/// One node's stream may name several accounts; a reporter per account must not cross-bill.
#[test]
fn levels_stay_per_account_across_the_seam() {
    const OTHER: &[u8] = b"someone-else";
    const OTHER_SEAM: &str = "someone-else";

    let mut mine = StoredBytesLevel::new(ACCOUNT.to_vec());
    let mut theirs = StoredBytesLevel::new(OTHER.to_vec());

    let mut stream = a_months_node_events();
    stream.push(UsageEvent::Stored { account: OTHER.to_vec(), delta_bytes: 777, at: 9 });
    for e in &stream {
        mine.observe(e);
        theirs.observe(e);
    }

    let mut queue = MeteringQueue::with_capacity(64);
    let a = mine.report_for_period(PERIOD).bytes_to_report().unwrap();
    let b = theirs.report_for_period(PERIOD).bytes_to_report().unwrap();
    report_to_operator(&mut queue, SEAM_ACCOUNT, a, 1);
    report_to_operator(&mut queue, OTHER_SEAM, b, 2);

    let mut acc = Accumulator::default();
    queue.drain_all(8, &mut acc);
    assert_eq!(acc.total(&SEAM_ACCOUNT.to_string(), UsageKind::StorageBytes), EXPECTED_LEVEL);
    assert_eq!(acc.total(&OTHER_SEAM.to_string(), UsageKind::StorageBytes), 777);
}
