// no-broker-dep:allow-file: doc comment notes the one role that remains (Pier) bills nothing and
// nothing here is wired to a bridge -- states the ABSENCE of a dependency.

//! Hosted-node **storage** seam — the node side of the operator seam (spec §12.2, §12.3, §12.4).
//!
//! A third-party operator hosting nodes for other people has a real "node usage" cost center:
//! **hosted-mailbox storage** — the durable bytes a node holds on an account's behalf. This
//! module is the OSS half of that meter (mirroring the shape the gateway already uses,
//! [`GatewayAuthz`] + [`GatewayMeter`], §7.9), and the whole operator relationship it exposes
//! reduces to exactly **two traits** —
//!
//! 1. [`StorageQuota`] — a **Policy** decision (§12.2): given an account and a proposed storage
//!    delta, may the node durably accept it, and what allowance remains? The self-host default
//!    ([`UnlimitedStorage`]) is **unlimited** and never denies.
//! 2. [`NodeUsageMeter`] — a **Metering** sink (§12.2): an append-only stream of usage events
//!    (stored-bytes delta / eviction / message-accepted) an operator may turn into a bill if they
//!    choose to. The self-host default ([`NullUsageMeter`]) is a no-op.
//!
//! ## Bridging these events to an operator's meter — read the contract before you write one
//!
//! **No such meter exists in this suite today.** The hosted control plane these counters were
//! originally shaped for (envoir-cloud) no longer exists, and reachability — the only operator
//! role that remains — is Pier, which bills nothing. So nothing here is wired to a bridge, and
//! nothing should be: these are LOCAL counters a node keeps about itself.
//!
//! The contract below is written down anyway, because the failure it prevents is expensive and
//! silent. A previous version of this doc instructed an implementor to forward a level to a
//! summing meter, which over-bills by the number of samples taken — roughly 30x for nightly
//! sampling. If anyone ever does build a bridge, these are the terms.
//! The events here are **deltas**; a hosted-storage meter is a **level**; and the reference
//! operator-side rater in this workspace (`dmtap_operator::queue::Accumulator`) **sums** the events
//! it receives. Those three facts only add up to a correct bill if the level is reported **once per
//! billing period** — sampling more often multiplies the bill by the number of samples. The full
//! contract is on [`UsageEvent::Stored`], and [`StoredBytesLevel`] is the guard that enforces it so a
//! bridge does not have to.
//!
//! ## No money, no plans, no pricing here
//! The seam carries **events and a yes/no** — nothing about currency, plans, or prices. The node
//! links **no** billing crate; an operator's own tooling *drops into* these traits from the
//! outside. The OSS defaults make the node run **identically with no operator attached**:
//! self-host stores everything and is billed by no one (§12.2 "self-host default is
//! unlimited/no-op").
//!
//! ## The inviolable rule (§12.3) — this seam gates operations, never protection
//! A denied store refuses to **durably add new inbound** to the mailbox. It does **not** — and MUST
//! never — touch encryption, decryption, the mixnet, metadata privacy, recovery, or a user's access
//! to keys or to already-stored mail. It is a storage **operation** limit on new writes, exactly the
//! "operations and organizational concerns only" the seam is allowed to meter and cap. Everything the
//! node already holds stays fully readable regardless of any quota verdict.
//!
//! ## Fail-closed enforcement vs. the impl's own fallback (§12.2)
//! The node **enforces a `Deny` faithfully**: a store the quota does not admit is **not** written and
//! **not** acked (fail-closed — the node never silently ignores a deny and stores anyway). What to do
//! when a *remote* operator is unreachable is the **impl's** concern, not the node's: per §12.2 an
//! operator's Policy SHOULD fall back to `Allow` there (a billing concern, not a security one). The
//! OSS default simply never denies, so this file's behavior on self-host is: admit everything.
//!
//! [`GatewayAuthz`]: crate — see `gateway` crate `provenance::GatewayAuthz`
//! [`GatewayMeter`]: crate — see `gateway` crate `provenance::GatewayMeter`

use std::cell::RefCell;
use std::rc::Rc;

use dmtap_core::TimestampMs;

// ── Storage Policy seam (§12.2 Policy: storage caps) ──────────────────────────────────────────

/// The verdict for a proposed durable storage write (§12.2 Policy). `remaining_bytes` is the
/// allowance left for this account **after** the decision would apply: `None` means *unlimited*
/// (the self-host default), `Some(n)` means at most `n` further bytes may be stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaDecision {
    /// The write is admitted. `remaining_bytes` is the allowance left afterwards (`None` = unlimited).
    Allow { remaining_bytes: Option<u64> },
    /// The write is refused — the account's storage cap would be exceeded. `remaining_bytes` is what
    /// the account may still store (`< delta_bytes`, possibly `0`); `reason` is safe to surface.
    Deny { reason: String, remaining_bytes: u64 },
}

impl QuotaDecision {
    /// Whether the write is admitted. The node stores + meters **iff** this is true (fail-closed).
    pub fn is_allowed(&self) -> bool {
        matches!(self, QuotaDecision::Allow { .. })
    }

    /// The allowance remaining after this decision would apply: `None` = unlimited, `Some(n)` = at
    /// most `n` further bytes. Uniform accessor across both variants.
    pub fn remaining_bytes(&self) -> Option<u64> {
        match self {
            QuotaDecision::Allow { remaining_bytes } => *remaining_bytes,
            QuotaDecision::Deny { remaining_bytes, .. } => Some(*remaining_bytes),
        }
    }
}

/// The **Policy** capability for hosted-mailbox storage (§12.2). Given the mailbox owner's account
/// (`account` — the node's root identity public bytes, §1.2, which a hosted deployment maps to its
/// billing account) and a proposed `delta_bytes` of new durable storage, decide [`QuotaDecision`]
/// and expose the remaining allowance.
///
/// The node consults this **before** durably accepting a stored MOTE/file. The OSS ships
/// [`UnlimitedStorage`] (never denies); a cloud impl drops in from the outside. No pricing, no plans
/// — only a yes/no and how much room is left. The trait carries no `Send + Sync` bound, matching the
/// node's other injected seams ([`crate::Journal`], the name-chain client): the node is a single
/// current-thread actor.
pub trait StorageQuota {
    /// May `account` durably store `delta_bytes` more? Returns the verdict and remaining allowance.
    fn admit(&self, account: &[u8], delta_bytes: u64) -> QuotaDecision;
}

/// The self-host default: **unlimited** (§12.2 "self-host default is unlimited/no-op"). Every write is
/// [`QuotaDecision::Allow`] with `remaining_bytes: None`, so a node with no operator stores everything
/// and self-host is byte-for-byte unaffected by the seam.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnlimitedStorage;

impl StorageQuota for UnlimitedStorage {
    fn admit(&self, _account: &[u8], _delta_bytes: u64) -> QuotaDecision {
        QuotaDecision::Allow { remaining_bytes: None }
    }
}

// ── Metering seam (§12.2 Metering: storage / message counts) ──────────────────────────────────

/// One appended node-usage event — the raw material the operator's billing (a **separate repo**)
/// turns into a bill. It carries **no** money, plan, or price: just what happened, to which account,
/// and when. Emitted by the node at the real storage cost centers only (§12.2, §12.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageEvent {
    /// A MOTE/file was durably accepted into the mailbox: `delta_bytes` were added. This is the
    /// primary "node usage" (hosted-mailbox storage) signal an operator samples into GB-month
    /// (§12.4).
    ///
    /// # CONTRACT for any future usage bridge — both halves, or users are billed wrongly
    /// (No bridge exists today; see the module doc. These are local counters.)
    ///
    /// 1. **Forward the LEVEL, not the deltas.** A storage meter is a *level* meter: forward the
    ///    current stored-bytes level (the running signed sum of [`UsageEvent::stored_delta`], i.e.
    ///    `Stored − Evicted`), NOT raw per-accept `Stored` deltas. Forwarding deltas over-bills a
    ///    churny mailbox and under-bills bytes held across periods.
    /// 2. **Forward that level AT MOST ONCE PER BILLING PERIOD.** An operator-side storage meter
    ///    (the `StorageBytes` dimension of `dmtap-seam`, whose reference rater
    ///    `dmtap_operator::queue::Accumulator` **sums** every matching event for an account) turns
    ///    the events it receives into a *total*. Sending a level `N` times in one period therefore
    ///    bills `N × level`: a nightly sample against a 30-day period over-bills by **~30×**. A sum
    ///    of samples is neither an average nor a level.
    ///
    /// Rule 2 is what makes rule 1 safe, and it is the rule that costs money when missed. A level
    /// fed to a summing meter is correct **iff exactly one sample lands per period** — so a bridge
    /// samples on a period boundary, not on a cron interval it picked for freshness.
    ///
    /// Do not re-derive this: [`StoredBytesLevel`] folds the deltas *and* refuses to emit a second
    /// report for a period, so the once-per-period rule is structural rather than remembered. The
    /// end-to-end consequence — the same level through a real summing rater, once versus nightly —
    /// is pinned by `integration/tests/storage_level_billing_contract.rs`.
    ///
    /// If an operator's meter is instead last-write-wins (a true level meter that overwrites), that
    /// is a *different* contract and switching to it is a deliberate, reviewed change on the meter's
    /// side — never something a bridge may assume.
    Stored { account: Vec<u8>, delta_bytes: u64, at: TimestampMs },
    /// Durably-stored bytes were released (expunge/retention eviction): `delta_bytes` were freed. The
    /// running signed sum of `Stored − Evicted` is the current stored-bytes level a GB-month sample
    /// reads. (The reference node has no eviction call site yet; the variant completes the seam so a
    /// cloud impl — or a future expunge path — can bill storage as a *level*, not a monotone total.)
    Evicted { account: Vec<u8>, delta_bytes: u64, at: TimestampMs },
    /// A message was accepted into the inbox (a unit count, independent of its size) — the optional
    /// message-count meter (§12.2 "message counts").
    MessageAccepted { account: Vec<u8>, at: TimestampMs },
}

impl UsageEvent {
    /// The account this event bills against (the mailbox owner's identity bytes).
    pub fn account(&self) -> &[u8] {
        match self {
            UsageEvent::Stored { account, .. }
            | UsageEvent::Evicted { account, .. }
            | UsageEvent::MessageAccepted { account, .. } => account,
        }
    }

    /// The signed contribution of this event to the account's stored-bytes level: `Stored` adds,
    /// `Evicted` subtracts, `MessageAccepted` is size-neutral (`0`). Summing this over the stream
    /// yields the current GB-month sample input.
    pub fn stored_delta(&self) -> i64 {
        match self {
            UsageEvent::Stored { delta_bytes, .. } => *delta_bytes as i64,
            UsageEvent::Evicted { delta_bytes, .. } => -(*delta_bytes as i64),
            UsageEvent::MessageAccepted { .. } => 0,
        }
    }
}

/// The **Metering** capability an operator's own tooling consumes (§12.2). The node calls
/// [`Self::record`] once per real storage cost event; the sink is append-only and holds no
/// policy. Like [`StorageQuota`], it carries no `Send + Sync` bound (single-threaded node actor)
/// and no billing dependency — a billing backend implements it from the outside, if one exists.
pub trait NodeUsageMeter {
    /// Append `event` to the usage stream. Best-effort and non-blocking: metering MUST NOT break
    /// user-facing storage (§12.2 "fail-open to function") — an unrecordable event is dropped/queued
    /// by the impl, never surfaced to the store path.
    fn record(&self, event: &UsageEvent);
}

/// The self-host default: a no-op meter (§12.2 "self-host default is unlimited/no-op"). A node with no
/// operator bills no one and holds nothing after emitting.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullUsageMeter;

impl NodeUsageMeter for NullUsageMeter {
    fn record(&self, _event: &UsageEvent) {}
}

/// An in-memory counting meter for tests and single-node deployments: it records every event and
/// exposes the running stored-bytes level, so a test can prove the node meters **exactly** the
/// storage it durably accepts. Cloning shares the same underlying log (via [`Rc`]), so a clone handed
/// to a [`crate::Node`] and a clone retained by the caller observe the **same** counter.
#[derive(Debug, Default, Clone)]
pub struct CountingUsageMeter {
    events: Rc<RefCell<Vec<UsageEvent>>>,
}

impl CountingUsageMeter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of usage events recorded so far.
    pub fn count(&self) -> usize {
        self.events.borrow().len()
    }

    /// The current stored-bytes level for `account`: the signed sum of its `Stored − Evicted`
    /// contributions. This is the value a GB-month sample reads (§12.4).
    pub fn stored_bytes(&self, account: &[u8]) -> i64 {
        self.events
            .borrow()
            .iter()
            .filter(|e| e.account() == account)
            .map(UsageEvent::stored_delta)
            .sum()
    }

    /// A snapshot of the recorded events (for audit / assertions).
    pub fn events(&self) -> Vec<UsageEvent> {
        self.events.borrow().clone()
    }
}

impl NodeUsageMeter for CountingUsageMeter {
    fn record(&self, event: &UsageEvent) {
        self.events.borrow_mut().push(event.clone());
    }
}

// ── Reporting the stored-bytes LEVEL into a SUMMING meter (§12.4) ──────────────────────────────

/// A billing-period ordinal: any integer that increases by at least one per billing period and never
/// decreases (months since an epoch, `year * 12 + month`, a period row id — the bridge chooses).
///
/// It is deliberately not a timestamp. [`StoredBytesLevel`] compares ordinals for equality and
/// monotonicity to decide whether a report has already been made, and a wall-clock millisecond value
/// would make every sample a "new period".
pub type PeriodOrdinal = u64;

/// What a bridge should do with a [`StoredBytesLevel::report_for_period`] call. Only
/// [`LevelReport::Report`] means "send an event"; both other variants mean **send nothing**, which is
/// the fail-closed direction — a missed report under-bills once, a duplicated report multiplies the
/// bill for the whole period.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LevelReport {
    /// Send exactly this many bytes to the operator's storage meter, once, for the requested period.
    Report(u64),
    /// This period's level was already reported. **Send nothing** — a summing meter would add the
    /// level a second time and bill twice.
    AlreadyReported { period: PeriodOrdinal },
    /// The period ordinal went backwards (clock skew, a restart reading a stale cursor, two bridges
    /// racing). **Send nothing**: the earlier period may already be closed and re-reporting into it
    /// bills it again.
    PeriodWentBackwards { period: PeriodOrdinal, last_reported: PeriodOrdinal },
}

impl LevelReport {
    /// The bytes to send, or `None` if nothing must be sent. `let Some(b) = r.bytes_to_report()` is
    /// the whole correct usage of this type.
    pub fn bytes_to_report(&self) -> Option<u64> {
        match self {
            LevelReport::Report(bytes) => Some(*bytes),
            LevelReport::AlreadyReported { .. } | LevelReport::PeriodWentBackwards { .. } => None,
        }
    }
}

/// The once-per-period stored-bytes **level** reporter — the guard that makes the
/// [`UsageEvent::Stored`] bridge contract structural instead of remembered.
///
/// A hosted-storage meter is a level, but the operator-side rater that receives events **sums** them
/// (`dmtap_operator::queue::Accumulator` is the reference one). Those two facts are only compatible
/// if exactly one level report lands per billing period. This type enforces that: it folds every
/// [`UsageEvent`] into a running level and hands the level out **at most once per
/// [`PeriodOrdinal`]**, so a bridge that samples nightly emits one report per period rather than
/// thirty and cannot over-bill by 30× through this API.
///
/// It is **per account** by construction — a level is billed to one account, and a stream a bridge
/// consumes may name more than one (each event carries its own [`UsageEvent::account`]).
/// [`Self::observe`] ignores events for any other account and says so in its return value, so a
/// bridge cannot accidentally bill one account for another's bytes.
///
/// It is state a bridge must persist across restarts if it wants the guarantee across restarts —
/// [`Self::last_reported_period`] and [`Self::level`] are the two values to store, and
/// [`Self::resume`] restores them.
///
/// ```
/// use dmtap::usage::{LevelReport, StoredBytesLevel, UsageEvent};
///
/// let mut lvl = StoredBytesLevel::new(b"account-a".to_vec());
/// lvl.observe(&UsageEvent::Stored { account: b"account-a".to_vec(), delta_bytes: 1_000, at: 1 });
/// lvl.observe(&UsageEvent::Evicted { account: b"account-a".to_vec(), delta_bytes: 400, at: 2 });
/// // Another account's bytes are not this account's level.
/// assert!(!lvl.observe(&UsageEvent::Stored { account: b"b".to_vec(), delta_bytes: 9, at: 3 }));
///
/// // One report per period: this is the amount to send to a summing storage meter.
/// assert_eq!(lvl.report_for_period(2026 * 12 + 7), LevelReport::Report(600));
/// // A nightly cron asking again inside the same period gets nothing to send.
/// assert_eq!(lvl.report_for_period(2026 * 12 + 7).bytes_to_report(), None);
/// // The next period reports the level again (bytes held across periods are billed again).
/// assert_eq!(lvl.report_for_period(2026 * 12 + 8), LevelReport::Report(600));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredBytesLevel {
    account: Vec<u8>,
    level: i64,
    last_reported_period: Option<PeriodOrdinal>,
}

impl StoredBytesLevel {
    /// A fresh reporter for one `account`: level `0`, nothing reported yet.
    pub fn new(account: impl Into<Vec<u8>>) -> Self {
        Self { account: account.into(), level: 0, last_reported_period: None }
    }

    /// Restore a persisted reporter so the once-per-period guarantee survives a restart. `level` is
    /// the last observed level; `last_reported_period` is [`Self::last_reported_period`] as stored.
    pub fn resume(
        account: impl Into<Vec<u8>>,
        level: i64,
        last_reported_period: Option<PeriodOrdinal>,
    ) -> Self {
        Self { account: account.into(), level, last_reported_period }
    }

    /// The account this level is billed to.
    pub fn account(&self) -> &[u8] {
        &self.account
    }

    /// Fold one node usage event into the running level (`Stored` adds, `Evicted` subtracts,
    /// `MessageAccepted` is size-neutral — see [`UsageEvent::stored_delta`]).
    ///
    /// Returns whether the event belonged to [`Self::account`] and was folded in. `false` means it
    /// was for a different account and was ignored — a bridge feeding a whole node's stream through
    /// one reporter per account gets the right per-account levels and no cross-billing.
    pub fn observe(&mut self, event: &UsageEvent) -> bool {
        if event.account() != self.account.as_slice() {
            return false;
        }
        self.level += event.stored_delta();
        true
    }

    /// The current signed level. Negative is a bug in the caller's event stream (more evicted than
    /// stored), never something to bill; [`Self::report_for_period`] clamps it to `0`.
    pub fn level(&self) -> i64 {
        self.level
    }

    /// The last period a report was handed out for, if any — persist this alongside [`Self::level`].
    pub fn last_reported_period(&self) -> Option<PeriodOrdinal> {
        self.last_reported_period
    }

    /// The level to report for `period`, **once**. Returns [`LevelReport::Report`] only the first
    /// time it is called with a period strictly greater than the last reported one; every repeat
    /// call inside the same period, and any call for an earlier period, returns a variant whose
    /// [`LevelReport::bytes_to_report`] is `None`.
    pub fn report_for_period(&mut self, period: PeriodOrdinal) -> LevelReport {
        match self.last_reported_period {
            Some(last) if period == last => LevelReport::AlreadyReported { period },
            Some(last) if period < last => {
                LevelReport::PeriodWentBackwards { period, last_reported: last }
            }
            _ => {
                self.last_reported_period = Some(period);
                LevelReport::Report(self.level.max(0) as u64)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlimited_admits_everything_with_no_bound() {
        let q = UnlimitedStorage;
        let d = q.admit(b"acct", u64::MAX);
        assert!(d.is_allowed());
        assert_eq!(d.remaining_bytes(), None, "unlimited exposes no finite allowance");
    }

    #[test]
    fn null_meter_is_a_noop() {
        // A no-op meter simply must not panic; it records nothing observable.
        NullUsageMeter.record(&UsageEvent::Stored {
            account: b"acct".to_vec(),
            delta_bytes: 42,
            at: 1_700_000_000_000,
        });
    }

    #[test]
    fn counting_meter_tracks_signed_stored_level_per_account() {
        let m = CountingUsageMeter::new();
        let a = b"account-a".to_vec();
        let b = b"account-b".to_vec();

        m.record(&UsageEvent::Stored { account: a.clone(), delta_bytes: 1000, at: 1 });
        m.record(&UsageEvent::Stored { account: a.clone(), delta_bytes: 500, at: 2 });
        m.record(&UsageEvent::MessageAccepted { account: a.clone(), at: 3 }); // size-neutral
        m.record(&UsageEvent::Evicted { account: a.clone(), delta_bytes: 200, at: 4 });
        m.record(&UsageEvent::Stored { account: b.clone(), delta_bytes: 7, at: 5 });

        assert_eq!(m.count(), 5);
        assert_eq!(m.stored_bytes(&a), 1000 + 500 - 200, "signed level, message-count is neutral");
        assert_eq!(m.stored_bytes(&b), 7, "levels are per-account");
    }

    /// The whole point of [`StoredBytesLevel`]: a bridge sampling nightly must still emit ONE
    /// report per period. Sending 30 reports of the same level to a summing meter bills 30×.
    #[test]
    fn nightly_sampling_yields_exactly_one_report_per_period() {
        let mut lvl = StoredBytesLevel::new(b"acct".to_vec());
        lvl.observe(&UsageEvent::Stored { account: b"acct".to_vec(), delta_bytes: 10_000, at: 1 });

        let period = 2026 * 12 + 7;
        let mut reported: Vec<u64> = Vec::new();
        for _night in 0..30 {
            if let Some(bytes) = lvl.report_for_period(period).bytes_to_report() {
                reported.push(bytes);
            }
        }
        assert_eq!(
            reported,
            vec![10_000],
            "30 nightly samples inside one period must produce ONE report; a summing meter would \
             otherwise be handed the level 30 times and bill 30x"
        );
    }

    #[test]
    fn a_repeat_call_in_the_same_period_reports_nothing() {
        let mut lvl = StoredBytesLevel::new(b"acct".to_vec());
        lvl.observe(&UsageEvent::Stored { account: b"acct".to_vec(), delta_bytes: 512, at: 1 });
        assert_eq!(lvl.report_for_period(10), LevelReport::Report(512));
        assert_eq!(lvl.report_for_period(10), LevelReport::AlreadyReported { period: 10 });
        assert_eq!(lvl.report_for_period(10).bytes_to_report(), None);
    }

    #[test]
    fn each_new_period_reports_the_level_again() {
        let mut lvl = StoredBytesLevel::new(b"acct".to_vec());
        lvl.observe(&UsageEvent::Stored { account: b"acct".to_vec(), delta_bytes: 1_000, at: 1 });
        assert_eq!(lvl.report_for_period(1), LevelReport::Report(1_000));
        // Bytes held across a period boundary are billed again — that is what a level meter means.
        assert_eq!(lvl.report_for_period(2), LevelReport::Report(1_000));
        // A delta inside the new period moves the level the next report carries.
        lvl.observe(&UsageEvent::Evicted { account: b"acct".to_vec(), delta_bytes: 400, at: 2 });
        assert_eq!(lvl.report_for_period(3), LevelReport::Report(600));
    }

    #[test]
    fn a_backwards_period_reports_nothing_and_does_not_move_the_cursor() {
        let mut lvl = StoredBytesLevel::new(b"acct".to_vec());
        lvl.observe(&UsageEvent::Stored { account: b"acct".to_vec(), delta_bytes: 77, at: 1 });
        assert_eq!(lvl.report_for_period(5), LevelReport::Report(77));
        assert_eq!(
            lvl.report_for_period(4),
            LevelReport::PeriodWentBackwards { period: 4, last_reported: 5 },
            "clock skew or a stale cursor must not re-bill a closed period"
        );
        assert_eq!(lvl.last_reported_period(), Some(5), "a refused report leaves the cursor alone");
        assert_eq!(lvl.report_for_period(6), LevelReport::Report(77), "and does not wedge it");
    }

    #[test]
    fn resume_carries_the_guarantee_across_a_restart() {
        let mut before = StoredBytesLevel::new(b"acct".to_vec());
        before.observe(&UsageEvent::Stored { account: b"acct".to_vec(), delta_bytes: 2_048, at: 1 });
        assert_eq!(before.report_for_period(9), LevelReport::Report(2_048));

        // A bridge that persists (level, last_reported_period) and restarts mid-period must not
        // report period 9 a second time.
        let mut after =
            StoredBytesLevel::resume(b"acct".to_vec(), before.level(), before.last_reported_period());
        assert_eq!(after.report_for_period(9).bytes_to_report(), None);
        assert_eq!(after.report_for_period(10), LevelReport::Report(2_048));
    }

    #[test]
    fn a_negative_level_reports_zero_rather_than_a_huge_number() {
        let mut lvl = StoredBytesLevel::new(b"acct".to_vec());
        // More evicted than stored is a caller bug; it must not become u64::MAX-ish on the bill.
        lvl.observe(&UsageEvent::Evicted { account: b"acct".to_vec(), delta_bytes: 5, at: 1 });
        assert_eq!(lvl.level(), -5);
        assert_eq!(lvl.report_for_period(1), LevelReport::Report(0));
    }

    #[test]
    fn a_reporter_ignores_another_accounts_events() {
        let mut a = StoredBytesLevel::new(b"account-a".to_vec());
        let mut b = StoredBytesLevel::new(b"account-b".to_vec());
        let stream = [
            UsageEvent::Stored { account: b"account-a".to_vec(), delta_bytes: 100, at: 1 },
            UsageEvent::Stored { account: b"account-b".to_vec(), delta_bytes: 7, at: 2 },
            UsageEvent::Evicted { account: b"account-a".to_vec(), delta_bytes: 40, at: 3 },
        ];
        for e in &stream {
            a.observe(e);
            b.observe(e);
        }
        assert_eq!(a.report_for_period(1), LevelReport::Report(60));
        assert_eq!(b.report_for_period(1), LevelReport::Report(7), "no cross-account billing");
        assert!(!b.observe(&stream[0]), "a foreign event is reported as ignored, not folded");
    }

    #[test]
    fn observing_folds_exactly_the_signed_stored_delta() {
        let mut lvl = StoredBytesLevel::new(b"acct".to_vec());
        for e in [
            UsageEvent::Stored { account: b"acct".to_vec(), delta_bytes: 100, at: 1 },
            UsageEvent::MessageAccepted { account: b"acct".to_vec(), at: 2 },
            UsageEvent::Evicted { account: b"acct".to_vec(), delta_bytes: 30, at: 3 },
        ] {
            lvl.observe(&e);
        }
        assert_eq!(lvl.level(), 70, "message counts are size-neutral in the storage level");
    }

    #[test]
    fn counting_meter_clone_shares_the_log() {
        let m = CountingUsageMeter::new();
        let handed_off = m.clone();
        handed_off.record(&UsageEvent::Stored {
            account: b"acct".to_vec(),
            delta_bytes: 9,
            at: 1,
        });
        assert_eq!(m.count(), 1, "a clone and the original observe the same underlying log");
    }
}
