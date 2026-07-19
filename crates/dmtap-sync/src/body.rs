//! [`SnapshotBody`] — what a fast-joining replica actually transfers and adopts (`SYNC.md` §6.1.2,
//! frozen as `SYNC-SNAP-03`), plus §6.2's body-retention obligation.
//!
//! # The body is a set of ops, not a state document
//!
//! ```cddl
//! SnapshotBody = [ * ( COSE_Sign1(SyncOp) / SyncFrame ) ]   ; framed per §5.2's op-framing rule
//! ```
//!
//! It is the **minimal set of canonical, individually-signed ops whose fold equals the snapshot's
//! observable state**, served by `GET /sync/state/<root>` and optionally inlined at `FastJoin` key
//! `3`. A replica adopts it by ingesting every member **through the ordinary op path of §4** — same
//! signature check, same `ext-value` validation, same CRDT apply, same `op-id` dedup. There is no
//! second ingest path here, and §6.1.2 is explicit that an implementation is not required to have
//! one.
//!
//! # Why `ObservableState` cannot be the body (§14 C-09)
//!
//! [`ObservableState`](crate::snapshot::ObservableState) is the *observable projection* — which is
//! exactly what makes `root` a clean equality object and exactly what makes it useless as a base
//! state. §6.1.1 drops, per kind, the one field the **next** merge needs:
//!
//! | Kind | Dropped | What breaks |
//! |---|---|---|
//! | §4.4 LWW | the winning cell's HLC | nothing to compare a later op against |
//! | §4.5 `death` | the certificate's HLC | §4.5's strictly-greater revival test is unevaluable |
//! | §4.3 OR-Set | the add-tags | a later `set-remove` cancels nothing; add-wins ⇒ add-always |
//! | §4.7 RGA | element ids | every post-`covers` insert strands in the readiness buffer |
//! | §4.6 PN | per-`op-id` deltas | a below-`covers` op arriving late is double-counted |
//!
//! The LWW case is the sharpest, and it is the one `SYNC-SNAP-03` freezes: `covers` bounds each
//! author's **own stream**, while the §3 HLC is a total order **across authors**. So an op that is
//! genuinely after `covers` can still sit *below* the incumbent. The vector's demo is post-`covers`
//! op `(W,3,B)` against incumbent `(W,4,A)`: a replica that folded the body keeps `"n"`, a replica
//! that adopted the projection has the value but not its HLC, applies the write, and lands on `"q"`
//! — **a different root, permanently, with no error raised on either side.**
//!
//! # Fold-then-recompute
//!
//! `Snapshot.root` still commits to `det_cbor(ObservableState)` (§6.1.1 is unchanged, every frozen
//! byte stands). So a body is verified by folding it and **recomputing** that hash, never by
//! hashing the received bytes:
//!
//! ```text
//!   ingest every op in SnapshotBody  →  derive ObservableState per §6.1.1  →  hash  ≟  Snapshot.root
//! ```
//!
//! That is strictly stronger than hashing an opaque blob, because it proves the ops actually
//! *produce* the committed state rather than only that someone shipped the bytes they promised. It
//! also shrinks the §6.1 trusted-checkpoint residual: every member is independently COSE-signed, so
//! a malicious signer can **omit** ops (detectable as a vector that never advances) but cannot
//! **forge** one. A mismatch is `ERR_SYNC_SNAPSHOT_ROOT_MISMATCH` (`0x0A09`) and the body is
//! discarded **whole** — which is why [`SnapshotBody::verify_against_root`] folds into a
//! *provisional* state it returns only on success, leaving the caller's live replica untouched.

use std::collections::{BTreeMap, BTreeSet};

use dmtap_core::id::ContentId;

use crate::cose::{self, CoseSign1};
use crate::detcbor::{decode, encode, SVal};
use crate::error::SyncError;
use crate::snapshot::ObservableState;
use crate::state::SyncState;
use crate::wire::{
    Hlc, SyncOp, OP_COUNTER, OP_DEATH, OP_LWW_SET, OP_SEQ_INSERT, OP_SEQ_REMOVE, OP_SET_ADD,
    OP_TREE_MOVE,
};

/// The §6.1.2 snapshot body: the compacted, individually-signed op set that folds to the
/// snapshot's observable state.
///
/// Members are `COSE_Sign1(SyncOp)` envelopes. §6.1.2 also admits `SyncFrame` (§4.1's OPTIONAL
/// amortized-signature batching, negotiated by `sync-1` sub-tokens); this crate does not implement
/// frames **anywhere** yet — not in `pull`, not in `ops`, not here — so a frame in a body is
/// refused rather than half-understood. When frames land, they land in one place for all three
/// paths, because they share §5.2's op-framing rule.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SnapshotBody {
    members: Vec<CoseSign1>,
}

impl SnapshotBody {
    /// A body over already-verified envelopes.
    pub fn new(members: Vec<CoseSign1>) -> Self {
        SnapshotBody { members }
    }

    /// The envelopes this body carries.
    pub fn members(&self) -> &[CoseSign1] {
        &self.members
    }

    /// How many ops the body carries.
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Whether the body is empty — legal: an empty namespace's body folds to the empty state,
    /// whose root is the frozen `0x86 80 80 80 80 80 80` hash.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// The canonical wire encoding: an array whose members are each embedded as a CBOR **item**,
    /// never `bstr`-wrapped — §5.2's op-framing rule, which §5.2.1 states governs "the ops *inside*
    /// a `SnapshotBody`, since it is an ops collection like any other" (correction C-06 is the same
    /// rule for `PullResponse` key 1).
    pub fn det_cbor(&self) -> Vec<u8> {
        let items: Vec<SVal> = self
            .members
            .iter()
            .map(|m| decode(&m.to_bytes()).expect("own COSE_Sign1 encoding"))
            .collect();
        encode(&SVal::Array(items))
    }

    /// Decode a body from wire bytes, fail-closed on any member that is not the frozen
    /// `COSE_Sign1` four-element array (`0x0A02`) and on a body that is not an array at all
    /// (`0x0A03`).
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, SyncError> {
        let cv = decode(bytes).map_err(|_| SyncError::OpInvalid)?;
        let SVal::Array(items) = cv else { return Err(SyncError::OpInvalid) };
        let mut members = Vec::with_capacity(items.len());
        for item in items {
            // A `bstr`-wrapped member is the C-06 non-conformant framing: refused, not unwrapped.
            members.push(CoseSign1::from_bytes(&encode(&item))?);
        }
        Ok(SnapshotBody { members })
    }

    /// **The fold.** Ingest every member through the ordinary §4 op path — COSE signature
    /// (`0x0A02`), `ext-value` and CRDT validation (`0x0A03`), `op-id` dedup — into a fresh
    /// provisional [`SyncState`].
    ///
    /// `ns`, when given, is the snapshot's namespace: a member outside it is `0x0A0A`. A body is
    /// scoped to exactly one namespace's state, so an op from another one could only ever be an
    /// attempt to write where the adopting replica did not subscribe (§7).
    pub fn fold(&self, ns: Option<&str>, receiver_now_ms: u64) -> Result<SyncState, SyncError> {
        let mut state = SyncState::new();
        for member in &self.members {
            let op = cose::verify_op(member)?;
            if let Some(ns) = ns {
                if op.ns != ns {
                    return Err(SyncError::NsLeak);
                }
            }
            state.ingest(&op, receiver_now_ms)?;
        }
        Ok(state)
    }

    /// **Fold-then-recompute** (§6.1.2 / §5.2.1 step 3): fold this body into a provisional state,
    /// derive [`ObservableState`] per §6.1.1, hash it under the snapshot-state DS-tag, and require
    /// equality with `root`.
    ///
    /// On mismatch: `ERR_SYNC_SNAPSHOT_ROOT_MISMATCH` (`0x0A09`), and **nothing** is returned — the
    /// body is discarded whole, which is only meaningful because the fold happened in a provisional
    /// state the caller never saw.
    ///
    /// This is deliberately *not* `hash(received_bytes) == root`. That check would prove only that
    /// the sender shipped the bytes it promised; this one proves the ops **produce** the committed
    /// state.
    pub fn verify_against_root(
        &self,
        root: &ContentId,
        ns: Option<&str>,
        receiver_now_ms: u64,
    ) -> Result<AdoptedBody, SyncError> {
        let state = self.fold(ns, receiver_now_ms)?;
        let observable = ObservableState::of(&state);
        if observable.root().as_bytes() != root.as_bytes() {
            return Err(SyncError::SnapshotRootMismatch);
        }
        Ok(AdoptedBody { state, observable })
    }

    /// **§6.2 body retention / compaction.** Build the body a truncating replica must be able to
    /// serve, by selecting from `journal` exactly the ops [`retention_set`] names.
    ///
    /// Returns `Err(SnapshotRootMismatch)` if the folded result does not reproduce `state`'s own
    /// root — the fail-closed half of §6.2's "a replica that cannot satisfy this retention set MUST
    /// refuse the truncation **whole** rather than perform it partially". The check is not
    /// decorative: it is the same fold-then-recompute the *receiver* will run, executed here where
    /// the ops are still enumerable, so a body can never be published that its own author could not
    /// verify.
    pub fn compact<'a, I>(
        state: &SyncState,
        journal: I,
        receiver_now_ms: u64,
    ) -> Result<SnapshotBody, SyncError>
    where
        I: IntoIterator<Item = (&'a SyncOp, &'a [u8])>,
    {
        let entries: Vec<(&SyncOp, &[u8])> = journal.into_iter().collect();
        let ops: Vec<&SyncOp> = entries.iter().map(|(op, _)| *op).collect();
        let keep = retention_set(state, &ops);
        let mut selected: Vec<(Hlc, Vec<u8>, CoseSign1)> = Vec::new();
        for (op, cose_bytes) in &entries {
            let id = op.op_id().as_bytes().to_vec();
            if !keep.contains(&id) {
                continue;
            }
            selected.push((op.hlc.clone(), id, CoseSign1::from_bytes(cose_bytes)?));
        }
        // Deterministic member order: `(hlc, op-id)`. The root commits to the FOLD, not to these
        // bytes, so ordering is not a correctness requirement — but two replicas compacting the
        // same state should still produce the same bytes, so the body dedupes in a content-
        // addressed store instead of forking per replica.
        selected.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        let body = SnapshotBody::new(selected.into_iter().map(|(_, _, c)| c).collect());
        body.verify_against_root(&ObservableState::of(state).root(), None, receiver_now_ms)?;
        Ok(body)
    }
}

/// The result of a successful [`SnapshotBody::verify_against_root`]: the provisional state the
/// caller may now promote (§5.2.1 step 4), and the observable projection that matched `root`.
///
/// Adoption is a **merge**, not a replace: the state is built from ops, so a caller that already
/// holds some of them dedupes by `op-id`, and re-adopting the same body is a no-op.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdoptedBody {
    /// The folded replica state — ops, HLCs, add-tags, element ids and all.
    pub state: SyncState,
    /// Its §6.1.1 projection, which hashed to the snapshot's `root`.
    pub observable: ObservableState,
}

/// **§6.2's body-retention obligation**, as a predicate over a journal: which `op-id`s a truncating
/// replica MUST keep, because the §6.1.2 body needs them.
///
/// Truncation removes **superseded** history, never **live** history. Retained:
///
/// * the winning `lww-set` per live `(target, field)`;
/// * the winning `death` per object — see the note below, this is wider than §6.2's wording;
/// * every uncancelled `set-add` for a present OR-Set element (§6.2 requires "at least one"; all of
///   them is the simpler superset and folds identically, since add-wins is idempotent over tags);
/// * the winning `tree-move` per node still in the tree;
/// * every live RGA atom's `seq-insert`, **plus, transitively, the `seq-insert` of any tombstoned
///   atom that is the left-origin of a retained atom** — §6.2's one explicitly non-obvious case:
///   dropping a tombstoned origin strands its successors in the causal-readiness buffer of every
///   replica that fast-joins from the body, which presents as a sequence that silently never
///   converges rather than as an error;
/// * every `counter` op (see the note below).
///
/// # Two places this is wider than §6.2's list, and why
///
/// Both are *entailed* by fold-then-recompute — a body that omitted them would fail
/// [`SnapshotBody::compact`]'s own check — but neither is spelled out in §6.2, so they are called
/// out here rather than buried:
///
/// 1. **`death` cells that are `Live`, not just deleted.** §6.2 says "the winning `death` per
///    *deleted* object". But a `Live` write at `(W,10)` that revived an object dominates any later
///    *concurrent* certificate below it: drop it, and a post-`covers` `death` at `(W,7)` deletes an
///    object a full replayer keeps alive. The projection cannot see the difference — §6.1.1 lists
///    only deleted objects — which is precisely why the omission is silent. The winning `death`-kind
///    op is retained per object, live or deleted.
/// 2. **`seq-remove` for a retained tombstoned origin.** Rule 5 above retains a tombstoned atom's
///    *insert*; its **tombstone** must be retained with it, or the fold shows the atom as live and
///    the recomputed root differs. §6.2 states the insert half and not this half.
///
/// And one place the list is simply silent: **PN-counter ops**. §6.1.2's own table says the
/// counter's `op-id`-keyed deltas are what make §4.6's merge idempotent, yet §6.2's retention
/// bullets never mention counters. No counter op is ever *superseded* — each delta is live history
/// — so every one is retained here.
pub fn retention_set(state: &SyncState, ops: &[&SyncOp]) -> BTreeSet<Vec<u8>> {
    // --- the winners, addressed the way the state stores them -----------------------------------
    let lww_winners: BTreeSet<(String, String, Hlc)> = state
        .lww
        .cells()
        .map(|((t, f), (hlc, _))| (t.clone(), f.clone(), hlc.clone()))
        .collect();

    // Every object with a death cell, live or deleted (see note 1 above).
    let mut death_winners: BTreeSet<(String, Hlc)> = BTreeSet::new();
    for op in ops {
        if op.kind == OP_DEATH {
            if let Some(hlc) = state.deaths.certificate_hlc(&op.target) {
                death_winners.insert((op.target.clone(), hlc.clone()));
            }
        }
    }

    // Surviving add-tags of the observably-present members (death-domination already applied).
    let mut surviving_adds: BTreeSet<(String, Hlc)> = BTreeSet::new();
    for (target, element) in state.present_members() {
        for tag in state.orset.surviving_tags(&target, &element) {
            surviving_adds.insert((target.clone(), tag.hlc));
        }
    }

    // The last applied move per node — the one that produced the surviving edge.
    let replay = state.tree.replay();
    let mut tree_winners: BTreeMap<String, Hlc> = BTreeMap::new();
    for (hlc, node) in &replay.applied {
        if replay.edges.contains_key(node) {
            tree_winners.insert(node.clone(), hlc.clone());
        }
    }

    // RGA: live atoms, then the transitive left-origin closure through tombstoned atoms.
    let mut rga_keep: BTreeMap<String, BTreeSet<Hlc>> = BTreeMap::new();
    for (target, seq) in &state.sequences {
        let mut keep: BTreeSet<Hlc> = BTreeSet::new();
        let mut frontier: Vec<Hlc> =
            seq.atom_ids().into_iter().filter(|id| !seq.is_tombstoned(id)).collect();
        while let Some(id) = frontier.pop() {
            if !keep.insert(id.clone()) {
                continue;
            }
            // The origin of a retained atom is retained too — even when tombstoned. This is the
            // transitive rule; it terminates because `keep` is monotone and the atom set is finite.
            if let Some(origin) = seq.atom_origin(&id) {
                frontier.push(origin.clone());
            }
        }
        rga_keep.insert(target.clone(), keep);
    }

    // --- classify the journal --------------------------------------------------------------------
    let mut out = BTreeSet::new();
    for op in ops {
        let retained = match op.kind {
            OP_LWW_SET => op
                .field
                .as_ref()
                .is_some_and(|f| lww_winners.contains(&(op.target.clone(), f.clone(), op.hlc.clone()))),
            OP_DEATH => death_winners.contains(&(op.target.clone(), op.hlc.clone())),
            OP_SET_ADD => surviving_adds.contains(&(op.target.clone(), op.hlc.clone())),
            // A `set-remove` is never retained: the adds it cancelled are dropped with it, and an
            // add-tag that survives it was never its business. §6.2's first compaction bullet says
            // exactly this — a tag present in both adds and tombstones is dropped *with* its
            // tombstone.
            OP_COUNTER => true,
            OP_TREE_MOVE => tree_winners.get(&op.target).is_some_and(|h| *h == op.hlc),
            OP_SEQ_INSERT => {
                rga_keep.get(&op.target).is_some_and(|keep| keep.contains(&op.hlc))
            }
            OP_SEQ_REMOVE => op
                .reference
                .as_ref()
                .and_then(|r| r.hlc.as_ref())
                .is_some_and(|id| {
                    // Retained iff the atom it tombstones is itself retained (as an origin): the
                    // fold must show that atom dead, or the recomputed root differs (note 2).
                    rga_keep.get(&op.target).is_some_and(|keep| keep.contains(id))
                }),
            _ => false,
        };
        if retained {
            out.insert(op.op_id().as_bytes().to_vec());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::state_root;
    use crate::wire::{AddTag, OpRef, OP_SET_REMOVE};
    use dmtap_core::identity::IdentityKey;

    const NOW: u64 = 1_700_000_900_000;

    fn key(seed: u8) -> IdentityKey {
        IdentityKey::from_seed(&[seed; 32])
    }

    fn hlc(counter: u32, sk: &IdentityKey) -> Hlc {
        Hlc { wall: 1_700_000_100_000, counter, author: sk.public() }
    }

    fn op(kind: u8, target: &str, sk: &IdentityKey, counter: u32) -> SyncOp {
        SyncOp {
            kind,
            ns: String::new(),
            target: target.into(),
            field: None,
            value: None,
            hlc: hlc(counter, sk),
            observed: None,
            reference: None,
        }
    }

    fn signed(sk: &IdentityKey, op: &SyncOp) -> (SyncOp, Vec<u8>) {
        (op.clone(), cose::sign_op(sk, op).expect("sign").to_bytes())
    }

    /// `SYNC-SNAP-03`'s ordering demo, end to end: the body's incumbent is `(W,4,A)`; a
    /// post-`covers` op at `(W,3,B)` is genuinely after `covers` (which does not name `B` at all)
    /// and still LOSES. A projection-adopter would take it.
    #[test]
    fn a_post_covers_op_below_the_incumbent_loses_and_the_roots_agree() {
        let a = key(0xcc);
        let b = key(0x11);
        let mut incumbent = op(OP_LWW_SET, "doc1", &a, 4);
        incumbent.field = Some("title".into());
        incumbent.value = Some(SVal::Text("n".into()));
        let (incumbent, cose_bytes) = signed(&a, &incumbent);

        let body = SnapshotBody::new(vec![CoseSign1::from_bytes(&cose_bytes).unwrap()]);
        let mut folded = body.fold(Some(""), NOW).expect("fold");
        let root = ObservableState::of(&folded).root();

        // The post-`covers` write: LOWER counter, DIFFERENT author.
        let mut later = op(OP_LWW_SET, "doc1", &b, 3);
        later.field = Some("title".into());
        later.value = Some(SVal::Text("q".into()));
        assert!(later.hlc < incumbent.hlc, "the vector's whole point: after `covers`, below the HLC");
        folded.ingest(&later, NOW).unwrap();

        assert_eq!(
            folded.lww.get("doc1", "title"),
            Some(&SVal::Text("n".into())),
            "a body-folding replica KEEPS the incumbent"
        );
        assert_eq!(
            state_root(&folded).as_bytes(),
            root.as_bytes(),
            "and its root is unchanged, because the losing op changed nothing observable"
        );

        // The non-conformant path, for contrast: adopt the PROJECTION (no incumbent HLC), then
        // apply the same op. It wins, because there is nothing to be less than.
        let mut projection = SyncState::new();
        projection.ingest(&later, NOW).unwrap();
        assert_eq!(projection.lww.get("doc1", "title"), Some(&SVal::Text("q".into())));
        assert_ne!(
            state_root(&projection).as_bytes(),
            root.as_bytes(),
            "silent, permanent divergence — the failure C-09 exists to rule out"
        );
    }

    #[test]
    fn body_round_trips_and_folds_to_its_root() {
        let a = key(0xcc);
        let mut set = op(OP_LWW_SET, "doc1", &a, 4);
        set.field = Some("title".into());
        set.value = Some(SVal::Text("n".into()));
        let (_, bytes) = signed(&a, &set);
        let body = SnapshotBody::new(vec![CoseSign1::from_bytes(&bytes).unwrap()]);
        let wire = body.det_cbor();
        assert_eq!(SnapshotBody::from_det_cbor(&wire).unwrap(), body);
        let state = body.fold(None, NOW).unwrap();
        assert!(body.verify_against_root(&state_root(&state), None, NOW).is_ok());
        assert_eq!(
            body.verify_against_root(&ContentId(vec![0u8; 33]), None, NOW),
            Err(SyncError::SnapshotRootMismatch)
        );
    }

    /// A `bstr`-wrapped member is the C-06 non-conformant framing and is refused, not unwrapped.
    #[test]
    fn bstr_wrapped_members_are_refused() {
        let a = key(0xcc);
        let mut set = op(OP_LWW_SET, "doc1", &a, 4);
        set.field = Some("title".into());
        set.value = Some(SVal::Text("n".into()));
        let (_, bytes) = signed(&a, &set);
        let wrong = encode(&SVal::Array(vec![SVal::Bytes(bytes)]));
        assert_eq!(SnapshotBody::from_det_cbor(&wrong), Err(SyncError::OpSigInvalid));
    }

    /// The retention set, exercised across every kind at once, and proved by the only test that
    /// matters: the compacted body folds back to the same root as the full journal.
    #[test]
    fn compaction_retains_exactly_what_the_fold_needs() {
        let a = key(0xcc);
        let b = key(0x11);
        let mut journal: Vec<(SyncOp, Vec<u8>)> = Vec::new();

        // LWW: a superseded write and its winner.
        for (counter, text) in [(1u32, "old"), (4, "new")] {
            let mut o = op(OP_LWW_SET, "doc1", &a, counter);
            o.field = Some("title".into());
            o.value = Some(SVal::Text(text.into()));
            journal.push(signed(&a, &o));
        }
        // OR-Set: one surviving add, one add cancelled by a remove.
        let mut add_live = op(OP_SET_ADD, "tags", &a, 10);
        add_live.value = Some(SVal::Text("keep".into()));
        journal.push(signed(&a, &add_live));
        let mut add_dead = op(OP_SET_ADD, "tags", &a, 11);
        add_dead.value = Some(SVal::Text("drop".into()));
        journal.push(signed(&a, &add_dead));
        let mut rm = op(OP_SET_REMOVE, "tags", &a, 12);
        rm.value = Some(SVal::Text("drop".into()));
        rm.observed = Some(vec![AddTag { author: a.public(), hlc: add_dead.hlc.clone() }]);
        journal.push(signed(&a, &rm));
        // Death: a certificate on a different object.
        let mut death = op(OP_DEATH, "rec1", &b, 3);
        death.field = Some("redact".into());
        journal.push(signed(&b, &death));
        // Counter: two deltas, neither superseded.
        for (counter, delta) in [(20u32, 5i64), (21, -2)] {
            let mut o = op(OP_COUNTER, "stock1", &a, counter);
            o.field = Some("qty".into());
            o.value = Some(SVal::int(delta));
            journal.push(signed(&a, &o));
        }
        // RGA: head atom, a second atom, the second is tombstoned, and a THIRD inserted after the
        // tombstoned one — so the tombstoned atom is a live atom's left-origin (the transitive case).
        let mut head = op(OP_SEQ_INSERT, "line1", &a, 30);
        head.value = Some(SVal::Text("h".into()));
        journal.push(signed(&a, &head));
        let mut mid = op(OP_SEQ_INSERT, "line1", &a, 31);
        mid.value = Some(SVal::Text("m".into()));
        mid.reference = Some(OpRef { target: "line1".into(), hlc: Some(head.hlc.clone()) });
        journal.push(signed(&a, &mid));
        let mut tail = op(OP_SEQ_INSERT, "line1", &a, 32);
        tail.value = Some(SVal::Text("t".into()));
        tail.reference = Some(OpRef { target: "line1".into(), hlc: Some(mid.hlc.clone()) });
        journal.push(signed(&a, &tail));
        let mut kill_mid = op(OP_SEQ_REMOVE, "line1", &a, 33);
        kill_mid.reference = Some(OpRef { target: "line1".into(), hlc: Some(mid.hlc.clone()) });
        journal.push(signed(&a, &kill_mid));
        // Tree: a superseded move and its winner.
        for (counter, parent) in [(40u32, "root-a"), (41, "root-b")] {
            let mut o = op(OP_TREE_MOVE, "node1", &a, counter);
            o.field = Some("k".into());
            o.reference = Some(OpRef { target: parent.into(), hlc: None });
            journal.push(signed(&a, &o));
        }

        let mut full = SyncState::new();
        for (o, _) in &journal {
            full.ingest(o, NOW).unwrap();
        }
        let body = SnapshotBody::compact(
            &full,
            journal.iter().map(|(o, c)| (o, c.as_slice())),
            NOW,
        )
        .expect("compaction must fold back to the same root");

        // It is genuinely a COMPACTION — the superseded LWW write, the cancelled add and its
        // remove are gone.
        assert!(body.len() < journal.len(), "nothing was dropped: {} of {}", body.len(), journal.len());
        // And the tombstoned-but-load-bearing RGA atom survived, with its tombstone.
        let kept: BTreeSet<Vec<u8>> = body
            .members()
            .iter()
            .map(|m| cose::verify_op(m).unwrap().op_id().as_bytes().to_vec())
            .collect();
        assert!(kept.contains(&mid.op_id().as_bytes().to_vec()), "tombstoned left-origin dropped");
        assert!(kept.contains(&kill_mid.op_id().as_bytes().to_vec()), "its tombstone dropped");
        assert!(!kept.contains(&rm.op_id().as_bytes().to_vec()), "a cancelling remove was retained");

        // The proof: fold-then-recompute against the full journal's root.
        let adopted = body
            .verify_against_root(&state_root(&full), Some(""), NOW)
            .expect("the compacted body must reproduce the root");
        assert_eq!(adopted.observable.det_cbor(), ObservableState::of(&full).det_cbor());

        // And the sequence still converges for a replica that fast-joined from the body: an insert
        // whose origin is the tombstoned atom resolves rather than stranding.
        let mut joined = adopted.state;
        let mut after = op(OP_SEQ_INSERT, "line1", &b, 50);
        after.value = Some(SVal::Text("z".into()));
        after.reference = Some(OpRef { target: "line1".into(), hlc: Some(mid.hlc.clone()) });
        joined.ingest(&after, NOW).unwrap();
        assert!(
            joined.sequences["line1"].has(&after.hlc),
            "the post-join insert stranded in the readiness buffer — the transitive rule failed"
        );
    }

    /// Note 1 in [`retention_set`]: a `Live` cell that revived an object is retained even though
    /// the projection cannot see it, because dropping it lets a later lower-HLC certificate win.
    #[test]
    fn a_winning_live_cell_is_retained_even_though_it_is_invisible() {
        let a = key(0xcc);
        let b = key(0x11);
        let mut death = op(OP_DEATH, "rec1", &a, 3);
        death.field = Some("redact".into());
        let mut revive = op(OP_DEATH, "rec1", &a, 10);
        revive.field = Some(crate::wire::DEATH_LIVE.into());
        let journal = vec![signed(&a, &death), signed(&a, &revive)];

        let mut full = SyncState::new();
        for (o, _) in &journal {
            full.ingest(o, NOW).unwrap();
        }
        assert!(!full.deaths.is_deleted("rec1"), "revived");
        let body =
            SnapshotBody::compact(&full, journal.iter().map(|(o, c)| (o, c.as_slice())), NOW)
                .unwrap();
        assert_eq!(body.len(), 1, "only the winning cell is retained");

        // A post-`covers` certificate BELOW the surviving `Live` write must not delete the object.
        let mut late = op(OP_DEATH, "rec1", &b, 7);
        late.field = Some("redact".into());
        let mut joined = body.fold(Some(""), NOW).unwrap();
        joined.ingest(&late, NOW).unwrap();
        assert!(
            !joined.deaths.is_deleted("rec1"),
            "the Live cell was dropped and a lower certificate deleted a live object"
        );
    }
}
