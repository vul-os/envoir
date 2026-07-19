//! Signed snapshots and the canonical observable state (`SYNC.md` §6.1 / §6.1.1, frozen as
//! `SYNC-SNAP-01`/`SYNC-SNAP-02`).
//!
//! [`ObservableState`] is the single deterministic-CBOR value a replica hashes to produce
//! `Snapshot.root`: a **fixed six-element positional array**, one section per CRDT type in
//! `kind`-ascending order. Positional sections — not a keyed map — are used deliberately: they
//! match the §5.6 reference and remove any map-key-scheme choice as a source of divergence.
//!
//! Only **observable** state appears. OR-Set add-tags and tombstones, PN-counter per-author `P`/`N`
//! maps, RGA element ids and tombstones, `Live` death cells, and superseded LWW cells are all
//! internal. That is exactly why fast-join works: adopting a snapshot and applying the
//! post-`covers` ops yields byte-identical `ObservableState` to a full replay, because the two
//! paths can differ only in bookkeeping the projection never serializes.

use crate::detcbor::{encode, SVal};
use crate::error::SyncError;
use crate::state::{SyncState, VersionVector};
use crate::wire::{ds_hash, Hlc, DS_SNAPSHOT, DS_SNAPSHOT_STATE, TREE_ROOT};
use dmtap_core::id::ContentId;
use dmtap_core::identity::{verify_domain, IdentityKey};

/// The canonical observable state of one namespace (§6.1.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObservableState {
    /// §4.3 — one entry per **present** `(target, element)`.
    pub orset: Vec<(String, SVal)>,
    /// §4.4 — the winning cell per `(target, field)`.
    pub lww: Vec<(String, String, SVal)>,
    /// §4.6 — `Σ_a P[a] − Σ_a N[a]` per `(target, field)`.
    pub pn: Vec<(String, String, i128)>,
    /// §4.5 — one entry per **deleted** object (`Live` contributes nothing).
    pub death: Vec<(String, String)>,
    /// §4.7 — per RGA target, the live atom values **in sequence order** (never re-sorted).
    pub rga: Vec<(String, Vec<SVal>)>,
    /// §4.8 — each non-root node's winning `(parent, ordering_key)` after the acyclic replay.
    pub tree: Vec<(String, String, String)>,
}

/// Sort a section ascending by the deterministic-CBOR encoding of each entry — a byte comparison,
/// so the ordering is implementation-independent (the same rule §5.6 already uses).
fn sort_section(entries: &mut Vec<SVal>) {
    entries.sort_by(|a, b| encode(a).cmp(&encode(b)));
}

impl ObservableState {
    /// Project a replica's state into its observable form (§6.1.1).
    pub fn of(state: &SyncState) -> ObservableState {
        let orset = state.present_members();
        let lww = state
            .lww
            .cells()
            .map(|((t, f), (_, v))| (t.clone(), f.clone(), v.clone()))
            .collect();
        let pn = state.counters.totals();
        let death = state
            .deaths
            .deleted()
            .into_iter()
            .map(|(t, c)| (t, c.token().to_string()))
            .collect();
        let rga = state
            .sequences
            .iter()
            .map(|(t, seq)| (t.clone(), seq.values()))
            .collect();
        let tree = state
            .tree
            .edges()
            .into_iter()
            // The reserved root node id `""` never appears as a `node` entry — the root has no
            // parent edge; it appears only as the `parent` of a top-level node.
            .filter(|(node, _)| node != TREE_ROOT)
            .map(|(node, (parent, ord))| (node, parent, ord))
            .collect();
        ObservableState { orset, lww, pn, death, rga, tree }
    }

    /// The canonical six-element array (§6.1.1). Empty sections are the empty array `[]`, present
    /// in position — a section is never omitted, so the array is always length 6.
    pub fn to_sval(&self) -> SVal {
        let mut orset: Vec<SVal> = self
            .orset
            .iter()
            .map(|(t, e)| SVal::Array(vec![SVal::Text(t.clone()), e.clone()]))
            .collect();
        sort_section(&mut orset);

        let mut lww: Vec<SVal> = self
            .lww
            .iter()
            .map(|(t, f, v)| {
                SVal::Array(vec![SVal::Text(t.clone()), SVal::Text(f.clone()), v.clone()])
            })
            .collect();
        sort_section(&mut lww);

        let mut pn: Vec<SVal> = self
            .pn
            .iter()
            .map(|(t, f, total)| {
                SVal::Array(vec![
                    SVal::Text(t.clone()),
                    SVal::Text(f.clone()),
                    SVal::int(*total as i64),
                ])
            })
            .collect();
        sort_section(&mut pn);

        let mut death: Vec<SVal> = self
            .death
            .iter()
            .map(|(t, c)| SVal::Array(vec![SVal::Text(t.clone()), SVal::Text(c.clone())]))
            .collect();
        sort_section(&mut death);

        // The RGA inner order is SEQUENCE order (the §4.7 pre-order walk) and is never re-sorted;
        // only the outer array is sorted, by `det_cbor(target)`.
        let mut rga: Vec<(Vec<u8>, SVal)> = self
            .rga
            .iter()
            .map(|(t, atoms)| {
                (
                    encode(&SVal::Text(t.clone())),
                    SVal::Array(vec![SVal::Text(t.clone()), SVal::Array(atoms.clone())]),
                )
            })
            .collect();
        rga.sort_by(|a, b| a.0.cmp(&b.0));
        let rga: Vec<SVal> = rga.into_iter().map(|(_, v)| v).collect();

        let mut tree: Vec<SVal> = self
            .tree
            .iter()
            .map(|(node, parent, ord)| {
                SVal::Array(vec![
                    SVal::Text(node.clone()),
                    SVal::Text(parent.clone()),
                    SVal::Text(ord.clone()),
                ])
            })
            .collect();
        sort_section(&mut tree);

        SVal::Array(vec![
            SVal::Array(orset),
            SVal::Array(lww),
            SVal::Array(pn),
            SVal::Array(death),
            SVal::Array(rga),
            SVal::Array(tree),
        ])
    }

    /// The canonical bytes two replicas at the same `covers` MUST agree on byte-for-byte.
    pub fn det_cbor(&self) -> Vec<u8> {
        encode(&self.to_sval())
    }

    /// `root = 0x1e ‖ BLAKE3-256("DMTAP-SYNC-v0/snapshot-state" ‖ 0x00 ‖ det_cbor(ObservableState))`
    /// (§6.1). A mismatch between two replicas at the same `covers` is
    /// `ERR_SYNC_SNAPSHOT_ROOT_MISMATCH` (`0x0A09`) — evidence of divergence, not a recoverable
    /// disagreement.
    pub fn root(&self) -> ContentId {
        ds_hash(DS_SNAPSHOT_STATE, &self.det_cbor())
    }

    /// Decode a canonical observable-state body (§6.1.1) — what a fast-joining replica receives
    /// instead of a history, and what `GET /sync/state/<root>` serves.
    ///
    /// Fails closed on anything that is not exactly six sections of correctly-shaped entries: a
    /// body that decodes loosely could hash to `root` yet mean something different to two
    /// replicas, which is the one thing §6.1 exists to rule out.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<ObservableState, SyncError> {
        let cv = crate::detcbor::decode(bytes).map_err(|_| SyncError::OpInvalid)?;
        let sections = match cv {
            SVal::Array(a) if a.len() == 6 => a,
            _ => return Err(SyncError::OpInvalid),
        };
        let rows = |i: usize, arity: usize| -> Result<Vec<Vec<SVal>>, SyncError> {
            match &sections[i] {
                SVal::Array(entries) => entries
                    .iter()
                    .map(|e| match e {
                        SVal::Array(t) if t.len() == arity => Ok(t.clone()),
                        _ => Err(SyncError::OpInvalid),
                    })
                    .collect(),
                _ => Err(SyncError::OpInvalid),
            }
        };
        let text = |v: &SVal| -> Result<String, SyncError> {
            v.as_text().map(str::to_owned).ok_or(SyncError::OpInvalid)
        };
        let mut st = ObservableState::default();
        for t in rows(0, 2)? {
            st.orset.push((text(&t[0])?, t[1].clone()));
        }
        for t in rows(1, 3)? {
            st.lww.push((text(&t[0])?, text(&t[1])?, t[2].clone()));
        }
        for t in rows(2, 3)? {
            st.pn.push((
                text(&t[0])?,
                text(&t[1])?,
                t[2].as_int().ok_or(SyncError::OpInvalid)? as i128,
            ));
        }
        for t in rows(3, 2)? {
            st.death.push((text(&t[0])?, text(&t[1])?));
        }
        for t in rows(4, 2)? {
            let atoms = match &t[1] {
                SVal::Array(a) => a.clone(),
                _ => return Err(SyncError::OpInvalid),
            };
            st.rga.push((text(&t[0])?, atoms));
        }
        for t in rows(5, 3)? {
            st.tree.push((text(&t[0])?, text(&t[1])?, text(&t[2])?));
        }
        Ok(st)
    }
}

/// The observable-state root of a replica.
pub fn state_root(state: &SyncState) -> ContentId {
    ObservableState::of(state).root()
}

/// Check a claimed `root` against the locally recomputed one (§6.1): a snapshot is **verifiable,
/// not merely trusted**, so a replica that backfills the pre-`covers` history MUST recompute and
/// confirm.
pub fn verify_root(state: &SyncState, claimed: &ContentId) -> Result<(), SyncError> {
    if state_root(state).as_bytes() == claimed.as_bytes() {
        Ok(())
    } else {
        Err(SyncError::SnapshotRootMismatch)
    }
}

/// A portable, signed checkpoint (§6.1). `covers` names the exact set of ops folded into `root`, so
/// a joining replica adopts the state, sets its vector to `covers`, and pulls **only** the ops
/// after it — never replaying the pre-snapshot history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// Version (key 1) — `0`.
    pub v: u8,
    /// Cryptographic suite (key 2).
    pub suite: u8,
    /// The namespace this snapshot covers (key 3).
    pub ns: String,
    /// The per-author max HLC folded into `root` (key 4).
    pub covers: VersionVector,
    /// The §6.1 observable-state root (key 5).
    pub root: ContentId,
    /// Timestamp, unix milliseconds (key 6).
    pub ts: u64,
    /// The signer's author key (key 7).
    pub signer: Vec<u8>,
    /// Signature over `det_cbor(Snapshot ∖ {8})`, DS-tag `DMTAP-SYNC-v0/snapshot` (key 8).
    pub sig: Vec<u8>,
}

impl Snapshot {
    fn body(&self) -> Vec<u8> {
        // The signature preimage body: the object WITHOUT key 8.
        encode(&SVal::Map(vec![
            (1, SVal::Uint(self.v as u64)),
            (2, SVal::Uint(self.suite as u64)),
            (3, SVal::Text(self.ns.clone())),
            (4, self.covers.to_sval()),
            (5, SVal::Bytes(self.root.as_bytes().to_vec())),
            (6, SVal::Uint(self.ts)),
            (7, SVal::Bytes(self.signer.clone())),
        ]))
    }

    /// The DS-tagged signing preimage. The **state-root** hash and the **snapshot signature** use
    /// two distinct DS-tags on purpose, so the two can never be confused (§6.1).
    fn preimage(&self) -> Vec<u8> {
        let mut p = DS_SNAPSHOT.to_vec();
        p.push(0x00);
        p.extend_from_slice(&self.body());
        p
    }

    /// The DS-tagged signing preimage, for a signer that holds the key **outside this process** —
    /// a hardware token, a remote signing service, or a browser `CryptoKey` that is deliberately
    /// non-extractable (see the `dmtap-sync-wasm` binding). Sign these bytes with Ed25519 under
    /// `signer`, put the result in `sig`, and [`Snapshot::verify_sig`] will accept it exactly as if
    /// [`Snapshot::create`] had produced it.
    pub fn signing_preimage(&self) -> Vec<u8> {
        self.preimage()
    }

    /// Mint a signed snapshot of `state` at its current vector.
    pub fn create(sk: &IdentityKey, suite: u8, ns: &str, state: &SyncState, ts: u64) -> Snapshot {
        let mut s = Snapshot {
            v: 0,
            suite,
            ns: ns.to_owned(),
            covers: state.vector.clone(),
            root: state_root(state),
            ts,
            signer: sk.public(),
            sig: Vec::new(),
        };
        s.sig = sk.sign_domain(&[], &s.preimage());
        s
    }

    /// The complete signed wire bytes: the signing body plus `sig` at key 8 (§6.1). A snapshot has
    /// to travel — it is what a truncated replica hands a peer that is behind the cut (§6.2) — so
    /// it needs a canonical encoding, not just a signing preimage.
    pub fn det_cbor(&self) -> Vec<u8> {
        encode(&SVal::Map(vec![
            (1, SVal::Uint(self.v as u64)),
            (2, SVal::Uint(self.suite as u64)),
            (3, SVal::Text(self.ns.clone())),
            (4, self.covers.to_sval()),
            (5, SVal::Bytes(self.root.as_bytes().to_vec())),
            (6, SVal::Uint(self.ts)),
            (7, SVal::Bytes(self.signer.clone())),
            (8, SVal::Bytes(self.sig.clone())),
        ]))
    }

    /// Decode a snapshot from wire bytes, denying unknown keys. The signature is **not** checked
    /// here — call [`Snapshot::verify_sig`]; decoding and trusting are deliberately separate steps.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, SyncError> {
        let cv = crate::detcbor::decode(bytes).map_err(|_| SyncError::OpInvalid)?;
        let mut f = crate::detcbor::Fields::new(cv).map_err(|_| SyncError::OpInvalid)?;
        let bad = |_| SyncError::OpInvalid;
        let SVal::Uint(v) = f.req(1).map_err(bad)? else { return Err(SyncError::OpInvalid) };
        let SVal::Uint(suite) = f.req(2).map_err(bad)? else { return Err(SyncError::OpInvalid) };
        let SVal::Text(ns) = f.req(3).map_err(bad)? else { return Err(SyncError::OpInvalid) };
        let covers = VersionVector::from_sval(f.req(4).map_err(bad)?).map_err(bad)?;
        let SVal::Bytes(root) = f.req(5).map_err(bad)? else { return Err(SyncError::OpInvalid) };
        let SVal::Uint(ts) = f.req(6).map_err(bad)? else { return Err(SyncError::OpInvalid) };
        let SVal::Bytes(signer) = f.req(7).map_err(bad)? else { return Err(SyncError::OpInvalid) };
        let SVal::Bytes(sig) = f.req(8).map_err(bad)? else { return Err(SyncError::OpInvalid) };
        f.deny_unknown().map_err(bad)?;
        Ok(Snapshot {
            v: u8::try_from(v).map_err(|_| SyncError::UnsupportedVersion)?,
            suite: u8::try_from(suite).map_err(|_| SyncError::UnsupportedVersion)?,
            ns,
            covers,
            root: ContentId(root),
            ts,
            signer,
            sig,
        })
    }

    /// Verify the snapshot's own signature under `signer` (fails closed, `0x0A02`).
    pub fn verify_sig(&self) -> Result<(), SyncError> {
        if self.v != 0 {
            return Err(SyncError::UnsupportedVersion);
        }
        verify_domain(&self.signer, &[], &self.preimage(), &self.sig)
            .map_err(|_| SyncError::OpSigInvalid)
    }
}

// ============================================================================================
// §5.2.1 — fast-join from a snapshot over the wire
// ============================================================================================

/// The `FastJoin` object a §5.2 `pull` returns to a caller below the responder's §6.2 truncation
/// floor (§5.2.1, frozen by `SYNC-FJ-01`).
///
/// ```cddl
/// FastJoin = {
///   1 => Snapshot,   ; the §6.1 signed descriptor — bounded, so it ships INLINE
///   2 => Hlc,        ; floor — the responder's §6.2 cut, the caller's audit handle
///   ? 3 => bstr,     ; OPTIONAL inline det_cbor(ObservableState), a bounded cache hint
/// }
/// ```
///
/// The encoding split is the design: the signed descriptor is sized by the author count and
/// carries the signature, `covers` and the `root` commitment, so it must travel inline; the
/// observable state is unbounded (potentially megabytes) and travels **by reference** at
/// `Snapshot.root`, fetched from `GET /sync/state/<root>`. By-reference keeps a sync round's
/// response bounded and reuses content addressing the protocol already has — the body is immutable
/// and self-verifying, so any holder may serve it and every peer joining at the same `covers`
/// dedupes to the same bytes.
///
/// [`FastJoin::state`] is a **cache hint, never a second source of truth**: it is hashed against
/// `root` exactly like a fetched body and discarded on mismatch, so there is one verification path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastJoin {
    /// The §6.1 signed snapshot that replaced the truncated prefix (key 1).
    pub snapshot: Snapshot,
    /// The §6.2 truncation floor in force at the responder (key 2).
    pub floor: Hlc,
    /// An OPTIONAL bounded inline copy of `det_cbor(ObservableState)` (key 3).
    pub state: Option<Vec<u8>>,
}

/// The RECOMMENDED ceiling on an inline state body (§5.2.1). Above it, ship by reference only —
/// the inline copy exists to collapse the small-namespace case to one round trip, not to make a
/// sync round's response size unbounded again.
pub const INLINE_STATE_CEILING: usize = 64 * 1024;

impl FastJoin {
    /// The canonical wire encoding.
    pub fn det_cbor(&self) -> Vec<u8> {
        let mut fields = vec![
            (1, crate::detcbor::decode(&self.snapshot.det_cbor()).expect("own snapshot encoding")),
            (2, self.floor.to_sval()),
        ];
        if let Some(state) = &self.state {
            fields.push((3, SVal::Bytes(state.clone())));
        }
        encode(&SVal::Map(fields))
    }

    /// Decode, denying unknown keys. The signature is **not** checked here — call
    /// [`FastJoin::adopt`]; decoding and trusting stay separate steps.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, SyncError> {
        let cv = crate::detcbor::decode(bytes).map_err(|_| SyncError::OpInvalid)?;
        let mut f = crate::detcbor::Fields::new(cv).map_err(|_| SyncError::OpInvalid)?;
        let bad = |_| SyncError::OpInvalid;
        let snapshot = Snapshot::from_det_cbor(&encode(&f.req(1).map_err(bad)?))?;
        let floor = Hlc::from_sval(f.req(2).map_err(bad)?).map_err(bad)?;
        let state = match f.take(3) {
            Some(SVal::Bytes(b)) => Some(b),
            Some(_) => return Err(SyncError::OpInvalid),
            None => None,
        };
        f.deny_unknown().map_err(bad)?;
        Ok(FastJoin { snapshot, floor, state })
    }

    /// The §5.2.1 caller-side sequence, steps 1–3, fail-closed at every step.
    ///
    /// 1. **Verify the snapshot** — signature under `DMTAP-SYNC-v0/snapshot` (`0x0A02`), signer
    ///    admission against `admitted` when the deployment supplies a list (`0x0A01`), and
    ///    `Snapshot.ns` among the caller's subscriptions (`0x0A0A`).
    /// 2. **Check what is checkable about `covers`** (§5.2.2) — a well-formed, non-empty
    ///    `VersionVector` (`0x0A03`), and the caller genuinely below the floor (`0x0A09`). There is
    ///    deliberately **no** floor-vs-`covers` comparison: see [`check_covers_closes_gap`] for why
    ///    that rule was removed rather than reworded (§14 C-07).
    /// 3. **Obtain and verify the state body** — the inline copy if it hashes to `root`, otherwise
    ///    whatever `fetch` returns for `root`, hashed the same way. `0x0A09` if a body is served
    ///    but does not hash to `root`; `0x0A0C` if no holder can serve one at all.
    ///
    /// Returns the **verified** observable state. Adoption itself (step 4) and resuming the pull at
    /// `covers` (step 5) are the caller's, under the deployment's §6.1 trust policy — this function
    /// exists so that no caller can reach those steps with an unverified snapshot or body.
    ///
    /// **There is deliberately no fallback here.** Every failure path returns an error and leaves
    /// the caller's vector untouched. Falling back to the responder's surviving suffix on a failed
    /// fast-join would reintroduce, by the back door, exactly the silent lost-write §5.2.1's MUST
    /// exists to prevent.
    pub fn adopt(
        &self,
        caller: &VersionVector,
        subscribed: &[String],
        admitted: &[Vec<u8>],
        fetch: impl FnOnce(&ContentId) -> Option<Vec<u8>>,
    ) -> Result<ObservableState, SyncError> {
        self.adopt_after(None, caller, subscribed, admitted, fetch)
    }

    /// **The §5.2.1 step-5 progress MUST.** A re-pull answered with another `fast-join` carrying the
    /// *same* `Snapshot.root` **and** `covers` means the responder is looping: the caller already
    /// adopted that exact checkpoint, so adopting it again cannot advance it. Fail `0x0A09` rather
    /// than re-adopt.
    ///
    /// This is the one loop a below-floor caller can otherwise spin in forever, which is why it is a
    /// MUST rather than a retry budget: the responder is not slow, it is stuck, and a caller that
    /// re-adopts learns nothing new on any iteration.
    ///
    /// `previous` is the `(root, covers)` of the fast-join this caller adopted on the preceding
    /// round of the *same* join, or `None` on the first round.
    pub fn check_progress(
        &self,
        previous: Option<(&ContentId, &VersionVector)>,
    ) -> Result<(), SyncError> {
        match previous {
            Some((root, covers))
                if *root == self.snapshot.root && *covers == self.snapshot.covers =>
            {
                Err(SyncError::SnapshotRootMismatch)
            }
            _ => Ok(()),
        }
    }

    /// [`FastJoin::adopt`] preceded by the §5.2.1 step-5 [progress MUST](Self::check_progress).
    ///
    /// Prefer this in a real pull loop; [`adopt`](Self::adopt) is the first-round case
    /// (`previous == None`) and is kept as-is so no existing caller changes behaviour.
    pub fn adopt_after(
        &self,
        previous: Option<(&ContentId, &VersionVector)>,
        caller: &VersionVector,
        subscribed: &[String],
        admitted: &[Vec<u8>],
        fetch: impl FnOnce(&ContentId) -> Option<Vec<u8>>,
    ) -> Result<ObservableState, SyncError> {
        // --- step 5's loop guard, checked BEFORE any work ------------------------------------
        self.check_progress(previous)?;
        // --- step 1: the snapshot itself -----------------------------------------------------
        self.snapshot.verify_sig()?;
        if !admitted.is_empty() {
            crate::crdt::check_admitted(&self.snapshot.signer, admitted)?;
        }
        if !subscribed.is_empty() && !subscribed.iter().any(|ns| *ns == self.snapshot.ns) {
            return Err(SyncError::NsLeak);
        }

        // --- step 2: does it close the gap? --------------------------------------------------
        check_covers_closes_gap(&self.snapshot, &self.floor, caller)?;

        // --- step 3: the state body ----------------------------------------------------------
        // The inline copy is tried first and held to the SAME hash check as a fetched body; on
        // mismatch it is discarded (not an error — it was only ever a hint) and the by-reference
        // path is taken.
        let inline = self.state.as_ref().filter(|b| state_root_of(b) == self.snapshot.root);
        let body = match inline {
            Some(b) => b.clone(),
            None => fetch(&self.snapshot.root).ok_or(SyncError::SnapshotStateUnavailable)?,
        };
        if state_root_of(&body) != self.snapshot.root {
            return Err(SyncError::SnapshotRootMismatch);
        }
        ObservableState::from_det_cbor(&body)
    }
}

/// The §6.1 root of an encoded observable-state body.
pub fn state_root_of(body: &[u8]) -> ContentId {
    ds_hash(DS_SNAPSHOT_STATE, body)
}

/// **The §5.2.1 responder predicate**: is `caller` below the floor a retained `snapshot` stands in
/// for — i.e. would the surviving suffix be an incomplete answer?
///
/// The test is domination of the snapshot's `covers`, **not** a comparison against the floor `Hlc`
/// alone: if the caller lacks any HLC the snapshot folded in, some op it needs may have been
/// truncated, and only the snapshot can give that state back.
///
/// A responder for which this is `true` MUST answer `fast-join`, never `ops`. A responder for which
/// it is `false` MUST answer `ops`, never `fast-join` — forcing a caught-up caller to fast-join
/// would trade its verified local history for a trusted checkpoint.
pub fn caller_is_below_floor(snapshot: &Snapshot, caller: &VersionVector) -> bool {
    snapshot.covers.marks().any(|(_, hlc)| caller.lacks(hlc))
}

/// **Advisory (§5.2.2, MAY — never a MUST).** Does `covers` carry a mark for `floor.author`?
///
/// A responder that truncated below `(W,5,A)` will, in the ordinary case, have folded some op of
/// `A`'s into the snapshot that replaced the prefix, so a `false` here is worth **logging**. It is
/// deliberately **not** a conformance test and MUST NOT be turned into one: it is not entailed. If
/// `A`'s only op is *at* the floor, that op is **retained** rather than truncated, and `covers` need
/// never name `A` at all. Inferring a conformance failure from this predicate rejects conformant
/// peers — the same class of error as the deleted floor-vs-`covers` rule (§14 C-07).
pub fn covers_carries_mark_for_floor_author(snapshot: &Snapshot, floor: &Hlc) -> bool {
    snapshot.covers.marks().any(|(author, _)| author.as_slice() == floor.author.as_slice())
}

/// The caller-side checks of §5.2.1 step 2, as restated by **§5.2.2**.
///
/// # There is no floor-vs-`covers` check here, and there must not be one
///
/// `floor` is a **single `Hlc`** — one point in the §3 total order, whose `author` field is the
/// tiebreaker component of *that timestamp*, not a claim about that author's stream. `covers` is a
/// **per-author `VersionVector`**. There is **no ordering between them**, so no such comparison is a
/// rule an implementation could fail to find — it is a category error (§5.2.2).
///
/// This crate previously enforced two checks that §14 C-07 removed, both of which rejected
/// **conformant** responders:
///
/// * `covers.lacks(floor)` — the natural-looking predicate. It returns `true` on `SYNC-FJ-01`'s own
///   frozen data (`floor = (W,5,A)`, `covers[A] = (W,4)`, because `A` produced no op in that
///   window). The vector caught the specification's own sentence.
/// * `covers` MUST carry a mark for `floor.author` — now MAY-grade only, see
///   [`covers_carries_mark_for_floor_author`].
///
/// # What remains verifiable
///
/// * `covers` is a **well-formed, non-empty** `VersionVector` — an empty one accounts for nothing,
///   so it can close no gap. Malformed ⇒ `0x0A03` (`ERR_SYNC_OP_INVALID`, §5.2.1 step 2).
/// * The **other direction** of §5.2.1's MUST: a caller that is *not* below the floor MUST NOT be
///   fast-joined (`0x0A09`). Its surviving-suffix answer is complete, and adopting a checkpoint
///   instead would trade verified local history for a trusted one. A responder that sends
///   `fast-join` anyway is refused rather than obeyed.
///
/// # What is merely trusted
///
/// That **every truncated op was folded into `covers`**. That is quantified over ops the caller
/// **cannot see** — they are precisely the ops that no longer exist at the responder — so no
/// comparison of `floor`, `covers` and the caller's own vector can establish it. The obligation
/// lives at the responder (§6.2, where the ops are still enumerable); the caller's residual
/// protection is the step-3 root check and the §6.1 trust policy's backfill-and-recompute.
pub fn check_covers_closes_gap(
    snapshot: &Snapshot,
    _floor: &Hlc,
    caller: &VersionVector,
) -> Result<(), SyncError> {
    // Well-formedness (§5.2.1 step 2): a non-empty VersionVector. `0x0A03`, not `0x0A09` — this is
    // a malformed object, not a root/coverage disagreement.
    if snapshot.covers.marks().next().is_none() {
        return Err(SyncError::OpInvalid);
    }
    if !caller_is_below_floor(snapshot, caller) {
        return Err(SyncError::SnapshotRootMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detcbor::SVal;
    use crate::state::SyncState;
    use crate::wire::{Hlc as WHlc, OpRef, SyncOp, OP_LWW_SET};

    fn a(seed: u8) -> Vec<u8> {
        vec![seed; 32]
    }

    fn h(counter: u32, author: u8) -> WHlc {
        WHlc { wall: 1_700_000_100_000, counter, author: a(author) }
    }

    fn lww(target: &str, field: &str, value: &str, counter: u32, author: u8) -> SyncOp {
        SyncOp {
            kind: OP_LWW_SET,
            ns: String::new(),
            target: target.into(),
            field: Some(field.into()),
            value: Some(SVal::Text(value.into())),
            hlc: h(counter, author),
            observed: None,
            reference: None,
        }
    }

    #[test]
    fn empty_state_is_six_empty_sections() {
        let s = ObservableState::default();
        assert_eq!(s.det_cbor(), vec![0x86, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80]);
    }

    #[test]
    fn fast_join_equals_full_replay() {
        let now = 1_700_000_200_000;
        // Full replay: every op, oldest first.
        let ops = vec![lww("doc1", "title", "m", 1, 0xcc), lww("doc1", "title", "p", 20, 0xdd)];
        let mut full = SyncState::new();
        for op in &ops {
            full.ingest(op, now).unwrap();
        }
        // Fast join: adopt the snapshot's observable state, then apply only the post-covers op.
        let mut pre = SyncState::new();
        pre.ingest(&ops[0], now).unwrap();
        let snap_state = ObservableState::of(&pre);
        let mut joined = SyncState::new();
        // Adoption of the projected state is modelled by replaying the (single) surviving cell —
        // the point of the test is that the OBSERVABLE bytes match, not the internal bookkeeping.
        joined.ingest(&ops[0], now).unwrap();
        assert_eq!(ObservableState::of(&joined).det_cbor(), snap_state.det_cbor());
        joined.ingest(&ops[1], now).unwrap();
        assert_eq!(ObservableState::of(&joined).det_cbor(), ObservableState::of(&full).det_cbor());
        assert_eq!(state_root(&joined).as_bytes(), state_root(&full).as_bytes());
    }

    #[test]
    fn snapshot_signature_round_trips_and_fails_closed_on_tamper() {
        let sk = IdentityKey::from_seed(&[0xcc; 32]);
        let mut state = SyncState::new();
        state.ingest(&lww("doc1", "title", "m", 1, 0xcc), 1_700_000_200_000).unwrap();
        let mut snap = Snapshot::create(&sk, 0x01, "", &state, 1_700_000_100_000);
        assert!(snap.verify_sig().is_ok());
        snap.ns = "other".into();
        assert_eq!(snap.verify_sig(), Err(SyncError::OpSigInvalid));
    }

    // --- §14 C-07: the floor/`covers` NON-relationship -------------------------------------------

    /// Build a fast-join shaped exactly like `SYNC-FJ-01`'s frozen data: `floor = (W,5,A)` sitting
    /// ABOVE `covers[A] = (W,4)`, because author `A` produced no op in that window.
    fn fj01_shaped() -> (FastJoin, VersionVector) {
        let sk = IdentityKey::from_seed(&[0xcc; 32]);
        let mut state = SyncState::new();
        state.ingest(&lww("doc1", "title", "m", 4, 0xcc), 1_700_000_200_000).unwrap();
        let mut snap = Snapshot::create(&sk, 0x01, "", &state, 1_700_000_100_000);
        // covers = {A@(W,4), B@(W,7)} — A below the floor, B above it.
        snap.covers = VersionVector::default();
        snap.covers.observe(&h(4, 0xcc));
        snap.covers.observe(&h(7, 0xdd));
        let snap = Snapshot { sig: snap.sig.clone(), ..snap };
        let mut caller = VersionVector::default();
        caller.observe(&h(2, 0xcc)); // behind B@(W,7) ⇒ genuinely below the floor
        (FastJoin { snapshot: snap, floor: h(5, 0xcc), state: None }, caller)
    }

    /// The regression this crate's first pass got wrong: `covers.lacks(floor)` is TRUE here, and a
    /// caller enforcing any floor-vs-`covers` ordering rejects a CONFORMANT responder. §5.2.2
    /// removed the rule, so this shape must now pass step 2.
    #[test]
    fn floor_above_covers_for_an_author_is_conformant_not_an_error() {
        let (fj, caller) = fj01_shaped();
        // The naive predicate the specification explicitly rejects would fire here...
        assert!(fj.snapshot.covers.lacks(&fj.floor), "the vector's own counterexample shape");
        // ...but step 2 must NOT reject it.
        assert_eq!(check_covers_closes_gap(&fj.snapshot, &fj.floor, &caller), Ok(()));
    }

    /// `covers` carrying a mark for `floor.author` is MAY-grade — true here, but never enforced.
    #[test]
    fn covers_mark_for_floor_author_is_advisory_only() {
        let (mut fj, caller) = fj01_shaped();
        assert!(covers_carries_mark_for_floor_author(&fj.snapshot, &fj.floor));
        // Drop A entirely: an author whose only op is AT the floor is retained, not truncated, so
        // `covers` need never name it. This MUST still pass step 2.
        let mut covers = VersionVector::default();
        covers.observe(&h(7, 0xdd));
        fj.snapshot.covers = covers;
        assert!(!covers_carries_mark_for_floor_author(&fj.snapshot, &fj.floor));
        assert_eq!(check_covers_closes_gap(&fj.snapshot, &fj.floor, &caller), Ok(()));
    }

    /// An empty `covers` accounts for nothing: malformed ⇒ `0x0A03`, not `0x0A09`.
    #[test]
    fn empty_covers_is_malformed_0a03() {
        let (mut fj, caller) = fj01_shaped();
        fj.snapshot.covers = VersionVector::default();
        assert_eq!(
            check_covers_closes_gap(&fj.snapshot, &fj.floor, &caller),
            Err(SyncError::OpInvalid)
        );
    }

    /// §5.2.1 step 5's progress MUST: the same `root` AND `covers` twice is a responder loop.
    #[test]
    fn repeated_fastjoin_at_same_root_and_covers_is_0a09() {
        let (fj, _) = fj01_shaped();
        let (root, covers) = (fj.snapshot.root.clone(), fj.snapshot.covers.clone());
        // First round: nothing adopted yet, so there is nothing to loop on.
        assert_eq!(fj.check_progress(None), Ok(()));
        // Second round, same checkpoint: refuse rather than re-adopt.
        assert_eq!(
            fj.check_progress(Some((&root, &covers))),
            Err(SyncError::SnapshotRootMismatch)
        );
        // A DIFFERENT covers at the same root is progress, not a loop.
        let mut moved = covers.clone();
        moved.observe(&h(9, 0xdd));
        assert_eq!(fj.check_progress(Some((&root, &moved))), Ok(()));
    }

    /// Adoption regressing the caller's vector for an author is intended, never an error (§5.2.2).
    #[test]
    fn adopting_covers_may_regress_an_author_and_that_is_not_an_error() {
        let (fj, mut caller) = fj01_shaped();
        // The caller holds a LATER mark for A than `covers` does.
        caller.observe(&h(6, 0xcc));
        assert!(caller.lacks(&h(7, 0xdd)), "still below the floor via B");
        assert_eq!(check_covers_closes_gap(&fj.snapshot, &fj.floor, &caller), Ok(()));
    }

    #[test]
    fn root_mismatch_is_detected() {
        let now = 1_700_000_200_000;
        let mut x = SyncState::new();
        x.ingest(&lww("doc1", "title", "m", 1, 0xcc), now).unwrap();
        let mut y = SyncState::new();
        y.ingest(&lww("doc1", "title", "z", 1, 0xdd), now).unwrap();
        assert_eq!(verify_root(&y, &state_root(&x)), Err(SyncError::SnapshotRootMismatch));
        assert!(verify_root(&x, &state_root(&x)).is_ok());
    }

    #[test]
    fn rga_inner_order_is_sequence_order_not_sorted() {
        let now = 1_700_000_200_000;
        let mut s = SyncState::new();
        let root = h(0, 0xcc);
        let mut ins = SyncOp {
            kind: crate::wire::OP_SEQ_INSERT,
            ns: String::new(),
            target: "line1".into(),
            field: None,
            value: Some(SVal::Text("atom0".into())),
            hlc: root.clone(),
            observed: None,
            reference: None,
        };
        s.ingest(&ins, now).unwrap();
        ins.hlc = h(3, 0xcc);
        ins.value = Some(SVal::Text("X".into()));
        ins.reference = Some(OpRef { target: "line1".into(), hlc: Some(root.clone()) });
        s.ingest(&ins, now).unwrap();
        ins.hlc = h(4, 0xcc);
        ins.value = Some(SVal::Text("Y".into()));
        s.ingest(&ins, now).unwrap();
        let obs = ObservableState::of(&s);
        assert_eq!(
            obs.rga[0].1,
            vec![SVal::Text("atom0".into()), SVal::Text("Y".into()), SVal::Text("X".into())],
            "newer-first sequence order survives into the snapshot; it is NOT re-sorted"
        );
    }
}
