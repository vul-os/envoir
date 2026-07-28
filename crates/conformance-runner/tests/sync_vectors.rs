//! `cargo test`-visible gate over the **Sync substrate** vectors
//! (`../kotva/conformance/vectors/sync_vectors.json`, `substrate/SYNC.md` §10), executed through
//! the reference crate — which now lives in that same repo as `kotva-sync`, consumed here under
//! the unchanged Rust path `dmtap_sync::` via a cargo dependency-rename.
//!
//! This is the CONSUMER-side gate: it proves the crate *as envoir compiles it* still reproduces
//! the frozen answers. KOTVA has its own gates beside the implementation
//! (`crates/kotva-sync-wasm/tests/native_trace.rs`, `bindings/go/vectors_test.go`), which read the
//! vectors in-tree and likewise fail closed.
//!
//! The counts are asserted **exactly**, in both directions: a regression in `dmtap-sync` fails
//! here, and so does an upstream *fix* to an allowlisted vector (that makes it pass, which this
//! test also notices, so the allowlist cannot rot). That second direction has now fired for real:
//! SYNC-PN-01 was corrected upstream (`SYNC.md` §14 C-02), this test failed because the
//! allowlisted vector had started passing, and the entry was deleted. The allowlist is empty and
//! all **24/24** vectors pass — 20 for the algebra; since correction C-05, `SYNC-FJ-01`/
//! `SYNC-FJ-02` for the §5.2.1 fast-join pull path; and since C-08/C-09, `SYNC-VAL-01` for the
//! full recursive `ext-value` boundary and `SYNC-SNAP-03` for the §6.1.2 op-set snapshot body.

use std::path::PathBuf;

use conformance_runner::{
    check_all_vectors, load_vectors, spec_repo_dir, Verdict, SYNC_KNOWN_DISCREPANCIES,
};

fn sync_vectors_path() -> PathBuf {
    spec_repo_dir().join("conformance/vectors/sync_vectors.json")
}

/// Every Sync vector passes byte-exactly (the discrepancy allowlist is currently empty, so this is
/// a 24/24 assertion).
#[test]
fn sync_vectors_pass_except_the_documented_discrepancy() {
    let path = sync_vectors_path();
    // FAILS CLOSED. This used to skip — loudly, but still skip — when the sibling KOTVA repo was
    // absent, on the reasoning that it was a developer-machine affordance. That reasoning has
    // expired, and leaving it would now be indefensible: this crate's MANDATORY gate
    // (`run_over_vectors::all_vectors_pass`) reads its `vectors.json` from that same repo since the
    // vector corpus was consolidated there, so a checkout without KOTVA cannot produce a green
    // `cargo test -p conformance-runner` under any circumstances. The skip branch could therefore
    // only ever have fired in a run that was already failing — it bought nothing and cost the one
    // thing that matters, which is that a gate never reports success having run zero cases. That
    // exact shape shipped here once already: a "24/24" that drove nothing.
    assert!(
        path.exists(),
        "the frozen SYNC.md §10 vectors are missing at {}, so NONE of the 24 would run. NOT \
         VERIFIED: that `dmtap-sync` (now `kotva-sync`, consumed from the KOTVA repo) reproduces \
         the spec's known answers at all. Check KOTVA out at ../kotva, or point KOTVA_DIR at it. \
         This is a hard failure on purpose: a conformance gate that passes without its vectors is \
         worse than no gate.",
        path.display()
    );
    let vf = load_vectors(&path).expect("sync_vectors.json must load");
    assert!(!vf.vectors.is_empty(), "sync_vectors.json loaded but is EMPTY — nothing was verified");
    assert_eq!(vf.vectors.len(), 24, "SYNC.md §10 freezes exactly 24 vectors");

    let mut passed = Vec::new();
    let mut failed = Vec::new();
    for (name, verdict) in check_all_vectors(&vf) {
        match verdict {
            Verdict::Pass => passed.push(name),
            // No sync vector may pass "generically": every one has a real executor.
            Verdict::PassGeneric => panic!("{name} fell through to the generic round-trip check"),
            Verdict::Fail(e) => failed.push((name, e)),
        }
    }

    let known: Vec<&str> = SYNC_KNOWN_DISCREPANCIES.iter().map(|(n, _)| *n).collect();
    let unexpected: Vec<&(String, String)> =
        failed.iter().filter(|(n, _)| !known.contains(&n.as_str())).collect();
    assert!(unexpected.is_empty(), "unexpected sync vector failures: {unexpected:#?}");

    for name in &known {
        assert!(
            failed.iter().any(|(n, _)| n == name),
            "`{name}` is allowlisted as a spec/vector discrepancy but now PASSES — the vector was \
             fixed upstream; delete the SYNC_KNOWN_DISCREPANCIES entry"
        );
    }
    assert_eq!(passed.len(), 24 - known.len(), "expected {} passing sync vectors", 24 - known.len());
}

/// The discrepancy allowlist is not a silent escape hatch: every entry must carry an explanation
/// long enough to be actionable in the `dmtap` repo, since this repo cannot fix the vector itself.
#[test]
fn every_known_discrepancy_is_explained() {
    for (name, why) in SYNC_KNOWN_DISCREPANCIES {
        assert!(!name.is_empty());
        assert!(
            why.len() > 200 && why.contains("MINIMAL FIX"),
            "discrepancy `{name}` must state the contradiction AND the minimal upstream fix"
        );
    }
}
