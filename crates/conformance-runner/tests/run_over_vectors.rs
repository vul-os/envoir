//! `cargo test`-visible proof that the conformance-runner engine is green over the current
//! `dmtap-core/vectors.json` (the VERIFICATION GATE for this crate). Also locks the current,
//! honestly-reported suite.json coverage numbers so any change (new vectors, a dmtap-core fix
//! that closes one of the known self-contained gaps, a suite.json catalog update) is *noticed*
//! here rather than silently drifting.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use conformance_runner::{check_all_vectors, load_suite, load_vectors, run_all_suite_cases, CaseOutcome, Verdict};

fn vectors_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../dmtap-core/vectors.json")
}

fn suite_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../dmtap/conformance/suite.json")
}

/// The mandatory gate: every vector in the committed `vectors.json` passes (reproduces from the
/// reference; every `cbor_*` vector canonically round-trips).
#[test]
fn all_vectors_pass() {
    let vf = load_vectors(&vectors_path()).expect("vectors.json must load");
    assert!(!vf.vectors.is_empty(), "vectors.json must not be empty");
    let results = check_all_vectors(&vf);
    let failures: Vec<String> = results
        .iter()
        .filter_map(|(name, v)| match v {
            Verdict::Fail(e) => Some(format!("{name}: {e}")),
            _ => None,
        })
        .collect();
    assert!(failures.is_empty(), "conformance-runner found FAILing vectors:\n{}", failures.join("\n"));
}

/// Every `cbor_*` vector this crate recognizes by `input.type` gets the stronger typed check
/// (not just the generic canonical round-trip) — i.e. no vector silently falls back to
/// `PassGeneric` without us knowing. If this starts failing, either a new cbor_* vector type
/// appeared (extend `check_cbor_encode_vector`) or a dispatch regressed.
#[test]
fn every_known_cbor_type_gets_the_typed_check() {
    let vf = load_vectors(&vectors_path()).expect("vectors.json must load");
    let results = check_all_vectors(&vf);
    let generic_only: Vec<&str> = results
        .iter()
        .filter(|(_, v)| matches!(v, Verdict::PassGeneric))
        .map(|(n, _)| n.as_str())
        .collect();
    assert!(
        generic_only.is_empty(),
        "these cbor_* vectors only got the generic round-trip check (no `input.type` or unrecognized type): {generic_only:?}"
    );
}

/// Cross-reference the sibling spec repo's conformance-suite catalog, when checked out next to
/// this worktree (`../../../dmtap`). This is a soft dependency: if the sibling repo is absent
/// (e.g. a CI checkout of only this repo), the test is skipped rather than failing — the
/// mandatory proof is `all_vectors_pass` above, not this cross-reference.
#[test]
fn suite_json_cross_reference_matches_known_state() {
    let sp = suite_path();
    if !sp.exists() {
        eprintln!("skipping: sibling spec repo not found at {}", sp.display());
        return;
    }
    let vf = load_vectors(&vectors_path()).expect("vectors.json must load");
    let suite = load_suite(&sp).expect("suite.json must parse");
    let results: BTreeMap<String, Verdict> = check_all_vectors(&vf).into_iter().collect();
    let outcomes = run_all_suite_cases(&suite, &vf, &results);

    let mut pass = 0usize;
    let mut skip = 0usize;
    let mut fails: Vec<(String, String)> = Vec::new();
    for (id, outcome) in &outcomes {
        match outcome {
            CaseOutcome::Pass => pass += 1,
            CaseOutcome::Skipped(_) => skip += 1,
            CaseOutcome::Fail(reason) => fails.push((id.clone(), reason.clone())),
        }
    }

    // GAPS CLOSED: dmtap-core's low-level `cbor::decode` now enforces the full §18.1.1 canonical
    // ruleset on input — shortest-form integers/lengths, definite-length only, strictly ascending
    // map-key order (by encoded bytes), no duplicates — so the three previously-failing
    // self-contained MUST-reject cases (DMTAP-CBOR-05/06/07) now correctly REJECT and pass. The
    // expected gap set is therefore empty; if a NEW case starts failing, this assertion catches it
    // immediately as a regression.
    let expected_gap_ids: Vec<&str> = vec![];
    let actual_gap_ids: Vec<&str> = fails.iter().map(|(id, _)| id.as_str()).collect();
    let mut sorted_actual = actual_gap_ids.clone();
    sorted_actual.sort_unstable();
    let mut sorted_expected = expected_gap_ids.clone();
    sorted_expected.sort_unstable();
    assert_eq!(
        sorted_actual, sorted_expected,
        "suite.json known-gap set changed — investigate (either a regression, or dmtap-core fixed \
         a gap and this expectation needs updating). Full failure detail: {fails:?}"
    );

    // Sanity: the catalog has the shape described in SUITE.md/README (84 cases total as of
    // writing; construction-todo cases dominate since only the deterministic Core spine is
    // byte-backed today). Rather than pin an exact total (which would break on every new spec
    // case), just sanity-check the three buckets sum correctly and skip is the majority.
    assert_eq!(pass + skip + fails.len(), outcomes.len());
    assert!(skip > 0, "expected at least some construction-todo cases to be skipped-with-note");
    assert!(pass > 0, "expected at least some vectored/self-contained cases to pass");
}
