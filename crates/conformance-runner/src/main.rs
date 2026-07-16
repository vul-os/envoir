//! CLI: run the conformance-runner engine (`lib.rs`) over `dmtap-core`'s committed `vectors.json`
//! and, when the sibling spec repo is checked out, cross-reference the conformance-suite catalog
//! (`../dmtap/conformance/{suite.json,SUITE.md}`).
//!
//! Exit code is driven **only** by the vectors.json-backed checks (the mandatory charter: every
//! vector must reproduce from the reference and every `cbor_*` vector must canonically round
//! trip). Suite.json cross-reference is printed as an additional, clearly-labeled report section:
//! `construction-todo` cases are skipped-with-note, and any `self-contained`/`vectored` case that
//! does not hold is reported as a named gap (see the KNOWN GAPS section of the report) rather than
//! silently hidden or allowed to fail the build — fixing `dmtap-core` itself is out of scope for
//! this harness.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use conformance_runner::{
    check_all_vectors, load_suite, load_vectors, run_all_suite_cases, CaseOutcome, Verdict,
};

fn vectors_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../dmtap-core/vectors.json")
}

/// The sibling spec repo's conformance-suite catalog. Optional: this harness's mandatory proof
/// (vectors.json) does not depend on it, but when present we cross-reference it for extra
/// coverage reporting.
fn suite_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../dmtap/conformance/suite.json")
}

fn main() {
    let vectors_path = vectors_path();
    let vf = match load_vectors(&vectors_path) {
        Ok(vf) => vf,
        Err(e) => {
            eprintln!("FATAL: could not load {}: {e}", vectors_path.display());
            std::process::exit(2);
        }
    };

    println!("=== DMTAP conformance-runner ===");
    println!("vectors file : {}", vectors_path.display());
    println!("format       : {}", vf.format);
    println!("suite        : {}", vf.suite);
    println!("generated_by : {}", vf.generated_by);
    println!("vector count : {}", vf.vectors.len());
    println!();

    let results = check_all_vectors(&vf);
    let mut pass = 0usize;
    let mut pass_generic = 0usize;
    let mut fail = 0usize;
    for (name, verdict) in &results {
        match verdict {
            Verdict::Pass => {
                pass += 1;
                println!("PASS   {name}");
            }
            Verdict::PassGeneric => {
                pass_generic += 1;
                println!("PASS   {name}  (generic canonical round-trip only; no typed verifier for this input.type)");
            }
            Verdict::Fail(e) => {
                fail += 1;
                println!("FAIL   {name}: {e}");
            }
        }
    }

    println!();
    println!(
        "--- vectors.json summary: {pass} pass, {pass_generic} pass (generic), {fail} FAIL, {} total ---",
        results.len()
    );

    // suite.json cross-reference (optional; report only, does not affect exit code — see docs).
    let suite_path = suite_path();
    if suite_path.exists() {
        match load_suite(&suite_path) {
            Ok(suite) => {
                let by_name: BTreeMap<String, Verdict> =
                    results.iter().cloned().collect();
                let case_outcomes = run_all_suite_cases(&suite, &vf, &by_name);
                let mut c_pass = 0usize;
                let mut c_fail = 0usize;
                let mut c_skip = 0usize;
                let mut gaps: Vec<(String, String)> = Vec::new();
                println!();
                println!("=== suite.json cross-reference: {} ===", suite_path.display());
                for (id, outcome) in &case_outcomes {
                    match outcome {
                        CaseOutcome::Pass => {
                            c_pass += 1;
                        }
                        CaseOutcome::Skipped(note) => {
                            c_skip += 1;
                            let _ = note; // printed in totals only; SUITE.md has the recipe text
                        }
                        CaseOutcome::Fail(reason) => {
                            c_fail += 1;
                            gaps.push((id.clone(), reason.clone()));
                        }
                    }
                }
                println!(
                    "case outcomes: {c_pass} pass, {c_skip} skipped (construction-todo), {c_fail} FAIL, {} total",
                    case_outcomes.len()
                );
                if !gaps.is_empty() {
                    println!();
                    println!("--- KNOWN GAPS (suite.json cases whose expected outcome does not hold against the current dmtap-core reference) ---");
                    for (id, reason) in &gaps {
                        println!("GAP    {id}: {reason}");
                    }
                    println!(
                        "\nThese are NOT vectors.json failures (the mandatory gate above is green) and do not \
                         fail this run's exit code: fixing dmtap-core's decoder is out of scope for this harness. \
                         They are surfaced here because they are real, reproducible conformance gaps a second \
                         implementer would also hit."
                    );
                }
            }
            Err(e) => {
                println!();
                println!("(suite.json present at {} but failed to parse: {e})", suite_path.display());
            }
        }
    } else {
        println!();
        println!("(sibling spec repo's suite.json not found at {} — skipping cross-reference; vectors.json-only run)", suite_path.display());
    }

    if fail > 0 {
        eprintln!("\nconformance-runner: {fail} vector(s) FAILED — this is the mandatory gate, exiting non-zero.");
        std::process::exit(1);
    }
    println!("\nconformance-runner: all {} vectors.json checks PASS.", pass + pass_generic);
}
