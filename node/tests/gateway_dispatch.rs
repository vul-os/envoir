//! Proves the `envoir-node gateway` / `--gateway` privilege-separation seam actually launches a
//! separate gateway process — that node execs the configured binary (default sibling location or
//! `ENVOIR_GATEWAY_BIN` override), honours the `--gateway` alias, and forwards argv exactly — as
//! well as the fail-closed path when no gateway binary is reachable at all. See `node/src/main.rs`'s
//! `run_gateway_mode` / `locate_gateway_binary` for the mechanism and its `TODO(privsep)`.
//!
//! The real `envoir-gateway` binary itself no longer lives in this workspace — the legacy SMTP/
//! IMAP/POP3 bridge moved out to the Pier broker repo (this repo is node-only; see
//! `pier/crates/pier-gateway/Cargo.toml`). A standing directive keeps products STANDALONE — envoir's
//! CI must not check out and build Pier just to prove envoir's own dispatch logic. And these tests
//! are about envoir's dispatch (does `node` exec the *configured* binary and forward argv
//! correctly?), not about what a real gateway then does with those arguments. So instead of an
//! external Pier build, the 4 dispatch tests below each write a tiny POSIX-shell **fixture**
//! binary of their own into a private tempdir at test time, point `ENVOIR_GATEWAY_BIN` at it, and
//! assert on what actually got exec'd/forwarded. That proves the real property (envoir-node's own
//! exec + argv-forwarding logic) with zero external binary and no cross-repo checkout, so they run
//! unconditionally in CI. They are `#[cfg(unix)]`: the fixture is a `#!/sh` script exec'd directly,
//! which matches CI (`ubuntu-latest`, see `.github/workflows/ci.yml`, no Windows runner) and every
//! POSIX dev machine this repo builds on; `missing_gateway_binary_fails_closed_...` below needs no
//! fixture and stays fully cross-platform.

#![cfg(unix)]

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// A fresh, private scratch dir under the OS temp dir, unique per call. No `tempfile`/`tempdir`
/// crate is a dependency of this workspace (checked `node/Cargo.toml` — no `[dev-dependencies]`
/// section at all) and none should be added just for this; this follows the exact same
/// process-id + nanosecond-timestamp pattern already used by `node/tests/daemon.rs` and
/// `node/tests/durability.rs`'s siblings for the same reason.
fn scratch_dir(tag: &str) -> PathBuf {
    let n = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let p = std::env::temp_dir()
        .join(format!("envoir-gateway-dispatch-{}-{}-{}", std::process::id(), tag, n));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Writes an executable POSIX-shell fixture at `dir/envoir-gateway` that, on a `version` argv[0],
/// prints `marker` to stdout and exits 0 — otherwise exits 0 with no output. Used by the 3 tests
/// that only need to prove *which* binary got exec'd (via a distinguishing marker in its output),
/// not what argv it received.
fn write_marker_fixture(dir: &Path, marker: &str) -> PathBuf {
    let script = dir.join("envoir-gateway");
    let body = format!(
        "#!/bin/sh\n\
         if [ \"$1\" = version ]; then\n\
         \x20\x20echo '{marker}'\n\
         fi\n\
         exit 0\n"
    );
    write_executable(&script, &body);
    script
}

/// Writes an executable POSIX-shell fixture at `dir/envoir-gateway` that unconditionally records
/// its exact argv, one per line, into `argv_log` (truncating any prior content), then exits 0.
/// Used by the argument-forwarding test — reading `argv_log` back proves precisely which arguments
/// arrived, not merely that some process ran.
fn write_argv_logging_fixture(dir: &Path, argv_log: &Path) -> PathBuf {
    let script = dir.join("envoir-gateway");
    let body = format!(
        "#!/bin/sh\n\
         : > '{log}'\n\
         for a in \"$@\"; do printf '%s\\n' \"$a\" >> '{log}'; done\n\
         exit 0\n",
        log = argv_log.display()
    );
    write_executable(&script, &body);
    script
}

fn write_executable(path: &Path, body: &str) {
    let mut f = std::fs::File::create(path).expect("create fixture script");
    f.write_all(body.as_bytes()).expect("write fixture script");
    drop(f);
    // The executable bit is not assumed — set it explicitly (a plain `File::create` on Unix
    // typically yields 0o644, which `exec` refuses with ENOEXEC/EACCES).
    let mut perms = std::fs::metadata(path).expect("stat fixture script").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).expect("chmod fixture script");
}

#[test]
fn gateway_subcommand_execs_the_dedicated_gateway_binary() {
    let dir = scratch_dir("subcommand");
    let fixture = write_marker_fixture(&dir, "envoir-gateway TEST-FIXTURE-MARKER");

    let output = Command::new(env!("CARGO_BIN_EXE_envoir-node"))
        .arg("gateway")
        .arg("version")
        .env("ENVOIR_GATEWAY_BIN", &fixture)
        .output()
        .expect("failed to run envoir-node gateway version");

    let stdout = String::from_utf8_lossy(&output.stdout);
    // The marker can only appear if `envoir-node gateway` actually exec'd our fixture and let its
    // own stdout through untouched — proving dispatch reached a genuinely separate process, not a
    // node-side stub that merely claims success.
    assert!(
        output.status.success() && stdout.contains("TEST-FIXTURE-MARKER"),
        "expected the fixture gateway's own version output, got status {:?} stdout: {stdout:?} \
         stderr: {:?}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn dash_dash_gateway_flag_is_accepted_as_an_alias() {
    let dir = scratch_dir("alias-flag");
    let fixture = write_marker_fixture(&dir, "envoir-gateway TEST-FIXTURE-MARKER");

    let output = Command::new(env!("CARGO_BIN_EXE_envoir-node"))
        .arg("--gateway")
        .arg("version")
        .env("ENVOIR_GATEWAY_BIN", &fixture)
        .output()
        .expect("failed to run envoir-node --gateway version");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("TEST-FIXTURE-MARKER"),
        "expected the fixture gateway's own version output via --gateway, got status {:?} \
         stdout: {stdout:?} stderr: {:?}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn gateway_dispatch_forwards_arguments_unchanged() {
    let dir = scratch_dir("forwarding");
    let argv_log = dir.join("argv.log");
    let fixture = write_argv_logging_fixture(&dir, &argv_log);

    // Multiple args, including one containing spaces — proves envoir-node forwards argv[2..] to
    // the child exactly as received (no re-tokenization / word-splitting / reordering), not just
    // "the child ran with roughly the right arguments".
    let output = Command::new(env!("CARGO_BIN_EXE_envoir-node"))
        .arg("gateway")
        .arg("personal")
        .arg("/some/config path with spaces.toml")
        .arg("--flag")
        .arg("value")
        .env("ENVOIR_GATEWAY_BIN", &fixture)
        .output()
        .expect("failed to run envoir-node gateway personal ...");
    assert!(
        output.status.success(),
        "fixture exec failed: status {:?} stderr: {:?}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let logged = std::fs::read_to_string(&argv_log)
        .unwrap_or_else(|e| panic!("fixture never wrote {}: {e}", argv_log.display()));
    let got: Vec<&str> = logged.lines().collect();
    assert_eq!(
        got,
        vec!["personal", "/some/config path with spaces.toml", "--flag", "value"],
        "argv forwarded to the gateway binary did not match exactly what was passed to \
         `envoir-node gateway ...`"
    );
}

#[test]
fn envoir_gateway_bin_override_is_honored() {
    // Two DISTINCT fixtures with different markers, in two DIFFERENT locations — proving the
    // *value* of ENVOIR_GATEWAY_BIN determines which binary executes (not just that setting it to
    // *something* makes gateway mode succeed, which the previous two tests already establish).
    let dir_a = scratch_dir("override-a");
    let fixture_a = write_marker_fixture(&dir_a, "envoir-gateway FIXTURE-A");
    let dir_b = scratch_dir("override-b");
    let fixture_b = write_marker_fixture(&dir_b, "envoir-gateway FIXTURE-B");

    for (fixture, expect_marker, other_marker) in
        [(&fixture_a, "FIXTURE-A", "FIXTURE-B"), (&fixture_b, "FIXTURE-B", "FIXTURE-A")]
    {
        let output = Command::new(env!("CARGO_BIN_EXE_envoir-node"))
            .arg("gateway")
            .arg("version")
            .env("ENVOIR_GATEWAY_BIN", fixture)
            .output()
            .expect("failed to run envoir-node gateway version with an explicit override");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains(expect_marker),
            "expected {expect_marker} from ENVOIR_GATEWAY_BIN={}, got status {:?} stdout: \
             {stdout:?}",
            fixture.display(),
            output.status
        );
        assert!(
            !stdout.contains(other_marker),
            "got the OTHER fixture's marker ({other_marker}) — ENVOIR_GATEWAY_BIN was not honored"
        );
    }
}

#[test]
fn missing_gateway_binary_fails_closed_with_a_clear_error_and_nonzero_exit() {
    // ENVOIR_GATEWAY_BIN pointed at a path that does not exist must fail loudly and refuse to
    // fall through to any node-side behavior — never a silent no-op, never node identity code.
    let output = Command::new(env!("CARGO_BIN_EXE_envoir-node"))
        .arg("gateway")
        .arg("version")
        .env("ENVOIR_GATEWAY_BIN", "/nonexistent/path/envoir-gateway-does-not-exist")
        .output()
        .expect("failed to run envoir-node gateway version");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("gateway") && stderr.contains("ENVOIR_GATEWAY_BIN"),
        "expected a clear --gateway/ENVOIR_GATEWAY_BIN error, got stderr: {stderr:?}"
    );
}
