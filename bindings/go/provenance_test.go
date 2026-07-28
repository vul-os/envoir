package dmtapsync

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// repoMarkers reports which "you are inside a source checkout" markers exist at root. It is the
// signal that separates a moved/deleted crates/ tree (drift — a failure) from a module fetched
// standalone through the Go proxy (nothing to check — a skip). A proxy fetch is rooted in the
// module cache, two levels above which is neither a Cargo workspace nor a git repository.
func repoMarkers(root string) []string {
	var found []string
	for _, m := range []string{"Cargo.toml", ".git", "crates"} {
		if _, err := os.Stat(filepath.Join(root, m)); err == nil {
			found = append(found, m)
		}
	}
	return found
}

// The staleness guard for the committed wasm artifact.
//
// dmtap_sync_abi.wasm is committed, because a Go module has no build step: `go get` runs neither
// `go generate` nor build-abi.sh, so a gitignored artifact makes this module simply uncompilable
// for anyone consuming it normally. Both products that adopted the engine hit that and vendored
// the file by hand instead.
//
// But committing it re-opens the exact drift this repo has already been bitten by once: a stale
// checked-in module kept aborting on free long after src/abi.rs had been fixed, and the failure
// looked intermittent because whether it manifested depended on a String's capacity happening to
// equal its length. Nothing in git ties a binary blob to the source that produced it.
//
// So the blob is tied to its source here instead. wasm_provenance.json records a digest over every
// Rust input that feeds the artifact; this test recomputes that digest and fails when it moves.
// The check deliberately does NOT rebuild — a rebuild would need a Rust toolchain and a wasm32
// target, which a Go consumer has no reason to install, and a guard that hard-fails on a Go-only
// machine would be worse than no guard at all. Hashing source inputs needs nothing but the files.
//
// When it fails, the fix is to rebuild and re-record, not to edit the digest:
//
//	crates/dmtap-sync-wasm/build-abi.sh
//	(cd bindings/go && go run ./internal/genprovenance)   # no go.mod at the repo root
type provenance struct {
	SourceDigest   string            `json:"source_digest"`
	ArtifactSHA256 string            `json:"artifact_sha256"`
	ArtifactBytes  int               `json:"artifact_bytes"`
	BuiltFrom      string            `json:"built_from_commit"`
	Rustc          string            `json:"rustc"`
	Sources        map[string]string `json:"sources"`
}

func loadProvenance(t *testing.T) provenance {
	t.Helper()
	raw, err := os.ReadFile("wasm_provenance.json")
	if err != nil {
		t.Fatalf("reading wasm_provenance.json: %v", err)
	}
	var p provenance
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("parsing wasm_provenance.json: %v", err)
	}
	return p
}

// TestEmbeddedArtifactMatchesProvenance catches a committed blob that no longer matches the bytes
// recorded for it — corruption, a partial write, or a hand-edited file.
func TestEmbeddedArtifactMatchesProvenance(t *testing.T) {
	p := loadProvenance(t)
	sum := sha256.Sum256(engineWasm)
	if got := hex.EncodeToString(sum[:]); got != p.ArtifactSHA256 {
		t.Fatalf("embedded artifact does not match its provenance record:\n  embedded: %s (%d bytes)\n  recorded: %s (%d bytes)\nRebuild and re-record: crates/dmtap-sync-wasm/build-abi.sh",
			got, len(engineWasm), p.ArtifactSHA256, p.ArtifactBytes)
	}
}

// TestArtifactIsNotStaleAgainstSource is the guard that matters: it fails when the Rust source has
// moved since the artifact was built, which is the drift that previously shipped a real bug.
//
// # Absent sources: two different situations, and only one of them is benign
//
// This test used to skip on a single condition — `crates/dmtap-sync-wasm` is not there — which
// conflates a consumer who fetched only the Go module through the proxy (nothing to check, nothing
// they could fix) with a checkout in which the Rust *moved*. The second is precisely the event this
// repo is preparing for: `dmtap-sync` and `dmtap-sync-wasm` are being extracted into their own
// crate. Under the old condition, the day that happens is the day this guard goes permanently green
// by doing nothing, which is the worst available outcome for a staleness check.
//
// So the two are told apart by whether a *repo* is present around this module. A standalone module
// fetch is rooted in the module cache and has no Cargo workspace and no git directory above it; an
// envoir checkout has both. Sources missing with a repo around them is drift, and drift fails.
//
// The benign skip states its reason on stderr as well as through `t.Skip`. Be precise about how far
// that gets: `go test` buffers a package's output and DISCARDS it when the package passes, so under
// a bare `go test` the notice is not shown and the package still prints only `ok` — measured, not
// assumed. It is shown under `-v`, `-json`, and any wrapper built on those (gotestsum, CI). There
// is no channel a passing Go test can write to that a bare `go test` will display; the only way to
// be unconditionally loud is to fail, and failing a consumer who legitimately has no Rust tree
// would be wrong. So: loud where anything is looking, and the drift cases above — which are the
// ones that can actually hide a bug — fail rather than skip.
func TestArtifactIsNotStaleAgainstSource(t *testing.T) {
	p := loadProvenance(t)
	root := filepath.Join("..", "..")

	if _, err := os.Stat(filepath.Join(root, "crates", "dmtap-sync-wasm")); err != nil {
		if markers := repoMarkers(root); len(markers) > 0 {
			t.Fatalf("the Rust sources this artifact was built from are GONE, but this is a repo checkout (%s present).\n"+
				"  looked for: %s\n"+
				"  stat said:  %v\n"+
				"If the crates were moved or extracted, this binding must follow them: repoint it at their new home and re-record with\n"+
				"  (cd bindings/go && go run ./internal/genprovenance)\n"+
				"Until then the committed dmtap_sync_abi.wasm is unverifiable, and an unverifiable blob is the exact failure mode this guard exists for.",
				strings.Join(markers, ", "), filepath.Join(root, "crates", "dmtap-sync-wasm"), err)
		}
		// Genuinely standalone: no crates/, and no repo around us either. Nothing to check and
		// nothing the consumer could do about it. Say so on stderr, which `go test` always shows.
		fmt.Fprintf(os.Stderr,
			"\nNOTICE: %s SKIPPED — Rust sources not present and no envoir checkout around this module\n"+
				"        (looked for %s). The committed dmtap_sync_abi.wasm is NOT being checked against the\n"+
				"        source that produced it in this run; only its own sha256 is (see\n"+
				"        TestEmbeddedArtifactMatchesProvenance). This is expected for a plain module fetch.\n\n",
			t.Name(), filepath.Join(root, "crates", "dmtap-sync-wasm"))
		t.Skip("Rust sources not present (module fetched standalone) — nothing to check against")
	}

	paths := make([]string, 0, len(p.Sources))
	for path := range p.Sources {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	h := sha256.New()
	var missing, changed []string
	for _, path := range paths {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			missing = append(missing, path)
			continue
		}
		h.Write([]byte(path))
		h.Write(data)
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != p.Sources[path] {
			changed = append(changed, path)
		}
	}

	if len(missing) > 0 {
		t.Fatalf("provenance lists sources that no longer exist: %v\nIf they were renamed or removed, rebuild and re-record.", missing)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != p.SourceDigest {
		t.Fatalf("dmtap_sync_abi.wasm is STALE against its source.\n  changed: %v\n  recorded digest: %s\n  current digest:  %s\nThe committed artifact was built from different code than is checked out. Rebuild it:\n  crates/dmtap-sync-wasm/build-abi.sh\nDo not edit wasm_provenance.json to silence this — the whole point is that the blob and the source agree.",
			changed, p.SourceDigest, got)
	}
}
