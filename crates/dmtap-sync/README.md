# dmtap-sync — the shared sync engine

DMTAP substrate capability ③, **Sync** ([`substrate/SYNC.md`](../../../kotva/substrate/SYNC.md)): a
**signed, deterministic, multi-author CRDT operation algebra** with range-Merkle reconciliation,
first-class signed snapshots, and sparse namespace sync.

**Not on crates.io yet** — see "Extraction status" below for exactly what is in the way. Adopters
today depend on it by git, which is the problem this crate is being packaged to solve, not a
recommendation.

Six CRDT types (§4.3–§4.8) — OR-Set, HLC-LWW register, remove-wins death certificate, PN-counter,
RGA sequence, cycle-safe movable tree — plus a hybrid logical clock (§3), per-op RFC 9052
`COSE_Sign1` authenticity (§4.1), canonical six-section observable-state snapshot roots (§6.1), and
the §5.3 range-Merkle fingerprint fold. **std + `dmtap-core` only**; this crate adds no third-party
dependency of its own, and `#![forbid(unsafe_code)]` is on the crate root.

The module map lives in the crate docs (`cargo doc -p dmtap-sync --open`) rather than being
duplicated here, where it would rot.

---

## What this is *for*

It is the one library in this workspace that other products consume, and it exists because several
of them had each written their own HLC, their own op encoder and their own merge — which converge
with each other exactly as well as separate teams reading the same prose carefully do. Adopting a
specified algebra replaces "we believe these agree" with frozen bytes that either match or do not.

Inside this repo the consumer is `envoir-node`'s `syncserve`. Outside it, adopters depend on this
directory by git rev; that is the arrangement "Extraction status" below is about ending, and this
crate cannot see or assert which revs they are on.

## What it deliberately is not

* **Transport.** §5.2's pull/push protocol is the host's job. No sockets, no discovery. Fast-join
  tells you what to fetch; you perform the fetch.
* **Persistence.** `SyncState` is in-memory. Bring your own store; replay or fast-join on load.
* **Identity or admission policy.** `check_admitted` tests membership in a list *you* supply. It
  resolves no `DeviceCert` chain, no namespace policy object, no revocation — that is capability ①.

## Honest limits

Carried over from the crate docs, because they belong in front of an adopter:

Sync is **not** sealed-sender: every op carries its author and HLC, visible to every replica in the
namespace — multi-author convergence needs attributable ops. A compromised author key can write ops
until revoked, and because replicated history is durable a malicious write must be *superseded* by a
later op, not "deleted". A trusted-checkpoint snapshot trusts its signer for pre-`covers` history
until backfilled and recomputed.

One more, and it is a deployment obligation rather than a runtime check: this engine is
`ext-value` **profile 2** (`EXT_VALUE_PROFILE`), a widening over §4.1's original narrower prose. A
mixed deployment diverges by *rejection* — an engine still on profile 1 refuses, with `0x0A03`, an
op an updated engine accepts — and nothing here can detect that from the other end. See the crate
docs and `SYNC.md` §4.1.2's `sync-1/ext-value-2` sub-token.

---

## The proof

```sh
cargo test -p dmtap-sync                                 # 52 unit + 6 convergence properties
cargo test -p dmtap-clustersync --test sync_parity       # agreement with the §5.6 reference
cargo test -p conformance-runner --test sync_vectors     # the 24 frozen SYNC.md §10 vectors
```

`tests/convergence.rs` asserts the algebraic laws directly — commutativity, associativity and
idempotence of merge over the *observable bytes*, and tree acyclicity under every arrival order.

`sync_parity` lives in `dmtap-clustersync` rather than here, on purpose; see the note at the bottom
of this crate's `Cargo.toml`.

The vector gate reads the frozen `sync_vectors.json` from the sibling **KOTVA** spec repo (default
`../kotva`; override with `KOTVA_DIR`, which the JS and Go harnesses read too). Note its posture,
because it still differs from the other two harnesses: without that checkout it **skips**, where
`crates/dmtap-sync-wasm/tests/native_trace.rs` and `bindings/go/vectors_test.go` both hard-fail
instead. The skip is no longer silent — it prints that zero of the 24 vectors ran and what that
leaves unverified — but a green `cargo test` on a machine with no sibling checkout still does not
by itself mean 24/24 ran. **In CI it does**: `.github/workflows/ci.yml` checks KOTVA out beside the
repo and fails closed before any test runs if that checkout is incomplete.

Two further surfaces execute the **same** compiled algebra and are diffed byte-for-byte against a
trace recorded from this crate: `crates/dmtap-sync-wasm` (browser/JS) and `bindings/go` (pure Go,
via wazero).

---

## Extraction status

This crate is being prepared to become **its own published crate** rather than a directory inside a
product. Every adopter's manifest currently reads `git = "https://github.com/vul-os/envoir"`, which
imports a mail node in order to get a CRDT library — the suite rule that products never import each
other, violated by exactly one line each.

**Done — it no longer reaches into envoir:**

* No dependency, not even a dev one, on any envoir-local crate. The §5.6 parity proof was moved to
  `crates/dmtap-clustersync/tests/sync_parity.rs`, which dev-depends on this crate rather than the
  other way round. Verify with `cargo tree -p dmtap-sync --edges normal,dev`.
* Publishable metadata: real version, real `repository`, `license`, `description`, `keywords`,
  `categories`, and this file.
* No envoir type, module or path appears in `src/`.

**Not done — what still has to change on the day it moves:**

1. **`dmtap-core` is inherited from the workspace** (`{ workspace = true }`), resolving to
   `kotva-core`, tag-pinned at `core-v0.2.0` from the KOTVA repo. KOTVA is a spec/substrate repo
   rather than a product, so this is not a product-to-product import — but a standalone crate cannot
   inherit from a workspace it has left, so that line becomes an explicit dependency.
2. **Publishing to crates.io is blocked upstream, not here.** `kotva-core` is a *git* dependency and
   is not on crates.io; cargo refuses to publish a crate with a version-less dependency. This is not
   fixable in this repo — `kotva-core` has to be published first. See "Publish readiness" below.
3. **The 24-vector gate lives in `crates/conformance-runner`** (envoir), not here. An extracted
   crate wants its own copy of that gate, or the vectors vendored, or it ships without the gate that
   makes its central claim checkable.
4. **Two doc comments in `src/lib.rs` name `envoir-node`'s `syncserve`** as the place capability
   negotiation happens. They are cross-references to a *consumer*, not dependencies, and nothing
   breaks if they dangle — but they will dangle.
5. **`bindings/go`'s Go module path is `github.com/vul-os/envoir/bindings/go`.** Moving it renames
   the import path, which is a breaking change for every Go adopter, independent of anything Cargo
   does.

### Publish readiness, measured

`cargo publish --dry-run -p dmtap-sync`, as of this writing:

```
error: failed to verify manifest at .../crates/dmtap-sync/Cargo.toml

Caused by:
  all dependencies must have a version requirement specified when publishing.
  dependency `kotva-core` does not specify a version
```

That is the whole remaining blocker, and it is item 2 above. To confirm nothing *else* is missing,
the same dry-run was re-run in a throwaway copy of the workspace with a `version` added alongside
the `kotva-core` git pin: it gets past manifest verification and into `Packaging dmtap-sync
v0.1.0`, then stops only at `no matching package named kotva-core found ... location searched:
crates.io index`. Nothing in this crate's own manifest is missing. The same is true of
`dmtap-sync-wasm`.
