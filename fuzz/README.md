# dmtap-core fuzz targets

`cargo-fuzz` (libFuzzer) targets over `dmtap-core`'s canonical-CBOR **decoders** — the real
attack surface: every one of these functions is called with fully attacker-controlled bytes
before any signature is checked. One target per decodable wire object (§18):

| target | decodes |
|---|---|
| `identity` | `dmtap_core::identity::Identity` |
| `device_cert` | `dmtap_core::identity::DeviceCert` |
| `recovery_policy` | `dmtap_core::identity::RecoveryPolicy` |
| `move_record` | `dmtap_core::identity::MoveRecord` |
| `envelope` | `dmtap_core::mote::Envelope` |
| `payload` | `dmtap_core::mote::Payload` |
| `manifest` | `dmtap_core::mote::Manifest` |
| `mix_node_descriptor` | `dmtap_core::mixnet::MixNodeDescriptor` |
| `mix_directory` | `dmtap_core::mixnet::MixDirectory` |
| `domain_directory` | `dmtap_core::directory::DomainDirectory` |
| `deniable_prekey_bundle` | `dmtap_core::deniable::DeniablePrekeyBundle` |
| `deniable_frame` | `dmtap_core::deniable::DeniableFrame` (both `Init`/`Message` discriminators) |
| `deniable_payload` | `dmtap_core::deniable::DeniablePayload` |

## Contract each target enforces (`fuzz_targets/common.rs`)

1. **Never panic / never UB** on any input. This is checked simply by calling the decoder inside
   the fuzz harness; a Rust panic or a sanitizer-caught UB *is* the crash libFuzzer reports.
2. Any `Ok(_)` decode result **re-encodes to byte-identical input** — canonical-form idempotence
   (§18.1.1). A decoder that accepts a non-canonical encoding of the same semantic object is a
   bug: two implementations (or the same node at two points in time) could disagree about whether
   two different byte-strings are "the same" object.

Property 2 is checked **non-fatally by default** (logged once to stderr) and **fatally** when the
environment variable `DMTAP_FUZZ_STRICT_CANONICAL` is set — see "Known finding" below for why.

## Running

```sh
# one target, short smoke run (what the verification gate uses):
cargo +nightly fuzz run envelope -- -max_total_time=5

# a real campaign (long-running):
cargo +nightly fuzz run envelope

# just prove everything builds, without running:
cargo +nightly fuzz build
```

A small seed corpus (`corpus/<target>/`) is checked in — the exact bytes from
`dmtap-core/vectors.json`'s `cbor_*` vectors (plus two hand-generated seeds for
`recovery_policy`/`move_record`, which have no committed vector today) — so every target starts
from known-valid, canonical input rather than an empty corpus.

## Known finding: canonical-form is not yet enforced at decode time

Running any target for even a few seconds with `DMTAP_FUZZ_STRICT_CANONICAL=1` set reliably finds
a "crash" — this is not a bug in the fuzz harness. `dmtap_core::cbor::decode` (the shared
low-level canonical-CBOR primitive every `from_det_cbor` is built on) currently rejects duplicate
keys, floats, CBOR `null`/tags/undefined — but does **not** reject non-shortest-form integers,
indefinite-length items, or a map whose keys are not in bytewise-ascending order (see
`dmtap-core/src/cbor.rs`'s `decode`/`from_map`). Every object decoder reads fields by key via
`Fields::req`/`take`, which is independent of a map's on-the-wire key order or how long-winded
each integer's encoding is — so re-ordering an object's top-level keys, or re-encoding one of its
integers in a longer-than-minimal form, still decodes to a bit-for-bit-identical semantic object,
whose canonical re-encoding (`det_cbor()`) then differs from the input bytes that were accepted.

This is the same root cause behind three specific, hand-picked gaps the sibling
`crates/conformance-runner` reports against the `../dmtap` spec repo's conformance-suite catalog
(`DMTAP-CBOR-05` non-shortest-int, `DMTAP-CBOR-06` indefinite-length, `DMTAP-CBOR-07`
descending-key-order — all status `self-contained`, all currently FAIL) — fuzzing here shows the
same gap is **systemic**: it reaches every wire object in the crate, not just the low-level `Cv`
primitive those three cases exercise directly.

**Why this isn't fixed here:** this task's scope is limited to `crates/conformance-runner/`,
`fuzz/`, and new test files under `crates/dmtap-core/tests/` — `dmtap-core/src/cbor.rs` itself is
out of bounds. The fix (when someone picks it up) is at the `cbor::decode`/`from_map` layer:
track each integer's *encoded byte length* against `write_head`'s shortest-form rule, and require
`Cv::Map` keys to already be in bytewise-ascending order on input (mirroring the ordering `encode`
already produces), rejecting otherwise with `CborError::Malformed`. Once that lands, flip this
harness back to `DMTAP_FUZZ_STRICT_CANONICAL=1`-by-default (or just remove the toggle) — the
default-mode smoke run will then need to stay green with the stricter check, which is exactly the
regression protection this harness is for.
