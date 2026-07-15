# envoir-node

Reference implementation of the DMTAP **node** — the whole client side. One binary, installed
on any always-on box; it *is* the mesh.

See the DMTAP spec repo ([`../dmtap/`](../dmtap/)) for the normative specification. This crate
is a **reference, not normative** (spec §10.4).

## Modules (planned)

| Module | Spec | Responsibility |
|--------|------|----------------|
| `identity` | §1 | Keys, device certs, recovery policy + rotation, migration |
| `mote`     | §2 | The MOTE object: build, seal, verify, content-address |
| `naming`   | §3 | name→key resolution, TOFU pinning, key transparency |
| `transport`| §4 | libp2p mesh, mixnet client, reachability ladder, delivery/retry |
| `messaging`| §5 | MLS groups, prekeys/KeyPackages, chat, files (chunked blobs) |
| `privacy`  | §6 | sealed sender, cover traffic, padding, privacy tiers |
| `clients`  | §8 | JMAP; IMAP/POP/SMTP-submission compatibility |
| `abuse`    | §9 | recipient policy, anonymous tokens, PoW, postage |
| `store`    | §2,§5 | encrypted-at-rest mailbox + blob store + device-cluster CRDT |

## Build

```sh
cargo build            # scaffold builds std-only; deps are commented in Cargo.toml
cargo run -- --help
```

## Status

Pre-alpha scaffold. Types mirror the spec; logic is stubbed with `todo!()`/`TODO`. The
dependency stack in `Cargo.toml` is the intended, standards-grounded reference (HPKE/MLS/
libp2p/…); uncomment as each subsystem is implemented.

## Key implementation cautions (from spec grounding)

- **MLS handshake ordering:** Commit/Proposal/Welcome messages require a totally-ordered
  channel per group; they MUST NOT traverse the reordering mixnet. Application messages may.
- **Async join:** use MLS-native KeyPackages + external commits, not a bolted-on PQXDH.
- **Deniability:** MLS is non-repudiable by design; do not claim message deniability without
  engineering it at another layer.
- **Sealed sender** hides the sender from intermediaries but not the IP (the mixnet does that)
  and is metadata-*reduction*, not elimination.
