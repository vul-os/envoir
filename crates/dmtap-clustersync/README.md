# dmtap-clustersync

DMTAP device-cluster sync (spec §5.6 / §18.6.3) — the ClusterSyncFrame/ClusterOp wire objects, range-based Merkle set-reconciliation, hash-chained journal backfill, and the OR-Set + HLC-LWW CRDT merge that converges an owner's personal device cluster with no primary and no central server

Part of the [envoir](https://github.com/vul-os/envoir) workspace — the node-only reference
implementation of DMTAP (Decentralized Message Transfer & Access Protocol). The **specification**
lives in the sibling [KOTVA](https://github.com/vul-os/kotva) repo, and so does the substrate it is
built on (`kotva-core`, `kotva-mail`, `kotva-sync`), consumed here under the `dmtap_*` Rust paths
via a cargo dependency-rename.

## What it is

# dmtap-clustersync — DMTAP device-cluster sync (§5.6 / §18.6.3)

## Dependencies

* `dmtap-core`

## Running its tests

```sh
cargo test -p dmtap-clustersync
```

## Publishing

This crate carries complete publishable metadata (description, license, repository,
homepage, keywords, readme). Publishing to crates.io is nevertheless **blocked upstream**: it
depends on `kotva-core`, which is a git dependency and is not on crates.io, and cargo refuses to
publish a crate with a version-less dependency. `kotva-core` has to be published first.

## License

MIT (see the workspace `LICENSE-MIT`; the workspace as a whole is `MIT OR Apache-2.0`).
