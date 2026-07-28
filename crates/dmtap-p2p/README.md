# dmtap-p2p

Envoir libp2p mesh transport for DMTAP (spec §4): Kademlia, request-response, relay + DCUtR, over the node's Transport trait

Part of the [envoir](https://github.com/vul-os/envoir) workspace — the node-only reference
implementation of DMTAP (Decentralized Message Transfer & Access Protocol). The **specification**
lives in the sibling [KOTVA](https://github.com/vul-os/kotva) repo, and so does the substrate it is
built on (`kotva-core`, `kotva-mail`, `kotva-sync`), consumed here under the `dmtap_*` Rust paths
via a cargo dependency-rename.

## What it is

# dmtap-p2p — the real libp2p mesh transport (spec §4)

## Dependencies

* `envoir-node`
* `dmtap-core`
* `libp2p`
* `tokio`
* `futures`
* `serde`
* `serde_bytes`
* `thiserror`

## Running its tests

```sh
cargo test -p dmtap-p2p
```

## Publishing

This crate carries complete publishable metadata (description, license, repository,
homepage, keywords, readme). Publishing to crates.io is nevertheless **blocked upstream**: it
depends on `kotva-core`, which is a git dependency and is not on crates.io, and cargo refuses to
publish a crate with a version-less dependency. `kotva-core` has to be published first.

## License

MIT (see the workspace `LICENSE-MIT`; the workspace as a whole is `MIT OR Apache-2.0`).
