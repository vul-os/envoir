# dmtap-mls

DMTAP MLS group layer (spec §5): real RFC 9420 groups via openmls, with the committer epoch-ordering seam

Part of the [envoir](https://github.com/vul-os/envoir) workspace — the node-only reference
implementation of DMTAP (Decentralized Message Transfer & Access Protocol). The **specification**
lives in the sibling [KOTVA](https://github.com/vul-os/kotva) repo, and so does the substrate it is
built on (`kotva-core`, `kotva-mail`, `kotva-sync`), consumed here under the `dmtap_*` Rust paths
via a cargo dependency-rename.

## What it is

# dmtap-mls — the DMTAP MLS group layer (spec §5)

## Dependencies

* `dmtap-core`
* `zeroize`
* `openmls`
* `openmls_rust_crypto`
* `openmls_basic_credential`
* `openmls_traits`
* `blake3`

## Running its tests

```sh
cargo test -p dmtap-mls
```

## Publishing

This crate carries complete publishable metadata (description, license, repository,
homepage, keywords, readme). Publishing to crates.io is nevertheless **blocked upstream**: it
depends on `kotva-core`, which is a git dependency and is not on crates.io, and cargo refuses to
publish a crate with a version-less dependency. `kotva-core` has to be published first.

## License

MIT (see the workspace `LICENSE-MIT`; the workspace as a whole is `MIT OR Apache-2.0`).
