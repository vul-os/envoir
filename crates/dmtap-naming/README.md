# dmtap-naming

DMTAP name→key resolver (spec §3): DNS record parsing, KT-verified resolution (RFC 6962 inclusion proofs, STH signatures, leaf-hash binding, v1 multi-log quorum), and the async-join KeyPackage fetch seam — fail-closed, network-abstracted, unit-testable offline

Part of the [envoir](https://github.com/vul-os/envoir) workspace — the node-only reference
implementation of DMTAP (Decentralized Message Transfer & Access Protocol). The **specification**
lives in the sibling [KOTVA](https://github.com/vul-os/kotva) repo, and so does the substrate it is
built on (`kotva-core`, `kotva-mail`, `kotva-sync`), consumed here under the `dmtap_*` Rust paths
via a cargo dependency-rename.

## What it is

# dmtap-naming — the DMTAP `name → key` resolver (spec §3)

## Dependencies

* `dmtap-core`
* `blake3`
* `thiserror`
* `idna`
* `unicode-normalization`
* `icu_properties`

## Running its tests

```sh
cargo test -p dmtap-naming
```

## Publishing

This crate carries complete publishable metadata (description, license, repository,
homepage, keywords, readme). Publishing to crates.io is nevertheless **blocked upstream**: it
depends on `kotva-core`, which is a git dependency and is not on crates.io, and cargo refuses to
publish a crate with a version-less dependency. `kotva-core` has to be published first.

## License

MIT (see the workspace `LICENSE-MIT`; the workspace as a whole is `MIT OR Apache-2.0`).
