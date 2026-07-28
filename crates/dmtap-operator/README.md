# dmtap-operator

Reference DMTAP operator machinery: a bounded/idempotent usage-ingest queue, flat quotas, fail-closed gateway authorization (spec §12.2), and gateway-domain DNS record automation — implements dmtap-seam with no billing logic

Part of the [envoir](https://github.com/vul-os/envoir) workspace — the node-only reference
implementation of DMTAP (Decentralized Message Transfer & Access Protocol). The **specification**
lives in the sibling [KOTVA](https://github.com/vul-os/kotva) repo, and so does the substrate it is
built on (`kotva-core`, `kotva-mail`, `kotva-sync`), consumed here under the `dmtap_*` Rust paths
via a cargo dependency-rename.

## What it is

# dmtap-operator — reference machinery for a third-party DMTAP operator

## Dependencies

* `dmtap-seam`
* `serde_json`
* `thiserror`
* `ureq`

## Running its tests

```sh
cargo test -p dmtap-operator
```

## Publishing

This crate carries complete publishable metadata (description, license, repository,
homepage, keywords, readme). Publishing to crates.io is nevertheless **blocked upstream**: it
depends on `kotva-core`, which is a git dependency and is not on crates.io, and cargo refuses to
publish a crate with a version-less dependency. `kotva-core` has to be published first.

## License

MIT (see the workspace `LICENSE-MIT`; the workspace as a whole is `MIT OR Apache-2.0`).
