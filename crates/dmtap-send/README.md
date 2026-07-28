# dmtap-send

Envoir Send — a Resend-style programmatic mail-send API built on DMTAP capability tokens: an API key IS a scoped, rotatable, revocable UCAN-style capability (spec §13.5.1), and a send builds + seals a real MOTE to the resolved recipient (spec §2). A sovereign/private Resend.

Part of the [envoir](https://github.com/vul-os/envoir) workspace — the node-only reference
implementation of DMTAP (Decentralized Message Transfer & Access Protocol). The **specification**
lives in the sibling [KOTVA](https://github.com/vul-os/kotva) repo, and so does the substrate it is
built on (`kotva-core`, `kotva-mail`, `kotva-sync`), consumed here under the `dmtap_*` Rust paths
via a cargo dependency-rename.

## What it is

# dmtap-send — Envoir Send

## Dependencies

* `dmtap-core`
* `serde`
* `serde_json`
* `rand_core`
* `thiserror`

## Running its tests

```sh
cargo test -p dmtap-send
```

## Publishing

This crate carries complete publishable metadata (description, license, repository,
homepage, keywords, readme). Publishing to crates.io is nevertheless **blocked upstream**: it
depends on `kotva-core`, which is a git dependency and is not on crates.io, and cargo refuses to
publish a crate with a version-less dependency. `kotva-core` has to be published first.

## License

MIT (see the workspace `LICENSE-MIT`; the workspace as a whole is `MIT OR Apache-2.0`).
