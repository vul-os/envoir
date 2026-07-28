# dmtap-auth

DMTAP-Auth (spec §13) — sovereign, decentralized web login: the native origin-bound login ceremony, cnf/proof-of-possession session binding, and DPoP-style key-bound sessions. Reference implementation of the RP + client crypto core; the WebAuthn/PRF front-end and HTTP layer slot in through documented seams.

Part of the [envoir](https://github.com/vul-os/envoir) workspace — the node-only reference
implementation of DMTAP (Decentralized Message Transfer & Access Protocol). The **specification**
lives in the sibling [KOTVA](https://github.com/vul-os/kotva) repo, and so does the substrate it is
built on (`kotva-core`, `kotva-mail`, `kotva-sync`), consumed here under the `dmtap_*` Rust paths
via a cargo dependency-rename.

## What it is

# dmtap-auth — DMTAP-Auth: sovereign, decentralized web login (spec §13)

## Dependencies

* `dmtap-core`
* `blake3`
* `rand_core`
* `thiserror`

## Running its tests

```sh
cargo test -p dmtap-auth
```

## Publishing

This crate carries complete publishable metadata (description, license, repository,
homepage, keywords, readme). Publishing to crates.io is nevertheless **blocked upstream**: it
depends on `kotva-core`, which is a git dependency and is not on crates.io, and cargo refuses to
publish a crate with a version-less dependency. `kotva-core` has to be published first.

## License

MIT (see the workspace `LICENSE-MIT`; the workspace as a whole is `MIT OR Apache-2.0`).
