# downgrade-tests

Downgrade & negative test suite proving DMTAP's §10.7 fail-closed invariants, driven entirely through dmtap-core's public API

Part of the [envoir](https://github.com/vul-os/envoir) workspace — the node-only reference
implementation of DMTAP (Decentralized Message Transfer & Access Protocol). The **specification**
lives in the sibling [KOTVA](https://github.com/vul-os/kotva) repo, and so does the substrate it is
built on (`kotva-core`, `kotva-mail`, `kotva-sync`), consumed here under the `dmtap_*` Rust paths
via a cargo dependency-rename.

## What it is

`downgrade-tests` — the DMTAP downgrade & fail-closed regression suite.

## Running its tests

```sh
cargo test -p downgrade-tests
```

## Publishing

This crate is `publish = false`: it is a harness/test crate, not a library anyone should
depend on.

## License

MIT (see the workspace `LICENSE-MIT`; the workspace as a whole is `MIT OR Apache-2.0`).
