# conformance-runner

Executable §18-conformance proof: drives dmtap-core's committed KAT vectors.json (and, where byte-backed, the ../dmtap conformance-suite catalog) through the reference codec and reports PASS/FAIL per case. This is the harness a second implementer runs to check their own decoder/signer against the same fixed inputs.

Part of the [envoir](https://github.com/vul-os/envoir) workspace — the node-only reference
implementation of DMTAP (Decentralized Message Transfer & Access Protocol). The **specification**
lives in the sibling [KOTVA](https://github.com/vul-os/kotva) repo, and so does the substrate it is
built on (`kotva-core`, `kotva-mail`, `kotva-sync`), consumed here under the `dmtap_*` Rust paths
via a cargo dependency-rename.

## What it is

The conformance-runner engine.

## Dependencies

* `dmtap-core`
* `dmtap-auth`
* `dmtap-naming`
* `dmtap-deniable`
* `dmtap-mls`
* `dmtap-clustersync`
* `dmtap-sync`
* `envoir-node`
* `serde`
* `serde_json`
* `ciborium`

## Running its tests

```sh
cargo test -p conformance-runner
```

## Publishing

This crate is `publish = false`: it is a harness/test crate, not a library anyone should
depend on.

## License

MIT (see the workspace `LICENSE-MIT`; the workspace as a whole is `MIT OR Apache-2.0`).
