//! The `abi` surface's entropy backend: **there isn't one, and that is deliberate.**
//!
//! `dmtap-core` pulls two `getrandom` majors transitively on `wasm32-unknown-unknown`: **0.2** via
//! `hpke` → `p256` → `elliptic-curve` → `crypto-bigint` → `rand_core` 0.6, and **0.4** via `x-wing`
//! → `ml-kem` → `sha3` → `digest` → `crypto-common`. (It used to be three. `getrandom` 0.3 left the
//! wasm32 graph and the crate stopped naming it — see the note on [`__getrandom_v03_custom`].)
//! Neither of them links unless it is told where entropy comes from. The
//! JS surface answers "the host's `crypto.getRandomValues`". This surface cannot give that answer:
//! the Go binding instantiates the module with **no host functions at all** — no clock, no
//! filesystem, no network, no imports of any kind — which is a large part of why it is easy to
//! reason about and cheap to instantiate.
//!
//! So the choice is between a backend that fabricates bytes and one that refuses. Fabricating —
//! zeros, a counter, a hash of a constant — links exactly as well and is the more dangerous option
//! by a wide margin: nothing on the reachable path needs entropy *today*, so the fake would never
//! be noticed, and the day someone wires up a code path that mints a key it would silently produce
//! a predictable one. There is no test that catches that, because the output looks like bytes.
//!
//! Refusing has the opposite failure mode. Nothing reachable calls it, so it costs nothing now; and
//! if a future change does reach for randomness, it fails loudly, at the call, with a code — instead
//! of returning a guessable key that verifies fine and is worthless.
//!
//! This is the same fail-closed reflex as the rest of the substrate (`SYNC.md` §12): when the honest
//! answer is "I cannot do this safely", say so rather than approximate it.

/// The `getrandom` 0.2 custom backend. Always fails.
///
/// `getrandom` 0.3/0.4 select their custom backend through a `--cfg getrandom_backend="custom"`
/// RUSTFLAG rather than a Cargo feature, so `build-abi.sh` sets that flag and
/// [`__getrandom_v03_custom`] below serves them.
#[cfg(all(target_arch = "wasm32", feature = "abi"))]
fn unavailable(_buf: &mut [u8]) -> Result<(), getrandom_02::Error> {
    Err(getrandom_02::Error::UNSUPPORTED)
}

#[cfg(all(target_arch = "wasm32", feature = "abi"))]
getrandom_02::register_custom_getrandom!(unavailable);

/// The 0.4 custom backend, same refusal.
///
/// The symbol name is `__getrandom_v03_custom` because 0.4 kept 0.3's spelling — both majors
/// `extern`-declare this exact name, each against **its own** `Error` type. This definition is
/// typed against 0.4's, because 0.4 is the only one of the two in the wasm32 graph
/// (`cargo tree -p dmtap-sync-wasm --target wasm32-unknown-unknown -i getrandom@0.3.x` finds no
/// requirer). It was previously typed against 0.3's `Error`, with 0.3 declared as a direct
/// dependency purely to name that type — which worked only because the two `Error`s happen to have
/// identical layout, and kept an otherwise-unused crate in the tree. If 0.3 ever re-enters the
/// graph the link fails loudly for want of a definition, which is the correct direction: this file
/// exists to refuse, not to fabricate.
///
/// # Safety
///
/// `getrandom` calls this with a valid, writable `dest`/`len`. It is never read from, because this
/// implementation never writes and always returns a non-zero (error) code.
#[cfg(all(target_arch = "wasm32", feature = "abi"))]
#[no_mangle]
pub unsafe extern "Rust" fn __getrandom_v03_custom(
    _dest: *mut u8,
    _len: usize,
) -> Result<(), getrandom_04::Error> {
    Err(getrandom_04::Error::UNSUPPORTED)
}
