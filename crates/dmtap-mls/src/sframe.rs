//! SFrame (RFC 9605) key derivation from the MLS epoch secret — DMTAP-RTC (spec §27).
//!
//! This is the load-bearing security code of DMTAP's real-time story. Everything else in the RTC
//! layer (`dmtap_core::rtc`) is plumbing around an existing, well-specified stack; this is the one
//! place DMTAP asserts a cryptographic property of its own, and the property is:
//!
//! > **A call is not a new trust domain. It inherits the group's membership, epoch, and forward
//! > secrecy, because its media secret is a function of the group's epoch secret and nothing
//! > else.**
//!
//! ## Why derive rather than negotiate
//!
//! WebRTC's own answer to "who can hear this call" is DTLS-SRTP: the two endpoints authenticate
//! fingerprints carried in the SDP. That answer does not survive an SFU — the SFU terminates SRTP
//! — which is why RFC 9605 (SFrame) exists: end-to-end frame protection *inside* the SRTP the SFU
//! can see. But SFrame deliberately specifies **no key management**. Something has to say which
//! keys, for whom, and until when.
//!
//! A DMTAP call already has that something. The participants are an MLS group (§5.1), and MLS's
//! key schedule already answers all three questions correctly:
//!
//! - **Membership** — only current members of the epoch hold the epoch secret. There is no separate
//!   call roster to get out of sync with the group roster, because there is no separate roster.
//! - **Forward secrecy** — a Commit advances the epoch and the old epoch secret is deleted (§5.2).
//!   Media secrets from a previous epoch cannot be re-derived, so a device compromised today does
//!   not decrypt a recording of yesterday's call.
//! - **Post-compromise security** — removing a member re-keys every path secret via TreeKEM. From
//!   the next epoch the removed device derives nothing, and (see [`Session::sframe_epoch_secret`])
//!   it cannot even ask: `openmls` refuses to export from an inactive group.
//!
//! Negotiating call keys separately would mean re-deriving all three properties by hand, in a
//! second protocol, and keeping the two agreeing forever. Exporting them means they hold by
//! construction.
//!
//! ## The residual this buys nothing against (§27.11 item 4 — read this before relying on §27.5)
//!
//! Because the secret is a function of the **group's** epoch and nothing else, **any current
//! member of the group can derive it, whether or not that member joined the call** — including one
//! who declined, and one who is present but silent. Excluding a participant from a call is
//! therefore a **forwarding/UX property, not a cryptographic one**: an SFU can decline to forward
//! to them and a mesh peer can decline to connect, but a member who obtains the ciphertext by any
//! other means (another participant, a compromised relay, a subpoena) decrypts it like anyone else
//! in the group. Nothing in this module — or in `dmtap_core::rtc` — implies otherwise, and nothing
//! calling into it should either. An application that needs cryptographic exclusion MUST create an
//! MLS group over exactly the intended participants and derive from **that** group; this module
//! does not, and must not, auto-create sub-groups on a call's behalf (§27.11 item 4, §27.14 C-05).
//!
//! ## The construction (§27.5.1, normative)
//!
//! One step. RFC 9420 §8.5's exporter, called once, against the group's **current** epoch:
//!
//! ```text
//! sframe_epoch_secret =
//!     MLS-Exporter( Label   = "DMTAP-RTC-v0/sframe",
//!                   Context = det_cbor([ call_id ]),
//!                   Length  = Nk )
//!
//!     ; MLS-Exporter is RFC 9420 §8.5:
//!     ;   MLS-Exporter(Label, Context, Length)
//!     ;     = ExpandWithLabel( DeriveSecret(epoch_secret, "exporter"),
//!     ;                        Label, Hash(Context), Length )
//!     ;   — computed by openmls (`MlsGroup::export_secret`), never re-implemented here.
//!     ;
//!     ; call_id = the 16 bytes the offerer chose (§27.4.1, dmtap_core::rtc::CALL_ID_LEN)
//!     ; Nk      = the key length of the SFrame cipher suite in use (RFC 9605), the `length`
//!     ;           argument to Session::sframe_epoch_secret
//! ```
//!
//! ### Domain separation, and why each piece is there
//!
//! **The label separates DMTAP-RTC from every other consumer of this group.** RFC 9420 guarantees
//! that exporter outputs under distinct labels are independent of each other *and* of MLS's own
//! handshake, application, and confirmation keys. So the SFrame secret cannot collide with the keys
//! protecting the MOTEs that set the call up, and a future §27-adjacent exporter (a recording key,
//! a transcript key) is one new label away rather than a re-derivation of this one. The stem
//! `DMTAP-RTC-v0/` follows the house convention (`DMTAP-PUB-v0/…`, `DMTAP-SYNC-v0/…`), and the
//! `-v0` in it means a v1 construction is a different label, not a silent reinterpretation of the
//! same bytes.
//!
//! **The epoch is bound structurally, not named.** There is no epoch field in the context, and that
//! is deliberate: the input is `epoch_secret`, which *is* the epoch. A named epoch number alongside
//! it would create a value an attacker could vary independently of the secret, i.e. a second,
//! forgeable opinion about which epoch this is. `RtcSignal.mls_epoch` on the wire exists for
//! diagnosis only, and is never fed here — see that field's docs in `dmtap_core::rtc`.
//!
//! **`call_id` is the *only* thing in the context (§27.5.1, RTC-7), and its arity is fixed.** The
//! `Context` MUST be `det_cbor([call_id])` — a CBOR array of exactly one element — not the bare 16
//! bytes, not a map, not an array that could later grow a second element under the same label. The
//! fixed arity matters for the same reason §24.4.4 fixes its statement's arity: a v0 decoder and a
//! hypothetical v1 decoder that both accepted a variable-length array could be made to agree on a
//! context that means different things to each, which is exactly the ambiguity a *label* bump
//! (`-v0` → `-v1`) exists to avoid needing to reason about. `call_id` alone is also sufficient:
//! RFC 9420 already mixes the group id into `epoch_secret` via the GroupContext, so two groups
//! cannot collide even though `group_id` is not repeated here, and two concurrent calls in the same
//! group at the same epoch are separated because each MUST use its own CSPRNG-drawn `call_id`
//! (§27.4.1) — reusing one, or deriving one from group state, is non-conformant (RTC-8) precisely
//! because `call_id` is this context's only degree of freedom.
//!
//! **The context is deterministic CBOR, not concatenation, and not a bare byte string.** Wrapping
//! `call_id` in a one-element array rather than passing it as raw bytes is not stylistic: it is
//! what lets a future revision bind a second value under a **new** label without the old and new
//! contexts ever being confusable, and it is invisible in prose — a vector or a reviewer that
//! silently drops the array framing and hashes the bare 16 bytes instead has quietly implemented a
//! different, non-interoperable construction. §18.1.1's encoding is injective (definite lengths,
//! shortest-form, no indefinite arrays), so this crate depends on `dmtap-core::cbor` for exactly
//! one reason: there must be exactly one canonical encoder in the tree, or two implementations
//! derive different secrets from the same call.
//!
//! ## Why the derivation takes no track argument, and no leaf/sender argument
//!
//! Look at the signature: [`Session::sframe_epoch_secret`] takes a `call_id` and a `length`. There
//! is no track parameter, no media kind, no `TrackPurpose` — **there is no argument you could pass
//! to obtain a different secret for a screen-share track**, because a screen share is not a thing
//! this function can see. That is the whole answer to "make it structurally impossible to end up
//! with a differently-keyed screen track" (`dmtap_core::rtc`'s module docs state the matching claim
//! about *encryption*, enforced in `sdp_scan`).
//!
//! There is also no per-sender or per-leaf argument. §27.5.1 is explicit that **DMTAP's
//! contribution ends at `sframe_epoch_secret`**: it is *SFrame's own* key schedule (RFC 9605) that
//! turns this one shared secret into per-sender base keys, salts, and key identifiers, and this
//! profile does not restate, profile, or vary that schedule, nor define a KID layout of its own
//! (§27.5.1, §27.13 item 3). An earlier revision of this module derived a distinct
//! `SframeBaseKey` per `(call_id, leaf)` directly from the MLS exporter and invented its own KID
//! (`epoch << 32 | leaf`) — that was this crate's own layer doing SFrame's job before `27-realtime-
//! media.md` existed to say otherwise (§10.4: the spec governs). It is removed here in favor of
//! exposing exactly the one secret §27.5.1 specifies; per-sender separation is the caller's SFrame
//! implementation's job, fed by [`SframeEpochSecret::as_bytes`].
//!
//! ## Retention and deletion (§27.5.2, normative, caller's responsibility)
//!
//! This module derives a secret; it does not retain one across calls. §27.5.2 requires a receiver
//! to keep **at most the current and immediately preceding** epoch's secret for a bounded reorder
//! window (RECOMMENDED 30s) and to **delete** every derived secret at the end of that window and
//! unconditionally at teardown. [`SframeEpochSecret`] zeroizes on drop so that dropping it *is*
//! deleting it, but the caller decides *when* to drop — holding one past its window, or past
//! teardown, is the one way §27.5.2 states an implementation can pass every other rule here and
//! still not have forward secrecy.

use dmtap_core::cbor::{self, Cv};
use zeroize::Zeroize;
use dmtap_core::rtc::CALL_ID_LEN;

use crate::error::MlsError;
use crate::session::Session;

/// The RFC 9420 §8.5 exporter label for the DMTAP-RTC SFrame secret (§27.5.1, registered per
/// §27.8 / §21.24f).
///
/// Note this is an MLS *exporter label*, which RFC 9420 already length-prefixes and domain-tags
/// inside `ExpandWithLabel`; it therefore does **not** carry the `\x00` separator that DMTAP's own
/// §18.1.6 signing DS-tags do (`b"DMTAP-PUB-v0/subscription\x00"`). Adding one would be
/// double-tagging a string MLS has already made unambiguous.
pub const SFRAME_EXPORTER_LABEL: &str = "DMTAP-RTC-v0/sframe";

/// A convenience default length for [`Session::sframe_epoch_secret`]'s `length` argument: 32 bytes
/// covers the base-key requirement of the AES-256 and ChaCha20-Poly1305 SFrame cipher suites (RFC
/// 9605 §4.5). **Not a wire-fixed length** — a caller negotiating a suite with a different `Nk`
/// MUST pass that suite's own key length instead, per §27.5.1's `Length = Nk`.
pub const SFRAME_DEFAULT_SECRET_LEN: usize = 32;

/// A derived DMTAP-RTC SFrame secret for one `(group, epoch, call)` — RFC 9420's
/// `sframe_epoch_secret` (§27.5.1). **Not** a per-sender key: it is the one shared input every
/// current group member derives identically, from which SFrame's own key schedule (RFC 9605), not
/// this crate, produces per-sender base keys, salts, and key identifiers.
///
/// Zeroized on drop (§27.5.2). Not `Clone`, not `Copy`, and it does not implement `Debug` in a way
/// that can print the secret — the whole point of the type is that the bytes go to the caller's
/// SFrame implementation and nowhere else, and a derived `Debug` would put them in the first log
/// line someone adds.
pub struct SframeEpochSecret {
    secret: Vec<u8>,
    epoch: u64,
}

impl SframeEpochSecret {
    /// The raw secret, to hand to an RFC 9605 SFrame implementation as its shared input.
    pub fn as_bytes(&self) -> &[u8] {
        &self.secret
    }

    /// The MLS epoch this secret belongs to. A caller holding one across a Commit can compare this
    /// against [`Session::epoch`] and re-derive for the new epoch, retaining this one only for the
    /// bounded §27.5.2 reorder window rather than indefinitely.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

impl Drop for SframeEpochSecret {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl std::fmt::Debug for SframeEpochSecret {
    /// Prints the *addressing* of the secret (which epoch) and never the secret itself. A secret
    /// that reaches a log has escaped every guarantee this module makes about it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SframeEpochSecret").field("epoch", &self.epoch).field("secret", &"<redacted>").finish()
    }
}

/// Build the exporter context: `det_cbor([call_id])` — a **fixed one-element array** — exactly as
/// §27.5.1 specifies, byte for byte. See the module docs for why this is not the bare 16 bytes and
/// not a map, and why that distinction is load-bearing rather than stylistic.
fn sframe_context(call_id: &[u8]) -> Vec<u8> {
    cbor::encode(&Cv::Array(vec![Cv::Bytes(call_id.to_vec())]))
}

impl Session {
    /// Derive `sframe_epoch_secret` (§27.5.1) for call `call_id`, at **this session's current
    /// epoch**, `length` bytes long (the SFrame cipher suite's `Nk`, RFC 9605 §4.5).
    ///
    /// Every current member of the group derives the **same** secret for the same `(call_id,
    /// epoch)` — there is no per-caller or per-leaf variation, because §27.5.1 defines none (see
    /// the module docs for why, and for the residual this implies about call exclusion).
    ///
    /// ## What this refuses, and why that matters
    ///
    /// - **A `call_id` that is not exactly [`CALL_ID_LEN`] bytes.** Enforced here and not only at
    ///   `RtcSignal` validation, because this is the function whose security actually depends on
    ///   it: `call_id` is the *only* input separating two concurrent calls in one group at one
    ///   epoch (RTC-8). A caller that constructs a derivation directly, bypassing
    ///   `RtcSignal::validate`, must not be able to bypass this with it.
    /// - **An inactive group.** `openmls`'s `export_secret` returns `UseAfterEviction` when the
    ///   group is no longer active, so a **removed member cannot derive call keys at all** — not a
    ///   wrong secret, not an empty one: an error. Combined with TreeKEM re-keying on Remove, that
    ///   is post-compromise security reaching the media layer with no RTC-specific code enforcing
    ///   it.
    pub fn sframe_epoch_secret(&self, call_id: &[u8], length: usize) -> Result<SframeEpochSecret, MlsError> {
        if call_id.len() != CALL_ID_LEN {
            return Err(MlsError::Group(format!(
                "call_id is {} bytes, not the required {CALL_ID_LEN}: a call_id of any other \
                 length is not the context §27.5.1 specifies and would not interoperate",
                call_id.len()
            )));
        }

        let context = sframe_context(call_id);
        let mut exported = self
            .export_secret(SFRAME_EXPORTER_LABEL, &context, length)
            .map_err(|e| MlsError::Group(e.to_string()))?;

        // The exporter is asked for exactly `length` bytes; a short return would otherwise be
        // padded with zeros by the copy below, silently weakening the secret. Fail closed instead.
        if exported.len() != length {
            exported.zeroize();
            return Err(MlsError::Group(format!(
                "MLS exporter returned {} bytes, expected {length}",
                exported.len()
            )));
        }

        let epoch = self.epoch();
        Ok(SframeEpochSecret { secret: exported, epoch })
    }
}
