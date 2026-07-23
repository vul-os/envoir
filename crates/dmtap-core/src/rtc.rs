//! DMTAP-RTC — real-time call **signaling** and **capacity advertisement** (spec §27).
//!
//! ## What this module is, and what it deliberately is not
//!
//! DMTAP does not invent a real-time media stack, and neither does this module. Media transport,
//! codecs, congestion control, and the SFU are **WebRTC's** problem and are solved: SRTP for the
//! wire, SDP (RFC 8866) for the session description, JSEP (RFC 8829) for the offer/answer state
//! machine, ICE/STUN/TURN (RFC 8445/8489/8656) for connectivity, and SFrame (RFC 9605) for the
//! end-to-end frame protection that survives an SFU. A DMTAP call must be implementable against an
//! *existing* SFU, which means DMTAP must not require the SFU to understand anything new.
//!
//! DMTAP contributes exactly three things, and this module holds two of them:
//!
//! 1. **[`RtcSignal`]** (kind [`RTC_SIGNAL_KIND`] `0x44`, §27.4.1) — the offer/answer/candidate/
//!    rollback/teardown object, carried as ordinary `Payload.body` inside a sealed MOTE (§2/§5).
//!    It is authenticated by the enclosing `Payload.sig` exactly as any other MOTE content is; it
//!    carries no signature of its own (§27.8's KDF-labels row), and — unlike a signed object such
//!    as [`FeedHint`](crate::pubsub::FeedHint) — it is not even re-preserved verbatim when a key
//!    is unrecognized, because it is never re-relayed, re-serialized or content-addressed by
//!    anyone but its one recipient (§27.4.1's forward-compatibility paragraph).
//! 2. **Capacity accounting** ([`MediaCapacity`], [`CapacityAdvert`], [`RtcCapacity`]) — an
//!    *advertised*, resource-derived ceiling expressed in tracks and bits/sec, never a guess by
//!    the far side and never a headcount (§27.7.4).
//!
//! The third — SFrame key derivation from the MLS epoch secret — lives in `dmtap-mls::sframe`,
//! because that is where the epoch secret is, and it must not be copied out of the MLS layer to
//! get here.
//!
//! ## Why one message kind and not several
//!
//! `Envelope.kind` travels **in the clear** (§2.2): it is on the signed envelope, outside the
//! sealed `ciphertext`. Allocating a kind per signaling object — `offer`, `answer`, `bye` — would
//! publish the *state of a call* to every relay on the path: who called whom, whether the callee
//! picked up, and when they hung up. That is precisely the call-detail record DMTAP exists to not
//! produce. So every signal type shares one kind, [`RTC_SIGNAL_KIND`], and the discriminator
//! ([`SignalType`], key 2) sits **inside** the sealed payload where only the recipient reads it
//! (§27.3.2). The cost is that a relay cannot prioritize a teardown over a candidate; that is a
//! scheduling nicety traded for not leaking call state, and the trade is not close.
//!
//! ## Renegotiation is not a type
//!
//! There is no `renegotiate` [`SignalType`]. Adding a screen share, removing it, adding a second
//! camera, restarting ICE, and changing simulcast layers are all the same operation: **an ordinary
//! `offer` with a higher `seq` on an existing `call_id`** (§27.4.4). A receiver that already holds
//! that `call_id` in an established state treats the new `offer` as a renegotiation instead of a
//! new call; nothing in the object itself distinguishes the two cases; the call state the receiver
//! already holds does.
//!
//! ## Screen sharing is not a call type
//!
//! A screen share is an **additional media track**, produced by `getDisplayMedia()`, added to a
//! live call by ordinary JSEP renegotiation (an `offer` per above). There is no screen-share
//! object here, no screen-share flag, and no screen-share key. Its *purpose* is carried
//! SDP-natively as `a=content:slides` (RFC 4796 §5.14, §27.6.2), read back out by [`sdp_scan`] —
//! DMTAP adds no parallel application-level purpose field that could disagree with the SDP the
//! media stack actually acts on. Two facts follow, and both are load-bearing:
//!
//! - **A screen track cannot be unencrypted.** [`sdp_scan`] refuses any media section offered over
//!   a non-SRTP profile ([`RtcError::UnprotectedMedia`], `ERR_RTC_SFRAME_REQUIRED` `0x0417`),
//!   uniformly, before any purpose is even looked at. There is no code path that admits a `slides`
//!   section on plain `RTP/AVP`.
//! - **A screen track cannot be differently keyed.** The key derivation in `dmtap_mls::sframe`
//!   takes no track argument at all — see that module's docs. Uniform keying is a property of the
//!   API's *shape*, not of a check someone has to remember to run. See
//!   `dmtap_mls::sframe::tests::screen_and_camera_track_derive_the_identical_secret` for the test
//!   that proves it.
//!
//! ## Registry status (§21.24f, §27.8)
//!
//! Every identifier this module allocates is now **registered**, not provisional: message kind
//! `0x44` (§21.16), capability tokens `rtc-1`/`rtc-sfu-1` (§21.22), error points `0x0415`–`0x0417`
//! within the existing subsystem `0x04` (§21.14), and the MLS exporter label
//! `DMTAP-RTC-v0/sframe` (§18.9). Where an earlier revision of this file predates `27-realtime-
//! media.md` and disagrees with it, the spec governs (§10.4) and the disagreement is fixed here,
//! not carried forward — see the `dmtap-envoir` change log for what changed and why.

use crate::cbor::{self, as_array, as_bool, as_bytes, as_text, as_u64, as_u8, CborError, Cv, Fields};
use crate::suite::Suite;

/// Message kind for a sealed [`RtcSignal`] (§27.4.1, §21.16 extension range). Registered as the
/// next point after `0x43 feed_unsubscribe` (§21.24f). One kind covers every signal type; see the
/// module docs for why.
pub const RTC_SIGNAL_KIND: u8 = 0x44;

/// Capability token (§21.22, §27.8) advertising DMTAP-RTC signaling support.
///
/// Advertising it means "I speak [`RtcSignal`] and honor JSEP renegotiation". Its **absence is a
/// fact about that peer, never a fault** (the §21.22 capability-absence rule): a peer that does
/// not advertise `rtc-1` is not callable, which is not an error condition to report to anyone
/// (§27.9 item 1).
pub const RTC_CAPABILITY_TOKEN: &str = "rtc-1";

/// Capability token (§21.22, §27.8) advertising the **SFU** role (§27.7.2). An operator MUST
/// advertise [`RTC_CAPABILITY_TOKEN`] to meaningfully advertise this one (§27.8), and MUST publish
/// an [`RtcCapacity`] alongside it (§27.7.4).
pub const RTC_SFU_CAPABILITY_TOKEN: &str = "rtc-sfu-1";

/// §27.4.1: `call_id` is `bstr .size 16` — **exactly** 16 bytes, not a floor.
///
/// It is not merely a uniqueness source. A `call_id` is the *entire* per-call context binding of
/// the SFrame secret derivation (`dmtap-mls::sframe`, §27.5.1), so an adversary who can predict or
/// collide one gets two calls in the same group at the same epoch sharing key material — which
/// turns a recording of one call into a decryptable replay into the other. It MUST be drawn from a
/// CSPRNG and MUST NOT be derived from group state or reused across calls (§27.4.1, RTC-8).
pub const CALL_ID_LEN: usize = 16;

/// Integer keys `>= 64` are reserved to future revisions of this profile (§27.4.1, §18.1.2's
/// general reservation), exactly as they are for every other DMTAP signed-object schema.
/// `RtcSignal` itself, however, has no signature of its own and is never re-serialized once
/// consumed (§27.4.1), so — unlike a `Headers.ext`-bearing signed object — an unrecognized key of
/// **any** number is simply ignored here rather than rejected-below/preserved-above this line;
/// this constant documents the reserved boundary, it does not gate decoding.
pub const RTC_EXT_MIN: u64 = 64;

// ── Errors ───────────────────────────────────────────────────────────────────────────────────

/// A DMTAP-RTC failure. Every variant fails **closed**: no signaling object is acted on in part.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RtcError {
    /// The object fails the §27.4.1 CDDL schema: a `call_id` not exactly [`CALL_ID_LEN`] bytes, an
    /// `sdp` missing on an SDP-bearing type or present on a type forbidding it, an empty
    /// `candidates` array (`candidate` MUST carry at least one), a `reason` missing on `bye` or
    /// present elsewhere, or an `sfu`/`sfu_suite` pair that does not agree with `topology`.
    /// `ERR_MALFORMED_OBJECT` (`0x020D`, DROP_SILENT, §21.4) — the disposition §27.4.5's RTC-5 row
    /// assigns to every one of these, uniformly; the profile registers no finer-grained code for
    /// "which field" because none of these partially-formed objects has a legitimate use.
    #[error("RtcSignal fails its schema: {0} (ERR_MALFORMED_OBJECT, 0x020D)")]
    Malformed(&'static str),

    /// `type` is not one of §27.4.2's seven registered values. Per §27.4.2 this MUST cause the
    /// signal to be discarded **without acting on any part of it**, and MUST NOT be treated as a
    /// fault of the sending peer (a future revision may register a type this build predates).
    /// Unlike [`RtcError::Malformed`], no wire error code is assigned — [`RtcError::code`] returns
    /// `None` — because the disposition is a silent, un-acked discard, the same shape as an
    /// unrecognized `Envelope.kind` (§2.3), not a rejection communicated to anyone.
    #[error("unrecognized RtcSignal.type {0} — discard, not a peer fault")]
    UnknownSignalType(u8),

    /// A media section was offered over a transport profile that is not SRTP-protected, or an
    /// already-established call's renegotiation attempts to remove SFrame protection. This is the
    /// check that makes "an unencrypted screen track" unreachable — see [`sdp_scan`].
    /// `ERR_RTC_SFRAME_REQUIRED` (`0x0417`, FAIL_CLOSED_BLOCK, §27.5.2/§27.6.5/§27.12) — protection
    /// ratchets up only, never down, never silently.
    #[error("media section `{0}` is offered over a non-SRTP profile (ERR_RTC_SFRAME_REQUIRED, 0x0417)")]
    UnprotectedMedia(String),

    /// Admitting this load would exceed a published [`RtcCapacity`] (or, for a mesh peer, the
    /// local [`MediaCapacity`]) ceiling. Reported, not silently clamped: a node that quietly
    /// accepts more than it advertised has made its advertisement a lie, and the far side has no
    /// way to learn it needs to shed a track. `ERR_RTC_CAPACITY_EXCEEDED` (`0x0416`, DENY_POLICY,
    /// §27.7.4/§27.12). Evaluated against **published** bounds only (RTC-17): a live measurement
    /// may inform what is published next, never what is admitted now.
    #[error("admitting this media load would exceed the advertised ceiling (ERR_RTC_CAPACITY_EXCEEDED, 0x0416)")]
    CapacityExceeded,

    /// The SDP could not be scanned (a media section before any `m=` line, an unparseable `m=`
    /// line). Not a DMTAP wire fault — SDP is opaque application content (§27.4.1) — so this has no
    /// assigned §21 code; [`RtcError::code`] returns `None`, the same shape §27.4.3 gives a
    /// malformed ICE candidate string (a media-stack error at the endpoint, not a protocol error).
    #[error("SDP is malformed: {0}")]
    SdpMalformed(&'static str),

    /// A CBOR decode failure. `ERR_MALFORMED_OBJECT` (`0x020D`) — the same code [`Malformed`]
    /// carries, since a schema violation caught at the CBOR layer and one caught by
    /// [`RtcSignal::validate`] are the same fault from a sender's point of view.
    ///
    /// [`Malformed`]: RtcError::Malformed
    #[error("canonical CBOR error: {0}")]
    Cbor(#[from] CborError),
}

impl RtcError {
    /// The normative §21/§27.12 wire error code this failure carries, when it carries one at all.
    /// See each variant's docs for why some return `None` (a silent discard or a local decode
    /// quality issue is not the same as a fault communicated back to a peer).
    pub fn code(&self) -> Option<u16> {
        match self {
            RtcError::Malformed(_) => Some(0x020D),
            RtcError::Cbor(_) => Some(0x020D),
            RtcError::UnprotectedMedia(_) => Some(0x0417),
            RtcError::CapacityExceeded => Some(0x0416),
            RtcError::UnknownSignalType(_) => None,
            RtcError::SdpMalformed(_) => None,
        }
    }
}

// ── Signal type ──────────────────────────────────────────────────────────────────────────────

/// Which JSEP/ICE step an [`RtcSignal`] carries (key 2, §27.4.2). Values `0x01`–`0x07` are the
/// registered set; `0x08`–`0x3F` are Specification Required (unassigned), `0x40`–`0xFE` Private
/// Use, `0x00`/`0xFF` Reserved. This implementation recognizes only the registered set and fails
/// closed ([`RtcError::UnknownSignalType`]) on everything else, per §27.4.2's forward-compatibility
/// rule for the type space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SignalType {
    /// `0x01` — a JSEP offer (RFC 8829). The **first** offer for a `call_id` opens the call; a
    /// **subsequent** offer on the same `call_id` is a renegotiation (§27.4.4) — there is no
    /// separate type for that.
    Offer = 0x01,
    /// `0x02` — a JSEP provisional answer. OPTIONAL to originate; a receiver that does not
    /// implement provisional answers treats an unexpected one as an unrecognized type and waits
    /// for `answer`.
    Pranswer = 0x02,
    /// `0x03` — a JSEP answer, completing the exchange opened by the highest-`seq` `offer` from
    /// the peer.
    Answer = 0x03,
    /// `0x04` — withdraws the sender's own outstanding offer (JSEP rollback). The glare resolution
    /// of §27.4.4 is expressed with this type; `sdp` MUST be absent.
    Rollback = 0x04,
    /// `0x05` — one or more trickled ICE candidates (RFC 8838). Carries `candidates` (key 5),
    /// non-empty.
    Candidate = 0x05,
    /// `0x06` — the sender has finished gathering for this negotiation. A distinct type rather
    /// than a sentinel candidate string, so "no more candidates" is not encoded as the absence of
    /// a value inside a field whose grammar RFC 8839 owns.
    EndOfCandidates = 0x06,
    /// `0x07` — teardown (§27.4.5). Carries `reason` (key 7).
    Bye = 0x07,
}

impl SignalType {
    /// Decode, failing closed on an unregistered discriminant (§27.4.2).
    pub fn from_u8(b: u8) -> Result<Self, RtcError> {
        Ok(match b {
            0x01 => SignalType::Offer,
            0x02 => SignalType::Pranswer,
            0x03 => SignalType::Answer,
            0x04 => SignalType::Rollback,
            0x05 => SignalType::Candidate,
            0x06 => SignalType::EndOfCandidates,
            0x07 => SignalType::Bye,
            other => return Err(RtcError::UnknownSignalType(other)),
        })
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Whether this type carries `sdp` (key 4) — i.e. whether it can add, remove, or re-purpose a
    /// media track (§27.4.1's field table: MUST **iff** `type ∈ {offer, pranswer, answer}`).
    pub fn carries_sdp(self) -> bool {
        matches!(self, SignalType::Offer | SignalType::Pranswer | SignalType::Answer)
    }
}

/// Why a call ended (`RtcSignal.reason`, key 7, §27.4.5). Advisory display data: a `Bye` is acted
/// on regardless of what the reason says (the call ends), so a hostile reason code changes only
/// what the user is told, never what the stack does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByeReason {
    /// `0` — normal hangup by the far side.
    Normal,
    /// `1` — the callee actively declined.
    Declined,
    /// `2` — the callee is already in a call it will not leave.
    Busy,
    /// `3` — no answer within the caller's own timeout.
    Timeout,
    /// `4` — an SFU refused on capacity (§27.7.4).
    Capacity,
    /// `5` — a media or signaling failure the far side could not recover from.
    Error,
    /// An out-of-range byte. Kept rather than collapsed onto [`ByeReason::Error`], because
    /// `reason` MUST NOT gate any security decision (§27.4.5) — there is nothing unsafe about
    /// preserving a value this build does not yet have a name for.
    Other(u8),
}

impl ByeReason {
    pub fn from_u8(b: u8) -> Self {
        match b {
            0 => ByeReason::Normal,
            1 => ByeReason::Declined,
            2 => ByeReason::Busy,
            3 => ByeReason::Timeout,
            4 => ByeReason::Capacity,
            5 => ByeReason::Error,
            other => ByeReason::Other(other),
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            ByeReason::Normal => 0,
            ByeReason::Declined => 1,
            ByeReason::Busy => 2,
            ByeReason::Timeout => 3,
            ByeReason::Capacity => 4,
            ByeReason::Error => 5,
            ByeReason::Other(b) => b,
        }
    }
}

/// Which media-forwarding shape a call uses (`RtcSignal.topology`, key 8, §27.7). Absent on the
/// wire ⇒ [`Topology::Mesh`] (§27.4.1's field table, §27.7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Topology {
    /// `1` — every participant sends directly to every other (§27.7.1). No third party is in the
    /// media path; the default.
    Mesh,
    /// `2` — a Selective Forwarding Unit is in the media path (§27.7.2). `sfu`/`sfu_suite` (keys
    /// 9/10) MUST be present.
    Sfu,
}

impl Topology {
    pub fn from_u8(b: u8) -> Result<Self, RtcError> {
        match b {
            1 => Ok(Topology::Mesh),
            2 => Ok(Topology::Sfu),
            _ => Err(RtcError::Malformed("topology is neither 1 (mesh) nor 2 (SFU)")),
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Topology::Mesh => 1,
            Topology::Sfu => 2,
        }
    }
}

// ── IceCandidate ─────────────────────────────────────────────────────────────────────────────

/// One trickled ICE candidate (§27.4.3), an element of `RtcSignal.candidates` (key 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceCandidate {
    /// key 1 — the RFC 8839 attribute value **including** its `candidate:` prefix, verbatim as
    /// the ICE agent produced it. DMTAP does not parse, validate or rewrite it.
    pub candidate: String,
    /// key 2 — the m-section this candidate belongs to, by its RFC 5888 `a=mid` value, **never**
    /// by m-line index (an index is invalidated by the very renegotiations §27.4.2 makes
    /// routine; a MID is stable for the life of the m-section).
    pub mid: String,
    /// key 3 — the ICE ufrag the candidate was gathered under (RFC 8839 §5.4), when the sender
    /// held one. A receiver that holds it MUST discard candidates whose `ufrag` does not match
    /// the current negotiation's — how a candidate from a superseded ICE generation is kept from
    /// being applied after an ICE restart.
    pub ufrag: Option<String>,
}

impl IceCandidate {
    fn to_cv(&self) -> Cv {
        let mut m = vec![(1u64, Cv::Text(self.candidate.clone())), (2, Cv::Text(self.mid.clone()))];
        if let Some(u) = &self.ufrag {
            m.push((3, Cv::Text(u.clone())));
        }
        Cv::Map(m)
    }

    fn from_cv(cv: Cv) -> Result<Self, RtcError> {
        let mut f = Fields::from_cv(cv)?;
        let candidate = as_text(f.req(1)?)?;
        let mid = as_text(f.req(2)?)?;
        let ufrag = f.take(3).map(as_text).transpose()?;
        // Unrecognized keys are ignored, not rejected — see RtcSignal's forward-compatibility
        // note; this nested object shares that rule (§27.4.1).
        Ok(IceCandidate { candidate, mid, ufrag })
    }
}

// ── RtcSignal ────────────────────────────────────────────────────────────────────────────────

/// One real-time signaling message, carried as `Payload.body` in a sealed MOTE with
/// `Envelope.kind = ` [`RTC_SIGNAL_KIND`] (§27.4.1).
///
/// Integer-keyed deterministic CBOR (§18.1.1). Unlike a signed object, an unrecognized key is
/// simply **ignored** here (never rejected, never preserved) — see [`RTC_EXT_MIN`]'s docs for why
/// that is the correct rule for this specific object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtcSignal {
    /// key 1 — the call's unpredictable identifier, exactly [`CALL_ID_LEN`] bytes. Stable for the
    /// whole call, across every epoch the call spans. MUST be CSPRNG-drawn; MUST NOT be reused
    /// across calls or derived from group state (§27.4.1, RTC-8) — it is an input to the SFrame
    /// key schedule (`dmtap-mls::sframe`).
    pub call_id: Vec<u8>,
    /// key 2 — which signaling step this is.
    pub typ: SignalType,
    /// key 3 — per-(`call_id`, sender) monotonic counter (§27.4.5). A receiver MUST discard an
    /// `offer`/`pranswer`/`answer`/`rollback`/`bye` whose `seq` is ≤ the highest `seq` of those
    /// types already applied from that sender for that call; a `candidate`/`end_of_candidates` is
    /// exempt (ICE is order-insensitive, RFC 8838) — that ordering/authorization state lives with
    /// the call session, not in this object, exactly as §2.7's dedup is the enclosing MOTE's job
    /// and is not re-implemented here.
    pub seq: u64,
    /// key 4 — the SDP body (RFC 8866), verbatim. Present iff [`SignalType::carries_sdp`].
    ///
    /// Carried **opaquely**. DMTAP does not rewrite, canonicalize, or re-generate SDP: the media
    /// stack is the only component entitled to interpret it, and a second interpreter is a second
    /// chance to disagree with the first. [`sdp_scan`] *reads* it for admission accounting and
    /// protection checking without ever producing a modified copy.
    pub sdp: Option<String>,
    /// key 5 — one or more trickled ICE candidates (RFC 8838). Present, and non-empty, iff
    /// `typ = `[`SignalType::Candidate`]; an empty array is malformed (`ERR_MALFORMED_OBJECT`) —
    /// end-of-candidates is its own type, not a sentinel empty array.
    pub candidates: Option<Vec<IceCandidate>>,
    /// key 6 — the MLS epoch the sender held when emitting, SHOULD-present on `offer`/`answer`.
    ///
    /// **Advisory only.** It lets a receiver detect the two sides are keying media from different
    /// epochs before media fails, rather than after. A receiver MUST NOT treat this as
    /// authorization for anything and MUST NOT key media from it — the authority is the epoch the
    /// receiver itself has applied (§27.4.1). This is why `dmtap-mls::sframe`'s derivation never
    /// takes an epoch argument: it always uses the session's own current epoch.
    pub mls_epoch: Option<u64>,
    /// key 7 — why the call ended. Present iff `typ = `[`SignalType::Bye`].
    pub reason: Option<ByeReason>,
    /// key 8 — mesh or SFU (§27.7). Absent ⇒ mesh. SHOULD be present on `offer`.
    pub topology: Option<Topology>,
    /// key 9 — the forwarding unit's DMTAP identity key, raw public-key bytes (never a digest,
    /// exactly as §24.3.1 carries an `ik-pub`). Present iff `topology = `[`Topology::Sfu`], so a
    /// participant knows *which* operator is in the path before it sends a byte of media.
    pub sfu: Option<Vec<u8>>,
    /// key 10 — the suite governing `sfu`'s length (§18.1.4, §18.2). Present iff key 9 is present.
    pub sfu_suite: Option<Suite>,
}

impl RtcSignal {
    /// A `Bye` — the one signal every implementation must be able to emit, including from an
    /// error path, so it takes no optional arguments beyond the reason.
    pub fn bye(call_id: Vec<u8>, seq: u64, reason: ByeReason) -> Self {
        RtcSignal {
            call_id,
            typ: SignalType::Bye,
            seq,
            sdp: None,
            candidates: None,
            mls_epoch: None,
            reason: Some(reason),
            topology: None,
            sfu: None,
            sfu_suite: None,
        }
    }

    /// An `Offer`, `Pranswer`, or `Answer` carrying `sdp`.
    ///
    /// There is no separate constructor for "add a screen share" or "renegotiate": adding one is
    /// an [`Offer`](SignalType::Offer) with a higher `seq` on an existing `call_id`, whose SDP has
    /// gained a section with `a=content:slides`. That is the whole mechanism (§27.4.4, §27.6.1).
    #[allow(clippy::too_many_arguments)]
    pub fn with_sdp(
        typ: SignalType,
        call_id: Vec<u8>,
        seq: u64,
        sdp: String,
        mls_epoch: Option<u64>,
        topology: Option<Topology>,
        sfu: Option<(Vec<u8>, Suite)>,
    ) -> Self {
        let (sfu, sfu_suite) = match sfu {
            Some((k, s)) => (Some(k), Some(s)),
            None => (None, None),
        };
        RtcSignal {
            call_id,
            typ,
            seq,
            sdp: Some(sdp),
            candidates: None,
            mls_epoch,
            reason: None,
            topology,
            sfu,
            sfu_suite,
        }
    }

    /// A `Candidate` signal trickling one or more ICE candidates.
    pub fn candidates(call_id: Vec<u8>, seq: u64, candidates: Vec<IceCandidate>) -> Self {
        RtcSignal {
            call_id,
            typ: SignalType::Candidate,
            seq,
            sdp: None,
            candidates: Some(candidates),
            mls_epoch: None,
            reason: None,
            topology: None,
            sfu: None,
            sfu_suite: None,
        }
    }

    fn to_cv(&self) -> Cv {
        let mut m = vec![
            (1u64, Cv::Bytes(self.call_id.clone())),
            (2, Cv::U64(self.typ.as_u8() as u64)),
            (3, Cv::U64(self.seq)),
        ];
        // Absent optionals are OMITTED, never encoded as null (§18.1.1).
        if let Some(s) = &self.sdp {
            m.push((4, Cv::Text(s.clone())));
        }
        if let Some(cs) = &self.candidates {
            m.push((5, Cv::Array(cs.iter().map(IceCandidate::to_cv).collect())));
        }
        if let Some(e) = &self.mls_epoch {
            m.push((6, Cv::U64(*e)));
        }
        if let Some(r) = &self.reason {
            m.push((7, Cv::U64(r.as_u8() as u64)));
        }
        if let Some(t) = &self.topology {
            m.push((8, Cv::U64(t.as_u8() as u64)));
        }
        if let Some(sfu) = &self.sfu {
            m.push((9, Cv::Bytes(sfu.clone())));
        }
        if let Some(s) = &self.sfu_suite {
            m.push((10, Cv::U64(s.as_u8() as u64)));
        }
        Cv::Map(m)
    }

    /// The exact wire bytes (§18.1.1 deterministic CBOR).
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv())
    }

    /// Decode from canonical CBOR, then [`validate`](RtcSignal::validate).
    ///
    /// Decoding and validating are one operation here on purpose. An `RtcSignal` that decoded but
    /// did not validate has no legitimate use — there is no receiver that can honestly consume a
    /// half-checked one — so the type is never handed out in that state.
    pub fn decode(bytes: &[u8]) -> Result<Self, RtcError> {
        let cv = cbor::decode(bytes)?;
        let sig = Self::from_cv(cv)?;
        sig.validate()?;
        Ok(sig)
    }

    fn from_cv(cv: Cv) -> Result<Self, RtcError> {
        let mut f = Fields::from_cv(cv)?;
        let call_id = as_bytes(f.req(1)?)?;
        let typ = SignalType::from_u8(as_u8(f.req(2)?)?)?;
        let seq = as_u64(f.req(3)?)?;
        let sdp = f.take(4).map(as_text).transpose()?;
        let candidates = match f.take(5) {
            Some(cv) => Some(
                as_array(cv)?
                    .into_iter()
                    .map(IceCandidate::from_cv)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            None => None,
        };
        let mls_epoch = f.take(6).map(as_u64).transpose()?;
        let reason = f.take(7).map(as_u8).transpose()?.map(ByeReason::from_u8);
        let topology = f.take(8).map(as_u8).transpose()?.map(Topology::from_u8).transpose()?;
        let sfu = f.take(9).map(as_bytes).transpose()?;
        let sfu_suite = f
            .take(10)
            .map(as_u8)
            .transpose()?
            .map(|b| Suite::from_u8(b).ok_or(RtcError::Malformed("sfu_suite names an unregistered suite")))
            .transpose()?;

        // §27.4.1: unrecognized keys are ignored — not rejected, not preserved. This object has no
        // signature of its own and is never re-serialized, so there is no round-trip byte identity
        // to protect, unlike `Headers.ext` or a signed object's `>= 64` extension range.
        let _ = f.into_pairs();

        Ok(RtcSignal { call_id, typ, seq, sdp, candidates, mls_epoch, reason, topology, sfu, sfu_suite })
    }

    /// Structural validation against the §27.4.1 CDDL: `call_id` length, and **exact**
    /// field/type agreement.
    ///
    /// The field/type agreement is the security-relevant half. A signaling object whose fields do
    /// not match its declared type is ambiguous, and the two obvious ways to resolve an ambiguity
    /// are both wrong:
    ///
    /// - *Ignore the extra field* — then a `bye` carrying an `sdp` is accepted, and an
    ///   implementation that reads `sdp` before dispatching on `typ` (a completely ordinary way to
    ///   write a handler) renegotiates the media session on a message the sender labelled as a
    ///   hangup. That is an attacker adding a screen-capture track to a call that is supposed to be
    ///   ending.
    /// - *Infer the type from the fields* — then `typ` is decorative and the sender's stated
    ///   intent is not what gets executed.
    ///
    /// So the object is refused (`ERR_MALFORMED_OBJECT`, §27.4.5's RTC-5). A well-formed sender
    /// never trips this; every message it produces has exactly the fields its type defines.
    pub fn validate(&self) -> Result<(), RtcError> {
        if self.call_id.len() != CALL_ID_LEN {
            return Err(RtcError::Malformed("call_id is not exactly 16 bytes"));
        }

        let t = self.typ;
        if self.sdp.is_some() != t.carries_sdp() {
            return Err(RtcError::Malformed(
                "sdp presence disagrees with type (MUST iff offer/pranswer/answer)",
            ));
        }
        match (&self.candidates, t == SignalType::Candidate) {
            (Some(cs), true) if cs.is_empty() => {
                return Err(RtcError::Malformed("candidates is present but empty"))
            }
            (Some(_), false) => return Err(RtcError::Malformed("candidates present on a non-candidate type")),
            (None, true) => return Err(RtcError::Malformed("candidates missing on a candidate signal")),
            _ => {}
        }
        if self.reason.is_some() != (t == SignalType::Bye) {
            return Err(RtcError::Malformed("reason presence disagrees with type (MUST iff bye)"));
        }
        let sfu_topology_ok = match self.topology {
            Some(Topology::Sfu) => self.sfu.is_some(),
            _ => self.sfu.is_none(),
        };
        if !sfu_topology_ok {
            return Err(RtcError::Malformed("sfu presence disagrees with topology (MUST iff SFU)"));
        }
        if self.sfu_suite.is_some() != self.sfu.is_some() {
            return Err(RtcError::Malformed("sfu_suite presence disagrees with sfu (MUST iff key 9 present)"));
        }
        Ok(())
    }

    /// Scan this signal's SDP into tracks, or `Ok(vec![])` for a signal that carries none.
    ///
    /// Convenience over [`sdp_scan`], and the call a receiver should actually make: it means the
    /// protection check ([`RtcError::UnprotectedMedia`]) runs on **every** description-bearing
    /// signal, including a mid-call renegotiation, rather than only on the initial offer. A call
    /// that checked only its first offer would let a screen share be added later over plain RTP.
    pub fn tracks(&self) -> Result<Vec<TrackDescriptor>, RtcError> {
        match &self.sdp {
            Some(sdp) => sdp_scan(sdp),
            None => Ok(Vec::new()),
        }
    }
}

// ── SDP scanning ─────────────────────────────────────────────────────────────────────────────

/// What a media section carries (the `<media>` field of an `m=` line, RFC 8866 §5.14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaKind {
    Audio,
    Video,
    /// A data channel (`m=application`, RFC 8841).
    Application,
    /// Anything else, kept verbatim rather than mapped onto a known kind we would then mis-charge.
    Other(String),
}

/// A track's declared **purpose**, from `a=content:` (RFC 4796 §5, §27.6.2).
///
/// This is the screen-share discriminator, and it is SDP-native on purpose: the media stack routes
/// and lays out on the strength of this attribute, so putting a second copy of the same fact in the
/// DMTAP object would create a pair that can disagree — and the one DMTAP checked would not be the
/// one the renderer used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrackPurpose {
    /// `a=content:main`, or no `a=content:` line at all (RFC 4796 §5: `main` is the default).
    Main,
    /// `a=content:slides` — **this is screen sharing**. RFC 4796 defines it as the presentation /
    /// shared-material stream, which is what `getDisplayMedia()` produces.
    Slides,
    /// `a=content:speaker` — a speaker-feed / return video.
    Speaker,
    /// `a=content:sl` — sign language.
    SignLanguage,
    /// `a=content:alt` — an alternative to the main stream.
    Alt,
    /// An unregistered `a=content:` token. Kept rather than collapsed to `Main`, because charging
    /// an unknown purpose the *main* rate would under-charge whatever it turns out to be.
    Other(String),
}

/// Which way a track flows, from the direction attribute (RFC 8866 §6.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    SendRecv,
    SendOnly,
    RecvOnly,
    /// `a=inactive` — negotiated but carrying nothing. This is how a track is muted or a share is
    /// paused without renegotiating it away.
    Inactive,
}

/// One media section of an SDP, reduced to the facts admission control needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackDescriptor {
    /// `a=mid:` — the section's identifier (RFC 9143), if it declared one.
    pub mid: Option<String>,
    pub media: MediaKind,
    pub purpose: TrackPurpose,
    pub direction: Direction,
    /// `b=AS:` in bits/sec (RFC 8866 §5.8 gives it in kilobits/sec), if declared.
    ///
    /// A **claim by the sender**, never a measurement. [`TrackDescriptor::budget_bitrate_bps`] is
    /// what the budget actually charges, and it does not simply trust this number.
    pub declared_bitrate_bps: Option<u64>,
}

impl TrackDescriptor {
    /// Whether this track is a screen share.
    ///
    /// Exposed so the *layout* layer can ask (§27.6.3: a client distinguishes concurrent shares by
    /// MID and sender, never assumes a single "the screen track"). Deliberately **not** consulted
    /// anywhere in key derivation, and not consulted by the protection check either — both of
    /// those apply to every track identically (§27.6.5), and a screen-share special case in either
    /// is the bug this API shape exists to prevent.
    pub fn is_screen_share(&self) -> bool {
        self.purpose == TrackPurpose::Slides
    }

    /// The bitrate the capacity budget charges for this track.
    ///
    /// `max(declared, floor)`, not `declared.unwrap_or(floor)`, and the difference is the whole
    /// point. `b=AS` is a hint the signaling layer cannot enforce — nothing here sees a single
    /// media byte, and the congestion controller that does is out of scope. If a declaration could
    /// lower the charge, `b=AS:1` on a 4K screen share would be a free pass through admission
    /// control, and the node would then be overrun by media it had formally agreed to accept.
    ///
    /// So a declaration can only ever charge a sender **more** than the floor, never less. A peer
    /// that genuinely sends a very low-bitrate stream is charged the floor and loses a little
    /// headroom; a peer that lies gains nothing. That asymmetry is the correct one: the cost of
    /// being wrong about an honest peer is some unused capacity, and the cost of being wrong about
    /// a hostile one is a saturated uplink.
    pub fn budget_bitrate_bps(&self) -> u64 {
        self.floor_bitrate_bps().max(self.declared_bitrate_bps.unwrap_or(0))
    }

    /// The conservative per-kind minimum charge. §27.13 item 6 states the spec recommends no
    /// number here; these are this implementation's own floors, not a registered value.
    ///
    /// A screen share floors highest of all: it is typically the largest stream in a call (high
    /// resolution, full frame updates on scroll) and the one whose cost is most often ignored when
    /// capacity is reasoned about per-person instead of per-track (§27.7.4).
    fn floor_bitrate_bps(&self) -> u64 {
        match (&self.media, &self.purpose) {
            (MediaKind::Audio, _) => 64_000,
            (MediaKind::Video, TrackPurpose::Slides) => 2_500_000,
            (MediaKind::Video, _) => 1_000_000,
            (MediaKind::Application, _) => 128_000,
            // An unknown media kind is charged the video floor rather than nothing: the cheap
            // mistake is over-charging something harmless, the expensive one is admitting an
            // unbounded stream because we had no row for it.
            (MediaKind::Other(_), _) => 1_000_000,
        }
    }
}

/// Whether an `m=` line's `<proto>` field is an SRTP-protected profile.
///
/// This is the gate that makes an unencrypted media track — screen or otherwise — unreachable.
/// RFC 8866 §5.14's `<proto>` names the transport: the `SAVP`/`SAVPF` profiles (RFC 3711 / RFC
/// 5124) are SRTP; plain `AVP`/`AVPF` (RFC 3551 / RFC 4585) are **unprotected RTP**. `DTLS/SCTP`
/// and `UDP/DTLS/SCTP` (RFC 8841) are data channels, protected by DTLS itself.
///
/// The test is `SAVP` as a substring rather than an allow-list of full proto strings, and that is a
/// considered choice: WebRTC has accumulated several spellings (`RTP/SAVP`, `RTP/SAVPF`,
/// `UDP/TLS/RTP/SAVPF`, `TCP/DTLS/RTP/SAVPF`) and an allow-list that missed one would reject a
/// legitimate offer. Crucially the substring cannot be reached *accidentally* by an unprotected
/// profile — `AVP` and `AVPF` do not contain `SAVP` — so the failure mode of this choice is
/// rejecting something valid, never admitting something unprotected.
fn proto_is_protected(proto: &str) -> bool {
    let p = proto.to_ascii_uppercase();
    p.contains("SAVP") || p.contains("DTLS/SCTP")
}

/// Read an SDP body (RFC 8866) into [`TrackDescriptor`]s, refusing any unprotected media section.
///
/// **This is not an SDP parser and must never become one.** It reads five things — the `m=` line's
/// media kind and proto, and the section's `a=mid:`, `a=content:`, direction attribute and `b=AS:`
/// — and ignores everything else. The media stack parses SDP; this reads the subset that admission
/// control and the protection check need. Keeping it deliberately incomplete is what stops it from
/// becoming a second, divergent interpretation of the same bytes.
///
/// Two properties it does guarantee:
///
/// - **Every** media section is protection-checked, before any other property of it is used. A
///   section on plain `RTP/AVP` fails the whole scan with [`RtcError::UnprotectedMedia`] — so an
///   offer cannot be part-admitted with its unprotected sections quietly dropped, which would leave
///   the two sides disagreeing about what was negotiated.
/// - Attributes are attributed to the section they follow. An `a=` line before the first `m=` is
///   session-level and is skipped, not mis-charged to section zero.
pub fn sdp_scan(sdp: &str) -> Result<Vec<TrackDescriptor>, RtcError> {
    let mut out: Vec<TrackDescriptor> = Vec::new();

    for raw in sdp.split('\n') {
        // Tolerate CRLF (RFC 8866 mandates it) and bare LF (what test fixtures and some stacks
        // emit). Trailing whitespace is stripped rather than treated as part of a value.
        let line = raw.trim_end_matches(['\r', ' ', '\t']);
        let Some((kind, value)) = line.split_once('=') else {
            continue; // blank or junk line — not this scanner's business to police
        };

        match kind {
            "m" => {
                // m=<media> <port> <proto> <fmt>...
                let mut parts = value.split(' ').filter(|s| !s.is_empty());
                let media = parts.next().ok_or(RtcError::SdpMalformed("m= line has no media field"))?;
                let _port = parts.next().ok_or(RtcError::SdpMalformed("m= line has no port field"))?;
                let proto = parts.next().ok_or(RtcError::SdpMalformed("m= line has no proto field"))?;

                if !proto_is_protected(proto) {
                    return Err(RtcError::UnprotectedMedia(media.to_string()));
                }

                out.push(TrackDescriptor {
                    mid: None,
                    media: match media {
                        "audio" => MediaKind::Audio,
                        "video" => MediaKind::Video,
                        "application" => MediaKind::Application,
                        other => MediaKind::Other(other.to_string()),
                    },
                    // RFC 4796 §5: absent `a=content:` means `main`.
                    purpose: TrackPurpose::Main,
                    // RFC 8866 §6.7: absent direction means `sendrecv`.
                    direction: Direction::SendRecv,
                    declared_bitrate_bps: None,
                });
            }
            "a" | "b" => {
                // Session-level attributes precede the first m= line and belong to no track.
                let Some(cur) = out.last_mut() else { continue };
                if kind == "b" {
                    if let Some(kbps) = value.strip_prefix("AS:") {
                        if let Ok(k) = kbps.trim().parse::<u64>() {
                            // Saturating: a hostile `b=AS:18446744073709551615` must not wrap to a
                            // small charge, which is exactly what a wrapping multiply would do.
                            cur.declared_bitrate_bps = Some(k.saturating_mul(1000));
                        }
                    }
                    continue;
                }
                if let Some(mid) = value.strip_prefix("mid:") {
                    cur.mid = Some(mid.trim().to_string());
                } else if let Some(content) = value.strip_prefix("content:") {
                    cur.purpose = match content.trim() {
                        "main" => TrackPurpose::Main,
                        "slides" => TrackPurpose::Slides,
                        "speaker" => TrackPurpose::Speaker,
                        "sl" => TrackPurpose::SignLanguage,
                        "alt" => TrackPurpose::Alt,
                        other => TrackPurpose::Other(other.to_string()),
                    };
                } else {
                    match value {
                        "sendrecv" => cur.direction = Direction::SendRecv,
                        "sendonly" => cur.direction = Direction::SendOnly,
                        "recvonly" => cur.direction = Direction::RecvOnly,
                        "inactive" => cur.direction = Direction::Inactive,
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    Ok(out)
}

// ── Capacity ─────────────────────────────────────────────────────────────────────────────────

/// The aggregate cost of a set of tracks — **the unit capacity is actually spent in**.
///
/// Two numbers, not one, because they run out independently: a laptop can decode more audio
/// streams than its uplink can carry screen shares, and a fat pipe on a weak CPU fails the other
/// way. Collapsing them to a single "participant" number is the mismeasurement §27.7.4 exists to
/// avoid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MediaLoad {
    pub tracks: u32,
    pub bitrate_bps: u64,
}

impl MediaLoad {
    /// Total a slice of tracks, charging each per [`TrackDescriptor::budget_bitrate_bps`].
    ///
    /// `Inactive` tracks are counted in `tracks` but not in `bitrate_bps`: a negotiated-but-muted
    /// track still occupies a transceiver slot and can be un-muted at any moment without further
    /// signaling — so it costs a slot — but it is carrying nothing right now, so charging it
    /// bandwidth would refuse calls that fit.
    ///
    /// Saturating throughout: this totals attacker-supplied numbers, and a wrapped total is a
    /// total that passes admission.
    pub fn of(tracks: &[TrackDescriptor]) -> MediaLoad {
        let mut load = MediaLoad::default();
        for t in tracks {
            load.tracks = load.tracks.saturating_add(1);
            if t.direction != Direction::Inactive {
                load.bitrate_bps = load.bitrate_bps.saturating_add(t.budget_bitrate_bps());
            }
        }
        load
    }

    fn plus(self, other: MediaLoad) -> MediaLoad {
        MediaLoad {
            tracks: self.tracks.saturating_add(other.tracks),
            bitrate_bps: self.bitrate_bps.saturating_add(other.bitrate_bps),
        }
    }
}

/// The per-participant track mix a ceiling is computed against.
///
/// This type is the honest part of the participant question. "How many people can this node host?"
/// has no answer; "how many people, each sending one audio and one camera track, and how many if
/// two of them are also sharing a screen?" does. Anything that reports a bare participant number
/// without one of these has quietly assumed a mix. **This is a local planning aid, not the wire
/// [`RtcCapacity`] object** — see that type for the thing an SFU actually publishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipantProfile {
    /// What each participant sends. Its [`MediaLoad`] is what each *other* participant must
    /// receive, in a full mesh.
    pub tracks: Vec<TrackDescriptor>,
}

impl ParticipantProfile {
    /// One audio track — a voice call.
    pub fn audio_only() -> Self {
        ParticipantProfile { tracks: vec![track(MediaKind::Audio, TrackPurpose::Main)] }
    }

    /// One audio + one camera track — the ordinary video call.
    pub fn audio_video() -> Self {
        ParticipantProfile {
            tracks: vec![
                track(MediaKind::Audio, TrackPurpose::Main),
                track(MediaKind::Video, TrackPurpose::Main),
            ],
        }
    }

    /// Audio + camera + a screen share. Provided precisely so the difference from
    /// [`audio_video`](Self::audio_video) is visible in the ceiling rather than assumed away.
    pub fn audio_video_screen() -> Self {
        ParticipantProfile {
            tracks: vec![
                track(MediaKind::Audio, TrackPurpose::Main),
                track(MediaKind::Video, TrackPurpose::Main),
                track(MediaKind::Video, TrackPurpose::Slides),
            ],
        }
    }

    /// The load one participant imposes on one peer.
    pub fn load(&self) -> MediaLoad {
        MediaLoad::of(&self.tracks)
    }
}

/// A synthetic descriptor for capacity planning (no SDP behind it), charged at the kind's floor.
fn track(media: MediaKind, purpose: TrackPurpose) -> TrackDescriptor {
    TrackDescriptor {
        mid: None,
        media,
        purpose,
        direction: Direction::SendRecv,
        declared_bitrate_bps: None,
    }
}

/// A node's real-time media ceiling, in **tracks and bits**, derived from local resources.
///
/// This is a **local** computation, used two ways: a mesh peer (§27.7.1) uses it directly to
/// decide what it can join or admit; an SFU operator uses it as the **auto-detection** input
/// §27.7.4 allows to inform the [`RtcCapacity`] it *publishes* next — never to override an
/// already-published bound (RTC-17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaCapacity {
    /// Simultaneous encode + decode slots this node will run.
    pub max_tracks: u32,
    /// Uplink budget for tracks this node sends.
    pub max_send_bitrate_bps: u64,
    /// Downlink budget for tracks this node receives.
    pub max_recv_bitrate_bps: u64,
}

impl MediaCapacity {
    /// Derive a ceiling from measured local resources. §27.13 item 6 states the spec recommends no
    /// concrete numbers; the shape — derive, do not guess — is what §27.7.4 actually requires.
    ///
    /// `cpu_cores` bounds tracks, because each simultaneous track is an encoder or decoder
    /// instance. Link rates are discounted to [`LINK_UTILIZATION_NUM`]/[`LINK_UTILIZATION_DEN`] of
    /// nominal: the nominal figure is what the interface reports, and real-time media on top of it
    /// still has to pay for RTP/UDP/IP/SRTP headers, RTX and FEC, and it must leave room for the
    /// congestion controller to probe. Advertising the full link rate is advertising a number the
    /// node cannot honor.
    pub fn from_local_resources(cpu_cores: u32, uplink_bps: u64, downlink_bps: u64) -> Self {
        let max_send_bitrate_bps =
            uplink_bps.saturating_mul(LINK_UTILIZATION_NUM) / LINK_UTILIZATION_DEN;
        let max_recv_bitrate_bps =
            downlink_bps.saturating_mul(LINK_UTILIZATION_NUM) / LINK_UTILIZATION_DEN;

        // A ceiling of 0 tracks is not a smaller call, it is a broken node that advertises
        // itself as callable and then admits nothing. Floor at 2 (one send, one recv) so a
        // single-core device still reports a coherent, honest, minimal capability.
        let max_tracks = cpu_cores.saturating_mul(TRACKS_PER_CORE).max(2);

        MediaCapacity { max_tracks, max_send_bitrate_bps, max_recv_bitrate_bps }
    }

    /// How many participants a **full mesh** call can have, for a given per-participant mix.
    ///
    /// **Not** the wire `RtcCapacity` admission basis (that is keys 1–4 of the published object,
    /// §27.7.4, RTC-15) — this is a local mesh-only planning number, since a mesh peer publishes
    /// no capacity object at all. Mesh cost is not linear in participants from any one node's point
    /// of view: with `N` participants, this node encodes its own tracks once but *decodes* every
    /// one of the other `N-1` participants' tracks, and its uplink carries its own tracks `N-1`
    /// times over (one copy per peer — there is no SFU to fan out for it). So all three of
    /// `max_tracks`, `max_send_bitrate_bps` and `max_recv_bitrate_bps` bind, and the ceiling is the
    /// tightest.
    ///
    /// This is the function that makes the dishonest answer impossible to give: passing
    /// [`ParticipantProfile::audio_only`] and [`ParticipantProfile::audio_video_screen`] returns
    /// different numbers, because they cost different amounts. A single advertised
    /// "max participants" would have had to pick one of them and not say which.
    ///
    /// Returns `1` when not even one peer fits — the node can be in a call by itself, which is to
    /// say it cannot host a call. Never returns `0`.
    pub fn mesh_participant_ceiling(&self, profile: &ParticipantProfile) -> u32 {
        let per_peer = profile.load();
        let own_tracks = per_peer.tracks;

        // Peers admitted by decode/encode slots: own tracks are encoded once, each peer's tracks
        // are decoded once.
        let by_tracks = if per_peer.tracks == 0 {
            u32::MAX
        } else {
            self.max_tracks.saturating_sub(own_tracks) / per_peer.tracks
        };

        // Peers admitted by uplink: this node's own tracks go out once per peer.
        let by_send = if per_peer.bitrate_bps == 0 {
            u32::MAX
        } else {
            clamp_u32(self.max_send_bitrate_bps / per_peer.bitrate_bps)
        };

        // Peers admitted by downlink: one peer's worth of tracks arrives per peer.
        let by_recv = if per_peer.bitrate_bps == 0 {
            u32::MAX
        } else {
            clamp_u32(self.max_recv_bitrate_bps / per_peer.bitrate_bps)
        };

        by_tracks.min(by_send).min(by_recv).saturating_add(1)
    }

    /// Admit `incoming` tracks on top of `current`, against the **receive** budget.
    pub fn admit_inbound(&self, current: MediaLoad, incoming: MediaLoad) -> Result<(), RtcError> {
        self.admit(current, incoming, self.max_recv_bitrate_bps)
    }

    /// Admit `incoming` tracks on top of `current`, against the **send** budget.
    pub fn admit_outbound(&self, current: MediaLoad, incoming: MediaLoad) -> Result<(), RtcError> {
        self.admit(current, incoming, self.max_send_bitrate_bps)
    }

    fn admit(&self, current: MediaLoad, incoming: MediaLoad, bitrate_ceiling: u64) -> Result<(), RtcError> {
        let total = current.plus(incoming);
        if total.tracks > self.max_tracks || total.bitrate_bps > bitrate_ceiling {
            return Err(RtcError::CapacityExceeded);
        }
        Ok(())
    }

    /// Materialize a published [`RtcCapacity`] from this local measurement — the §27.7.4
    /// auto-detection path, made concrete: a live measurement informs what is published, and
    /// nothing here lets it override an already-admitted call's bound (that guarantee is the
    /// caller's, since only the caller knows what is already admitted).
    pub fn to_rtc_capacity(
        &self,
        max_tracks_per_participant: u32,
        max_bps_per_track: u64,
        sframe_required: bool,
    ) -> RtcCapacity {
        RtcCapacity {
            max_tracks: self.max_tracks,
            max_aggregate_bps: self.max_send_bitrate_bps.min(self.max_recv_bitrate_bps),
            max_tracks_per_participant,
            max_bps_per_track,
            advisory_max_participants: None,
            sframe_required,
        }
    }
}

/// Fraction of nominal link rate advertised as usable. See [`MediaCapacity::from_local_resources`].
pub const LINK_UTILIZATION_NUM: u64 = 3;
/// Denominator of [`LINK_UTILIZATION_NUM`].
pub const LINK_UTILIZATION_DEN: u64 = 4;
/// Simultaneous encode/decode slots assumed per CPU core. Not a registered value (§27.13 item 6).
pub const TRACKS_PER_CORE: u32 = 4;

fn clamp_u32(v: u64) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

/// What a peer **advertises** about its real-time capacity.
///
/// The two arms are genuinely different claims, and flattening them would let a caller read a
/// gateway's guarantee off a mesh peer's estimate:
///
/// - A **mesh** peer advertises resources (§27.7.1), and the participant count falls out of the
///   mix ([`MediaCapacity::mesh_participant_ceiling`]). It cannot honestly promise a participant
///   number without knowing what everyone will send, and it publishes no wire object at all.
/// - A **gateway** (an SFU, §27.7.2) advertises an [`RtcCapacity`] (§27.7.4), a signed object
///   riding an ordinary `system` MOTE, because it *is* the fan-out point: it knows its own
///   conference ceiling and enforces it, and every participant's cost to it is bounded by its own
///   admission policy rather than by the other participants.
///
/// Either way this is **advertised, never guessed**. A caller that estimates a callee's capacity
/// from anything other than one of these — an SFU's participant count, a hardware guess, a default
/// — is making a claim on the callee's behalf that the callee never made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapacityAdvert {
    /// A peer joining the mesh directly.
    Mesh(MediaCapacity),
    /// A gateway / SFU, with the published [`RtcCapacity`] it enforces itself.
    Gateway(RtcCapacity),
}

impl CapacityAdvert {
    /// The participant ceiling implied by this advertisement for a given mix.
    ///
    /// For a gateway, [`RtcCapacity::advisory_max_participants`] is **display only** (RTC-15) and
    /// is never consulted here; the ceiling is derived from keys 1–4, the same admission basis
    /// [`RtcCapacity::admit`] uses.
    pub fn participant_ceiling(&self, profile: &ParticipantProfile) -> u32 {
        match self {
            CapacityAdvert::Mesh(c) => c.mesh_participant_ceiling(profile),
            CapacityAdvert::Gateway(cap) => {
                let per_peer = profile.load();
                let by_tracks_per_participant =
                    if per_peer.tracks == 0 { u32::MAX } else { cap.max_tracks_per_participant / per_peer.tracks };
                let by_aggregate_tracks =
                    if per_peer.tracks == 0 { u32::MAX } else { cap.max_tracks / per_peer.tracks };
                let by_aggregate_bps = if per_peer.bitrate_bps == 0 {
                    u32::MAX
                } else {
                    clamp_u32(cap.max_aggregate_bps / per_peer.bitrate_bps)
                };
                by_tracks_per_participant.min(by_aggregate_tracks).min(by_aggregate_bps)
            }
        }
    }
}

/// The signed SFU capacity advertisement (§27.7.4) — an operator's published ceiling, expressed in
/// **tracks and bandwidth, never headcount**. Carried in an ordinary `system` MOTE (`kind = 0x0a`)
/// alongside the [`RTC_SFU_CAPABILITY_TOKEN`] token, rollback-protected by the same monotonic
/// `caps_version` machinery every other capability announcement uses
/// (`ERR_CAPABILITY_ANNOUNCE_ROLLBACK`, `0x030A`) — no new signed structure.
///
/// **The ceiling is expressed in tracks and bandwidth, not in headcount.** This is the load-bearing
/// choice §27.7.4 makes. A screen share is typically the highest-bitrate stream in a conference —
/// a 1080p30 screen share of moving content can exceed the aggregate of every camera in a
/// six-person call — so six participants with two shares can cost several times what six
/// participants on camera cost. A `max_participants` bound is wrong in both directions: too
/// permissive for a call with shares, too restrictive for an audio-only one.
///
/// This type models the CDDL shape only (encode/decode + the admission check over keys 1–4); the
/// signed `system`-MOTE envelope carrying it, and the `caps_version` rollback tracker, are the
/// existing capability-announcement machinery (`crate::capability`) and are not duplicated here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtcCapacity {
    /// key 1 — simultaneous forwarded tracks per call, REQUIRED.
    pub max_tracks: u32,
    /// key 2 — aggregate forwarded bitrate per call, bits/s, REQUIRED.
    pub max_aggregate_bps: u64,
    /// key 3 — REQUIRED.
    pub max_tracks_per_participant: u32,
    /// key 4 — REQUIRED.
    pub max_bps_per_track: u64,
    /// key 5 — DISPLAY ONLY (RTC-15): a client MAY show it; an operator MUST NOT use it, and a
    /// client MUST NOT rely on it, as an admission basis.
    pub advisory_max_participants: Option<u32>,
    /// key 6 — true iff this operator refuses to forward media that is not SFrame-protected,
    /// REQUIRED. Publishing `true` obligates enforcement (`ERR_RTC_SFRAME_REQUIRED`, `0x0417`,
    /// §27.5.2); publishing `false` obligates disclosing to the user, before joining, that this
    /// operator's confidentiality depends on the client's own configuration (§27.7.4).
    pub sframe_required: bool,
}

impl RtcCapacity {
    fn to_cv(&self) -> Cv {
        let mut m = vec![
            (1u64, Cv::U64(self.max_tracks as u64)),
            (2, Cv::U64(self.max_aggregate_bps)),
            (3, Cv::U64(self.max_tracks_per_participant as u64)),
            (4, Cv::U64(self.max_bps_per_track)),
        ];
        if let Some(p) = self.advisory_max_participants {
            m.push((5, Cv::U64(p as u64)));
        }
        m.push((6, Cv::Bool(self.sframe_required)));
        Cv::Map(m)
    }

    /// The exact wire bytes (§18.1.1 deterministic CBOR) of the `RtcCapacity` value carried inside
    /// the enclosing `system` MOTE's `Payload.body`.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv())
    }

    /// Decode a bare `RtcCapacity` value (the caller is responsible for the enclosing signed
    /// `system` MOTE / `caps_version` rollback check — see the type docs).
    pub fn decode(bytes: &[u8]) -> Result<Self, RtcError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let max_tracks = as_u64(f.req(1)?)? as u32;
        let max_aggregate_bps = as_u64(f.req(2)?)?;
        let max_tracks_per_participant = as_u64(f.req(3)?)? as u32;
        let max_bps_per_track = as_u64(f.req(4)?)?;
        let advisory_max_participants = f.take(5).map(as_u64).transpose()?.map(|v| v as u32);
        let sframe_required = as_bool(f.req(6)?)?;
        Ok(RtcCapacity {
            max_tracks,
            max_aggregate_bps,
            max_tracks_per_participant,
            max_bps_per_track,
            advisory_max_participants,
            sframe_required,
        })
    }

    /// Evaluate an admission or renegotiation request against keys 1–4 **only** (RTC-15): headcount
    /// and `advisory_max_participants` never enter this decision. Callers MUST invoke this on
    /// **every** `offer`, not only on join (RTC-16), because renegotiation is how a track — a
    /// screen share among them — is added.
    pub fn admit(&self, current: MediaLoad, incoming: MediaLoad, per_participant: MediaLoad) -> Result<(), RtcError> {
        let total = current.plus(incoming);
        if total.tracks > self.max_tracks
            || total.bitrate_bps > self.max_aggregate_bps
            || per_participant.tracks > self.max_tracks_per_participant
            || per_participant.bitrate_bps > self.max_bps_per_track
        {
            return Err(RtcError::CapacityExceeded);
        }
        Ok(())
    }
}
