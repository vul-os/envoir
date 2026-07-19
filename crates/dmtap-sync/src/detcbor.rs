//! Deterministic CBOR (RFC 8949 §4.2 / DMTAP §18.1.1) for the Sync substrate.
//!
//! ## Why a value type of its own, rather than `dmtap_core::cbor::Cv`
//!
//! Core's [`Cv`](dmtap_core::cbor::Cv) is the §18 *mail-object* wire subset, and that subset
//! deliberately admits **only unsigned integers** ("DMTAP uses only unsigned integers on the
//! wire"). The Sync substrate's `cv = ext-value` (`SYNC.md` §4.1, §18.3.6) additionally admits
//! **negative** integers — a PN-counter delta of `−2` is the canonical case (`SYNC-PN-01` encodes
//! it as the major-type-1 head `0x21`), and an LWW register may legitimately hold a negative
//! scalar. Encoding a sync op through a codec that cannot represent a negative integer would
//! either lose the vector or force a lossy re-spelling, so this module carries the *same*
//! canonical rules over a value type that spans the whole `ext-value` domain.
//!
//! The rules enforced here are exactly §18.1.1's, and this codec is strict in **both** directions:
//! it only ever *emits* canonical bytes, and it **rejects** on decode (fail closed, never
//! re-canonicalize silently) any of:
//!
//! 1. non-shortest-form integer or length heads,
//! 2. indefinite-length strings/arrays/maps,
//! 3. floats, tags, `null`, `undefined`, or any other simple value than `true`/`false`,
//! 4. map keys outside the three majors DMTAP uses (uint / bstr / tstr), maps that **mix** key
//!    majors, and keys that are unsorted or duplicated,
//! 5. trailing bytes after a complete top-level item,
//! 6. container nesting beyond [`MAX_NESTING_DEPTH`] — the §4.1 transport-level ceiling that
//!    bounds the otherwise unbounded recursion of `ext-value`.

use std::fmt;

/// A deterministic-CBOR value in the Sync substrate's domain: the whole §18.3.6 `ext-value` type
/// (text, byte strings, unsigned **and negative** integers, booleans, arrays, and **text-keyed
/// maps**, the last two recursively) plus the integer-keyed maps every `SyncOp`/`Hlc`/`AddTag`/
/// `OpRef` object is built from and the byte-keyed map a §5.1 `VersionVector` is.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SVal {
    /// Unsigned integer (major type 0).
    Uint(u64),
    /// Negative integer (major type 1). The held value is the CBOR *argument* `n`, encoding the
    /// number `−1 − n`, so the full 64-bit negative range is representable without an `i128`.
    Nint(u64),
    /// Byte string (major type 2).
    Bytes(Vec<u8>),
    /// UTF-8 text string (major type 3).
    Text(String),
    /// Boolean (major type 7, `0xf4`/`0xf5`).
    Bool(bool),
    /// Definite-length array (major type 4).
    Array(Vec<SVal>),
    /// Integer-keyed, ascending-sorted map (major type 5) — the DMTAP object encoding (§18.1.2).
    Map(Vec<(u64, SVal)>),
    /// Byte-string-keyed map (major type 5), sorted ascending by **encoded key**. The substrate
    /// needs exactly one of these: the §5.1 `VersionVector = { * ik-pub => Hlc }`, whose keys are
    /// author public keys rather than schema labels. It is deliberately NOT admitted as a `cv`
    /// ([`is_ext_value`](SVal::is_ext_value) rejects it), so it can only ever appear where a schema
    /// names it.
    BytesMap(Vec<(Vec<u8>, SVal)>),
    /// **Text-keyed** map (major type 5), sorted ascending by **encoded key** — §18.3.6's
    /// `{ * tstr => ext-value }` arm, and the one map form that IS an `ext-value` (§14 C-08).
    TextMap(Vec<(String, SVal)>),
}

/// The transport-level nesting-depth ceiling applied while validating an `ext-value` (§4.1: the
/// type is recursive and places no depth limit of its own, so "an implementation MUST apply its
/// ordinary deterministic-CBOR nesting-depth ceiling ... and reject an over-deep value as `0x0A03`
/// rather than recursing without bound"). This is deliberately the **same** number
/// `dmtap_core::cbor` applies to every other DMTAP object, so one encoder cannot mint a value a
/// second decoder refuses.
pub const MAX_NESTING_DEPTH: u32 = 64;

impl SVal {
    /// A signed integer as its canonical CBOR value (`i64` covers every value the substrate mints;
    /// counters and deltas are §4.6 scalars).
    pub fn int(v: i64) -> SVal {
        if v < 0 {
            // −1 − n = v  ⇒  n = −1 − v, computed without overflowing at i64::MIN.
            SVal::Nint((-(v as i128) - 1) as u64)
        } else {
            SVal::Uint(v as u64)
        }
    }

    /// The signed value of an integer node, or `None` for a non-integer / out-of-`i64` value.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            SVal::Uint(u) => i64::try_from(*u).ok(),
            SVal::Nint(n) => i64::try_from(-1i128 - (*n as i128)).ok(),
            _ => None,
        }
    }

    /// The text of a `Text` node.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            SVal::Text(t) => Some(t),
            _ => None,
        }
    }

    /// The bytes of a `Bytes` node.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            SVal::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// The elements of an `Array` node.
    pub fn as_array(&self) -> Option<&[SVal]> {
        match self {
            SVal::Array(a) => Some(a),
            _ => None,
        }
    }

    /// Whether this value is a legal §4.1 `cv` — **exactly** §18.3.6's `ext-value`, no narrower:
    ///
    /// ```cddl
    /// ext-value = bool / int / bytes / tstr / [* ext-value] / { * tstr => ext-value }
    /// ```
    ///
    /// Validation is **recursive** and fails closed at the **first** violating node, at any depth:
    /// a text-keyed map whose value is an integer-keyed map is refused at depth 2, never waved
    /// through by a shallow check (`SYNC-VAL-01`). Excluded are floats, tags, `null`/`undefined`
    /// (all three unrepresentable in [`SVal`] at all, so they are already refused by the decoder)
    /// and **integer-keyed maps**, which `ext-value` has no arm for — that is the shape a product
    /// reaches for second, and it answers `false` rather than crashing.
    ///
    /// # §14 C-08: this used to be narrower than the type it named
    ///
    /// Earlier text of §4.1 described `ext-value` as "text, byte strings, integers, booleans and
    /// **homogeneous arrays** thereof", silently dropping §18.3.6's map arm and inventing a
    /// homogeneity constraint §18.3.6 never had — and this function implemented that prose. Both
    /// restrictions are gone: arrays may be **heterogeneous** and text-keyed maps are **admitted**,
    /// recursively. Nesting stays deterministic because §2.2 canonicalizes text keys by *encoded
    /// key bytes* exactly as it does integer keys, at every depth — the same recursive type
    /// §18.3.6's `Headers.ext` already carries inside a MOTE signature preimage.
    ///
    /// **This is a widening, and widenings diverge by rejection.** No previously-valid op becomes
    /// invalid, but an engine that has not been updated refuses ops an updated one accepts, so a
    /// mixed deployment disagrees about op *validity* rather than about merge order. See
    /// [`crate::EXT_VALUE_PROFILE`] for the capability-negotiation consequence.
    ///
    /// The **depth ceiling** is [`MAX_NESTING_DEPTH`]: the type itself is unbounded, so the
    /// transport bounds it, and an over-deep value is refused rather than recursed into.
    pub fn is_ext_value(&self) -> bool {
        self.is_ext_value_at(0)
    }

    fn is_ext_value_at(&self, depth: u32) -> bool {
        if depth > MAX_NESTING_DEPTH {
            return false;
        }
        match self {
            SVal::Uint(_) | SVal::Nint(_) | SVal::Bytes(_) | SVal::Text(_) | SVal::Bool(_) => true,
            // An integer-keyed map is not an `ext-value` — with one canonical exception: the EMPTY
            // map. `{}` encodes as `0xa0` whatever its key type would have been, so canonical CBOR
            // cannot tell an empty text-keyed map from an empty integer-keyed one, and the decoder
            // yields `Map([])` for both. The empty `{ * tstr => ext-value }` map IS an ext-value,
            // so refusing `0xa0` would make a legal value un-decodable; accepting it admits nothing
            // extra, because an empty map carries no entries to smuggle anything in.
            SVal::Map(entries) => entries.is_empty(),
            SVal::BytesMap(_) => false,
            SVal::TextMap(entries) => entries.iter().all(|(_, v)| v.is_ext_value_at(depth + 1)),
            // Heterogeneous arrays are legal: §18.3.6 is `[* ext-value]`, with no same-major-type
            // constraint. Only the elements' own conformance is checked, recursively.
            SVal::Array(items) => items.iter().all(|v| v.is_ext_value_at(depth + 1)),
        }
    }

    /// This value's canonical encoding — the byte string every §2.2 "larger `det_cbor(value)`
    /// wins" tiebreak and every §6.1.1 section sort compares.
    pub fn det_cbor(&self) -> Vec<u8> {
        encode(self)
    }
}

/// A canonical-CBOR decode failure. Every variant is a **refusal**: the substrate never guesses at
/// a non-canonical encoding, because two replicas that disagree about how to re-canonicalize the
/// same bytes would diverge (`SYNC.md` §11 item 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetCborError {
    /// Truncated or structurally malformed input.
    Malformed,
    /// A non-shortest-form integer or length head (§18.1.1 rule 1).
    NonShortestForm,
    /// An indefinite-length string, array, or map (§18.1.1 rule 4).
    IndefiniteLength,
    /// A float, tag, `null`, `undefined`, or an unsupported major type (§18.1.1 rule 5).
    UnsupportedType,
    /// A map key whose major type is none of the three DMTAP uses: unsigned integer (§18.1.2
    /// objects), byte string (§5.1 `VersionVector`), or text (§18.3.6 `ext-value` maps).
    UnsupportedKeyType,
    /// A map mixing key major types. No DMTAP schema has one, and canonical ordering across two
    /// key majors is not a rule §2.2 states — so it is refused rather than guessed at.
    MixedKeyTypes,
    /// Container nesting beyond [`MAX_NESTING_DEPTH`] (§4.1's transport-level depth ceiling).
    NestingTooDeep,
    /// Map keys that are not in strictly ascending order (unsorted, or duplicated).
    UnsortedKeys,
    /// Bytes remaining after a complete top-level item.
    TrailingBytes,
    /// A text string that is not valid UTF-8.
    InvalidUtf8,
}

impl fmt::Display for DetCborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            DetCborError::Malformed => "malformed CBOR",
            DetCborError::NonShortestForm => "non-shortest-form integer/length (§18.1.1)",
            DetCborError::IndefiniteLength => "indefinite-length item (§18.1.1)",
            DetCborError::UnsupportedType => "float/tag/null/undefined or unsupported major type",
            DetCborError::UnsupportedKeyType => "map key is neither uint, bstr nor tstr",
            DetCborError::MixedKeyTypes => "map mixes key major types",
            DetCborError::NestingTooDeep => "nesting deeper than the §4.1 depth ceiling",
            DetCborError::UnsortedKeys => "unsorted or duplicate map keys (§18.1.1)",
            DetCborError::TrailingBytes => "trailing bytes after top-level item",
            DetCborError::InvalidUtf8 => "invalid UTF-8 in a text string",
        };
        f.write_str(s)
    }
}

impl std::error::Error for DetCborError {}

// --- encoding -------------------------------------------------------------------------------

fn put_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    match arg {
        0..=23 => out.push(m | arg as u8),
        24..=0xff => {
            out.push(m | 24);
            out.push(arg as u8);
        }
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend_from_slice(&(arg as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(m | 26);
            out.extend_from_slice(&(arg as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 27);
            out.extend_from_slice(&arg.to_be_bytes());
        }
    }
}

/// Encode `v` as canonical deterministic CBOR. Map entries are emitted in ascending key order
/// regardless of the order they appear in the `Map` vector, so an encoder can never leak a
/// construction-order dependency into the bytes.
pub fn encode(v: &SVal) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(v, &mut out);
    out
}

fn encode_into(v: &SVal, out: &mut Vec<u8>) {
    match v {
        SVal::Uint(u) => put_head(out, 0, *u),
        SVal::Nint(n) => put_head(out, 1, *n),
        SVal::Bytes(b) => {
            put_head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        SVal::Text(t) => {
            put_head(out, 3, t.len() as u64);
            out.extend_from_slice(t.as_bytes());
        }
        SVal::Array(items) => {
            put_head(out, 4, items.len() as u64);
            for i in items {
                encode_into(i, out);
            }
        }
        SVal::Map(entries) => {
            let mut sorted: Vec<&(u64, SVal)> = entries.iter().collect();
            sorted.sort_by_key(|(k, _)| *k);
            put_head(out, 5, sorted.len() as u64);
            for (k, val) in sorted {
                put_head(out, 0, *k);
                encode_into(val, out);
            }
        }
        SVal::BytesMap(entries) => {
            // Keys are sorted by their ENCODED bytes (RFC 8949 §4.2.1): for byte strings of the
            // same length — which author keys always are — that is plain lexicographic order.
            let mut sorted: Vec<&(Vec<u8>, SVal)> = entries.iter().collect();
            sorted.sort_by(|(a, _), (b, _)| {
                (a.len(), a.as_slice()).cmp(&(b.len(), b.as_slice()))
            });
            put_head(out, 5, sorted.len() as u64);
            for (k, val) in sorted {
                put_head(out, 2, k.len() as u64);
                out.extend_from_slice(k);
                encode_into(val, out);
            }
        }
        SVal::TextMap(entries) => {
            // §2.2 sorts by ENCODED key bytes, applied recursively at every depth. For text keys
            // the head encodes the length first (shortest-form), so `(len, bytes)` is exactly
            // encoded-byte order — the same rule as `BytesMap`, one major type over.
            let mut sorted: Vec<&(String, SVal)> = entries.iter().collect();
            sorted.sort_by(|(a, _), (b, _)| (a.len(), a.as_str()).cmp(&(b.len(), b.as_str())));
            put_head(out, 5, sorted.len() as u64);
            for (k, val) in sorted {
                put_head(out, 3, k.len() as u64);
                out.extend_from_slice(k.as_bytes());
                encode_into(val, out);
            }
        }
        SVal::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
    }
}

// --- decoding -------------------------------------------------------------------------------

/// Decode a single canonical-CBOR item from `bytes`, **rejecting** any non-canonical encoding and
/// any trailing byte (fail closed, §18.1.1).
pub fn decode(bytes: &[u8]) -> Result<SVal, DetCborError> {
    let mut p = Parser { b: bytes, i: 0 };
    let v = p.item(0)?;
    if p.i != bytes.len() {
        return Err(DetCborError::TrailingBytes);
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn byte(&mut self) -> Result<u8, DetCborError> {
        let b = *self.b.get(self.i).ok_or(DetCborError::Malformed)?;
        self.i += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DetCborError> {
        let end = self.i.checked_add(n).ok_or(DetCborError::Malformed)?;
        let s = self.b.get(self.i..end).ok_or(DetCborError::Malformed)?;
        self.i = end;
        Ok(s)
    }

    /// Read a major type + its argument, enforcing shortest-form and rejecting indefinite lengths.
    fn head(&mut self) -> Result<(u8, u64), DetCborError> {
        let ib = self.byte()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        let arg = match ai {
            0..=23 => ai as u64,
            24 => {
                let v = self.byte()? as u64;
                if v < 24 {
                    return Err(DetCborError::NonShortestForm);
                }
                v
            }
            25 => {
                let s = self.take(2)?;
                let v = u16::from_be_bytes([s[0], s[1]]) as u64;
                if v <= 0xff {
                    return Err(DetCborError::NonShortestForm);
                }
                v
            }
            26 => {
                let s = self.take(4)?;
                let v = u32::from_be_bytes([s[0], s[1], s[2], s[3]]) as u64;
                if v <= 0xffff {
                    return Err(DetCborError::NonShortestForm);
                }
                v
            }
            27 => {
                let s = self.take(8)?;
                let v = u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]);
                if v <= 0xffff_ffff {
                    return Err(DetCborError::NonShortestForm);
                }
                v
            }
            31 => return Err(DetCborError::IndefiniteLength),
            _ => return Err(DetCborError::Malformed),
        };
        Ok((major, arg))
    }

    /// Decode one item at nesting `depth`. The ceiling is enforced **before** recursing, so a
    /// hostile deeply-nested value is a refusal rather than a stack overflow (§4.1's depth bullet).
    fn item(&mut self, depth: u32) -> Result<SVal, DetCborError> {
        if depth > MAX_NESTING_DEPTH {
            return Err(DetCborError::NestingTooDeep);
        }
        let start = self.i;
        let ib = *self.b.get(start).ok_or(DetCborError::Malformed)?;
        // Major type 7 is handled before the generic head reader: only the two boolean simple
        // values are admitted; floats (0xf9..0xfb), null (0xf6), undefined (0xf7) and every other
        // simple value are refused outright.
        if ib >> 5 == 7 {
            self.i += 1;
            return match ib {
                0xf4 => Ok(SVal::Bool(false)),
                0xf5 => Ok(SVal::Bool(true)),
                _ => Err(DetCborError::UnsupportedType),
            };
        }
        let (major, arg) = self.head()?;
        match major {
            0 => Ok(SVal::Uint(arg)),
            1 => Ok(SVal::Nint(arg)),
            2 => {
                let n = usize::try_from(arg).map_err(|_| DetCborError::Malformed)?;
                Ok(SVal::Bytes(self.take(n)?.to_vec()))
            }
            3 => {
                let n = usize::try_from(arg).map_err(|_| DetCborError::Malformed)?;
                let s = self.take(n)?;
                Ok(SVal::Text(
                    std::str::from_utf8(s).map_err(|_| DetCborError::InvalidUtf8)?.to_owned(),
                ))
            }
            4 => {
                let n = usize::try_from(arg).map_err(|_| DetCborError::Malformed)?;
                let mut items = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    items.push(self.item(depth + 1)?);
                }
                Ok(SVal::Array(items))
            }
            5 => {
                let n = usize::try_from(arg).map_err(|_| DetCborError::Malformed)?;
                // A map's keys are homogeneous: all unsigned integers (a DMTAP object), all byte
                // strings (a §5.1 VersionVector), or all text (§18.3.6's `{ * tstr => ext-value }`
                // arm, admitted by §14 C-08). A mixed-key map is refused — there is no schema in
                // DMTAP that has one, and a decoder that guessed at the ordering of two key majors
                // would be inventing a canonicalization rule §2.2 does not state.
                let mut int_entries: Vec<(u64, SVal)> = Vec::new();
                let mut bytes_entries: Vec<(Vec<u8>, SVal)> = Vec::new();
                let mut text_entries: Vec<(String, SVal)> = Vec::new();
                for i in 0..n {
                    let (kmajor, karg) = self.head()?;
                    let mixed = |seen: usize| i > 0 && seen == 0;
                    match kmajor {
                        0 => {
                            if mixed(int_entries.len()) {
                                return Err(DetCborError::MixedKeyTypes);
                            }
                            if let Some((prev, _)) = int_entries.last() {
                                if karg <= *prev {
                                    return Err(DetCborError::UnsortedKeys);
                                }
                            }
                            let val = self.item(depth + 1)?;
                            int_entries.push((karg, val));
                        }
                        2 => {
                            if mixed(bytes_entries.len()) {
                                return Err(DetCborError::MixedKeyTypes);
                            }
                            let len = usize::try_from(karg).map_err(|_| DetCborError::Malformed)?;
                            let key = self.take(len)?.to_vec();
                            if let Some((prev, _)) = bytes_entries.last() {
                                if (key.len(), key.as_slice()) <= (prev.len(), prev.as_slice()) {
                                    return Err(DetCborError::UnsortedKeys);
                                }
                            }
                            let val = self.item(depth + 1)?;
                            bytes_entries.push((key, val));
                        }
                        3 => {
                            if mixed(text_entries.len()) {
                                return Err(DetCborError::MixedKeyTypes);
                            }
                            let len = usize::try_from(karg).map_err(|_| DetCborError::Malformed)?;
                            let raw = self.take(len)?;
                            let key = std::str::from_utf8(raw)
                                .map_err(|_| DetCborError::InvalidUtf8)?
                                .to_owned();
                            if let Some((prev, _)) = text_entries.last() {
                                if (key.len(), key.as_str()) <= (prev.len(), prev.as_str()) {
                                    return Err(DetCborError::UnsortedKeys);
                                }
                            }
                            let val = self.item(depth + 1)?;
                            text_entries.push((key, val));
                        }
                        _ => return Err(DetCborError::UnsupportedKeyType),
                    }
                }
                // Empty ⇒ `Map([])`: `0xa0` is key-type-agnostic on the wire, so the integer-keyed
                // spelling is chosen as the canonical decode and every consumer that can take an
                // empty map of another key type special-cases it (see `VersionVector::from_sval`
                // and `SVal::is_ext_value`).
                if !bytes_entries.is_empty() {
                    Ok(SVal::BytesMap(bytes_entries))
                } else if !text_entries.is_empty() {
                    Ok(SVal::TextMap(text_entries))
                } else {
                    Ok(SVal::Map(int_entries))
                }
            }
            6 => Err(DetCborError::UnsupportedType), // tags
            _ => Err(DetCborError::UnsupportedType),
        }
    }
}

/// Field-taking helper over a decoded integer-keyed map: takes required/optional keys and then
/// **denies any unknown key** — the §18.1.2 fail-closed rule for signed objects.
pub struct Fields {
    entries: Vec<(u64, SVal)>,
}

impl Fields {
    /// Wrap a decoded map (fails if `cv` is not a map).
    pub fn new(cv: SVal) -> Result<Self, DetCborError> {
        match cv {
            SVal::Map(entries) => Ok(Fields { entries }),
            _ => Err(DetCborError::Malformed),
        }
    }

    /// Remove and return the value at `k`, if present.
    pub fn take(&mut self, k: u64) -> Option<SVal> {
        let pos = self.entries.iter().position(|(key, _)| *key == k)?;
        Some(self.entries.remove(pos).1)
    }

    /// Remove and return a required key, failing closed when absent.
    pub fn req(&mut self, k: u64) -> Result<SVal, DetCborError> {
        self.take(k).ok_or(DetCborError::Malformed)
    }

    /// Fail if any key was not consumed (unknown-key rejection).
    pub fn deny_unknown(&self) -> Result<(), DetCborError> {
        if self.entries.is_empty() {
            Ok(())
        } else {
            Err(DetCborError::Malformed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn negative_integers_round_trip() {
        assert_eq!(hex(&encode(&SVal::int(-2))), "21");
        assert_eq!(hex(&encode(&SVal::int(-8))), "27");
        assert_eq!(SVal::int(-2).as_int(), Some(-2));
        assert_eq!(decode(&[0x21]).unwrap(), SVal::int(-2));
        assert_eq!(SVal::int(i64::MIN).as_int(), Some(i64::MIN));
    }

    #[test]
    fn maps_encode_ascending_regardless_of_construction_order() {
        let a = SVal::Map(vec![(4, SVal::Uint(1)), (1, SVal::Uint(0))]);
        let b = SVal::Map(vec![(1, SVal::Uint(0)), (4, SVal::Uint(1))]);
        assert_eq!(encode(&a), encode(&b));
        assert_eq!(hex(&encode(&a)), "a2010004 01".replace(' ', ""));
    }

    #[test]
    fn rejects_non_canonical_and_forbidden_encodings() {
        assert_eq!(decode(&[0x18, 0x01]), Err(DetCborError::NonShortestForm));
        assert_eq!(decode(&[0x19, 0x00, 0x01]), Err(DetCborError::NonShortestForm));
        assert_eq!(decode(&[0x5f, 0xff]), Err(DetCborError::IndefiniteLength));
        assert_eq!(decode(&[0xf6]), Err(DetCborError::UnsupportedType)); // null
        assert_eq!(decode(&[0xfb, 0, 0, 0, 0, 0, 0, 0, 0]), Err(DetCborError::UnsupportedType));
        assert_eq!(decode(&[0xc0, 0x01]), Err(DetCborError::UnsupportedType)); // tag
        // unsorted map keys {4:0, 1:0}
        assert_eq!(decode(&[0xa2, 0x04, 0x00, 0x01, 0x00]), Err(DetCborError::UnsortedKeys));
        // duplicate map keys
        assert_eq!(decode(&[0xa2, 0x01, 0x00, 0x01, 0x00]), Err(DetCborError::UnsortedKeys));
        // a text key is now a legal map key (C-08), but a map MIXING key majors never is
        assert_eq!(decode(&[0xa1, 0x61, 0x61, 0x00]).unwrap(), SVal::TextMap(vec![("a".into(), SVal::Uint(0))]));
        assert_eq!(
            decode(&[0xa2, 0x00, 0x00, 0x61, 0x61, 0x00]),
            Err(DetCborError::MixedKeyTypes)
        );
        // unsorted text keys: {"bb":0, "a":0} — encoded-byte order is length-first
        assert_eq!(
            decode(&[0xa2, 0x62, 0x62, 0x62, 0x00, 0x61, 0x61, 0x00]),
            Err(DetCborError::UnsortedKeys)
        );
        assert_eq!(decode(&[0x00, 0x00]), Err(DetCborError::TrailingBytes));
    }

    /// The §4.1 depth ceiling: unbounded recursion is a refusal, not a stack overflow.
    #[test]
    fn nesting_beyond_the_ceiling_is_refused() {
        let n = MAX_NESTING_DEPTH as usize;
        let mut ok = vec![0x81u8; n];
        ok.push(0x00);
        assert!(decode(&ok).is_ok(), "exactly at the ceiling is accepted");
        let mut too_deep = vec![0x81u8; n + 1];
        too_deep.push(0x00);
        assert_eq!(decode(&too_deep), Err(DetCborError::NestingTooDeep));
        // The validator applies the same bound, so an over-deep value can never be smuggled in by
        // a caller that constructed it in memory rather than decoding it.
        let mut deep = SVal::Uint(0);
        for _ in 0..=n {
            deep = SVal::Array(vec![deep]);
        }
        assert!(!deep.is_ext_value());
    }

    /// `SYNC-VAL-01` in miniature — the boundary from both sides. The frozen vector drives the
    /// same cases through the conformance runner; this keeps the unit-level regression local.
    #[test]
    fn ext_value_is_the_whole_recursive_type() {
        // accepts
        assert!(SVal::Text("v".into()).is_ext_value());
        assert!(SVal::int(-9).is_ext_value());
        assert!(SVal::Bool(true).is_ext_value());
        assert!(SVal::Array(vec![SVal::Uint(1), SVal::Uint(2)]).is_ext_value());
        // heterogeneous arrays: NEVER actually constrained by §18.3.6 (C-08)
        assert!(SVal::Array(vec![SVal::Uint(1), SVal::Text("a".into())]).is_ext_value());
        // text-keyed maps, recursively (depth 2)
        assert!(SVal::TextMap(vec![(
            "meta".into(),
            SVal::TextMap(vec![("z".into(), SVal::Bytes(vec![1, 2]))])
        )])
        .is_ext_value());
        // the empty map is key-agnostic on the wire and IS the empty ext-value map
        assert!(SVal::Map(Vec::new()).is_ext_value());

        // rejects
        assert!(!SVal::Map(vec![(1, SVal::Uint(1))]).is_ext_value());
        assert!(!SVal::BytesMap(vec![(vec![1], SVal::Uint(1))]).is_ext_value());
        // RECURSIVE: an integer-keyed map nested at depth 2 is caught, not waved through
        assert!(!SVal::TextMap(vec![("meta".into(), SVal::Map(vec![(1, SVal::Uint(0))]))])
            .is_ext_value());
        assert!(!SVal::Array(vec![SVal::Map(vec![(1, SVal::Uint(0))])]).is_ext_value());
    }

    /// A text-keyed map round-trips through the codec byte-exactly, sorted by encoded key bytes
    /// regardless of construction order.
    #[test]
    fn text_keyed_maps_canonicalize_by_encoded_key_bytes() {
        let built = SVal::TextMap(vec![
            ("meta".into(), SVal::TextMap(vec![("z".into(), SVal::Bytes(vec![1, 2]))])),
            ("x".into(), SVal::Uint(10)),
            ("id".into(), SVal::Text("shape-a".into())),
            ("locked".into(), SVal::Bool(false)),
            ("pts".into(), SVal::Array(vec![SVal::Uint(1), SVal::int(-2)])),
        ]);
        // The exact accept-case bytes frozen by `SYNC-VAL-01` (`tstr_map_nested`).
        let want = "a561780a6269646773686170652d6163707473820121646d657461a1617a420102666c6f636b6564f4";
        assert_eq!(hex(&encode(&built)), want);
        // Round-trip: decoding yields the entries in canonical (sorted) order, which re-encodes to
        // the identical bytes. Entry-vector equality is construction-order-sensitive by design —
        // `encode` is the canonicalizer, not the constructor — so the byte form is what round-trips.
        assert_eq!(hex(&encode(&decode(&unhex(want)).unwrap())), want);
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
}
