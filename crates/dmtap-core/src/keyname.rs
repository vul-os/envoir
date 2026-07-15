//! The zero-authority **key-name** — spec §3.9.1, §16.2.
//!
//! Every identity has a memorable name computed deterministically from its identity key,
//! requiring **no directory, no consensus, and no registration**. Two different keys yield
//! different names by construction (uniqueness is cryptographic, not adjudicated).
//!
//! Encoding (spec §3.9.1 / §16.2):
//! `key-name = words( truncate( BLAKE3(IK), 80 bits ), wordlist )` — **8 words** of 10 bits
//! each from a **1024-word** language-agnostic list, giving a 2⁸⁰ address space, plus a
//! **checksum word** so a mistyped/misheard name fails closed rather than resolving to a
//! different key. This crate emits `8 data words + 1 checksum word = 9 words` joined by `-`
//! (§16.2 lists the wordlist "+1 checksum word"; §3.9.1's 8-word example is illustrative of
//! the entropy words only).
//!
//! ## Wordlist source
//! The embedded [`wordlist.txt`](../../wordlist.txt) is **algorithmically generated** (not
//! sourced from a third party, to keep it licensing-clean and reproducible): 1024 unique,
//! short, pronounceable CVCV syllable-words over a confusable-reduced consonant set
//! (`b d f g k l m n p r s t v z`) and the five vowels, spread evenly across the CVCV space
//! for initial-letter variety. This is the proquint-adjacent "pronounceable syllable"
//! encoding explicitly permitted by §3.9.1. Regenerate with `tools/gen_wordlist.py`.

/// The embedded 1024-word list, one word per line (see module docs for provenance).
static WORDLIST_RAW: &str = include_str!("../wordlist.txt");

/// Number of data words (10 bits each ⇒ 80 bits, spec §16.2).
pub const DATA_WORDS: usize = 8;
/// Bits encoded per word (`log2(1024)`).
pub const BITS_PER_WORD: usize = 10;
/// Wordlist size (spec §16.2).
pub const WORDLIST_SIZE: usize = 1 << BITS_PER_WORD; // 1024

fn wordlist() -> &'static [&'static str] {
    use std::sync::OnceLock;
    static WL: OnceLock<Vec<&'static str>> = OnceLock::new();
    WL.get_or_init(|| {
        let v: Vec<&'static str> = WORDLIST_RAW.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(
            v.len(),
            WORDLIST_SIZE,
            "embedded wordlist must contain exactly {WORDLIST_SIZE} words"
        );
        v
    })
}

/// Index of a word in the list, or `None` if absent.
fn word_index(w: &str) -> Option<u16> {
    wordlist().iter().position(|&x| x == w).map(|i| i as u16)
}

/// Pull `DATA_WORDS` 10-bit groups (big-endian bit order) out of the first 10 bytes of `hash`.
fn indices_from_hash(hash: &[u8; 32]) -> [u16; DATA_WORDS] {
    // 80 bits = 10 bytes, read MSB-first into 10-bit chunks.
    let mut acc: u32 = 0;
    let mut bits = 0usize;
    let mut out = [0u16; DATA_WORDS];
    let mut oi = 0usize;
    for &byte in &hash[..10] {
        acc = (acc << 8) | byte as u32;
        bits += 8;
        while bits >= BITS_PER_WORD && oi < DATA_WORDS {
            bits -= BITS_PER_WORD;
            out[oi] = ((acc >> bits) & 0x3ff) as u16;
            oi += 1;
        }
    }
    debug_assert_eq!(oi, DATA_WORDS);
    out
}

/// The checksum word index: the top 10 bits of `BLAKE3("dmtap-keyname-checksum" || first 10
/// bytes of the key hash)`. Folding a fresh hash over the entropy bytes makes a
/// single-character typo overwhelmingly likely to change the checksum word.
fn checksum_index(hash: &[u8; 32]) -> u16 {
    let mut h = blake3::Hasher::new();
    h.update(b"dmtap-keyname-checksum");
    h.update(&hash[..10]);
    let d = h.finalize();
    let b = d.as_bytes();
    (((b[0] as u16) << 2) | ((b[1] as u16) >> 6)) & 0x3ff
}

/// Derive the key-name for an identity public key (spec §3.9.1).
///
/// Returns `8 data words + 1 checksum word`, hyphen-joined, e.g.
/// `"ma: bafu-…-…"` (data words derived from `BLAKE3(pubkey)`).
pub fn encode(pubkey: &[u8]) -> String {
    let wl = wordlist();
    let hash: [u8; 32] = *blake3::hash(pubkey).as_bytes();
    let idx = indices_from_hash(&hash);
    let cksum = checksum_index(&hash);

    let mut words: Vec<&str> = idx.iter().map(|&i| wl[i as usize]).collect();
    words.push(wl[cksum as usize]);
    words.join("-")
}

/// Verify a key-name's **internal checksum** (typo/mishear detection, spec §3.9.1).
///
/// This does not prove the name maps to any particular key — it fails closed on a mistyped or
/// truncated name so it cannot silently resolve to a *different* key. To bind a name to a key,
/// compare against [`encode`] of the pinned key.
pub fn verify(name: &str) -> bool {
    let words: Vec<&str> = name.split('-').collect();
    if words.len() != DATA_WORDS + 1 {
        return false; // wrong length — fail closed
    }
    // Reconstruct the 80-bit hash prefix from the 8 data words, then recompute the checksum.
    let mut idx = [0u16; DATA_WORDS];
    for (slot, w) in idx.iter_mut().zip(&words[..DATA_WORDS]) {
        match word_index(w) {
            Some(i) => *slot = i,
            None => return false, // unknown word — fail closed
        }
    }
    let claimed_cksum = match word_index(words[DATA_WORDS]) {
        Some(i) => i,
        None => return false,
    };

    // Pack the 8×10 bits back into the first 10 bytes of a scratch hash buffer.
    let mut bytes = [0u8; 32];
    let mut acc: u32 = 0;
    let mut bits = 0usize;
    let mut bi = 0usize;
    for &i in &idx {
        acc = (acc << BITS_PER_WORD) | i as u32;
        bits += BITS_PER_WORD;
        while bits >= 8 {
            bits -= 8;
            bytes[bi] = ((acc >> bits) & 0xff) as u8;
            bi += 1;
        }
    }
    checksum_index(&bytes) == claimed_cksum
}

/// Verify a key-name actually belongs to `pubkey` (checksum + full key binding).
pub fn matches(name: &str, pubkey: &[u8]) -> bool {
    verify(name) && encode(pubkey) == name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_is_exactly_1024_unique() {
        let wl = wordlist();
        assert_eq!(wl.len(), 1024);
        let mut sorted = wl.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 1024, "wordlist must be 1024 UNIQUE words");
    }

    #[test]
    fn determinism_same_key_same_name() {
        let key = [7u8; 32];
        let a = encode(&key);
        let b = encode(&key);
        assert_eq!(a, b, "encoding must be deterministic");
        assert_eq!(a.split('-').count(), DATA_WORDS + 1);
    }

    #[test]
    fn different_keys_different_names() {
        let n1 = encode(&[1u8; 32]);
        let n2 = encode(&[2u8; 32]);
        assert_ne!(n1, n2, "distinct keys must yield distinct names");
    }

    #[test]
    fn checksum_accepts_valid_and_rejects_typos() {
        let name = encode(&[42u8; 32]);
        assert!(verify(&name), "a freshly encoded name must checksum-verify");

        // Corrupt one data word → checksum must fail closed.
        let mut words: Vec<String> = name.split('-').map(str::to_owned).collect();
        let wl = wordlist();
        let bad = if words[0] == wl[0] { wl[1] } else { wl[0] };
        words[0] = bad.to_string();
        let typo = words.join("-");
        assert_ne!(typo, name);
        assert!(!verify(&typo), "a mistyped word must fail the checksum");
    }

    #[test]
    fn wrong_word_count_and_unknown_words_fail_closed() {
        assert!(!verify("baba-badu")); // too short
        assert!(!verify("not-a-real-word-here-nope-nada-zilch-xxxx")); // unknown words
    }

    #[test]
    fn matches_binds_name_to_key() {
        let key = [9u8; 32];
        let name = encode(&key);
        assert!(matches(&name, &key));
        assert!(!matches(&name, &[10u8; 32]));
    }
}
