//! Minimal, strict **base64url without padding** (RFC 4648 §5) — the DNS TXT `ik=`/`id=` encoding
//! (§3.2). Kept dependency-free and fail-closed: a non-alphabet byte, stray padding, or an
//! impossible length (a lone trailing sextet) is rejected rather than silently normalised, so a
//! malformed record never decodes to a plausible-looking key.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode `bytes` as unpadded base64url. Total function.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 0x3f) as usize] as char);
        }
    }
    out
}

/// Decode unpadded base64url, failing closed on any non-alphabet character, embedded/trailing `=`
/// padding, or an impossible sextet count. Returns `None` on any violation.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let s = s.as_bytes();
    // A base64 group is 4 sextets; a remainder of exactly 1 sextet is impossible (would encode 6
    // bits, less than one byte).
    if s.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for chunk in s.chunks(4) {
        let mut acc = 0u32;
        for &c in chunk {
            acc = (acc << 6) | val(c)?; // fail closed on '=' or any non-alphabet byte
        }
        // Left-align the accumulated bits for a short (2- or 3-char) final group.
        acc <<= 6 * (4 - chunk.len());
        out.push((acc >> 16) as u8);
        if chunk.len() >= 3 {
            out.push((acc >> 8) as u8);
        }
        if chunk.len() >= 4 {
            out.push(acc as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_arbitrary_lengths() {
        for len in 0..40 {
            let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37)).collect();
            let enc = encode(&data);
            assert!(!enc.contains('='), "no padding in base64url");
            assert_eq!(decode(&enc).as_deref(), Some(data.as_slice()));
        }
    }

    #[test]
    fn rejects_padding_and_bad_chars() {
        assert_eq!(decode("QQ=="), None, "padding is rejected");
        assert_eq!(decode("AA+B"), None, "'+' is base64, not base64url");
        assert_eq!(decode("AA/B"), None, "'/' is base64, not base64url");
        assert_eq!(decode("A"), None, "a lone sextet is impossible");
        assert_eq!(decode("****"), None, "non-alphabet bytes fail closed");
    }

    #[test]
    fn decodes_url_safe_alphabet() {
        // 0xff 0xff -> "__" bits; use a vector exercising - and _.
        let data = vec![0xfb, 0xff, 0xbf];
        let enc = encode(&data);
        assert_eq!(decode(&enc), Some(data));
    }
}
