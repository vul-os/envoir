//! Minimal Ethereum **Keccak-256 + ABI** helpers for the ENS path — just enough to encode two calls
//! (`resolver(bytes32)`, `text(bytes32,string)`), the CCIP-Read callback, and to decode a returned
//! `string`/`address` and an `OffchainLookup` revert. No `ethabi`/`ethers` dependency.
//!
//! Ethereum uses **pre-NIST Keccak-256** (`sha3::Keccak256`), not SHA3-256; the 4-byte function/error
//! selectors and the EIP-137 namehash both fold with it.

use sha3::{Digest, Keccak256};

use crate::NamechainError;

/// Keccak-256 (Ethereum's hash), the primitive under EIP-137 namehash and every 4-byte selector.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// The 4-byte function/error selector for a Solidity signature: `keccak256(sig)[..4]`.
pub fn selector(signature: &str) -> [u8; 4] {
    let h = keccak256(signature.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

/// ABI-encode a `bytes32` argument (already 32 bytes) as one word.
pub fn word_bytes32(node: &[u8; 32]) -> [u8; 32] {
    *node
}

/// ABI-encode call data for `resolver(bytes32 node)` on the ENS registry.
pub fn encode_resolver(node: &[u8; 32]) -> Vec<u8> {
    let mut v = selector("resolver(bytes32)").to_vec();
    v.extend_from_slice(&word_bytes32(node));
    v
}

/// ABI-encode call data for `text(bytes32 node, string key)` on an ENS resolver.
pub fn encode_text(node: &[u8; 32], key: &str) -> Vec<u8> {
    let mut v = selector("text(bytes32,string)").to_vec();
    v.extend_from_slice(&word_bytes32(node)); // arg0: node
    v.extend_from_slice(&left_pad_u64(0x40)); // arg1: offset to the dynamic string (2 words in)
    v.extend_from_slice(&encode_dynamic_bytes(key.as_bytes())); // len + padded utf-8
    v
}

/// ABI-encode a CCIP-Read callback: `callbackFn(bytes response, bytes extraData)` (EIP-3668 step 4).
pub fn encode_callback(callback_fn: [u8; 4], response: &[u8], extra_data: &[u8]) -> Vec<u8> {
    let mut v = callback_fn.to_vec();
    // Two `bytes` args: two head offset words, then each arg's (len + padded data) tail.
    v.extend_from_slice(&left_pad_u64(0x40)); // offset to arg0
    let arg0 = encode_dynamic_bytes(response);
    v.extend_from_slice(&left_pad_u64(0x40 + arg0.len() as u64)); // offset to arg1
    v.extend_from_slice(&arg0);
    v.extend_from_slice(&encode_dynamic_bytes(extra_data));
    v
}

/// The `len` word followed by the data right-padded to a 32-byte boundary (ABI `bytes`/`string`).
fn encode_dynamic_bytes(data: &[u8]) -> Vec<u8> {
    let mut v = left_pad_u64(data.len() as u64).to_vec();
    v.extend_from_slice(data);
    let rem = data.len() % 32;
    if rem != 0 {
        v.extend(std::iter::repeat(0u8).take(32 - rem));
    }
    v
}

/// A `u64` left-padded into a 32-byte big-endian ABI word.
fn left_pad_u64(n: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&n.to_be_bytes());
    w
}

/// Read a 32-byte word at word index `i` (byte offset `i*32`).
fn word_at(data: &[u8], i: usize) -> Result<&[u8], NamechainError> {
    let start = i.checked_mul(32).ok_or(bad("word index overflow"))?;
    data.get(start..start + 32).ok_or(bad("truncated ABI word"))
}

/// Read a 32-byte word as a byte offset/length `usize` (rejecting absurd high words).
fn read_usize(data: &[u8], i: usize) -> Result<usize, NamechainError> {
    let w = word_at(data, i)?;
    // Only the low 8 bytes may be set for a sane offset/length; reject anything larger.
    if w[..24].iter().any(|b| *b != 0) {
        return Err(bad("ABI offset/length too large"));
    }
    let mut n = [0u8; 8];
    n.copy_from_slice(&w[24..]);
    Ok(u64::from_be_bytes(n) as usize)
}

/// Decode an ABI-returned `string` (the shape ENS `text()` returns): `[offset][len][utf8…]`.
pub fn decode_string(data: &[u8]) -> Result<String, NamechainError> {
    let off = read_usize(data, 0)?;
    let len = read_usize_at_byte(data, off)?;
    let start = off
        .checked_add(32)
        .ok_or(bad("string data offset overflow"))?;
    let bytes = data
        .get(start..start.checked_add(len).ok_or(bad("string length overflow"))?)
        .ok_or(bad("truncated ABI string"))?;
    String::from_utf8(bytes.to_vec()).map_err(|_| bad("ABI string is not utf-8"))
}

/// Decode an ABI-returned `address` (right-aligned in a 32-byte word) to its 20 bytes; `None` for the
/// zero address (ENS registry's "no resolver set").
pub fn decode_address(data: &[u8]) -> Result<Option<[u8; 20]>, NamechainError> {
    let w = word_at(data, 0)?;
    if w.iter().all(|b| *b == 0) {
        return Ok(None);
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(&w[12..32]);
    Ok(Some(a))
}

/// Decode an ABI `bytes` value whose header word sits at byte offset `off`: `[len][data…]`.
fn dynamic_bytes_at(data: &[u8], off: usize) -> Result<Vec<u8>, NamechainError> {
    let len = read_usize_at_byte(data, off)?;
    let start = off.checked_add(32).ok_or(bad("bytes offset overflow"))?;
    let end = start.checked_add(len).ok_or(bad("bytes length overflow"))?;
    Ok(data.get(start..end).ok_or(bad("truncated ABI bytes"))?.to_vec())
}

/// Read a 32-byte length/offset word located at an arbitrary **byte** offset (not word-aligned index).
fn read_usize_at_byte(data: &[u8], byte_off: usize) -> Result<usize, NamechainError> {
    let w = data
        .get(byte_off..byte_off.checked_add(32).ok_or(bad("word overflow"))?)
        .ok_or(bad("truncated ABI word"))?;
    if w[..24].iter().any(|b| *b != 0) {
        return Err(bad("ABI offset/length too large"));
    }
    let mut n = [0u8; 8];
    n.copy_from_slice(&w[24..]);
    Ok(u64::from_be_bytes(n) as usize)
}

/// The selector of the EIP-3668 CCIP-Read revert `OffchainLookup(address,string[],bytes,bytes4,bytes)`.
pub fn offchain_lookup_selector() -> [u8; 4] {
    selector("OffchainLookup(address,string[],bytes,bytes4,bytes)")
}

/// A decoded EIP-3668 `OffchainLookup` revert (ENSIP-10 off-chain resolution).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OffchainLookup {
    /// The contract that must receive the CCIP callback (the resolver), 20 bytes.
    pub sender: [u8; 20],
    /// Gateway URL templates (`{sender}` / `{data}` placeholders), in preference order.
    pub urls: Vec<String>,
    /// The opaque request payload the gateway is asked to answer for.
    pub call_data: Vec<u8>,
    /// The 4-byte callback function to `eth_call` on `sender` with the gateway's answer.
    pub callback_function: [u8; 4],
    /// Opaque data echoed back into the callback alongside the gateway response.
    pub extra_data: Vec<u8>,
}

/// Decode the ABI body of an `OffchainLookup` revert (the bytes **after** its 4-byte selector).
///
/// Layout (5 head words): `sender`, `off(urls)`, `off(callData)`, `callbackFunction`, `off(extraData)`.
pub fn decode_offchain_lookup(body: &[u8]) -> Result<OffchainLookup, NamechainError> {
    // head[0]: sender address (right-aligned).
    let sender = decode_address(body)?.ok_or(bad("OffchainLookup zero sender"))?;

    // head[3]: callbackFunction, a bytes4 left-aligned in its word.
    let cbw = word_at(body, 3)?;
    let callback_function = [cbw[0], cbw[1], cbw[2], cbw[3]];

    // head[1]: string[] urls, at a byte offset from the start of `body`.
    let urls_off = read_usize(body, 1)?;
    let urls = decode_string_array(body, urls_off)?;

    // head[2] / head[4]: two `bytes` at their byte offsets.
    let call_data = dynamic_bytes_at(body, read_usize(body, 2)?)?;
    let extra_data = dynamic_bytes_at(body, read_usize(body, 4)?)?;

    Ok(OffchainLookup {
        sender,
        urls,
        call_data,
        callback_function,
        extra_data,
    })
}

/// Decode an ABI `string[]` whose header sits at byte offset `off`: `[count][off0][off1]…[str0]…`,
/// where each `offi` is relative to the first word **after** the count.
fn decode_string_array(data: &[u8], off: usize) -> Result<Vec<String>, NamechainError> {
    let count = read_usize_at_byte(data, off)?;
    if count > 64 {
        return Err(bad("implausible OffchainLookup url count"));
    }
    let base = off.checked_add(32).ok_or(bad("url array base overflow"))?;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let slot = base
            .checked_add(i.checked_mul(32).ok_or(bad("url index overflow"))?)
            .ok_or(bad("url slot overflow"))?;
        let rel = read_usize_at_byte(data, slot)?;
        let str_off = base.checked_add(rel).ok_or(bad("url string offset overflow"))?;
        let len = read_usize_at_byte(data, str_off)?;
        let s = str_off.checked_add(32).ok_or(bad("url string data overflow"))?;
        let bytes = data
            .get(s..s.checked_add(len).ok_or(bad("url string length overflow"))?)
            .ok_or(bad("truncated OffchainLookup url"))?;
        out.push(String::from_utf8(bytes.to_vec()).map_err(|_| bad("OffchainLookup url not utf-8"))?);
    }
    Ok(out)
}

fn bad(msg: &'static str) -> NamechainError {
    NamechainError::MalformedRecord(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Keccak-256 known-answer vectors (Ethereum's hash, NOT NIST SHA3-256) ----
    #[test]
    fn keccak256_empty_kat() {
        // The canonical keccak256("") every EVM tool agrees on.
        assert_eq!(
            hex::encode(keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn well_known_selectors_kat() {
        // These 4-byte selectors are fixed constants of the ENS ABI; deriving them from the signature
        // doubles as a keccak KAT.
        assert_eq!(hex::encode(selector("resolver(bytes32)")), "0178b8bf");
        assert_eq!(hex::encode(selector("text(bytes32,string)")), "59d1d43c");
        assert_eq!(hex::encode(selector("addr(bytes32)")), "3b3b57de");
        assert_eq!(hex::encode(offchain_lookup_selector()), "556f1830");
    }

    #[test]
    fn encode_text_roundtrips_shape() {
        let node = [0x11u8; 32];
        let data = encode_text(&node, "dmtap");
        // selector(4) + node(32) + offset(32) + len(32) + "dmtap" padded(32) = 132 bytes.
        assert_eq!(&data[..4], &hex::decode("59d1d43c").unwrap()[..]);
        assert_eq!(&data[4..36], &node[..]);
        assert_eq!(data.len(), 132);
        assert_eq!(&data[36..68][24..], &0x40u64.to_be_bytes());
        assert_eq!(&data[68..100][24..], &5u64.to_be_bytes());
        assert_eq!(&data[100..105], b"dmtap");
    }

    #[test]
    fn decode_string_kat() {
        // ABI string "0xabcd": offset 0x20, len 6, then the 6 bytes right-padded.
        let mut blob = Vec::new();
        blob.extend_from_slice(&{
            let mut w = [0u8; 32];
            w[31] = 0x20;
            w
        });
        blob.extend_from_slice(&{
            let mut w = [0u8; 32];
            w[31] = 6;
            w
        });
        let mut last = [0u8; 32];
        last[..6].copy_from_slice(b"0xabcd");
        blob.extend_from_slice(&last);
        assert_eq!(decode_string(&blob).unwrap(), "0xabcd");
    }

    #[test]
    fn decode_address_zero_is_none() {
        assert_eq!(decode_address(&[0u8; 32]).unwrap(), None);
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&[0xabu8; 20]);
        assert_eq!(decode_address(&w).unwrap(), Some([0xabu8; 20]));
    }

    #[test]
    fn decode_offchain_lookup_kat() {
        // Hand-build a minimal OffchainLookup body: sender, one url "https://g/{sender}/{data}",
        // callData 0x1234, callback 0xdeadbeef, extraData 0x99.
        let sender = [0x0au8; 20];
        let url = "https://g/{sender}/{data}.json";
        let call_data = vec![0x12, 0x34];
        let extra = vec![0x99];

        // Head: 5 words. Tail begins at byte 160.
        fn w_usize(n: u64) -> [u8; 32] {
            let mut w = [0u8; 32];
            w[24..].copy_from_slice(&n.to_be_bytes());
            w
        }
        fn dyn_bytes(b: &[u8]) -> Vec<u8> {
            let mut v = w_usize(b.len() as u64).to_vec();
            v.extend_from_slice(b);
            let rem = b.len() % 32;
            if rem != 0 {
                v.extend(std::iter::repeat(0u8).take(32 - rem));
            }
            v
        }

        let mut body = Vec::new();
        // head[0] sender
        let mut sw = [0u8; 32];
        sw[12..].copy_from_slice(&sender);
        body.extend_from_slice(&sw);
        // We will fill offsets after laying the tail out.
        let head_len = 160usize;
        // Tail 1: urls (string[]) — count 1, one rel offset (0x20), then the string.
        let mut urls_tail = Vec::new();
        urls_tail.extend_from_slice(&w_usize(1)); // count
        urls_tail.extend_from_slice(&w_usize(0x20)); // rel offset to url0 from after count
        urls_tail.extend_from_slice(&dyn_bytes(url.as_bytes()));
        // Tail 2: callData bytes. Tail 3: extraData bytes.
        let call_tail = dyn_bytes(&call_data);
        let extra_tail = dyn_bytes(&extra);

        let urls_off = head_len;
        let call_off = urls_off + urls_tail.len();
        let extra_off = call_off + call_tail.len();

        body.extend_from_slice(&w_usize(urls_off as u64)); // head[1]
        body.extend_from_slice(&w_usize(call_off as u64)); // head[2]
        let mut cbw = [0u8; 32];
        cbw[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // head[3] callbackFunction
        body.extend_from_slice(&cbw);
        body.extend_from_slice(&w_usize(extra_off as u64)); // head[4]
        assert_eq!(body.len(), head_len);
        body.extend_from_slice(&urls_tail);
        body.extend_from_slice(&call_tail);
        body.extend_from_slice(&extra_tail);

        let ol = decode_offchain_lookup(&body).unwrap();
        assert_eq!(ol.sender, sender);
        assert_eq!(ol.urls, vec![url.to_string()]);
        assert_eq!(ol.call_data, call_data);
        assert_eq!(ol.callback_function, [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(ol.extra_data, extra);
    }

    #[test]
    fn decode_string_rejects_truncation() {
        assert!(decode_string(&[0u8; 16]).is_err());
    }
}
