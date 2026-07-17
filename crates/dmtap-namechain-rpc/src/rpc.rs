//! JSON-RPC request/response shaping over an [`HttpTransport`] — the pure glue between the ENS/SNS
//! decoders and the wire. Read-only methods only: Ethereum `eth_call` and Solana `getAccountInfo`
//! (§3.12.5(c) — a lookup never sends a transaction).

use base64::Engine;
use serde_json::Value;

use crate::transport::HttpTransport;
use crate::NamechainError;

/// The outcome of an `eth_call`: either the returned bytes, or the contract's revert data (needed to
/// detect an EIP-3668 `OffchainLookup`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallResult {
    /// The call returned normally with these ABI-encoded bytes.
    Return(Vec<u8>),
    /// The call reverted with this data (may be a decodable custom error such as `OffchainLookup`).
    Revert(Vec<u8>),
}

/// `eth_call { to, data }` at `latest`. Returns [`CallResult`]; a JSON-RPC error **without** revert
/// data (or malformed JSON) is a fail-closed [`NamechainError::Rpc`].
pub fn eth_call<T: HttpTransport>(
    transport: &T,
    endpoint: &str,
    to: &[u8; 20],
    data: &[u8],
) -> Result<CallResult, NamechainError> {
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [
            { "to": format!("0x{}", hex::encode(to)), "data": format!("0x{}", hex::encode(data)) },
            "latest"
        ]
    });
    let body = transport.post_json(endpoint, req.to_string().as_bytes())?;
    let v: Value = serde_json::from_slice(&body).map_err(|e| NamechainError::Rpc(e.to_string()))?;

    if let Some(result) = v.get("result").and_then(Value::as_str) {
        return Ok(CallResult::Return(decode_hex_0x(result)?));
    }
    // An error object: an `OffchainLookup` (and other custom errors) arrive as revert data here.
    if let Some(err) = v.get("error") {
        if let Some(data) = err.get("data").and_then(Value::as_str) {
            if let Ok(bytes) = decode_hex_0x(data) {
                return Ok(CallResult::Revert(bytes));
            }
        }
        let msg = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("eth_call error");
        return Err(NamechainError::Rpc(msg.to_owned()));
    }
    Err(NamechainError::Rpc("eth_call: no result or error".into()))
}

/// `getAccountInfo(pubkey, base64)`. `Ok(None)` when the account does not exist (null value);
/// `Ok(Some(bytes))` is the decoded account data. Malformed JSON fails closed.
pub fn get_account_info<T: HttpTransport>(
    transport: &T,
    endpoint: &str,
    pubkey_base58: &str,
) -> Result<Option<Vec<u8>>, NamechainError> {
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [ pubkey_base58, { "encoding": "base64", "commitment": "confirmed" } ]
    });
    let body = transport.post_json(endpoint, req.to_string().as_bytes())?;
    let v: Value = serde_json::from_slice(&body).map_err(|e| NamechainError::Rpc(e.to_string()))?;

    if let Some(err) = v.get("error") {
        let msg = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("getAccountInfo error");
        return Err(NamechainError::Rpc(msg.to_owned()));
    }
    let value = v
        .get("result")
        .and_then(|r| r.get("value"))
        .ok_or_else(|| NamechainError::Rpc("getAccountInfo: no result.value".into()))?;
    if value.is_null() {
        return Ok(None); // account does not exist → unregistered name
    }
    // result.value.data == ["<base64>", "base64"].
    let b64 = value
        .get("data")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(Value::as_str)
        .ok_or_else(|| NamechainError::Rpc("getAccountInfo: unexpected data encoding".into()))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| NamechainError::MalformedRecord("account data is not valid base64"))?;
    Ok(Some(bytes))
}

/// Decode a `0x`-prefixed hex string to bytes.
pub fn decode_hex_0x(s: &str) -> Result<Vec<u8>, NamechainError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|_| NamechainError::MalformedRecord("value is not 0x-hex"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::MockTransport;

    #[test]
    fn eth_call_return_is_decoded() {
        let mock = MockTransport::ok(br#"{"jsonrpc":"2.0","id":1,"result":"0x00ff"}"#.to_vec());
        let r = eth_call(&mock, "https://rpc", &[0u8; 20], &[0x12]).unwrap();
        assert_eq!(r, CallResult::Return(vec![0x00, 0xff]));
        // Assert the request was well-formed JSON-RPC.
        let (url, body) = mock.requests.borrow()[0].clone();
        assert_eq!(url, "https://rpc");
        let sent: Value = serde_json::from_slice(&body.unwrap()).unwrap();
        assert_eq!(sent["method"], "eth_call");
        assert_eq!(sent["params"][0]["data"], "0x12");
    }

    #[test]
    fn eth_call_revert_data_surfaces_as_revert() {
        let mock = MockTransport::ok(
            br#"{"jsonrpc":"2.0","id":1,"error":{"code":3,"message":"execution reverted","data":"0x556f1830"}}"#.to_vec(),
        );
        let r = eth_call(&mock, "https://rpc", &[0u8; 20], &[]).unwrap();
        assert_eq!(r, CallResult::Revert(vec![0x55, 0x6f, 0x18, 0x30]));
    }

    #[test]
    fn eth_call_error_without_data_fails_closed() {
        let mock = MockTransport::ok(
            br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"boom"}}"#.to_vec(),
        );
        assert!(matches!(
            eth_call(&mock, "https://rpc", &[0u8; 20], &[]),
            Err(NamechainError::Rpc(_))
        ));
    }

    #[test]
    fn get_account_info_null_is_none() {
        let mock = MockTransport::ok(
            br#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":null}}"#.to_vec(),
        );
        assert_eq!(
            get_account_info(&mock, "https://sol", "So11111111111111111111111111111111111111112").unwrap(),
            None
        );
    }

    #[test]
    fn get_account_info_decodes_base64() {
        // base64("hi") == "aGk=".
        let mock = MockTransport::ok(
            br#"{"jsonrpc":"2.0","id":1,"result":{"value":{"data":["aGk=","base64"],"lamports":1}}}"#
                .to_vec(),
        );
        assert_eq!(
            get_account_info(&mock, "https://sol", "x").unwrap(),
            Some(b"hi".to_vec())
        );
    }

    #[test]
    fn malformed_json_fails_closed() {
        let mock = MockTransport::ok(b"not json".to_vec());
        assert!(matches!(
            eth_call(&mock, "https://rpc", &[0u8; 20], &[]),
            Err(NamechainError::Rpc(_))
        ));
    }
}
