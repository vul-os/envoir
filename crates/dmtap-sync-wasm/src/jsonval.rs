//! The JS↔Rust value marshalling: a **tagged, lossless** JSON spelling of the substrate's
//! `ext-value` domain, plus `Hlc`/`AddTag`/`OpRef`/`SyncOp` projections.
//!
//! ## Why tagged JSON and not "just JSON"
//!
//! JSON cannot tell a text string from a hex-spelled byte string, and its single `number` type
//! cannot tell `5` from `5.0`. The substrate's whole contract is that *the bytes are the
//! semantics* (`SYNC.md` §2.2) — a value that round-trips through an ambiguous JS shape and comes
//! back as a different CBOR encoding is a divergence, not a formatting difference. So every value
//! crossing the boundary is spelled with an explicit type tag:
//!
//! | `SVal` | JSON |
//! |---|---|
//! | `Text` | `{"tstr": "v"}` |
//! | `Bytes` | `{"bstr": "6162"}` (lowercase hex) |
//! | `Uint`/`Nint` | `{"int": -3}` |
//! | `Bool` | `{"bool": true}` |
//! | `Array` | `{"arr": [ … ]}` |
//! | `Map` | `{"map": [[1, …], …]}` (integer keys) |
//! | `BytesMap` | `{"bmap": [["6162", …], …]}` |
//! | `TextMap` | `{"tmap": [["x", …], …]}` (text keys — the `ext-value` map arm, §14 C-08) |
//!
//! `tmap` is the newest of these and the one a *product* actually reaches for: it is §18.3.6's
//! `{ * tstr => ext-value }` arm, which §4.1 previously omitted. Without a tag for it there is no
//! way to *encode* a nested application object from JS at all — which is exactly the encoder-side
//! half of the double refusal C-08 records.
//!
//! Integers are carried as JSON numbers and are therefore bounded by JS's exact-integer range
//! (±2^53). That is enough for every value the substrate mints (HLC walls are milliseconds, PN
//! deltas are §4.6 scalars) and it is checked, not assumed: an out-of-range integer is a hard
//! error here rather than a silently rounded one on the JS side.

use dmtap_sync::detcbor::SVal;
use dmtap_sync::wire::{AddTag, Hlc, OpRef, SyncOp};
use serde_json::{json, Map, Value};

/// The largest integer JS represents exactly. Anything beyond it is refused, never rounded.
const JS_SAFE_INT: i64 = 9_007_199_254_740_991;

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!("hex string has odd length ({})", s.len()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("bad hex: {e}")))
        .collect()
}

fn safe_int(v: i64, what: &str) -> Result<Value, String> {
    if v.abs() > JS_SAFE_INT {
        return Err(format!("{what} ({v}) is outside JavaScript's exact-integer range"));
    }
    Ok(json!(v))
}

fn field<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    v.get(k).filter(|x| !x.is_null())
}

fn text(v: &Value, k: &str) -> Result<String, String> {
    field(v, k)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("missing or non-string `{k}`"))
}

fn u64_of(v: &Value, k: &str) -> Result<u64, String> {
    field(v, k).and_then(Value::as_u64).ok_or_else(|| format!("missing or non-integer `{k}`"))
}

// --- SVal ---------------------------------------------------------------------------------------

/// Project an `SVal` into its tagged JSON spelling.
pub fn sval_to_json(v: &SVal) -> Result<Value, String> {
    Ok(match v {
        SVal::Text(t) => json!({ "tstr": t }),
        SVal::Bytes(b) => json!({ "bstr": hex(b) }),
        SVal::Bool(b) => json!({ "bool": b }),
        SVal::Uint(_) | SVal::Nint(_) => {
            let n = v.as_int().ok_or("integer is outside the i64 range")?;
            json!({ "int": safe_int(n, "integer")? })
        }
        SVal::Array(items) => {
            let a: Result<Vec<Value>, String> = items.iter().map(sval_to_json).collect();
            json!({ "arr": a? })
        }
        SVal::Map(entries) => {
            let mut out = Vec::with_capacity(entries.len());
            for (k, val) in entries {
                out.push(json!([safe_int(*k as i64, "map key")?, sval_to_json(val)?]));
            }
            json!({ "map": out })
        }
        SVal::BytesMap(entries) => {
            let mut out = Vec::with_capacity(entries.len());
            for (k, val) in entries {
                out.push(json!([hex(k), sval_to_json(val)?]));
            }
            json!({ "bmap": out })
        }
        SVal::TextMap(entries) => {
            let mut out = Vec::with_capacity(entries.len());
            for (k, val) in entries {
                out.push(json!([k, sval_to_json(val)?]));
            }
            json!({ "tmap": out })
        }
    })
}

/// Parse a tagged JSON value back into an `SVal`. Exactly one tag must be present.
pub fn sval_from_json(v: &Value) -> Result<SVal, String> {
    let obj: &Map<String, Value> = v.as_object().ok_or("value is not a tagged object")?;
    if obj.len() != 1 {
        return Err(format!("a tagged value carries exactly one tag, got {}", obj.len()));
    }
    let (tag, body) = obj.iter().next().expect("len == 1");
    match tag.as_str() {
        "tstr" => Ok(SVal::Text(body.as_str().ok_or("`tstr` is not a string")?.to_owned())),
        "bstr" => Ok(SVal::Bytes(unhex(body.as_str().ok_or("`bstr` is not a string")?)?)),
        "bool" => Ok(SVal::Bool(body.as_bool().ok_or("`bool` is not a boolean")?)),
        "int" => {
            let n = body.as_i64().ok_or("`int` is not an integer")?;
            if n.abs() > JS_SAFE_INT {
                return Err(format!("`int` ({n}) is outside JavaScript's exact-integer range"));
            }
            Ok(SVal::int(n))
        }
        "arr" => {
            let items = body.as_array().ok_or("`arr` is not an array")?;
            Ok(SVal::Array(items.iter().map(sval_from_json).collect::<Result<_, _>>()?))
        }
        "map" => {
            let items = body.as_array().ok_or("`map` is not an array")?;
            let mut out = Vec::with_capacity(items.len());
            for pair in items {
                let p = pair.as_array().filter(|p| p.len() == 2).ok_or("`map` entry is not a pair")?;
                let k = p[0].as_u64().ok_or("`map` key is not an unsigned integer")?;
                out.push((k, sval_from_json(&p[1])?));
            }
            Ok(SVal::Map(out))
        }
        "bmap" => {
            let items = body.as_array().ok_or("`bmap` is not an array")?;
            let mut out = Vec::with_capacity(items.len());
            for pair in items {
                let p = pair.as_array().filter(|p| p.len() == 2).ok_or("`bmap` entry is not a pair")?;
                let k = unhex(p[0].as_str().ok_or("`bmap` key is not a hex string")?)?;
                out.push((k, sval_from_json(&p[1])?));
            }
            Ok(SVal::BytesMap(out))
        }
        "tmap" => {
            let items = body.as_array().ok_or("`tmap` is not an array")?;
            let mut out = Vec::with_capacity(items.len());
            for pair in items {
                let p = pair.as_array().filter(|p| p.len() == 2).ok_or("`tmap` entry is not a pair")?;
                let k = p[0].as_str().ok_or("`tmap` key is not a string")?.to_owned();
                out.push((k, sval_from_json(&p[1])?));
            }
            Ok(SVal::TextMap(out))
        }
        other => Err(format!("unknown value tag `{other}`")),
    }
}

// --- Hlc / AddTag / OpRef -----------------------------------------------------------------------

pub fn hlc_to_json(h: &Hlc) -> Value {
    json!({ "wall": h.wall, "counter": h.counter, "author": hex(&h.author) })
}

pub fn hlc_from_json(v: &Value) -> Result<Hlc, String> {
    // `author_hex` is accepted as an alias because that is the spelling the frozen conformance
    // vectors use; a harness should never have to rename a field to feed the engine.
    let author = match field(v, "author").or_else(|| field(v, "author_hex")) {
        Some(a) => unhex(a.as_str().ok_or("`author` is not a hex string")?)?,
        None => return Err("missing `author`".into()),
    };
    Ok(Hlc {
        wall: u64_of(v, "wall")?,
        counter: u32::try_from(u64_of(v, "counter")?).map_err(|_| "`counter` exceeds u32")?,
        author,
    })
}

pub fn addtag_to_json(t: &AddTag) -> Value {
    json!({ "author": hex(&t.author), "hlc": hlc_to_json(&t.hlc) })
}

fn addtag_from_json(v: &Value) -> Result<AddTag, String> {
    Ok(AddTag {
        author: unhex(&text(v, "author")?)?,
        hlc: hlc_from_json(field(v, "hlc").ok_or("missing `hlc`")?)?,
    })
}

fn opref_to_json(r: &OpRef) -> Value {
    json!({ "target": r.target, "hlc": r.hlc.as_ref().map(hlc_to_json) })
}

fn opref_from_json(v: &Value) -> Result<OpRef, String> {
    Ok(OpRef {
        target: text(v, "target")?,
        hlc: match field(v, "hlc") {
            Some(h) => Some(hlc_from_json(h)?),
            None => None,
        },
    })
}

// --- SyncOp -------------------------------------------------------------------------------------

pub fn op_to_json(op: &SyncOp) -> Result<Value, String> {
    let value = match &op.value {
        Some(v) => Some(sval_to_json(v)?),
        None => None,
    };
    let observed = match &op.observed {
        Some(tags) => Some(tags.iter().map(addtag_to_json).collect::<Vec<_>>()),
        None => None,
    };
    Ok(json!({
        "kind": op.kind,
        "ns": op.ns,
        "target": op.target,
        "field": op.field,
        "value": value,
        "hlc": hlc_to_json(&op.hlc),
        "observed": observed,
        "reference": op.reference.as_ref().map(opref_to_json),
    }))
}

pub fn op_from_json(v: &Value) -> Result<SyncOp, String> {
    let kind = u64_of(v, "kind")?;
    let observed = match field(v, "observed") {
        Some(tags) => Some(
            tags.as_array()
                .ok_or("`observed` is not an array")?
                .iter()
                .map(addtag_from_json)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        None => None,
    };
    Ok(SyncOp {
        kind: u8::try_from(kind).map_err(|_| "`kind` exceeds u8")?,
        ns: text(v, "ns").unwrap_or_default(),
        target: text(v, "target")?,
        field: match field(v, "field") {
            Some(f) => Some(f.as_str().ok_or("`field` is not a string")?.to_owned()),
            None => None,
        },
        value: match field(v, "value") {
            Some(val) => Some(sval_from_json(val)?),
            None => None,
        },
        hlc: hlc_from_json(field(v, "hlc").ok_or("missing `hlc`")?)?,
        observed,
        reference: match field(v, "reference") {
            Some(r) => Some(opref_from_json(r)?),
            None => None,
        },
    })
}
