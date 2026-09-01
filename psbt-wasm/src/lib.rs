//! WebAssembly bindings to rust-bitcoin's PSBT (BIP-174) types for EntropyLab.
//!
//! The JS side is src/js/psbt-wasm.js; the editor UI is src/js/psbt-editor.js.
//! The boundary is deliberately narrow and carries no secrets: PSBT bytes and
//! UTF-8 JSON only.
//!
//!   psbt_inspect(psbt_ptr, psbt_len, out, out_cap) -> JSON document
//!   psbt_build(json_ptr, json_len, out, out_cap)  -> PSBT bytes
//!
//! Both use a two-call convention: a null `out` returns the required capacity,
//! a second call with a big enough buffer writes the payload and returns its
//! length. A negative return reports an error; the message is available via
//! psbt_last_error (same two-call convention).
//!
//! `psbt_inspect` decodes every key-value pair in every map (known BIP-174 /
//! BIP-371 types get a structured decode; unknown pairs stay raw hex), plus the
//! unsigned transaction and a fee summary. `psbt_build` takes the same document
//! shape back, re-serializes the transaction and maps, and validates the result
//! with rust-bitcoin's `Psbt::deserialize` before returning it. Nothing here
//! generates randomness or touches the network.

use bitcoin::bip32::{ChildNumber, DerivationPath, Xpub};
use bitcoin::consensus::encode::{self, Decodable, Encodable};
use bitcoin::locktime::absolute::LockTime;
use bitcoin::psbt::{Psbt, PsbtSighashType};
use bitcoin::taproot::{LeafVersion, TapTree, TaprootBuilder};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, VarInt, Witness,
};
use serde_json::{json, Map, Value};
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::str::FromStr;

// Keep the inspector bounded like the JS side (src/js/app.js): 5 MB of PSBT,
// 10k pairs per map, 100k transaction inputs/outputs.
const MAX_PSBT_BYTES: usize = 5_000_000;
const MAX_JSON_BYTES: usize = 64_000_000;
const MAX_PAIRS_PER_MAP: usize = 10_000;
const MAX_TX_ELEMENTS: usize = 100_000;

thread_local! {
    static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
}

fn set_error(message: String) -> i32 {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = message);
    -1
}

fn clear_error() {
    LAST_ERROR.with(|slot| slot.borrow_mut().clear());
}

/// Allocates `len` zero-filled bytes of linear memory for JS to fill. Pair
/// with `psbt_free`. The box owns exactly `len` bytes, so the deallocation
/// layout is reproducible from `len` alone.
#[no_mangle]
pub extern "C" fn psbt_alloc(len: usize) -> *mut u8 {
    Box::into_raw(vec![0u8; len].into_boxed_slice()) as *mut u8
}

/// # Safety
/// `ptr` must come from `psbt_alloc` and `len` must be exactly the length
/// passed there: the box is reconstructed from `len` alone, so any other
/// length deallocates with the wrong layout.
#[no_mangle]
pub unsafe extern "C" fn psbt_free(ptr: *mut u8, len: usize) {
    // Zero the buffer before deallocation. The boundary is watch-only by
    // design, but a pasted PSBT can carry xprvs in proprietary fields; freed
    // linear memory must not retain it for a later allocation to expose.
    wipe(ptr, len);
    let slice = std::ptr::slice_from_raw_parts_mut(ptr, len);
    drop(Box::from_raw(slice));
}

/// Overwrites `len` bytes at `ptr` with zeroes. Volatile stores plus a
/// compiler fence, so the wipe cannot be elided as a dead store ahead of
/// deallocation.
unsafe fn wipe(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        for i in 0..len {
            std::ptr::write_volatile(ptr.add(i), 0u8);
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Copies the last error message into `out` (two-call convention: null `out`
/// returns the required capacity). Returns the byte length, 0 when there is
/// no error, or -1 (and a fresh "buffer too small" error) when `out` is
/// too small.
#[no_mangle]
pub unsafe extern "C" fn psbt_last_error(out: *mut u8, out_cap: usize) -> i32 {
    let len = LAST_ERROR.with(|slot| slot.borrow().len());
    if len == 0 {
        return 0;
    }
    if out.is_null() {
        return len as i32;
    }
    if out_cap < len {
        return set_error("psbt_last_error buffer too small".into());
    }
    LAST_ERROR.with(|slot| std::ptr::copy_nonoverlapping(slot.borrow().as_ptr(), out, len));
    len as i32
}

/// Parses the PSBT at `in_ptr`/`in_len` and writes the inspection JSON to
/// `out`. Two-call convention; negative return + psbt_last_error on failure.
#[no_mangle]
pub unsafe extern "C" fn psbt_inspect(
    in_ptr: *const u8,
    in_len: usize,
    out: *mut u8,
    out_cap: usize,
) -> i32 {
    clear_error();
    let input = std::slice::from_raw_parts(in_ptr, in_len);
    match inspect(input) {
        Ok(json) => write_out(json.as_bytes(), out, out_cap),
        Err(message) => set_error(message),
    }
}

/// Rebuilds a PSBT from the (possibly edited) JSON document at
/// `in_ptr`/`in_len` and writes the bytes to `out`. Two-call convention;
/// negative return + psbt_last_error on failure.
#[no_mangle]
pub unsafe extern "C" fn psbt_build(
    in_ptr: *const u8,
    in_len: usize,
    out: *mut u8,
    out_cap: usize,
) -> i32 {
    clear_error();
    let input = std::slice::from_raw_parts(in_ptr, in_len);
    match build(input) {
        Ok(bytes) => write_out(&bytes, out, out_cap),
        Err(message) => set_error(message),
    }
}

/// Shared two-call output helper: null `out` reports capacity, otherwise the
/// payload is copied and its length returned.
unsafe fn write_out(payload: &[u8], out: *mut u8, out_cap: usize) -> i32 {
    if out.is_null() {
        return payload.len() as i32;
    }
    if out_cap < payload.len() {
        return set_error("output buffer too small".into());
    }
    std::ptr::copy_nonoverlapping(payload.as_ptr(), out, payload.len());
    payload.len() as i32
}

// ── Hex and compact-size helpers ────────────────────────────────────────────

fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 15) as usize] as char);
    }
    out
}

fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
    let bytes = text.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err("hex value has an odd number of digits".into());
    }
    let nibble = |c: u8| -> Result<u8, String> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err("hex value contains a non-hex character".into()),
        }
    };
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Ok(out)
}

/// Reads a BIP-174 compact-size (bitcoin VarInt) at `off`, rejecting
/// non-canonical encodings exactly like the JS parser does.
fn read_varint(bytes: &[u8], off: &mut usize) -> Result<u64, String> {
    if *off >= bytes.len() {
        return Err("PSBT ended early".into());
    }
    let marker = bytes[*off];
    *off += 1;
    let (len, min): (usize, u64) = match marker {
        0..=252 => return Ok(marker as u64),
        253 => (2, 253),
        254 => (4, 0x1_0000),
        _ => (8, 0x1_0000_0000),
    };
    if *off + len > bytes.len() {
        return Err("PSBT ended early".into());
    }
    let mut value = 0u64;
    for i in 0..len {
        value |= (bytes[*off + i] as u64) << (8 * i);
    }
    *off += len;
    if value < min {
        return Err("non-canonical compact integer".into());
    }
    Ok(value)
}

fn push_varint(out: &mut Vec<u8>, value: u64) {
    // bitcoin::VarInt is the same compact-size encoding BIP-174 uses.
    VarInt(value)
        .consensus_encode(out)
        .expect("writing to a Vec cannot fail");
}

// ── Raw map parsing ─────────────────────────────────────────────────────────

struct RawPair {
    key: Vec<u8>,     // type byte + keydata, exactly as serialized
    value: Vec<u8>,
}

fn read_map(bytes: &[u8], off: &mut usize) -> Result<Vec<RawPair>, String> {
    let mut pairs = Vec::new();
    loop {
        if pairs.len() >= MAX_PAIRS_PER_MAP {
            return Err("PSBT map has too many entries to inspect safely".into());
        }
        let key_len = read_varint(bytes, off)? as usize;
        if key_len == 0 {
            return Ok(pairs);
        }
        if *off + key_len > bytes.len() {
            return Err("PSBT ended inside a key".into());
        }
        let key = bytes[*off..*off + key_len].to_vec();
        *off += key_len;
        let value_len = read_varint(bytes, off)? as usize;
        if *off + value_len > bytes.len() {
            return Err("PSBT ended inside a value".into());
        }
        let value = bytes[*off..*off + value_len].to_vec();
        *off += value_len;
        pairs.push(RawPair { key, value });
    }
}

struct RawPsbt {
    globals: Vec<RawPair>,
    inputs: Vec<Vec<RawPair>>,
    outputs: Vec<Vec<RawPair>>,
    unsigned_tx: Transaction,
    version: u32,
}

fn parse_raw(bytes: &[u8]) -> Result<RawPsbt, String> {
    if bytes.len() > MAX_PSBT_BYTES {
        return Err("this PSBT is too large to inspect safely".into());
    }
    if bytes.len() < 5 || &bytes[..5] != b"psbt\xff" {
        return Err("not a PSBT: it must start with the bytes `psbt` followed by 0xff".into());
    }
    let mut off = 5;
    let globals = read_map(bytes, &mut off)?;

    let mut version = 0u32;
    let mut unsigned: Option<Vec<u8>> = None;
    for pair in &globals {
        let (kind, keydata) = (pair.key[0], &pair.key[1..]);
        if kind == 0xfb && keydata.is_empty() {
            if pair.value.len() != 4 {
                return Err("PSBT_GLOBAL_VERSION must be a 4-byte value".into());
            }
            version = u32::from_le_bytes(pair.value[..4].try_into().unwrap());
        }
        if kind == 0x00 && keydata.is_empty() {
            if unsigned.is_some() {
                return Err("this PSBT must contain exactly one unsigned transaction".into());
            }
            unsigned = Some(pair.value.clone());
        }
    }
    if version != 0 {
        return Err(format!("only PSBT v0 is supported (this file declares v{version})"));
    }
    let unsigned = unsigned.ok_or("this PSBT must contain exactly one unsigned transaction")?;
    let unsigned_tx = decode_unsigned_tx(&unsigned)?;

    if unsigned_tx.input.len() > MAX_TX_ELEMENTS || unsigned_tx.output.len() > MAX_TX_ELEMENTS {
        return Err("unsigned transaction has too many inputs or outputs".into());
    }
    let mut inputs = Vec::with_capacity(unsigned_tx.input.len());
    for _ in 0..unsigned_tx.input.len() {
        if off >= bytes.len() {
            return Err("PSBT is missing an input map".into());
        }
        inputs.push(read_map(bytes, &mut off)?);
    }
    let mut outputs = Vec::with_capacity(unsigned_tx.output.len());
    for _ in 0..unsigned_tx.output.len() {
        if off >= bytes.len() {
            return Err("PSBT is missing an output map".into());
        }
        outputs.push(read_map(bytes, &mut off)?);
    }
    if off != bytes.len() {
        return Err("PSBT contains trailing data or extra maps".into());
    }
    Ok(RawPsbt { globals, inputs, outputs, unsigned_tx, version })
}

/// Consensus-decodes the unsigned transaction, enforcing the PSBT v0 rules:
/// legacy (witness-free) serialization, empty scriptSigs, exact consumption.
fn decode_unsigned_tx(bytes: &[u8]) -> Result<Transaction, String> {
    // A marker/flag pair right after the 4-byte version is only meaningful in
    // segwit serialization.
    if bytes.len() >= 6 && bytes[4] == 0 && bytes[5] == 1 {
        return Err("the PSBT v0 unsigned transaction must not contain a witness marker".into());
    }
    let tx = Transaction::consensus_decode(&mut &bytes[..])
        .map_err(|e| format!("unsigned transaction does not decode: {e}"))?;
    if encode::serialize(&tx) != bytes {
        return Err("unsigned transaction has trailing bytes or a non-minimal encoding".into());
    }
    for input in &tx.input {
        if !input.script_sig.is_empty() {
            return Err("PSBT v0 unsigned transaction inputs must have empty scriptSigs".into());
        }
        if !input.witness.is_empty() {
            return Err("PSBT v0 unsigned transaction inputs must have empty witnesses".into());
        }
    }
    Ok(tx)
}

// ── Inspect: typed decoding of every pair ───────────────────────────────────

fn sighash_name(n: u32) -> String {
    PsbtSighashType::from_u32(n).to_string()
}

fn path_string(path: &[u8]) -> Result<String, String> {
    if path.len() % 4 != 0 {
        return Err("derivation path is not a multiple of 4 bytes".into());
    }
    let children: Vec<ChildNumber> = path
        .chunks_exact(4)
        .map(|c| ChildNumber::from(u32::from_le_bytes(c.try_into().unwrap())))
        .collect();
    Ok(format!("m/{path}", path = DerivationPath::from(children)))
}

fn script_json(script: &Script) -> Value {
    json!({ "hex": hex_encode(script.as_bytes()), "asm": script.to_asm_string() })
}

fn proprietary_json(keydata: &[u8]) -> Value {
    // <prefix compactsize><prefix><subtype 1 byte><keydata>
    let mut off = 0usize;
    let prefix_len = match read_varint(keydata, &mut off) {
        Ok(n) => n as usize,
        Err(_) => return json!({ "error": "malformed proprietary key prefix" }),
    };
    if off + prefix_len + 1 > keydata.len() {
        return json!({ "error": "malformed proprietary key" });
    }
    let prefix = &keydata[off..off + prefix_len];
    let subtype = keydata[off + prefix_len];
    let rest = &keydata[off + prefix_len + 1..];
    let mut out = json!({
        "prefix": hex_encode(prefix),
        "subtype": subtype,
        "keydata": hex_encode(rest),
    });
    if let Ok(text) = std::str::from_utf8(prefix) {
        if text.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
            out["prefixText"] = Value::String(text.to_string());
        }
    }
    out
}

fn fingerprint_and_path(value: &[u8]) -> Result<(String, String), String> {
    if value.len() < 4 {
        return Err("derivation value is shorter than its 4-byte fingerprint".into());
    }
    let fingerprint = hex_encode(&value[..4]);
    let path = path_string(&value[4..])?;
    Ok((fingerprint, path))
}

/// Decodes one key-value pair into a display JSON object. `kind` is "global",
/// "input" or "output"; `input_index` is the pair's input-map index when
/// `kind` is "input". Unknown types decode to null and stay raw.
fn decode_pair(kind: &str, pair: &RawPair, tx: &Transaction, input_index: Option<usize>) -> Value {
    let type_byte = pair.key[0];
    let keydata = &pair.key[1..];
    let name = match (kind, type_byte) {
        ("global", 0x00) => "PSBT_GLOBAL_UNSIGNED_TX",
        ("global", 0x01) => "PSBT_GLOBAL_XPUB",
        ("global", 0xfb) => "PSBT_GLOBAL_VERSION",
        ("global", 0xfc) => "PSBT_GLOBAL_PROPRIETARY",
        ("global", _) => "PSBT_GLOBAL_UNKNOWN",
        ("input", 0x00) => "PSBT_IN_NON_WITNESS_UTXO",
        ("input", 0x01) => "PSBT_IN_WITNESS_UTXO",
        ("input", 0x02) => "PSBT_IN_PARTIAL_SIG",
        ("input", 0x03) => "PSBT_IN_SIGHASH_TYPE",
        ("input", 0x04) => "PSBT_IN_REDEEM_SCRIPT",
        ("input", 0x05) => "PSBT_IN_WITNESS_SCRIPT",
        ("input", 0x06) => "PSBT_IN_BIP32_DERIVATION",
        ("input", 0x07) => "PSBT_IN_FINAL_SCRIPTSIG",
        ("input", 0x08) => "PSBT_IN_FINAL_SCRIPTWITNESS",
        ("input", 0x0a) => "PSBT_IN_RIPEMD160",
        ("input", 0x0b) => "PSBT_IN_SHA256",
        ("input", 0x0c) => "PSBT_IN_HASH160",
        ("input", 0x0d) => "PSBT_IN_HASH256",
        ("input", 0x13) => "PSBT_IN_TAP_KEY_SIG",
        ("input", 0x14) => "PSBT_IN_TAP_SCRIPT_SIG",
        ("input", 0x15) => "PSBT_IN_TAP_LEAF_SCRIPT",
        ("input", 0x16) => "PSBT_IN_TAP_BIP32_DERIVATION",
        ("input", 0x17) => "PSBT_IN_TAP_INTERNAL_KEY",
        ("input", 0x18) => "PSBT_IN_TAP_MERKLE_ROOT",
        ("input", 0xfc) => "PSBT_IN_PROPRIETARY",
        ("input", _) => "PSBT_IN_UNKNOWN",
        ("output", 0x00) => "PSBT_OUT_REDEEM_SCRIPT",
        ("output", 0x01) => "PSBT_OUT_WITNESS_SCRIPT",
        ("output", 0x02) => "PSBT_OUT_BIP32_DERIVATION",
        ("output", 0x05) => "PSBT_OUT_TAP_INTERNAL_KEY",
        ("output", 0x06) => "PSBT_OUT_TAP_TREE",
        ("output", 0x07) => "PSBT_OUT_TAP_BIP32_DERIVATION",
        ("output", 0xfc) => "PSBT_OUT_PROPRIETARY",
        ("output", _) => "PSBT_OUT_UNKNOWN",
        _ => "PSBT_UNKNOWN",
    }
    .to_string();

    let decoded: Result<Value, String> = (|| {
        Ok(match (kind, type_byte) {
            ("global", 0x00) => json!({
                "note": "Decoded in the transaction section; edit it there.",
            }),
            ("global", 0x01) => {
                let xpub = Xpub::decode(keydata)
                    .map_err(|e| format!("xpub keydata does not decode: {e}"))?;
                let (fingerprint, path) = fingerprint_and_path(&pair.value)?;
                json!({ "xpub": xpub.to_string(), "fingerprint": fingerprint, "path": path })
            }
            ("global", 0xfb) => {
                if pair.value.len() != 4 {
                    return Err("version must be 4 bytes".into());
                }
                json!({ "version": u32::from_le_bytes(pair.value[..4].try_into().unwrap()) })
            }
            (_, 0xfc) => proprietary_json(keydata),
            ("input", 0x00) => {
                let prev = Transaction::consensus_decode(&mut &pair.value[..])
                    .map_err(|e| format!("non-witness utxo does not decode: {e}"))?;
                if encode::serialize(&prev) != pair.value {
                    return Err("non-witness utxo has trailing bytes".into());
                }
                let mut out = json!({
                    "txid": prev.compute_txid().to_string(),
                    "outputCount": prev.output.len(),
                });
                // Show the prevout this input actually spends, when present.
                // The input map is matched to its unsigned-transaction input
                // by index, never by a transaction-wide txid search: several
                // inputs can spend different outputs of one transaction, and
                // only the indexed input's outpoint identifies which one.
                if let Some(input) = input_index.and_then(|n| tx.input.get(n)) {
                    let outpoint = input.previous_output;
                    if outpoint.txid == prev.compute_txid() {
                        if let Some(spent) = prev.output.get(outpoint.vout as usize) {
                            out["prevout"] = json!({ "vout": outpoint.vout, "value": spent.value.to_sat(),
                                "scriptPubKey": hex_encode(spent.script_pubkey.as_bytes()) });
                        }
                    }
                }
                out
            }
            ("input", 0x01) => {
                // TxOut consensus: 8-byte LE amount, compact-size script.
                let mut off = 0usize;
                if pair.value.len() < 9 {
                    return Err("witness utxo is truncated".into());
                }
                let amount = u64::from_le_bytes(pair.value[..8].try_into().unwrap());
                off += 8;
                let script_len = read_varint(&pair.value, &mut off)? as usize;
                if off + script_len != pair.value.len() {
                    return Err("witness utxo has trailing bytes".into());
                }
                let script = Script::from_bytes(&pair.value[off..off + script_len]);
                json!({ "value": amount, "scriptPubKey": hex_encode(script.as_bytes()),
                    "asm": script.to_asm_string() })
            }
            ("input", 0x02) => {
                if pair.value.is_empty() {
                    return Err("partial signature is empty".into());
                }
                let sighash = *pair.value.last().unwrap();
                json!({
                    "pubkey": hex_encode(keydata),
                    "signature": hex_encode(&pair.value[..pair.value.len() - 1]),
                    "sighashByte": sighash,
                    "sighash": sighash_name(sighash as u32),
                })
            }
            ("input", 0x03) => {
                if pair.value.len() != 4 {
                    return Err("sighash type must be 4 bytes".into());
                }
                let n = u32::from_le_bytes(pair.value[..4].try_into().unwrap());
                json!({ "sighashType": n, "sighash": sighash_name(n) })
            }
            ("input", 0x04) | ("input", 0x05) | ("output", 0x00) | ("output", 0x01) => {
                script_json(Script::from_bytes(&pair.value))
            }
            ("input", 0x06) | ("output", 0x02) => {
                let (fingerprint, path) = fingerprint_and_path(&pair.value)?;
                json!({ "pubkey": hex_encode(keydata), "fingerprint": fingerprint, "path": path })
            }
            ("input", 0x07) => script_json(Script::from_bytes(&pair.value)),
            ("input", 0x08) => {
                let witness = Witness::consensus_decode(&mut &pair.value[..])
                    .map_err(|e| format!("final witness does not decode: {e}"))?;
                if encode::serialize(&witness) != pair.value {
                    return Err("final witness has trailing bytes".into());
                }
                json!({ "items": witness.iter().map(hex_encode).collect::<Vec<_>>() })
            }
            ("input", 0x0a) | ("input", 0x0b) | ("input", 0x0c) | ("input", 0x0d) => {
                json!({ "hash": hex_encode(keydata), "preimage": hex_encode(&pair.value) })
            }
            ("input", 0x13) => tap_sig_json(&pair.value)?,
            ("input", 0x14) => {
                if keydata.len() != 64 {
                    return Err("tap script sig keydata must be xonly key + leaf hash".into());
                }
                let mut out = tap_sig_json(&pair.value)?;
                out["xonly"] = json!(hex_encode(&keydata[..32]));
                out["leafHash"] = json!(hex_encode(&keydata[32..]));
                out
            }
            ("input", 0x15) => {
                if pair.value.is_empty() {
                    return Err("tap leaf script value is empty".into());
                }
                let (script, version) = pair.value.split_at(pair.value.len() - 1);
                json!({
                    "controlBlock": hex_encode(keydata),
                    "script": hex_encode(script),
                    "asm": Script::from_bytes(script).to_asm_string(),
                    "leafVersion": hex_encode(version),
                })
            }
            ("input", 0x16) | ("output", 0x07) => {
                let mut off = 0usize;
                let count = read_varint(&pair.value, &mut off)? as usize;
                if off + count * 32 + 4 > pair.value.len() {
                    return Err("tap bip32 derivation is truncated".into());
                }
                let leaves: Vec<String> = pair.value[off..off + count * 32]
                    .chunks_exact(32)
                    .map(hex_encode)
                    .collect();
                off += count * 32;
                let (fingerprint, path) = fingerprint_and_path(&pair.value[off..])?;
                json!({ "xonly": hex_encode(keydata), "leafHashes": leaves,
                    "fingerprint": fingerprint, "path": path })
            }
            ("input", 0x17) => json!({ "xonly": hex_encode(&pair.value) }),
            ("input", 0x18) => json!({ "merkleRoot": hex_encode(&pair.value) }),
            ("output", 0x05) => json!({ "xonly": hex_encode(&pair.value) }),
            ("output", 0x06) => tap_tree_json(&pair.value)?,
            _ => return Ok(Value::Null),
        })
    })();

    let mut view = Map::new();
    view.insert("name".into(), Value::String(name));
    match decoded {
        Ok(value) => view.insert("decoded".into(), value),
        Err(message) => {
            view.insert("decoded".into(), Value::Null);
            view.insert("decodeError".into(), Value::String(message))
        }
    };
    view.into()
}

fn tap_sig_json(value: &[u8]) -> Result<Value, String> {
    if value.len() != 64 && value.len() != 65 {
        return Err("taproot signature must be 64 or 65 bytes".into());
    }
    let sighash = if value.len() == 65 { value[64] } else { 0 };
    Ok(json!({
        "signature": hex_encode(&value[..64]),
        "sighashByte": sighash,
        "sighash": sighash_name(sighash as u32),
    }))
}

fn tap_tree_json(value: &[u8]) -> Result<Value, String> {
    // Decode the raw (depth, version, script) tuples for display while feeding
    // them through rust-bitcoin's builder, which enforces DFS order and tree
    // completeness exactly like PSBT deserialization does.
    let mut builder = TaprootBuilder::new();
    let mut leaves = Vec::new();
    let mut off = 0usize;
    while off < value.len() {
        if off + 2 > value.len() {
            return Err("tap tree leaf is truncated".into());
        }
        let depth = value[off];
        let version = LeafVersion::from_consensus(value[off + 1])
            .map_err(|e| format!("bad leaf version: {e}"))?;
        off += 2;
        let script_len = read_varint(value, &mut off)? as usize;
        if off + script_len > value.len() {
            return Err("tap tree leaf script is truncated".into());
        }
        let script = &value[off..off + script_len];
        builder = builder
            .add_leaf_with_ver(depth, ScriptBuf::from_bytes(script.to_vec()), version)
            .map_err(|_| "tap tree leaves are not in DFS order".to_string())?;
        leaves.push(json!({
            "depth": depth,
            "leafVersion": hex_encode(&[version.to_consensus()]),
            "script": hex_encode(script),
            "asm": Script::from_bytes(script).to_asm_string(),
        }));
        off += script_len;
    }
    TapTree::try_from(builder).map_err(|e| format!("tap tree is incomplete: {e}"))?;
    Ok(json!({ "leaves": leaves }))
}

fn pair_json(kind: &str, pair: &RawPair, tx: &Transaction, input_index: Option<usize>) -> Value {
    let mut view = decode_pair(kind, pair, tx, input_index);
    view["key"] = json!(hex_encode(&pair.key));
    view["value"] = json!(hex_encode(&pair.value));
    view["type"] = json!(pair.key[0]);
    view
}

/// The prevout amount this pair claims for the input at `input_index`, and
/// only when this pair is that input's (witness or verified non-witness) UTXO
/// declaration; None otherwise.
fn claimed_prevout_amount(pair: &RawPair, tx: &Transaction, input_index: usize) -> Option<u64> {
    match pair.key[0] {
        0x01 if pair.key.len() == 1 && pair.value.len() >= 8 => {
            Some(u64::from_le_bytes(pair.value[..8].try_into().unwrap()))
        }
        0x00 if pair.key.len() == 1 => {
            let prev = Transaction::consensus_decode(&mut &pair.value[..]).ok()?;
            // Match the input map to its unsigned-transaction input by index
            // (not by txid) and require the non-witness utxo to be that exact
            // outpoint's transaction before claiming its amount.
            let outpoint = tx.input.get(input_index)?.previous_output;
            if outpoint.txid != prev.compute_txid() {
                return None;
            }
            prev.output.get(outpoint.vout as usize).map(|o| o.value.to_sat())
        }
        _ => None,
    }
}

fn inspect(bytes: &[u8]) -> Result<String, String> {
    let raw = parse_raw(bytes)?;
    let tx = &raw.unsigned_tx;

    let tx_json = json!({
        "version": tx.version.0,
        "locktime": tx.lock_time.to_consensus_u32(),
        "inputs": tx.input.iter().map(|input| json!({
            "txid": input.previous_output.txid.to_string(),
            "vout": input.previous_output.vout,
            "scriptSig": hex_encode(input.script_sig.as_bytes()),
            "sequence": input.sequence.to_consensus_u32(),
        })).collect::<Vec<_>>(),
        "outputs": tx.output.iter().map(|output| json!({
            "value": output.value.to_sat(),
            "scriptPubKey": hex_encode(output.script_pubkey.as_bytes()),
            "asm": output.script_pubkey.to_asm_string(),
        })).collect::<Vec<_>>(),
    });

    let mut known_in_sats = 0u64;
    let mut known_inputs = 0usize;
    for (index, pairs) in raw.inputs.iter().enumerate() {
        if let Some(amount) = pairs.iter().find_map(|p| claimed_prevout_amount(p, tx, index)) {
            known_in_sats += amount;
            known_inputs += 1;
        }
    }
    let out_sum: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
    let fee = if known_inputs == tx.input.len() {
        if known_in_sats >= out_sum {
            json!({ "known": true, "sats": known_in_sats - out_sum })
        } else {
            json!({ "known": true, "sats": Value::Null, "error": "outputs exceed claimed inputs" })
        }
    } else {
        json!({ "known": false })
    };

    let rust_bitcoin_error = match Psbt::deserialize(bytes) {
        Ok(_) => Value::Null,
        Err(e) => Value::String(e.to_string()),
    };

    let doc = json!({
        "psbtVersion": raw.version,
        "tx": tx_json,
        "globals": raw.globals.iter().map(|p| pair_json("global", p, tx, None)).collect::<Vec<_>>(),
        "inputs": raw.inputs.iter().enumerate().map(|(n, map)| map.iter().map(|p| pair_json("input", p, tx, Some(n))).collect::<Vec<_>>()).collect::<Vec<_>>(),
        "outputs": raw.outputs.iter().map(|map| map.iter().map(|p| pair_json("output", p, tx, None)).collect::<Vec<_>>()).collect::<Vec<_>>(),
        "totalIn": if known_inputs == tx.input.len() { json!(known_in_sats) } else { Value::Null },
        "totalOut": out_sum,
        "fee": fee,
        "rustBitcoinError": rust_bitcoin_error,
    });
    let text = serde_json::to_string(&doc).map_err(|e| format!("JSON encode failed: {e}"))?;
    if text.len() > MAX_JSON_BYTES {
        return Err("inspection output is too large".into());
    }
    Ok(text)
}

// ── Build: edited JSON document back to PSBT bytes ──────────────────────────

fn json_u64(value: &Value, what: &str, max: u64) -> Result<u64, String> {
    let n = match value {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse::<u64>().ok(),
        _ => None,
    }
    .ok_or_else(|| format!("{what} must be a non-negative integer"))?;
    if n > max {
        return Err(format!("{what} is too large"));
    }
    Ok(n)
}

fn json_hex<'a>(value: &'a Value, what: &str) -> Result<Vec<u8>, String> {
    let text = value
        .as_str()
        .ok_or_else(|| format!("{what} must be a hex string"))?;
    hex_decode(text).map_err(|e| format!("{what}: {e}"))
}

fn build_tx(doc: &Value) -> Result<Transaction, String> {
    let tx = doc.get("tx").ok_or("document is missing `tx`")?;
    let version = match &tx["version"] {
        Value::Number(n) => n
            .as_i64()
            .filter(|v| *v >= i32::MIN as i64 && *v <= i32::MAX as i64),
        Value::String(s) => s.parse::<i64>().ok().filter(|v| *v >= i32::MIN as i64 && *v <= i32::MAX as i64),
        _ => None,
    }
    .ok_or("transaction version must be a 32-bit integer")? as i32;
    let locktime = json_u64(&tx["locktime"], "locktime", u32::MAX as u64)? as u32;

    let inputs_doc = tx["inputs"]
        .as_array()
        .ok_or("tx.inputs must be an array")?;
    let mut inputs = Vec::with_capacity(inputs_doc.len());
    for (index, input) in inputs_doc.iter().enumerate() {
        let what = format!("input {index}");
        let txid_hex = input["txid"].as_str().ok_or(format!("{what}: txid must be hex"))?;
        let txid = Txid::from_str(txid_hex)
            .map_err(|e| format!("{what}: txid does not parse: {e}"))?;
        let vout = json_u64(&input["vout"], &format!("{what} vout"), u32::MAX as u64)? as u32;
        let sequence = json_u64(&input["sequence"], &format!("{what} sequence"), u32::MAX as u64)? as u32;
        let script_sig = json_hex(&input["scriptSig"], &format!("{what} scriptSig"))?;
        if !script_sig.is_empty() {
            return Err(format!("{what}: PSBT v0 unsigned transaction inputs must have empty scriptSigs"));
        }
        inputs.push(TxIn {
            previous_output: OutPoint { txid, vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_consensus(sequence),
            witness: Witness::new(),
        });
    }

    let outputs_doc = tx["outputs"]
        .as_array()
        .ok_or("tx.outputs must be an array")?;
    let mut outputs = Vec::with_capacity(outputs_doc.len());
    for (index, output) in outputs_doc.iter().enumerate() {
        let what = format!("output {index}");
        let value = json_u64(&output["value"], &format!("{what} value"), u64::MAX)?;
        let script_pubkey = ScriptBuf::from_bytes(json_hex(&output["scriptPubKey"], &format!("{what} scriptPubKey"))?);
        outputs.push(TxOut { value: Amount::from_sat(value), script_pubkey });
    }

    if inputs.len() > MAX_TX_ELEMENTS || outputs.len() > MAX_TX_ELEMENTS {
        return Err("transaction has too many inputs or outputs".into());
    }
    Ok(Transaction {
        version: Version(version),
        lock_time: LockTime::from_consensus(locktime),
        input: inputs,
        output: outputs,
    })
}

fn build_map(map: &Value, what: &str) -> Result<Vec<RawPair>, String> {
    let pairs = map
        .as_array()
        .ok_or_else(|| format!("{what} must be an array of pairs"))?;
    let mut seen = BTreeSet::new();
    let mut built = Vec::with_capacity(pairs.len());
    for (index, pair) in pairs.iter().enumerate() {
        let pair_what = format!("{what} pair {index}");
        let key = json_hex(&pair["key"], &format!("{pair_what} key"))?;
        if key.is_empty() {
            return Err(format!("{pair_what}: key must include a type byte"));
        }
        let value = json_hex(&pair["value"], &format!("{pair_what} value"))?;
        if !seen.insert(key.clone()) {
            return Err(format!("{pair_what}: duplicate key {}", hex_encode(&key)));
        }
        built.push(RawPair { key, value });
    }
    if built.len() > MAX_PAIRS_PER_MAP {
        return Err(format!("{what} has too many pairs"));
    }
    Ok(built)
}

fn build_pairs(doc: &Value, field: &str) -> Result<Vec<Vec<RawPair>>, String> {
    let maps = doc[field]
        .as_array()
        .ok_or_else(|| format!("`{field}` must be an array of maps"))?;
    maps.iter()
        .enumerate()
        .map(|(index, map)| build_map(map, &format!("{field} map {index}")))
        .collect()
}

fn push_pair(out: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    push_varint(out, key.len() as u64);
    out.extend_from_slice(key);
    push_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

fn build(json_bytes: &[u8]) -> Result<Vec<u8>, String> {
    if json_bytes.len() > MAX_JSON_BYTES {
        return Err("edit document is too large".into());
    }
    let doc: Value = serde_json::from_slice(json_bytes)
        .map_err(|e| format!("edit document is not valid JSON: {e}"))?;

    let tx = build_tx(&doc)?;
    let unsigned = encode::serialize(&tx);

    // The unsigned transaction pair is regenerated from the tx section; a
    // passed-through PSBT_GLOBAL_UNSIGNED_TX pair (key "00") is dropped.
    let global_pairs = build_map(&doc["globals"], "`globals`")?;
    for pair in &global_pairs {
        if pair.key == [0xfb] && pair.value != [0, 0, 0, 0] {
            return Err("only PSBT v0 is supported: the global version pair must be absent or 0".into());
        }
    }

    let inputs = build_pairs(&doc, "inputs")?;
    let outputs = build_pairs(&doc, "outputs")?;
    if inputs.len() != tx.input.len() {
        return Err(format!(
            "the document has {} input maps but the transaction has {} inputs",
            inputs.len(),
            tx.input.len()
        ));
    }
    if outputs.len() != tx.output.len() {
        return Err(format!(
            "the document has {} output maps but the transaction has {} outputs",
            outputs.len(),
            tx.output.len()
        ));
    }

    let mut out = Vec::with_capacity(unsigned.len() + 256);
    out.extend_from_slice(b"psbt\xff");
    push_pair(&mut out, &[0x00], &unsigned);
    for pair in global_pairs {
        if pair.key == [0x00] {
            continue; // regenerated above from the tx section
        }
        push_pair(&mut out, &pair.key, &pair.value);
    }
    out.push(0x00);
    for map in inputs.iter().chain(outputs.iter()) {
        for pair in map {
            push_pair(&mut out, &pair.key, &pair.value);
        }
        out.push(0x00);
    }

    if out.len() > MAX_PSBT_BYTES * 2 {
        return Err("rebuilt PSBT is too large".into());
    }
    // The authoritative gate: the rebuilt file must parse as a PSBT under
    // rust-bitcoin, which rejects duplicate keys, malformed typed values,
    // witness-carrying unsigned transactions and count mismatches.
    Psbt::deserialize(&out).map_err(|e| format!("rebuilt PSBT does not parse: {e}"))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The allocator pair must round-trip exact sizes, including zero length:
    // psbt_free reconstructs a Box<[u8]> whose layout comes from `len` alone,
    // so a capacity mismatch corrupts the host allocator. The wasm suite
    // (test/wipe-wasm.test.mjs) pins this behavior in the artifact; this test
    // makes the same lifecycle checkable on the host — `cargo test`, or
    // `cargo +nightly miri test` for a UB-checked run.
    #[test]
    fn alloc_free_round_trips_exact_sizes() {
        for len in [0usize, 1, 2, 15, 16, 31, 32, 255, 256, 4096] {
            for cycle in 0..8u8 {
                let ptr = psbt_alloc(len);
                assert!(!ptr.is_null());
                unsafe {
                    for i in 0..len {
                        // A recycled block must never expose stale bytes.
                        assert_eq!(ptr.add(i).read(), 0);
                        ptr.add(i).write_volatile(cycle ^ i as u8);
                    }
                    psbt_free(ptr, len);
                }
            }
        }
    }
}
