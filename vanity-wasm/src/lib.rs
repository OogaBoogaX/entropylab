//! Deterministic vanity-address grinder for EntropyLab.
//!
//! Candidates come from a counter, never from randomness, and every candidate
//! is a wallet the Key Station key already describes — the grinder only
//! searches one of that wallet's own dials:
//!
//! * **Passphrase grind** (`MODE_PASSPHRASE`): counter `i` maps to a
//!   fixed-width base-62 "odometer" string over a-zA-Z0-9 (in that order), the
//!   candidate BIP39 passphrase is the key's starting passphrase followed by
//!   that string, and the address is derived the standard way: PBKDF2-HMAC-
//!   SHA512 (2048 rounds) → BIP32 master → the caller's derivation path.
//! * **Derivation grind** (`MODE_NODE`): the passphrase is fixed, the caller
//!   hands over one BIP32 parent node (private key ‖ chain code) and a path
//!   below it, and counter `i` replaces one path component (the account
//!   index, keeping that slot's hardened bit).
//!
//! Address types are the four mainnet single-signature scripts (P2PKH,
//! P2SH-P2WPKH, P2WPKH, P2TR) plus BIP-352 Silent Payment addresses. For
//! Silent Payments the path is the account path `m/352'/0'/account'`; the
//! grinder appends the BIP-352 scan (`/1'/0`) and spend (`/0'/0`) steps itself.
//!
//! Same key, same counter, same address: a found counter is reproducible by
//! anyone holding the words, so this is a calculator over a user-chosen range
//! and not an entropy source.
//!
//! Bucketing: a contiguous counter range is a bucket (odometer order for the
//! passphrase grind, ascending account indexes for the derivation grind), so
//! the JS side splits the search space across Web Workers as disjoint ranges
//! with no overlap and no gap. This crate only ever sees one range at a time.
//!
//! The boundary mirrors entropylab-wasm: one `vanity_grind` call grinds
//! `[start, start + count)` and writes a small header plus fixed-size match
//! records into a caller-owned buffer. Private keys never leave the loop —
//! only the counter, the odometer string, and the address payload of a
//! *matching* candidate cross into JS (HASH160 for hash-based scripts, the
//! x-only output key for P2TR, scan ‖ spend compressed public keys for
//! Silent Payments).
//!
//! Output buffer layout (little-endian):
//!   [0..8]    u64 processed   — candidates tested (== count unless the
//!                               record area filled up first)
//!   [8..12]   u32 matches     — number of 106-byte records that follow
//!   [12..]    records: u64 counter | 32-byte odometer string (zero-padded,
//!                      empty for the derivation grind) | 66-byte payload
//!
//! Return value: 0 on success, -1 for invalid arguments, -2 when the record
//! area filled up (the header still reports progress; re-enter at
//! `start + processed`).

use ripemd::Ripemd160;
use secp256k1_sys as ffi;
use sha2::{Digest, Sha256, Sha512};
use std::alloc::{alloc, Layout};
use std::ptr::NonNull;
use std::sync::OnceLock;

// From the pinned vendored include/secp256k1.h (same values as entropylab-wasm):
// SECP256K1_CONTEXT_SIGN = (1<<0)|(1<<9). Grinding only creates public keys,
// so no verify (ecmult) tables are built.
const CONTEXT_FLAGS: u32 = (1 << 0) | (1 << 9);

struct Context(*mut ffi::Context);
// wasm32-unknown-unknown is single-threaded, so sharing the pointer is sound.
unsafe impl Sync for Context {}
unsafe impl Send for Context {}
static CONTEXT: OnceLock<Context> = OnceLock::new();

fn ctx() -> *const ffi::Context {
    CONTEXT
        .get_or_init(|| unsafe {
            let size = ffi::secp256k1_context_preallocated_size(CONTEXT_FLAGS);
            // 16 matches max_align_t for the wasm32 C ABI.
            let layout = Layout::from_size_align(size, 16).expect("valid context layout");
            let mem = alloc(layout);
            assert!(!mem.is_null(), "context allocation failed");
            let cx = ffi::secp256k1_context_preallocated_create(
                NonNull::new(mem.cast()).expect("allocation is non-null"),
                CONTEXT_FLAGS,
            );
            Context(cx.as_ptr())
        })
        .0
}

/// The passphrase alphabet, in the user-facing order a-zA-Z0-9.
const ALPHABET: &[u8; 62] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BECH32: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST: u32 = 0x2bc830a3;
const SCRIPT_P2PKH: u32 = 0;
const SCRIPT_P2SH_P2WPKH: u32 = 1;
const SCRIPT_P2WPKH: u32 = 2;
const SCRIPT_P2TR: u32 = 3;
const SCRIPT_SP: u32 = 4;

/// The counter is the odometer string appended to the BIP39 passphrase.
const MODE_PASSPHRASE: u32 = 0;
/// The counter is one BIP32 path component below a caller-supplied node.
const MODE_NODE: u32 = 1;

/// BIP32 hardened-index bit.
const HARDENED: u32 = 0x8000_0000;
/// PBKDF2 rounds fixed by BIP39.
const PBKDF2_ROUNDS: u32 = 2048;
/// Odometer strings are at most 32 characters (62^32 dwarfs the u64 counter).
const MAX_PASS_LEN: usize = 32;
/// The starting passphrase is at most 256 bytes (the JS worker allocates its
/// buffer with the same limit, `MAX_SALT` in vanity-worker.js).
const MAX_SALT_LEN: usize = 256;
/// The NFKD mnemonic is at most 1024 bytes (`MAX_KEY` in vanity-worker.js);
/// a BIP32 node is exactly 64 bytes (32-byte private key ‖ 32-byte chain code).
const MAX_KEY_LEN: usize = 1024;
const NODE_LEN: usize = 64;
/// A derivation path is at most 16 components (`MAX_PATH` in vanity-worker.js).
const MAX_PATH_LEN: usize = 16;
/// The longest supported address is a 116-character BIP-352 Silent Payment
/// code (bech32m over a 66-byte payload). Every other type is shorter and
/// shares the same buffer.
const MAX_ADDR_LEN: usize = 116;
/// Bech32 data values: version + ceil(66 * 8 / 5) for the Silent Payment payload.
const MAX_BECH32_VALUES: usize = 107;
/// Scan ‖ spend compressed public keys; other scripts use a prefix of it.
const PAYLOAD_LEN: usize = 66;
/// counter (8) + odometer string (32) + address payload (66).
const RECORD_LEN: usize = 8 + MAX_PASS_LEN + PAYLOAD_LEN;
const HEADER_LEN: usize = 12;

/// Allocates `len` zero-filled bytes of linear memory for JS to fill. Pair
/// with `vanity_free`. The box owns exactly `len` bytes, so the deallocation
/// layout is reproducible from `len` alone.
#[no_mangle]
pub extern "C" fn vanity_alloc(len: usize) -> *mut u8 {
    Box::into_raw(vec![0u8; len].into_boxed_slice()) as *mut u8
}

/// # Safety
/// `ptr` must come from `vanity_alloc` and `len` must be exactly the length
/// passed there: the box is reconstructed from `len` alone, so any other
/// length deallocates with the wrong layout.
#[no_mangle]
pub unsafe extern "C" fn vanity_free(ptr: *mut u8, len: usize) {
    // Zero before deallocation: these buffers carry the NFKD mnemonic or a
    // raw 64-byte BIP32 node (private key ‖ chain code) — strictly more
    // sensitive than anything the other crates handle (issues #327, #356).
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

/// Volatile-zero a byte string we own (same reasoning as `wipe`).
fn wipe_bytes(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        unsafe { std::ptr::write_volatile(byte, 0u8) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn hash160(data: &[u8]) -> [u8; 20] {
    Ripemd160::digest(sha256(data)).into()
}

/// HMAC-SHA512 (RFC 2104) with the padded key blocks absorbed once, so the
/// PBKDF2 loop and every BIP32 child step pay only for their message bytes.
/// Written out here rather than pulled from a crate: it is a dozen lines and
/// keeps the dependency list to the hash functions themselves.
struct HmacSha512 {
    inner: Sha512,
    outer: Sha512,
}

impl HmacSha512 {
    fn new(key: &[u8]) -> Self {
        let mut block = [0u8; 128];
        if key.len() > 128 {
            block[..64].copy_from_slice(&Sha512::digest(key));
        } else {
            block[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0u8; 128];
        let mut opad = [0u8; 128];
        for i in 0..128 {
            ipad[i] = block[i] ^ 0x36;
            opad[i] = block[i] ^ 0x5c;
        }
        let engine = HmacSha512 {
            inner: Sha512::new().chain_update(ipad),
            outer: Sha512::new().chain_update(opad),
        };
        // The key-bearing pads have been absorbed; the working copies go now.
        // (The sha2 crate's mid-state is opaque and cannot be zeroed from
        // here — the buffer wipes around the call sites carry the hygiene.)
        wipe_bytes(&mut block);
        wipe_bytes(&mut ipad);
        wipe_bytes(&mut opad);
        engine
    }

    fn mac(&self, parts: &[&[u8]]) -> [u8; 64] {
        let mut inner = self.inner.clone();
        for part in parts {
            inner.update(part);
        }
        let digest = inner.finalize();
        let mut outer = self.outer.clone();
        outer.update(digest);
        outer.finalize().into()
    }
}

/// BIP39 seed: PBKDF2-HMAC-SHA512 with the mnemonic as password and
/// "mnemonic" ‖ passphrase as salt, 2048 rounds, one 64-byte block. The
/// passphrase arrives in parts (starting passphrase, odometer string) so the
/// candidate never has to be concatenated.
fn bip39_seed(mnemonic: &HmacSha512, passphrase_parts: &[&[u8]]) -> [u8; 64] {
    let mut salted: Vec<&[u8]> = Vec::with_capacity(passphrase_parts.len() + 2);
    salted.push(b"mnemonic");
    salted.extend_from_slice(passphrase_parts);
    let block_index = 1u32.to_be_bytes();
    salted.push(&block_index);
    let mut u = mnemonic.mac(&salted);
    let mut t = u;
    for _ in 1..PBKDF2_ROUNDS {
        u = mnemonic.mac(&[&u]);
        for (acc, next) in t.iter_mut().zip(u.iter()) {
            *acc ^= next;
        }
    }
    wipe_bytes(&mut u); // same secret as the returned seed
    t
}

#[derive(Clone, Copy)]
struct Node {
    key: [u8; 32],
    chain: [u8; 32],
}

/// A BIP32 node holds a private key: volatile-zero it when it retires.
fn wipe_node(node: &mut Node) {
    wipe_bytes(&mut node.key);
    wipe_bytes(&mut node.chain);
}

unsafe fn pubkey_compressed(seckey: &[u8; 32]) -> Option<[u8; 33]> {
    let mut pk = ffi::PublicKey::new();
    if ffi::secp256k1_ec_pubkey_create(ctx(), &mut pk, seckey.as_ptr()) != 1 {
        return None;
    }
    let mut serialized = [0u8; 33];
    let mut len = 33usize;
    if ffi::secp256k1_ec_pubkey_serialize(ctx(), serialized.as_mut_ptr(), &mut len, &pk, ffi::SECP256K1_SER_COMPRESSED) != 1 || len != 33 {
        return None;
    }
    Some(serialized)
}

/// BIP32 master node from a seed. Returns None for the (2^-128 rare) invalid
/// master key.
unsafe fn master_node(seed: &[u8]) -> Option<Node> {
    let mut i = HmacSha512::new(b"Bitcoin seed").mac(&[seed]);
    let mut node = Node { key: [0u8; 32], chain: [0u8; 32] };
    node.key.copy_from_slice(&i[..32]);
    node.chain.copy_from_slice(&i[32..]);
    wipe_bytes(&mut i); // the HMAC output is the master key ‖ chain code
    if ffi::secp256k1_ec_seckey_verify(ctx(), node.key.as_ptr()) != 1 {
        wipe_node(&mut node);
        return None;
    }
    Some(node)
}

/// BIP32 CKDpriv. Returns None when the child is invalid (IL >= n or a zero
/// key), which BIP32 says to skip.
unsafe fn ckd_priv(parent: &Node, index: u32) -> Option<Node> {
    let mac = HmacSha512::new(&parent.chain);
    let index_bytes = index.to_be_bytes();
    let mut i = if index & HARDENED != 0 {
        mac.mac(&[&[0u8], &parent.key, &index_bytes])
    } else {
        let pk = pubkey_compressed(&parent.key)?;
        mac.mac(&[&pk, &index_bytes])
    };
    let mut node = Node { key: parent.key, chain: [0u8; 32] };
    // child = (IL + k_par) mod n; libsecp256k1 rejects IL >= n and a zero result.
    let ok = ffi::secp256k1_ec_seckey_tweak_add(ctx(), node.key.as_mut_ptr(), i[..32].as_ptr()) == 1;
    node.chain.copy_from_slice(&i[32..]);
    wipe_bytes(&mut i); // IL is the private tweak
    if !ok {
        wipe_node(&mut node);
        return None;
    }
    Some(node)
}

unsafe fn derive_path(root: &Node, path: &[u32]) -> Option<Node> {
    let mut node = *root;
    for &index in path {
        match ckd_priv(&node, index) {
            // `node` is always our owned copy, never the caller's memory.
            Some(child) => {
                wipe_node(&mut node);
                node = child;
            }
            None => {
                wipe_node(&mut node);
                return None;
            }
        }
    }
    Some(node)
}

/// Base58Check of version + HASH160 (mainnet P2PKH/P2SH), written into the
/// fixed address buffer. Returns the encoded length.
fn base58check_address(version: u8, hash: &[u8; 20]) -> ([u8; MAX_ADDR_LEN], usize) {
    let mut payload = [0u8; 25];
    payload[0] = version;
    payload[1..21].copy_from_slice(hash);
    let checksum = sha256(&sha256(&payload[..21]));
    payload[21..25].copy_from_slice(&checksum[..4]);

    let zeros = payload.iter().take_while(|&&b| b == 0).count();
    // Repeated carry propagation, base 256 -> base 58 (digits little-endian).
    let mut digits = [0u8; 35];
    let mut digit_len = 0usize;
    for &byte in &payload[zeros..] {
        let mut carry = byte as u32;
        for d in digits[..digit_len].iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits[digit_len] = (carry % 58) as u8;
            carry /= 58;
            digit_len += 1;
        }
    }
    let mut out = [0u8; MAX_ADDR_LEN];
    out[..zeros].fill(b'1');
    for k in 0..digit_len {
        out[zeros + k] = B58[digits[digit_len - 1 - k] as usize];
    }
    (out, zeros + digit_len)
}

fn bech32_polymod_step(chk: u32) -> u32 {
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let top = chk >> 25;
    let mut next = (chk & 0x1ffffff) << 5;
    for (i, generator) in GEN.iter().enumerate() {
        if (top >> i) & 1 == 1 {
            next ^= generator;
        }
    }
    next
}

/// Version + program as 5-bit bech32 data values (version first).
fn bech32_data_values(version: u8, program: &[u8]) -> ([u8; MAX_BECH32_VALUES], usize) {
    let mut values = [0u8; MAX_BECH32_VALUES];
    values[0] = version;
    let mut len = 1usize;
    let mut acc = 0u16;
    let mut bits = 0u8;
    for &byte in program {
        acc = (acc << 8) | byte as u16;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            values[len] = ((acc >> bits) & 31) as u8;
            len += 1;
        }
    }
    if bits > 0 {
        values[len] = ((acc << (5 - bits)) & 31) as u8;
        len += 1;
    }
    (values, len)
}

/// BIP173/BIP350 bech32(m) encode. `hrp` is "bc" for witness addresses and
/// "sp" for BIP-352 Silent Payment codes (bech32m, no 90-character limit).
fn bech32_encode(hrp: &[u8], version: u8, program: &[u8], bech32m: bool) -> ([u8; MAX_ADDR_LEN], usize) {
    let (values, value_len) = bech32_data_values(version, program);
    let mut chk = 1u32;
    for &c in hrp {
        chk = bech32_polymod_step(chk) ^ (c >> 5) as u32;
    }
    chk = bech32_polymod_step(chk);
    for &c in hrp {
        chk = bech32_polymod_step(chk) ^ (c & 31) as u32;
    }
    for &value in &values[..value_len] {
        chk = bech32_polymod_step(chk) ^ value as u32;
    }
    for _ in 0..6 {
        chk = bech32_polymod_step(chk);
    }
    let polymod = chk ^ if bech32m { BECH32M_CONST } else { 1 };

    let mut out = [0u8; MAX_ADDR_LEN];
    let mut len = 0usize;
    out[len..len + hrp.len()].copy_from_slice(hrp);
    len += hrp.len();
    out[len] = b'1';
    len += 1;
    for &value in &values[..value_len] {
        out[len] = BECH32[value as usize];
        len += 1;
    }
    for i in 0..6 {
        let value = (polymod >> (5 * (5 - i))) & 31;
        out[len] = BECH32[value as usize];
        len += 1;
    }
    (out, len)
}

/// BIP86 output key: internal x-only key tweaked by tagged_hash("TapTweak", x).
unsafe fn taproot_output_key(seckey: &[u8; 32]) -> Option<[u8; 32]> {
    let mut pk = ffi::PublicKey::new();
    if ffi::secp256k1_ec_pubkey_create(ctx(), &mut pk, seckey.as_ptr()) != 1 {
        return None;
    }
    let mut internal = ffi::XOnlyPublicKey::new();
    let mut parity = 0;
    if ffi::secp256k1_xonly_pubkey_from_pubkey(ctx(), &mut internal, &mut parity, &pk) != 1 {
        return None;
    }
    let mut internal_bytes = [0u8; 32];
    if ffi::secp256k1_xonly_pubkey_serialize(ctx(), internal_bytes.as_mut_ptr(), &internal) != 1 {
        return None;
    }
    let tag = sha256(b"TapTweak");
    let tweak: [u8; 32] = Sha256::new()
        .chain_update(tag)
        .chain_update(tag)
        .chain_update(internal_bytes)
        .finalize()
        .into();
    let mut output = ffi::PublicKey::new();
    if ffi::secp256k1_xonly_pubkey_tweak_add(ctx(), &mut output, &internal, tweak.as_ptr()) != 1 {
        return None;
    }
    let mut output_xonly = ffi::XOnlyPublicKey::new();
    if ffi::secp256k1_xonly_pubkey_from_pubkey(ctx(), &mut output_xonly, &mut parity, &output) != 1 {
        return None;
    }
    let mut output_bytes = [0u8; 32];
    if ffi::secp256k1_xonly_pubkey_serialize(ctx(), output_bytes.as_mut_ptr(), &output_xonly) != 1 {
        return None;
    }
    Some(output_bytes)
}

/// The address of the selected type for a derived node, plus the payload the
/// JS side re-encodes for display. For Silent Payments `node` is the account
/// node and the BIP-352 scan/spend steps are appended here.
unsafe fn candidate_address(script: u32, node: &Node) -> Option<([u8; MAX_ADDR_LEN], usize, [u8; PAYLOAD_LEN])> {
    let mut payload = [0u8; PAYLOAD_LEN];
    match script {
        SCRIPT_SP => {
            let scan = derive_path(node, &[1 | HARDENED, 0])?;
            let spend = derive_path(node, &[HARDENED, 0])?;
            payload[..33].copy_from_slice(&pubkey_compressed(&scan.key)?);
            payload[33..].copy_from_slice(&pubkey_compressed(&spend.key)?);
            let (addr, len) = bech32_encode(b"sp", 0, &payload, true);
            Some((addr, len, payload))
        }
        SCRIPT_P2TR => {
            let output_key = taproot_output_key(&node.key)?;
            payload[..32].copy_from_slice(&output_key);
            let (addr, len) = bech32_encode(b"bc", 1, &output_key, true);
            Some((addr, len, payload))
        }
        _ => {
            let pubkey_hash = hash160(&pubkey_compressed(&node.key)?);
            payload[..20].copy_from_slice(&pubkey_hash);
            let (addr, len) = match script {
                SCRIPT_P2PKH => base58check_address(0, &pubkey_hash),
                SCRIPT_P2SH_P2WPKH => {
                    let mut redeem = [0u8; 22];
                    redeem[1] = 20;
                    redeem[2..22].copy_from_slice(&pubkey_hash);
                    base58check_address(5, &hash160(&redeem))
                }
                SCRIPT_P2WPKH => bech32_encode(b"bc", 0, &pubkey_hash, false),
                _ => return None,
            };
            Some((addr, len, payload))
        }
    }
}

/// Grinds counters `[start, start + count)` and records candidates whose
/// address starts with `prefix`.
///
/// `mode` selects the dial the counter turns:
/// * `MODE_PASSPHRASE`: `key` is the NFKD mnemonic, `salt` the NFKD starting
///   passphrase, `path` the full derivation path from the master node, and
///   the counter is the `pass_len`-character odometer string appended to the
///   passphrase. `counter_slot` must be `u32::MAX`.
/// * `MODE_NODE`: `key` is a 64-byte BIP32 node (private key ‖ chain code),
///   `path` the components below it, and the counter replaces
///   `path[counter_slot]` (keeping that slot's hardened bit). `salt_len` and
///   `pass_len` must be 0.
///
/// `path` is little-endian u32 components with the BIP32 hardened bit set
/// where hardened. For `SCRIPT_SP` it ends at the account node.
///
/// # Safety
/// `key`, `salt` (or `salt_len == 0`), `path`, and `prefix` must be readable
/// for their lengths, and `out` must hold `out_cap` writable bytes
/// (>= `HEADER_LEN` + 106 per record capacity desired).
#[no_mangle]
pub unsafe extern "C" fn vanity_grind(
    mode: u32,
    key: *const u8,
    key_len: usize,
    salt: *const u8,
    salt_len: usize,
    path: *const u8,
    path_len: usize,
    counter_slot: u32,
    prefix: *const u8,
    prefix_len: usize,
    pass_len: usize,
    start: u64,
    count: u64,
    out: *mut u8,
    out_cap: usize,
    script: u32,
) -> i32 {
    if key.is_null() || path.is_null() || prefix.is_null() || out.is_null()
        || prefix_len == 0 || prefix_len > MAX_ADDR_LEN
        || path_len == 0 || path_len > MAX_PATH_LEN
        || out_cap < HEADER_LEN || script > SCRIPT_SP
        || (salt_len > 0 && salt.is_null())
    {
        return -1;
    }
    let valid_mode = match mode {
        MODE_PASSPHRASE => {
            key_len > 0 && key_len <= MAX_KEY_LEN && salt_len <= MAX_SALT_LEN
                && pass_len > 0 && pass_len <= MAX_PASS_LEN && counter_slot == u32::MAX
        }
        MODE_NODE => key_len == NODE_LEN && salt_len == 0 && pass_len == 0 && (counter_slot as usize) < path_len,
        _ => false,
    };
    if !valid_mode {
        return -1;
    }
    let key = std::slice::from_raw_parts(key, key_len);
    let salt = if salt_len == 0 { &[][..] } else { std::slice::from_raw_parts(salt, salt_len) };
    let prefix = std::slice::from_raw_parts(prefix, prefix_len);
    let path_bytes = std::slice::from_raw_parts(path, path_len * 4);
    let mut path = [0u32; MAX_PATH_LEN];
    for (i, chunk) in path_bytes.chunks_exact(4).enumerate() {
        path[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    let path = &mut path[..path_len];
    let out_slice = std::slice::from_raw_parts_mut(out, out_cap);
    let record_cap = (out_cap - HEADER_LEN) / RECORD_LEN;

    // The counter space: 62^pass_len odometer strings (saturating at
    // u64::MAX; 62^11 already exceeds it), or the 2^31 BIP32 indexes.
    let space = if mode == MODE_PASSPHRASE {
        62u64.checked_pow(pass_len as u32).unwrap_or(u64::MAX)
    } else {
        HARDENED as u64
    };
    let count = count.min(space.saturating_sub(start));

    // Odometer digits (indexes into ALPHABET), most significant first.
    let mut digit = [0u8; MAX_PASS_LEN];
    if mode == MODE_PASSPHRASE {
        let mut c = start;
        for i in (0..pass_len).rev() {
            digit[i] = (c % 62) as u8;
            c /= 62;
        }
    }
    // The mnemonic pads are absorbed once for the whole range (passphrase
    // grind); the parent node is fixed for the whole range (derivation grind).
    let mnemonic = if mode == MODE_PASSPHRASE { Some(HmacSha512::new(key)) } else { None };
    let parent = if mode == MODE_NODE {
        let mut node = Node { key: [0u8; 32], chain: [0u8; 32] };
        node.key.copy_from_slice(&key[..32]);
        node.chain.copy_from_slice(&key[32..]);
        Some(node)
    } else {
        None
    };
    let hardened_slot = if mode == MODE_NODE { path[counter_slot as usize] & HARDENED } else { 0 };

    let mut processed: u64 = 0;
    let mut matches: u32 = 0;
    let mut pass = [0u8; MAX_PASS_LEN];
    let mut status = 0;

    while processed < count {
        let counter = start + processed;
        let node = match (&mnemonic, &parent) {
            (Some(mnemonic), _) => {
                for i in 0..pass_len {
                    pass[i] = ALPHABET[digit[i] as usize];
                }
                let mut seed = bip39_seed(mnemonic, &[salt, &pass[..pass_len]]);
                // Every stage of the per-candidate chain is wiped on use:
                // the 64-byte seed, the master node, each intermediate CKD
                // node (in derive_path), and the final child (below).
                let node = match master_node(&seed) {
                    Some(mut root) => {
                        let node = derive_path(&root, path);
                        wipe_node(&mut root);
                        node
                    }
                    None => None,
                };
                wipe_bytes(&mut seed);
                node
            }
            (_, Some(parent)) => {
                path[counter_slot as usize] = (counter as u32) | hardened_slot;
                derive_path(parent, path)
            }
            _ => None,
        };
        // Invalid children (IL >= n, zero keys) are ~2^-128 rare; skip them.
        if let Some(mut node) = node {
            let candidate = candidate_address(script, &node);
            wipe_node(&mut node);
            if let Some((addr, addr_len, payload)) = candidate {
                if addr_len >= prefix_len && &addr[..prefix_len] == prefix {
                    if (matches as usize) < record_cap {
                        let at = HEADER_LEN + matches as usize * RECORD_LEN;
                        out_slice[at..at + 8].copy_from_slice(&counter.to_le_bytes());
                        out_slice[at + 8..at + 8 + MAX_PASS_LEN].fill(0);
                        out_slice[at + 8..at + 8 + pass_len].copy_from_slice(&pass[..pass_len]);
                        out_slice[at + 40..at + 40 + PAYLOAD_LEN].copy_from_slice(&payload);
                        matches += 1;
                    } else {
                        status = -2;
                        break;
                    }
                }
            }
        }
        // Increment the odometer (least significant character last).
        if mode == MODE_PASSPHRASE {
            let mut i = pass_len;
            while i > 0 {
                i -= 1;
                digit[i] += 1;
                if digit[i] < 62 {
                    break;
                }
                digit[i] = 0;
            }
        }
        processed += 1;
    }

    out_slice[0..8].copy_from_slice(&processed.to_le_bytes());
    out_slice[8..12].copy_from_slice(&matches.to_le_bytes());
    // Retire the long-lived secrets: the fixed parent node and the candidate
    // passphrase window. (The absorbed HMAC pads sit in the sha2 crate's
    // opaque state and cannot be zeroed from here; the input buffers are
    // wiped by vanity_free when JS releases them.)
    if let Some(mut node) = parent {
        wipe_node(&mut node);
    }
    wipe_bytes(&mut pass);
    status
}
