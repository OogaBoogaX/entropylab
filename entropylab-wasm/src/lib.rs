//! WebAssembly bindings to libsecp256k1, bitcoin_hashes, rust-bitcoin,
//! rust-bip39, base58ck, bech32, scrypt, and a vendored AEZ v5 (src/aez/,
//! for the aezeed cipher seed) for EntropyLab.
//!
//! Every secp256k1 curve operation and every cryptographic hash in the app
//! goes through this library, along with BIP32/BIP39/address/transaction
//! work and the aezeed (LND cipher seed) decipher (the JS facades —
//! secp256k1.js, hashes.js, hdkey.js, bip39.js, base58.js, addresses.js,
//! bech32.js, tx.js, aezeed.js — all share the loader
//! src/js/entropylab-wasm.js).
//! The boundary is deliberately narrow: scalars and hashes cross as fixed
//! 32-byte buffers, public points as their SEC serialization (33 bytes
//! compressed / 65 uncompressed), ECDSA signatures as 64-byte compact
//! (r || s), hash inputs as arbitrary byte strings. There are no handles and
//! no strings; a point "object" in JS is just its compressed encoding,
//! re-parsed on each call.
//!
//! Private keys enter WASM linear memory only for the duration of one call,
//! matching the Uint8Array lifetimes of the previous implementation. This
//! library never generates randomness: signing is RFC 6979 with caller-fixed
//! extra entropy, exactly as before.
//!
//! Secret hygiene: every buffer JS allocates through `el_alloc` is zeroed
//! by `el_free` before deallocation, and the secret temporaries below
//! (private keys, seeds, chain codes, mnemonics, passphrases, tweaks, and the
//! intermediate HMAC/PBKDF2 blocks) are overwritten in place before they go
//! out of scope. `SecretKey`/`Scalar` use libsecp256k1's own
//! `non_secure_erase`; plain arrays, `String`s, and newtype wrappers such as
//! `ChainCode` go through the volatile `wipe` helpers. The scrypt crate
//! never zeroizes its internal working buffers (128·N·r bytes of V, plus B
//! and T, at aezeed's production N=2^15), so both scrypt exports overwrite
//! them immediately after every call by re-allocating and wiping the same
//! sizes (see `scrub_scrypt`; V's first block otherwise retains one PBKDF2
//! iteration of the passphrase, a passphrase-guessing accelerator), and the
//! vendored AEZ module wipes its expanded key schedule on drop and its
//! Blake2b key-expansion hasher after use. What cannot be wiped without new
//! dependencies: state hidden inside dependency types that expose no erase
//! (the `HmacEngine` key pads, `bip39::Mnemonic`'s stored phrase, and the
//! by-value moves inside `bitcoin::bip32`). Those copies are short lived
//! stack/heap cells, but they are the known residual. The scrypt working
//! buffer also grows WASM linear memory permanently (linear memory never
//! shrinks); that is a size cost, not a secrecy cost.
//!
//! Curve operations go through the safe `secp256k1` crate (rust-bitcoin's
//! wrapper over the vendored bitcoin-core C library); hashes go through
//! `bitcoin_hashes`. One preallocated context is created at first use; it
//! holds no secret state (only precomputed tables) and lives for the page's
//! lifetime.

use bitcoin_hashes::{hash160, ripemd160, sha256, sha512, Hash, HashEngine, Hmac, HmacEngine};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId, Signature};
use secp256k1::{Message, PublicKey, Scalar, Secp256k1, SecretKey};
use std::sync::OnceLock;

mod aez;
mod descriptor;

static CONTEXT: OnceLock<Secp256k1<secp256k1::All>> = OnceLock::new();

fn ctx() -> &'static Secp256k1<secp256k1::All> {
    CONTEXT.get_or_init(Secp256k1::new)
}

/// Allocates `len` zero-filled bytes of linear memory for JS to fill. Pair
/// with `el_free`. The box owns exactly `len` bytes, so the deallocation
/// layout is reproducible from `len` alone. The `el_` prefix matches every
/// other export: this is the crate-wide allocator, not curve-specific.
#[no_mangle]
pub extern "C" fn el_alloc(len: usize) -> *mut u8 {
    Box::into_raw(vec![0u8; len].into_boxed_slice()) as *mut u8
}

/// # Safety
/// `ptr` must come from `el_alloc` and `len` must be exactly the length
/// passed there: the box is reconstructed from `len` alone, so any other
/// length deallocates with the wrong layout.
#[no_mangle]
pub unsafe extern "C" fn el_free(ptr: *mut u8, len: usize) {
    // Zero the buffer before deallocation: inputs can carry private keys,
    // seeds, mnemonics, or passphrases, and freed linear memory must not
    // retain them for a later allocation to expose.
    wipe(ptr, len);
    let slice = std::ptr::slice_from_raw_parts_mut(ptr, len);
    drop(Box::from_raw(slice));
}

/// Overwrites `len` bytes at `ptr` with zeroes. Volatile stores plus a
/// compiler fence, so the wipe cannot be elided as a dead store ahead of
/// deallocation or reordered after the secret's last use. (The `zeroize`
/// crate does the same; it is not a dependency here, per project policy.)
unsafe fn wipe(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        for i in 0..len {
            std::ptr::write_volatile(ptr.add(i), 0u8);
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Wipes a byte slice (arrays, `Vec`s).
fn wipe_bytes(bytes: &mut [u8]) {
    unsafe { wipe(bytes.as_mut_ptr(), bytes.len()) };
}

/// Wipes any plain-old-data value in place (e.g. `ChainCode`, whose field is
/// private and which exposes no erase of its own).
fn wipe_val<T>(value: &mut T) {
    unsafe { wipe(value as *mut T as *mut u8, std::mem::size_of::<T>()) };
}

/// Wipes a `String`'s bytes (mnemonic phrases, WIF/xprv encodings).
fn wipe_string(text: &mut String) {
    unsafe { wipe(text.as_mut_ptr(), text.len()) };
}

/// `Xpriv` is `Copy` and has no `Drop`, so its two secret halves are
/// overwritten explicitly.
fn wipe_xpriv(node: &mut Xpriv) {
    node.private_key.non_secure_erase();
    wipe_val(&mut node.chain_code);
}

/// # Safety
/// `ptr` must be valid for `len` bytes (or `len` zero).
unsafe fn read<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        return &[];
    }
    std::slice::from_raw_parts(ptr, len)
}

// ── secp256k1 curve operations (the secp256k1.js facade) ────────────────────

/// 1 if the 32 bytes at `seckey` are a valid secp256k1 secret key, else 0.
#[no_mangle]
pub unsafe extern "C" fn secp_seckey_valid(seckey: *const u8) -> i32 {
    let mut sk = match SecretKey::from_slice(read(seckey, 32)) {
        Ok(sk) => sk,
        Err(_) => return 0,
    };
    sk.non_secure_erase();
    1
}

/// Public key for `seckey`, serialized into `out` (which must hold 65 bytes).
/// Returns 33/65, or -1 if the key is invalid.
#[no_mangle]
pub unsafe extern "C" fn secp_pubkey_create(seckey: *const u8, out: *mut u8, compressed: i32) -> i32 {
    let mut sk = match SecretKey::from_slice(read(seckey, 32)) {
        Ok(sk) => sk,
        Err(_) => return -1,
    };
    let pk = PublicKey::from_secret_key(ctx(), &sk);
    let written = write_serialized(&pk, out, compressed != 0);
    sk.non_secure_erase();
    written
}

fn write_serialized(pk: &PublicKey, out: *mut u8, compressed: bool) -> i32 {
    if compressed {
        let bytes = pk.serialize();
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, 33) };
        33
    } else {
        let bytes = pk.serialize_uncompressed();
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, 65) };
        65
    }
}

/// Validates a SEC-encoded point and re-serializes it into `out` (33 or 65
/// bytes per `compressed`). Returns the serialized length, or -1 if the
/// encoding is not a valid curve point.
#[no_mangle]
pub unsafe extern "C" fn secp_point_parse_serialize(
    input: *const u8,
    input_len: usize,
    out: *mut u8,
    compressed: i32,
) -> i32 {
    match PublicKey::from_slice(read(input, input_len)) {
        Ok(pk) => write_serialized(&pk, out, compressed != 0),
        Err(_) => -1,
    }
}

/// Compressed encoding of the sum of two SEC-encoded points. Returns 33, or
/// -1 if either point is invalid or the sum is the point at infinity.
#[no_mangle]
pub unsafe extern "C" fn secp_point_add(
    a: *const u8,
    a_len: usize,
    b: *const u8,
    b_len: usize,
    out: *mut u8,
) -> i32 {
    let (pa, pb) = match (PublicKey::from_slice(read(a, a_len)), PublicKey::from_slice(read(b, b_len))) {
        (Ok(pa), Ok(pb)) => (pa, pb),
        _ => return -1,
    };
    match pa.combine(&pb) {
        Ok(sum) => write_serialized(&sum, out, true),
        Err(_) => -1,
    }
}

/// SEC-serializes `point * scalar` into `out`. Returns 33/65, or -1 if the
/// point is invalid, the scalar is out of range, or the result is the point
/// at infinity.
#[no_mangle]
pub unsafe extern "C" fn secp_point_mul(
    point: *const u8,
    point_len: usize,
    scalar: *const u8,
    out: *mut u8,
    compressed: i32,
) -> i32 {
    let pk = match PublicKey::from_slice(read(point, point_len)) {
        Ok(pk) => pk,
        Err(_) => return -1,
    };
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(read(scalar, 32));
    let mut tweak = match Scalar::from_be_bytes(bytes) {
        Ok(tweak) => tweak,
        Err(_) => {
            wipe_bytes(&mut bytes);
            return -1;
        }
    };
    let result = match pk.mul_tweak(ctx(), &tweak) {
        Ok(product) => write_serialized(&product, out, compressed != 0),
        Err(_) => -1,
    };
    tweak.non_secure_erase();
    wipe_bytes(&mut bytes);
    result
}

/// RFC 6979 ECDSA over the 32-byte `msg32`, serialized compact (r || s, low-S
/// guaranteed by libsecp256k1) into `out64`. `extra32` is either null (plain
/// RFC 6979) or a pointer to 32 bytes of extra entropy mixed into the nonce
/// exactly like Bitcoin Core's low-r grinding counter. Returns 64, or -1 if
/// the secret key is invalid.
#[no_mangle]
pub unsafe extern "C" fn secp_sign(
    msg32: *const u8,
    seckey: *const u8,
    extra32: *const u8,
    out64: *mut u8,
) -> i32 {
    let msg = match Message::from_digest_slice(read(msg32, 32)) {
        Ok(msg) => msg,
        Err(_) => return -1,
    };
    let mut sk = match SecretKey::from_slice(read(seckey, 32)) {
        Ok(sk) => sk,
        Err(_) => return -1,
    };
    let sig = if extra32.is_null() {
        ctx().sign_ecdsa(&msg, &sk)
    } else {
        let mut extra = [0u8; 32];
        extra.copy_from_slice(read(extra32, 32));
        let sig = ctx().sign_ecdsa_with_noncedata(&msg, &sk, &extra);
        wipe_bytes(&mut extra);
        sig
    };
    std::ptr::copy_nonoverlapping(sig.serialize_compact().as_ptr(), out64, 64);
    sk.non_secure_erase();
    64
}

/// Verifies a compact (r || s) ECDSA signature. Returns 1 for valid, 0 for
/// invalid, -1 if the public key encoding is not a curve point.
#[no_mangle]
pub unsafe extern "C" fn secp_verify(
    msg32: *const u8,
    pubin: *const u8,
    pub_len: usize,
    sig64: *const u8,
) -> i32 {
    let pk = match PublicKey::from_slice(read(pubin, pub_len)) {
        Ok(pk) => pk,
        Err(_) => return -1,
    };
    let msg = match Message::from_digest_slice(read(msg32, 32)) {
        Ok(msg) => msg,
        Err(_) => return -1,
    };
    let sig = match Signature::from_compact(read(sig64, 64)) {
        Ok(sig) => sig,
        Err(_) => return 0,
    };
    i32::from(ctx().verify_ecdsa(&msg, &sig, &pk).is_ok())
}

/// Recovers the public key from a compact (r || s) ECDSA signature over the
/// 32-byte `msg32` and a recovery id (0-3), serialized compressed into `out`.
/// Used by the BOLT11 invoice decoder to recover the payee node id from the
/// invoice signature. Returns 33, or -1 on any malformed input.
#[no_mangle]
pub unsafe extern "C" fn secp_ecdsa_recover(
    msg32: *const u8,
    sig64: *const u8,
    recid: i32,
    out: *mut u8,
) -> i32 {
    let msg = match Message::from_digest_slice(read(msg32, 32)) {
        Ok(msg) => msg,
        Err(_) => return -1,
    };
    let id = match RecoveryId::from_i32(recid) {
        Ok(id) => id,
        Err(_) => return -1,
    };
    let sig = match RecoverableSignature::from_compact(read(sig64, 64), id) {
        Ok(sig) => sig,
        Err(_) => return -1,
    };
    match ctx().recover_ecdsa(&msg, &sig) {
        Ok(pk) => {
            let serialized = pk.serialize();
            std::ptr::copy_nonoverlapping(serialized.as_ptr(), out, 33);
            33
        }
        Err(_) => -1,
    }
}

/// Normalizes a compact signature to low-S form in place. Returns 1 if S was
/// flipped, 0 if it was already low, -1 if the input is not a parseable
/// signature.
#[no_mangle]
pub unsafe extern "C" fn secp_sig_normalize(sig64: *mut u8) -> i32 {
    let mut sig = match Signature::from_compact(read(sig64, 64)) {
        Ok(sig) => sig,
        Err(_) => return -1,
    };
    let before = sig.serialize_compact();
    sig.normalize_s();
    let after = sig.serialize_compact();
    std::ptr::copy_nonoverlapping(after.as_ptr(), sig64, 64);
    i32::from(before != after)
}

// ── Hashes (the hashes.js facade) ───────────────────────────────────────────

/// SHA-256 of the input, written as 32 bytes into `out`. Returns 32.
#[no_mangle]
pub unsafe extern "C" fn el_sha256(input: *const u8, input_len: usize, out: *mut u8) -> i32 {
    // Digests can themselves be key material (e.g. a brain-wallet SHA-256 is
    // the private key), so the local copy is wiped after it is written out.
    let mut digest = sha256::Hash::hash(read(input, input_len)).to_byte_array();
    std::ptr::copy_nonoverlapping(digest.as_ptr(), out, 32);
    wipe_bytes(&mut digest);
    32
}

/// SHA-512 of the input, written as 64 bytes into `out`. Returns 64.
#[no_mangle]
pub unsafe extern "C" fn el_sha512(input: *const u8, input_len: usize, out: *mut u8) -> i32 {
    let mut digest = sha512::Hash::hash(read(input, input_len)).to_byte_array();
    std::ptr::copy_nonoverlapping(digest.as_ptr(), out, 64);
    wipe_bytes(&mut digest);
    64
}

/// RIPEMD-160 of the input, written as 20 bytes into `out`. Returns 20.
#[no_mangle]
pub unsafe extern "C" fn el_ripemd160(input: *const u8, input_len: usize, out: *mut u8) -> i32 {
    let mut digest = ripemd160::Hash::hash(read(input, input_len)).to_byte_array();
    std::ptr::copy_nonoverlapping(digest.as_ptr(), out, 20);
    wipe_bytes(&mut digest);
    20
}

/// HASH160 (RIPEMD-160 of SHA-256) of the input, written as 20 bytes into
/// `out`. Returns 20.
#[no_mangle]
pub unsafe extern "C" fn el_hash160(input: *const u8, input_len: usize, out: *mut u8) -> i32 {
    let mut digest = hash160::Hash::hash(read(input, input_len)).to_byte_array();
    std::ptr::copy_nonoverlapping(digest.as_ptr(), out, 20);
    wipe_bytes(&mut digest);
    20
}

/// HMAC-SHA-512 (RFC 2104) of the input under `key`, written as 64 bytes
/// into `out`. Returns 64.
#[no_mangle]
pub unsafe extern "C" fn el_hmac_sha512(
    key: *const u8,
    key_len: usize,
    input: *const u8,
    input_len: usize,
    out: *mut u8,
) -> i32 {
    let mut engine = HmacEngine::<sha512::Hash>::new(read(key, key_len));
    engine.input(read(input, input_len));
    let mut digest = Hmac::<sha512::Hash>::from_engine(engine).to_byte_array();
    std::ptr::copy_nonoverlapping(digest.as_ptr(), out, 64);
    wipe_bytes(&mut digest);
    64
}

/// PBKDF2-HMAC-SHA-512 (RFC 2898): `iterations` rounds, derived key written
/// into `out`/`out_len`. Returns `out_len`, or -1 on a zero iteration count
/// or an output length over 4096 (the app only ever asks for 64).
#[no_mangle]
pub unsafe extern "C" fn el_pbkdf2_hmac_sha512(
    pass: *const u8,
    pass_len: usize,
    salt: *const u8,
    salt_len: usize,
    iterations: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if iterations == 0 || out_len == 0 || out_len > 4096 {
        return -1;
    }
    let pass = read(pass, pass_len);
    let salt = read(salt, salt_len);
    let mut block: u32 = 1;
    let mut written = 0usize;
    while written < out_len {
        // U1 = HMAC(pass, salt || INT32_BE(block))
        let mut engine = HmacEngine::<sha512::Hash>::new(pass);
        engine.input(salt);
        engine.input(&block.to_be_bytes());
        let mut u = Hmac::<sha512::Hash>::from_engine(engine).to_byte_array();
        let mut t = u;
        for _ in 1..iterations {
            let mut engine = HmacEngine::<sha512::Hash>::new(pass);
            engine.input(&u);
            u = Hmac::<sha512::Hash>::from_engine(engine).to_byte_array();
            for i in 0..64 {
                t[i] ^= u[i];
            }
        }
        let take = (out_len - written).min(64);
        std::ptr::copy_nonoverlapping(t.as_ptr(), out.add(written), take);
        // The U/T blocks are the derived key (and its preimage) — for BIP39
        // that is the seed itself. Wipe each block as soon as it is copied.
        wipe_bytes(&mut u);
        wipe_bytes(&mut t);
        written += take;
        block += 1;
    }
    out_len as i32
}

// ── scrypt and the aezeed cipher seed (the aezeed.js facade) ────────────────
// aezeed is LND's 24-word cipher-seed scheme. The mnemonic decodes (11 bits
// per word, JS side) to version(1) || AEZ ciphertext(23) || salt(5) ||
// CRC-32C(4), and the ciphertext deciphers under an scrypt-derived key to
// internal version(1) || birthday(2, big-endian days since the Bitcoin
// genesis block) || entropy(16). LND feeds that entropy directly to BIP32 as
// the master seed. This library only deciphers (a deterministic
// transformation of user input); it never creates seeds. KDF parameters are
// caller-fixed on both exports, matching el_pbkdf2_hmac_sha512: this library
// never invents them, production callers pass LND's log_n=15, r=8, p=1, and
// the test suite passes the weakened log_n=4 that LND's published vectors
// were generated with. The parameters are BOUNDED, not just caller-fixed:
// scrypt's working buffer is 128·r·2^log_n bytes and WASM linear memory never
// shrinks, so an unbounded call would grow the heap permanently (or trap on
// allocation failure, killing every export until reload). el_scrypt caps the
// working buffer at 32 MiB and p at 16; el_aezeed_decipher accepts exactly
// the two parameter sets a cipher seed can legitimately need.

/// The scrypt working-buffer cap for `el_scrypt` (128·r·2^log_n bytes).
const SCRYPT_MAX_MEMORY: u64 = 32 * 1024 * 1024;
/// The scrypt parallelism cap for `el_scrypt`.
const SCRYPT_MAX_P: u32 = 16;

/// Bounded scrypt parameters: 1 ≤ log_n ≤ 20, 128·r·2^log_n ≤ 32 MiB, and
/// 1 ≤ p ≤ 16, then the crate's own validation on top.
fn scrypt_params(log_n: u32, r: u32, p: u32) -> Option<scrypt::Params> {
    if log_n == 0 || log_n > 20 || p == 0 || p > SCRYPT_MAX_P {
        return None;
    }
    let memory = 128u64 * u64::from(r) * (1u64 << log_n);
    if memory > SCRYPT_MAX_MEMORY {
        return None;
    }
    scrypt::Params::new(log_n as u8, r, p).ok()
}

/// Overwrites scrypt's internal working buffers after the call. The scrypt
/// crate (0.12.0) allocates B (128·r·p bytes), V (128·r·2^log_n), and T
/// (128·r) as plain `vec![]`s it never zeroizes, and WASM linear memory
/// never shrinks: V's first block still holds the pre-ROMix B (one PBKDF2
/// iteration of the passphrase), which would let a later reader of the heap
/// test passphrase guesses without paying the scrypt cost. Re-allocating
/// the same sizes immediately after the call reuses the just-freed blocks
/// with the default allocator, so wiping the fresh buffers overwrites the
/// residue in place. Best effort by construction — the Node suite asserts
/// the PBKDF2 block is absent from the heap after a decode.
fn scrub_scrypt(log_n: u32, r: u32, p: u32) {
    let r128 = 128usize * r as usize;
    let mut b = vec![0u8; r128 * p as usize];
    let mut v = vec![0u8; r128 << log_n];
    let mut t = vec![0u8; r128];
    wipe_bytes(&mut b);
    wipe_bytes(&mut v);
    wipe_bytes(&mut t);
}

/// Overwrites the dead stack cells the KDF and cipher frames leave behind:
/// WASM linear memory holds the call stack too, and the PBKDF2/HMAC rounds
/// inside scrypt (and the Blake2b key expansion inside `Aez::new`) spill
/// key material into frame slots that popping the stack does not erase.
/// One wide, non-inlined frame, zeroed with volatile writes, rewrites the
/// addresses the just-returned calls used. Best effort — the Node suite
/// asserts the derived key is absent from linear memory after a decode.
#[inline(never)]
fn scrub_stack() {
    // Nested non-inlined frames: each level wipes its own 4 KiB while the
    // deeper levels run, so one call rewrites a contiguous ~40 KiB of stack
    // down past the deepest frame scrypt/pbkdf2/hmac used.
    #[inline(never)]
    fn level(depth: u32) {
        let mut frame = [0u8; 4096];
        wipe_bytes(&mut frame);
        std::hint::black_box(frame.as_ptr());
        if depth > 0 {
            level(depth - 1);
        }
    }
    level(9);
}

/// scrypt (RFC 7914) with parameters `2^log_n`, `r`, `p`, derived key written
/// into `out`/`out_len`. Returns `out_len`, or -1 on invalid parameters, an
/// output length over 128 (the app only ever asks for 32), a working buffer
/// over 32 MiB, or p over 16.
#[no_mangle]
pub unsafe extern "C" fn el_scrypt(
    pass: *const u8,
    pass_len: usize,
    salt: *const u8,
    salt_len: usize,
    log_n: u32,
    r: u32,
    p: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if out_len == 0 || out_len > 128 {
        return -1;
    }
    let params = match scrypt_params(log_n, r, p) {
        Some(params) => params,
        None => return -1,
    };
    let mut key = vec![0u8; out_len];
    let result = scrypt::scrypt(read(pass, pass_len), read(salt, salt_len), &params, &mut key);
    scrub_scrypt(log_n, r, p);
    if result.is_err() {
        wipe_bytes(&mut key);
        scrub_stack();
        return -1;
    }
    std::ptr::copy_nonoverlapping(key.as_ptr(), out, out_len);
    wipe_bytes(&mut key);
    scrub_stack();
    out_len as i32
}

/// CRC-32C (Castagnoli), bitwise over the reflected polynomial 0x82F63B78,
/// exactly Go's `crc32.MakeTable(crc32.Castagnoli)` as LND uses for the
/// aezeed checksum. Bitwise instead of table-driven: this checks one 29-byte
/// header per user action, and the eight-line loop is the auditable form.
fn crc32c(data: &[u8]) -> u32 {
    let mut crc: u32 = !0;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0x82F6_3B78 & mask);
        }
    }
    !crc
}

/// aezeed version-0 (LND cipher seed) decipher. `seed33` is the 33-byte
/// decoding of the 24 words; `pass` is the passphrase (the caller substitutes
/// LND's default "aezeed" for an empty one). The key is
/// scrypt(pass, salt, 2^log_n, r, p, 32) and the 23-byte ciphertext opens
/// with AEZ v5 (empty nonce, the single 6-byte AD string version || salt,
/// tau = 4). Writes the 19-byte plaintext into `out`. Returns 19, or:
///   -1 invalid KDF parameters,
///   -2 unsupported external version (byte 0 is not 0),
///   -3 CRC-32C mismatch (mistyped or swapped words),
///   -4 AEZ authentication failure (wrong passphrase).
/// Only the two legitimate parameter sets are accepted: LND's production
/// (log_n=15, r=8, p=1) and the weakened (log_n=4, r=8, p=1) that LND's
/// published test vectors were generated with.
#[no_mangle]
pub unsafe extern "C" fn el_aezeed_decipher(
    seed33: *const u8,
    pass: *const u8,
    pass_len: usize,
    log_n: u32,
    r: u32,
    p: u32,
    out: *mut u8,
) -> i32 {
    let seed = read(seed33, 33);
    if seed[0] != 0 {
        return -2;
    }
    let expected = u32::from_be_bytes([seed[29], seed[30], seed[31], seed[32]]);
    if crc32c(&seed[..29]) != expected {
        return -3;
    }
    let salt = &seed[24..29];
    if !matches!((log_n, r, p), (15, 8, 1) | (4, 8, 1)) {
        return -1;
    }
    let params = match scrypt_params(log_n, r, p) {
        Some(params) => params,
        None => return -1,
    };
    let mut key = [0u8; 32];
    let result = scrypt::scrypt(read(pass, pass_len), salt, &params, &mut key);
    scrub_scrypt(log_n, r, p);
    if result.is_err() {
        wipe_bytes(&mut key);
        scrub_stack();
        return -1;
    }
    let aez = aez::Aez::new(&key);
    // The expanded key schedule lives inside `aez`, which wipes it on drop;
    // the caller-visible key copy is wiped at once.
    wipe_bytes(&mut key);
    let mut ad = [0u8; 6];
    ad[0] = seed[0];
    ad[1..].copy_from_slice(salt);
    let plaintext = aez.decrypt(&[], &[&ad], 4, &seed[1..24]);
    let mut plaintext = match plaintext {
        Some(plaintext) => plaintext,
        None => {
            scrub_stack();
            return -4;
        }
    };
    if plaintext.len() != 19 {
        wipe_bytes(&mut plaintext);
        scrub_stack();
        return -1;
    }
    std::ptr::copy_nonoverlapping(plaintext.as_ptr(), out, 19);
    // The plaintext carries the wallet's master entropy; wipe the temporary
    // once the boundary buffer (zeroed later by el_free) holds it.
    wipe_bytes(&mut plaintext);
    scrub_stack();
    19
}

// ── Base58Check (bitcoin::base58 / base58ck) ────────────────────────────────
// Strings cross as UTF-8 bytes; outputs use the caller's `cap` and fail with
// -1 rather than overflowing. A 78-byte extended key encodes to <= 112 chars.

/// Base58Check-encodes the payload, writing UTF-8 into `out` (capacity
/// `cap`). Returns the string length, or -1 if `cap` is too small.
#[no_mangle]
pub unsafe extern "C" fn el_b58check_encode(input: *const u8, input_len: usize, out: *mut u8, cap: usize) -> i32 {
    // The payload can be a WIF or extended private key; the encoded string is
    // then secret too, so both the boundary buffer (el_free) and this
    // temporary copy are wiped.
    let mut encoded = base58ck::encode_check(read(input, input_len));
    let len = encoded.len();
    if len > cap {
        wipe_string(&mut encoded);
        return -1;
    }
    std::ptr::copy_nonoverlapping(encoded.as_ptr(), out, len);
    wipe_string(&mut encoded);
    len as i32
}

/// Base58Check-decodes the UTF-8 string, verifying the checksum, writing the
/// payload into `out` (capacity `cap`). Returns the payload length, or -1 on
/// malformed input / bad checksum / small `cap`.
#[no_mangle]
pub unsafe extern "C" fn el_b58check_decode(input: *const u8, input_len: usize, out: *mut u8, cap: usize) -> i32 {
    let text = match std::str::from_utf8(read(input, input_len)) {
        Ok(text) => text,
        Err(_) => return -1,
    };
    let mut payload = match base58ck::decode_check(text) {
        Ok(payload) => payload,
        Err(_) => return -1,
    };
    if payload.len() > cap {
        wipe_bytes(&mut payload);
        return -1;
    }
    std::ptr::copy_nonoverlapping(payload.as_ptr(), out, payload.len());
    let len = payload.len() as i32;
    wipe_bytes(&mut payload);
    len
}

// ── BIP32 (bitcoin::bip32) ──────────────────────────────────────────────────
// A node crosses the boundary as its 78-byte BIP32 serialization with the
// mainnet version bytes (xprv/xpub); the JS side owns SLIP-132 re-versioning
// exactly as before. Derivation returns 78 (bytes written) on success, 1 for
// the retry-with-next-index verdict BIP32 mandates for an invalid I_L or child
// (rust-bitcoin's own ckd_* `expect` on these statistically-unreachable
// branches; the previous JS implementation retried, so we keep that contract
// and never panic), and -1 for hard errors.

use bitcoin::bip32::{ChainCode, ChildNumber, Xpriv, Xpub};

// By reference, so the caller can wipe its single owned copy of the node
// serialization instead of leaving a moved-from stack copy behind.
fn write78(node: &[u8; 78], out: *mut u8) -> i32 {
    unsafe { std::ptr::copy_nonoverlapping(node.as_ptr(), out, 78) };
    78
}

/// Master xprv node (78 bytes) for `seed`. Returns 78, or -1 if the seed's
/// I_L is not a valid secret key.
#[no_mangle]
pub unsafe extern "C" fn el_hd_master(seed: *const u8, seed_len: usize, out: *mut u8) -> i32 {
    match Xpriv::new_master(bitcoin::Network::Bitcoin, read(seed, seed_len)) {
        Ok(mut master) => {
            let mut encoded = master.encode();
            let written = write78(&encoded, out);
            wipe_bytes(&mut encoded);
            wipe_xpriv(&mut master);
            written
        }
        Err(_) => -1,
    }
}

/// One private CKD step from the 78-byte parent node at child `index`
/// (hardened bit included). Returns 78 via `out`, 1 for the BIP32 retry
/// verdict, or -1 on a malformed parent.
#[no_mangle]
pub unsafe extern "C" fn el_hd_ckd_priv(node: *const u8, index: u32, out: *mut u8) -> i32 {
    let mut parent = match Xpriv::decode(read(node, 78)) {
        Ok(parent) => parent,
        Err(_) => return -1,
    };
    let depth = match parent.depth.checked_add(1) {
        Some(depth) => depth,
        None => {
            wipe_xpriv(&mut parent);
            return -1;
        }
    };
    let i = ChildNumber::from(index);
    let mut engine = HmacEngine::<sha512::Hash>::new(&parent.chain_code[..]);
    if i.is_hardened() {
        engine.input(&[0u8]);
        engine.input(&parent.private_key[..]);
    } else {
        engine.input(&PublicKey::from_secret_key(ctx(), &parent.private_key).serialize());
    }
    engine.input(&u32::from(i).to_be_bytes());
    let mut hmac = Hmac::<sha512::Hash>::from_engine(engine).to_byte_array();
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&hmac[32..]);
    // Single exit, so every secret temporary is wiped on every path below.
    let result = 'ckd: {
        let il: &[u8] = &hmac[..32];
        let child_key = if il.iter().all(|b| *b == 0) {
            // I_L == 0: BIP32 says proceed with the next value for i, and so
            // do we — the retry verdict (statistically unreachable) goes to
            // the caller's retry loop instead of inventing a node BIP32 never
            // defines (issue #359).
            break 'ckd 1;
        } else {
            let mut tweak = match SecretKey::from_slice(il) {
                Ok(tweak) => tweak,
                Err(_) => break 'ckd 1, // I_L >= n: retry with the next index
            };
            let mut scalar = Scalar::from(tweak);
            let sum = parent.private_key.add_tweak(&scalar);
            tweak.non_secure_erase();
            scalar.non_secure_erase();
            match sum {
                Ok(sum) => sum,
                Err(_) => break 'ckd 1, // child would be zero: retry
            }
        };
        let mut child = Xpriv {
            network: parent.network,
            depth,
            parent_fingerprint: parent.fingerprint(ctx()),
            child_number: i,
            private_key: child_key,
            chain_code: ChainCode::from(chain_code),
        };
        let mut encoded = child.encode();
        let written = write78(&encoded, out);
        wipe_bytes(&mut encoded);
        wipe_xpriv(&mut child);
        written
    };
    wipe_xpriv(&mut parent);
    wipe_bytes(&mut hmac);
    wipe_bytes(&mut chain_code);
    result
}

/// One public CKD step (normal indexes only) from the 78-byte parent xpub.
/// Returns 78 via `out`, 1 for the BIP32 retry verdict, -1 for a hardened
/// index or a malformed parent.
#[no_mangle]
pub unsafe extern "C" fn el_hd_ckd_pub(node: *const u8, index: u32, out: *mut u8) -> i32 {
    let parent = match Xpub::decode(read(node, 78)) {
        Ok(parent) => parent,
        Err(_) => return -1,
    };
    let i = ChildNumber::from(index);
    if i.is_hardened() {
        return -1; // public derivation cannot produce hardened children
    }
    let mut engine = HmacEngine::<sha512::Hash>::new(&parent.chain_code[..]);
    engine.input(&parent.public_key.serialize());
    engine.input(&u32::from(i).to_be_bytes());
    let hmac = Hmac::<sha512::Hash>::from_engine(engine);
    let il: &[u8] = &hmac[..32];
    let child_point = if il.iter().all(|b| *b == 0) {
        // I_L == 0: retry with the next index, exactly like el_hd_ckd_priv
        // (statistically unreachable, but spec-defined — issue #359).
        return 1;
    } else {
        let tweak = match SecretKey::from_slice(il) {
            Ok(tweak) => tweak,
            Err(_) => return 1, // I_L >= n: retry with the next index
        };
        let tweak_point = PublicKey::from_secret_key(ctx(), &tweak);
        match parent.public_key.combine(&tweak_point) {
            Ok(sum) => sum,
            Err(_) => return 1, // point at infinity: retry
        }
    };
    let depth = match parent.depth.checked_add(1) {
        Some(depth) => depth,
        None => return -1,
    };
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&hmac[32..]);
    let child = Xpub {
        network: parent.network,
        depth,
        parent_fingerprint: parent.fingerprint(),
        child_number: i,
        public_key: child_point,
        chain_code: ChainCode::from(chain_code),
    };
    // Public derivation only: everything here is recoverable from the xpub,
    // so there is no secret temporary to wipe.
    write78(&child.encode(), out)
}

/// Classifies a 78-byte node: 1 = valid private node, 2 = valid public node,
/// 0 = neither (bad version, length, or key payload).
#[no_mangle]
pub unsafe extern "C" fn el_hd_validate(node: *const u8) -> i32 {
    let bytes = read(node, 78);
    if let Ok(mut xprv) = Xpriv::decode(bytes) {
        wipe_xpriv(&mut xprv);
        return 1;
    }
    if Xpub::decode(bytes).is_ok() {
        return 2;
    }
    0
}

// ── BIP39 (rust-bip39, English) ─────────────────────────────────────────────
// Phrases cross as UTF-8, already NFKD-normalized by the JS caller
// (String.normalize, the same step the previous implementation ran).
// mnemonicToSeed is deliberately NOT here: it is PBKDF2-HMAC-SHA512 over the
// JS-side NFKD of phrase and "mnemonic"+passphrase (hashes.js), keeping the
// exact previous normalization semantics.

use bip39::{Language, Mnemonic};

/// BIP39 mnemonic sentence for `entropy` (16/20/24/28/32 bytes), written as
/// UTF-8 into `out` (capacity `cap`). Returns the phrase length, or -1 on a
/// bad entropy length or small `cap`.
#[no_mangle]
pub unsafe extern "C" fn el_bip39_entropy_to_mnemonic(entropy: *const u8, len: usize, out: *mut u8, cap: usize) -> i32 {
    let mnemonic = match Mnemonic::from_entropy_in(Language::English, read(entropy, len)) {
        Ok(mnemonic) => mnemonic,
        Err(_) => return -1,
    };
    let mut phrase = mnemonic.words().collect::<Vec<&str>>().join(" ");
    if phrase.len() > cap {
        wipe_string(&mut phrase);
        return -1;
    }
    std::ptr::copy_nonoverlapping(phrase.as_ptr(), out, phrase.len());
    let len = phrase.len() as i32;
    wipe_string(&mut phrase);
    len
}

/// Entropy behind a BIP39 English mnemonic (caller NFKD-normalized), written
/// into `out` (capacity `cap`). Returns the entropy length, or -1 on unknown
/// words, bad word count, or a checksum mismatch.
#[no_mangle]
pub unsafe extern "C" fn el_bip39_mnemonic_to_entropy(phrase: *const u8, len: usize, out: *mut u8, cap: usize) -> i32 {
    let text = match std::str::from_utf8(read(phrase, len)) {
        Ok(text) => text,
        Err(_) => return -1,
    };
    let mnemonic = match Mnemonic::parse_in_normalized(Language::English, text) {
        Ok(mnemonic) => mnemonic,
        Err(_) => return -1,
    };
    let (mut entropy, entropy_len) = mnemonic.to_entropy_array();
    if entropy_len > cap {
        wipe_bytes(&mut entropy);
        return -1;
    }
    std::ptr::copy_nonoverlapping(entropy.as_ptr(), out, entropy_len);
    wipe_bytes(&mut entropy);
    entropy_len as i32
}

/// 1 if the phrase is a checksum-valid BIP39 English mnemonic, else 0.
#[no_mangle]
pub unsafe extern "C" fn el_bip39_validate(phrase: *const u8, len: usize) -> i32 {
    let text = match std::str::from_utf8(read(phrase, len)) {
        Ok(text) => text,
        Err(_) => return 0,
    };
    i32::from(Mnemonic::parse_in_normalized(Language::English, text).is_ok())
}

/// Word `index` of the crate's English wordlist, written as UTF-8 into `out`
/// (capacity `cap`). Lets the test suite prove the JS-side wordlist copy is
/// identical to the one the mnemonic operations use. Returns the word length,
/// or -1 for an out-of-range index or small `cap`.
#[no_mangle]
pub unsafe extern "C" fn el_bip39_word_at(index: u32, out: *mut u8, cap: usize) -> i32 {
    let list = Language::English.word_list();
    let word = match list.get(index as usize) {
        Some(word) => word,
        None => return -1,
    };
    let bytes = word.as_bytes();
    if bytes.len() > cap {
        return -1;
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
    bytes.len() as i32
}

// ── Scripts and addresses (bitcoin::Address / ScriptBuf) ────────────────────
// scriptPubKey builders take keys/scripts in and produce the raw script bytes;
// network selection only shapes the address string (el_addr_from_script),
// mirroring how the previous @scure/btc-signer code was used. net: 0 =
// mainnet, 1 = testnet, 2 = signet, 3 = regtest. Signet shares testnet's
// tb1…/m…/n…/2… encodings; regtest differs only in its bcrt1… bech32 HRP.
// All return the byte length written, or -1 on invalid input (bad key, bad
// template arguments, unknown script type).

use bitcoin::address::Address;
use bitcoin::key::XOnlyPublicKey;
use bitcoin::script::PushBytesBuf;
use bitcoin::{Network, PublicKey as BtcPublicKey, ScriptBuf};

fn network_from_selector(sel: u8) -> Option<Network> {
    match sel {
        0 => Some(Network::Bitcoin),
        1 => Some(Network::Testnet),
        2 => Some(Network::Signet),
        3 => Some(Network::Regtest),
        _ => None,
    }
}

fn write_script(script: ScriptBuf, out: *mut u8, cap: usize) -> i32 {
    let bytes = script.as_bytes();
    if bytes.len() > cap {
        return -1;
    }
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len()) };
    bytes.len() as i32
}

/// P2PKH scriptPubKey for a 33/65-byte public key. Returns 25 or -1.
#[no_mangle]
pub unsafe extern "C" fn el_spk_p2pkh(pubkey: *const u8, len: usize, out: *mut u8, cap: usize) -> i32 {
    let pk = match BtcPublicKey::from_slice(read(pubkey, len)) {
        Ok(pk) => pk,
        Err(_) => return -1,
    };
    write_script(ScriptBuf::new_p2pkh(&pk.pubkey_hash()), out, cap)
}

/// P2WPKH scriptPubKey for a 33-byte (compressed) public key. Returns 22 or
/// -1 (uncompressed keys are rejected, as before; CompressedPublicKey would
/// otherwise silently accept and normalize them).
#[no_mangle]
pub unsafe extern "C" fn el_spk_p2wpkh(pubkey: *const u8, len: usize, out: *mut u8, cap: usize) -> i32 {
    if len != 33 {
        return -1;
    }
    let pk = match bitcoin::CompressedPublicKey::from_slice(read(pubkey, len)) {
        Ok(pk) => pk,
        Err(_) => return -1,
    };
    write_script(ScriptBuf::new_p2wpkh(&pk.wpubkey_hash()), out, cap)
}

/// P2SH-wrapped P2WPKH scriptPubKey for a 33-byte public key. Returns 23 or
/// -1.
#[no_mangle]
pub unsafe extern "C" fn el_spk_p2sh_p2wpkh(pubkey: *const u8, len: usize, out: *mut u8, cap: usize) -> i32 {
    let inner = el_spk_p2wpkh;
    let mut buf = [0u8; 22];
    let n = inner(pubkey, len, buf.as_mut_ptr(), 22);
    if n != 22 {
        return -1;
    }
    let redeem = ScriptBuf::from(buf.to_vec());
    let hash = hash160::Hash::hash(redeem.as_bytes()).to_byte_array();
    write_script(ScriptBuf::new_p2sh(&bitcoin::ScriptHash::from_byte_array(hash)), out, cap)
}

/// BIP86 P2TR scriptPubKey (key-path only, tweaked) for a 32-byte x-only
/// internal key. Returns 34 or -1.
#[no_mangle]
pub unsafe extern "C" fn el_spk_p2tr_key(internal: *const u8, out: *mut u8, cap: usize) -> i32 {
    let key = match XOnlyPublicKey::from_slice(read(internal, 32)) {
        Ok(key) => key,
        Err(_) => return -1,
    };
    write_script(ScriptBuf::new_p2tr(ctx(), key, None), out, cap)
}

/// P2TR scriptPubKey with a single-leaf tapscript tree (the multisig taproot
/// case). Returns 34 or -1.
#[no_mangle]
pub unsafe extern "C" fn el_spk_p2tr_leaf(internal: *const u8, leaf: *const u8, leaf_len: usize, out: *mut u8, cap: usize) -> i32 {
    let key = match XOnlyPublicKey::from_slice(read(internal, 32)) {
        Ok(key) => key,
        Err(_) => return -1,
    };
    let script = ScriptBuf::from(read(leaf, leaf_len).to_vec());
    // Single-leaf tree: the merkle root is the leaf hash itself.
    let root = bitcoin::taproot::LeafNode::new_script(script, bitcoin::taproot::LeafVersion::TapScript).node_hash();
    let info = bitcoin::taproot::TaprootSpendInfo::new_key_spend(ctx(), key, Some(root));
    write_script(ScriptBuf::new_p2tr_tweaked(info.output_key()), out, cap)
}

/// P2SH scriptPubKey wrapping an arbitrary redeem script. Returns 23 or -1.
#[no_mangle]
pub unsafe extern "C" fn el_spk_p2sh(script: *const u8, len: usize, out: *mut u8, cap: usize) -> i32 {
    let hash = hash160::Hash::hash(read(script, len)).to_byte_array();
    write_script(ScriptBuf::new_p2sh(&bitcoin::ScriptHash::from_byte_array(hash)), out, cap)
}

/// P2WSH scriptPubKey for an arbitrary witness script. Returns 34 or -1.
#[no_mangle]
pub unsafe extern "C" fn el_spk_p2wsh(script: *const u8, len: usize, out: *mut u8, cap: usize) -> i32 {
    let hash = sha256::Hash::hash(read(script, len)).to_byte_array();
    write_script(ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::from_byte_array(hash)), out, cap)
}

/// Bare multisig (BIP11-style) redeem script: OP_m <pk1>..<pkN> OP_N
/// OP_CHECKMULTISIG over 33-byte public keys packed back to back. Returns the
/// script length, or -1 unless 0 < m <= n <= 16 with valid keys.
#[no_mangle]
pub unsafe extern "C" fn el_script_multisig(m: u32, pubs: *const u8, pubs_len: usize, out: *mut u8, cap: usize) -> i32 {
    if m == 0 || m > 16 || pubs_len == 0 || pubs_len % 33 != 0 {
        return -1;
    }
    let n = pubs_len / 33;
    if m as usize > n || n > 16 {
        return -1;
    }
    let raw = read(pubs, pubs_len);
    let mut builder = bitcoin::script::Builder::new().push_int(m as i64);
    for i in 0..n {
        let pk = &raw[i * 33..(i + 1) * 33];
        if BtcPublicKey::from_slice(pk).is_err() {
            return -1;
        }
        let mut buf = PushBytesBuf::with_capacity(33);
        if buf.extend_from_slice(pk).is_err() {
            return -1;
        }
        builder = builder.push_slice(buf.as_push_bytes());
    }
    builder = builder.push_int(n as i64).push_opcode(bitcoin::opcodes::all::OP_CHECKMULTISIG);
    write_script(builder.into_script(), out, cap)
}

/// Taproot multisig leaf (BIP342 CHECKSIGADD form): <pk1> OP_CHECKSIG <pk2>
/// OP_CHECKSIGADD .. <pkN> OP_CHECKSIGADD <m> OP_NUMEQUAL over 32-byte x-only
/// keys packed back to back. Returns the script length, or -1 unless
/// 0 < m <= n <= 999 with valid keys.
#[no_mangle]
pub unsafe extern "C" fn el_script_multisig_tr(m: u32, pubs: *const u8, pubs_len: usize, out: *mut u8, cap: usize) -> i32 {
    if m == 0 || pubs_len == 0 || pubs_len % 32 != 0 {
        return -1;
    }
    let n = pubs_len / 32;
    if m as usize > n || n > 999 {
        return -1;
    }
    let raw = read(pubs, pubs_len);
    let mut builder = bitcoin::script::Builder::new();
    for i in 0..n {
        let pk = &raw[i * 32..(i + 1) * 32];
        if XOnlyPublicKey::from_slice(pk).is_err() {
            return -1;
        }
        let mut buf = PushBytesBuf::with_capacity(32);
        if buf.extend_from_slice(pk).is_err() {
            return -1;
        }
        builder = builder.push_slice(buf.as_push_bytes());
        builder = builder.push_opcode(if i == 0 {
            bitcoin::opcodes::all::OP_CHECKSIG
        } else {
            bitcoin::opcodes::all::OP_CHECKSIGADD
        });
    }
    builder = builder.push_int(m as i64).push_opcode(bitcoin::opcodes::all::OP_NUMEQUAL);
    write_script(builder.into_script(), out, cap)
}

/// Renders a scriptPubKey as an address string (UTF-8 into `out`). Covers
/// pkh/sh/wpkh/wsh/tr plus the fixed BIP433 P2A program, matching the previous
/// Address.encode behavior. Returns the string length, or -1 for unknown
/// script types (the caller falls back to showing the script hex).
#[no_mangle]
pub unsafe extern "C" fn el_addr_from_script(script: *const u8, len: usize, net_sel: u8, out: *mut u8, cap: usize) -> i32 {
    let network = match network_from_selector(net_sel) {
        Some(network) => network,
        None => return -1,
    };
    let script = ScriptBuf::from(read(script, len).to_vec());
    let addr = match Address::from_script(&script, network) {
        Ok(addr) => addr.to_string(),
        Err(_) => return -1,
    };
    let bytes = addr.as_bytes();
    if bytes.len() > cap {
        return -1;
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
    bytes.len() as i32
}

// ── bech32m, word-level (BIP352 silent payment addresses) ───────────────────
// scure's bech32m.encode/decode took 5-bit words; this boundary does the
// same. The JS side keeps its convertbits (toWords/fromWords) helpers — pure
// bit reshaping, no cryptography. The checksum math (the part that matters)
// is rust-bitcoin's bech32 crate, whose code-length limit for Bech32m (1023)
// matches BIP352's extended addresses.

use bech32::primitives::decode::CheckedHrpstring;
use bech32::primitives::gf32::Fe32;
use bech32::Bech32m;
use bech32::Hrp;

/// bech32m-encodes `hrp` + 5-bit `words`, writing the string into `out`.
/// Returns the string length, or -1 on a bad hrp/word or small `cap`.
#[no_mangle]
pub unsafe extern "C" fn el_bech32m_encode(
    hrp_ptr: *const u8,
    hrp_len: usize,
    words: *const u8,
    words_len: usize,
    out: *mut u8,
    cap: usize,
) -> i32 {
    let hrp_text = match std::str::from_utf8(read(hrp_ptr, hrp_len)) {
        Ok(text) => text,
        Err(_) => return -1,
    };
    let hrp = match Hrp::parse(hrp_text) {
        Ok(hrp) => hrp,
        Err(_) => return -1,
    };
    let raw = read(words, words_len);
    let mut fes = Vec::with_capacity(raw.len());
    for &w in raw {
        match Fe32::try_from(w) {
            Ok(fe) => fes.push(fe),
            Err(_) => return -1,
        }
    }
    let mut encoded = bech32::primitives::encode::Encoder::<_, Bech32m>::new(fes.into_iter(), &hrp)
        .chars()
        .collect::<String>();
    // BIP352 spscan/spspend strings carry private keys, so the temporary
    // encoded copy is wiped after it is written out.
    if encoded.len() > cap {
        wipe_string(&mut encoded);
        return -1;
    }
    std::ptr::copy_nonoverlapping(encoded.as_ptr(), out, encoded.len());
    let len = encoded.len() as i32;
    wipe_string(&mut encoded);
    len
}

/// Decodes a bech32m string: writes the hrp (UTF-8, `hrp_out`/`hrp_cap`) and
/// the 5-bit data words (`words_out`/`words_cap`). Returns
/// `hrp_len + (word_count << 12)`, or -1 on any checksum/format error. Mixed
/// case is rejected (as bech32 requires); callers lowercase first.
#[no_mangle]
pub unsafe extern "C" fn el_bech32m_decode(
    input: *const u8,
    input_len: usize,
    hrp_out: *mut u8,
    hrp_cap: usize,
    words_out: *mut u8,
    words_cap: usize,
) -> i32 {
    let text = match std::str::from_utf8(read(input, input_len)) {
        Ok(text) => text,
        Err(_) => return -1,
    };
    let parsed = match CheckedHrpstring::new::<Bech32m>(text) {
        Ok(parsed) => parsed,
        Err(_) => return -1,
    };
    let hrp_value = parsed.hrp();
    let hrp = hrp_value.as_str().as_bytes();
    if hrp.len() > hrp_cap || hrp.len() > 0xfff {
        return -1;
    }
    let mut count = 0usize;
    for fe in parsed.fe32_iter::<std::iter::Empty<u8>>() {
        if count >= words_cap {
            return -1;
        }
        *words_out.add(count) = fe.to_u8();
        count += 1;
    }
    std::ptr::copy_nonoverlapping(hrp.as_ptr(), hrp_out, hrp.len());
    (hrp.len() + (count << 12)) as i32
}

// ── Transactions and sighash (bitcoin::Transaction consensus decode) ────────
// The inspector walks PSBT key-value maps itself (it must see malformed and
// duplicate fields to report on them), but the transactions inside — and the
// BIP143 sighash the RFC 6979 comparison replays — are consensus territory
// and run on rust-bitcoin's own decoder.
//
// el_tx_parse emits a flat little-endian layout:
//   i32 version (the consensus-signed bit pattern; JavaScript reads it with
//   getInt32) | u8 segwit | u32 in_count | per input: 32-byte prev txid
//   (wire order) | u32 vout | u32 script_len + script | u32 sequence |
//   u32 witness_count + per item (u32 len + bytes) || u32 out_count |
//   per output: u64 amount | u32 script_len + script || u32 locktime
// Returns bytes written, -1 on decode failure, -2 when bytes trail the
// transaction, -3 when the output capacity is too small. A null `out` is a
// size query: it returns the required flat capacity instead of writing.

use bitcoin::consensus::Decodable;
use bitcoin::Transaction;

#[no_mangle]
pub unsafe extern "C" fn el_tx_parse(input: *const u8, input_len: usize, out: *mut u8, cap: usize) -> i32 {
    let bytes = read(input, input_len);
    let mut cursor: &[u8] = bytes;
    let tx = match Transaction::consensus_decode_from_finite_reader(&mut cursor) {
        Ok(tx) => tx,
        Err(_) => return -1,
    };
    if !cursor.is_empty() {
        return -2;
    }
    let mut size = 4 + 1 + 4 + 4 + 4;
    for txin in &tx.input {
        size += 36 + 4 + txin.script_sig.len() + 4 + 4;
        for item in txin.witness.iter() {
            size += 4 + item.len();
        }
    }
    for txout in &tx.output {
        size += 8 + 4 + txout.script_pubkey.len();
    }
    if out.is_null() {
        // Size query (the two-call convention): report the flat-layout
        // capacity the caller must provide. The estimate-based caller cap
        // could under-allocate a decodable transaction — a witness can carry
        // many empty items at one wire byte each against four flat bytes —
        // and misreport it as truncated (issue #339).
        return if size > i32::MAX as usize { -3 } else { size as i32 };
    }
    if size > cap {
        return -3;
    }
    let mut w = Vec::with_capacity(size);
    let put32 = |v: u32, w: &mut Vec<u8>| w.extend_from_slice(&v.to_le_bytes());
    put32(tx.version.0 as u32, &mut w);
    let segwit = tx.input.iter().any(|i| !i.witness.is_empty());
    w.push(u8::from(segwit));
    put32(tx.input.len() as u32, &mut w);
    for txin in &tx.input {
        w.extend_from_slice(&txin.previous_output.txid.to_byte_array());
        put32(txin.previous_output.vout, &mut w);
        put32(txin.script_sig.len() as u32, &mut w);
        w.extend_from_slice(txin.script_sig.as_bytes());
        put32(txin.sequence.0, &mut w);
        let items: Vec<&[u8]> = txin.witness.iter().collect();
        put32(items.len() as u32, &mut w);
        for item in items {
            put32(item.len() as u32, &mut w);
            w.extend_from_slice(item);
        }
    }
    put32(tx.output.len() as u32, &mut w);
    for txout in &tx.output {
        w.extend_from_slice(&txout.value.to_sat().to_le_bytes());
        put32(txout.script_pubkey.len() as u32, &mut w);
        w.extend_from_slice(txout.script_pubkey.as_bytes());
    }
    put32(tx.lock_time.to_consensus_u32(), &mut w);
    std::ptr::copy_nonoverlapping(w.as_ptr(), out, w.len());
    w.len() as i32
}

/// BIP143 SegWit v0 sighash (SIGHASH_ALL only) for the transaction at
/// `tx_ptr`, input `index`, `script_code`, and the prevout amount in sats.
/// Writes the 32-byte digest into `out`. Returns 32, or -1 on failure. This
/// is exactly the digest the RFC 6979 comparison re-derives.
#[no_mangle]
pub unsafe extern "C" fn el_sighash_segwit_v0(
    tx_ptr: *const u8,
    tx_len: usize,
    index: u32,
    script_code: *const u8,
    sc_len: usize,
    amount: u64,
    out: *mut u8,
) -> i32 {
    use bitcoin::hashes::Hash as _;
    let mut cursor: &[u8] = read(tx_ptr, tx_len);
    let tx = match Transaction::consensus_decode_from_finite_reader(&mut cursor) {
        Ok(tx) => tx,
        Err(_) => return -1,
    };
    if !cursor.is_empty() {
        return -1;
    }
    let script = bitcoin::Script::from_bytes(read(script_code, sc_len));
    let mut cache = bitcoin::sighash::SighashCache::new(&tx);
    let mut buf = Vec::new();
    if cache
        .segwit_v0_encode_signing_data_to(
            &mut buf,
            index as usize,
            script,
            bitcoin::Amount::from_sat(amount),
            bitcoin::sighash::EcdsaSighashType::All,
        )
        .is_err()
    {
        return -1;
    }
    let digest = bitcoin_hashes::sha256d::Hash::hash(&buf).to_byte_array();
    std::ptr::copy_nonoverlapping(digest.as_ptr(), out, 32);
    32
}

#[cfg(test)]
mod tests {
    use super::*;

    // The allocator pair must round-trip exact sizes, including zero length:
    // el_free reconstructs a Box<[u8]> whose layout comes from `len` alone,
    // so a capacity mismatch corrupts the host allocator. The wasm suite
    // (test/wipe-wasm.test.mjs) pins this behavior in the artifact; this test
    // makes the same lifecycle checkable on the host — `cargo test`, or
    // `cargo +nightly miri test` for a UB-checked run.
    #[test]
    fn alloc_free_round_trips_exact_sizes() {
        for len in [0usize, 1, 2, 15, 16, 31, 32, 255, 256, 4096] {
            for cycle in 0..8u8 {
                let ptr = el_alloc(len);
                assert!(!ptr.is_null());
                unsafe {
                    for i in 0..len {
                        // A recycled block must never expose stale bytes.
                        assert_eq!(ptr.add(i).read(), 0);
                        ptr.add(i).write_volatile(cycle ^ i as u8);
                    }
                    el_free(ptr, len);
                }
            }
        }
    }

    // The standard CRC-32C check value: crc32c("123456789") = 0xE3069283
    // (RFC 3720 appendix B.4 lists the same reference implementation).
    #[test]
    fn crc32c_check_value() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    /// 24 aezeed words to their 33-byte encoding: 11 bits per word,
    /// big-endian bitstream, using the crate's own English wordlist.
    fn aezeed_words_to_bytes(mnemonic: &str) -> [u8; 33] {
        let list = Language::English.word_list();
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 24);
        let mut bytes = [0u8; 33];
        let mut bit = 0usize;
        for word in words {
            let index = list.iter().position(|w| *w == word).expect("word on list") as u32;
            for i in (0..11).rev() {
                if index >> i & 1 == 1 {
                    bytes[bit / 8] |= 0x80 >> (bit % 8);
                }
                bit += 1;
            }
        }
        bytes
    }

    fn decipher(mnemonic: &str, pass: &str, log_n: u32) -> Result<[u8; 19], i32> {
        let seed = aezeed_words_to_bytes(mnemonic);
        let mut out = [0u8; 19];
        let code = unsafe {
            el_aezeed_decipher(seed.as_ptr(), pass.as_ptr(), pass.len(), log_n, 8, 1, out.as_mut_ptr())
        };
        if code == 19 {
            Ok(out)
        } else {
            Err(code)
        }
    }

    // LND's published version-0 vectors (lnd/aezeed/cipherseed_test.go at
    // commit 63bd8e7, MIT): entropy 81b637d86359e6960de795e41e0b4cfd, salt
    // "salt1". The vectors were generated with weakened scrypt (n=16, r=8,
    // p=1), hence log_n = 4 here; the parameters are caller-fixed for
    // exactly this reason.
    #[test]
    fn aezeed_deciphers_lnd_vectors() {
        let entropy: [u8; 16] = [
            0x81, 0xb6, 0x37, 0xd8, 0x63, 0x59, 0xe6, 0x96, 0x0d, 0xe7, 0x95, 0xe4, 0x1e, 0x0b,
            0x4c, 0xfd,
        ];
        let plain = decipher(
            "ability liquid travel stem barely drastic pact cupboard apple thrive \
             morning oak feature tissue couch old math inform success suggest drink \
             motion know royal",
            "aezeed",
            4,
        )
        .expect("default-passphrase vector deciphers");
        assert_eq!(plain[0], 0, "internal version");
        assert_eq!(u16::from_be_bytes([plain[1], plain[2]]), 0, "birthday");
        assert_eq!(plain[3..], entropy, "entropy");

        let plain = decipher(
            "able tree stool crush transfer cloud cross three profit outside hen \
             citizen plate ride require leg siren drum success suggest drink \
             require fiscal upgrade",
            "!very_safe_55345_password*",
            4,
        )
        .expect("passphrase vector deciphers");
        assert_eq!(plain[0], 0, "internal version");
        assert_eq!(u16::from_be_bytes([plain[1], plain[2]]), 3365, "birthday");
        assert_eq!(plain[3..], entropy, "entropy");
    }

    // A production-parameter (n=2^15) vector published in guggero's
    // cryptography-toolkit e2e suite (e2e/aezeed.spec.mjs, MIT): entropy
    // 000102030405060708090a0b0c0d0e0f, salt 0001020304, birthday 0,
    // internal version 1, default passphrase.
    #[test]
    fn aezeed_deciphers_full_strength_vector() {
        let plain = decipher(
            "ability result leisure oven shiver wedding toe broccoli exclude \
             mosquito kind van action waste merit bundle robust source able \
             advice core humor kitchen siren",
            "aezeed",
            15,
        )
        .expect("full-strength vector deciphers");
        assert_eq!(plain[0], 1, "internal version");
        assert_eq!(u16::from_be_bytes([plain[1], plain[2]]), 0, "birthday");
        let entropy: Vec<u8> = (0..16).collect();
        assert_eq!(plain[3..], entropy[..], "entropy");
    }

    #[test]
    fn aezeed_error_taxonomy() {
        let good = "ability liquid travel stem barely drastic pact cupboard apple thrive \
                    morning oak feature tissue couch old math inform success suggest drink \
                    motion know royal";
        // Wrong passphrase: checksum still passes, AEZ authentication fails.
        assert_eq!(decipher(good, "wrong", 4), Err(-4));
        // A swapped word breaks the CRC-32C before any KDF work happens.
        let flipped = good.replacen("liquid", "travel", 1);
        assert_eq!(decipher(&flipped, "aezeed", 4), Err(-3));
        // A nonzero external version byte (checksum recomputed so only the
        // version check can object).
        let mut seed = aezeed_words_to_bytes(good);
        seed[0] = 1;
        let crc = crc32c(&seed[..29]).to_be_bytes();
        seed[29..].copy_from_slice(&crc);
        let mut out = [0u8; 19];
        let code = unsafe {
            el_aezeed_decipher(seed.as_ptr(), "aezeed".as_ptr(), 6, 4, 8, 1, out.as_mut_ptr())
        };
        assert_eq!(code, -2);
    }

    // el_scrypt against an RFC 7914 section 13 vector.
    #[test]
    fn scrypt_rfc7914_vector() {
        let mut out = [0u8; 64];
        let code = unsafe {
            el_scrypt(
                "password".as_ptr(), 8,
                "NaCl".as_ptr(), 4,
                10, 8, 16,
                out.as_mut_ptr(), 64,
            )
        };
        assert_eq!(code, 64);
        let expected: [u8; 16] = [
            0xfd, 0xba, 0xbe, 0x1c, 0x9d, 0x34, 0x72, 0x00, 0x78, 0x56, 0xe7, 0x19, 0x0d, 0x01,
            0xe9, 0xfe,
        ];
        assert_eq!(out[..16], expected, "first 16 bytes of the RFC vector");
    }

    // The exports bound the scrypt parameters: the working buffer
    // (128·r·2^log_n bytes) never exceeds 32 MiB and p never exceeds 16, so
    // no call can grow linear memory by more than the aezeed production cost
    // (linear memory never shrinks). el_aezeed_decipher is stricter: only
    // LND's production (15, 8, 1) and weakened (4, 8, 1) sets.
    #[test]
    fn scrypt_parameters_are_bounded() {
        let mut out = [0u8; 32];
        let mut call = |log_n: u32, r: u32, p: u32| unsafe {
            el_scrypt(
                "pass".as_ptr(), 4,
                "salt".as_ptr(), 4,
                log_n, r, p,
                out.as_mut_ptr(), 32,
            )
        };
        // Accepted: the production and test-vector shapes.
        assert_eq!(call(15, 8, 1), 32, "production aezeed shape");
        assert_eq!(call(4, 8, 1), 32, "weakened test-vector shape");
        // Rejected: 64 MiB working buffer.
        assert_eq!(call(16, 8, 1), -1, "log_n=16 exceeds the 32 MiB cap");
        // Rejected: 36 MiB working buffer.
        assert_eq!(call(15, 9, 1), -1, "r=9 exceeds the 32 MiB cap");
        // Rejected: the 1 GiB case the raw crate would have accepted.
        assert_eq!(call(20, 8, 1), -1, "log_n=20 exceeds the 32 MiB cap");
        // Rejected: parallelism over 16.
        assert_eq!(call(4, 8, 17), -1, "p=17 exceeds the cap");
        // Rejected: zero parameters.
        assert_eq!(call(0, 8, 1), -1);
        assert_eq!(call(4, 0, 1), -1);
        assert_eq!(call(4, 8, 0), -1);
    }

    #[test]
    fn aezeed_decipher_accepts_only_lnd_parameter_sets() {
        let seed = aezeed_words_to_bytes(
            "ability liquid travel stem barely drastic pact cupboard apple thrive \
             morning oak feature tissue couch old math inform success suggest drink \
             motion know royal",
        );
        let mut out = [0u8; 19];
        let mut call = |log_n: u32, r: u32, p: u32| unsafe {
            el_aezeed_decipher(seed.as_ptr(), "aezeed".as_ptr(), 6, log_n, r, p, out.as_mut_ptr())
        };
        assert_eq!(call(4, 8, 1), 19, "the weakened test-vector set deciphers");
        // Wrong parameters for this seed, but a legitimate set: AEZ auth
        // failure, not a parameter rejection.
        assert_eq!(call(15, 8, 1), -4, "the production set is accepted");
        // Everything else is a parameter rejection before any KDF work.
        assert_eq!(call(10, 8, 1), -1, "no third log_n");
        assert_eq!(call(15, 8, 2), -1, "no third parameter set");
        assert_eq!(call(4, 9, 1), -1);
        assert_eq!(call(0, 8, 1), -1);
    }
}
