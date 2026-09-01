// The WebAssembly boundary itself: the shared loader's memory discipline and
// the complete export surface of the shipped artifact. Two exports
// (secp_seckey_valid, el_hd_validate) ship in the artifact with no JS caller;
// their contracts are locked here so a crate-side change cannot silently
// alter shipped behavior. The negative-length and throw paths of
// withInput/withOutput are the failure semantics every facade relies on.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { heap, requireReady, wasmExports, wasmReady, withInput, withOutput } from "../src/js/entropylab-wasm.js";
import { HDKey } from "../src/js/hdkey.js";
import { base58checkDecode } from "../src/js/base58.js";

await wasmReady;

// Every export the crate ships (entropylab-wasm/src/lib.rs), alphabetically.
const CRATE_EXPORTS = [
  "el_addr_from_script",
  "el_b58check_decode",
  "el_b58check_encode",
  "el_bech32m_decode",
  "el_bech32m_encode",
  "el_bip39_entropy_to_mnemonic",
  "el_bip39_mnemonic_to_entropy",
  "el_bip39_validate",
  "el_bip39_word_at",
  "el_hash160",
  "el_hd_ckd_priv",
  "el_hd_ckd_pub",
  "el_hd_master",
  "el_hd_validate",
  "el_hmac_sha512",
  "el_pbkdf2_hmac_sha512",
  "el_ripemd160",
  "el_script_multisig",
  "el_script_multisig_tr",
  "el_sha256",
  "el_sha512",
  "el_sighash_segwit_v0",
  "el_spk_p2pkh",
  "el_spk_p2sh",
  "el_spk_p2sh_p2wpkh",
  "el_spk_p2tr_key",
  "el_spk_p2tr_leaf",
  "el_spk_p2wpkh",
  "el_spk_p2wsh",
  "el_tx_parse",
  "el_alloc",
  "el_free",
  "secp_point_add",
  "secp_point_mul",
  "secp_point_parse_serialize",
  "secp_pubkey_create",
  "secp_seckey_valid",
  "secp_sign",
  "secp_sig_normalize",
  "secp_verify",
];

const SECP256K1_ORDER = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
const big32 = (value) => {
  const bytes = new Uint8Array(32);
  let remaining = value;
  for (let index = 31; index >= 0; index--) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
};

test("the module is initialized synchronously under Node and exports the full crate surface", () => {
  assert.doesNotThrow(() => requireReady());
  const exports = wasmExports();
  for (const name of CRATE_EXPORTS) {
    assert.equal(typeof exports[name], "function", `the artifact is missing the ${name} export`);
  }
  assert.ok(exports.memory instanceof WebAssembly.Memory);
});

test("withInput copies the input into linear memory and frees it on throw", () => {
  const input = new Uint8Array([1, 2, 3, 250]);
  const seen = withInput(input, (pointer) => heap().slice(pointer, pointer + input.length));
  assert.deepEqual(seen, input, "the callback observes the copied bytes");
  assert.throws(() => withInput(input, () => { throw new Error("boom"); }), /boom/);
  // A throw must not corrupt the allocator: the next real call still works.
  const digest = withInput(new Uint8Array([0x61, 0x62, 0x63]), (pointer) =>
    withOutput(32, (out) => wasmExports().el_sha256(pointer, 3, out)),
  );
  assert.equal(Buffer.from(digest).toString("hex"), createHash("sha256").update("abc").digest("hex"));
});

test("withOutput maps a negative return to null and a zero return to empty bytes", () => {
  assert.equal(withOutput(32, () => -1), null, "the crate's error sentinel becomes null");
  assert.deepEqual(withOutput(32, () => 0), new Uint8Array(0));
  assert.throws(() => withOutput(32, () => { throw new Error("boom"); }), /boom/);
  assert.equal(
    Buffer.from(withInput(new Uint8Array([0x61]), (pointer) => withOutput(32, (out) => wasmExports().el_sha256(pointer, 1, out)))).toString("hex"),
    createHash("sha256").update("a").digest("hex"),
    "the allocator is healthy after a thrown call",
  );
});

test("heap() returns a live view that reflects WASM-side writes", () => {
  const before = heap().length;
  assert.ok(before > 0);
  const written = withInput(new Uint8Array(4), (pointer) => {
    heap().fill(0xee, pointer, pointer + 4);
    return heap().slice(pointer, pointer + 4);
  });
  assert.deepEqual(written, new Uint8Array([0xee, 0xee, 0xee, 0xee]));
});

test("secp_seckey_valid accepts exactly the range 1..n-1", () => {
  const valid = (bytes) => withInput(bytes, (pointer) => wasmExports().secp_seckey_valid(pointer));
  assert.equal(valid(big32(1n)), 1);
  assert.equal(valid(big32(0n)), 0, "zero is not a secret key");
  assert.equal(valid(big32(SECP256K1_ORDER)), 0, "the group order is not a secret key");
  assert.equal(valid(big32(SECP256K1_ORDER - 1n)), 1);
  assert.equal(valid(big32(SECP256K1_ORDER + 1n)), 0);
  assert.equal(valid(new Uint8Array(32).fill(0xff)), 0);
});

test("el_hd_validate classifies private, public, and invalid 78-byte nodes", () => {
  const root = HDKey.fromMasterSeed(new Uint8Array(16).fill(1));
  const xprvBytes = base58checkDecode(root.privateExtendedKey);
  const xpubBytes = base58checkDecode(root.neutered().publicExtendedKey);
  assert.equal(xprvBytes.length, 78);
  assert.equal(withInput(xprvBytes, (pointer) => wasmExports().el_hd_validate(pointer)), 1);
  assert.equal(withInput(xpubBytes, (pointer) => wasmExports().el_hd_validate(pointer)), 2);
  assert.equal(withInput(new Uint8Array(78), (pointer) => wasmExports().el_hd_validate(pointer)), 0);
  const badVersion = Uint8Array.from(xprvBytes);
  badVersion[0] ^= 0xff;
  assert.equal(withInput(badVersion, (pointer) => wasmExports().el_hd_validate(pointer)), 0, "an unknown version is invalid");
});
