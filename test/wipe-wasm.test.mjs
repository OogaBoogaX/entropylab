// Secret buffers must not linger after use: the WASM free functions zero the
// linear-memory buffer they release, secret inputs are gone from linear
// memory once a call returns, and the JS facades wipe the byte buffers they
// are done with. Behavioral checks where the memory is observable, source
// checks (like secret-clear.test.mjs) where it is not.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { wasmExports, heap } from "../src/js/entropylab-wasm.js";
import { secp256k1 } from "../src/js/secp256k1.js";
import { HDKey } from "../src/js/hdkey.js";
import { PSBT_WASM_B64 } from "../src/js/psbt-wasm-b64.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (file) => readFileSync(join(root, file), "utf8");
// Distinctive fixed patterns; nothing here is anyone's key.
const pattern = (size, seed) => new Uint8Array(size).map((_, i) => (i * seed + seed) & 0xff);
const wasmMemoryContains = (bytes) => Buffer.from(heap().buffer).indexOf(Buffer.from(bytes)) !== -1;
const psbtBinary = new Uint8Array(Buffer.from(PSBT_WASM_B64, "base64"));
const psbtWasm = new WebAssembly.Instance(new WebAssembly.Module(psbtBinary), {}).exports;
const psbtHeap = () => new Uint8Array(psbtWasm.memory.buffer);

test("el_free zeroes the linear-memory buffer before deallocating it", () => {
  const wasm = wasmExports();
  const secret = pattern(64, 7);
  const ptr = wasm.el_alloc(secret.length);
  heap().set(secret, ptr);
  wasm.el_free(ptr, secret.length);
  assert.deepEqual([...heap().slice(ptr, ptr + secret.length)], new Array(secret.length).fill(0));
});

test("psbt_free zeroes the linear-memory buffer before deallocating it", () => {
  const secret = pattern(96, 13);
  const ptr = psbtWasm.psbt_alloc(secret.length);
  psbtHeap().set(secret, ptr);
  psbtWasm.psbt_free(ptr, secret.length);
  assert.deepEqual([...psbtHeap().slice(ptr, ptr + secret.length)], new Array(secret.length).fill(0));
});

test("both WASM allocators support exact-size repeated and zero-length lifecycles", () => {
  const allocators = [
    { alloc: wasmExports().el_alloc, free: wasmExports().el_free, memory: heap },
    { alloc: psbtWasm.psbt_alloc, free: psbtWasm.psbt_free, memory: psbtHeap },
  ];
  for (const { alloc, free, memory } of allocators) {
    for (const size of [0, 1, 2, 15, 16, 31, 32, 255, 256, 4096]) {
      for (let cycle = 0; cycle < 8; cycle++) {
        const ptr = alloc(size);
        assert.ok(Number.isInteger(ptr) && ptr >= 0);
        const marker = pattern(size, cycle + 3);
        memory().set(marker, ptr);
        free(ptr, size);
        assert.deepEqual(memory().slice(ptr, ptr + size), new Uint8Array(size));
      }
    }
  }
});

test("a private key is absent from linear memory once public-key derivation returns", () => {
  const priv = pattern(32, 41);
  assert.equal(secp256k1.getPublicKey(priv, true).length, 33);
  assert.equal(wasmMemoryContains(priv), false, "the private key survived in WASM linear memory");
});

test("signing leaves neither the private key nor the extra entropy in linear memory", () => {
  const priv = pattern(32, 17);
  const msg = pattern(32, 5);
  const extra = pattern(32, 29);
  assert.equal(secp256k1.sign(msg, priv, { prehash: false, extraEntropy: extra }).length, 64);
  assert.equal(wasmMemoryContains(priv), false, "the signing key survived in WASM linear memory");
  assert.equal(wasmMemoryContains(extra), false, "the extra entropy survived in WASM linear memory");
});

test("HDKey.wipePrivateData zeroes and drops the internal private key buffer", () => {
  const hd = HDKey.fromMasterSeed(pattern(32, 3));
  const internal = hd._privateKey; // the node owns this exact buffer
  assert.ok(internal instanceof Uint8Array && internal.some((byte) => byte !== 0));
  hd.wipePrivateData();
  assert.equal(hd._privateKey, null);
  assert.equal(hd.privateKey, null);
  assert.ok(internal.every((byte) => byte === 0), "the internal key buffer was not zeroed");
});

test("HDKey.derive wipes the intermediate path nodes but keeps the returned child usable", () => {
  const hd = HDKey.fromMasterSeed(pattern(32, 19));
  const seen = [];
  const original = HDKey.prototype.deriveChild;
  HDKey.prototype.deriveChild = function (index) {
    const child = original.call(this, index);
    seen.push(child);
    return child;
  };
  let leaf;
  try {
    leaf = hd.derive("m/44'/0'/0'/0/5");
  } finally {
    HDKey.prototype.deriveChild = original;
  }
  assert.equal(seen.length, 5);
  for (const node of seen.slice(0, -1)) {
    assert.equal(node._privateKey, null, "an intermediate path node kept its private key");
  }
  assert.equal(leaf, seen.at(-1));
  assert.ok(leaf._privateKey instanceof Uint8Array, "the returned child lost its private key");
  assert.match(leaf.privateExtendedKey, /^xprv/, "the returned child no longer serializes");
  assert.ok(hd._privateKey instanceof Uint8Array, "derive must not wipe the node it was called on");
  hd.wipePrivateData();
  leaf.wipePrivateData();
});

test("the Rust free functions wipe before deallocating (source guard)", () => {
  // The behavioral tests above pin the committed artifact; this pins the
  // source so a future edit cannot quietly drop the wipe.
  assert.match(
    read("entropylab-wasm/src/lib.rs"),
    /fn el_free\(ptr: \*mut u8, len: usize\) \{\s*(?:\/\/[^\n]*\n\s*(?:\/\/[^\n]*\n\s*)*)?wipe\(ptr, len\);/,
  );
  assert.match(
    read("psbt-wasm/src/lib.rs"),
    /fn psbt_free\(ptr: \*mut u8, len: usize\) \{\s*(?:\/\/[^\n]*\n\s*(?:\/\/[^\n]*\n\s*)*)?wipe\(ptr, len\);/,
  );
});

test("the Rust allocators reconstruct the exact boxed-slice layout", () => {
  for (const file of ["entropylab-wasm/src/lib.rs", "psbt-wasm/src/lib.rs"]) {
    const source = read(file);
    assert.match(source, /vec!\[0u8; len\]\.into_boxed_slice\(\)/);
    assert.match(source, /slice_from_raw_parts_mut\(ptr, len\)/);
    assert.doesNotMatch(source, /Vec::<u8>::with_capacity\(len\)/);
    assert.doesNotMatch(source, /Vec::from_raw_parts\(ptr, 0, len\)/);
  }
});

test("the JS facades wipe their secret byte buffers (source guard)", () => {
  const bip39 = read("src/js/bip39.js");
  assert.match(bip39, /phrase\.fill\(0\);\s*salt\.fill\(0\);/, "mnemonicToSeedSync must wipe the encoded phrase and salt");
  assert.equal((bip39.match(/phrase\.fill\(0\)/g) || []).length, 3, "every encoded phrase buffer must be wiped");
  const bip85 = read("src/js/bip85.js");
  assert.match(bip85, /child\.wipePrivateData\(\)/, "deriveBip85Entropy must wipe the derived child node");
  assert.ok((bip85.match(/wipeBytes\(digest\)/g) || []).length >= 4, "every BIP-85 HMAC digest must be wiped");
  const hdkey = read("src/js/hdkey.js");
  assert.match(hdkey, /if \(child !== this\) child\.wipePrivateData\(\);/, "derive must wipe intermediate path nodes");
  assert.match(hdkey, /input\.fill\(0\)/, "deriveChild must wipe the packed parent node");
});

test("app derivation paths wipe seeds, roots, and per-address keys (source guard)", () => {
  const app = read("src/js/app.js");
  const psbtWipe = app.slice(app.indexOf("function hodlPsbtWipeMem()"), app.indexOf("function hodlLoadPsbtKey"));
  assert.match(psbtWipe, /hodlPsbtHd\.wipePrivateData\(\)/, "the PSBT session root must be wiped, not a getter copy");
  const bip85Wipe = app.slice(app.indexOf("function hodlBip85WipeMem()"), app.indexOf("function hodlBip85PrivateValue"));
  assert.match(bip85Wipe, /hodlBip85Root\.wipePrivateData\(\)/, "the BIP-85 root must be wiped, not a getter copy");
  const spWipe = app.slice(app.indexOf("function hodlSpWipeKeys()"), app.indexOf("function hodlSpWipeMem"));
  assert.match(spWipe, /hodlSpHd\.wipePrivateData\(\)/, "the Silent Payments root must be wiped, not a getter copy");
  const bip47Wipe = app.slice(app.indexOf("function hodlBip47WipeResult()"), app.indexOf("function hodlBip47WipeMem"));
  assert.match(bip47Wipe, /hodlBip47Wipe\(hodlBip47Result\.notificationPrivateKey\)/, "the BIP-47 notification private key must be zeroed");
  assert.match(bip47Wipe, /hodlBip47Hd\.wipePrivateData\(\)/, "the BIP-47 session root must be wiped, not a getter copy");
  const bip47 = read("src/js/bip47.js");
  assert.match(bip47, /node\.wipePrivateData\(\)/, "derivePaymentCodeKeys must wipe the payment code node it derived");
  assert.match(bip47, /notificationNode\.wipePrivateData\(\)/, "the notification node must be wiped after its key is copied out");
  assert.match(bip47, /wipeBytes\(childPriv\)/, "each receive child's private getter copy must be wiped");
  assert.match(bip47, /wipeBytes\(privateKey\)/, "the tweaked receive key must be wiped after it is rendered");
  const mnemonicPath = app.slice(app.indexOf("async function hodlMnemonicWalletWithProgress("), app.indexOf("async function hodlEntropyWalletWithProgress("));
  assert.match(mnemonicPath, /seed\.fill\(0\)/, "the BIP39 seed must be wiped after master derivation");
  assert.match(mnemonicPath, /root\.wipePrivateData\(\)/, "the master root node must be wiped after the wallet is built");
  const entropyPath = app.slice(app.indexOf("async function hodlEntropyWalletWithProgress("), app.indexOf("async function hodlImportedWalletWithProgress("));
  assert.match(entropyPath, /entropy\.bytes\.fill\(0\)/, "the entropy bytes must be wiped once the mnemonic exists");
});
