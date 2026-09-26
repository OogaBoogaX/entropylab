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
import { VANITY_WASM_B64 } from "../src/js/vanity-wasm-b64.js";
import { mnemonicToSeedSync } from "../src/js/bip39.js";
import { base58checkEncode } from "../src/js/base58.js";
import { hash160 } from "../src/js/hashes.js";

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
  for (const [file, free] of [
    ["entropylab-wasm/src/lib.rs", "el_free"],
    ["psbt-wasm/src/lib.rs", "psbt_free"],
    ["vanity-wasm/src/lib.rs", "vanity_free"],
  ]) {
    assert.match(
      read(file),
      new RegExp(`fn ${free}\\(ptr: \\*mut u8, len: usize\\) \\{\\s*(?://[^\\n]*\\n\\s*(?://[^\\n]*\\n\\s*)*)?wipe\\(ptr, len\\);`),
      `${file}: ${free} must wipe before deallocating`,
    );
  }
});

test("the Rust allocators reconstruct the exact boxed-slice layout", () => {
  for (const file of ["entropylab-wasm/src/lib.rs", "psbt-wasm/src/lib.rs", "vanity-wasm/src/lib.rs"]) {
    const source = read(file);
    assert.match(source, /vec!\[0u8; len\]\.into_boxed_slice\(\)/);
    assert.match(source, /slice_from_raw_parts_mut\(ptr, len\)/);
    assert.doesNotMatch(source, /Vec::<u8>::with_capacity\(len\)/);
    assert.doesNotMatch(source, /Vec::from_raw_parts\(ptr, 0, len\)/);
  }
});

test("the vanity crate wipes its derivation secrets and the worker its buffers (source guard)", () => {
  const vanity = read("vanity-wasm/src/lib.rs");
  // HMAC pads in HmacSha512::new, the PBKDF2 round value, the master HMAC
  // output, the CKD tweak, intermediate path nodes, and the grind loop's
  // seed, per-candidate node, parent node, and passphrase window.
  assert.ok((vanity.match(/wipe_bytes\(/g) || []).length >= 6, "secret byte strings must be wiped");
  assert.ok((vanity.match(/wipe_node\(/g) || []).length >= 4, "private-key nodes must be wiped");
  const worker = read("src/js/vanity-worker.js");
  assert.match(worker, /function wipeSecrets\(\)/);
  assert.match(worker, /heap\(\)\.fill\(0, keyPtr, keyPtr \+ MAX_KEY\)/);
  assert.match(worker, /heap\(\)\.fill\(0, saltPtr, saltPtr \+ MAX_SALT\)/);
  // Job start, both done paths, and the grind-error path all wipe.
  assert.ok((worker.match(/wipeSecrets\(\);/g) || []).length >= 4, "every job-ending path must wipe");
  assert.match(worker, /heap\(\)\.fill\(0, outPtr/, "the record area is wiped after each drain");
});

// Behavioral counterpart to the source guard above: after a grind, and after
// the same buffer wipes the worker performs when a job ends (key, salt, and
// record areas), nothing secret the grind handled or derived may remain
// anywhere in the vanity module's linear memory, shadow stack included. The
// expected secrets are recomputed with the main module, which has its own
// linear memory, so computing them cannot plant the bytes being searched for.
test("a vanity grind leaves no input or derived secret in its linear memory once the worker wipes", () => {
  const binary = new Uint8Array(Buffer.from(VANITY_WASM_B64, "base64"));
  const vanity = new WebAssembly.Instance(new WebAssembly.Module(binary), {}).exports;
  const vHeap = () => new Uint8Array(vanity.memory.buffer);
  const contains = (bytes) => Buffer.from(vHeap().buffer).indexOf(Buffer.from(bytes)) !== -1;
  const encode = (text) => new TextEncoder().encode(text);
  // Same sizes as the worker (vanity-worker.js).
  const MAX_PREFIX = 116, MAX_SALT = 256, MAX_KEY = 1024, MAX_PATH = 16, OUT_CAP = 12 + 106 * 8192;
  const prefixPtr = vanity.vanity_alloc(MAX_PREFIX);
  const saltPtr = vanity.vanity_alloc(MAX_SALT);
  const keyPtr = vanity.vanity_alloc(MAX_KEY);
  const pathPtr = vanity.vanity_alloc(MAX_PATH * 4);
  const outPtr = vanity.vanity_alloc(OUT_CAP);
  const H = 0x80000000;
  const grind = (mode, key, salt, path, counterSlot, passLen) => {
    vHeap().set(encode("bc1q"), prefixPtr);
    vHeap().set(key, keyPtr);
    vHeap().set(salt, saltPtr);
    const pathView = new DataView(vanity.memory.buffer, pathPtr, MAX_PATH * 4);
    path.forEach((component, i) => pathView.setUint32(i * 4, component >>> 0, true));
    const status = vanity.vanity_grind(mode, keyPtr, key.length, saltPtr, salt.length, pathPtr, path.length,
      counterSlot, prefixPtr, 4, passLen, 0n, 4n, outPtr, OUT_CAP, 2);
    assert.equal(status, 0, `vanity_grind mode ${mode} failed`);
    // Every bc1q address matches the prefix, so each candidate leaves a
    // record; its HASH160 lets the test prove it recomputed the same keys.
    const count = new DataView(vanity.memory.buffer, outPtr, 12).getUint32(8, true);
    const hashes = Array.from({ length: count }, (_, i) =>
      Buffer.from(vHeap().slice(outPtr + 12 + i * 106 + 40, outPtr + 12 + i * 106 + 60)).toString("hex"));
    vHeap().fill(0, keyPtr, keyPtr + MAX_KEY); // wipeSecrets()
    vHeap().fill(0, saltPtr, saltPtr + MAX_SALT);
    vHeap().fill(0, outPtr, outPtr + OUT_CAP); // the post-drain record wipe
    return hashes;
  };
  const hashOf = (hd) => Buffer.from(hash160(hd.publicKey)).toString("hex");

  // Passphrase grind: odometer candidates "aaa".."aad" after the salt.
  const phrase = "legal winner thank year wave sausage worth useful legal winner thank yellow";
  const salt = "residue-scan-salt";
  const passphraseHits = grind(0, encode(phrase), encode(salt), [84 + H, H, H, 0, 0], 0xffffffff, 3);
  assert.equal(passphraseHits.length, 4);
  assert.equal(contains(encode(phrase)), false, "the mnemonic survived");
  assert.equal(contains(encode(salt)), false, "the starting passphrase survived");
  for (const [i, odometer] of ["aaa", "aab", "aac", "aad"].entries()) {
    const seed = mnemonicToSeedSync(phrase, salt + odometer);
    const master = HDKey.fromMasterSeed(seed);
    const account = master.derive("m/84'/0'/0'");
    const leaf = account.derive("m/0/0");
    assert.equal(passphraseHits[i], hashOf(leaf), `candidate ${odometer}: recomputed keys differ from the grind's`);
    for (const [label, bytes] of [
      ["seed", seed.subarray(0, 32)],
      ["master key", master.privateKey],
      ["account key", account.privateKey],
      ["address key", leaf.privateKey],
    ]) {
      assert.equal(contains(bytes), false, `candidate ${odometer}: the ${label} survived`);
    }
    for (const node of [master, account, leaf]) node.wipePrivateData();
  }

  // Derivation grind: counter in slot 0 below a 64-byte node (key ‖ chain code).
  const node = pattern(64, 101);
  const derivationHits = grind(1, node, new Uint8Array(0), [0, 0], 0, 0);
  assert.equal(derivationHits.length, 4);
  assert.equal(contains(node.subarray(0, 32)), false, "the parent private key survived");
  assert.equal(contains(node.subarray(32)), false, "the parent chain code survived");
  const xprv = new Uint8Array(78);
  xprv.set([0x04, 0x88, 0xad, 0xe4]);
  xprv.set(node.subarray(32), 13);
  xprv.set(node.subarray(0, 32), 46);
  const parent = HDKey.fromExtendedKey(base58checkEncode(xprv));
  for (let counter = 0; counter < 4; counter++) {
    const child = parent.deriveChild(counter);
    const leaf = child.deriveChild(0);
    assert.equal(derivationHits[counter], hashOf(leaf), `counter ${counter}: recomputed keys differ from the grind's`);
    assert.equal(contains(child.privateKey), false, `counter ${counter}: the child key survived`);
    assert.equal(contains(child.chainCode), false, `counter ${counter}: the child chain code survived`);
    assert.equal(contains(leaf.privateKey), false, `counter ${counter}: the address key survived`);
    child.wipePrivateData();
    leaf.wipePrivateData();
  }
  parent.wipePrivateData();
});

test("the JS facades wipe their secret byte buffers (source guard)", () => {
  const bip39 = read("src/js/bip39.js");
  assert.match(bip39, /phrase\.fill\(0\);\s*salt\.fill\(0\);/, "mnemonicToSeedSync must wipe the encoded phrase and salt");
  assert.equal((bip39.match(/phrase\.fill\(0\)/g) || []).length, 3, "every encoded phrase buffer must be wiped");
  const bip85 = read("src/js/bip85.js");
  assert.match(bip85, /child\.wipePrivateData\(\)/, "deriveBip85Entropy must wipe the derived child node");
  assert.ok((bip85.match(/wipeBytes\(digest\)/g) || []).length >= 6, "every BIP-85 HMAC digest must be wiped");
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
  const mnemonicPath = app.slice(app.indexOf("async function hodlMnemonicWalletWithProgress("), app.indexOf("async function hodlEntropyWalletWithProgress("));
  assert.match(mnemonicPath, /seed\.fill\(0\)/, "the BIP39 seed must be wiped after master derivation");
  assert.match(mnemonicPath, /root\.wipePrivateData\(\)/, "the master root node must be wiped after the wallet is built");
  const entropyPath = app.slice(app.indexOf("async function hodlEntropyWalletWithProgress("), app.indexOf("async function hodlImportedWalletWithProgress("));
  assert.match(entropyPath, /entropy\.bytes\.fill\(0\)/, "the entropy bytes must be wiped once the mnemonic exists");
});
