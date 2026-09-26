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
import { wasmExports, heap, scrubStack, stackRegion, wasmStackTop } from "../src/js/entropylab-wasm.js";
import { secp256k1 } from "../src/js/secp256k1.js";
import { HDKey } from "../src/js/hdkey.js";
import { entropyToMnemonic, mnemonicToEntropy, mnemonicToSeedSync, validateMnemonic } from "../src/js/bip39.js";
import { hmacSha512, pbkdf2Sha512, sha256, sha512 } from "../src/js/hashes.js";
import { base58checkDecode, base58checkEncode } from "../src/js/base58.js";
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

// Rust frames spill their arguments and temporaries into the WASM shadow
// stack, which also lives in linear memory, and popping a frame does not
// erase it. The loader zeroes the stack region once per task after any export
// ran, so these checks let the task settle before scanning.
const settled = () => new Promise((resolve) => setImmediate(resolve));
const stackResidue = [
  ["BIP39 entropy → mnemonic", (s) => entropyToMnemonic(s.entropy), { entropy: pattern(32, 43) }],
  ["BIP39 mnemonic validation", (s) => validateMnemonic(s.phrase), { entropy: pattern(32, 47) }],
  ["BIP39 mnemonic → entropy", (s) => mnemonicToEntropy(s.phrase), { entropy: pattern(32, 53) }],
  ["BIP39 mnemonic → seed", (s) => mnemonicToSeedSync(s.phrase, "stack residue passphrase"), {
    entropy: pattern(16, 59),
    salt: new TextEncoder().encode("mnemonicstack residue passphrase"),
  }],
  ["PBKDF2-HMAC-SHA512", (s) => pbkdf2Sha512(s.password, s.salt, 2), {
    password: pattern(40, 61),
    salt: pattern(24, 67),
  }],
  ["HMAC-SHA512", (s) => hmacSha512(s.key, s.data), { key: pattern(32, 71), data: pattern(37, 73) }],
  ["SHA-256 of a secret", (s) => sha256(s.input), { input: pattern(32, 79) }],
  ["SHA-512 of a secret", (s) => sha512(s.input), { input: pattern(32, 83) }],
  ["Base58Check WIF encode", (s) => base58checkEncode(s.wif), { key: pattern(32, 89) }],
  ["Base58Check WIF decode", (s) => base58checkDecode(s.text), { key: pattern(32, 97) }],
];

for (const [name, run, secrets] of stackResidue) {
  test(`${name} leaves no stack residue in linear memory once the task settles`, async () => {
    const inputs = { ...secrets };
    if (secrets.entropy && name !== "BIP39 entropy → mnemonic") inputs.phrase = entropyToMnemonic(secrets.entropy);
    if (secrets.key) {
      inputs.wif = new Uint8Array([0x80, ...secrets.key, 0x01]);
      inputs.text = base58checkEncode(inputs.wif);
    }
    await settled();
    run(inputs);
    await settled();
    for (const [label, bytes] of Object.entries(secrets)) {
      assert.equal(wasmMemoryContains(bytes), false, `${name}: the ${label} survived in WASM linear memory`);
    }
  });
}

test("scrubStack zeroes the whole stack region at once and the module keeps working", () => {
  const top = wasmStackTop();
  heap().fill(0xa5, 0, top); // no export is running, so the region is dead
  scrubStack();
  assert.ok(heap().subarray(0, top).every((byte) => byte === 0), "stack region not fully zeroed");
  // BIP39 vector 1 (all-zero entropy, passphrase TREZOR).
  const phrase = entropyToMnemonic(new Uint8Array(16));
  assert.equal(
    Buffer.from(mnemonicToSeedSync(phrase, "TREZOR")).toString("hex"),
    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
  );
});

test("the loaded module is stack-first: the region below the stack top holds only the stack", () => {
  const wasm = wasmExports();
  const top = wasmStackTop();
  assert.ok(top > 0 && top % 16 === 0, `implausible stack top ${top}`);
  assert.ok(wasm.__data_end.value >= top, "static data sits below the stack top");
  assert.ok(wasm.__heap_base.value >= top, "the heap starts below the stack top");
});

// Minimal module: memory, one mutable i32 global (the stack pointer) at
// 65536, and one-byte active data segments at `offsets` (several, so a
// mis-skipped segment length would derail the parse).
const layoutModule = (...offsets) => {
  const leb = (n) => { const out = []; for (;;) { const b = n & 0x7f; n >>= 7; if ((n === 0 && !(b & 0x40)) || (n === -1 && (b & 0x40))) { out.push(b); return out; } out.push(b | 0x80); } };
  const section = (id, body) => [id, ...leb(body.length), ...body];
  return new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    ...section(5, [1, 0x00, 2]),
    ...section(6, [1, 0x7f, 0x01, 0x41, ...leb(65536), 0x0b]),
    ...section(11, [offsets.length, ...offsets.flatMap((offset) => [0x00, 0x41, ...leb(offset), 0x0b, 1, 0x2a])]),
  ]);
};

test("stackRegion reads the stack top and refuses a layout with data below it", () => {
  const ok = layoutModule(65536 + 16, 65536 + 300000);
  const bad = layoutModule(65536 + 16, 16);
  assert.ok(WebAssembly.validate(ok) && WebAssembly.validate(bad), "fixture modules must be valid WASM");
  assert.equal(stackRegion(ok), 65536);
  assert.throws(() => stackRegion(bad), /stack-first/);
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
