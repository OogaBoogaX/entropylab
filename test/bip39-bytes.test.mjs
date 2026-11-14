// Tests for the byte-based BIP39 seed derivation (seedFromEntropy /
// seedFromIndices in src/js/bip39.js): the BIP39 seed without ever building
// the phrase as a JavaScript string. Run with `npm test`.
//
// Assurance:
//  1. The published BIP39 vector already pinned in
//     test/hdkey-bip39-wasm.test.mjs (trezor/python-mnemonic, "TREZOR").
//  2. Agreement with today's text path, mnemonicToSeedSync(entropyToMnemonic(e), p),
//     for every entropy length and ASCII / non-ASCII passphrases.
//  3. Refusals and buffer wiping, observed as the module's existing tests do.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { bip39English, entropyToMnemonic, mnemonicToSeedSync, seedFromEntropy, seedFromIndices, entropyFromWordIndices } from "../src/js/bip39.js";
import * as scureBip39 from "@scure/bip39";
import { wordlist as scureEnglish } from "@scure/bip39/wordlists/english.js";
import { HDKey as ScureHDKey } from "@scure/bip32";
import { HDKey } from "../src/js/hdkey.js";
import vm from "node:vm";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const hexToBytes = (hex) => new Uint8Array(hex.match(/.{2}/g).map((b) => parseInt(b, 16)));
const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const indicesOf = (phrase) => Uint16Array.from(phrase.split(" "), (word) => bip39English.indexOf(word));

const VECTOR_PHRASE = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const VECTOR_ENTROPY = hexToBytes("00000000000000000000000000000000");
const VECTOR_SEED = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";

test("byte-based seeds reproduce the published BIP39 vector (TREZOR passphrase)", () => {
  assert.equal(bytesToHex(seedFromEntropy(VECTOR_ENTROPY, "TREZOR")), VECTOR_SEED);
  assert.equal(bytesToHex(seedFromIndices(indicesOf(VECTOR_PHRASE), "TREZOR")), VECTOR_SEED);
});

test("byte-based seeds agree with mnemonicToSeedSync for every length and passphrase", () => {
  const passphrases = [
    "",
    "TREZOR",
    "pässwörd", // precomposed
    "pässwörd".normalize("NFD"), // decomposed
    "a\u030A\u0301", // combining marks
    "日本語",
    "🔑",
  ];
  for (let length = 16; length <= 32; length += 4) {
    for (let round = 0; round < 4; round++) {
      const entropy = new Uint8Array(length).map((_, j) => (length * 53 + round * 77 + j * 31 + 11) & 0xff);
      const phrase = entropyToMnemonic(entropy);
      const indices = indicesOf(phrase);
      for (const passphrase of passphrases) {
        const expected = mnemonicToSeedSync(phrase, passphrase);
        assert.deepEqual(seedFromEntropy(entropy, passphrase), expected, `entropy ${length}/${round} ${JSON.stringify(passphrase)}`);
        assert.deepEqual(seedFromIndices(indices, passphrase), expected, `indices ${length}/${round} ${JSON.stringify(passphrase)}`);
      }
    }
  }
});

test("byte-based seeds refuse bad input", () => {
  // Wrong checksum: the all-"abandon" twelve-word phrase is invalid.
  const badChecksum = Uint16Array.from(indicesOf(VECTOR_PHRASE));
  badChecksum[11] = 0; // "about" -> "abandon"
  assert.throws(() => seedFromIndices(badChecksum), /Invalid mnemonic/);
  // Wrong number of indices.
  for (const count of [11, 13, 23]) {
    assert.throws(() => seedFromIndices(new Uint16Array(count)), /Invalid mnemonic/);
  }
  // An index above 2047.
  const tooBig = Uint16Array.from(indicesOf(VECTOR_PHRASE));
  tooBig[3] = 2048;
  assert.throws(() => seedFromIndices(tooBig), /Invalid mnemonic/);
  // Wrong entropy length.
  for (const length of [15, 17, 33]) {
    assert.throws(() => seedFromEntropy(new Uint8Array(length)), /invalid entropy length/);
  }
});

// Observe the buffers bip39.js allocates for a call (the phrase bytes, the
// salt, the indices copy, the checksum) by proxying the Uint8Array
// constructor, as the hdkey tests observe its allocations. After the call
// every one must be zero.
function observeBip39Allocations(operation) {
  // Both typed-array kinds bip39.js allocates directly: the phrase, salt and
  // checksum bytes, and the Uint16Array word-index copies (new or .from()).
  // Frame 3 (under this helper and the trap) is the allocating call site, so
  // buffers hashes.js returns (the seed itself) are not counted.
  const allocated = [], real = { Uint8Array: globalThis.Uint8Array, Uint16Array: globalThis.Uint16Array };
  const fromBip39 = () => new Error().stack.split("\n")[3]?.includes("/src/js/bip39.js:");
  const observe = (Real) => {
    const Observed = new Proxy(Real, {
      construct(target, args, newTarget) {
        const bytes = Reflect.construct(target, args, newTarget === Observed ? target : newTarget);
        if (fromBip39()) allocated.push(bytes);
        return bytes;
      },
      get(target, key) {
        if (key !== "from") return Reflect.get(target, key);
        return function from(...args) {
          const bytes = Real.from(...args);
          if (fromBip39()) allocated.push(bytes);
          return bytes;
        };
      },
    });
    return Observed;
  };
  let result, error;
  globalThis.Uint8Array = observe(real.Uint8Array);
  globalThis.Uint16Array = observe(real.Uint16Array);
  try { result = operation(); } catch (caught) { error = caught; } finally {
    globalThis.Uint8Array = real.Uint8Array;
    globalThis.Uint16Array = real.Uint16Array;
  }
  return { result, error, allocated };
}

test("a passphrase saltFor refuses leaves no word-index copy behind", () => {
  for (const passphrase of [null, "\uD800"]) {
    for (const operation of [
      () => seedFromEntropy(VECTOR_ENTROPY, passphrase),
      () => seedFromIndices(indicesOf(VECTOR_PHRASE), passphrase),
    ]) {
      const { error, allocated } = observeBip39Allocations(operation);
      assert.match(String(error?.message), /Invalid passphrase/);
      assert.ok(allocated.some((buffer) => buffer instanceof globalThis.Uint16Array && buffer.length > 0), "must observe the word-index copy");
      for (const buffer of allocated) {
        assert.ok(buffer.every((value) => value === 0), `a ${buffer.length}-element ${buffer.constructor.name} still holds secret material`);
      }
    }
  }
});

test("byte-based seed derivation zeroes the phrase, salt and index buffers", () => {
  for (const operation of [
    () => seedFromEntropy(VECTOR_ENTROPY, "TREZOR"),
    () => seedFromIndices(indicesOf(VECTOR_PHRASE), "TREZOR"),
  ]) {
    const { result, allocated } = observeBip39Allocations(operation);
    assert.equal(bytesToHex(result), VECTOR_SEED);
    assert.ok(allocated.length > 0, "must observe real buffers");
    for (const bytes of allocated) {
      assert.ok(bytes.every((byte) => byte === 0), `a ${bytes.length}-byte buffer still holds secret material`);
    }
  }
});

test("no call site passes a joined or regenerated phrase string to hodlMnemonicToSeed", () => {
  const source = readFileSync(join(repoRoot, "src/js/app.js"), "utf8");
  assert.doesNotMatch(source, /hodlMnemonicToSeed\(\s*hodlResultMnemonic/);
  assert.doesNotMatch(source, /hodlMnemonicToSeed\(\s*[a-z]+\.words\.join\(/);
  assert.doesNotMatch(source, /let mnemonic = validation\.words\.join\(" "\), seed = hodlMnemonicToSeed/);
});

test("entropyFromWordIndices round-trips with seedFromEntropy's indices and refuses bad input", () => {
  for (let length = 16; length <= 32; length += 4) {
    for (let round = 0; round < 4; round++) {
      const entropy = new Uint8Array(length).map((_, j) => (length * 53 + round * 77 + j * 31 + 11) & 0xff);
      const phrase = entropyToMnemonic(entropy);
      const indices = indicesOf(phrase);
      assert.deepEqual(entropyFromWordIndices(indices), entropy, `entropy ${length}/${round}`);
    }
  }
  // Bad checksum: the all-"abandon" twelve-word phrase is invalid.
  const badChecksum = Uint16Array.from(indicesOf(VECTOR_PHRASE));
  badChecksum[11] = 0; // "about" -> "abandon"
  assert.throws(() => entropyFromWordIndices(badChecksum), /Invalid mnemonic/);
  // Wrong number of indices.
  for (const count of [11, 13, 23]) {
    assert.throws(() => entropyFromWordIndices(new Uint16Array(count)), /Invalid mnemonic/);
  }
  // An index above 2047.
  const tooBig = Uint16Array.from(indicesOf(VECTOR_PHRASE));
  tooBig[3] = 2048;
  assert.throws(() => entropyFromWordIndices(tooBig), /Invalid mnemonic/);
});

test("entropyFromWordIndices zeroes its index copy", () => {
  const { result, allocated } = observeBip39Allocations(() => entropyFromWordIndices(indicesOf(VECTOR_PHRASE)));
  assert.deepEqual(result, VECTOR_ENTROPY);
  assert.ok(allocated.some((buffer) => buffer instanceof globalThis.Uint16Array && buffer.length > 0), "must observe the word-index copy");
  for (const buffer of allocated) {
    if (buffer instanceof globalThis.Uint16Array) {
      assert.ok(buffer.every((value) => value === 0), "the index copy still holds secret material");
    }
  }
});

test("byte-based seeds match @scure/bip39 for every length and passphrase", () => {
  const passphrases = [
    "",
    "TREZOR",
    "pässwörd",
    "pässwörd".normalize("NFD"),
    "a\u030A\u0301",
    "日本語",
    "🔑",
  ];
  for (let length = 16; length <= 32; length += 4) {
    for (let round = 0; round < 4; round++) {
      const entropy = new Uint8Array(length).map((_, j) => (length * 53 + round * 77 + j * 31 + 11) & 0xff);
      const phrase = scureBip39.entropyToMnemonic(entropy, scureEnglish);
      for (const passphrase of passphrases) {
        const expected = scureBip39.mnemonicToSeedSync(phrase, passphrase);
        assert.deepEqual(seedFromEntropy(entropy, passphrase), expected, `entropy ${length}/${round} ${JSON.stringify(passphrase)}`);
      }
    }
  }
});

test("hodlMasterFingerprint derives from { entropy } and { indices } with the real bip39 and hdkey", () => {
  const appSource = readFileSync(join(repoRoot, "src/js/app.js"), "utf8");
  const fnSource = appSource.match(/^function hodlMasterFingerprint\([^]*?^}/m)[0];
  // Record every root the function builds, so the test can see whether the
  // master private key was wiped before the node was dropped.
  const roots = [];
  const context = vm.createContext({
    hodlSeedFromEntropy: seedFromEntropy,
    hodlSeedFromIndices: seedFromIndices,
    hodlHDKey: {
      fromMasterSeed(seed, versions) {
        const root = HDKey.fromMasterSeed(seed, versions);
        roots.push(root);
        return root;
      },
    },
    hodlFingerprintHex: (fingerprint) => fingerprint,
  });
  vm.runInContext(fnSource, context);
  const expected = (passphrase) => {
    const seed = scureBip39.mnemonicToSeedSync(VECTOR_PHRASE, passphrase);
    return ScureHDKey.fromMasterSeed(seed).fingerprint;
  };
  const assertRootsWiped = (label) => {
    assert.ok(roots.length > 0, `must observe the root node for ${label}`);
    for (const root of roots) {
      assert.equal(root.privateKey, null, `the root node for ${label} still holds the master private key`);
    }
    roots.length = 0;
  };
  for (const passphrase of ["", "TREZOR"]) {
    assert.equal(context.hodlMasterFingerprint({ entropy: VECTOR_ENTROPY }, passphrase), expected(passphrase), `entropy ${passphrase}`);
    assertRootsWiped(`entropy ${JSON.stringify(passphrase)}`);
    assert.equal(context.hodlMasterFingerprint({ indices: indicesOf(VECTOR_PHRASE) }, passphrase), expected(passphrase), `indices ${passphrase}`);
    assertRootsWiped(`indices ${JSON.stringify(passphrase)}`);
  }
});

test("hodlRenderMasterFingerprintPreview zeroes the fingerprint source in a finally", () => {
  const appSource = readFileSync(join(repoRoot, "src/js/app.js"), "utf8");
  const fnSource = appSource.match(/^function hodlRenderMasterFingerprintPreview\([^]*?^}/m)[0];
  assert.match(fnSource, /finally\s*\{\s*source\.entropy\?\.fill\(0\);\s*source\.indices\?\.fill\(0\);\s*\}/);
});
