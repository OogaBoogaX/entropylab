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
import { bip39English, entropyToMnemonic, mnemonicToSeedSync, seedFromEntropy, seedFromIndices } from "../src/js/bip39.js";

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
