// Mutation-testing follow-up for src/js/bip39.js: targeted assertions for
// the surviving mutants of Stryker run 10 (survivors.md, rock 05066472),
// matched by the quoted original lines because #1015 shifted line numbers.
// Every non-equivalent mutant in that list fails at least one test here.
// Expected values come from the published trezor/python-mnemonic BIP39
// vectors, from @scure/bip39 (the pinned previous implementation), or from
// behaviour already pinned by test/hdkey-bip39-wasm.test.mjs — never from
// the code under test.
//
// Truly equivalent mutants from survivors.md (no observable difference, so
// no test is written for them), one line each:
// - bip39.js `if (!out) throw new Error("BIP39 mnemonic encoding failed.")` ConditionalExpression -> false: unreachable without an injected WASM encoding fault.
// - bip39.js `throw new Error("BIP39 mnemonic encoding failed.")` StringLiteral -> "": same unreachable branch.
// - bip39.js `if (passphrase.every((byte) => byte < 0x80))` ConditionalExpression -> false (102:7): the decoded path yields a byte-identical salt for ASCII bytes (NFKD is the identity on ASCII, UTF-8 round-trips).
// - bip39.js `if (passphrase.every((byte) => byte < 0x80))` ConditionalExpression -> false (102:36): the comparison becomes constantly false, i.e. the decoded path, same salt.
// - bip39.js `if (passphrase.every((byte) => byte < 0x80))` ArrowFunction -> () => undefined: every() becomes false, i.e. the decoded path, same salt.
// - bip39.js `if (passphrase.every((byte) => byte < 0x80))` BlockStatement -> {}: the emptied fast path falls through to the decoded path, same salt.
import { test } from "node:test";
import assert from "node:assert/strict";
import * as scureBip39 from "@scure/bip39";
import { wordlist as scureEnglish } from "@scure/bip39/wordlists/english.js";
import { wordlist as spanish } from "@scure/bip39/wordlists/spanish.js";
import { entropyToMnemonic, mnemonicToEntropy, mnemonicToSeedSync, validateMnemonic } from "../src/js/bip39.js";

const hexToBytes = (hex) => new Uint8Array(hex.match(/.{2}/g).map((b) => parseInt(b, 16)));
const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

// trezor/python-mnemonic vector: 16 zero bytes, passphrase "TREZOR".
const VECTOR_ENTROPY = "00000000000000000000000000000000";
const VECTOR_PHRASE = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const VECTOR_SEED_TREZOR = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
// Twelve clean words whose checksum is wrong (pinned by hdkey-bip39-wasm.test.mjs).
const BAD_CHECKSUM = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";

// Observe the secret byte buffers bip39.js creates (every TextEncoder /
// TextDecoder call made from src/js/bip39.js) without touching their
// contents, and keep the references beyond return or throw: the module's
// own copies must be zero, while caller inputs and returned values stay
// usable. Same technique as the HDKey temporary-buffer tests.
function observeBip39Temporaries(operation) {
  const captured = [];
  const originalDecode = TextDecoder.prototype.decode;
  const originalEncode = TextEncoder.prototype.encode;
  TextDecoder.prototype.decode = function (bytes, ...rest) {
    const decoded = originalDecode.call(this, bytes, ...rest);
    if (new Error().stack.split("\n")[2]?.includes("/src/js/bip39.js:")) captured.push(bytes);
    return decoded;
  };
  TextEncoder.prototype.encode = function (text) {
    const encoded = originalEncode.call(this, text);
    if (new Error().stack.split("\n")[2]?.includes("/src/js/bip39.js:")) captured.push(encoded);
    return encoded;
  };
  let result, error;
  try {
    result = operation();
  } catch (caught) {
    error = caught;
  } finally {
    TextDecoder.prototype.decode = originalDecode;
    TextEncoder.prototype.encode = originalEncode;
  }
  return { result, error, captured };
}

const allZero = (bytes) => bytes.every((byte) => byte === 0);
const invalidMnemonic = (err) => err.constructor === Error && err.message === "Invalid mnemonic";

// --- nfkd -----------------------------------------------------------------

test("nfkd: a non-string mnemonic is a TypeError naming the type", () => {
  for (const [bad, type] of [[123, "number"], [null, "object"], [Symbol("x"), "symbol"], [hexToBytes(VECTOR_ENTROPY), "object"]]) {
    assert.throws(
      () => mnemonicToEntropy(bad),
      (err) => err instanceof TypeError && err.message === `invalid mnemonic type: ${type}`,
      `${type}: mnemonicToEntropy`
    );
    assert.equal(validateMnemonic(bad), false, `${type}: validateMnemonic must fail closed`);
  }
});

// --- entropyToMnemonic ----------------------------------------------------

test("entropyToMnemonic: exactly 16/20/24/28/32-byte Uint8Arrays are accepted", () => {
  for (const len of [16, 20, 24, 28, 32]) {
    const entropy = new Uint8Array(len).map((_, i) => (i * 41 + 3) & 0xff);
    assert.equal(entropyToMnemonic(entropy), scureBip39.entropyToMnemonic(entropy, scureEnglish), `${len} bytes`);
  }
  for (const len of [0, 15, 17, 33, 64]) {
    assert.throws(() => entropyToMnemonic(new Uint8Array(len)), RangeError, `${len} bytes: error type`);
    assert.throws(() => entropyToMnemonic(new Uint8Array(len)), /invalid entropy length/, `${len} bytes: message`);
  }
  // A non-Uint8Array whose length is accepted must be refused the same way:
  // the type check must not be short-circuited by the length check.
  for (const notBytes of [[...hexToBytes(VECTOR_ENTROPY)], "0".repeat(16), { length: 16 }]) {
    assert.throws(() => entropyToMnemonic(notBytes), RangeError);
    assert.throws(() => entropyToMnemonic(notBytes), /invalid entropy length/);
  }
});

test("entropyToMnemonic: a non-English wordlist is refused with the exact error", () => {
  assert.throws(() => entropyToMnemonic(hexToBytes(VECTOR_ENTROPY), spanish), Error);
  assert.throws(() => entropyToMnemonic(hexToBytes(VECTOR_ENTROPY), spanish), /Only the BIP39 English wordlist is supported/);
});

test("entropyToMnemonic wipes its decoded copy of the mnemonic", () => {
  const { result, error, captured } = observeBip39Temporaries(() => entropyToMnemonic(hexToBytes(VECTOR_ENTROPY)));
  assert.equal(error, undefined);
  assert.equal(result, VECTOR_PHRASE);
  assert.ok(captured.length >= 1, "must observe the decoded mnemonic buffer");
  assert.ok(captured.every(allZero), "the decoded mnemonic bytes must be cleared after return");
});

// --- mnemonicToEntropy ----------------------------------------------------

test("mnemonicToEntropy: a non-English wordlist is refused with the exact error", () => {
  assert.throws(() => mnemonicToEntropy(VECTOR_PHRASE, spanish), Error);
  assert.throws(() => mnemonicToEntropy(VECTOR_PHRASE, spanish), /Only the BIP39 English wordlist is supported/);
});

test("mnemonicToEntropy: a checksum failure is refused with the exact error", () => {
  assert.equal(validateMnemonic(BAD_CHECKSUM), false);
  assert.equal(validateMnemonic(BAD_CHECKSUM), scureBip39.validateMnemonic(BAD_CHECKSUM, scureEnglish));
  assert.throws(() => mnemonicToEntropy(BAD_CHECKSUM), invalidMnemonic);
});

test("mnemonicToEntropy wipes its encoded copy of the mnemonic", () => {
  const { result, error, captured } = observeBip39Temporaries(() => mnemonicToEntropy(VECTOR_PHRASE));
  assert.equal(error, undefined);
  assert.equal(bytesToHex(result), VECTOR_ENTROPY);
  assert.ok(captured.length >= 1, "must observe the encoded mnemonic buffer");
  assert.ok(captured.every(allZero), "the encoded mnemonic bytes must be cleared after return");
});

// --- phrase form: word counts, whitespace, NFKD ---------------------------

test("word counts 12/15/18/21/24 round-trip; 11/13/25 are refused", () => {
  for (const [entropyLen, words] of [[16, 12], [20, 15], [24, 18], [28, 21], [32, 24]]) {
    const entropy = new Uint8Array(entropyLen).map((_, i) => (i * 41 + 3) & 0xff);
    const phrase = entropyToMnemonic(entropy);
    assert.equal(phrase.split(" ").length, words, `${entropyLen} bytes`);
    assert.equal(phrase, scureBip39.entropyToMnemonic(entropy, scureEnglish));
    assert.equal(validateMnemonic(phrase), true, `${words} words`);
    assert.equal(bytesToHex(mnemonicToEntropy(phrase)), bytesToHex(entropy), `${words} words round-trip`);
  }
  for (const words of [11, 13, 25]) {
    const phrase = new Array(words).fill("abandon").join(" ");
    assert.equal(validateMnemonic(phrase), false, `${words} words`);
    assert.equal(validateMnemonic(phrase), scureBip39.validateMnemonic(phrase, scureEnglish), `${words} words vs @scure`);
    assert.throws(() => mnemonicToEntropy(phrase), /Invalid mnemonic/, `${words} words: entropy`);
    assert.throws(() => mnemonicToSeedSync(phrase), /Invalid mnemonic/, `${words} words: seed`);
  }
});

test("whitespace and NFKD handling matches @scure/bip39", () => {
  // A separator that NFKD folds to a single ASCII space stays valid and
  // derives the canonical entropy and seed.
  const folded = VECTOR_PHRASE.replace(" abandon", "\u3000abandon");
  assert.equal(bytesToHex(mnemonicToEntropy(folded)), VECTOR_ENTROPY);
  assert.equal(bytesToHex(mnemonicToEntropy(folded)), bytesToHex(scureBip39.mnemonicToEntropy(folded, scureEnglish)));
  assert.deepEqual(mnemonicToSeedSync(folded), scureBip39.mnemonicToSeedSync(folded, ""));
  // Everything the single-space tokenization rejects is refused everywhere.
  for (const bad of [
    VECTOR_PHRASE.replace(" abandon", "\tabandon"),
    VECTOR_PHRASE.replace(" abandon", "\nabandon"),
    VECTOR_PHRASE.replace("abandon abandon", "abandon  abandon"),
    ` ${VECTOR_PHRASE}`,
    `${VECTOR_PHRASE} `,
  ]) {
    assert.equal(validateMnemonic(bad), false, JSON.stringify(bad));
    assert.throws(() => mnemonicToEntropy(bad), /Invalid mnemonic/, JSON.stringify(bad));
    assert.throws(() => mnemonicToSeedSync(bad), invalidMnemonic, JSON.stringify(bad));
  }
});

// --- validateMnemonic -----------------------------------------------------

test("validateMnemonic: a non-English wordlist fails closed", () => {
  assert.equal(validateMnemonic(VECTOR_PHRASE), true);
  assert.equal(validateMnemonic(VECTOR_PHRASE, spanish), false);
  assert.equal(validateMnemonic(VECTOR_PHRASE, []), false);
});

test("validateMnemonic: a throwing input returns exactly false", () => {
  for (const bad of [123, null, undefined, Symbol("x")]) {
    assert.equal(validateMnemonic(bad), false, typeof bad);
  }
});

test("validateMnemonic wipes its encoded copy of the mnemonic", () => {
  for (const [phrase, expected] of [[VECTOR_PHRASE, true], [BAD_CHECKSUM, false]]) {
    const { result, error, captured } = observeBip39Temporaries(() => validateMnemonic(phrase));
    assert.equal(error, undefined);
    assert.equal(result, expected);
    assert.ok(captured.length >= 1, "must observe the encoded mnemonic buffer");
    assert.ok(captured.every(allZero), "the encoded mnemonic bytes must be cleared after return");
  }
});

// --- mnemonicToSeedSync / saltFor -----------------------------------------

test("mnemonicToSeedSync: the published TREZOR vector and the empty default passphrase", () => {
  assert.equal(bytesToHex(mnemonicToSeedSync(VECTOR_PHRASE, "TREZOR")), VECTOR_SEED_TREZOR);
  const empty = scureBip39.mnemonicToSeedSync(VECTOR_PHRASE, "");
  assert.deepEqual(mnemonicToSeedSync(VECTOR_PHRASE), empty, "omitted passphrase");
  assert.deepEqual(mnemonicToSeedSync(VECTOR_PHRASE, undefined), empty, "undefined passphrase");
  // null is a caller bug: must throw, not silently derive the empty-passphrase wallet.
  assert.throws(() => mnemonicToSeedSync(VECTOR_PHRASE, null), /Invalid passphrase/);
});

test("mnemonicToSeedSync: a non-string mnemonic is refused before hashing", () => {
  for (const bad of [123, null, {}, [], hexToBytes(VECTOR_ENTROPY)]) {
    assert.throws(() => mnemonicToSeedSync(bad), invalidMnemonic, String(bad));
  }
});

test("mnemonicToSeedSync: a mnemonic with a lone surrogate is refused, not hashed as U+FFFD", { skip: typeof "".isWellFormed !== "function" && "needs String.prototype.isWellFormed (Node >= 20)" }, () => {
  // The isWellFormed guard is what refuses this phrase, so removing that
  // guard makes this test fail: mnemonicToSeedSync does no wordlist or
  // checksum check, and isCanonicalPhrase accepts the phrase (\S matches a
  // lone surrogate and it is twelve single-space-separated tokens), so
  // without the guard TextEncoder would silently hash the surrogate as
  // U+FFFD and return a seed instead of throwing. The guard is not an
  // equivalent mutant.
  const phrase = `${VECTOR_PHRASE.slice(0, -5)}abou\uD800t`;
  assert.equal(phrase.split(" ").length, 12);
  assert.equal(phrase.isWellFormed(), false);
  assert.throws(() => mnemonicToSeedSync(phrase), invalidMnemonic);
});

test("mnemonicToSeedSync: the lone-surrogate refusal does not need the native isWellFormed", () => {
  // Deep sweep of cb18b09 (eight reports across five models): the guard was
  // feature-tested on String.prototype.isWellFormed, so an engine without it
  // hashed the surrogate as U+FFFD. The module's own check runs everywhere.
  const phrase = `${VECTOR_PHRASE.slice(0, -5)}abou\uD800t`;
  const native = Object.getOwnPropertyDescriptor(String.prototype, "isWellFormed");
  if (native) delete String.prototype.isWellFormed;
  try {
    assert.throws(() => mnemonicToSeedSync(phrase), invalidMnemonic);
  } finally {
    if (native) Object.defineProperty(String.prototype, "isWellFormed", native);
  }
});

test("mnemonicToSeedSync: a passphrase with a lone surrogate is refused, not hashed as U+FFFD", () => {
  // saltFor's isWellFormed guard: without it, TextEncoder would silently
  // substitute U+FFFD into the PBKDF2 salt and derive a different wallet.
  assert.throws(() => mnemonicToSeedSync(VECTOR_PHRASE, "abou\uD800t"), /Invalid passphrase/);
});

test("mnemonicToSeedSync: a non-canonical phrase is refused before hashing", () => {
  for (const bad of ["abandon abandon abandon", ` ${VECTOR_PHRASE}`, `${VECTOR_PHRASE}\t`, VECTOR_PHRASE.replace(/ /g, "\n")]) {
    assert.throws(() => mnemonicToSeedSync(bad), invalidMnemonic, JSON.stringify(bad));
  }
});

test("salt: ASCII bytes (fast path) and non-ASCII bytes (decoded path) match the text form", () => {
  const encoder = new TextEncoder();
  assert.equal(bytesToHex(mnemonicToSeedSync(VECTOR_PHRASE, encoder.encode("TREZOR"))), VECTOR_SEED_TREZOR, "ASCII bytes take the fast path");
  assert.deepEqual(mnemonicToSeedSync(VECTOR_PHRASE, encoder.encode("päss phrase")), scureBip39.mnemonicToSeedSync(VECTOR_PHRASE, "päss phrase"), "non-ASCII bytes take the decoded path");
  assert.deepEqual(mnemonicToSeedSync(VECTOR_PHRASE, new Uint8Array(0)), scureBip39.mnemonicToSeedSync(VECTOR_PHRASE, ""), "empty bytes are the empty passphrase");
  // NFKD (BIP39 applies it to the salt): fullwidth letters fold to their
  // ASCII counterparts, so this passphrase is "TREZOR".
  assert.equal(bytesToHex(mnemonicToSeedSync(VECTOR_PHRASE, "ＴＲＥＺＯＲ")), VECTOR_SEED_TREZOR, "NFKD folds the fullwidth passphrase");
});

test("salt: the ASCII boundary is 0x80 and non-ASCII bytes are NFKD-normalized as text", () => {
  // 0x80 is a stray continuation byte (invalid UTF-8): it must be refused by
  // the decoded path, not copied raw into the salt by the fast path.
  assert.throws(() => mnemonicToSeedSync(VECTOR_PHRASE, Uint8Array.of(0x80)), /Invalid passphrase/);
  assert.throws(() => mnemonicToSeedSync(VECTOR_PHRASE, Uint8Array.of(0x41, 0x80)), /Invalid passphrase/);
  // 0x7f is the last ASCII byte and takes the fast path.
  assert.deepEqual(mnemonicToSeedSync(VECTOR_PHRASE, Uint8Array.of(0x7f)), scureBip39.mnemonicToSeedSync(VECTOR_PHRASE, "\x7f"));
  // "é" (U+00E9) NFKD-decomposes to "e" + U+0301: its UTF-8 bytes must be
  // decoded and normalized, not hashed raw.
  assert.deepEqual(mnemonicToSeedSync(VECTOR_PHRASE, Uint8Array.of(0xc3, 0xa9)), scureBip39.mnemonicToSeedSync(VECTOR_PHRASE, "é"));
});

test("mnemonicToSeedSync wipes the encoded phrase and the salt, and the seed is correct", () => {
  const { result, error, captured } = observeBip39Temporaries(() => mnemonicToSeedSync(VECTOR_PHRASE, "päss phrase"));
  assert.equal(error, undefined);
  assert.deepEqual(result, scureBip39.mnemonicToSeedSync(VECTOR_PHRASE, "päss phrase"));
  assert.ok(captured.length >= 2, "must observe the salt and the encoded phrase");
  assert.ok(captured.every(allZero), "the encoded phrase and salt bytes must be cleared after return");
});
