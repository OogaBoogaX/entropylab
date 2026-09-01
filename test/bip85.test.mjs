// Official BIP-85 test vectors (bitcoin/bips bip-0085.mediawiki) plus the
// English 15/21-word lengths the BIP table allows but does not vector.
import { test } from "node:test";
import assert from "node:assert/strict";
import { HDKey } from "@scure/bip32";
import { validateMnemonic } from "@scure/bip39";
import { wordlist as bip39English } from "@scure/bip39/wordlists/english.js";
import { hex as hexCoder } from "@scure/base";
import {
  BIP85_APPS,
  BIP85_HMAC_KEY,
  BIP85_PURPOSE,
  INDEX_MAX,
  RFC1924_ALPHABET,
  SECP256K1_ORDER,
  assertValidSecp256k1Secret,
  bip85Path,
  deriveApplication,
  deriveBip39,
  deriveBip85Entropy,
  deriveHex,
  derivePwdBase64,
  derivePwdBase85,
  deriveWif,
  deriveXprv,
  encodeRfc1924Base85,
  encodeWifCompressed,
  encodeXprv,
  hardenedPath,
  isValidSecp256k1Secret,
  parseChildIndex,
  truncateEntropy,
  wipeBip85Result,
  wipeBytes
} from "../src/js/bip85.js";

const MASTER = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";
const root = HDKey.fromExtendedKey(MASTER);

test("path builder is fully hardened from purpose 83696968'", () => {
  assert.equal(hardenedPath([BIP85_PURPOSE, 0, 0]), "m/83696968'/0'/0'");
  assert.equal(bip85Path(BIP85_APPS.BIP39, 0, 12, 0), "m/83696968'/39'/0'/12'/0'");
  assert.equal(bip85Path(BIP85_APPS.WIF, 0), "m/83696968'/2'/0'");
  assert.equal(bip85Path(BIP85_APPS.XPRV, 0), "m/83696968'/32'/0'");
  assert.equal(bip85Path(BIP85_APPS.HEX, 64, 0), "m/83696968'/128169'/64'/0'");
  assert.equal(bip85Path(BIP85_APPS.PWD_BASE64, 21, 0), "m/83696968'/707764'/21'/0'");
  assert.equal(bip85Path(BIP85_APPS.PWD_BASE85, 12, 0), "m/83696968'/707785'/12'/0'");
});

test("HMAC-SHA512 test case 1 (m/83696968'/0'/0')", () => {
  let entropy = deriveBip85Entropy(root, "m/83696968'/0'/0'");
  assert.equal(hexCoder.encode(entropy), "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7");
  assert.equal(BIP85_HMAC_KEY, "bip-entropy-from-k");
});

test("HMAC-SHA512 test case 2 (m/83696968'/0'/1')", () => {
  let entropy = deriveBip85Entropy(root, "m/83696968'/0'/1'");
  assert.equal(hexCoder.encode(entropy), "70c6e3e8ebee8dc4c0dbba66076819bb8c09672527c4277ca8729532ad711872218f826919f6b67218adde99018a6df9095ab2b58d803b5b93ec9802085a690e");
});

test("truncateEntropy keeps the leftmost (most significant) bytes", () => {
  let digest = deriveBip85Entropy(root, "m/83696968'/0'/0'");
  assert.equal(hexCoder.encode(truncateEntropy(digest, 16)), "efecfbccffea313214232d29e71563d9");
  assert.equal(hexCoder.encode(truncateEntropy(digest, 32)), "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f0");
  assert.equal(hexCoder.encode(truncateEntropy(digest, 64)), hexCoder.encode(digest));
});

test("BIP39 English 12 words", () => {
  let derived = deriveBip39(root, { words: 12, index: 0 });
  assert.equal(derived.path, "m/83696968'/39'/0'/12'/0'");
  assert.equal(derived.entropyHex, "6250b68daf746d12a24d58b4787a714b");
  assert.equal(derived.secret, "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose");
});

test("BIP39 English 18 words", () => {
  let derived = deriveBip39(root, { words: 18, index: 0 });
  assert.equal(derived.path, "m/83696968'/39'/0'/18'/0'");
  assert.equal(derived.entropyHex, "938033ed8b12698449d4bbca3c853c66b293ea1b1ce9d9dc");
  assert.equal(derived.secret, "near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey outdoor supply token");
});

test("BIP39 English 24 words", () => {
  let derived = deriveBip39(root, { words: 24, index: 0 });
  assert.equal(derived.path, "m/83696968'/39'/0'/24'/0'");
  assert.equal(derived.entropyHex, "ae131e2312cdc61331542efe0d1077bac5ea803adf24b313a4f0e48e9c51f37f");
  assert.equal(derived.secret, "puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano");
});

test("BIP39 English 15 and 21 words are valid checksummed phrases", () => {
  for (const words of [15, 21]) {
    let derived = deriveBip39(root, { words, index: 0 });
    assert.equal(derived.entropy.length, words === 15 ? 20 : 28);
    assert.equal(derived.secret.split(/\s+/).length, words);
    assert.equal(validateMnemonic(derived.secret, bip39English), true, `${words} words`);
    assert.equal(derived.path, `m/83696968'/39'/0'/${words}'/0'`);
  }
});

test("HD-seed WIF (compressed mainnet)", () => {
  let derived = deriveWif(root, { index: 0 });
  assert.equal(derived.path, "m/83696968'/2'/0'");
  assert.equal(derived.entropyHex, "7040bb53104f27367f317558e78a994ada7296c6fde36a364e5baf206e502bb1");
  assert.equal(derived.secret, "Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp");
  assert.equal(encodeWifCompressed(derived.entropy, false), derived.secret);
});

test("XPRV reverses the BIP32 HMAC split and forces depth 0", () => {
  let derived = deriveXprv(root, { index: 0 });
  assert.equal(derived.path, "m/83696968'/32'/0'");
  assert.equal(derived.entropyHex, "ead0b33988a616cf6a497f1c169d9e92562604e38305ccd3fc96f2252c177682");
  assert.equal(derived.secret, "xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX");
  let child = HDKey.fromExtendedKey(derived.secret);
  assert.equal(child.depth, 0);
  assert.equal(child.index, 0);
  assert.equal(child.parentFingerprint, 0);
  assert.equal(hexCoder.encode(child.privateKey), derived.entropyHex);
});

test("HEX 64 bytes keeps the full HMAC (leftmost 64)", () => {
  let derived = deriveHex(root, { numBytes: 64, index: 0 });
  assert.equal(derived.path, "m/83696968'/128169'/64'/0'");
  assert.equal(derived.entropyHex, "492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c");
  assert.equal(derived.secret, derived.entropyHex);
});

test("PWD BASE64 21 characters", () => {
  let derived = derivePwdBase64(root, { length: 21, index: 0 });
  assert.equal(derived.path, "m/83696968'/707764'/21'/0'");
  assert.equal(derived.entropyHex, "74a2e87a9ba0cdd549bdd2f9ea880d554c6c355b08ed25088cfa88f3f1c4f74632b652fd4a8f5fda43074c6f6964a3753b08bb5210c8f5e75c07a4c2a20bf6e9");
  assert.equal(derived.secret, "dKLoepugzdVJvdL56ogNV");
  assert.equal(derived.secret.length, 21);
  assert.doesNotMatch(derived.secret, /=/);
});

test("PWD BASE85 12 characters uses RFC1924", () => {
  assert.equal(RFC1924_ALPHABET.length, 85);
  let derived = derivePwdBase85(root, { length: 12, index: 0 });
  assert.equal(derived.path, "m/83696968'/707785'/12'/0'");
  assert.equal(derived.entropyHex, "f7cfe56f63dca2490f65fcbf9ee63dcd85d18f751b6b5e1c1b8733af6459c904a75e82b4a22efff9b9e69de2144b293aa8714319a054b6cb55826a8e51425209");
  assert.equal(derived.secret, "_s`{TW89)i4`");
  assert.equal(encodeRfc1924Base85(derived.entropy).slice(0, 12), derived.secret);
});

test("deriveApplication dispatches the six v1 apps", () => {
  assert.equal(deriveApplication(root, { app: "bip39", words: 12 }).secret.split(" ").length, 12);
  assert.equal(deriveApplication(root, { app: "wif" }).secret.startsWith("K") || deriveApplication(root, { app: "wif" }).secret.startsWith("L"), true);
  assert.match(deriveApplication(root, { app: "xprv" }).secret, /^xprv/);
  assert.equal(deriveApplication(root, { app: "hex", numBytes: 32 }).secret.length, 64);
  assert.equal(deriveApplication(root, { app: "pwd-base64", length: 21 }).secret.length, 21);
  assert.equal(deriveApplication(root, { app: "pwd-base85", length: 12 }).secret.length, 12);
});

test("invalid secp256k1 secrets hard-fail", () => {
  assert.equal(isValidSecp256k1Secret(new Uint8Array(32)), false);
  let n = new Uint8Array(32);
  for (let i = 0; i < 32; i++) n[i] = Number((SECP256K1_ORDER >> BigInt((31 - i) * 8)) & 0xffn);
  assert.equal(isValidSecp256k1Secret(n), false);
  assert.throws(() => assertValidSecp256k1Secret(n), /increment the index/);
  assert.throws(() => encodeWifCompressed(new Uint8Array(32)), /increment the index/);
  assert.throws(() => encodeXprv(new Uint8Array(32), new Uint8Array(32)), /increment the index/);
});

test("range checks reject values the BIP does not define", () => {
  assert.throws(() => deriveBip39(root, { words: 13 }), /12, 15, 18, 21, or 24/);
  assert.throws(() => deriveBip39(root, { language: 1 }), /English/);
  assert.throws(() => deriveHex(root, { numBytes: 15 }), /16 to 64/);
  assert.throws(() => deriveHex(root, { numBytes: 65 }), /16 to 64/);
  assert.throws(() => derivePwdBase64(root, { length: 19 }), /20 to 86/);
  assert.throws(() => derivePwdBase85(root, { length: 9 }), /10 to 80/);
  assert.throws(() => parseChildIndex(-1), /0 to 2147483647/);
  assert.throws(() => parseChildIndex(INDEX_MAX + 1), /0 to 2147483647/);
  assert.throws(() => deriveApplication(root, { app: "rsa" }), /Unknown BIP-85 application/);
});

test("watch-only roots cannot derive children", () => {
  let watch = HDKey.fromExtendedKey(root.publicExtendedKey);
  assert.equal(watch.privateKey, null);
  assert.throws(() => deriveBip39(watch, { words: 12 }), /private key|Watch-only/);
});

test("wiping a result discards secret bytes", () => {
  let derived = deriveBip39(root, { words: 12, index: 0 });
  let copy = derived.entropy.slice();
  wipeBip85Result(derived);
  assert.equal(derived.secret, "");
  assert.equal(derived.entropyHex, "");
  assert.ok(derived.entropy.every((b) => b === 0));
  assert.notEqual(hexCoder.encode(copy), hexCoder.encode(derived.entropy));
  wipeBytes(copy);
});
