// Tests for the BIP32 (src/js/hdkey.js) and BIP39 (src/js/bip39.js) WASM
// facades, both backed by the rust-bitcoin ecosystem crates in
// entropylab-wasm/. Run with `npm test`.
//
// Three layers of assurance:
//  1. The published BIP32 test vectors (bitcoin/bips BIP-0032) and BIP39
//     vectors (trezor/python-mnemonic), independent of any implementation.
//  2. Differential checks against @scure/bip32 and @scure/bip39 (pinned,
//     previously the implementation): the migration must be byte-for-byte
//     behavior preserving.
//  3. A word-for-word agreement proof between the JS wordlist data file and
//     the rust-bip39 crate's English list (single source of truth check).
import { test } from "node:test";
import assert from "node:assert/strict";
import { HDKey as ScureHDKey } from "@scure/bip32";
import * as scureBip39 from "@scure/bip39";
import { wordlist as scureEnglish } from "@scure/bip39/wordlists/english.js";
import { HDKey } from "../src/js/hdkey.js";
import { bip39English, entropyToMnemonic, mnemonicToEntropy, mnemonicToSeedSync, validateMnemonic } from "../src/js/bip39.js";
import { wasmExports } from "../src/js/entropylab-wasm.js";
import { withInput, withOutput } from "../src/js/entropylab-wasm.js";

const hexToBytes = (hex) => new Uint8Array(hex.match(/.{2}/g).map((b) => parseInt(b, 16)));
const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

// BIP32 test vector 1 (https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
test("BIP32 published vector 1: master and m/0'", () => {
  const root = HDKey.fromMasterSeed(hexToBytes("000102030405060708090a0b0c0d0e0f"));
  assert.equal(root.privateExtendedKey, "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi");
  assert.equal(root.publicExtendedKey, "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");
  const child = root.derive("m/0'");
  assert.equal(child.privateExtendedKey, "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7");
  assert.equal(child.publicExtendedKey, "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw");
});

test("BIP32 published vector 2: master and m/0/2147483647'", () => {
  const root = HDKey.fromMasterSeed(hexToBytes("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"));
  assert.equal(root.privateExtendedKey, "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U");
  const child = root.derive("m/0/2147483647'");
  assert.equal(child.publicExtendedKey, "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a");
  assert.equal(child.privateExtendedKey, "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9");
});

test("BIP32 differential: private and public derivation match @scure/bip32", () => {
  for (const seedHex of ["000102030405060708090a0b0c0d0e0f", "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"]) {
    const paths = ["m", "m/0'", "m/0'/1", "m/0'/1/2'", "m/0'/1/2'/2", "m/0'/1/2'/2/1000000000", "m/84'/0'/0'/0/5", "m/83696968'/39'/0'/12'/0'"];
    for (const path of paths) {
      const ours = HDKey.fromMasterSeed(hexToBytes(seedHex)).derive(path);
      const theirs = ScureHDKey.fromMasterSeed(hexToBytes(seedHex)).derive(path);
      assert.equal(ours.privateExtendedKey, theirs.privateExtendedKey, `xprv ${path}`);
      assert.equal(ours.publicExtendedKey, theirs.publicExtendedKey, `xpub ${path}`);
      assert.equal(ours.fingerprint, theirs.fingerprint, `fingerprint ${path}`);
      assert.equal(ours.depth, theirs.depth);
      assert.equal(ours.index, theirs.index);
      assert.equal(ours.parentFingerprint, theirs.parentFingerprint);
      assert.equal(bytesToHex(ours.chainCode), bytesToHex(theirs.chainCode), `chainCode ${path}`);
      assert.equal(bytesToHex(ours.privateKey), bytesToHex(theirs.privateKey), `privateKey ${path}`);
    }
  }
});

test("BIP32 path grammar accepts h, H, and ' as the hardened marker (audit #365)", () => {
  // The UI path parsers accept all three notations and normalize to ' before
  // calling derive; a direct call with h or H must not throw.
  const root = HDKey.fromMasterSeed(hexToBytes("000102030405060708090a0b0c0d0e0f"));
  const prime = root.derive("m/84'/0'/0'");
  for (const path of ["m/84h/0h/0h", "m/84H/0H/0H", "m/84h/0'/0H"]) {
    const node = root.derive(path);
    assert.equal(node.privateExtendedKey, prime.privateExtendedKey, path);
  }
  assert.throws(() => root.derive("m/84p"), /invalid child index/);
});

test("BIP32 watch-only: neutered derivation matches scure on normal paths", () => {
  const oursRoot = HDKey.fromMasterSeed(hexToBytes("000102030405060708090a0b0c0d0e0f"));
  const theirsRoot = ScureHDKey.fromMasterSeed(hexToBytes("000102030405060708090a0b0c0d0e0f"));
  const oursPub = HDKey.fromExtendedKey(oursRoot.derive("m/84'/0'/0'").publicExtendedKey);
  const theirsPub = ScureHDKey.fromExtendedKey(theirsRoot.derive("m/84'/0'/0'").publicExtendedKey);
  for (const path of ["m/0/0", "m/0/17", "m/1/3"]) {
    const ours = oursPub.derive(path);
    const theirs = theirsPub.derive(path);
    assert.equal(ours.publicExtendedKey, theirs.publicExtendedKey, `xpub ${path}`);
    assert.equal(ours.privateKey, null);
  }
  assert.throws(() => oursPub.derive("m/0'"), /hardened/);
  assert.throws(() => theirsPub.derive("m/0'"), /hardened/);
});

test("BIP32 fromExtendedKey round-trips and rejects malformed input", () => {
  const root = HDKey.fromMasterSeed(hexToBytes("000102030405060708090a0b0c0d0e0f"));
  const node = root.derive("m/44'/0'/0'");
  const restored = HDKey.fromExtendedKey(node.privateExtendedKey);
  assert.equal(restored.privateExtendedKey, node.privateExtendedKey);
  assert.equal(restored.depth, 3);
  assert.equal(restored.index, 0x80000000);
  assert.throws(() => HDKey.fromExtendedKey("xpub6blahblah"), /Base58|length/);
  // xpub payload with xprv-version expectation mismatch is rejected
  const xpubAsXprv = node.publicExtendedKey;
  assert.equal(HDKey.fromExtendedKey(xpubAsXprv).privateKey, null);
  assert.throws(() => HDKey.fromExtendedKey(node.privateExtendedKey, { private: 0x0488b21e, public: 0x0488b21e }), /Version mismatch/);
  // scure parity: seed length bounds
  assert.throws(() => HDKey.fromMasterSeed(new Uint8Array(15)), /seed length/);
  assert.throws(() => HDKey.fromMasterSeed(new Uint8Array(65)), /seed length/);
});

test("BIP39 published vectors (trezor/python-mnemonic subset)", () => {
  const vectors = [
    ["00000000000000000000000000000000", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"],
    ["7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "legal winner thank year wave sausage worth useful legal winner thank yellow"],
    ["80808080808080808080808080808080", "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"],
    ["000000000000000000000000000000000000000000000000", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent"],
    ["9e885d952ad362caeb4efe34a8e91bd2", "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic"],
  ];
  for (const [entropyHex, phrase] of vectors) {
    assert.equal(entropyToMnemonic(hexToBytes(entropyHex)), phrase);
    assert.equal(bytesToHex(mnemonicToEntropy(phrase)), entropyHex);
    assert.equal(validateMnemonic(phrase), true);
  }
});

test("BIP39 seed matches the published vector (TREZOR passphrase)", () => {
  const seed = mnemonicToSeedSync("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "TREZOR");
  assert.equal(
    bytesToHex(seed),
    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
  );
});

test("BIP39 differential vs @scure/bip39 (mnemonic, entropy, seed, validate)", () => {
  for (let i = 0; i < 16; i++) {
    const entropy = new Uint8Array(16 + (i % 5) * 4).map((_, j) => (i * 77 + j * 31 + 11) & 0xff);
    const phrase = entropyToMnemonic(entropy);
    assert.equal(phrase, scureBip39.entropyToMnemonic(entropy, scureEnglish), `phrase ${i}`);
    assert.equal(bytesToHex(mnemonicToEntropy(phrase)), bytesToHex(scureBip39.mnemonicToEntropy(phrase, scureEnglish)), `entropy ${i}`);
    assert.equal(validateMnemonic(phrase), scureBip39.validateMnemonic(phrase, scureEnglish));
    const pass = i % 2 ? "päss phrase" : "";
    assert.equal(bytesToHex(mnemonicToSeedSync(phrase, pass)), bytesToHex(scureBip39.mnemonicToSeedSync(phrase, pass)), `seed ${i}`);
  }
  // Invalid phrases agree too
  const bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
  assert.equal(validateMnemonic(bad), scureBip39.validateMnemonic(bad, scureEnglish));
  assert.throws(() => mnemonicToEntropy(bad));
});

// Regression guard for #183: rust-bip39 splits on any run of whitespace,
// where @scure/bip39 split on a single ASCII space. Accepting the loose forms
// would be unsafe rather than lenient — mnemonicToSeedSync hashes the phrase
// as typed, so a phrase validated with a stray space derives a seed no other
// wallet produces.
test("BIP39 rejects non-canonical whitespace exactly as @scure/bip39 did", () => {
  const phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  assert.equal(validateMnemonic(phrase), true);
  const loose = {
    "double space": phrase.replace("abandon abandon", "abandon  abandon"),
    "leading and trailing spaces": `  ${phrase}  `,
    "newline separators": phrase.replace(/ /g, "\n"),
    "tab separators": phrase.replace(/ /g, "\t"),
  };
  for (const [name, value] of Object.entries(loose)) {
    assert.equal(scureBip39.validateMnemonic(value, scureEnglish), false, `${name}: scure baseline`);
    assert.equal(validateMnemonic(value), false, `${name}: accepted a phrase scure rejected`);
    assert.throws(() => mnemonicToEntropy(value), /Invalid mnemonic/, `${name}: entropy`);
  }
});

// The count check alone was not the whole guard: "word\t word" splits into
// twelve pieces on " " (count passes) but rust-bip39's whitespace-run split
// sees twelve clean words and accepts. Every separator shape scure's
// split(" ") tokenization disagrees on must be rejected, and every shape it
// agrees on must keep its outcome — across word counts and positions.
test("BIP39 separator matrix: acceptance matches @scure/bip39 for every word count", () => {
  const words12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  const phrases = {
    12: words12,
    15: entropyToMnemonic(new Uint8Array(20).fill(0)),
    18: entropyToMnemonic(new Uint8Array(24).fill(0)),
    21: entropyToMnemonic(new Uint8Array(28).fill(0)),
    24: entropyToMnemonic(new Uint8Array(32).fill(0)),
  };
  // What rust-bip39 treats as whitespace that could desync the tokenizations.
  // 0xA0 and 0x3000 fold to ASCII space under NFKD, so both implementations
  // accept them; the rest must be rejected by both.
  const separators = {
    "tab": "\t",
    "newline": "\n",
    "carriage return": "\r",
    "CRLF": "\r\n",
    "vertical tab": "\v",
    "form feed": "\f",
    "double space": "  ",
    "tab + space": "\t ",
    "space + tab": " \t",
    "space + newline": " \n",
    "ogham space mark (U+1680)": "\u1680",
    "line separator (U+2028)": "\u2028",
    "paragraph separator (U+2029)": "\u2029",
    "zero-width no-break space (U+FEFF)": "\uFEFF",
    "no-break space (U+00A0, NFKD folds)": "\u00A0",
    "ideographic space (U+3000, NFKD folds)": "\u3000",
  };
  for (const [count, phrase] of Object.entries(phrases)) {
    assert.equal(validateMnemonic(phrase), true, `${count}-word canonical phrase must stay valid`);
    const words = phrase.split(" ");
    for (const [name, sep] of Object.entries(separators)) {
      const variants = {
        "interior": words.slice(0, 2).join(" ") + sep + words.slice(2).join(" "),
        "leading": sep + phrase,
        "trailing": phrase + sep,
      };
      for (const [position, value] of Object.entries(variants)) {
        const label = `${count} words, ${name} at ${position}`;
        const expected = scureBip39.validateMnemonic(value, scureEnglish);
        assert.equal(validateMnemonic(value), expected, `${label}: validateMnemonic disagrees with scure`);
        const entropy = () => mnemonicToEntropy(value);
        const scureEntropy = () => scureBip39.mnemonicToEntropy(value, scureEnglish);
        if (expected) {
          assert.equal(bytesToHex(entropy()), bytesToHex(scureEntropy()), `${label}: entropy disagrees with scure`);
        } else {
          assert.throws(entropy, undefined, `${label}: mnemonicToEntropy accepted a phrase scure rejected`);
          assert.throws(scureEntropy, undefined, `${label}: scure baseline must reject`);
        }
      }
    }
  }
});

// A phrase the loose split accepts hashes to a seed no canonical phrase
// produces, which is the failure this guard exists to prevent. Prove the
// guard rejects every one of them before the crate sees the text.
test("BIP39: no non-canonical separator yields a derivable seed-bearing phrase", () => {
  const words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split(" ");
  const sneak = ["\t ", " \t", " \n", "\v ", "\f ", "\u2028 ", " \u2029"];
  for (const sep of sneak) {
    for (let gap = 1; gap < words.length; gap++) {
      const phrase = words.slice(0, gap).join(" ") + sep + words.slice(gap).join(" ");
      assert.equal(validateMnemonic(phrase), false, `separator ${JSON.stringify(sep)} at gap ${gap} validated`);
      assert.throws(() => mnemonicToEntropy(phrase), /Invalid mnemonic/, `separator ${JSON.stringify(sep)} at gap ${gap} derived entropy`);
    }
  }
  // Off-count phrases agree with scure as well (11/13/14/16/17/23/25 words).
  for (const count of [11, 13, 14, 16, 17, 23, 25]) {
    const phrase = new Array(count).fill("abandon").join(" ");
    assert.equal(validateMnemonic(phrase), scureBip39.validateMnemonic(phrase, scureEnglish), `${count} words`);
    assert.throws(() => mnemonicToEntropy(phrase), undefined, `${count} words`);
  }
});

// Regression guard for #283 ("Wrong keys derived when adding numbers as
// passphrase"): a passphrase of ASCII digits must reach PBKDF2 as the exact
// string typed — no numeric coercion (leading zeros are significant), no
// trimming, no length capping. ColdCard and every other BIP39 signer stretch
// the string as-is, so any transformation here derives a wallet nothing else
// reproduces. The fingerprints are pinned to values an independent
// implementation (@scure/bip39 + @scure/bip32) produces, so the guard holds
// even if the oracle dependency moves.
test("BIP39 numeric passphrases stretch the exact string (#283)", () => {
  const phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  const fingerprintHex = (pass) => (HDKey.fromMasterSeed(mnemonicToSeedSync(phrase, pass)).fingerprint >>> 0).toString(16).padStart(8, "0");
  const cases = [
    ["", "73c5da0a"],
    ["0", "4d9cb38e"],
    ["007", "9f67e695"],
    ["123456", "e9646cf9"],
    ["987654321098765432109876543210", "aa5d8432"],
    ["abc123", "23a41e58"],
    ["hello world", "ec372958"],
  ];
  for (const [pass, expected] of cases) {
    assert.equal(bytesToHex(mnemonicToSeedSync(phrase, pass)), bytesToHex(scureBip39.mnemonicToSeedSync(phrase, pass)), `seed for ${JSON.stringify(pass)} disagrees with scure`);
    assert.equal(fingerprintHex(pass), expected, `master fingerprint for ${JSON.stringify(pass)}`);
  }
  // Numeric coercion would collapse these pairs; exact-string semantics keep
  // every one distinct.
  const distinct = [["007", "7"], ["123456", "123456 "], ["0", "00"], ["000102", "102"]];
  for (const [a, b] of distinct) {
    assert.notEqual(fingerprintHex(a), fingerprintHex(b), `${JSON.stringify(a)} and ${JSON.stringify(b)} must derive different wallets`);
  }
});

test("wordlist agreement: JS data file == rust-bip39 English list, word for word", () => {
  assert.equal(bip39English.length, 2048);
  const wasm = wasmExports();
  const decoder = new TextDecoder();
  for (let i = 0; i < 2048; i++) {
    const word = withOutput(16, (out) => wasm.el_bip39_word_at(i, out, 16));
    assert.equal(decoder.decode(word), bip39English[i], `word ${i}`);
  }
  // scure's copy (previously the app's list) is identical as well
  for (let i = 0; i < 2048; i += 137) assert.equal(scureEnglish[i], bip39English[i], `scure word ${i}`);
});
