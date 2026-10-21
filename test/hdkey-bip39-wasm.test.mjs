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
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { HDKey as ScureHDKey } from "@scure/bip32";
import * as scureBip39 from "@scure/bip39";
import { wordlist as scureEnglish } from "@scure/bip39/wordlists/english.js";
import { HDKey } from "../src/js/hdkey.js";
import { bip39English, entropyToMnemonic, mnemonicToEntropy, mnemonicToSeedSync, validateMnemonic } from "../src/js/bip39.js";
import { wasmExports } from "../src/js/entropylab-wasm.js";
import { withInput, withOutput } from "../src/js/entropylab-wasm.js";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const hexToBytes = (hex) => new Uint8Array(hex.match(/.{2}/g).map((b) => parseInt(b, 16)));
const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

test("failed HD paths wipe intermediate private buffers and preserve the caller root", () => {
  for (const path of ["m/0'/bad", "m/0'/2147483648", "m/0'/1/bad"]) {
    const root = HDKey.fromMasterSeed(hexToBytes("000102030405060708090a0b0c0d0e0f"));
    const rootKey = root.privateKey;
    const nodes = [], buffers = [];
    const original = HDKey.prototype.deriveChild;
    HDKey.prototype.deriveChild = function (index) {
      const node = original.call(this, index);
      nodes.push(node);
      buffers.push(node._privateKey);
      return node;
    };
    try {
      assert.throws(() => root.derive(path), /invalid child index|Invalid index/);
      assert.ok(nodes.length > 0);
      for (const node of nodes) assert.equal(node.hasPrivateKey, false, path);
      for (const buffer of buffers) assert.ok(buffer.every((byte) => byte === 0), path);
      assert.deepEqual(root.privateKey, rootKey);
      // Published BIP32 vector 1 proves a successful child stays usable.
      const child = root.derive("m/0'");
      assert.equal(child.privateExtendedKey, "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7");
      child.wipePrivateData();
    } finally {
      HDKey.prototype.deriveChild = original;
      root.wipePrivateData();
    }
  }
});

test("a child-derivation error wipes the last intermediate and success retains only the returned private node", () => {
  const seed = hexToBytes("000102030405060708090a0b0c0d0e0f");
  const root = HDKey.fromMasterSeed(seed);
  const rootKey = root.privateKey;
  const original = HDKey.prototype.deriveChild;
  const nodes = [], buffers = [];
  const failure = new Error("injected child derivation failure");
  let inject = true;
  HDKey.prototype.deriveChild = function (index) {
    if (inject && this !== root) throw failure;
    const node = original.call(this, index);
    nodes.push(node);
    buffers.push(node._privateKey);
    return node;
  };
  try {
    assert.throws(() => root.derive("m/0'/1"), (error) => error === failure);
    assert.equal(nodes.length, 1);
    assert.equal(nodes[0].hasPrivateKey, false);
    assert.ok(buffers[0].every((byte) => byte === 0));
    assert.deepEqual(root.privateKey, rootKey);
    inject = false;
    const child = root.derive("m/0'/1");
    assert.equal(nodes[1].hasPrivateKey, false);
    assert.ok(buffers[1].every((byte) => byte === 0));
    assert.equal(child.hasPrivateKey, true);
    assert.equal(child.privateExtendedKey, ScureHDKey.fromMasterSeed(seed).derive("m/0'/1").privateExtendedKey);
    child.wipePrivateData();
  } finally {
    HDKey.prototype.deriveChild = original;
    for (const node of nodes) node.wipePrivateData();
    root.wipePrivateData();
    rootKey.fill(0);
  }
});

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

// BIP39 hashes NFKD("mnemonic" + passphrase) as UTF-8. A lone surrogate has
// no UTF-8 encoding; TextEncoder substitutes U+FFFD, so accepting it would
// derive the seed of a different passphrase. The byte path must likewise
// refuse malformed UTF-8 instead of decoding it with replacement characters.
test("BIP39 refuses a passphrase that is not well-formed Unicode or valid UTF-8", () => {
  const phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  for (const passphrase of ["\uD800", "a\uDC00b", "\uD800\uD800", new String("\uD800")]) {
    assert.throws(() => mnemonicToSeedSync(phrase, passphrase), /Invalid passphrase/, JSON.stringify(passphrase));
  }
  // A well-formed surrogate pair is a valid passphrase and derives what
  // @scure/bip39 derives for it.
  assert.deepEqual(mnemonicToSeedSync(phrase, "🔑"), scureBip39.mnemonicToSeedSync(phrase, "🔑"));
  // null is a caller bug: must throw, not silently derive the empty-passphrase wallet.
  assert.throws(() => mnemonicToSeedSync(phrase, null), /Invalid passphrase/);
  // Valid non-ASCII UTF-8 bytes derive what the same text derives in @scure.
  assert.deepEqual(mnemonicToSeedSync(phrase, new TextEncoder().encode("päss phrase")), scureBip39.mnemonicToSeedSync(phrase, "päss phrase"));
  // The coercion matches "mnemonic" + passphrase: a Symbol still throws.
  assert.throws(() => mnemonicToSeedSync(phrase, Symbol("x")), TypeError);
  // Malformed UTF-8 bytes: an encoded surrogate, a truncated sequence, and a
  // stray continuation byte. The vault refuses these at intake; the direct
  // byte path must too.
  for (const bytes of [
    Uint8Array.of(0xed, 0xa0, 0x80),
    Uint8Array.of(0xc3),
    Uint8Array.of(0x80),
  ]) {
    assert.throws(() => mnemonicToSeedSync(phrase, bytes), /Invalid passphrase/, bytes.toString());
  }
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

test("I_L == 0 returns the BIP32 retry verdict, never an invented node (issue #359)", () => {
  // No real vector exists (the case is ~2^-128 per step), so pin the wiring:
  // both CKD steps return the retry code and the JS loop proceeds with the
  // next index, exactly as BIP32 specifies.
  const rust = readFileSync(join(repoRoot, "entropylab-wasm/src/lib.rs"), "utf8");
  assert.match(rust, /I_L == 0: BIP32 says proceed with the next value for i[\s\S]*?break 'ckd 1;/);
  assert.match(rust, /exactly like el_hd_ckd_priv[\s\S]*?return 1;/);
  assert.doesNotMatch(rust, /keep the parent/);
  const js = readFileSync(join(repoRoot, "src/js/hdkey.js"), "utf8");
  assert.match(js, /if \(code === 1\) \{/);
  assert.match(js, /deriveChild\(index \+ 1\)/);
});

// Observe the real facade's temporary byte copies/views without changing their
// contents or replacing its cryptography. Keep references beyond return/throw:
// all must be zero, while returned nodes and caller-owned inputs stay usable.
function observeHdKeyTemporaries(operation) {
  const retained = [], originals = {};
  let result, error;
  for (const name of ["slice", "subarray"]) {
    originals[name] = Uint8Array.prototype[name];
    Uint8Array.prototype[name] = function (...args) {
      const bytes = originals[name].apply(this, args);
      const caller = new Error().stack.split("\n")[2];
      if (caller.includes("/src/js/hdkey.js:")) retained.push(bytes);
      return bytes;
    };
  }
  try { result = operation(); } catch (caught) { error = caught; }
  finally {
    for (const name of Object.keys(originals)) Uint8Array.prototype[name] = originals[name];
  }
  assert.ok(retained.length > 0, "must observe real temporary buffers");
  assert.ok(retained.every(bytes => bytes.every(byte => byte === 0)), "HDKey temporary bytes must be cleared after return or throw");
  return { result, error };
}

const wipeVectorSeed = "000102030405060708090a0b0c0d0e0f";
const wipeVectorXprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

for (const operation of ["master", "import", "private child", "public child"]) {
  test(`HDKey temporary bytes are cleared after ${operation}`, () => {
    const seed = hexToBytes(wipeVectorSeed);
    const root = HDKey.fromMasterSeed(seed);
    const publicRoot = root.neutered();
    const oracle = ScureHDKey.fromMasterSeed(seed);
    const { result, error } = observeHdKeyTemporaries(() => {
      if (operation === "master") return HDKey.fromMasterSeed(seed);
      if (operation === "import") return HDKey.fromExtendedKey(wipeVectorXprv);
      if (operation === "private child") return root.deriveChild(0x80000000);
      return publicRoot.deriveChild(1);
    });
    assert.equal(error, undefined);
    const expected = operation === "private child" ? oracle.deriveChild(0x80000000)
      : operation === "public child" ? oracle.deriveChild(1) : oracle;
    assert.equal(result.publicExtendedKey, expected.publicExtendedKey);
    if (operation !== "public child") assert.equal(result.privateExtendedKey, expected.privateExtendedKey);
    else assert.equal(result.privateKey, null);
    assert.equal(root.privateExtendedKey, wipeVectorXprv, "parent must survive cleanup");
    assert.equal(bytesToHex(seed), wipeVectorSeed, "caller seed must survive cleanup");
  });
}

test("HDKey temporary bytes are cleared after rejecting an import version", () => {
  const { error } = observeHdKeyTemporaries(() => HDKey.fromExtendedKey(wipeVectorXprv, { private: 1, public: 2 }));
  assert.match(error.message, /Version mismatch/);
});

test("HDKey temporary bytes are cleared after rejecting a zero private scalar", async () => {
  const { base58checkDecode, base58checkEncode } = await import("../src/js/base58.js");
  const payload = base58checkDecode(wipeVectorXprv);
  payload.fill(0, 46);
  const invalid = base58checkEncode(payload);
  payload.fill(0);
  const { error } = observeHdKeyTemporaries(() => HDKey.fromExtendedKey(invalid));
  assert.match(error.message, /Invalid private key/);
});

for (const operation of ["master", "child"]) {
  test(`HDKey temporary bytes are cleared if ${operation} construction throws`, async (t) => {
    const { secp256k1 } = await import("../src/js/secp256k1.js");
    const root = HDKey.fromMasterSeed(hexToBytes(wipeVectorSeed));
    const failure = new Error("injected public-key failure");
    t.mock.method(secp256k1, "getPublicKey", () => { throw failure; });
    const { error } = observeHdKeyTemporaries(() => operation === "master"
      ? HDKey.fromMasterSeed(hexToBytes(wipeVectorSeed)) : root.deriveChild(1));
    assert.equal(error, failure);
    assert.equal(root.privateExtendedKey, wipeVectorXprv);
  });
}

// Contract: privateExtendedKey returns the published serialization, and every
// byte buffer hdkey.js allocates to build it (the 33-byte key field and the
// 78-byte body that holds the key and chain code) is zero when it returns.
// observeHdKeyTemporaries sees only slice/subarray copies, so this observes
// `new Uint8Array(n)` made directly by hdkey.js. The constructor is proxied,
// not subclassed, so the buffers stay plain Uint8Arrays and instanceof checks
// elsewhere keep passing. Found by the mutation-testing pilot: deleting either
// fill(0) passed every test that reaches hdkey.js.
function observeHdKeyAllocations(operation) {
  const RealUint8Array = globalThis.Uint8Array, allocated = [];
  const Observed = new Proxy(RealUint8Array, {
    construct(target, args, newTarget) {
      const bytes = Reflect.construct(target, args, newTarget === Observed ? target : newTarget);
      if (new Error().stack.split("\n")[2]?.includes("/src/js/hdkey.js:")) allocated.push(bytes);
      return bytes;
    },
  });
  let result;
  globalThis.Uint8Array = Observed;
  try { result = operation(); } finally { globalThis.Uint8Array = RealUint8Array; }
  return { result, allocated };
}

test("privateExtendedKey clears the key field and the serialization it builds", () => {
  // BIP32 test vector 1: m and m/0H.
  const root = HDKey.fromMasterSeed(hexToBytes(wipeVectorSeed));
  const child = root.deriveChild(0x80000000);
  for (const [node, expected] of [
    [root, wipeVectorXprv],
    [child, "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"],
  ]) {
    const { result, allocated } = observeHdKeyAllocations(() => node.privateExtendedKey);
    assert.equal(result, expected);
    assert.deepEqual(allocated.map((bytes) => bytes.length).sort((a, b) => a - b), [33, 78], "observes the key field and the body");
    for (const bytes of allocated) assert.ok(bytes.every((byte) => byte === 0), `the ${bytes.length}-byte buffer still holds key material`);
    // The node itself is untouched: the getter wipes its own copies only.
    assert.equal(node.privateExtendedKey, expected);
  }
  child.wipePrivateData();
  root.wipePrivateData();
});

// Contract: when a CKD step reports the BIP32 retry verdict (I_L >= n, or a
// child at infinity; WASM code 1), deriveChild proceeds with the next index,
// exactly as BIP32 specifies, and refuses once no next index exists (2^32 - 1
// for a private parent, 2^31 - 1 for a public one). No real vector exists
// (about 2^-128 per step) and the WASM exports are frozen, so the test loads
// a copy of hdkey.js whose only change routes the CKD call through a stub
// that reports the retry verdict at chosen indexes and calls the real WASM
// export otherwise. @scure/bip32 is the oracle for the node that results.
// The #359 test above pins the same wiring by source text; this one runs it.
async function loadHdKeyWithCkdStub() {
  const source = readFileSync(join(repoRoot, "src/js/hdkey.js"), "utf8");
  const call = "wasm()[fn](p, index >>> 0, outPtr)";
  assert.equal(source.split(call).length, 2, "hdkey.js must make exactly one CKD call in this form; update the seam with it");
  const srcUrl = pathToFileURL(join(repoRoot, "src/js/")).href;
  const patched = source
    .replace(call, "globalThis.__hdkeyCkdStub(fn, p, index >>> 0, outPtr)")
    .replace(/from "\.\/([^"]+)"/g, (_, file) => `from "${srcUrl}${file}"`);
  const dir = mkdtempSync(join(tmpdir(), "hdkey-ckd-stub-"));
  try {
    writeFileSync(join(dir, "hdkey.mjs"), patched);
    return (await import(pathToFileURL(join(dir, "hdkey.mjs")).href)).HDKey;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("a BIP32 retry verdict derives the next index, and the last index refuses (issue #359)", async () => {
  const StubbedHDKey = await loadHdKeyWithCkdStub();
  let retryAt = new Set();
  globalThis.__hdkeyCkdStub = (fn, p, index, outPtr) => retryAt.has(index) ? 1 : wasmExports()[fn](p, index, outPtr);
  try {
    const seed = hexToBytes(wipeVectorSeed);
    const root = StubbedHDKey.fromMasterSeed(seed);
    const publicRoot = root.neutered();
    const oracle = ScureHDKey.fromMasterSeed(seed);
    const H = 0x80000000;
    // Control: with no retry verdict the copy derives exactly what scure does.
    assert.equal(root.deriveChild(5).privateExtendedKey, oracle.deriveChild(5).privateExtendedKey);
    // One retry verdict: the next index, for private normal, private hardened
    // and public children.
    retryAt = new Set([5, H + 5]);
    for (const [parent, index, expected] of [
      [root, 5, oracle.deriveChild(6).privateExtendedKey],
      [root, H + 5, oracle.deriveChild(H + 6).privateExtendedKey],
      [publicRoot, 5, oracle.deriveChild(6).publicExtendedKey],
    ]) {
      const child = parent.deriveChild(index);
      assert.equal(child.index, index + 1, `retry at ${index}`);
      assert.equal(parent === publicRoot ? child.publicExtendedKey : child.privateExtendedKey, expected, `retry at ${index}`);
    }
    // Consecutive verdicts keep moving forward.
    retryAt = new Set([5, 6]);
    assert.equal(root.deriveChild(5).privateExtendedKey, oracle.deriveChild(7).privateExtendedKey);
    // The last index has no next one: refuse instead of wrapping or guessing.
    retryAt = new Set([2 ** 32 - 1, H - 1]);
    assert.throws(() => root.deriveChild(2 ** 32 - 1), /cannot retry child derivation at index 4294967295/);
    assert.throws(() => publicRoot.deriveChild(H - 1), /cannot retry child derivation at index 2147483647/);
  } finally {
    delete globalThis.__hdkeyCkdStub;
  }
});
