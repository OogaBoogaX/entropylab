// Tests for src/js/self-test.js, the known-answer self-test app boot runs
// before wiring any input. Four things are proven here:
//   1. The shipped WebAssembly engine passes every vector.
//   2. Every expected value is independent of that engine: each one is
//      recomputed with @scure/bip32, @scure/bip39, @scure/btc-signer and
//      @noble/curves (pinned devDependencies), so a vector cannot have been
//      copied from the output it is meant to check.
//   3. No test can pass vacuously: each fails when its expectation moves, when
//      it throws, and when its expectation is missing or empty; and injected
//      engine faults (a fail-open verifier, a wrong child derivation) are
//      caught by exactly the tests that cover them.
//   4. The boot gate records its outcome and refuses to boot on any failure.
// Named *-wasm so the build-wasm gate also runs it against a fresh crate build.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { HDKey as ScureHDKey } from "@scure/bip32";
import * as scureBip39 from "@scure/bip39";
import { wordlist as scureEnglish } from "@scure/bip39/wordlists/english.js";
import * as btc from "@scure/btc-signer";
import { secp256k1 as nobleSecp } from "@noble/curves/secp256k1.js";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { wasmReady } from "../src/js/entropylab-wasm.js";
import { HDKey } from "../src/js/hdkey.js";
import { secp256k1 } from "../src/js/secp256k1.js";
import { SELF_TESTS, PSBT_SELF_TESTS, PSBT_SELF_TEST_VECTORS, runSelfTests, selfTestGate, LND_MAINNET_NODE_PUBKEY, LND_TESTNET_NODE_PUBKEY, LDK_NODE_PUBKEY, LDK_PLAIN_NODE_PUBKEY } from "../src/js/self-test.js";
import { hex as scureHex } from "@scure/base";

await wasmReady;

const ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ALL_TESTS = [...SELF_TESTS, ...PSBT_SELF_TESTS];
const byName = (name) => {
  const found = ALL_TESTS.find((entry) => entry.name === name);
  assert.ok(found, `self-test "${name}" exists`);
  return found;
};
// Moves an expectation by one character, so the comparison, not the
// computation, is what gets exercised.
const shifted = (value) => value.slice(0, -1) + (value.endsWith("0") ? "1" : "0");

test("every self-test has a unique name and a non-empty expected string", () => {
  assert.ok(SELF_TESTS.length >= 10, `expected the vector barrage, found ${SELF_TESTS.length}`);
  assert.ok(PSBT_SELF_TESTS.length >= 5, `expected the PSBT vectors, found ${PSBT_SELF_TESTS.length}`);
  // Unique across both lists: boot runs them as one list, and the failure
  // screen names them.
  const names = ALL_TESTS.map((entry) => entry.name);
  assert.equal(new Set(names).size, names.length, "self-test names must be unique");
  for (const { name, expected, run } of ALL_TESTS) {
    assert.ok(typeof name === "string" && name.length > 0, "every self-test is named");
    // Names are rendered as markup on the failure screen; keep them inert.
    assert.doesNotMatch(name, /[<>&"']/, `${name}: names must carry no markup characters`);
    assert.ok(typeof expected === "string" && expected.length > 0, `${name}: expected must be a non-empty string`);
    assert.equal(typeof run, "function", `${name}: run must be a function`);
  }
});

test("the shipped WebAssembly engine passes every published vector", () => {
  assert.deepEqual(runSelfTests(), []);
});

test("the shipped PSBT module passes every published vector", () => {
  assert.deepEqual(runSelfTests(PSBT_SELF_TESTS), []);
});

test("every PSBT expected value matches an independent implementation", () => {
  const decode = (hexText) => btc.Transaction.fromPSBT(scureHex.decode(hexText), { allowUnknownInputs: true, allowUnknownOutputs: true });
  const summary = (tx, version) => {
    const inputs = Array.from({ length: tx.inputsLength }, (_, i) => tx.getInput(i));
    const outputs = Array.from({ length: tx.outputsLength }, (_, i) => tx.getOutput(i));
    const total = outputs.reduce((sum, output) => sum + output.amount, 0n);
    return `v${version} in:${inputs.map((input) => `${scureHex.encode(input.txid)}:${input.index}`).join(",")}` +
      ` out:${outputs.map((output) => `${output.amount}:${scureHex.encode(output.script)}`).join(",")} total:${total}`;
  };
  const { BIP174_VALID_2, BIP174_INVALID_2, BIP370_MINIMAL } = PSBT_SELF_TEST_VECTORS;
  assert.equal(byName("PSBT decode (BIP-174)").expected, summary(decode(BIP174_VALID_2), 0));
  assert.equal(byName("PSBT v2 decode (BIP-370)").expected, summary(decode(BIP370_MINIMAL), 2));
  assert.throws(() => decode(BIP174_INVALID_2), "the independent decoder must refuse invalid vector 2 as well");
  assert.equal(byName("PSBT rejects an invalid file (BIP-174)").expected, "valid:accepted invalid:rejected");
  // Rebuild: the published file byte for byte, then the same file with only
  // output 1's amount changed. The independent decoder confirms the edited
  // literal differs from the original in exactly that amount.
  const [unedited, edited] = byName("PSBT rebuild (BIP-174)").expected.match(/^unedited:(\S+) edited:(\S+)$/).slice(1);
  assert.equal(unedited, BIP174_VALID_2);
  assert.equal(BIP174_VALID_2.split("8e24000000000000").length, 2, "the edited amount field must occur exactly once");
  const [before, after] = [decode(unedited), decode(edited)];
  assert.equal(before.getOutput(1).amount, 9358n);
  assert.equal(after.getOutput(1).amount, 9357n);
  assert.equal(summary(after, 0), summary(before, 0).replace("9358:", "9357:").replace("total:199909358", "total:199909357"));
  // BIP-341: a 65-byte Taproot signature ends in one of six defined sighash
  // bytes; 0x00 (SIGHASH_DEFAULT) is only valid as the implicit 64-byte form.
  const defined = ["01", "02", "03", "81", "82", "83"];
  const verdicts = ["01", "00", "ff"].map((byte) => `${byte}:${defined.includes(byte) ? "decoded" : "rejected"}`).join(" ");
  assert.equal(byName("Taproot signature sighash check (BIP-341)").expected, verdicts);
});

test("every expected value matches an independent implementation", () => {
  const expected = (name) => byName(name).expected;
  assert.equal(expected("BIP39 mnemonic encoding"), scureBip39.entropyToMnemonic(hexToBytes("7f".repeat(16)), scureEnglish));
  assert.equal(expected("BIP39 seed (PBKDF2-HMAC-SHA512)"), bytesToHex(scureBip39.mnemonicToSeedSync(ABANDON, "TREZOR")));
  const v1 = ScureHDKey.fromMasterSeed(hexToBytes("000102030405060708090a0b0c0d0e0f"));
  assert.equal(expected("BIP32 private derivation"), v1.derive("m/0'/1/2'/2/1000000000").privateExtendedKey);
  const neutered = ScureHDKey.fromExtendedKey(v1.derive("m/0'/1/2'").publicExtendedKey).derive("m/2/1000000000");
  assert.equal(expected("BIP32 public derivation"), neutered.publicExtendedKey);
  const root = ScureHDKey.fromMasterSeed(scureBip39.mnemonicToSeedSync(ABANDON));
  const pub = (purpose) => root.derive(`m/${purpose}'/0'/0'/0/0`).publicKey;
  assert.equal(expected("P2PKH address (BIP44)"), btc.p2pkh(pub(44)).address);
  assert.equal(expected("P2SH-P2WPKH address (BIP49)"), btc.p2sh(btc.p2wpkh(pub(49))).address);
  assert.equal(expected("P2WPKH address (BIP84)"), btc.p2wpkh(pub(84)).address);
  assert.equal(expected("P2TR address (BIP86)"), btc.p2tr(pub(86).slice(1)).address);
  // The Lightning node-key self-tests pin the published roots the LND/LDK
  // derivations start from and gate the node pubkey against HARDCODED
  // constants, so a systematic engine fault cannot make the tool and a
  // boot-time re-derivation agree on a wrong key. Prove every constant
  // against @scure here — the constants are sourced from the independent
  // implementation, never from the app; the tool's own outputs stay
  // differentials against @scure in test/lightning.test.mjs.
  assert.equal(expected("LND node key (aezeed, mainnet)"), `m/1017'/0'/6'/0/0 ${v1.privateExtendedKey}`);
  assert.equal(expected("LND node key (aezeed, testnet)"), `m/1017'/1'/6'/0/0 ${v1.privateExtendedKey}`);
  assert.equal(expected("LDK node key (ldk-node)"), `m/0' ${root.privateExtendedKey}`);
  const nodePubKeyConstants = {
    LND_MAINNET_NODE_PUBKEY,
    LND_TESTNET_NODE_PUBKEY,
    LDK_NODE_PUBKEY,
    LDK_PLAIN_NODE_PUBKEY,
  };
  const scureNodePubKeys = {
    LND_MAINNET_NODE_PUBKEY: bytesToHex(v1.derive("m/1017'/0'/6'/0/0").publicKey),
    LND_TESTNET_NODE_PUBKEY: bytesToHex(v1.derive("m/1017'/1'/6'/0/0").publicKey),
    LDK_NODE_PUBKEY: bytesToHex(ScureHDKey.fromMasterSeed(root.privateKey).deriveChild(0x80000000).publicKey),
    LDK_PLAIN_NODE_PUBKEY: bytesToHex(root.deriveChild(0x80000000).publicKey),
  };
  const wrongConstants = Object.keys(scureNodePubKeys)
    .filter((name) => nodePubKeyConstants[name] !== scureNodePubKeys[name])
    .map((name) => `${name}="${scureNodePubKeys[name]}"`);
  assert.deepEqual(wrongConstants, [], "hardcoded node-pubkey constants that differ from @scure (paste these): " + wrongConstants.join(" "));
  const one = new Uint8Array(32);
  one[31] = 1;
  const msghash = nobleSha256(utf8ToBytes("Satoshi Nakamoto"));
  const signature = nobleSecp.sign(msghash, one, { prehash: false, extraEntropy: false });
  assert.equal(expected("ECDSA signing (RFC 6979)"), bytesToHex(signature));
  assert.equal(expected("ECDSA verification"), "valid:true tampered:false");
});

test("every self-test fails when its expectation moves", () => {
  for (const entry of ALL_TESTS) {
    assert.deepEqual(runSelfTests([{ ...entry, expected: shifted(entry.expected) }]), [entry.name], `${entry.name} passed a wrong expectation`);
  }
});

test("a throwing, unexpected, or expectation-less test is a failure", () => {
  const run = () => "same";
  assert.deepEqual(runSelfTests([{ name: "throws", expected: "x", run: () => { throw new Error("engine fault"); } }]), ["throws"]);
  assert.deepEqual(runSelfTests([{ name: "missing expectation", run: () => undefined }]), ["missing expectation"]);
  assert.deepEqual(runSelfTests([{ name: "empty expectation", expected: "", run: () => "" }]), ["empty expectation"]);
  assert.deepEqual(runSelfTests([{ name: "non-string", expected: 1, run: () => 1 }]), ["non-string"]);
  // Control: the same shape with a real expectation passes.
  assert.deepEqual(runSelfTests([{ name: "control", expected: "same", run }]), []);
});

test("a fail-open or fail-closed verifier is caught", () => {
  const real = secp256k1.verify;
  try {
    secp256k1.verify = () => true; // accepts forged signatures
    assert.deepEqual(runSelfTests(), ["ECDSA verification"]);
    secp256k1.verify = () => false; // rejects everything
    assert.deepEqual(runSelfTests(), ["ECDSA verification"]);
  } finally {
    secp256k1.verify = real;
  }
  assert.deepEqual(runSelfTests(), [], "restoring the verifier restores a clean run");
});

test("a wrong child derivation is caught by exactly the tests that derive", () => {
  const real = HDKey.prototype.derive;
  try {
    // Off by one on the last path element: the kind of silent miscomputation
    // that produces a valid-looking but wrong key. The LND entries fail too:
    // their tool path walks derive, and the node pubkey is pinned to a
    // hardcoded constant, so the wrong child shows up as a pubkey mismatch.
    // The LDK tool walks deriveChild, which this patch does not touch, so
    // its entry stays green here; its wrong-key coverage is the re-seed and
    // shared-fault injections below.
    HDKey.prototype.derive = function (path) {
      return real.call(this, path.replace(/(\d+)('?)$/, (_, index, hardened) => `${Number(index) + 1}${hardened}`));
    };
    assert.deepEqual(runSelfTests(), [
      "BIP32 private derivation",
      "BIP32 public derivation",
      "P2PKH address (BIP44)",
      "P2SH-P2WPKH address (BIP49)",
      "P2WPKH address (BIP84)",
      "P2TR address (BIP86)",
      "LND node key (aezeed, mainnet)",
      "LND node key (aezeed, testnet)",
    ]);
  } finally {
    HDKey.prototype.derive = real;
  }
  assert.deepEqual(runSelfTests(), [], "restoring derivation restores a clean run");
});

test("a wrong LND node-key child is caught by the Lightning self-tests", () => {
  // The red-team scenario: lightning.js derives a different child while the
  // reported path string stays correct, so only the node pubkey moves. The
  // patch confines the wrong child to the LND paths, and exactly the two
  // LND entries must fail — their node pubkey is pinned to a hardcoded
  // constant the patched engine cannot reach.
  const real = HDKey.prototype.derive;
  try {
    HDKey.prototype.derive = function (path) {
      return real.call(this, path.startsWith("m/1017'/") ? path.replace(/0$/, "1") : path);
    };
    assert.deepEqual(runSelfTests(), ["LND node key (aezeed, mainnet)", "LND node key (aezeed, testnet)"]);
  } finally {
    HDKey.prototype.derive = real;
  }
  assert.deepEqual(runSelfTests(), [], "restoring derivation restores a clean run");
});

test("an engine fault shared by both LND walks is caught by the LND self-tests", () => {
  // The hole the hardcoded constants close: the round-2 gate re-derived its
  // expected pubkey through the same engine, so a fault in a primitive both
  // the tool and the cross-check share — here the 1017' child moved
  // identically in derive and deriveChild — made the tool and the
  // expectation agree on a wrong key. Patch both primitives the same way
  // and exactly the two LND entries must fail against the constants.
  const realDerive = HDKey.prototype.derive;
  const realDeriveChild = HDKey.prototype.deriveChild;
  try {
    HDKey.prototype.derive = function (path) {
      return realDerive.call(this, path.replace("1017'", "1018'"));
    };
    HDKey.prototype.deriveChild = function (index) {
      return realDeriveChild.call(this, index === 1017 + 0x80000000 ? 1018 + 0x80000000 : index);
    };
    assert.deepEqual(runSelfTests(), ["LND node key (aezeed, mainnet)", "LND node key (aezeed, testnet)"]);
  } finally {
    HDKey.prototype.derive = realDerive;
    HDKey.prototype.deriveChild = realDeriveChild;
  }
  assert.deepEqual(runSelfTests(), [], "restoring both primitives restores a clean run");
});

test("a skipped LDK second-stage re-seed is caught by the LDK self-test", () => {
  // The other red-team scenario: KeysManager's re-seed from the master's
  // private key is skipped, so the node key becomes the plain m/0' of the
  // BIP39 seed. Patch fromMasterSeed to re-derive the first stage for the
  // second (32-byte) call — the same wrong key the tool and a boot-time
  // re-derivation would both compute — and the entry's hardcoded constant
  // must still fail the gate.
  const real = HDKey.fromMasterSeed;
  let seed64 = null;
  try {
    HDKey.fromMasterSeed = (seed) => {
      if (seed.length === 64) {
        seed64 = seed;
        return real.call(HDKey, seed);
      }
      if (seed.length === 32 && seed64) return real.call(HDKey, seed64); // the re-seed, skipped
      return real.call(HDKey, seed);
    };
    assert.deepEqual(runSelfTests(), ["LDK node key (ldk-node)"]);
  } finally {
    HDKey.fromMasterSeed = real;
  }
  assert.deepEqual(runSelfTests(), [], "restoring the re-seed restores a clean run");
});

test("an engine fault shared by both LDK walks is caught by the LDK self-test", () => {
  // The LDK side of the same hole: a fault confined to the second-stage
  // re-seed (fromMasterSeed on the 32-byte master key) moves the tool's
  // node key and the round-2 expectation together, to a key that is not
  // the plain m/0' either, so no engine-internal comparison can see it.
  // The hardcoded constant must refuse it.
  const real = HDKey.fromMasterSeed;
  let seed64 = null;
  try {
    HDKey.fromMasterSeed = (seed) => {
      if (seed.length === 64) {
        seed64 = seed;
        return real.call(HDKey, seed);
      }
      if (seed.length === 32 && seed64) {
        const wrong = seed.slice();
        wrong[31] ^= 1; // a wrong, self-consistent second stage
        return real.call(HDKey, wrong);
      }
      return real.call(HDKey, seed);
    };
    assert.deepEqual(runSelfTests(), ["LDK node key (ldk-node)"]);
  } finally {
    HDKey.fromMasterSeed = real;
  }
  assert.deepEqual(runSelfTests(), [], "restoring fromMasterSeed restores a clean run");
});

test("the boot gate records a clean run and lets boot proceed", () => {
  const root = { dataset: {} };
  const reported = [];
  assert.equal(selfTestGate(root, (failed) => reported.push(failed)), true);
  assert.deepEqual(reported, []);
  assert.equal(root.dataset.selfTests, String(SELF_TESTS.length));
  assert.equal(root.dataset.selfTestsFailed, "0");
});

test("the boot gate reports failures and refuses to boot", () => {
  const root = { dataset: {} };
  const reported = [];
  const broken = SELF_TESTS.map((entry, index) => (index === 1 ? { ...entry, expected: shifted(entry.expected) } : entry));
  assert.equal(selfTestGate(root, (failed) => reported.push(failed), broken), false);
  assert.deepEqual(reported, [[SELF_TESTS[1].name]], "onFail receives exactly the failed names, once");
  assert.equal(root.dataset.selfTests, String(SELF_TESTS.length));
  assert.equal(root.dataset.selfTestsFailed, "1");
  // No <html> (a host broken enough to lose it) still refuses to boot.
  assert.equal(selfTestGate(null, () => {}, broken), false);
});

test("the boot gate runs the PSBT vectors alongside the core ones when given both", () => {
  const root = { dataset: {} };
  const reported = [];
  const broken = PSBT_SELF_TESTS.map((entry, index) => (index === 0 ? { ...entry, expected: shifted(entry.expected) } : entry));
  assert.equal(selfTestGate(root, (failed) => reported.push(failed), [...SELF_TESTS, ...broken]), false);
  assert.deepEqual(reported, [[PSBT_SELF_TESTS[0].name]], "a PSBT failure alone must stop boot");
  assert.equal(root.dataset.selfTests, String(ALL_TESTS.length));
  assert.equal(root.dataset.selfTestsFailed, "1");
});

test("the module never talks to the network, browser storage, or a CSPRNG", () => {
  const src = readFileSync(new URL("../src/js/self-test.js", import.meta.url), "utf8");
  assert.doesNotMatch(src, /\bfetch\s*\(/);
  assert.doesNotMatch(src, /\bWebSocket\b/);
  assert.doesNotMatch(src, /\blocalStorage\b/);
  assert.doesNotMatch(src, /\bsessionStorage\b/);
  assert.doesNotMatch(src, /\bindexedDB\b/);
  assert.doesNotMatch(src, /\bgetRandomValues\b/);
  assert.doesNotMatch(src, /\bMath\.random\b/);
});
