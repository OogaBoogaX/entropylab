// Wallet Recovery Equivalence Verification (issue #171) — tests.
//
// Two layers:
//   1. Shape contract: the {steps, verdict} object shape and the
//      'insufficient' edge cases. These pinned the module before it existed
//      (red-before-green; the file failed at module load until
//      src/js/recovery-equivalence.js landed).
//   2. Concrete fixtures from published BIP-84 / BIP-49 test vectors
//      (mnemonic, root fingerprint, zpub/ypub, receive addresses). Expected
//      values come from the specs, never from running the new code — per
//      the security-sensitive test guidance in AGENTS.md / #452. The
//      SLIP-132 → Core xpub normalization and descriptor checksums in the
//      fixtures are built with the repo's existing, already-pinned helpers
//      (base58check version-word swap; descriptorChecksum()).
//
// Run with `node --test test/recovery-equivalence.test.mjs`.
import { test } from "node:test";
import assert from "node:assert/strict";

import { compareRecoveryArtifacts } from "../src/js/recovery-equivalence.js";
import { descriptorChecksum } from "../src/js/core-importdescriptors.js";
import { base58checkDecode, base58checkEncode } from "../src/js/base58.js";
import { HDKey } from "../src/js/hdkey.js";
import { mnemonicToSeedSync } from "../src/js/bip39.js";
import { addressFor } from "../src/js/addresses.js";

test("returns a non-null object", () => {
  const out = compareRecoveryArtifacts({}, { network: "mainnet", receiveIndex: 0 });
  assert.equal(typeof out, "object");
  assert.ok(out !== null);
});

test("result.steps is an array of { name: string, ok: boolean } objects", () => {
  const out = compareRecoveryArtifacts({}, { network: "mainnet", receiveIndex: 0 });
  assert.ok(Array.isArray(out.steps), "out.steps is an array");
  for (const step of out.steps) {
    assert.equal(typeof step.name, "string", `step.name is a string (got ${typeof step.name})`);
    assert.equal(typeof step.ok, "boolean", `step.ok is a boolean (got ${typeof step.ok})`);
  }
});

test("out.verdict is one of 'consistent' | 'inconsistent' | 'insufficient'", () => {
  const out = compareRecoveryArtifacts({}, { network: "mainnet", receiveIndex: 0 });
  assert.ok(
    ["consistent", "inconsistent", "insufficient"].includes(out.verdict),
    `verdict '${out.verdict}' is not one of: consistent, inconsistent, insufficient`,
  );
});

test("empty artifacts object → 'insufficient' verdict (no throw)", () => {
  assert.doesNotThrow(() => {
    const out = compareRecoveryArtifacts({}, { network: "mainnet", receiveIndex: 0 });
    assert.equal(out.verdict, "insufficient");
  });
});

test("only one artifact (descriptor alone) → 'insufficient' (no throw)", () => {
  assert.doesNotThrow(() => {
    const out = compareRecoveryArtifacts(
      // BIP-32 test vector 1 master xpub + fingerprint; the path does
      // not match this xpub, but the function never reaches parsing
      // for an insufficient artifact count. Well-formed input regardless.
      {
        descriptor: "wpkh([3442193e/84'/0'/0']xpub6CVKsQYXc9awxgV1tWbG4foDvdcnieK2JkbpPEBKB5WwAPkArY1ssordaRffWaMeWiST7SnxYSGPUsnnE9cj8HDRhDzykXuGAJUCC9jVy8h/0/*)#n8a2qkyc",
      },
      { network: "mainnet", receiveIndex: 0 },
    );
    assert.equal(out.verdict, "insufficient");
  });
});

// ---- Concrete fixtures: published BIP-84 / BIP-49 test vectors ----------
//
// Anchors (from the BIP specs, not from running this code):
//   BIP-84 mnemonic : "abandon" x11 + "about" (12 words — the BIP-84/49
//     spec vector; NOT the 24-word "abandon"x23+"art" BIP-39 vector)
//   BIP-84 root fpr : 73c5da0a
//   BIP-84 root fpr : 73c5da0a
//   BIP-84 account 0 zpub (m/84'/0'/0'):
//     zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs
//   BIP-84 receive 0 (m/84'/0'/0'/0/0): bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
//   BIP-84 receive 1 (m/84'/0'/0'/0/1): bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g
//   BIP-49 account 0 ypub (m/49'/0'/0', same mnemonic):
//     ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP

const BIP84_MNEMONIC = "abandon ".repeat(11) + "about";
const BIP84_FPR = "73c5da0a";
const BIP84_ZPUB =
  "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
const BIP84_ADDR0 = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
const BIP84_ADDR1 = "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g";
const BIP49_YPUB =
  "ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP";
// BIP-86 test vector: m/86'/0'/0' xpub of the same mnemonic.
const BIP86_XPUB =
  "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ";

// Fixture construction helpers — existing repo primitives, not the new code:

// SLIP-132 pub → Core xpub is a 4-byte version-word swap on the same
// 78-byte payload. Deterministic and verifiable byte-for-byte.
function slipToCoreXpub(key) {
  const body = base58checkDecode(key);
  try {
    const view = new DataView(body.buffer, body.byteOffset);
    view.setUint32(0, 0x0488b21e, false); // mainnet xpub version word
    return base58checkEncode(body);
  } finally {
    body.fill(0);
  }
}

// Re-version an extended key: same 78-byte payload, new version word.
function toVersion(key, version) {
  const body = base58checkDecode(key);
  try {
    new DataView(body.buffer, body.byteOffset).setUint32(0, version, false);
    return base58checkEncode(body);
  } finally {
    body.fill(0);
  }
}

// Repo-pinned descriptor checksum so fixtures are syntactically valid.
function desc(body) {
  return `${body}#${descriptorChecksum(body)}`;
}

const BIP84_XPUB = slipToCoreXpub(BIP84_ZPUB);
const BIP84_DESC = desc(`wpkh([${BIP84_FPR}/84'/0'/0']${BIP84_XPUB}/0/*)`);
const BIP49_XPUB = slipToCoreXpub(BIP49_YPUB);

// Testnet fixtures: the same mnemonic's BIP-84/49 account keys on testnet,
// derived with the repo's already-pinned HDKey (not the code under test) and
// re-versioned to the SLIP-132 testnet prefixes (vpub/upub).
const TESTNET_VERSIONS = { private: 0x04358394, public: 0x043587cf };
const BIP84_TESTNET_TPUB = HDKey.fromMasterSeed(mnemonicToSeedSync(BIP84_MNEMONIC), TESTNET_VERSIONS)
  .derive("m/84'/1'/0'").neutered().publicExtendedKey;
const BIP84_TESTNET_VPUB = toVersion(BIP84_TESTNET_TPUB, 0x045f1cf6);
const BIP84_TESTNET_DESC = desc(`wpkh([${BIP84_FPR}/84'/1'/0']${BIP84_TESTNET_TPUB}/0/*)`);
const BIP49_TESTNET_TPUB = HDKey.fromMasterSeed(mnemonicToSeedSync(BIP84_MNEMONIC), TESTNET_VERSIONS)
  .derive("m/49'/1'/0'").neutered().publicExtendedKey;
const BIP49_TESTNET_UPUB = toVersion(BIP49_TESTNET_TPUB, 0x044a5262);
const BIP49_TESTNET_DESC = desc(`sh(wpkh([${BIP84_FPR}/49'/1'/0']${BIP49_TESTNET_TPUB}/0/*))`);
const BIP49_AS_ZPUB = toVersion(BIP49_YPUB, 0x04b24746);

// ---- Round 4 fixtures --------------------------------------------------
//
// BIP-39 published vectors for the BIP-84 mnemonic (entropy
// 00000000000000000000000000000000): the seed with no passphrase and the
// seed with passphrase "TREZOR". These anchor the mnemonic-vs-seed and
// passphrase checks independently of the code under test.
const BIP39_SEED_HEX =
  "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
const BIP39_PASSPHRASE = "TREZOR";
const BIP39_PASSPHRASE_SEED_HEX =
  "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}
function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// The same mnemonic with passphrase "TREZOR", at m/84'/0'/0', as a zpub.
const BIP39_PASSPHRASE_ZPUB = toVersion(
  HDKey.fromMasterSeed(hexToBytes(BIP39_PASSPHRASE_SEED_HEX)).derive("m/84'/0'/0'").neutered().publicExtendedKey,
  0x04b24746,
);

// BIP-44 first receive address of the BIP-84 mnemonic, built with the repo's
// already-pinned HDKey/addressFor (not the code under test).
const BIP44_ADDR0 = addressFor(
  "p2pkh",
  HDKey.fromMasterSeed(mnemonicToSeedSync(BIP84_MNEMONIC)).derive("m/44'/0'/0'/0/0").publicKey,
  "mainnet",
);

// Account 1 of the BIP-84 mnemonic (m/84'/0'/1'), and two keys that are not
// account-level: the master (depth 0) and a depth-3 non-hardened child.
const BIP84_ACCOUNT1_XPUB = HDKey.fromMasterSeed(mnemonicToSeedSync(BIP84_MNEMONIC))
  .derive("m/84'/0'/1'").neutered().publicExtendedKey;
const BIP84_MASTER_XPUB = HDKey.fromMasterSeed(mnemonicToSeedSync(BIP84_MNEMONIC)).neutered().publicExtendedKey;
const BIP84_NONHARDENED_XPUB = HDKey.fromMasterSeed(mnemonicToSeedSync(BIP84_MNEMONIC))
  .derive("m/84'/0/0").neutered().publicExtendedKey;

// A different valid BIP-39 mnemonic's seed, for the "another wallet" case.
const OTHER_MNEMONIC = "abandon ".repeat(23) + "art";
const OTHER_SEED_HEX = toHex(mnemonicToSeedSync(OTHER_MNEMONIC));

test("BIP-84 vector: mnemonic + descriptor + first receive address → consistent", () => {
  const out = compareRecoveryArtifacts(
    { mnemonic: BIP84_MNEMONIC, descriptor: BIP84_DESC, address: BIP84_ADDR0 },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "consistent");
  const names = out.steps.map((s) => s.name);
  assert.ok(names.includes("Master fingerprint"), "fingerprint step ran");
  assert.ok(names.includes("Account key"), "account key step ran");
  assert.ok(names.includes("Receive address"), "receive address step ran");
  for (const step of out.steps) {
    assert.equal(step.ok, true, `${step.name}: ${step.detail ?? ""}`);
  }
});

test("BIP-84 vector: mnemonic + descriptor, no address → consistent incl. seed-side receive cross-check", () => {
  const out = compareRecoveryArtifacts(
    { mnemonic: BIP84_MNEMONIC, descriptor: BIP84_DESC },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "consistent");
  const receive = out.steps.find((s) => s.name === "Receive address");
  assert.ok(receive && receive.ok === true, "seed-side receive cross-check ran and matched");
});

test("BIP-84 vector: descriptor origin fingerprint divergence → inconsistent at Master fingerprint", () => {
  const bad = desc(`wpkh([deadbeef/84'/0'/0']${BIP84_XPUB}/0/*)`);
  const out = compareRecoveryArtifacts(
    { mnemonic: BIP84_MNEMONIC, descriptor: bad },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "inconsistent");
  assert.equal(out.mismatchAt, "Master fingerprint");
});

test("BIP-84 vector: second receive address compared at index 0 → inconsistent at Receive address", () => {
  const out = compareRecoveryArtifacts(
    { descriptor: BIP84_DESC, address: BIP84_ADDR1 },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "inconsistent");
  assert.equal(out.mismatchAt, "Receive address");
});

test("BIP-84 mnemonic + BIP-49 ypub + wpkh descriptor of the same key → inconsistent at Script type", () => {
  // The BIP-49 ypub and this descriptor carry the *same key bytes* — the
  // Account key comparison must pass. What diverges is the script-type
  // claim: ypub implies p2sh-p2wpkh (BIP-49), the descriptor says wpkh.
  // This is exactly the "imported a ypub as wpkh()" failure mode the
  // issue body calls out.
  const ypubAsWpkh = desc(`wpkh([${BIP84_FPR}/49'/0'/0']${BIP49_XPUB}/0/*)`);
  const out = compareRecoveryArtifacts(
    { mnemonic: BIP84_MNEMONIC, slip132: BIP49_YPUB, descriptor: ypubAsWpkh },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "inconsistent");
  assert.equal(out.mismatchAt, "Script type");
  const acct = out.steps.find((s) => s.name === "Account key");
  assert.ok(acct && acct.ok === true, "same key bytes should still match on Account key");
});

test("BIP-84 zpub + matching wpkh descriptor → consistent (SLIP-132 normalized to Core xpub)", () => {
  const out = compareRecoveryArtifacts(
    { slip132: BIP84_ZPUB, descriptor: BIP84_DESC },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "consistent");
  const names = out.steps.map((s) => s.name);
  assert.ok(names.includes("Account key"));
  assert.ok(names.includes("Script type"));
});

// ---- Testnet version words (RE-1) --------------------------------------

test("testnet vpub + matching testnet descriptor → consistent", () => {
  const out = compareRecoveryArtifacts(
    { slip132: BIP84_TESTNET_VPUB, descriptor: BIP84_TESTNET_DESC },
    { network: "testnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "consistent");
  const names = out.steps.map((s) => s.name);
  assert.ok(names.includes("Account key"));
  assert.ok(names.includes("Script type"));
});

test("testnet upub + matching sh(wpkh) testnet descriptor → consistent", () => {
  const out = compareRecoveryArtifacts(
    { slip132: BIP49_TESTNET_UPUB, descriptor: BIP49_TESTNET_DESC },
    { network: "testnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "consistent");
  const names = out.steps.map((s) => s.name);
  assert.ok(names.includes("Account key"));
  assert.ok(names.includes("Script type"));
});

test("testnet tpub + mainnet descriptor → inconsistent at Network", () => {
  const out = compareRecoveryArtifacts(
    { xpub: BIP84_TESTNET_TPUB, descriptor: BIP84_DESC },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "inconsistent");
  assert.equal(out.mismatchAt, "Network");
});

// ---- Account-level origin (RE-2) ---------------------------------------

test("descriptor origin that is not an account path → inconsistent at Support", () => {
  const bad = desc(`wpkh([${BIP84_FPR}/84'/0'/0'/0]${BIP84_XPUB}/0/*)`);
  const out = compareRecoveryArtifacts(
    { mnemonic: BIP84_MNEMONIC, descriptor: bad },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "inconsistent");
  assert.equal(out.mismatchAt, "Support");
});

// ---- Descriptor key path (RE-2) ----------------------------------------

test("change-branch descriptor (/1/*) of the same wallet → consistent", () => {
  const changeDesc = desc(`wpkh([${BIP84_FPR}/84'/0'/0']${BIP84_XPUB}/1/*)`);
  const out = compareRecoveryArtifacts(
    { mnemonic: BIP84_MNEMONIC, descriptor: changeDesc },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "consistent");
  const receive = out.steps.find((s) => s.name === "Receive address");
  assert.ok(receive && receive.ok === true, "seed-side change-branch cross-check ran and matched");
});

test("descriptor key path /0/5/* → inconsistent at Support", () => {
  const bad = desc(`wpkh([${BIP84_FPR}/84'/0'/0']${BIP84_XPUB}/0/5/*)`);
  const out = compareRecoveryArtifacts(
    { mnemonic: BIP84_MNEMONIC, descriptor: bad },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "inconsistent");
  assert.equal(out.mismatchAt, "Support");
  const support = out.steps.find((s) => s.name === "Support" && !s.ok);
  assert.ok(support, "a Support failure is reported");
  assert.ok(support.detail.includes("key path"), `Support detail names the key path: ${support.detail}`);
});

// ---- Taproot scope (RE-3) ----------------------------------------------

test("tr() with a script tree → inconsistent at Support", () => {
  const body = `tr([${BIP84_FPR}/86'/0'/0']${BIP86_XPUB}/0/*,{pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)})`;
  const out = compareRecoveryArtifacts(
    { mnemonic: BIP84_MNEMONIC, descriptor: desc(body) },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "inconsistent");
  assert.equal(out.mismatchAt, "Support");
  const support = out.steps.find((s) => s.name === "Support" && !s.ok);
  assert.ok(support, "a Support failure is reported");
  assert.ok(support.detail.includes("script tree"), `Support detail names the script tree: ${support.detail}`);
});

// ---- No descriptor, no guessed path (RE-4) -----------------------------

test("BIP-49 ypub of the seed (no descriptor) → consistent at Account key", () => {
  const out = compareRecoveryArtifacts(
    { mnemonic: BIP84_MNEMONIC, slip132: BIP49_YPUB },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "consistent");
  const acct = out.steps.find((s) => s.name === "Account key");
  assert.ok(acct && acct.ok === true);
});

test("BIP-86 xpub of the seed (no descriptor) → consistent at Account key", () => {
  const out = compareRecoveryArtifacts(
    { mnemonic: BIP84_MNEMONIC, xpub: BIP86_XPUB },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "consistent");
  const acct = out.steps.find((s) => s.name === "Account key");
  assert.ok(acct && acct.ok === true);
});

// ---- Checksum wording (RE-5) -------------------------------------------

test("descriptor without a checksum is accepted and flagged checksum: 'absent'", () => {
  const noChecksum = `wpkh([${BIP84_FPR}/84'/0'/0']${BIP84_XPUB}/0/*)`;
  const out = compareRecoveryArtifacts(
    { mnemonic: BIP84_MNEMONIC, descriptor: noChecksum },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "consistent");
  assert.equal(out.checksum, "absent");
});

// ---- Fail closed on a failed check (RE-3) ------------------------------

test("descriptor with a bad checksum → inconsistent at Support, never consistent", () => {
  const bad = BIP84_DESC.slice(0, BIP84_DESC.lastIndexOf("#")) + "#deadbeef";
  const out = compareRecoveryArtifacts(
    { mnemonic: BIP84_MNEMONIC, descriptor: bad },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "inconsistent");
  assert.equal(out.mismatchAt, "Support");
});

// ---- Key argument and checksum (RE-4, RE-5) ----------------------------

test("descriptor with more than one extended key → inconsistent at Support", () => {
  const body = `wpkh([${BIP84_FPR}/84'/0'/0']${BIP84_XPUB}/0/*,${BIP49_XPUB}/0/*)`;
  const out = compareRecoveryArtifacts(
    { mnemonic: BIP84_MNEMONIC, descriptor: desc(body) },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "inconsistent");
  assert.equal(out.mismatchAt, "Support");
});

test("descriptor whose key is not an extended public key → inconsistent at Support", () => {
  const body = "wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
  const out = compareRecoveryArtifacts(
    { mnemonic: BIP84_MNEMONIC, descriptor: desc(body) },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "inconsistent");
  assert.equal(out.mismatchAt, "Support");
});

// ---- Every supplied key is compared (item 5) ---------------------------

test("xpub + a different SLIP-132 key + descriptor → inconsistent at Account key", () => {
  const out = compareRecoveryArtifacts(
    { xpub: BIP84_XPUB, slip132: BIP49_AS_ZPUB, descriptor: BIP84_DESC },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "inconsistent");
  assert.equal(out.mismatchAt, "Account key");
});

test("mnemonic + matching xpub + matching SLIP-132 key + descriptor → consistent", () => {
  const out = compareRecoveryArtifacts(
    { mnemonic: BIP84_MNEMONIC, xpub: BIP84_XPUB, slip132: BIP84_ZPUB, descriptor: BIP84_DESC },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "consistent");
});

test("mnemonic + matching SLIP-132 key (no descriptor) → consistent at Account key", () => {
  const out = compareRecoveryArtifacts(
    { mnemonic: BIP84_MNEMONIC, slip132: BIP84_ZPUB },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "consistent");
  const acct = out.steps.find((s) => s.name === "Account key");
  assert.ok(acct && acct.ok === true);
});

test("xpub + matching SLIP-132 key (no descriptor) → consistent at Account key", () => {
  const out = compareRecoveryArtifacts(
    { xpub: BIP84_XPUB, slip132: BIP84_ZPUB },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "consistent");
  const acct = out.steps.find((s) => s.name === "Account key");
  assert.ok(acct && acct.ok === true);
});

// ---- Never throw (item 6) ----------------------------------------------

test("malformed artifacts never throw; each becomes a named Support failure", () => {
  const cases = [
    { seed: "abcd", xpub: BIP84_XPUB },
    { xpub: "xpub!!!not-base58!!!", address: BIP84_ADDR0 },
    { mnemonic: BIP84_MNEMONIC, descriptor: desc(`wpkh([${BIP84_FPR}/2147483648'/0'/0']${BIP84_XPUB}/0/*)`) },
  ];
  for (const artifacts of cases) {
    assert.doesNotThrow(() => {
      const out = compareRecoveryArtifacts(artifacts, { network: "mainnet", receiveIndex: 0 });
      assert.equal(out.verdict, "inconsistent");
      assert.equal(out.mismatchAt, "Support");
    });
  }
});

// ---- Address without a descriptor (R3-1) -------------------------------

test("mnemonic + first receive address, no descriptor → consistent at Receive address", () => {
  const out = compareRecoveryArtifacts(
    { mnemonic: BIP84_MNEMONIC, address: BIP84_ADDR0 },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "consistent");
  const receive = out.steps.find((s) => s.name === "Receive address");
  assert.ok(receive && receive.ok === true, "address was checked against derived candidates");
});

test("xpub + first receive address, no descriptor → consistent at Receive address", () => {
  const out = compareRecoveryArtifacts(
    { xpub: BIP84_XPUB, address: BIP84_ADDR0 },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "consistent");
  const receive = out.steps.find((s) => s.name === "Receive address");
  assert.ok(receive && receive.ok === true);
});

test("SLIP-132 zpub + first receive address, no descriptor → consistent at Receive address", () => {
  const out = compareRecoveryArtifacts(
    { slip132: BIP84_ZPUB, address: BIP84_ADDR0 },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "consistent");
  const receive = out.steps.find((s) => s.name === "Receive address");
  assert.ok(receive && receive.ok === true);
});

test("BIP-49 ypub + first receive address, no descriptor → consistent at Receive address", () => {
  // BIP-49 spec vector: m/49'/0'/0'/0/0 of the same mnemonic.
  const out = compareRecoveryArtifacts(
    { slip132: BIP49_YPUB, address: "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf" },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "consistent");
  const receive = out.steps.find((s) => s.name === "Receive address");
  assert.ok(receive && receive.ok === true);
});

test("mnemonic + an address from another wallet, no descriptor → inconsistent at Receive address", () => {
  // BIP-173 test-vector P2WPKH address (witness program of the generator
  // point), not derived from the BIP-84 mnemonic.
  const out = compareRecoveryArtifacts(
    { mnemonic: BIP84_MNEMONIC, address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4" },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "inconsistent");
  assert.equal(out.mismatchAt, "Receive address");
  const receive = out.steps.find((s) => s.name === "Receive address" && !s.ok);
  assert.ok(receive, "a Receive address failure is reported");
  assert.ok(receive.detail.includes("not among the first 20"), `detail names the scan: ${receive.detail}`);
});

test("address alone (nothing to derive from) → insufficient", () => {
  const out = compareRecoveryArtifacts(
    { address: BIP84_ADDR0 },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "insufficient");
});

// ---- SLIP-132 prefix wins over field name (R3-2) -----------------------

test("SLIP-132 prefix in the xpub field keeps its script-type claim → inconsistent at Script type", () => {
  const ypubAsWpkh = desc(`wpkh([${BIP84_FPR}/49'/0'/0']${BIP49_XPUB}/0/*)`);
  const out = compareRecoveryArtifacts(
    { xpub: BIP49_YPUB, descriptor: ypubAsWpkh },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "inconsistent");
  assert.equal(out.mismatchAt, "Script type");
});

// ---- bech32 case-insensitivity (R3-3) ----------------------------------

test("bech32 address compares case-insensitively → consistent", () => {
  const out = compareRecoveryArtifacts(
    { descriptor: BIP84_DESC, address: BIP84_ADDR0.toUpperCase() },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "consistent");
  const receive = out.steps.find((s) => s.name === "Receive address");
  assert.ok(receive && receive.ok === true);
});

test("mixed-case bech32 address is invalid (BIP-173) → inconsistent", () => {
  const mixed = BIP84_ADDR0.slice(0, 6) + BIP84_ADDR0.slice(6).toUpperCase();
  const out = compareRecoveryArtifacts(
    { descriptor: BIP84_DESC, address: mixed },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "inconsistent");
  assert.equal(out.mismatchAt, "Receive address");
});

test("Base58 address compares exactly (case matters) → inconsistent", () => {
  const out = compareRecoveryArtifacts(
    { slip132: BIP49_YPUB, address: "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf".toLowerCase() },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "inconsistent");
  assert.equal(out.mismatchAt, "Receive address");
});

// ---- opts.network enforcement (R3-4) -----------------------------------

test("mainnet key + descriptor with opts.network testnet → inconsistent at Network", () => {
  const out = compareRecoveryArtifacts(
    { xpub: BIP84_XPUB, descriptor: BIP84_DESC },
    { network: "testnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "inconsistent");
  assert.equal(out.mismatchAt, "Network");
});

test("testnet key + descriptor with opts.network mainnet → inconsistent at Network", () => {
  const out = compareRecoveryArtifacts(
    { xpub: BIP84_TESTNET_TPUB, descriptor: BIP84_TESTNET_DESC },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "inconsistent");
  assert.equal(out.mismatchAt, "Network");
});

// ---- R4-1: mnemonic vs seed, and the BIP-39 passphrase ----------------

test("R4-1: a matching mnemonic + BIP-39 seed pair alone is consistent", () => {
  const out = compareRecoveryArtifacts(
    { mnemonic: BIP84_MNEMONIC, seed: BIP39_SEED_HEX },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "consistent");
  const seedStep = out.steps.find((s) => s.name === "Seed");
  assert.ok(seedStep && seedStep.ok === true, "the Seed step ran and matched");
});

test("R4-1: another wallet's seed is inconsistent at Seed even when the address matches the mnemonic", () => {
  const out = compareRecoveryArtifacts(
    { mnemonic: BIP84_MNEMONIC, seed: OTHER_SEED_HEX, address: BIP84_ADDR0 },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "inconsistent");
  assert.equal(out.mismatchAt, "Seed");
});

test("R4-1: a passphrase-protected xpub matches only when the passphrase is supplied", () => {
  const without = compareRecoveryArtifacts(
    { mnemonic: BIP84_MNEMONIC, slip132: BIP39_PASSPHRASE_ZPUB },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(without.verdict, "inconsistent");
  assert.equal(without.mismatchAt, "Account key");

  const withPass = compareRecoveryArtifacts(
    { mnemonic: BIP84_MNEMONIC, slip132: BIP39_PASSPHRASE_ZPUB, passphrase: BIP39_PASSPHRASE },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(withPass.verdict, "consistent");

  // Spaces are part of a BIP-39 passphrase: a trailing space is a different
  // passphrase and must not be trimmed into a match.
  const trailing = compareRecoveryArtifacts(
    { mnemonic: BIP84_MNEMONIC, slip132: BIP39_PASSPHRASE_ZPUB, passphrase: BIP39_PASSPHRASE + " " },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(trailing.verdict, "inconsistent");
  assert.equal(trailing.mismatchAt, "Account key");
});

// ---- R4-2: a supplied key decides where the address must be -----------

test("R4-2: a zpub pins the address to its own account and script type", () => {
  const out = compareRecoveryArtifacts(
    { mnemonic: BIP84_MNEMONIC, slip132: BIP84_ZPUB, address: BIP44_ADDR0 },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "inconsistent");
  assert.equal(out.mismatchAt, "Receive address");
});

test("R4-2: a zpub still matches its own receive address when a mnemonic is present", () => {
  const out = compareRecoveryArtifacts(
    { mnemonic: BIP84_MNEMONIC, slip132: BIP84_ZPUB, address: BIP84_ADDR0 },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "consistent");
});

// ---- R4-3: the account index comes from the key itself ----------------

test("R4-3: an account-1 xpub matches its mnemonic at the key's own account", () => {
  const out = compareRecoveryArtifacts(
    { mnemonic: BIP84_MNEMONIC, xpub: BIP84_ACCOUNT1_XPUB },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "consistent");
  const acct = out.steps.find((s) => s.name === "Account key");
  assert.ok(acct && acct.ok === true);
});

test("R4-3: a depth-0 key is a named Support failure", () => {
  const out = compareRecoveryArtifacts(
    { mnemonic: BIP84_MNEMONIC, xpub: BIP84_MASTER_XPUB },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "inconsistent");
  assert.equal(out.mismatchAt, "Support");
});

test("R4-3: a depth-3 key with a non-hardened index is a named Support failure", () => {
  const out = compareRecoveryArtifacts(
    { mnemonic: BIP84_MNEMONIC, xpub: BIP84_NONHARDENED_XPUB },
    { network: "mainnet", receiveIndex: 0 },
  );
  assert.equal(out.verdict, "inconsistent");
  assert.equal(out.mismatchAt, "Support");
});

// ---- R4-4a: private key material is wiped before return ---------------

test("R4-4a: every HDKey built from the mnemonic/seed is wiped before return", () => {
  const masters = [];
  const derived = [];
  const wiped = [];
  const fromMasterSeed = HDKey.fromMasterSeed;
  const deriveChild = HDKey.prototype.deriveChild;
  const wipe = HDKey.prototype.wipePrivateData;
  HDKey.fromMasterSeed = function (...args) {
    const node = fromMasterSeed.apply(this, args);
    masters.push(node);
    return node;
  };
  HDKey.prototype.deriveChild = function (index) {
    const node = deriveChild.call(this, index);
    derived.push(node);
    return node;
  };
  HDKey.prototype.wipePrivateData = function () {
    wiped.push(this);
    return wipe.call(this);
  };
  try {
    const out = compareRecoveryArtifacts(
      { mnemonic: BIP84_MNEMONIC, seed: BIP39_SEED_HEX, descriptor: BIP84_DESC, address: BIP84_ADDR0 },
      { network: "mainnet", receiveIndex: 0 },
    );
    assert.equal(out.verdict, "consistent");
  } finally {
    HDKey.fromMasterSeed = fromMasterSeed;
    HDKey.prototype.deriveChild = deriveChild;
    HDKey.prototype.wipePrivateData = wipe;
  }
  assert.equal(masters.length, 2, "one master per seed artifact");
  for (const master of masters) {
    assert.equal(master.hasPrivateKey, false, "the master built from seed material is wiped");
    assert.ok(wiped.includes(master), "wipePrivateData ran on the master");
  }
  for (const node of derived) {
    assert.equal(node.hasPrivateKey, false, "every derived node is wiped");
  }
});

// ---- R4-4b: non-string artifacts fail closed, never throw -------------

test("R4-4b: a non-string artifact value is a named Support failure, never a throw", () => {
  const hostile = { toString() { throw new Error("hostile toString"); } };
  const cases = [
    { mnemonic: BIP84_MNEMONIC, xpub: BIP84_XPUB, seed: 12345 },
    { mnemonic: BIP84_MNEMONIC, xpub: BIP84_XPUB, address: hostile },
    { mnemonic: BIP84_MNEMONIC, xpub: BIP84_XPUB, descriptor: Symbol("descriptor") },
    // One valid artifact plus a refused one is still a Support failure, not
    // "insufficient" (Muse, round 4 review).
    { mnemonic: BIP84_MNEMONIC, seed: 12345 },
    { mnemonic: BIP84_MNEMONIC, passphrase: 7 },
  ];
  for (const artifacts of cases) {
    assert.doesNotThrow(() => {
      const out = compareRecoveryArtifacts(artifacts, { network: "mainnet", receiveIndex: 0 });
      assert.equal(out.verdict, "inconsistent");
      assert.equal(out.mismatchAt, "Support");
    });
  }
});

// ---- Round 4 red-team (RE-3, RE-10) ------------------------------------

test("a descriptor with text after its key expression is refused, never read past", () => {
  const key = `[${BIP84_FPR}/84'/0'/0']${BIP84_XPUB}`;
  for (const body of [`wpkh(${key}/0/*)junk`, `wpkh(${key}/0/*),{pk(${key}/1/*)}`, `sh(wpkh(${key}/0/*))x`]) {
    const out = compareRecoveryArtifacts({ mnemonic: BIP84_MNEMONIC, descriptor: desc(body) }, { network: "mainnet", receiveIndex: 0 });
    assert.equal(out.verdict, "inconsistent", body);
    assert.equal(out.mismatchAt, "Support", body);
  }
});

test("BIP-86 taproot success path matches the spec's own addresses", () => {
  // Literal values from bip-0086.mediawiki (account xpub, m/86'/0'/0'/0/0
  // and m/86'/0'/0'/1/0), so a wrong p2tr path cannot agree with itself.
  const BIP86_ADDR0 = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";
  const BIP86_CHANGE0 = "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7";
  const opts = { network: "mainnet", receiveIndex: 0 };
  const receive = desc(`tr([${BIP84_FPR}/86'/0'/0']${BIP86_XPUB}/0/*)`);
  assert.equal(compareRecoveryArtifacts({ mnemonic: BIP84_MNEMONIC, descriptor: receive, address: BIP86_ADDR0 }, opts).verdict, "consistent");
  assert.equal(compareRecoveryArtifacts({ mnemonic: BIP84_MNEMONIC, xpub: BIP86_XPUB, address: BIP86_ADDR0 }, opts).verdict, "consistent");
  const change = desc(`tr([${BIP84_FPR}/86'/0'/0']${BIP86_XPUB}/1/*)`);
  assert.equal(compareRecoveryArtifacts({ mnemonic: BIP84_MNEMONIC, descriptor: change, address: BIP86_CHANGE0 }, opts).verdict, "consistent");
  // BIP-389 multipath: one descriptor for both branches; receive index 0 is
  // the spec's first receive address (Kimi K3, round 4 review).
  const multipath = desc(`tr([${BIP84_FPR}/86'/0'/0']${BIP86_XPUB}/<0;1>/*)`);
  assert.equal(compareRecoveryArtifacts({ mnemonic: BIP84_MNEMONIC, descriptor: multipath, address: BIP86_ADDR0 }, opts).verdict, "consistent");
});

test("a descriptor whose origin purpose disagrees with its template is inconsistent at Script type", () => {
  // The 49' account key under wpkh(): the key matches the seed at the origin
  // path, but 49' means p2sh-p2wpkh, so restoring from this descriptor shows
  // different addresses than the wallet used (MiniMax; red-team RE-1).
  const opts = { network: "mainnet", receiveIndex: 0 };
  const out = compareRecoveryArtifacts({ mnemonic: BIP84_MNEMONIC, descriptor: desc(`wpkh([${BIP84_FPR}/49'/0'/0']${BIP49_XPUB}/0/*)`) }, opts);
  assert.equal(out.verdict, "inconsistent");
  assert.equal(out.mismatchAt, "Script type");
  // The matching template under the same origin stays consistent.
  assert.equal(compareRecoveryArtifacts({ mnemonic: BIP84_MNEMONIC, descriptor: desc(`sh(wpkh([${BIP84_FPR}/49'/0'/0']${BIP49_XPUB}/0/*))`) }, opts).verdict, "consistent");
});

test("with no origin, the purpose the seed matched still claims a script type", () => {
  const opts = { network: "mainnet", receiveIndex: 0 };
  // The 49' account key under wpkh() with no origin: the seed derives it at
  // 49', so it is the same mismatch as with a 49' origin (MiniMax).
  const noOrigin = compareRecoveryArtifacts({ mnemonic: BIP84_MNEMONIC, descriptor: desc(`wpkh(${BIP49_XPUB}/0/*)`) }, opts);
  assert.equal(noOrigin.verdict, "inconsistent");
  assert.equal(noOrigin.mismatchAt, "Script type");
  // A plain xpub of the 84' account does not "match" a p2pkh address of the
  // same key once the seed has fixed its purpose at 84'.
  const account84 = HDKey.fromMasterSeed(mnemonicToSeedSync(BIP84_MNEMONIC)).derive("m/84'/0'/0'");
  const p2pkhOf84 = addressFor("p2pkh", account84.derive("m/0/0").publicKey, "mainnet");
  const scan = compareRecoveryArtifacts({ mnemonic: BIP84_MNEMONIC, xpub: BIP84_XPUB, address: p2pkhOf84 }, opts);
  assert.equal(scan.verdict, "inconsistent");
  assert.equal(scan.mismatchAt, "Receive address");
  // The same xpub with its real p2wpkh address stays consistent.
  assert.equal(compareRecoveryArtifacts({ mnemonic: BIP84_MNEMONIC, xpub: BIP84_XPUB, address: BIP84_ADDR0 }, opts).verdict, "consistent");
});

test("a descriptor key that is not at its stated origin fails at Origin, with no seed needed", () => {
  // Origin says account 0', the key is the account-1 key (red-team RE-1).
  const mislabelled = desc(`wpkh([${BIP84_FPR}/84'/0'/0']${BIP84_ACCOUNT1_XPUB}/0/*)`);
  const out = compareRecoveryArtifacts({ xpub: BIP84_ACCOUNT1_XPUB, descriptor: mislabelled }, { network: "mainnet", receiveIndex: 0 });
  assert.equal(out.verdict, "inconsistent");
  assert.equal(out.mismatchAt, "Origin");
  // The same key under its true origin passes that check.
  const correct = desc(`wpkh([${BIP84_FPR}/84'/0'/1']${BIP84_ACCOUNT1_XPUB}/0/*)`);
  assert.equal(compareRecoveryArtifacts({ xpub: BIP84_ACCOUNT1_XPUB, descriptor: correct }, { network: "mainnet", receiveIndex: 0 }).verdict, "consistent");
});

test("an unknown network or an invalid receiveIndex is refused up front", () => {
  const artifacts = { mnemonic: BIP84_MNEMONIC, descriptor: BIP84_DESC };
  for (const opts of [{ network: "regtest" }, { network: "foo" }, { receiveIndex: -1 }, { receiveIndex: 1.5 }, { receiveIndex: "0" }, { receiveIndex: 2 ** 31 }]) {
    const out = compareRecoveryArtifacts(artifacts, opts);
    assert.equal(out.verdict, "inconsistent", JSON.stringify(opts));
    assert.equal(out.mismatchAt, "Support", JSON.stringify(opts));
  }
  assert.equal(compareRecoveryArtifacts(artifacts, { network: "mainnet", receiveIndex: 0 }).verdict, "consistent");
});

test("a descriptor key with two origins, or an origin not directly before it, is refused", () => {
  // Muse (review of ff6854a): a second "[...]" was ignored. BIP-380 allows at
  // most one key origin, directly before the key.
  const opts = { network: "mainnet", receiveIndex: 0 };
  for (const body of [
    `wpkh([${BIP84_FPR}/84'/0'/0'][deadbeef/84'/0'/1']${BIP84_XPUB}/0/*)`,
    `wpkh(${BIP84_XPUB}[${BIP84_FPR}/84'/0'/0']/0/*)`,
  ]) {
    const out = compareRecoveryArtifacts({ mnemonic: BIP84_MNEMONIC, descriptor: desc(body) }, opts);
    assert.equal(out.verdict, "inconsistent", body);
    assert.equal(out.mismatchAt, "Support", body);
  }
  assert.equal(compareRecoveryArtifacts({ mnemonic: BIP84_MNEMONIC, descriptor: BIP84_DESC }, opts).verdict, "consistent");
});

test("a descriptor containing whitespace is refused", () => {
  // Muse (review of 57e9d37): "[origin] key" read as "[origin]key".
  const opts = { network: "mainnet", receiveIndex: 0 };
  // No checksum: the repo's checksum helper refuses whitespace itself, and a
  // descriptor without one is accepted (flagged absent), so this reaches the
  // whitespace check.
  for (const body of [`wpkh([${BIP84_FPR}/84'/0'/0'] ${BIP84_XPUB}/0/*)`, `wpkh([${BIP84_FPR}/84'/0'/0']${BIP84_XPUB}/0/* )`]) {
    const out = compareRecoveryArtifacts({ mnemonic: BIP84_MNEMONIC, descriptor: body }, opts);
    assert.equal(out.verdict, "inconsistent", body);
    assert.equal(out.mismatchAt, "Support", body);
  }
});

test("no step detail ever repeats secret input; a private key in a descriptor is refused", () => {
  // The BIP-32 test-vector-1 master xprv (public test data, not a secret
  // anyone holds) and a made-up mnemonic word stand in for private input.
  const XPRV = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
  const opts = { network: "mainnet", receiveIndex: 0 };
  const cases = [
    { descriptor: desc(`wpkh([${BIP84_FPR}/84'/0'/0']${XPRV}/0/*)`), xpub: BIP84_XPUB },
    { xpub: XPRV, mnemonic: BIP84_MNEMONIC },
    { slip132: XPRV, descriptor: BIP84_DESC },
    { mnemonic: "abandon ".repeat(11) + "zzzzsecretword", xpub: BIP84_XPUB },
    { seed: "zzzz" + "00".repeat(31), xpub: BIP84_XPUB },
  ];
  for (const artifacts of cases) {
    const out = compareRecoveryArtifacts(artifacts, opts);
    assert.equal(out.verdict, "inconsistent", JSON.stringify(Object.keys(artifacts)));
    const details = JSON.stringify(out.steps);
    for (const secret of [XPRV, XPRV.slice(4, 30), "zzzzsecretword"]) assert.ok(!details.includes(secret), "a step detail repeats secret input");
  }
  const refused = compareRecoveryArtifacts(cases[0], opts);
  assert.equal(refused.mismatchAt, "Support");
});

test("a seed outside BIP-32's 16 to 64 bytes is refused", () => {
  // Red-team RE-3: a 1-byte "seed" was accepted and could report consistent
  // against a key derived from it. BIP-32 seeds are 128 to 512 bits.
  const opts = { network: "mainnet", receiveIndex: 0 };
  for (const seed of ["ab", "00".repeat(15), "00".repeat(65)]) {
    const out = compareRecoveryArtifacts({ seed, xpub: BIP84_XPUB }, opts);
    assert.equal(out.verdict, "inconsistent", `${seed.length / 2} bytes`);
    assert.equal(out.mismatchAt, "Support", `${seed.length / 2} bytes`);
  }
  // The edges are accepted: the 64-byte BIP-39 seed already verifies above,
  // and a 16-byte seed parses (it only has to derive the same keys).
  assert.notEqual(compareRecoveryArtifacts({ seed: "00".repeat(16), xpub: BIP84_XPUB }, opts).mismatchAt, "Support");
});

test("a passphrase without a mnemonic is refused, not silently ignored", () => {
  const opts = { network: "mainnet", receiveIndex: 0 };
  const out = compareRecoveryArtifacts({ seed: BIP39_SEED_HEX, xpub: BIP84_XPUB, passphrase: BIP39_PASSPHRASE }, opts);
  assert.equal(out.verdict, "inconsistent");
  assert.equal(out.mismatchAt, "Support");
  // An empty passphrase is the BIP-39 default, not an artifact.
  assert.equal(compareRecoveryArtifacts({ seed: BIP39_SEED_HEX, xpub: BIP84_XPUB, passphrase: "" }, opts).verdict, "consistent");
});
