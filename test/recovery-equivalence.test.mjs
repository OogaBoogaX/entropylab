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

// Repo-pinned descriptor checksum so fixtures are syntactically valid.
function desc(body) {
  return `${body}#${descriptorChecksum(body)}`;
}

const BIP84_XPUB = slipToCoreXpub(BIP84_ZPUB);
const BIP84_DESC = desc(`wpkh([${BIP84_FPR}/84'/0'/0']${BIP84_XPUB}/0/*)`);
const BIP49_XPUB = slipToCoreXpub(BIP49_YPUB);

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
