// The PSBT inspector's input-side key work is bounded per render, as the
// output side's is (audit M3). xflow sweep of cb18b09: each signature row
// rescanned every BIP32 record of its input with a point parse (DeepSeek
// V4.1, GLM 5.3), and resolved the session key with one private CKD per step
// of an attacker-named path, with no budget (GLM 5.3, Kimi K3).
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { HDKey } from "../src/js/hdkey.js";
import { secp256k1 } from "../src/js/secp256k1.js";
import { loadAppFunctions } from "./app-slice-harness.mjs";

const inertDom = new Proxy(function () {}, { get: (target, key) => (key === Symbol.toPrimitive ? () => "" : key === "then" ? undefined : inertDom), apply: () => inertDom, construct: () => inertDom });
Object.assign(globalThis, { __ENTROPYLAB_TEST_HOOKS__: false, document: inertDom, window: inertDom });
let compressedCalls = 0;
const real = await loadAppFunctions(["hodlCompressedPubkey"]);
// The session root's own address index (hodlSessionOwnership) is a fixed
// cost of every render, not one a file controls; it is left out so the
// counts below are the input side's alone.
const psbtRender = await loadAppFunctions(
  ["hodlRenderPsbt", "hodlPsbtWipeMem"],
  {
    settable: ["hodlPsbtHd", "hodlPsbtNonceHistory"],
    stubs: { hodlCompressedPubkey: (pubkey) => (compressedCalls++, real.hodlCompressedPubkey(pubkey)), hodlSessionOwnership: () => new Map() },
  },
);
after(() => {
  delete globalThis.__ENTROPYLAB_TEST_HOOKS__;
  delete globalThis.document;
  delete globalThis.window;
});

// A strict-DER signature (r = s = 1) with SIGHASH_ALL: its r is readable, so
// the row resolves a key and a fingerprint. No previous output is in the
// file, so no digest is rebuilt and nothing else on the row costs a CKD.
const SIGNATURE = Uint8Array.of(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01);
const pubkeys = (count, offset = 1) => Array.from({ length: count }, (_, i) => {
  const secret = new Uint8Array(32);
  new DataView(secret.buffer).setUint32(28, offset + i);
  return secp256k1.getPublicKey(secret, true);
});
const bip32Entry = (pubkey, fingerprint, steps) => {
  const val = new Uint8Array(4 + 4 * steps);
  new DataView(val.buffer).setUint32(0, fingerprint >>> 0);
  return { type: 6, keydata: pubkey, val };
};
const fixture = (entries) => {
  const tx = { version: 2, inputs: [{ txid: new Uint8Array(32).fill(0x11), vout: 0, sequence: 0xfffffffd }], outputs: [{ amount: 900n, script: Uint8Array.of(0x00, 0x14, ...new Uint8Array(20).fill(0x42)) }], locktime: 0 };
  return { tx, inputs: [entries], outputs: [[]], referenceVerdict: { state: "incomplete", problems: [], unlisted: 0 } };
};
// Renders with an HD session root and counts every private CKD under it.
function renderCountingCkds(root, psbt) {
  const deriveChild = HDKey.prototype.deriveChild;
  let ckds = 0;
  HDKey.prototype.deriveChild = function (index) {
    ckds++;
    return deriveChild.call(this, index);
  };
  psbtRender.__set.hodlPsbtHd(root);
  psbtRender.__set.hodlPsbtNonceHistory([]);
  try {
    psbtRender.hodlRenderPsbt(psbt, new Uint8Array(), "2026-01-01T00:00:00.000Z", "all");
    return ckds;
  } finally {
    HDKey.prototype.deriveChild = deriveChild;
    psbtRender.hodlPsbtWipeMem();
    psbtRender.__set.hodlPsbtNonceHistory([]);
  }
}

test("a path deeper than 255 levels costs no derivation", () => {
  const root = HDKey.fromMasterSeed(new Uint8Array(32).fill(7));
  const [deep, honest] = pubkeys(2);
  const ckds = renderCountingCkds(root, fixture([
    { type: 2, keydata: deep, val: SIGNATURE }, bip32Entry(deep, root.fingerprint, 300),
    { type: 2, keydata: honest, val: SIGNATURE }, bip32Entry(honest, root.fingerprint, 5),
  ]));
  // rock ran 255 CKDs on the deep path before HDKey refused the 256th level.
  // Skipping it must not zero the budget either (Muse Spark and DeepSeek V4.1
  // on b31504d): the later 5-step path is still walked.
  assert.equal(ckds, 5);
});

test("signature rows share one input-side derivation budget per render", () => {
  const root = HDKey.fromMasterSeed(new Uint8Array(32).fill(7));
  // 25 rows of 200 steps each would be 5,000 CKDs; the budget covers 20 full
  // paths (4,000), skips the five that no longer fit, and a later 50-step path
  // still fits in the 96 left. The render completes.
  const entries = [];
  const keys = pubkeys(26);
  keys.forEach((pubkey, i) => entries.push({ type: 2, keydata: pubkey, val: SIGNATURE }, bip32Entry(pubkey, root.fingerprint, i < 25 ? 200 : 50)));
  const ckds = renderCountingCkds(root, fixture(entries));
  assert.ok(ckds <= 4096, `${ckds} CKDs in one render`);
  assert.equal(ckds, 20 * 200 + 50, "paths the budget covers are still walked");
});

test("each input's BIP32 records are parsed once, not once per signature row", () => {
  // 60 signature rows and 60 records: the per-row rescan parsed 60 x 60 points.
  const entries = [];
  const keys = pubkeys(60);
  for (const pubkey of keys) entries.push({ type: 2, keydata: pubkey, val: SIGNATURE }, bip32Entry(pubkey, 0x01020304, 3));
  compressedCalls = 0;
  psbtRender.__set.hodlPsbtNonceHistory([]);
  try {
    psbtRender.hodlRenderPsbt(fixture(entries), new Uint8Array(), "2026-01-01T00:00:00.000Z", "all");
  } finally {
    psbtRender.__set.hodlPsbtNonceHistory([]);
  }
  assert.ok(compressedCalls <= 4 * keys.length, `${compressedCalls} point parses for ${keys.length} rows and ${keys.length} records`);
});
