// The Inspector's SIGHASH policy verdict on two input shapes (red-team sweep
// 0eed735, part09 #9 and #10):
// - SIGHASH 0 is Taproot's DEFAULT only on a Taproot input. Whether an input
//   is one is decided by its resolved previous output, so a P2WPKH input that
//   merely carries a 0x13-0x18 field still reads 0 as an undefined policy.
// - A finalized Taproot signature's sighash byte is checked like a 0x13 one,
//   so a SIGHASH_NONE suffix in the final witness is a policy problem.
// The verdict is read from the analysis checks the render builds.
// Run with `npm test` (part of the default suite).
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { t as tText } from "../src/js/i18n.js";
import { loadAppFunctions } from "./app-slice-harness.mjs";

const inertDom = new Proxy(function () {}, { get: (target, key) => (key === Symbol.toPrimitive ? () => "" : key === "then" ? undefined : inertDom), apply: () => inertDom, construct: () => inertDom });
Object.assign(globalThis, { __ENTROPYLAB_TEST_HOOKS__: false, document: inertDom, window: inertDom });
after(() => {
  delete globalThis.__ENTROPYLAB_TEST_HOOKS__;
  delete globalThis.document;
  delete globalThis.window;
});

let checks = null;
const view = await loadAppFunctions(["hodlRenderPsbt", "hodlPsbtWipeMem"], {
  settable: ["hodlPsbtNonceHistory"],
  stubs: { hodlPsbtAnalysisSummary: (list) => ((checks = list), ""), hodlSessionOwnership: () => new Map() },
});
// The SIGHASH policy row, found by its label key.
const policyState = (psbt) => {
  checks = null;
  view.__set.hodlPsbtNonceHistory([]);
  try {
    view.hodlRenderPsbt(psbt, new Uint8Array(), "2026-01-01T00:00:00.000Z", "all");
  } finally {
    view.hodlPsbtWipeMem();
  }
  const row = checks?.find((check) => check.label === tText("SIGHASH policy"));
  assert.ok(row, "the render lists a SIGHASH policy check");
  return row.state;
};

const u32 = (value) => { const bytes = new Uint8Array(4); new DataView(bytes.buffer).setUint32(0, value, true); return bytes; };
const witnessUtxo = (amount, script) => {
  const val = new Uint8Array(8 + 1 + script.length);
  new DataView(val.buffer).setBigUint64(0, BigInt(amount), true);
  val[8] = script.length;
  val.set(script, 9);
  return { type: 1, keydata: new Uint8Array(), val };
};
const P2WPKH = Uint8Array.of(0x00, 0x14, ...new Uint8Array(20).fill(0x42));
const P2TR = Uint8Array.of(0x51, 0x20, ...new Uint8Array(32).fill(0x24));
const declared = (value) => ({ type: 3, keydata: new Uint8Array(), val: u32(value) });
const internalKey = { type: 0x17, keydata: new Uint8Array(), val: new Uint8Array(32).fill(0x24) };
const psbtOf = (entries) => ({
  tx: { version: 2, inputs: [{ txid: new Uint8Array(32).fill(0x11), vout: 0, sequence: 0xfffffffd }], outputs: [{ amount: 900n, script: Uint8Array.of(0x00, 0x14, ...new Uint8Array(20).fill(0x43)) }], locktime: 0 },
  inputs: [entries],
  outputs: [[]],
  referenceVerdict: { state: "incomplete", problems: [], unlisted: 0 },
});

test("SIGHASH 0 on a P2WPKH input is an undefined policy, whatever Taproot fields it carries", () => {
  assert.equal(policyState(psbtOf([witnessUtxo(1000, P2WPKH), declared(0)])), "problem", "the plain case, as before");
  assert.equal(policyState(psbtOf([witnessUtxo(1000, P2WPKH), declared(0), internalKey])), "problem", "a 0x17 field does not make it Taproot");
});

test("SIGHASH 0 stays Taproot's DEFAULT on a Taproot input", () => {
  assert.notEqual(policyState(psbtOf([witnessUtxo(1000, P2TR), declared(0), internalKey])), "problem", "a P2TR previous output");
  assert.notEqual(policyState(psbtOf([declared(0), internalKey])), "problem", "no previous output: the Taproot fields decide, as before");
});

// A finalized key-path spend: a final witness of one 64- or 65-byte signature.
const finalWitness = (signature) => {
  const val = Uint8Array.of(1, signature.length, ...signature);
  return { type: 8, keydata: new Uint8Array(), val };
};
const signature = (suffix) => Uint8Array.of(...new Uint8Array(32).fill(0x31), ...new Uint8Array(32).fill(0x32), ...(suffix === null ? [] : [suffix]));

test("a finalized Taproot signature with SIGHASH_NONE is a policy problem", () => {
  for (const suffix of [0x02, 0x03, 0x81, 0x82]) {
    assert.equal(policyState(psbtOf([witnessUtxo(1000, P2TR), finalWitness(signature(suffix))])), "problem", `suffix 0x${suffix.toString(16)}`);
  }
});

test("a finalized Taproot signature that commits to everything is not a policy problem", () => {
  for (const suffix of [null, 0x01]) {
    assert.notEqual(policyState(psbtOf([witnessUtxo(1000, P2TR), finalWitness(signature(suffix))])), "problem", suffix === null ? "64 bytes (DEFAULT)" : "SIGHASH_ALL");
  }
});
