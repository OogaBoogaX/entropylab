// Focused tests for the read-only UTXO verification labels in the PSBT
// flow visualizer. The verifier is intentionally a thin view over the
// inspector's already-decoded witness/non-witness UTXO fields.
import { test } from "node:test";
import assert from "node:assert/strict";
import { psbtVizHtml } from "../src/js/psbt-viz.js";

const makeDoc = (inputPairs, outputValues = ["900"]) => ({
  psbtVersion: 0,
  tx: {
    version: 2,
    locktime: 0,
    inputs: inputPairs.map((pairs) => ({
      txid: pairs.find((pair) => pair.name === "PSBT_IN_NON_WITNESS_UTXO")?.decoded?.txid ?? "11".repeat(32),
      vout: 0,
      scriptSig: "",
      sequence: 0,
    })),
    outputs: outputValues.map((value) => ({ value, scriptPubKey: "6a00", asm: "OP_RETURN" })),
  },
  globals: [],
  inputs: inputPairs,
  outputs: outputValues.map(() => []),
  totalIn: null,
  totalOut: outputValues.reduce((sum, value) => (BigInt(sum) + BigInt(value)).toString(), "0"),
  fee: { known: false },
});

const doc = (pairs) => makeDoc([pairs]);

test("a matching non-witness UTXO without witness data remains unverified", () => {
  const pairs = [{
    name: "PSBT_IN_NON_WITNESS_UTXO",
    decoded: {
      txid: "11".repeat(32),
      outputCount: 1,
      prevout: { vout: 0, value: "1000", scriptPubKey: "51" },
    },
  }];
  const html = psbtVizHtml(doc(pairs), "mainnet");
  assert.ok(html.includes("1000 sats"), "non-witness amount missing");
  assert.ok(html.includes("(unverified)"), "non-witness-only claim was incorrectly marked verified");
  assert.ok(!html.includes("(verified)"), "non-witness-only claim was incorrectly marked verified");
});

test("a witness-only UTXO is shown as an unverified claim", () => {
  const pairs = [{
    name: "PSBT_IN_WITNESS_UTXO",
    decoded: { value: "1000", scriptPubKey: "51" },
  }];
  const html = psbtVizHtml(doc(pairs), "mainnet");
  assert.ok(html.includes("1000 sats"), "witness claim amount missing");
  assert.ok(html.includes("(unverified)"), "witness-only claim was not marked unverified");
  assert.ok(!html.includes("(verified)"), "witness-only claim was incorrectly marked verified");
});

test("no usable UTXO declaration is unverified", () => {
  const html = psbtVizHtml(doc([]), "mainnet");
  assert.ok(html.includes("no amount claim"), "missing claim was not shown");
  assert.ok(html.includes("(unverified)"), "missing claim was not marked unverified");
});

test("a malformed non-witness declaration does not become verified", () => {
  const pairs = [{
    name: "PSBT_IN_NON_WITNESS_UTXO",
    decoded: null,
    decodeError: "non-witness utxo does not decode",
  }];
  const html = psbtVizHtml(doc(pairs), "mainnet");
  assert.ok(html.includes("no amount claim"), "malformed declaration should not supply an amount");
  assert.ok(html.includes("(unverified)"), "malformed declaration was incorrectly marked verified");
});

test("a non-witness declaration without a matched prevout is unverified", () => {
  const pairs = [{
    name: "PSBT_IN_NON_WITNESS_UTXO",
    decoded: { txid: "22".repeat(32), outputCount: 1 },
  }];
  const html = psbtVizHtml(doc(pairs), "mainnet");
  assert.ok(html.includes("no amount claim"), "unmatched non-witness declaration should not supply an amount");
  assert.ok(html.includes("(unverified)"), "unmatched non-witness declaration was incorrectly marked verified");
});

test("agreeing witness and non-witness claims are verified", () => {
  const pairs = [
    { name: "PSBT_IN_WITNESS_UTXO", decoded: { value: "1000", scriptPubKey: "51" } },
    { name: "PSBT_IN_NON_WITNESS_UTXO", decoded: { txid: "11".repeat(32), outputCount: 1, prevout: { vout: 0, value: "1000", scriptPubKey: "51" } } },
  ];
  const html = psbtVizHtml(doc(pairs), "mainnet");
  assert.ok(html.includes("1000 sats"), "agreed amount missing");
  assert.ok(html.includes("(verified)"), "agreed non-witness claim was not marked verified");
  assert.ok(!html.includes("conflicting"), "agreeing claims incorrectly conflict");
});

test("disagreeing amounts are a mismatch", () => {
  const pairs = [
    { name: "PSBT_IN_WITNESS_UTXO", decoded: { value: "5000", scriptPubKey: "51" } },
    { name: "PSBT_IN_NON_WITNESS_UTXO", decoded: { txid: "11".repeat(32), outputCount: 1, prevout: { vout: 0, value: "1000", scriptPubKey: "51" } } },
  ];
  const html = psbtVizHtml(doc(pairs), "mainnet");
  assert.ok(html.includes("mismatch: conflicting claims: 5 000 vs 1 000 sats"), "valid amount disagreement was not marked mismatch");
});

test("disagreeing scripts are a mismatch even when amounts agree", () => {
  const pairs = [
    { name: "PSBT_IN_WITNESS_UTXO", decoded: { value: "1000", scriptPubKey: "51" } },
    { name: "PSBT_IN_NON_WITNESS_UTXO", decoded: { txid: "11".repeat(32), outputCount: 1, prevout: { vout: 0, value: "1000", scriptPubKey: "52" } } },
  ];
  const html = psbtVizHtml(doc(pairs), "mainnet");
  assert.ok(html.includes("mismatch: conflicting scriptPubKeys"), "script disagreement was not marked mismatch");
  assert.ok(!html.includes("(verified)"), "script disagreement was incorrectly marked verified");
});

test("verified status explains that both claims agree on amount and script", () => {
  const pairs = [
    { name: "PSBT_IN_WITNESS_UTXO", decoded: { value: "1000", scriptPubKey: "51" } },
    { name: "PSBT_IN_NON_WITNESS_UTXO", decoded: { txid: "11".repeat(32), outputCount: 1, prevout: { vout: 0, value: "1000", scriptPubKey: "51" } } },
  ];
  const html = psbtVizHtml(doc(pairs), "mainnet");
  assert.ok(html.includes("amount and scriptPubKey independently established by agreement"), "verification basis was not exposed in the UI");
});

test("all inputs verified exposes an independently verified fee", () => {
  const pairs = [
    { name: "PSBT_IN_WITNESS_UTXO", decoded: { value: "1000", scriptPubKey: "51" } },
    { name: "PSBT_IN_NON_WITNESS_UTXO", decoded: { txid: "11".repeat(32), outputCount: 1, prevout: { vout: 0, value: "1000", scriptPubKey: "51" } } },
  ];
  const html = psbtVizHtml(doc(pairs), "mainnet");
  assert.ok(html.includes("100 sats"), "independently verified fee missing");
  assert.ok(html.includes("(independently verified)"), "fee was not labeled independently verified");
  assert.ok(!html.includes("(PSBT claim)"), "verified fee still used the PSBT-claim label");
});

test("an unverified input does not promote the fee to independently verified", () => {
  const pairs = [
    { name: "PSBT_IN_WITNESS_UTXO", decoded: { value: "1000", scriptPubKey: "51" } },
  ];
  const html = psbtVizHtml(doc(pairs), "mainnet");
  assert.ok(!html.includes("(independently verified)"), "unverified input incorrectly promoted the fee");
});

test("a mismatched input does not promote the fee to independently verified", () => {
  const pairs = [
    { name: "PSBT_IN_WITNESS_UTXO", decoded: { value: "1000", scriptPubKey: "51" } },
    { name: "PSBT_IN_NON_WITNESS_UTXO", decoded: { txid: "11".repeat(32), outputCount: 1, prevout: { vout: 0, value: "900", scriptPubKey: "51" } } },
  ];
  const html = psbtVizHtml(doc(pairs), "mainnet");
  assert.ok(!html.includes("(independently verified)"), "mismatched input incorrectly promoted the fee");
});

test("multiple verified inputs contribute to the independently verified fee", () => {
  const first = [
    { name: "PSBT_IN_WITNESS_UTXO", decoded: { value: "1000", scriptPubKey: "51" } },
    { name: "PSBT_IN_NON_WITNESS_UTXO", decoded: { txid: "11".repeat(32), outputCount: 1, prevout: { vout: 0, value: "1000", scriptPubKey: "51" } } },
  ];
  const second = [
    { name: "PSBT_IN_WITNESS_UTXO", decoded: { value: "1000", scriptPubKey: "51" } },
    { name: "PSBT_IN_NON_WITNESS_UTXO", decoded: { txid: "22".repeat(32), outputCount: 1, prevout: { vout: 0, value: "1000", scriptPubKey: "51" } } },
  ];
  const html = psbtVizHtml(makeDoc([first, second], ["1500"]), "mainnet");
  assert.ok(html.includes("500 sats"), "fee did not aggregate all verified inputs");
  assert.ok(html.includes("(independently verified)"), "aggregate verified fee was not labeled independently verified");
});
