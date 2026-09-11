import { test } from "node:test";
import assert from "node:assert/strict";
import { constructUnsignedPsbtDoc, encodeWitnessUtxo, parseAmountSats, MAX_MONEY_SATS } from "../src/js/psbt-construct.js";
import { psbtBuildBytes, psbtInspectDoc } from "../src/js/psbt-wasm.js";
import { psbtEditorBuildDoc } from "../src/js/psbt-editor.js";

const P2WPKH = "0014751e76e8199196d454941c45d1b3a323f1433bd6";
const TXID = "11".repeat(32);

test("parseAmountSats accepts sats and BTC", () => {
  assert.equal(parseAmountSats("150000"), 150000n);
  assert.equal(parseAmountSats("1.5"), 150000000n);
  assert.equal(parseAmountSats("0.00000001"), 1n);
  assert.throws(() => parseAmountSats("21000000.00000001"), /MAX_MONEY/);
});

test("encodeWitnessUtxo is 8-byte LE amount plus compact-size script", () => {
  const hex = encodeWitnessUtxo(1000n, "0014aa");
  assert.equal(hex.slice(0, 16), "e803000000000000");
  assert.equal(hex.slice(16, 18), "03");
  assert.equal(hex.slice(18), "0014aa");
});

test("constructUnsignedPsbtDoc builds a rust-bitcoin-accepted unsigned PSBT", () => {
  const doc = constructUnsignedPsbtDoc({
    version: 2,
    locktime: 0,
    inputs: [{ txid: TXID, vout: "1", value: "200000", script: P2WPKH }],
    outputs: [{ value: "199000", script: P2WPKH }],
  });
  assert.equal(doc.claimedFeeSats, 1000n);
  assert.equal(doc.tx.inputs[0].scriptSig, "");
  assert.equal(doc.inputs[0][0].key, "01");
  const bytes = psbtBuildBytes(psbtEditorBuildDoc(doc));
  const inspected = psbtInspectDoc(bytes);
  assert.equal(inspected.tx.inputs.length, 1);
  assert.equal(inspected.tx.outputs.length, 1);
  assert.equal(Number(inspected.tx.outputs[0].value), 199000);
  assert.ok(inspected.inputs[0].some((pair) => pair.key === "01" || pair.name === "PSBT_IN_WITNESS_UTXO"));
  assert.ok(!inspected.inputs[0].some((pair) => pair.name === "PSBT_IN_PARTIAL_SIG"));
});

test("constructUnsignedPsbtDoc rejects empty sides, duplicates, and overspend", () => {
  assert.throws(() => constructUnsignedPsbtDoc({ inputs: [], outputs: [{ value: "1", script: P2WPKH }] }), /at least one input/);
  assert.throws(() => constructUnsignedPsbtDoc({ inputs: [{ txid: TXID, vout: "0", value: "1", script: P2WPKH }], outputs: [] }), /at least one output/);
  assert.throws(
    () =>
      constructUnsignedPsbtDoc({
        inputs: [
          { txid: TXID, vout: "0", value: "2", script: P2WPKH },
          { txid: TXID, vout: "0", value: "2", script: P2WPKH },
        ],
        outputs: [{ value: "1", script: P2WPKH }],
      }),
    /duplicate prevout/,
  );
  assert.throws(
    () =>
      constructUnsignedPsbtDoc({
        inputs: [{ txid: TXID, vout: "0", value: "1", script: P2WPKH }],
        outputs: [{ value: "2", script: P2WPKH }],
      }),
    /exceed claimed input/,
  );
});

test("MAX_MONEY is the consensus cap used by the constructor", () => {
  assert.equal(MAX_MONEY_SATS, 2100000000000000n);
});
