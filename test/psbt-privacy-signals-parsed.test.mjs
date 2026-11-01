import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { psbtPrivacySignals } from "../src/js/psbt-privacy-signals.js";
import { loadAppFunctions } from "./app-slice-harness.mjs";

// The privacy signals read the Inspector's own parsed PSBT, so each fixture
// goes through the app's hodlParsePsbt rather than hand-built entries (GLM,
// #1363 round 2: a parser shape change would otherwise turn every signal into
// a false "nothing found"). Expected values come from the fixture generator
// (test/fixtures/psbt/generate.mjs), where every key path uses the one
// fingerprint 12345678.
const fixture = (name) => Uint8Array.from(Buffer.from(readFileSync(new URL(`./fixtures/psbt/${name}.b64`, import.meta.url), "utf8").trim(), "base64"));
const { hodlParsePsbt } = await loadAppFunctions(["hodlParsePsbt"]);
const signalsOf = (name) => {
  const psbt = hodlParsePsbt(fixture(name));
  return psbtPrivacySignals({ inputs: psbt.inputs, outputs: psbt.tx.outputs });
};

test("BIP-174 key paths (type 6) are read from a parsed PSBT", () => {
  const signals = signalsOf("multisig-2of3-p2wsh");
  assert.equal(signals.available, true);
  assert.equal(signals.masterKeys, 1);
  assert.equal(signals.originGroups, 1);
});

test("BIP-371 Taproot key paths (type 0x16) are read from a parsed PSBT", () => {
  const signals = signalsOf("p2tr-taproot");
  assert.equal(signals.masterKeys, 1);
  assert.equal(signals.originGroups, 1);
});

test("one finalized input among unfinalized ones reads as mixed finalization", () => {
  // Input 4 of mixed-many-inputs carries a final witness; inputs 0 to 3 do not.
  const signals = signalsOf("mixed-many-inputs");
  assert.equal(signals.mixedFinalization, true);
  assert.equal(signals.masterKeys, 1);
});

test("the parsed outputs carry amounts the equal-output check reads", () => {
  // p2wpkh-1in-2out pays two different amounts: no equal-output group, and
  // the amounts are bigints from the parser, not a fallback field.
  const psbt = hodlParsePsbt(fixture("p2wpkh-1in-2out"));
  assert.ok(psbt.tx.outputs.every((output) => typeof output.amount === "bigint"));
  assert.deepEqual(psbtPrivacySignals({ inputs: psbt.inputs, outputs: psbt.tx.outputs }).equalOutputs, []);
});
