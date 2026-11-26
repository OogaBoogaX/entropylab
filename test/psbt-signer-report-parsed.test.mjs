// The signer availability report over the app's own parser and collectors.
// Expected values come from the fixture generator (test/fixtures/psbt/
// generate.mjs), whose keys are the public test private keys 1, 2 and 3.
// Run with `npm test`.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { psbtSignerReport } from "../src/js/psbt-signer-report.js";
import { secp256k1 } from "../src/js/secp256k1.js";
import { loadAppFunctions } from "./app-slice-harness.mjs";

const fixture = (name) => Uint8Array.from(Buffer.from(readFileSync(new URL(`./fixtures/psbt/${name}.b64`, import.meta.url), "utf8").trim(), "base64"));
const { hodlParsePsbt, hodlSignerReportInputs, hodlSignerReportVerifier } = await loadAppFunctions(["hodlParsePsbt", "hodlSignerReportInputs", "hodlSignerReportVerifier"]);

const priv = (n) => {
  const key = new Uint8Array(32);
  key[31] = n;
  return key;
};
const singleSource = (id, n) => {
  const key = priv(n);
  return { id, label: `Key ${n}`, private: true, pubkeys: [secp256k1.getPublicKey(key, true), secp256k1.getPublicKey(key, false)] };
};
const reportOf = (name, sources) => {
  const psbt = hodlParsePsbt(fixture(name));
  const inputs = hodlSignerReportInputs(psbt);
  return psbtSignerReport({ inputs, sources, network: "mainnet", verify: hodlSignerReportVerifier(psbt, inputs) });
};

test("multisig-2of3-p2wsh: one, two and three keys, and a duplicate import", () => {
  const one = reportOf("multisig-2of3-p2wsh", [singleSource("1", 1)]);
  assert.equal(one.inputs[1].state, "short");
  assert.equal(one.inputs[1].signed + one.inputs[1].canAdd, 1);
  const two = reportOf("multisig-2of3-p2wsh", [singleSource("1", 1), singleSource("2", 2)]);
  assert.equal(two.inputs[1].state, "ready");
  assert.equal(two.inputs[1].all, false);
  const three = reportOf("multisig-2of3-p2wsh", [singleSource("1", 1), singleSource("2", 2), singleSource("3", 3)]);
  assert.equal(three.inputs[1].state, "ready");
  assert.equal(three.inputs[1].all, true);
  const twice = reportOf("multisig-2of3-p2wsh", [singleSource("1", 1), singleSource("1b", 1)]);
  assert.equal(twice.inputs[1].state, "short");
  assert.equal(twice.inputs[1].signed + twice.inputs[1].canAdd, 1);
  // Input 0's two fixture signatures sign nothing.
  assert.equal(three.inputs[0].invalid, 2);
});

test("mixed-many-inputs: every script shape through the app's own parser", () => {
  const report = reportOf("mixed-many-inputs", [singleSource("1", 1), singleSource("2", 2), singleSource("3", 3)]);
  assert.equal(report.inputs[0].state, "ready");
  assert.equal(report.inputs[0].script, "p2pkh");
  assert.equal(report.inputs[1].state, "ready");
  assert.equal(report.inputs[1].invalid, 1);
  assert.equal(report.inputs[2].state, "unsupported");
  assert.equal(report.inputs[2].reason, "taproot");
  assert.equal(report.inputs[3].state, "ready");
  assert.equal(report.inputs[3].all, true);
  assert.equal(report.inputs[3].unchecked, 1);
  assert.equal(report.inputs[4].state, "finalized");
  const onlyTwo = reportOf("mixed-many-inputs", [singleSource("2", 2)]);
  assert.equal(onlyTwo.inputs[3].state, "unknown");
  assert.equal(onlyTwo.inputs[3].reason, "unchecked-signatures");
});

test("p2tr-taproot: both inputs are unsupported", () => {
  const report = reportOf("p2tr-taproot", [singleSource("1", 1)]);
  assert.deepEqual(report.inputs.map((row) => row.state), ["unsupported", "unsupported"]);
});

test("bip174-valid-vector-2: a finalized input and a nested P2WPKH", () => {
  const report = reportOf("bip174-valid-vector-2", [singleSource("1", 1)]);
  assert.equal(report.inputs[0].state, "finalized");
  assert.equal(report.inputs[1].script, "p2sh-p2wpkh");
});

test("the verifier checks a real BIP-143 signature and refuses what it cannot check", () => {
  const psbt = hodlParsePsbt(fixture("mixed-many-inputs"));
  const inputs = hodlSignerReportInputs(psbt);
  const verify = hodlSignerReportVerifier(psbt, inputs);
  // Input 4's final witness is `02 <len> <sig> 21 <pk3>`.
  const final = psbt.inputs[4].find((entry) => entry.type === 8 && entry.keydata.length === 0).val;
  const sigLength = final[1];
  const signature = final.slice(2, 2 + sigLength);
  const pubkey = final.slice(3 + sigLength);
  assert.equal(verify(4, pubkey, signature), true);
  const flipped = Uint8Array.from(signature);
  flipped[10] ^= 0x01;
  assert.equal(verify(4, pubkey, flipped), false);
  const wrongSighash = Uint8Array.from(signature);
  wrongSighash[wrongSighash.length - 1] = 0x81;
  assert.equal(verify(4, pubkey, wrongSighash), null);
  // A legacy P2PKH input has no BIP-143 sighash here.
  assert.equal(verify(0, pubkey, signature), null);
});
