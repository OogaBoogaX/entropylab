import test from "node:test";
import assert from "node:assert/strict";

import { checkRbfReplacement } from "../src/js/psbt-rbf-check.js";

const TXID_A = "aa".repeat(32);
const TXID_B = "bb".repeat(32);

const OURS = `0014${"11".repeat(20)}`;
const THEIRS = `0014${"22".repeat(20)}`;
const ATTACKER = `0014${"33".repeat(20)}`;
const OP_RETURN_A = "6a0b68656c6c6f20776f726c64";
const OP_RETURN_B = "6a0b68656c6c6f207468657265";

const input = (txid, vout, overrides = {}) => ({
  txid,
  vout,
  sequence: 0xfffffffd,
  sighash: null,
  amount: null,
  amountVerified: false,
  ...overrides,
});

const output = (script, amount) => ({ script, amount });

const transaction = (inputs, outputs, overrides = {}) => ({
  version: 2,
  locktime: 0,
  inputs,
  outputs,
  ...overrides,
});

const codes = (result) => result.items.map((item) => item.code);
const itemWith = (result, code) => result.items.find((item) => item.code === code);
const ownsOnly = (ours) => (script) => script === ours;

test("a clean fee bump of the change output is green", () => {
  const original = transaction([input(TXID_A, 0)], [output(THEIRS, 100000n), output(OURS, 50000n)]);
  const replacement = transaction([input(TXID_A, 0)], [output(THEIRS, 100000n), output(OURS, 49000n)]);
  const result = checkRbfReplacement({ original, replacement, ownsScript: ownsOnly(OURS) });
  assert.equal(result.verdict, "green");
  assert.deepEqual(result.feeIncrease, { sats: 1000n, basis: "outputs" });
  assert.equal(result.feeComplete, true);
  assert.deepEqual(codes(result), ["change-decreased"]);
  assert.deepEqual(result.addedInputs, []);
  assert.deepEqual(result.droppedInputs, []);
});

test("a reduced recipient payment is red when ownership is known", () => {
  const original = transaction([input(TXID_A, 0)], [output(THEIRS, 100000n), output(OURS, 50000n)]);
  const replacement = transaction([input(TXID_A, 0)], [output(THEIRS, 99000n), output(OURS, 50000n)]);
  const result = checkRbfReplacement({ original, replacement, ownsScript: ownsOnly(OURS) });
  assert.equal(result.verdict, "red");
  const changed = itemWith(result, "payment-changed");
  assert.ok(changed);
  assert.equal(changed.script, THEIRS);
  assert.equal(changed.before, 100000n);
  assert.equal(changed.after, 99000n);
  assert.deepEqual(result.feeIncrease, { sats: 1000n, basis: "outputs" });
});

test("a reduced output with unknown ownership is amber and never green", () => {
  const original = transaction([input(TXID_A, 0)], [output(THEIRS, 100000n), output(OURS, 50000n)]);
  const replacement = transaction([input(TXID_A, 0)], [output(THEIRS, 99000n), output(OURS, 50000n)]);
  const result = checkRbfReplacement({ original, replacement, ownsScript: null });
  assert.equal(result.verdict, "amber");
  const decreased = itemWith(result, "output-decreased-unverified");
  assert.ok(decreased);
  assert.equal(decreased.script, THEIRS);
  assert.equal(decreased.before, 100000n);
  assert.equal(decreased.after, 99000n);
  assert.match(decreased.message, /Check that it is your change/);
  assert.ok(!codes(result).includes("change-decreased"));
});

test("replacing the recipient with an attacker script is red", () => {
  const original = transaction([input(TXID_A, 0)], [output(THEIRS, 100000n), output(OURS, 50000n)]);
  const replacement = transaction([input(TXID_A, 0)], [output(ATTACKER, 100000n), output(OURS, 49000n)]);
  const result = checkRbfReplacement({ original, replacement, ownsScript: ownsOnly(OURS) });
  assert.equal(result.verdict, "red");
  const removed = itemWith(result, "payment-removed");
  assert.ok(removed);
  assert.equal(removed.script, THEIRS);
  assert.equal(removed.before, 100000n);
  const added = itemWith(result, "new-output-unverified");
  assert.ok(added);
  assert.equal(added.script, ATTACKER);
  assert.equal(added.after, 100000n);
});

test("two decreased outputs are red", () => {
  const original = transaction([input(TXID_A, 0)], [output(OURS, 50000n), output(THEIRS, 100000n)]);
  const replacement = transaction([input(TXID_A, 0)], [output(OURS, 49000n), output(THEIRS, 99000n)]);
  const result = checkRbfReplacement({ original, replacement, ownsScript: null });
  assert.equal(result.verdict, "red");
  assert.ok(codes(result).includes("multiple-decreases"));
  assert.equal(codes(result).filter((code) => code === "output-decreased-unverified").length, 2);
});

test("a dropped input is amber and leaves the fee incomplete", () => {
  const original = transaction([input(TXID_A, 0), input(TXID_B, 1)], [output(THEIRS, 100000n), output(OURS, 50000n)]);
  const replacement = transaction([input(TXID_A, 0)], [output(THEIRS, 100000n), output(OURS, 49000n)]);
  const result = checkRbfReplacement({ original, replacement, ownsScript: ownsOnly(OURS) });
  assert.equal(result.verdict, "amber");
  assert.deepEqual(result.droppedInputs, [{ txid: TXID_B, vout: 1 }]);
  assert.deepEqual(result.addedInputs, []);
  assert.equal(result.feeComplete, false);
  assert.equal(result.feeIncrease, null);
  assert.ok(codes(result).includes("input-dropped"));
  assert.ok(codes(result).includes("fee-incomplete"));
});

test("a verified added input gives the verified-amounts basis", () => {
  const original = transaction([input(TXID_A, 0)], [output(THEIRS, 100000n), output(OURS, 50000n)]);
  const replacement = transaction(
    [input(TXID_A, 0), input(TXID_B, 1, { amount: 60000n, amountVerified: true })],
    [output(THEIRS, 100000n), output(OURS, 50000n)],
  );
  const result = checkRbfReplacement({ original, replacement, ownsScript: ownsOnly(OURS) });
  assert.deepEqual(result.addedInputs, [{ txid: TXID_B, vout: 1 }]);
  assert.deepEqual(result.feeIncrease, { sats: 60000n, basis: "verified-amounts" });
  assert.equal(result.feeComplete, true);
  assert.ok(codes(result).includes("input-added"));
});

test("an unverified added input leaves the fee incomplete", () => {
  const original = transaction([input(TXID_A, 0)], [output(THEIRS, 100000n), output(OURS, 50000n)]);
  const replacement = transaction(
    [input(TXID_A, 0), input(TXID_B, 1, { amount: 60000n, amountVerified: false })],
    [output(THEIRS, 100000n), output(OURS, 50000n)],
  );
  const result = checkRbfReplacement({ original, replacement, ownsScript: ownsOnly(OURS) });
  assert.deepEqual(result.addedInputs, [{ txid: TXID_B, vout: 1 }]);
  assert.equal(result.feeIncrease, null);
  assert.equal(result.feeComplete, false);
  assert.ok(codes(result).includes("fee-incomplete"));
});

test("a verified flag without an amount still leaves the fee incomplete", () => {
  const original = transaction([input(TXID_A, 0)], [output(THEIRS, 100000n), output(OURS, 50000n)]);
  const replacement = transaction(
    [input(TXID_A, 0), input(TXID_B, 1, { amount: null, amountVerified: true })],
    [output(THEIRS, 100000n), output(OURS, 50000n)],
  );
  const result = checkRbfReplacement({ original, replacement, ownsScript: ownsOnly(OURS) });
  assert.equal(result.feeIncrease, null);
  assert.equal(result.feeComplete, false);
  assert.ok(codes(result).includes("fee-incomplete"));
});

test("duplicate outputs are matched one for one", () => {
  const original = transaction(
    [input(TXID_A, 0)],
    [output(THEIRS, 100000n), output(THEIRS, 100000n), output(OURS, 50000n)],
  );
  const replacement = transaction([input(TXID_A, 0)], [output(THEIRS, 100000n), output(OURS, 50000n)]);
  const result = checkRbfReplacement({ original, replacement, ownsScript: ownsOnly(OURS) });
  assert.equal(result.verdict, "red");
  assert.equal(codes(result).filter((code) => code === "payment-removed").length, 1);
});

test("reordering outputs alone is not a change", () => {
  const original = transaction([input(TXID_A, 0)], [output(THEIRS, 100000n), output(OURS, 50000n)]);
  const reordered = transaction([input(TXID_A, 0)], [output(OURS, 50000n), output(THEIRS, 100000n)]);
  const plain = checkRbfReplacement({ original, replacement: reordered, ownsScript: ownsOnly(OURS) });
  assert.deepEqual(codes(plain), ["fee-not-increased"]);

  const bumped = transaction([input(TXID_A, 0)], [output(OURS, 49000n), output(THEIRS, 100000n)]);
  const result = checkRbfReplacement({ original, replacement: bumped, ownsScript: ownsOnly(OURS) });
  assert.equal(result.verdict, "green");
  assert.deepEqual(codes(result), ["change-decreased"]);
});

test("an OP_RETURN output change is detected", () => {
  const original = transaction([input(TXID_A, 0)], [output(THEIRS, 100000n), output(OP_RETURN_A, 0n)]);
  const replacement = transaction([input(TXID_A, 0)], [output(THEIRS, 100000n), output(OP_RETURN_B, 0n)]);
  const result = checkRbfReplacement({ original, replacement, ownsScript: null });
  assert.equal(result.verdict, "red");
  const removed = itemWith(result, "payment-removed");
  assert.ok(removed);
  assert.equal(removed.script, OP_RETURN_A);
  const added = itemWith(result, "new-output-unverified");
  assert.ok(added);
  assert.equal(added.script, OP_RETURN_B);
});

test("version and locktime changes are amber", () => {
  const original = transaction([input(TXID_A, 0)], [output(THEIRS, 100000n), output(OURS, 50000n)]);
  const replacement = transaction(
    [input(TXID_A, 0)],
    [output(THEIRS, 100000n), output(OURS, 49000n)],
    { version: 1, locktime: 800000 },
  );
  const result = checkRbfReplacement({ original, replacement, ownsScript: ownsOnly(OURS) });
  assert.equal(result.verdict, "amber");
  assert.ok(codes(result).includes("version-changed"));
  assert.ok(codes(result).includes("locktime-changed"));
});

test("a sequence change on a kept input is amber", () => {
  const original = transaction([input(TXID_A, 0)], [output(THEIRS, 100000n), output(OURS, 50000n)]);
  const replacement = transaction(
    [input(TXID_A, 0, { sequence: 0xffffffff })],
    [output(THEIRS, 100000n), output(OURS, 49000n)],
  );
  const result = checkRbfReplacement({ original, replacement, ownsScript: ownsOnly(OURS) });
  assert.equal(result.verdict, "amber");
  const changed = itemWith(result, "sequence-changed");
  assert.ok(changed);
  assert.equal(changed.txid, TXID_A);
  assert.equal(changed.vout, 0);
});

test("a sighash change on a kept input is amber", () => {
  const original = transaction([input(TXID_A, 0, { sighash: 1 })], [output(THEIRS, 100000n), output(OURS, 50000n)]);
  const replacement = transaction([input(TXID_A, 0, { sighash: 2 })], [output(THEIRS, 100000n), output(OURS, 49000n)]);
  const result = checkRbfReplacement({ original, replacement, ownsScript: ownsOnly(OURS) });
  assert.equal(result.verdict, "amber");
  assert.ok(codes(result).includes("sighash-changed"));
  assert.ok(codes(result).includes("sighash-not-all"));
});

test("a non-ALL sighash on a replacement input is amber", () => {
  const original = transaction([input(TXID_A, 0)], [output(THEIRS, 100000n), output(OURS, 50000n)]);
  const replacement = transaction([input(TXID_A, 0, { sighash: 0x81 })], [output(THEIRS, 100000n), output(OURS, 49000n)]);
  const result = checkRbfReplacement({ original, replacement, ownsScript: ownsOnly(OURS) });
  assert.equal(result.verdict, "amber");
  const item = itemWith(result, "sighash-not-all");
  assert.ok(item);
  assert.equal(item.sighash, 0x81);
});

test("a replacement that does not raise the fee is amber", () => {
  const original = transaction([input(TXID_A, 0)], [output(THEIRS, 100000n), output(OURS, 50000n)]);
  const replacement = transaction([input(TXID_A, 0)], [output(THEIRS, 100000n), output(OURS, 50000n)]);
  const result = checkRbfReplacement({ original, replacement, ownsScript: ownsOnly(OURS) });
  assert.equal(result.verdict, "amber");
  const item = itemWith(result, "fee-not-increased");
  assert.ok(item);
  assert.equal(item.sats, 0n);
});

test("transactions with no shared input are neutral", () => {
  const original = transaction([input(TXID_A, 0)], [output(THEIRS, 100000n)]);
  const replacement = transaction([input(TXID_B, 1)], [output(THEIRS, 99000n)]);
  const result = checkRbfReplacement({ original, replacement, ownsScript: ownsOnly(OURS) });
  assert.equal(result.verdict, "neutral");
  assert.deepEqual(codes(result), ["no-shared-inputs"]);
});

test("ownsScript is only asked about changed, removed and new outputs", () => {
  const original = transaction(
    [input(TXID_A, 0)],
    [output(THEIRS, 100000n), output(OURS, 50000n), output(OP_RETURN_A, 0n)],
  );
  const replacement = transaction(
    [input(TXID_A, 0)],
    [output(ATTACKER, 100000n), output(OURS, 49000n), output(OP_RETURN_B, 0n)],
  );
  const asked = [];
  const result = checkRbfReplacement({
    original,
    replacement,
    ownsScript: (script) => {
      asked.push(script);
      return script === OURS;
    },
  });
  assert.equal(asked.length, 5);
  assert.deepEqual([...asked].sort(), [THEIRS, OURS, OP_RETURN_A, ATTACKER, OP_RETURN_B].sort());
  assert.equal(result.verdict, "red");
});

test("malformed input throws TypeError", () => {
  const good = transaction([input(TXID_A, 0)], [output(THEIRS, 100000n)]);
  const cases = [
    undefined,
    {},
    { original: good, replacement: null },
    { original: good, replacement: good, ownsScript: "yes" },
    { original: { ...good, inputs: [{ ...input(TXID_A, 0), txid: TXID_A.toUpperCase() }] }, replacement: good },
    { original: { ...good, inputs: [{ ...input(TXID_A, 0), vout: -1 }] }, replacement: good },
    { original: { ...good, inputs: [{ ...input(TXID_A, 0), amount: 1000 }] }, replacement: good },
    { original: { ...good, inputs: [{ ...input(TXID_A, 0), amountVerified: undefined }] }, replacement: good },
    { original: { ...good, inputs: [{ ...input(TXID_A, 0), sighash: "1" }] }, replacement: good },
    { original: { ...good, inputs: [input(TXID_A, 0), input(TXID_A, 0)] }, replacement: good },
    { original: { ...good, outputs: [{ script: THEIRS, amount: 1000 }] }, replacement: good },
    { original: { ...good, outputs: [{ script: `0014${"AB".repeat(20)}`, amount: 1000n }] }, replacement: good },
    { original: { ...good, outputs: [{ script: "abc", amount: 1000n }] }, replacement: good },
    { original: { ...good, version: "2" }, replacement: good },
  ];
  for (const value of cases) {
    assert.throws(() => checkRbfReplacement(value), TypeError);
  }
});
