import test from "node:test";
import assert from "node:assert/strict";
import { psbtPrivacySignals } from "../src/js/psbt-privacy-signals.js";

const bytes = (...values) => Uint8Array.from(values);
const hex = (text) => Uint8Array.from(text.match(/../g).map((pair) => Number.parseInt(pair, 16)));
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};
const entry = (type, keydata = new Uint8Array(), val = new Uint8Array()) => ({ type, keydata, val });
// BIP-174 type 6: a 33-byte public key in the key, then fingerprint || path.
const pubkey = concat(bytes(0x02), new Uint8Array(32).fill(0x22));
const keyPath = (fingerprint) => entry(6, pubkey, concat(hex(fingerprint), hex("54000080")));
// BIP-371 type 0x16: a 32-byte x-only key in the key, then
// CompactSize(leaf count) || leaf hashes || fingerprint || path.
const xonly = new Uint8Array(32).fill(0x33);
const tapKeyPath = (fingerprint, leaves = 1) =>
  entry(0x16, xonly, concat(bytes(leaves), new Uint8Array(leaves * 32).fill(0x11), hex(fingerprint), hex("56000080")));

test("mixed finalization: all finalized is not mixed", () => {
  const inputs = [[entry(7)], [entry(8)]];
  assert.equal(psbtPrivacySignals({ inputs, outputs: [] }).mixedFinalization, false);
});

test("mixed finalization: none finalized is not mixed", () => {
  const inputs = [[entry(0)], [entry(2)]];
  assert.equal(psbtPrivacySignals({ inputs, outputs: [] }).mixedFinalization, false);
});

test("mixed finalization: one finalized and one not is mixed", () => {
  const inputs = [[entry(7)], [entry(0)]];
  assert.equal(psbtPrivacySignals({ inputs, outputs: [] }).mixedFinalization, true);
});

test("mixed finalization: a type 7 entry with keydata does not count", () => {
  assert.equal(psbtPrivacySignals({ inputs: [[entry(7, bytes(0xaa))]], outputs: [] }).mixedFinalization, false);
  assert.equal(psbtPrivacySignals({ inputs: [[entry(7, bytes(0xaa))], [entry(7)]], outputs: [] }).mixedFinalization, true);
});

test("origin groups: different fingerprints are different groups", () => {
  const inputs = [[keyPath("aabbccdd")], [keyPath("11223344")]];
  assert.equal(psbtPrivacySignals({ inputs, outputs: [] }).originGroups, 2);
});

test("origin groups: a shared multisig fingerprint set is one group", () => {
  const prints = ["aaaaaaaa", "bbbbbbbb", "cccccccc"];
  const inputs = [prints.map(keyPath), prints.map(keyPath)];
  assert.equal(psbtPrivacySignals({ inputs, outputs: [] }).originGroups, 1);
});

test("origin groups: inputs without fingerprints are ignored", () => {
  const inputs = [[keyPath("aabbccdd")], [entry(0)]];
  assert.equal(psbtPrivacySignals({ inputs, outputs: [] }).originGroups, 1);
});

test("origin groups: a taproot key path reads the fingerprint after its leaf hashes", () => {
  assert.equal(psbtPrivacySignals({ inputs: [[tapKeyPath("deadbeef", 1)], [keyPath("deadbeef")]], outputs: [] }).originGroups, 1);
  assert.equal(psbtPrivacySignals({ inputs: [[tapKeyPath("deadbeef", 1)], [keyPath("cafebabe")]], outputs: [] }).originGroups, 2);
});

test("origin groups: malformed values are skipped without throwing", () => {
  const inputs = [
    [entry(6, pubkey, bytes(0xaa, 0xbb, 0xcc))],
    [entry(0x16, xonly, bytes(0xfd, 0x01))],
    [entry(0x16, xonly, bytes(0x02, 0x11))],
  ];
  assert.equal(psbtPrivacySignals({ inputs, outputs: [] }).originGroups, 0);
});

// Astra, round 1: a fingerprint followed by a truncated path element, or a
// record without its public key, names no master key.
test("origin groups: a record that is not a BIP-32 origin is skipped", () => {
  const truncated = [[entry(6, pubkey, hex("aabbccdd01"))], [entry(6, pubkey, hex("1122334401"))]];
  assert.equal(psbtPrivacySignals({ inputs: truncated, outputs: [] }).originGroups, 0);
  const keyless = [[entry(6, new Uint8Array(), hex("aabbccdd"))], [entry(0x16, new Uint8Array(), concat(bytes(0), hex("11223344")))]];
  assert.equal(psbtPrivacySignals({ inputs: keyless, outputs: [] }).originGroups, 0);
  const tapTruncated = [[entry(0x16, xonly, concat(bytes(0), hex("aabbccdd"), bytes(1)))]];
  assert.equal(psbtPrivacySignals({ inputs: tapTruncated, outputs: [] }).originGroups, 0);
});

// BIP-371's own layout, with no leaf hashes: the fingerprint follows the
// CompactSize count directly (there is no key-origin count).
test("origin groups: BIP-371 key-path value with no leaf hashes", () => {
  const value = hex("00" + "d90c6a4f" + "00000000");
  const signals = psbtPrivacySignals({ inputs: [[entry(0x16, xonly, value)], [keyPath("d90c6a4f")]], outputs: [] });
  assert.equal(signals.originGroups, 1);
  assert.equal(signals.masterKeys, 1);
});

// GLM, round 1: {A, B}, {A}, {C} is two groups of inputs but three master
// keys; the line names the keys.
test("master keys: counted across groups, not as groups", () => {
  const inputs = [[keyPath("aaaaaaaa"), keyPath("bbbbbbbb")], [keyPath("aaaaaaaa")], [keyPath("cccccccc")]];
  const signals = psbtPrivacySignals({ inputs, outputs: [] });
  assert.equal(signals.originGroups, 2);
  assert.equal(signals.masterKeys, 3);
});

test("equal outputs: three equal non-zero amounts form one group", () => {
  const outputs = [{ amount: 100000n }, { amount: 100000n }, { amount: 100000n }];
  assert.deepEqual(psbtPrivacySignals({ inputs: null, outputs }).equalOutputs, [{ amount: 100000n, count: 3 }]);
});

test("equal outputs: zero amounts never group", () => {
  const outputs = [{ amount: 0n }, { amount: 0n }, { amount: 0n }];
  assert.deepEqual(psbtPrivacySignals({ inputs: null, outputs }).equalOutputs, []);
});

test("equal outputs: at most the three largest groups", () => {
  const outputs = [
    { amount: 1n }, { amount: 1n },
    { amount: 2n }, { amount: 2n }, { amount: 2n }, { amount: 2n }, { amount: 2n },
    { amount: 3n }, { amount: 3n }, { amount: 3n },
    { amount: 4n }, { amount: 4n }, { amount: 4n }, { amount: 4n },
  ];
  assert.deepEqual(psbtPrivacySignals({ inputs: null, outputs }).equalOutputs, [
    { amount: 2n, count: 5 },
    { amount: 4n, count: 4 },
    { amount: 3n, count: 3 },
  ]);
});

test("a raw transaction has no key paths or signing state", () => {
  const signals = psbtPrivacySignals({ inputs: null, outputs: [{ amount: 5000n }, { amount: 5000n }] });
  assert.equal(signals.available, false);
  assert.equal(signals.mixedFinalization, false);
  assert.equal(signals.originGroups, 0);
  assert.equal(signals.masterKeys, 0);
  assert.deepEqual(signals.equalOutputs, [{ amount: 5000n, count: 2 }]);
});

// Kimi, GLM, round 1: past the bounds nothing is said, not the raw-transaction
// line about a PSBT.
test("over the input bound returns null", () => {
  const inputs = Array.from({ length: 10001 }, () => []);
  assert.equal(psbtPrivacySignals({ inputs, outputs: [{ amount: 1n }, { amount: 1n }] }), null);
});

test("over the output bound returns null", () => {
  const outputs = Array.from({ length: 10001 }, () => ({ amount: 1n }));
  assert.equal(psbtPrivacySignals({ inputs: [[entry(7)]], outputs }), null);
  assert.equal(psbtPrivacySignals({ inputs: null, outputs }), null);
});
