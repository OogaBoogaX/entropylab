// MuSig2 (BIP-327) key aggregation and Taproot (BIP-341) commitment checks.
// Expected values come from the BIP-327 / BIP-373 fixtures under
// test/fixtures/musig2, never from the module under test.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { keyAggExport, keyAggregate } from "@scure/btc-signer/musig2.js";
import { secp256k1 } from "../src/js/secp256k1.js";
import { psbtInspectDoc } from "../src/js/psbt-wasm.js";
import {
  applyTweak,
  crossCheckKeyAgg,
  keyAgg,
  keySort,
  musig2PsbtEvidence,
  plain,
  taprootOutputKey,
  xonly,
} from "../src/js/musig2-verify.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const fixture = (name) => JSON.parse(readFileSync(join(root, "test/fixtures/musig2", name), "utf8"));

const hexToBytes = (hex) => {
  assert.match(hex, /^(?:[0-9a-fA-F]{2})*$/, "fixture hex");
  return Uint8Array.from(hex.match(/../g) ?? [], (byte) => parseInt(byte, 16));
};
const bytesToHex = (bytes) => [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
const lower = (hex) => hex.toLowerCase();

// A key is usable only as a 33-byte compressed point; libsecp256k1 decides,
// not the module under test.
const isValidPoint = (key) => {
  if (key.length !== 33 || (key[0] !== 0x02 && key[0] !== 0x03)) return false;
  try {
    secp256k1.Point.fromBytes(key);
    return true;
  } catch {
    return false;
  }
};

test("keySort matches the BIP-327 key sorting vectors", () => {
  const vectors = fixture("bip327-key_sort_vectors.json");
  const input = vectors.pubkeys.map(hexToBytes);
  const before = input.map(bytesToHex);
  const sorted = keySort(input);
  assert.deepEqual(sorted.map(bytesToHex), vectors.sorted_pubkeys.map(lower));
  assert.deepEqual(input.map(bytesToHex), before, "the input array is not reordered");
});

test("keyAgg matches the BIP-327 key aggregation vectors", () => {
  const vectors = fixture("bip327-key_agg_vectors.json");
  const pubkeys = vectors.pubkeys.map(hexToBytes);
  for (const testCase of vectors.valid_test_cases) {
    const selected = testCase.key_indices.map((index) => pubkeys[index]);
    assert.equal(bytesToHex(xonly(keyAgg(selected))), lower(testCase.expected), `keys ${testCase.key_indices.join(",")}`);
  }
});

test("keyAgg refuses the BIP-327 invalid contributions", () => {
  const vectors = fixture("bip327-key_agg_vectors.json");
  const pubkeys = vectors.pubkeys.map(hexToBytes);
  const tweaks = vectors.tweaks.map(hexToBytes);
  for (const testCase of vectors.error_test_cases) {
    const selected = testCase.key_indices.map((index) => pubkeys[index]);
    const signer = selected.findIndex((key) => !isValidPoint(key));
    if (signer >= 0) {
      assert.throws(() => keyAgg(selected), (error) => {
        assert.equal(error.type, "invalid_contribution");
        assert.equal(error.contrib, "pubkey");
        assert.equal(error.signer, signer);
        return true;
      }, `keys ${testCase.key_indices.join(",")}`);
      continue;
    }
    // No invalid key: the listed tweak is out of range, which KeyAgg accepts
    // and ApplyTweak refuses.
    const tweakList = (testCase.tweak_indices ?? []).map((index) => tweaks[index]);
    const isXonly = testCase.is_xonly ?? [];
    assert.ok(tweakList.length, "fixture: an error case names a key or a tweak");
    let ctx = keyAgg(selected);
    assert.throws(() => {
      for (let i = 0; i < tweakList.length; i++) ctx = applyTweak(ctx, tweakList[i], !!isXonly[i]);
    }, /tweak/i, `keys ${testCase.key_indices.join(",")}`);
  }
});

test("applyTweak matches the BIP-327 tweak vectors", () => {
  const vectors = fixture("bip327-tweak_vectors.json");
  const pubkeys = vectors.pubkeys.map(hexToBytes);
  const tweaks = vectors.tweaks.map(hexToBytes);
  for (const testCase of vectors.valid_test_cases) {
    // The fixture's expected values are signatures, which need nonces and
    // belong to a later stage; the tweaked key is checked against the
    // independent btc-signer implementation instead.
    const selected = testCase.key_indices.map((index) => pubkeys[index]);
    const tweakList = testCase.tweak_indices.map((index) => tweaks[index]);
    const isXonly = testCase.is_xonly.map(Boolean);
    let ctx = keyAgg(selected);
    for (let i = 0; i < tweakList.length; i++) ctx = applyTweak(ctx, tweakList[i], isXonly[i]);
    assert.equal(
      bytesToHex(plain(ctx)),
      bytesToHex(keyAggregate(selected, tweakList, isXonly).aggPublicKey.toBytes(true)),
      `keys ${testCase.key_indices.join(",")}`,
    );
  }
  for (const testCase of vectors.error_test_cases) {
    const selected = testCase.key_indices.map((index) => pubkeys[index]);
    const tweakList = testCase.tweak_indices.map((index) => tweaks[index]);
    const isXonly = testCase.is_xonly.map(Boolean);
    let ctx = keyAgg(selected);
    assert.throws(() => {
      for (let i = 0; i < tweakList.length; i++) ctx = applyTweak(ctx, tweakList[i], isXonly[i]);
    }, /tweak/i, `keys ${testCase.key_indices.join(",")}`);
  }
});

// BIP-341 wallet test vectors, scriptPubKey section:
// https://github.com/bitcoin/bips/blob/21bfd24d6e397a7d3d169e86be9f6b54f6c8cce0/bip-0341/wallet-test-vectors.json
test("taprootOutputKey matches the BIP-341 wallet test vectors", () => {
  const vectors = [
    ["187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27", "5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21", "147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3"],
    ["93478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820", "c525714a7f49c28aedbbba78c005931a81c234b2f6c99a73e4d06082adc8bf2b", "e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e"],
    ["ee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf3786592", "6c2dc106ab816b73f9d07e3cd1ef2c8c1256f519748e0813e4edd2405d277bef", "712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5"],
    ["f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd8", "ab179431c28d3b68fb798957faf5497d69c883c6fb1e1cd9f81483d87bac90cc", "77e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220"],
    ["e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f", "ccbd66c6f7e8fdab47b3a486f59d28262be857f30d4773f2d5ea47f7761ce0e2", "91b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605"],
    ["55adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d", "2f6b2c5397b6d68ca18e09a3f05161668ffe93a988582d55c6f07bd5b3329def", "75169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831"],
  ];
  for (const [internal, root, expected] of vectors) {
    assert.equal(bytesToHex(taprootOutputKey(hexToBytes(internal), hexToBytes(root))), expected, `internal ${internal}`);
  }
  // No merkle root: the key-path-only tweak.
  assert.equal(
    bytesToHex(taprootOutputKey(hexToBytes("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d"), null)),
    "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343",
  );
});

// ── BIP-373 PSBT vectors ───────────────────────────────────────────────────
const PSBT_MAGIC = /^70736274ff/i;

// The BIP-373 fixture stores each PSBT as base64 (the BIP-174 convention);
// accept a hex PSBT or a byte array too, and normalize every form to
// lowercase hex.
const psbtHex = (text) => {
  const trimmed = text.trim();
  const hex = trimmed.replace(/^0x/i, "");
  if (PSBT_MAGIC.test(hex)) return lower(hex);
  const compact = trimmed.replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(compact)) return null;
  const padded = compact + "=".repeat((4 - (compact.length % 4)) % 4);
  let bytes;
  try {
    bytes = Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
  } catch {
    return null;
  }
  return bytes.length >= 5 && bytesToHex(bytes.slice(0, 5)) === "70736274ff" ? bytesToHex(bytes) : null;
};

// Each vector is labelled from the fixture itself: its `case` and `stage`.
const psbtCases = () => fixture("bip373-vectors.json").vectors.map((vector) => ({
  label: vector.stage ? `${vector.case} / ${vector.stage}` : vector.case,
  validity: vector.validity,
  stage: vector.stage,
  psbt: psbtHex(vector.base64),
}));

const commitmentOf = (label) => {
  if (/a key in a script|derived from/i.test(label)) return "not-checked";
  if (/output key is/i.test(label)) return "verified-output";
  if (/internal key is/i.test(label)) return "verified-internal";
  throw new Error(`unrecognised BIP-373 vector label: ${label}`);
};

test("musig2PsbtEvidence verifies every valid BIP-373 spend vector", () => {
  const spends = psbtCases().filter(({ validity, stage }) => validity === "valid" && stage);
  assert.equal(spends.length, 12, "fixture: twelve valid BIP-373 spend vectors");
  for (const { label, psbt } of spends) {
    assert.ok(psbt, `${label}: base64 decodes to a PSBT`);
    const records = musig2PsbtEvidence(psbtInspectDoc(hexToBytes(psbt)));
    assert.ok(records.length > 0, `${label}: expected MuSig2 evidence`);
    const expected = commitmentOf(label);
    for (const record of records) {
      assert.equal(record.keyAgg, "verified", `${label}: key aggregation`);
      assert.equal(record.commitment, expected, `${label}: commitment`);
      if (expected === "not-checked") {
        assert.equal(record.commitmentReason, "indirect", `${label}: commitment reason`);
      }
    }
  }
});

test("musig2PsbtEvidence verifies the BIP-373 receive vectors", () => {
  const receives = psbtCases().filter(({ validity, stage }) => validity === "valid" && !stage);
  assert.equal(receives.length, 2, "fixture: two valid BIP-373 receive vectors");
  for (const { label, psbt } of receives) {
    assert.ok(psbt, `${label}: base64 decodes to a PSBT`);
    const records = musig2PsbtEvidence(psbtInspectDoc(hexToBytes(psbt)));
    const outputs = records.filter((record) => record.where.scope === "output");
    assert.ok(outputs.length > 0, `${label}: expected output MuSig2 evidence`);
    assert.ok(outputs.some((record) => record.keyAgg === "verified"), `${label}: key aggregation`);
    const expected = commitmentOf(label);
    assert.ok(outputs.some((record) => record.commitment === expected), `${label}: commitment ${expected}`);
  }
});

test("malformed MuSig2 participant fields are reported, never verified", () => {
  const malformed = psbtCases().filter(({ validity }) => validity === "invalid").slice(0, 4);
  assert.equal(malformed.length, 4, "fixture: four malformed participant-field vectors");
  // At the pinned BIP-373 commit, "PSBT with an x-only output participant
  // pubkey" repeats the bytes of "PSBT with x-only aggregate pubkey in output
  // participant pubkeys keydata" (an upstream copy error): its field holds a
  // 32-byte aggregate key and three valid participants, so it is malformed by
  // the aggregate's length. A real x-only output participant is covered by the
  // hand-built test below. If upstream fixes the vector, this falls back to
  // the label.
  const psbtOf = (name) => malformed.find(({ label }) => label === name)?.psbt;
  const outputCaseRepeated = psbtOf("PSBT with an x-only output participant pubkey")
    === psbtOf("PSBT with x-only aggregate pubkey in output participant pubkeys keydata");
  // Vectors rust-bitcoin's parser refuses outright. None observed at this
  // version (BIP-373 fields are kept as unknown pairs); add a label here only
  // if the run shows a refusal, and the test then asserts it throws.
  const expectedRefused = [];
  let reached = 0;
  for (const { label, psbt } of malformed) {
    assert.ok(psbt, `${label}: base64 decodes to a PSBT`);
    if (expectedRefused.includes(label)) {
      assert.throws(() => psbtInspectDoc(hexToBytes(psbt)), `${label}: refused by the parser`);
      continue;
    }
    let doc;
    try {
      doc = psbtInspectDoc(hexToBytes(psbt));
    } catch (error) {
      assert.fail(`${label}: psbtInspectDoc refused the vector (${error.message}); list it in expectedRefused if rust-bitcoin really refuses it`);
    }
    reached += 1;
    const records = musig2PsbtEvidence(doc);
    assert.ok(records.length > 0, `${label}: expected MuSig2 evidence`);
    assert.ok(records.every((record) => record.keyAgg !== "verified"), `${label}: nothing verifies`);
    const xonlyAggregate = /x-only aggregate/i.test(label)
      || (outputCaseRepeated && /x-only output participant/i.test(label));
    const reason = xonlyAggregate ? "aggregate-length" : "participants-length";
    assert.ok(records.some((record) => record.keyAgg === "malformed" && record.reason === reason), `${label}: ${reason}`);
  }
  assert.equal(reached, malformed.length - expectedRefused.length, "every non-refused vector reached musig2PsbtEvidence");
});

test("an x-only participant in an output field is malformed, never verified", () => {
  const vectors = fixture("bip373-vectors.json");
  // The first participant as a 32-byte x-only key: 32 + 33 + 33 bytes.
  const participants = vectors.participants[0].slice(2) + vectors.participants.slice(1).join("");
  const doc = {
    inputs: [],
    outputs: [[{ key: "08" + vectors.aggregatePubkey, value: participants }]],
    tx: { outputs: [{ scriptPubKey: "5120" + "11".repeat(32) }] },
  };
  const records = musig2PsbtEvidence(doc);
  assert.equal(records.length, 1, "the field gets its own record");
  assert.equal(records[0].keyAgg, "malformed");
  assert.equal(records[0].reason, "participants-length");
});

test("nonce and partial-signature vectors do not throw in M1", () => {
  // M1 does not judge nonces or partial signatures; it only must not crash.
  const later = psbtCases().filter(({ validity }) => validity === "invalid").slice(4);
  assert.equal(later.length, 6, "fixture: six nonce/partial-signature invalid vectors");
  // Vectors rust-bitcoin's parser refuses outright. None observed at this
  // version (BIP-373 fields are kept as unknown pairs); add a label here only
  // if the run shows a refusal, and the test then asserts it throws.
  const expectedRefused = [];
  let reached = 0;
  for (const { label, psbt } of later) {
    assert.ok(psbt, `${label}: base64 decodes to a PSBT`);
    if (expectedRefused.includes(label)) {
      assert.throws(() => psbtInspectDoc(hexToBytes(psbt)), `${label}: refused by the parser`);
      continue;
    }
    let doc;
    try {
      doc = psbtInspectDoc(hexToBytes(psbt));
    } catch (error) {
      assert.fail(`${label}: psbtInspectDoc refused the vector (${error.message}); list it in expectedRefused if rust-bitcoin really refuses it`);
    }
    reached += 1;
    assert.doesNotThrow(() => musig2PsbtEvidence(doc), `${label}: evidence does not throw`);
  }
  assert.equal(reached, later.length - expectedRefused.length, "every non-refused vector reached musig2PsbtEvidence");
});

// The MuSig2 field is keylen 0x22, key 0x1a || 33 bytes, then the value.
const musig2Field = (psbtHex) => {
  const hex = lower(psbtHex);
  for (let at = hex.indexOf("221a"); at >= 0; at = hex.indexOf("221a", at + 2)) {
    const keyStart = at + 2;
    const keyEnd = keyStart + 68;
    if (keyEnd + 2 > hex.length) continue;
    const length = parseInt(hex.slice(keyEnd, keyEnd + 2), 16);
    if (!Number.isInteger(length) || length < 33) continue;
    const valueStart = keyEnd + 2;
    const valueEnd = valueStart + length * 2;
    if (valueEnd > hex.length) continue;
    return { keyStart, keyEnd, valueStart, valueEnd, length };
  }
  return null;
};

const replaceRange = (hex, start, end, replacement) => hex.slice(0, start) + replacement + hex.slice(end);

const firstMusig2Case = () => {
  const found = psbtCases().find(({ psbt }) => musig2Field(psbt));
  assert.ok(found, "fixture: a PSBT carrying a MuSig2 participant field");
  return found;
};

test("a flipped participant bit is never verified", () => {
  const { psbt } = firstMusig2Case();
  const field = musig2Field(psbt);
  const value = lower(psbt).slice(field.valueStart, field.valueEnd);
  const flipped = value.slice(0, 2)
    + ((parseInt(value.slice(2, 4), 16) ^ 0x01).toString(16).padStart(2, "0"))
    + value.slice(4);
  const mutated = replaceRange(lower(psbt), field.valueStart, field.valueEnd, flipped);
  const records = musig2PsbtEvidence(psbtInspectDoc(hexToBytes(mutated)));
  const record = records.find((item) => item.participants === flipped);
  assert.ok(record, "the mutated field is reported");
  assert.notEqual(record.keyAgg, "verified");
});

test("swapped participants are a mismatch", () => {
  const candidates = psbtCases().filter(({ psbt }) => {
    const field = musig2Field(psbt);
    if (!field || field.length < 66) return false;
    const value = lower(psbt).slice(field.valueStart, field.valueEnd);
    return value.slice(0, 66) !== value.slice(66, 132);
  });
  assert.ok(candidates.length, "fixture: a PSBT with two distinct participants");
  const { psbt } = candidates[0];
  const field = musig2Field(psbt);
  const value = lower(psbt).slice(field.valueStart, field.valueEnd);
  const swapped = value.slice(66, 132) + value.slice(0, 66) + value.slice(132);
  const mutated = replaceRange(lower(psbt), field.valueStart, field.valueEnd, swapped);
  const records = musig2PsbtEvidence(psbtInspectDoc(hexToBytes(mutated)));
  const record = records.find((item) => item.participants === swapped);
  assert.ok(record, "the mutated field is reported");
  assert.equal(record.keyAgg, "mismatch");
});

test("a participant list that is not a multiple of 33 bytes is malformed", () => {
  const { psbt } = firstMusig2Case();
  const field = musig2Field(psbt);
  const value = lower(psbt).slice(field.valueStart, field.valueEnd);
  const shortened = value.slice(0, -2);
  const length = (field.length - 1).toString(16).padStart(2, "0");
  const mutated = replaceRange(lower(psbt), field.keyEnd, field.valueEnd, length + shortened);
  const records = musig2PsbtEvidence(psbtInspectDoc(hexToBytes(mutated)));
  const record = records.find((item) => item.participants === shortened);
  assert.ok(record, "the mutated field is reported");
  assert.equal(record.keyAgg, "malformed");
});

// Every P2TR scriptPubKey in the PSBT is 0x22 || 0x51 0x20 || 32 bytes.
const flipTaprootKeys = (hex) => {
  let out = hex;
  let at = out.indexOf("225120");
  while (at >= 0) {
    const keyStart = at + 6;
    const first = (parseInt(out.slice(keyStart, keyStart + 2), 16) ^ 0x01).toString(16).padStart(2, "0");
    out = out.slice(0, keyStart) + first + out.slice(keyStart + 2);
    at = out.indexOf("225120", at + 6);
  }
  return out;
};

test("a changed Taproot output key is a commitment mismatch", () => {
  let target = null;
  let mutated = null;
  for (const { psbt } of psbtCases()) {
    const before = musig2PsbtEvidence(psbtInspectDoc(hexToBytes(psbt)));
    const record = before.find((item) => item.commitment === "verified-internal");
    if (!record) continue;
    const changed = flipTaprootKeys(lower(psbt));
    if (changed === lower(psbt)) continue;
    target = record;
    mutated = changed;
    break;
  }
  assert.ok(target, "fixture: an internal-key vector with a P2TR scriptPubKey");
  const after = musig2PsbtEvidence(psbtInspectDoc(hexToBytes(mutated)));
  const changed = after.find((item) => item.where.scope === target.where.scope && item.where.index === target.where.index);
  assert.ok(changed, "the mutated record is reported");
  assert.equal(changed.commitment, "mismatch");
});

// ── Differential check against btc-signer ──────────────────────────────────
const ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

const seeded = (seed) => {
  let state = seed;
  return () => {
    state = (state + 0x9e3779b97f4a7c15n) & 0xffffffffffffffffn;
    let z = state;
    z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & 0xffffffffffffffffn;
    z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & 0xffffffffffffffffn;
    return z ^ (z >> 31n);
  };
};

const scalarBytes = (value) => {
  const out = new Uint8Array(32);
  let rest = value;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  return out;
};

test("this module and btc-signer agree on 200 seeded participant sets", () => {
  const next = seeded(0x5eedn);
  const pool = [];
  for (let i = 0; i < 8; i++) {
    const scalar = (next() % (ORDER - 1n)) + 1n;
    pool.push(secp256k1.Point.BASE.multiply(scalar).toBytes(true));
  }
  for (let round = 0; round < 200; round++) {
    const size = Number(next() % 8n) + 1;
    const pubkeys = [];
    for (let i = 0; i < size; i++) pubkeys.push(pool[Number(next() % 8n)]);
    const tweakCount = Number(next() % 4n);
    const tweaks = [];
    const isXonly = [];
    for (let i = 0; i < tweakCount; i++) {
      tweaks.push(scalarBytes(next() % ORDER));
      isXonly.push((next() & 1n) === 1n);
    }
    let ctx = keyAgg(pubkeys);
    for (let i = 0; i < tweaks.length; i++) ctx = applyTweak(ctx, tweaks[i], isXonly[i]);
    const mine = plain(ctx);
    const agg = keyAggregate(
      pubkeys.map((key) => key.slice()),
      tweaks.map((tweak) => tweak.slice()),
      isXonly,
    );
    // keyAggExport is BIP-327's x-only export (32 bytes); the full point,
    // parity included, comes from the aggregate context itself.
    assert.equal(bytesToHex(xonly(ctx)), bytesToHex(keyAggExport(agg)), `round ${round}: btc-signer x-only`);
    assert.equal(bytesToHex(mine), bytesToHex(agg.aggPublicKey.toBytes(true)), `round ${round}: btc-signer point`);
    assert.equal(bytesToHex(mine), bytesToHex(crossCheckKeyAgg(pubkeys, tweaks, isXonly)), `round ${round}: cross-check`);
  }
});

// Claude's review of round 2: BIP-373 allows one participant field per
// aggregate key, and a second or repeated entry must never be skipped.
test("every MuSig2 participant field on an input gets its own record", () => {
  const { psbt } = firstMusig2Case();
  const doc = psbtInspectDoc(hexToBytes(psbt));
  const index = doc.inputs.findIndex((input) => input.some((pair) => /^1a/i.test(pair.key) && pair.key.length === 68));
  assert.ok(index >= 0, "fixture: an input with a MuSig2 participant field");
  const original = doc.inputs[index].find((pair) => /^1a/i.test(pair.key) && pair.key.length === 68);
  const before = musig2PsbtEvidence(doc).length;
  // The same participants under a different claimed aggregate key: the
  // second entry must be reported, and must not verify.
  const otherAggregate = bytesToHex(plain(keyAgg([hexToBytes(fixture("bip373-vectors.json").participants[0])])));
  doc.inputs[index].push({ key: "1a" + otherAggregate, value: original.value });
  const records = musig2PsbtEvidence(doc);
  assert.equal(records.length, before + 1, "the second participant field is reported");
  const added = records.find((record) => record.aggregate === otherAggregate);
  assert.ok(added, "the added entry has its own record");
  assert.equal(added.keyAgg, "mismatch");
});

// Claude's review of round 2: an output committing to a script tree this
// stage cannot hash is "not-checked", never a false "mismatch".
test("an output with a script tree is not-checked, not a mismatch", () => {
  const vectors = fixture("bip373-vectors.json");
  const aggregate = vectors.aggregatePubkey;
  const participants = vectors.participants.join("");
  const internal = hexToBytes(aggregate).slice(1);
  const root = new Uint8Array(32).fill(7);
  const outputKey = taprootOutputKey(internal, root);
  const outputDoc = (withTree) => ({
    inputs: [],
    outputs: [[
      { key: "08" + aggregate, value: participants },
      { key: "05", value: bytesToHex(internal) },
      ...(withTree ? [{ key: "06", value: "00c0" + "01" + "51" }] : []),
    ]],
    tx: { outputs: [{ scriptPubKey: "5120" + bytesToHex(outputKey) }] },
  });
  const [withTree] = musig2PsbtEvidence(outputDoc(true));
  assert.equal(withTree.keyAgg, "verified");
  assert.equal(withTree.commitment, "not-checked");
  // Without the tree field the same output is checked as key-path only, and
  // the root it really commits to makes that a mismatch.
  const [withoutTree] = musig2PsbtEvidence(outputDoc(false));
  assert.equal(withoutTree.commitment, "mismatch");
});

test("a MuSig2 internal key with a merkle root commits to the tweaked output key", () => {
  const vectors = fixture("bip373-vectors.json");
  const aggregate = vectors.aggregatePubkey;
  const participants = vectors.participants.join("");
  const internal = hexToBytes(aggregate).slice(1);
  const root = new Uint8Array(32).fill(0x42);
  const outputKey = taprootOutputKey(internal, root);
  const witnessUtxo = "0000000000000000" + "22" + "5120" + bytesToHex(outputKey);
  const doc = (merkleRoot) => ({
    inputs: [[
      { key: "1a" + aggregate, value: participants },
      { key: "17", value: bytesToHex(internal) },
      { key: "18", value: bytesToHex(merkleRoot) },
      { key: "01", value: witnessUtxo },
    ]],
    outputs: [],
    tx: { outputs: [] },
  });
  const [record] = musig2PsbtEvidence(doc(root));
  assert.equal(record.keyAgg, "verified");
  assert.equal(record.commitment, "verified-internal");
  const flipped = root.slice();
  flipped[0] ^= 0x01;
  const [changed] = musig2PsbtEvidence(doc(flipped));
  assert.equal(changed.commitment, "mismatch");
});

test("a 1-byte witness UTXO is malformed, not absent", () => {
  const vectors = fixture("bip373-vectors.json");
  const aggregate = vectors.aggregatePubkey;
  const participants = vectors.participants.join("");
  const doc = {
    inputs: [[
      { key: "1a" + aggregate, value: participants },
      { key: "01", value: "00" },
    ]],
    outputs: [],
    tx: { outputs: [] },
  };
  const [record] = musig2PsbtEvidence(doc);
  assert.equal(record.commitment, "malformed");
  assert.equal(record.commitmentReason, "witness-utxo");
});

test("a 31-byte TAP_INTERNAL_KEY is malformed, not absent", () => {
  const vectors = fixture("bip373-vectors.json");
  const aggregate = vectors.aggregatePubkey;
  const participants = vectors.participants.join("");
  const doc = {
    inputs: [[
      { key: "1a" + aggregate, value: participants },
      { key: "17", value: "00".repeat(31) },
    ]],
    outputs: [],
    tx: { outputs: [] },
  };
  const [record] = musig2PsbtEvidence(doc);
  assert.equal(record.commitment, "malformed");
  assert.equal(record.commitmentReason, "internal-key");
});

test("two 0x17 pairs are a duplicate field", () => {
  const vectors = fixture("bip373-vectors.json");
  const aggregate = vectors.aggregatePubkey;
  const participants = vectors.participants.join("");
  const internal = bytesToHex(hexToBytes(aggregate).slice(1));
  const doc = {
    inputs: [[
      { key: "1a" + aggregate, value: participants },
      { key: "17", value: internal },
      { key: "17", value: internal },
    ]],
    outputs: [],
    tx: { outputs: [] },
  };
  const [record] = musig2PsbtEvidence(doc);
  assert.equal(record.commitment, "malformed");
  assert.equal(record.commitmentReason, "duplicate-field");
});

test("an output whose tx script and PSBT_OUT_SCRIPT differ is a mismatch", () => {
  const vectors = fixture("bip373-vectors.json");
  const aggregate = vectors.aggregatePubkey;
  const participants = vectors.participants.join("");
  const internal = hexToBytes(aggregate).slice(1);
  const outputKey = taprootOutputKey(internal, null);
  const doc = {
    inputs: [],
    outputs: [[
      { key: "08" + aggregate, value: participants },
      { key: "05", value: bytesToHex(internal) },
      { key: "04", value: "5120" + "00".repeat(32) },
    ]],
    tx: { outputs: [{ scriptPubKey: "5120" + bytesToHex(outputKey) }] },
  };
  const [record] = musig2PsbtEvidence(doc);
  assert.equal(record.commitment, "mismatch");
  assert.equal(record.commitmentReason, "script-conflict");
});

test("a non-hex PSBT_OUT_SCRIPT is malformed, not missing", () => {
  const vectors = fixture("bip373-vectors.json");
  const aggregate = vectors.aggregatePubkey;
  const participants = vectors.participants.join("");
  const doc = {
    inputs: [],
    outputs: [[
      { key: "08" + aggregate, value: participants },
      { key: "04", value: "zz" },
    ]],
    tx: { outputs: [] },
  };
  const [record] = musig2PsbtEvidence(doc);
  assert.equal(record.commitment, "malformed");
  assert.equal(record.commitmentReason, "output-script");
});

test("a P2WPKH script is missing, not taproot", () => {
  const vectors = fixture("bip373-vectors.json");
  const aggregate = vectors.aggregatePubkey;
  const participants = vectors.participants.join("");
  const doc = {
    inputs: [[
      { key: "1a" + aggregate, value: participants },
      { key: "01", value: "0000000000000000" + "16" + "0014" + "00".repeat(20) },
    ]],
    outputs: [],
    tx: { outputs: [] },
  };
  const [record] = musig2PsbtEvidence(doc);
  assert.equal(record.commitment, "missing");
  assert.equal(record.commitmentReason, "not-taproot");
});

test("a field with more than 100 participant keys is malformed, not aggregated", () => {
  const vectors = fixture("bip373-vectors.json");
  const aggregate = vectors.aggregatePubkey;
  // 101 valid compressed keys: the generator times 1..101.
  const keys = [];
  for (let i = 1; i <= 101; i++) {
    keys.push(bytesToHex(secp256k1.Point.BASE.multiply(BigInt(i)).toBytes(true)));
  }
  const doc = {
    inputs: [[{ key: "1a" + aggregate, value: keys.join("") }]],
    outputs: [],
    tx: { outputs: [] },
  };
  let records;
  assert.doesNotThrow(() => { records = musig2PsbtEvidence(doc); });
  assert.equal(records.length, 1);
  assert.equal(records[0].keyAgg, "malformed");
  assert.equal(records[0].reason, "participants-too-many");
});

test("a document that aggregates more than 1000 participant keys budgets the later fields", () => {
  const vectors = fixture("bip373-vectors.json");
  const aggregate = vectors.aggregatePubkey;
  const keys = [];
  for (let i = 1; i <= 100; i++) {
    keys.push(bytesToHex(secp256k1.Point.BASE.multiply(BigInt(i)).toBytes(true)));
  }
  const participants = keys.join("");
  // 11 fields of 100 keys each: 1100 keys total. The aggregate is deliberately
  // malformed so the test exercises the budget, not the (expensive) cross-check.
  const inputs = [];
  for (let i = 0; i < 11; i++) inputs.push([{ key: "1a" + "00", value: participants }]);
  const records = musig2PsbtEvidence({ inputs, outputs: [], tx: { outputs: [] } });
  assert.equal(records.length, 11);
  for (let i = 0; i < 10; i++) {
    assert.notEqual(records[i].reason, "budget", `field ${i} is within budget`);
  }
  assert.equal(records[10].keyAgg, "malformed");
  assert.equal(records[10].reason, "budget");
});

test("a nested hex-keyed object inside an input map yields no record", () => {
  const vectors = fixture("bip373-vectors.json");
  const aggregate = vectors.aggregatePubkey;
  const other = vectors.participants[0];
  const participants = vectors.participants.join("");
  const doc = {
    inputs: [[
      { key: "1a" + aggregate, value: participants },
      { nested: { ["1a" + other]: participants } },
    ]],
    outputs: [],
    tx: { outputs: [] },
  };
  const records = musig2PsbtEvidence(doc);
  assert.equal(records.length, 1, "only the real field yields a record");
  assert.equal(records[0].aggregate, lower(aggregate));
});

// The cross-check compares the whole 33-byte key, parity included.
test("the cross-check agrees with btc-signer on the full compressed key", () => {
  const vectors = fixture("bip373-vectors.json");
  const keys = vectors.participants.map(hexToBytes);
  const mine = crossCheckKeyAgg(keys);
  assert.equal(mine.length, 33);
  assert.equal(bytesToHex(mine), lower(vectors.aggregatePubkey));
});
