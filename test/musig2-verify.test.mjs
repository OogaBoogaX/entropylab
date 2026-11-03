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
  for (const { label, psbt } of malformed) {
    assert.ok(psbt, `${label}: base64 decodes to a PSBT`);
    let doc = null;
    try {
      doc = psbtInspectDoc(hexToBytes(psbt));
    } catch {
      // The parser refuses the bytes; that is fail-closed too.
    }
    if (!doc) continue;
    const records = musig2PsbtEvidence(doc);
    assert.ok(records.length > 0, `${label}: expected MuSig2 evidence`);
    assert.ok(records.every((record) => record.keyAgg !== "verified"), `${label}: nothing verifies`);
    const xonlyAggregate = /x-only aggregate/i.test(label)
      || (outputCaseRepeated && /x-only output participant/i.test(label));
    const reason = xonlyAggregate ? "aggregate-length" : "participants-length";
    assert.ok(records.some((record) => record.keyAgg === "malformed" && record.reason === reason), `${label}: ${reason}`);
  }
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
  for (const { label, psbt } of later) {
    assert.ok(psbt, `${label}: base64 decodes to a PSBT`);
    let doc = null;
    try {
      doc = psbtInspectDoc(hexToBytes(psbt));
    } catch {
      // The parser refuses the file; that is fail-closed too.
    }
    if (!doc) continue;
    assert.doesNotThrow(() => musig2PsbtEvidence(doc), `${label}: evidence does not throw`);
  }
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

// The cross-check compares the whole 33-byte key, parity included.
test("the cross-check agrees with btc-signer on the full compressed key", () => {
  const vectors = fixture("bip373-vectors.json");
  const keys = vectors.participants.map(hexToBytes);
  const mine = crossCheckKeyAgg(keys);
  assert.equal(mine.length, 33);
  assert.equal(bytesToHex(mine), lower(vectors.aggregatePubkey));
});
