import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  AexbError,
  aexbDecode,
  aexbEncode,
  aexbEncodePackage,
  aexbVerify,
  aextDecodePackage,
  aextEncodePackage
} from "../src/js/aexb.js";
import { secp256k1Ready } from "../src/js/secp256k1.js";
import { hashesReady, sha256 } from "../src/js/hashes.js";

await secp256k1Ready;
await hashesReady;

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "fixtures", "aexb");
const readJson = (name) => JSON.parse(readFileSync(join(fixtures, name), "utf8"));
const positive = readJson("protocol-v1-multislot-vectors.json");
const negative = readJson("protocol-v1-negative-vectors.json");
const transport = readJson("transport-v1-vectors.json");

// The verifier accepts objects, so canonical v1 constraints must hold even
// when callers modify decoder output. Expectations come from wire-format
// sections 4-7, independently of the verifier implementation.
for (const mutation of [
  ["duplicate slots", (m) => { m.slots = [m.slots[0], m.slots[0]]; }],
  ["reordered slots", (m) => { m.slots.reverse(); }],
  ["unsupported sighash", (m) => { m.slots[0].sighashType = 2; }],
  ["invalid network", (m) => { m.network = 255; }],
  ["fractional network", (m) => { m.network = 1.5; }],
  ["missing network", (m) => { delete m.network; }],
  ["short session", (m) => { m.sessionId = new Uint8Array(1); }],
  ["short PSBT digest", (m) => { m.psbtDigest = new Uint8Array(1); }],
  ["too many slots", (m) => { m.slots = Array(129).fill(m.slots[0]); }],
  ["null slot", (m) => { m.slots[0] = null; }],
  ["invalid input index", (m) => { m.slots[0].inputIndex = -1; }],
  ["invalid opening", (m) => { m.slots[0].opening = new Uint8Array(33); }],
]) {
  test(`object verifier rejects ${mutation[0]} in signatures and reveals`, () => {
    const [stage2, reveal, signatures] = [2, 3, 4].map((stage) =>
      aexbDecode(positive.messages.find((m) => m.stage === stage).message_hex));
    for (const message of [stage2, reveal, signatures]) mutation[1](message);
    assert.equal(aexbVerify(signatures, reveal, stage2).ok, false);
    assert.equal(aexbVerify(reveal, null, stage2).ok, false);
  });
  for (const stage of [2, 3, 4]) {
    test(`object verifier rejects ${mutation[0]} in stage ${stage} with canonical reason`, () => {
      const messages = [2, 3, 4].map((s) =>
        aexbDecode(positive.messages.find((m) => m.stage === s).message_hex));
      mutation[1](messages[stage - 2]);
      const reason = ["duplicate slots", "reordered slots"].includes(mutation[0])
        ? "SIGNATURE_SLOT_MISMATCH" : "INVALID_MESSAGE";
      const expected = { ok: false, verdict: "fail", reason, slots: [] };
      assert.deepEqual(aexbVerify(messages[2], messages[1], messages[0]), expected);
      if (stage !== 4) {
        assert.deepEqual(aexbVerify(messages[1], null, messages[0]), expected);
      }
    });
  }
}

test("canonical object rejection precedes signature verification", () => {
  const [stage2, reveal, signatures] = [2, 3, 4].map((stage) =>
    aexbDecode(positive.messages.find((m) => m.stage === stage).message_hex));
  signatures.slots.reverse();
  signatures.slots[0].signature.fill(0);
  assert.deepEqual(aexbVerify(signatures, reveal, stage2), {
    ok: false, verdict: "fail", reason: "SIGNATURE_SLOT_MISMATCH", slots: []
  });
});

test("object verifier validates stage-specific fields on every supplied stage", () => {
  for (const stage of [2, 3, 4]) {
    const messages = [2, 3, 4].map((s) =>
      aexbDecode(positive.messages.find((m) => m.stage === s).message_hex));
    const changed = messages[stage - 2].slots[0];
    if (stage === 2) changed.rho = new Uint8Array(32);
    if (stage === 3) changed.signature = new Uint8Array(64);
    if (stage === 4) changed.rho = new Uint8Array(32);
    assert.equal(aexbVerify(messages[2], messages[1], messages[0]).ok, false);
  }
});

test("encoder rejects noninteger stage and network values", () => {
  for (const field of ["stage", "network"]) {
    for (const value of [undefined, NaN, 1.5, "1"]) {
      const message = aexbDecode(positive.messages[0].message_hex);
      message[field] = value;
      assert.throws(() => aexbEncode(message), AexbError);
    }
  }
});

function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function flipFirstByte(bytes) {
  const out = new Uint8Array(bytes);
  out[0] ^= 1;
  return out;
}

function bytesToBigInt(bytes) {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function bigIntTo32(value) {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return out;
}

function concatBytes(...arrays) {
  const total = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) {
    out.set(arr, offset);
    offset += arr.length;
  }
  return out;
}

function taggedHash(tag, data) {
  const tagHash = sha256(new TextEncoder().encode(tag));
  return sha256(concatBytes(tagHash, tagHash, data));
}

test("positive AEXB messages decode and verify", () => {
  const byStage = new Map();
  for (const vector of positive.messages) {
    const decoded = aexbDecode(vector.message_hex);
    byStage.set(vector.stage, decoded);
    assert.equal(decoded.stage, vector.stage);
    assert.equal(decoded.network, positive.network_code);
    assert.equal(decoded.slots.length, positive.slot_count);
    assert.equal(decoded.slots[0].inputIndex, positive.slot_identifiers[0].input_index);
    assert.equal(bytesToHex(decoded.slots[0].signerPubkey), positive.slot_identifiers[0].signer_pubkey);
    assert.equal(bytesToHex(aexbEncode(decoded)), vector.message_hex);
  }

  const stage2 = byStage.get(2);
  const reveal = byStage.get(3);
  const signatures = byStage.get(4);
  const revealResult = aexbVerify(reveal, null, stage2);
  assert.equal(revealResult.ok, true);
  assert.equal(revealResult.verdict, "ok");
  assert.equal(revealResult.slots.length, positive.slot_count);
  assert.ok(revealResult.slots.every((slot) => slot.ok));

  const signatureResult = aexbVerify(signatures, reveal, stage2);
  assert.equal(signatureResult.ok, true);
  assert.equal(signatureResult.verdict, "ok");
  assert.equal(signatureResult.slots.length, positive.slot_count);
  assert.ok(signatureResult.slots.every((slot) => slot.ok));
});

test("positive AEXT packages decode and round-trip", () => {
  for (const vector of positive.messages) {
    const decoded = aexbDecode(vector.package_hex);
    assert.equal(decoded.stage, vector.stage);
    assert.equal(decoded.network, positive.network_code);
    assert.equal(bytesToHex(aexbEncode(decoded)), vector.message_hex);
    assert.equal(bytesToHex(aexbEncodePackage(decoded)), vector.package_hex);
  }
});

test("negative vectors fail closed with the reference error code", () => {
  for (const vector of negative.cases) {
    assert.throws(
      () => aexbDecode(vector.message_hex),
      (err) => {
        assert.ok(err instanceof AexbError);
        assert.equal(err.code, vector.expected_error);
        return true;
      }
    );
    assert.throws(
      () => aexbDecode(vector.package_hex),
      (err) => {
        assert.ok(err instanceof AexbError);
        assert.equal(err.code, vector.expected_error);
        return true;
      }
    );
  }
});

test("transport vectors round-trip and embedded messages decode", () => {
  for (const vector of transport.vectors) {
    const decoded = aextDecodePackage(vector.package_hex);
    assert.equal(decoded.stage, vector.stage);
    assert.equal(bytesToHex(aextEncodePackage(decoded)), vector.package_hex);

    // transport-v1-vectors.json preserves the historical single-slot
    // RungBMessage physical-prototype packages. protocol-v1-wire-format.md §1
    // states the historical and v1 layouts are not interchangeable despite
    // sharing the AEXB magic and version byte, so the v1 decoder must reject
    // them. Decode every embedded message that is AEXB v1; for the historical
    // single-slot payloads, assert the historical header instead of skipping
    // silently.
    let embedded;
    try {
      embedded = aexbDecode(decoded.message);
    } catch (err) {
      assert.ok(err instanceof AexbError);
      assert.equal(bytesToHex(decoded.message.slice(0, 4)), "41455842");
      assert.equal(decoded.message[4], 1);
      const historicalLength = (decoded.message[6] << 8) | decoded.message[7];
      assert.equal(decoded.message.length, 8 + historicalLength);
      continue;
    }
    assert.equal(embedded.stage, vector.stage);
    assert.equal(embedded.network, decoded.network);
  }
});

test("a changed signature r fails the S2C check", () => {
  const stage2 = aexbDecode(positive.messages.find((m) => m.stage === 2).message_hex);
  const reveal = aexbDecode(positive.messages.find((m) => m.stage === 3).message_hex);
  const signatures = aexbDecode(positive.messages.find((m) => m.stage === 4).message_hex);
  const tampered = {
    ...signatures,
    slots: signatures.slots.map((slot, index) =>
      index === 0 ? { ...slot, signature: flipFirstByte(slot.signature) } : slot
    )
  };
  const result = aexbVerify(tampered, reveal, stage2);
  assert.equal(result.ok, false);
  assert.equal(result.verdict, "fail");
  assert.equal(result.slots[0].ok, false);
  assert.equal(result.slots[0].reason, "OPENING_MISMATCH");
});

test("a changed host reveal fails the commitment check", () => {
  const stage2 = aexbDecode(positive.messages.find((m) => m.stage === 2).message_hex);
  const reveal = aexbDecode(positive.messages.find((m) => m.stage === 3).message_hex);
  const tampered = {
    ...reveal,
    slots: reveal.slots.map((slot, index) =>
      index === 0 ? { ...slot, rho: flipFirstByte(slot.rho) } : slot
    )
  };
  const result = aexbVerify(tampered, null, stage2);
  assert.equal(result.ok, false);
  assert.equal(result.verdict, "fail");
  assert.equal(result.slots[0].ok, false);
  assert.equal(result.slots[0].reason, "COMMITMENT_MISMATCH");
});

test("a high-S signature fails the low-S check", () => {
  const stage2 = aexbDecode(positive.messages.find((m) => m.stage === 2).message_hex);
  const reveal = aexbDecode(positive.messages.find((m) => m.stage === 3).message_hex);
  const signatures = aexbDecode(positive.messages.find((m) => m.stage === 4).message_hex);
  const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
  const tampered = {
    ...signatures,
    slots: signatures.slots.map((slot, index) => {
      if (index !== 0) return slot;
      const s = bytesToBigInt(slot.signature.slice(32));
      const signature = new Uint8Array(64);
      signature.set(slot.signature.slice(0, 32), 0);
      signature.set(bigIntTo32(N - s), 32);
      return { ...slot, signature };
    })
  };
  const result = aexbVerify(tampered, reveal, stage2);
  assert.equal(result.ok, false);
  assert.equal(result.verdict, "fail");
  assert.equal(result.slots[0].ok, false);
  assert.equal(result.slots[0].reason, "NON_LOW_S");
});

test("a changed low-S s fails at the ECDSA verify step itself", () => {
  // r is kept, so the S2C x(R0 + t·G) == r check still passes, and s - 1 is
  // still low-S: only the final ECDSA verification can reject this slot.
  const stage2 = aexbDecode(positive.messages.find((m) => m.stage === 2).message_hex);
  const reveal = aexbDecode(positive.messages.find((m) => m.stage === 3).message_hex);
  const signatures = aexbDecode(positive.messages.find((m) => m.stage === 4).message_hex);
  const tampered = {
    ...signatures,
    slots: signatures.slots.map((slot, index) => {
      if (index !== 0) return slot;
      const s = bytesToBigInt(slot.signature.slice(32));
      assert.ok(s > 1n, "the vector's s leaves room for s - 1");
      const signature = new Uint8Array(64);
      signature.set(slot.signature.slice(0, 32), 0);
      signature.set(bigIntTo32(s - 1n), 32);
      return { ...slot, signature };
    })
  };
  const result = aexbVerify(tampered, reveal, stage2);
  assert.equal(result.ok, false);
  assert.equal(result.slots[0].ok, false);
  assert.equal(result.slots[0].reason, "SIGNATURE_INVALID");
  assert.ok(result.slots.slice(1).every((slot) => slot.ok), "the untouched slots still verify");
});

test("explicit reveal and commitment arguments win over a wrapper's fields", () => {
  const stage1 = aexbDecode(positive.messages.find((m) => m.stage === 1).message_hex);
  const stage2 = aexbDecode(positive.messages.find((m) => m.stage === 2).message_hex);
  const reveal = aexbDecode(positive.messages.find((m) => m.stage === 3).message_hex);
  const signatures = aexbDecode(positive.messages.find((m) => m.stage === 4).message_hex);
  // The wrapper carries only a stage-1 commitment; the caller's explicit
  // stage-2 message must be the one used, so this verifies.
  assert.equal(aexbVerify({ message4: signatures, message3: reveal, message1: stage1 }, null, stage2).verdict, "ok");
  // And a caller's explicit stage-1 is not silently upgraded by the wrapper.
  assert.equal(aexbVerify({ message4: signatures, message3: reveal, message2: stage2 }, null, stage1).reason, "MISSING_STAGE2_OPENING");
});

test("an empty slot set fails closed", () => {
  const emptyReveal = {
    stage: 3,
    network: 0,
    sessionId: new Uint8Array(32),
    psbtDigest: new Uint8Array(32),
    slots: []
  };
  const revealResult = aexbVerify(emptyReveal);
  assert.equal(revealResult.ok, false);
  assert.equal(revealResult.verdict, "fail");
  assert.equal(revealResult.reason, "EMPTY_SLOT_SET");

  const emptySignatures = { ...emptyReveal, stage: 4 };
  const signatureResult = aexbVerify(emptySignatures, emptyReveal);
  assert.equal(signatureResult.ok, false);
  assert.equal(signatureResult.verdict, "fail");
  assert.equal(signatureResult.reason, "EMPTY_SLOT_SET");
});

test("a reveal not bound to the stage-2 commitment fails", () => {
  const stage2 = aexbDecode(positive.messages.find((m) => m.stage === 2).message_hex);
  const reveal = aexbDecode(positive.messages.find((m) => m.stage === 3).message_hex);
  const forged = {
    ...reveal,
    slots: reveal.slots.map((slot, index) => {
      if (index !== 0) return slot;
      const rho = flipFirstByte(slot.rho);
      return { ...slot, rho, commitment: taggedHash("s2c/ecdsa/data", rho) };
    })
  };
  const result = aexbVerify(forged, null, stage2);
  assert.equal(result.ok, false);
  assert.equal(result.verdict, "fail");
  assert.equal(result.slots[0].ok, false);
  assert.equal(result.slots[0].reason, "COMMITMENT_MISMATCH");
});

test("a changed stage-3 commitment fails the commitment binding", () => {
  const stage2 = aexbDecode(positive.messages.find((m) => m.stage === 2).message_hex);
  const reveal = aexbDecode(positive.messages.find((m) => m.stage === 3).message_hex);
  const signatures = aexbDecode(positive.messages.find((m) => m.stage === 4).message_hex);
  const tampered = {
    ...reveal,
    slots: reveal.slots.map((slot, index) =>
      index === 0 ? { ...slot, commitment: flipFirstByte(slot.commitment) } : slot
    )
  };

  const revealResult = aexbVerify(tampered, null, stage2);
  assert.equal(revealResult.ok, false);
  assert.equal(revealResult.verdict, "fail");
  assert.equal(revealResult.slots[0].ok, false);
  assert.equal(revealResult.slots[0].reason, "COMMITMENT_MISMATCH");

  const signatureResult = aexbVerify(signatures, tampered, stage2);
  assert.equal(signatureResult.ok, false);
  assert.equal(signatureResult.verdict, "fail");
  assert.equal(signatureResult.slots[0].ok, false);
  assert.equal(signatureResult.slots[0].reason, "COMMITMENT_MISMATCH");
});

test("a stage-1-only commitment is refused without the stage-2 openings", () => {
  const stage1 = aexbDecode(positive.messages.find((m) => m.stage === 1).message_hex);
  const reveal = aexbDecode(positive.messages.find((m) => m.stage === 3).message_hex);
  const signatures = aexbDecode(positive.messages.find((m) => m.stage === 4).message_hex);

  const revealResult = aexbVerify(reveal, null, stage1);
  assert.equal(revealResult.ok, false);
  assert.equal(revealResult.verdict, "fail");
  assert.equal(revealResult.reason, "MISSING_STAGE2_OPENING");

  const signatureResult = aexbVerify(signatures, reveal, stage1);
  assert.equal(signatureResult.ok, false);
  assert.equal(signatureResult.verdict, "fail");
  assert.equal(signatureResult.reason, "MISSING_STAGE2_OPENING");
});

test("a stage-3 opening that differs from the stage-2 opening is refused", () => {
  const stage2 = aexbDecode(positive.messages.find((m) => m.stage === 2).message_hex);
  const reveal = aexbDecode(positive.messages.find((m) => m.stage === 3).message_hex);
  const signatures = aexbDecode(positive.messages.find((m) => m.stage === 4).message_hex);

  const tamperedReveal = {
    ...reveal,
    slots: reveal.slots.map((slot, index) =>
      index === 0 ? { ...slot, opening: flipFirstByte(slot.opening) } : slot
    )
  };
  const revealResult = aexbVerify(tamperedReveal, null, stage2);
  assert.equal(revealResult.ok, false);
  assert.equal(revealResult.verdict, "fail");
  assert.equal(revealResult.reason, "OPENING_MISMATCH");

  const tamperedSignatures = {
    ...signatures,
    slots: signatures.slots.map((slot, index) =>
      index === 0 ? { ...slot, opening: flipFirstByte(slot.opening) } : slot
    )
  };
  const signatureResult = aexbVerify(tamperedSignatures, reveal, stage2);
  assert.equal(signatureResult.ok, false);
  assert.equal(signatureResult.verdict, "fail");
  assert.equal(signatureResult.slots[0].ok, false);
  assert.equal(signatureResult.slots[0].reason, "OPENING_MISMATCH");
});

test("message 4 without the accepted reveal fails closed", () => {
  const signatures = aexbDecode(positive.messages.find((m) => m.stage === 4).message_hex);
  const result = aexbVerify(signatures);
  assert.equal(result.ok, false);
  assert.equal(result.verdict, "fail");
  assert.equal(result.reason, "MISSING_REVEAL");
});
