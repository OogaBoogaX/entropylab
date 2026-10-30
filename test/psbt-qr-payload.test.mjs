import test from "node:test";
import assert from "node:assert/strict";
import { createPsbtQrReader } from "../src/js/psbt-qr-payload.js";
import {
  hodlCrc32,
  hodlBytewordsEncode,
  hodlCborBstr,
  hodlUrPartCbor,
} from "../src/js/psbt-ur.js";
import {
  findNominalFragmentLength,
  partitionMessage,
  chooseFragments,
} from "../src/js/ur-fountain.js";

// A minimal PSBT: the magic, an empty global map, no inputs and no outputs.
// The reader only checks the magic, so this is enough to exercise every path.
const PSBT_HEX = "70736274ff000000";
const PSBT = Uint8Array.from(PSBT_HEX.match(/../g).map((byte) => parseInt(byte, 16)));
const PSBT_BASE64 = Buffer.from(PSBT).toString("base64");

// The bytewords table, the minimal two-letter form and the CRC32 are pinned by
// test/ur-fountain.test.mjs against the BCR-2020-012 reference vectors
// (vectors.urEncoder.parts), so the UR text below does not come from
// psbt-qr-payload.js, the module under test.
const singlePartUr = (bytes) => "ur:crypto-psbt/" + hodlBytewordsEncode(bytes, "minimal");

// Tag 310 (crypto-psbt) and tag 40310 (psbt), as BCR-2020-006 sends them.
const TAG_CRYPTO_PSBT = Uint8Array.from([0xd9, 0x01, 0x36]);
const TAG_PSBT = Uint8Array.from([0xd9, 0x9d, 0x76]);
const concatBytes = (...arrays) => {
  const out = new Uint8Array(arrays.reduce((total, array) => total + array.length, 0));
  let at = 0;
  for (const array of arrays) {
    out.set(array, at);
    at += array.length;
  }
  return out;
};

const crc32Number = (bytes) => {
  const crc = hodlCrc32(bytes);
  return ((crc[0] << 24) | (crc[1] << 16) | (crc[2] << 8) | crc[3]) >>> 0;
};

const xorInto = (target, source) => {
  for (let i = 0; i < target.length; i++) target[i] ^= source[i];
};

// The collector-compatible part format test/ur-fountain.test.mjs already uses.
const encodeParts = (message, maxFragmentLen, count) => {
  const fragmentLen = findNominalFragmentLength(message.length, 10, maxFragmentLen);
  const fragments = partitionMessage(message, fragmentLen);
  const checksum = crc32Number(message);
  const seqLen = fragments.length;
  const parts = [];
  for (let i = 0; i < count; i++) {
    const seqNum = i + 1;
    const indexes = chooseFragments(seqNum, seqLen, checksum);
    const data = new Uint8Array(fragmentLen);
    for (const index of indexes) xorInto(data, fragments[index]);
    parts.push({ seqNum, seqLen, messageLen: message.length, checksum, data });
  }
  return parts;
};

const partUr = (part) =>
  "ur:crypto-psbt/" + part.seqNum + "-" + part.seqLen + "/" +
  hodlBytewordsEncode(hodlUrPartCbor(part.seqNum, part.seqLen, part.messageLen, part.checksum, part.data), "minimal");

test("a static base64 PSBT is accepted", () => {
  const reader = createPsbtQrReader();
  const result = reader.receive(PSBT_BASE64);
  assert.equal(result.status, "complete");
  assert.deepEqual([...result.bytes], [...PSBT]);
});

test("a static hex PSBT is accepted", () => {
  const reader = createPsbtQrReader();
  const result = reader.receive(PSBT_HEX);
  assert.equal(result.status, "complete");
  assert.deepEqual([...result.bytes], [...PSBT]);
});

test("text that is not a PSBT is refused", () => {
  const reader = createPsbtQrReader();
  assert.equal(reader.receive("hello").status, "not-psbt");
  assert.equal(reader.receive("").status, "not-psbt");
  assert.equal(reader.receive("70736274f").status, "not-psbt");
  assert.equal(reader.receive("deadbeef").status, "not-psbt");
});

test("a single-part UR wrapping the PSBT is accepted", () => {
  const reader = createPsbtQrReader();
  const result = reader.receive(singlePartUr(hodlCborBstr(PSBT)));
  assert.equal(result.status, "complete");
  assert.deepEqual([...result.bytes], [...PSBT]);
});

test("a crypto-psbt UR tagged 310 is accepted", () => {
  const reader = createPsbtQrReader();
  const message = concatBytes(TAG_CRYPTO_PSBT, hodlCborBstr(PSBT));
  const result = reader.receive(singlePartUr(message));
  assert.equal(result.status, "complete");
  assert.deepEqual([...result.bytes], [...PSBT]);
});

test("a psbt UR tagged 40310 is accepted", () => {
  const reader = createPsbtQrReader();
  const message = concatBytes(TAG_PSBT, hodlCborBstr(PSBT));
  const result = reader.receive(singlePartUr(message));
  assert.equal(result.status, "complete");
  assert.deepEqual([...result.bytes], [...PSBT]);
});

test("a tagged message with a trailing byte is bad-cbor", () => {
  const reader = createPsbtQrReader();
  const message = concatBytes(TAG_CRYPTO_PSBT, hodlCborBstr(PSBT), Uint8Array.of(0x00));
  assert.equal(reader.receive(singlePartUr(message)).status, "bad-cbor");
});

test("a text string behind tag 310 is bad-cbor", () => {
  const reader = createPsbtQrReader();
  const message = Uint8Array.from([0xd9, 0x01, 0x36, 0x63, 0x61, 0x62, 0x63]);
  assert.equal(reader.receive(singlePartUr(message)).status, "bad-cbor");
});

test("a UR of another type is wrong-type", () => {
  const reader = createPsbtQrReader();
  const ur = "ur:crypto-seed/" + hodlBytewordsEncode(Uint8Array.from([1, 2, 3]), "minimal");
  assert.equal(reader.receive(ur).status, "wrong-type");
});

test("a CBOR text string is bad-cbor", () => {
  const reader = createPsbtQrReader();
  // Major type 3: a text string, not a byte string.
  const text = Uint8Array.from([0x63, 0x61, 0x62, 0x63]);
  assert.equal(reader.receive(singlePartUr(text)).status, "bad-cbor");
});

test("a byte string whose length header disagrees is bad-cbor", () => {
  const reader = createPsbtQrReader();
  // 0x58 says one length byte follows; 0x09 says nine bytes, but only eight do.
  const bad = Uint8Array.from([0x58, 0x09, ...PSBT]);
  assert.equal(reader.receive(singlePartUr(bad)).status, "bad-cbor");
});

test("a UR payload without the PSBT magic is not-psbt", () => {
  const reader = createPsbtQrReader();
  const result = reader.receive(singlePartUr(hodlCborBstr(Uint8Array.from([1, 2, 3]))));
  assert.equal(result.status, "not-psbt");
});

test("a payload over maxBytes is too-large", () => {
  const staticReader = createPsbtQrReader({ maxBytes: 4 });
  assert.equal(staticReader.receive(PSBT_BASE64).status, "too-large");
  const urReader = createPsbtQrReader({ maxBytes: 4 });
  assert.equal(urReader.receive(singlePartUr(hodlCborBstr(PSBT))).status, "too-large");
});

test("after complete the reader is done until reset", () => {
  const reader = createPsbtQrReader();
  assert.equal(reader.receive(PSBT_BASE64).status, "complete");
  assert.equal(reader.receive(PSBT_BASE64).status, "done");
  reader.reset();
  assert.equal(reader.receive(PSBT_BASE64).status, "complete");
});

test("three parts out of order complete and progress reports the counts", () => {
  const reader = createPsbtQrReader();
  // 80 bytes: the CBOR wrapper is 82 bytes, which partitions into 3 fragments.
  const big = new Uint8Array(80);
  big.set(PSBT);
  const message = hodlCborBstr(big);
  const parts = encodeParts(message, 30, 3);
  assert.equal(parts.length, 3);
  assert.equal(parts[0].seqLen, 3);
  assert.equal(reader.receive(partUr(parts[2])).status, "partial");
  assert.deepEqual(reader.progress(), { received: 1, total: 3 });
  assert.equal(reader.receive(partUr(parts[0])).status, "partial");
  assert.deepEqual(reader.progress(), { received: 2, total: 3 });
  const result = reader.receive(partUr(parts[1]));
  assert.equal(result.status, "complete");
  assert.deepEqual([...result.bytes], [...big]);
});
