import { test } from "node:test";
import assert from "node:assert/strict";
import {
  WORDS,
  hodlCrc32,
  hodlBytewordsEncode,
  hodlBytewordsDecode,
  hodlCborCryptoPsbt,
  hodlUrEncodePsbt,
  hodlUrDecodePsbt,
} from "../src/js/psbt-ur.js";

const hex = (s) => Uint8Array.from(s.match(/../g).map((b) => parseInt(b, 16)));
const hexEncode = (b) => Buffer.from(b).toString("hex");

test("bytewords list is 256 unique four-letter words", () => {
  assert.equal(WORDS.length, 256);
  assert.equal(new Set(WORDS).size, 256);
  assert.equal(WORDS[0], "able");
  assert.equal(WORDS[0xc6], "skew");
  assert.equal(WORDS[255], "zoom");
});

test("CRC32 matches BCR-2020-012 vector", () => {
  const body = hex("d99d6ca20150c7098580125e2ab0981253468b2dbc5202c11947da");
  assert.equal(hexEncode(hodlCrc32(body)), "c904f40b");
});

test("standard Bytewords encode matches BCR-2020-012 vector", () => {
  const body = hex("d99d6ca20150c7098580125e2ab0981253468b2dbc5202c11947da");
  assert.equal(
    hodlBytewordsEncode(body, "standard"),
    "tuna next jazz oboe acid good slot axis limp lava brag holy door puff monk brag guru frog luau drop roof grim also safe chef fuel twin solo aqua work bald",
  );
  assert.deepEqual(
    hodlBytewordsDecode("tuna next jazz oboe acid good slot axis limp lava brag holy door puff monk brag guru frog luau drop roof grim also safe chef fuel twin solo aqua work bald"),
    body,
  );
});

test("minimal Bytewords round-trips", () => {
  const body = hex("d99d6ca20150c7098580125e2ab0981253468b2dbc5202c11947da");
  const minimal = hodlBytewordsEncode(body, "minimal");
  assert.equal(minimal, "tantjzoeadgdstaslplabghydrpfmkbggufgludprfgmaosecffltnsoaawkbd");
  assert.deepEqual(hodlBytewordsDecode(minimal), body);
});

test("crypto-psbt UR single-part encode/decode round-trips PSBT bytes", () => {
  const psbt = hex("70736274ff010000000000");
  const parts = hodlUrEncodePsbt(psbt);
  assert.equal(parts.length, 1);
  assert.match(parts[0], /^ur:crypto-psbt\/[a-z]+$/);
  const decoded = hodlUrDecodePsbt(parts[0]);
  assert.equal(decoded.type, "crypto-psbt");
  assert.equal(hexEncode(decoded.psbt), hexEncode(psbt));
  assert.equal(decoded.parts, 1);
});

test("sequential seq-len fragments reassemble when all are present", () => {
  const psbt = hex("70736274ff" + "11".repeat(80));
  const parts = hodlUrEncodePsbt(psbt, { maxBytes: 40 });
  assert.ok(parts.length >= 2);
  assert.match(parts[0], /^ur:crypto-psbt\/1-\d+\//);
  const decoded = hodlUrDecodePsbt(parts);
  assert.equal(hexEncode(decoded.psbt), hexEncode(psbt));
  assert.equal(decoded.parts, parts.length);
});

test("incomplete fragments and fountain seq>count are refused", () => {
  const psbt = hex("70736274ff" + "11".repeat(80));
  const parts = hodlUrEncodePsbt(psbt, { maxBytes: 40 });
  assert.throws(() => hodlUrDecodePsbt(parts[0]), /Need all/);
  assert.throws(
    () => hodlUrDecodePsbt("ur:crypto-psbt/5-3/" + hodlBytewordsEncode(hex("00"), "minimal")),
    /Fountain UR/,
  );
});

test("duplicate sequence numbers never silently overwrite a filled slot (issue #364)", () => {
  // Fragments spliced from two different PSBTs with the same fragment count:
  // last-wins reassembly would decode a transaction neither sender produced.
  const a = hodlUrEncodePsbt(hex("70736274ff" + "aa".repeat(80)), { maxBytes: 40 });
  const b = hodlUrEncodePsbt(hex("70736274ff" + "bb".repeat(80)), { maxBytes: 40 });
  assert.equal(a.length, b.length);
  // Every slot of A filled, plus B's seq-1 fragment spliced in: the duplicate
  // must be caught, never last-wins over A's own seq-1 fragment.
  assert.throws(() => hodlUrDecodePsbt([...a, b[0]]), /Duplicate UR fragment 1/);
  // An exact repeat of the same fragment (pasted twice) is idempotent.
  const repeated = [...a.slice(0, -1), a[a.length - 1], a[a.length - 1]];
  const decoded = hodlUrDecodePsbt(repeated);
  assert.equal(decoded.parts, a.length);
});

test("bad checksum is refused", () => {
  assert.throws(
    () => hodlBytewordsDecode("able able able able able"),
    /checksum/,
  );
});

test("tag 310 prefix is the crypto-psbt CBOR", () => {
  const psbt = hex("70736274ff");
  const cbor = hodlCborCryptoPsbt(psbt);
  assert.equal(cbor[0], 0xd9);
  assert.equal(cbor[1], 0x01);
  assert.equal(cbor[2], 0x36);
});
