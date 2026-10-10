import { test } from "node:test";
import assert from "node:assert/strict";
import {
  WORDS,
  hodlCrc32,
  hodlBytewordsEncode,
  hodlBytewordsDecode,
  hodlCborBstr,
  hodlUrPartCbor,
  hodlUrEncodeMessage,
  hodlUrEncodePsbt,
  hodlUrDecodePsbt,
} from "../src/js/psbt-ur.js";

const hex = (s) => Uint8Array.from(s.match(/../g).map((b) => parseInt(b, 16)));
const hexEncode = (b) => Buffer.from(b).toString("hex");
const concat = (...parts) => Uint8Array.from(parts.flatMap((part) => [...part]));

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
  // BCR-2020-005: a top-level UR object MUST NOT carry its CBOR tag — the
  // type component already says crypto-psbt. The payload is the bare byte
  // string, not 0xd90136-prefixed (audit C3-5).
  const payload = hodlBytewordsDecode(parts[0].split("/")[1]);
  assert.notEqual(payload[0], 0xd9, "single-part payload must be the untagged byte string");
  assert.deepEqual(payload, hodlCborBstr(psbt));
  const decoded = hodlUrDecodePsbt(parts[0]);
  assert.equal(decoded.type, "crypto-psbt");
  assert.equal(hexEncode(decoded.psbt), hexEncode(psbt));
  assert.equal(decoded.parts, 1);
  // Deployed wallets do tag it; the decoder keeps accepting both.
  const tagged = concat(hex("d90136"), hodlCborBstr(psbt));
  const legacy = hodlUrDecodePsbt("ur:crypto-psbt/" + hodlBytewordsEncode(tagged, "minimal"));
  assert.equal(hexEncode(legacy.psbt), hexEncode(psbt));
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

// BCR-2024-001 "testEncoderCBOR": the published part serialization for
// message 916ec65c… (256 bytes, CRC-32 0x0167aa07) in 30-byte fragments.
const MUR_MESSAGE_LEN = 256;
const MUR_CHECKSUM = 0x0167aa07;
const MUR_FRAGMENTS = [
  "916ec65cf77cadf55cd7f9cda1a1030026ddd42e905b77adc36e4f2d3c",
  "cba44f7f04f2de44f42d84c374a0e149136f25b01852545961d55f7f7a",
  "8cde6d0e2ec43f3b2dcb644a2209e8c9e34af5c4747984a5e873c9cf5f",
  "965e25ee29039fdf8ca74f1c769fc07eb7ebaec46e0695aea6cbd60b3e",
  "c4bbff1b9ffe8a9e7240129377b9d3711ed38d412fbb4442256f1e6f59",
  "5e0fc57fed451fb0a0101fb76b1fb1e1b88cfdfdaa946294a47de8fff1",
  "73f021c0e6f65b05c0a494e50791270a0050a73ae69b6725505a2ec8a5",
  "791457c9876dd34aadd192a53aa0dc66b556c0c215c7ceb8248b717c22",
  // The last fragment is zero-padded to the common fragment length.
  "951e65305b56a3706e3e86eb01c803bbf915d80edcd64d4d0000000000",
];

test("UR part CBOR matches the published BCR-2024-001 vectors", () => {
  assert.equal(
    hexEncode(hodlUrPartCbor(1, 9, MUR_MESSAGE_LEN, MUR_CHECKSUM, hex(MUR_FRAGMENTS[0]))),
    "8501" + "09" + "190100" + "1a0167aa07" + "581d" + MUR_FRAGMENTS[0],
  );
  assert.equal(
    hexEncode(hodlUrPartCbor(9, 9, MUR_MESSAGE_LEN, MUR_CHECKSUM, hex(MUR_FRAGMENTS[8]))),
    "8509" + "09" + "190100" + "1a0167aa07" + "581d" + MUR_FRAGMENTS[8],
  );
  // And the published fragments reassemble to a message with the published
  // checksum (padding stripped by the declared message length).
  const message = concat(...MUR_FRAGMENTS.map(hex)).slice(0, MUR_MESSAGE_LEN);
  assert.equal(message.length, MUR_MESSAGE_LEN);
  assert.equal(hexEncode(hodlCrc32(message)), "0167aa07");
});

test("multi-part fragments carry the MUR metadata and verify the whole message (audit C3-5)", () => {
  // 81 payload bytes at 40-byte fragments: the last fragment is padded.
  const psbt = hex("70736274ff" + "11".repeat(80));
  const parts = hodlUrEncodePsbt(psbt, { maxBytes: 40 });
  assert.ok(parts.length >= 2);
  const decoded = hodlUrDecodePsbt(parts);
  assert.equal(hexEncode(decoded.psbt), hexEncode(psbt));
  // Fragments spliced from a different PSBT into *different* slots were
  // previously concatenated without any tie between them; now the per-part
  // metadata (and behind it the whole-message CRC-32) refuses the mix.
  const other = hodlUrEncodePsbt(hex("70736274ff" + "22".repeat(80)), { maxBytes: 40 });
  assert.equal(other.length, parts.length);
  assert.throws(() => hodlUrDecodePsbt([parts[0], other[1], ...parts.slice(2)]), /metadata do not match|checksum/i);
  // A fragment with intact per-part encoding but tampered data passes the
  // Bytewords checksum and fails only the whole-message CRC-32.
  const tamperedPayload = hodlBytewordsDecode(parts[1].split("/")[2]);
  tamperedPayload[tamperedPayload.length - 6] ^= 1; // inside the fragment data
  const tampered = "ur:crypto-psbt/2-" + parts.length + "/" + hodlBytewordsEncode(tamperedPayload, "minimal");
  assert.throws(() => hodlUrDecodePsbt([parts[0], tampered, ...parts.slice(2)]), /checksum/i);
});

test("legacy pre-MUR fragments still decode", () => {
  // Fragments written by earlier EntropyLab versions: a raw chunk of the
  // tagged message with only the per-fragment Bytewords checksum.
  const psbt = hex("70736274ff" + "33".repeat(80));
  const message = concat(hex("d90136"), hodlCborBstr(psbt));
  const chunks = [];
  for (let offset = 0; offset < message.length; offset += 40) chunks.push(message.slice(offset, offset + 40));
  const parts = chunks.map((chunk, i) => "ur:crypto-psbt/" + (i + 1) + "-" + chunks.length + "/" + hodlBytewordsEncode(chunk, "minimal"));
  const decoded = hodlUrDecodePsbt(parts);
  assert.equal(hexEncode(decoded.psbt), hexEncode(psbt));
  assert.equal(decoded.parts, chunks.length);
});

// Blockchain Commons bc-ur (C++ reference implementation) test.cpp
// "test_ur_encoder": the published ur:bytes serialization of the same
// 256-byte Xoshiro256("Wolf") message as above, as a CBOR byte string split
// at the reference encoder's nominal 29-byte fragment length (its 30-byte
// maximum reduced by find_nominal_fragment_length: ceil(259/9) = 29). This is
// the encode path watchOnlyQrPlan uses (hodlCborBstr + hodlUrEncodeMessage).
const BC_UR_REFERENCE_PARTS = [
  "ur:bytes/1-9/lpadascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtdkgslpgh",
  "ur:bytes/2-9/lpaoascfadaxcywenbpljkhdcagwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsgmghhkhstlrdcxaefz",
  "ur:bytes/3-9/lpaxascfadaxcywenbpljkhdcahelbknlkuejnbadmssfhfrdpsbiegecpasvssovlgeykssjykklronvsjksopdzmol",
  "ur:bytes/4-9/lpaaascfadaxcywenbpljkhdcasotkhemthydawydtaxneurlkosgwcekonertkbrlwmplssjtammdplolsbrdzcrtas",
  "ur:bytes/5-9/lpahascfadaxcywenbpljkhdcatbbdfmssrkzmcwnezelennjpfzbgmuktrhtejscktelgfpdlrkfyfwdajldejokbwf",
  "ur:bytes/6-9/lpamascfadaxcywenbpljkhdcackjlhkhybssklbwefectpfnbbectrljectpavyrolkzczcpkmwidmwoxkilghdsowp",
  "ur:bytes/7-9/lpatascfadaxcywenbpljkhdcavszmwnjkwtclrtvaynhpahrtoxmwvwatmedibkaegdosftvandiodagdhthtrlnnhy",
  "ur:bytes/8-9/lpayascfadaxcywenbpljkhdcadmsponkkbbhgsoltjntegepmttmoonftnbuoiyrehfrtsabzsttorodklubbuyaetk",
  "ur:bytes/9-9/lpasascfadaxcywenbpljkhdcajskecpmdckihdyhphfotjojtfmlnwmadspaxrkytbztpbauotbgtgtaeaevtgavtny",
];

test("ur:bytes encode matches the published bc-ur reference strings", () => {
  const message = concat(...MUR_FRAGMENTS.map(hex)).slice(0, MUR_MESSAGE_LEN);
  assert.deepEqual(hodlUrEncodeMessage("bytes", hodlCborBstr(message), { maxBytes: 29 }), BC_UR_REFERENCE_PARTS);
});
