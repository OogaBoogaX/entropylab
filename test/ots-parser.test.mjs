// OpenTimestamps (.ots) parser tests — issue #315, phase 1.
//
// Fixture provenance: every byte string below is hand-constructed from the
// wire format as defined by the python-opentimestamps reference
// (serialize.py / op.py / timestamp.py / notary.py), NOT produced by running
// the parser under test. The two digest anchors are NIST-published hash
// values (SHA-256 and SHA-1 of the empty string). Comments on each fixture
// derive the bytes field-by-field so reviewers can check them against the
// format without running anything.
//
// Run with: node --test test/ots-parser.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";

import { parseDetachedTimestamp, OtsParseError } from "../src/js/ots-parser.js";

// ---- byte helpers ---------------------------------------------------------

const u8 = (arr) => Uint8Array.from(arr);
const ascii = (s) => Array.from(s, (c) => c.charCodeAt(0));
const hexToBytes = (hex) => u8(hex.match(/../g).map((b) => parseInt(b, 16)));
const bytesToHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

// ---- format anchors (literal, spec-derived) -------------------------------

// DetachedTimestampFile.HEADER_MAGIC (timestamp.py):
//   \x00 "OpenTimestamps" \x00\x00 "Proof" \x00 <8 fixed bytes>
const MAGIC = [
  0x00,
  ...ascii("OpenTimestamps"),
  0x00, 0x00,
  ...ascii("Proof"),
  0x00,
  0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
];

// NIST-published SHA-256 of the empty string. Arbitrary 32-byte stand-in for
// a file digest; using a published constant keeps fixtures self-documenting.
const DIGEST_SHA256_EMPTY = hexToBytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

// NIST-published SHA-1 of the empty string (for the 20-byte digest case).
const DIGEST_SHA1_EMPTY = hexToBytes("da39a3ee5e6b4b0d3255bfef95601890afd80709");

// Attestation URI tags (notary.py), 8 bytes each.
const BTC_ATT_URI = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
const PENDING_ATT_URI = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
const LTC_ATT_URI = [0x06, 0x86, 0x9a, 0x0d, 0x73, 0xd7, 0x1b, 0x45];

// LEB128 varuint for block height 123456:
//   123456 = 64 + 68·2⁷ + 7·2¹⁴  →  bytes 0xc0 0xc4 0x07 (continuation bits on first two)
const HEIGHT_123456 = [0xc0, 0xc4, 0x07];

// A complete minimal Bitcoin-attested proof: header, sha256 digest, then a
// single attestation leaf. BitcoinBlockHeaderAttestation payload is
// varuint(height) = HEIGHT_123456 (3 bytes), wrapped as varbytes → len 0x03.
const MINIMAL_BITCOIN_PROOF = [
  ...MAGIC,
  0x01, // major version
  0x08, // file hash op: sha256
  ...DIGEST_SHA256_EMPTY,
  0x00, // attestation tag
  ...BTC_ATT_URI,
  0x03, ...HEIGHT_123456,
];

// Pending attestation for a fixed URI. Payload = varbytes(uri bytes), then
// the attestation wraps that as varbytes again. URI string is the oracle.
const PENDING_URI = "https://a.pool.opentimestamps.org";
const pendingAttestation = (() => {
  const uriBytes = ascii(PENDING_URI); // 33 bytes, all in ALLOWED_URI_CHARS
  const payload = [uriBytes.length, ...uriBytes]; // inner varbytes
  return [...PENDING_ATT_URI, payload.length, ...payload];
})();

// ---- helpers ---------------------------------------------------------------

const expectCode = (code, bytesOrFn) => {
  const fn = typeof bytesOrFn === "function" ? bytesOrFn : () => parseDetachedTimestamp(u8(bytesOrFn));
  assert.throws(
    fn,
    (e) => e instanceof OtsParseError && e.code === code,
    `expected OtsParseError ${code}`,
  );
};

// ---- valid proofs -----------------------------------------------------------

test("minimal Bitcoin-attested proof parses; header, digest, and height extracted", () => {
  const out = parseDetachedTimestamp(u8(MINIMAL_BITCOIN_PROOF));
  assert.equal(out.majorVersion, 1);
  assert.equal(out.fileHashOp.name, "sha256");
  assert.equal(out.fileHashOp.digestLength, 32);
  assert.equal(bytesToHex(out.fileDigest), bytesToHex(DIGEST_SHA256_EMPTY));
  assert.equal(out.timestamp.ops.length, 0);
  assert.equal(out.timestamp.attestations.length, 1);
  const att = out.timestamp.attestations[0];
  assert.equal(att.type, "bitcoin");
  assert.equal(att.height, 123456);
});

test("pending attestation: URI extracted as a string", () => {
  const out = parseDetachedTimestamp(u8([...MAGIC, 0x01, 0x08, ...DIGEST_SHA256_EMPTY, 0x00, ...pendingAttestation]));
  const att = out.timestamp.attestations[0];
  assert.equal(att.type, "pending");
  assert.equal(att.uri, PENDING_URI);
});

test("op chain sha256 → append(0xbeef) → prepend(0xdead) → attestation parses as nested children", () => {
  const bytes = [
    ...MAGIC, 0x01, 0x08, ...DIGEST_SHA256_EMPTY,
    0x08, // sha256
    0xf0, 0x02, 0xbe, 0xef, // append varbytes(len 2)
    0xf1, 0x02, 0xde, 0xad, // prepend varbytes(len 2)
    0x00, ...BTC_ATT_URI, 0x03, ...HEIGHT_123456,
  ];
  const out = parseDetachedTimestamp(u8(bytes));
  assert.equal(out.timestamp.attestations.length, 0);
  assert.equal(out.timestamp.ops.length, 1);
  const l1 = out.timestamp.ops[0];
  assert.equal(l1.op.name, "sha256");
  const l2 = l1.child.ops[0];
  assert.equal(l2.op.name, "append");
  assert.deepEqual([...l2.op.arg], [0xbe, 0xef]);
  const l3 = l2.child.ops[0];
  assert.equal(l3.op.name, "prepend");
  assert.deepEqual([...l3.op.arg], [0xde, 0xad]);
  assert.equal(l3.child.attestations[0].type, "bitcoin");
  assert.equal(l3.child.attestations[0].height, 123456);
});

test("DAG fork: 0xff sibling separator yields two op branches on one node", () => {
  const bytes = [
    ...MAGIC, 0x01, 0x08, ...DIGEST_SHA256_EMPTY,
    0xff, 0x08, 0x00, ...BTC_ATT_URI, 0x03, ...HEIGHT_123456, // sibling: sha256 → bitcoin att
    0xf1, 0x02, 0xde, 0xad, 0x00, ...BTC_ATT_URI, 0x03, ...HEIGHT_123456, // final: prepend → bitcoin att
  ];
  const out = parseDetachedTimestamp(u8(bytes));
  assert.equal(out.timestamp.ops.length, 2);
  assert.equal(out.timestamp.ops[0].op.name, "sha256");
  assert.equal(out.timestamp.ops[0].child.attestations[0].type, "bitcoin");
  assert.equal(out.timestamp.ops[1].op.name, "prepend");
  assert.equal(out.timestamp.ops[1].child.attestations[0].height, 123456);
});

test("unknown/future attestation URI parses as type 'unknown' with payload preserved", () => {
  const unknownUri = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
  const bytes = [...MAGIC, 0x01, 0x08, ...DIGEST_SHA256_EMPTY, 0x00, ...unknownUri, 0x02, 0xaa, 0xbb];
  const out = parseDetachedTimestamp(u8(bytes));
  const att = out.timestamp.attestations[0];
  assert.equal(att.type, "unknown");
  assert.equal(att.uriHex, "0102030405060708");
  assert.deepEqual([...att.payload], [0xaa, 0xbb]);
});

test("known-but-unsupported-in-v1 ops (keccak 0x67, reverse 0xf2, hexlify 0xf3) parse structurally", () => {
  // The parser must represent these so the VERIFIER can mark their paths
  // UNSUPPORTED without poisoning sibling branches (#315 result rules).
  const bytes = [
    ...MAGIC, 0x01, 0x08, ...DIGEST_SHA256_EMPTY,
    0x67, // keccak256
    0xf2, // reverse
    0xf3, // hexlify
    0x00, ...BTC_ATT_URI, 0x03, ...HEIGHT_123456,
  ];
  const out = parseDetachedTimestamp(u8(bytes));
  assert.equal(out.timestamp.ops[0].op.name, "keccak256");
  assert.equal(out.timestamp.ops[0].child.ops[0].op.name, "reverse");
  assert.equal(out.timestamp.ops[0].child.ops[0].child.ops[0].op.name, "hexlify");
});

test("sha1 file-hash op yields a 20-byte digest", () => {
  const bytes = [...MAGIC, 0x01, 0x02, ...DIGEST_SHA1_EMPTY, 0x00, ...BTC_ATT_URI, 0x03, ...HEIGHT_123456];
  const out = parseDetachedTimestamp(u8(bytes));
  assert.equal(out.fileHashOp.name, "sha1");
  assert.equal(out.fileDigest.length, 20);
});

test("litecoin attestation parses with height (verifier will mark UNSUPPORTED)", () => {
  const bytes = [...MAGIC, 0x01, 0x08, ...DIGEST_SHA256_EMPTY, 0x00, ...LTC_ATT_URI, 0x03, ...HEIGHT_123456];
  const out = parseDetachedTimestamp(u8(bytes));
  assert.equal(out.timestamp.attestations[0].type, "litecoin");
  assert.equal(out.timestamp.attestations[0].height, 123456);
});

// ---- fail-closed malformed inputs ------------------------------------------

test("empty input → TRUNCATED", () => {
  expectCode("TRUNCATED", []);
});

test("bad magic → BAD_MAGIC", () => {
  const bytes = [...MINIMAL_BITCOIN_PROOF];
  bytes[5] ^= 0xff;
  expectCode("BAD_MAGIC", bytes);
});

test("major version 2 → UNSUPPORTED_VERSION", () => {
  expectCode("UNSUPPORTED_VERSION", [...MAGIC, 0x02, 0x08, ...DIGEST_SHA256_EMPTY, 0x00, ...BTC_ATT_URI, 0x03, ...HEIGHT_123456]);
});

test("non-crypt op as file-hash op (0xf0 append) → UNKNOWN_OP_TAG", () => {
  expectCode("UNKNOWN_OP_TAG", [...MAGIC, 0x01, 0xf0, 0x01, 0x00]);
});

test("digest truncated mid-field → TRUNCATED", () => {
  expectCode("TRUNCATED", [...MAGIC, 0x01, 0x08, ...DIGEST_SHA256_EMPTY.slice(0, 16)]);
});

test("attestation payload truncated → TRUNCATED", () => {
  // varbytes announces 5 bytes, only 2 present
  expectCode("TRUNCATED", [...MAGIC, 0x01, 0x08, ...DIGEST_SHA256_EMPTY, 0x00, ...BTC_ATT_URI, 0x05, 0x01, 0x02]);
});

test("trailing garbage after a complete proof → TRAILING_GARBAGE", () => {
  expectCode("TRAILING_GARBAGE", [...MINIMAL_BITCOIN_PROOF, 0x00]);
});

test("unknown op tag 0x99 in timestamp body → UNKNOWN_OP_TAG", () => {
  expectCode("UNKNOWN_OP_TAG", [...MAGIC, 0x01, 0x08, ...DIGEST_SHA256_EMPTY, 0x99]);
});

test("binary op with empty argument (append len 0) → LENGTH_LIMIT (reference reads min_len=1)", () => {
  expectCode("LENGTH_LIMIT", [...MAGIC, 0x01, 0x08, ...DIGEST_SHA256_EMPTY, 0xf0, 0x00]);
});

test("attestation payload length 8193 → LENGTH_LIMIT (max 8192)", () => {
  // LEB128(8193) = 0x81 0x40; the length check fires before any payload read.
  expectCode("LENGTH_LIMIT", [...MAGIC, 0x01, 0x08, ...DIGEST_SHA256_EMPTY, 0x00, ...BTC_ATT_URI, 0x81, 0x40]);
});

test("varuint with 9 continuation bytes → VARUINT_TOO_LONG", () => {
  expectCode("VARUINT_TOO_LONG", [
    ...MAGIC, 0x01, 0x08, ...DIGEST_SHA256_EMPTY, 0x00, ...BTC_ATT_URI,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  ]);
});

test("timestamp nesting deeper than 256 → RECURSION_LIMIT", () => {
  const deep = [
    ...MAGIC, 0x01, 0x08, ...DIGEST_SHA256_EMPTY,
    ...Array(300).fill(0x08), // 300 nested sha256 ops
    0x00, ...BTC_ATT_URI, 0x03, ...HEIGHT_123456,
  ];
  expectCode("RECURSION_LIMIT", deep);
});

test("pending attestation with disallowed URI character → INVALID_URI", () => {
  // '@' is not in PendingAttestation.ALLOWED_URI_CHARS (notary.py)
  const uri = ascii("https://user@example.com"); // 24 bytes
  const payload = [uri.length, ...uri];
  expectCode("INVALID_URI", [...MAGIC, 0x01, 0x08, ...DIGEST_SHA256_EMPTY, 0x00, ...PENDING_ATT_URI, payload.length, ...payload]);
});

test("non-Uint8Array input → TypeError", () => {
  assert.throws(() => parseDetachedTimestamp("not bytes"), TypeError);
});
