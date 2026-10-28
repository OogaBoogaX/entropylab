// OpenTimestamps verifier tests — issue #315, phase 2.
//
// Fixture provenance: every byte string below is hand-constructed from the
// format spec; digest anchors are NIST-published SHA-256, SHA-1, and
// RIPEMD-160 test vectors.
//
// Run with: node --test test/ots-verifier.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";

import { verifyOts } from "../src/js/ots-verifier.js";
import { OTS_LIMITS } from "../src/js/ots-parser.js";

// ---- byte helpers ---------------------------------------------------------

const u8 = (arr) => Uint8Array.from(arr);
const ascii = (s) => Array.from(s, (c) => c.charCodeAt(0));
const hexToBytes = (hex) => u8(hex.match(/../g).map((b) => parseInt(b, 16)));

// ---- format anchors (literal, spec-derived) -------------------------------

const MAGIC = [
  0x00,
  ...ascii("OpenTimestamps"),
  0x00, 0x00,
  ...ascii("Proof"),
  0x00,
  0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
];

// NIST-published SHA-256 vectors.
const DIGEST_SHA256_ABC = hexToBytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
const DIGEST_SHA256_EMPTY = hexToBytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

// NIST-published RIPEMD-160 vector (used for the SHA-1 op wiring test —
// 32-byte input so the sha1 op transforms into a 20-byte digest).
const DIGEST_RIPEMD160_ABC = hexToBytes("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
const DIGEST_SHA1_EMPTY = hexToBytes("da39a3ee5e6b4b0d3255bfef95601890afd80709");

const BTC_ATT_URI = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
const PENDING_ATT_URI = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
const LTC_ATT_URI = [0x06, 0x86, 0x9a, 0x0d, 0x73, 0xd7, 0x1b, 0x45];
const HEIGHT_123456 = [0xc0, 0xc4, 0x07]; // LEB128(123456)

const PENDING_URI = "https://a.pool.opentimestamps.org"; // 33 bytes, charset-safe

const pendingAttestation = (() => {
  const uriBytes = ascii(PENDING_URI);
  return [...PENDING_ATT_URI, uriBytes.length + 1, uriBytes.length, ...uriBytes];
})();

const bitcoinAttestation = [...BTC_ATT_URI, 0x03, ...HEIGHT_123456];
const litecoinAttestation = [...LTC_ATT_URI, 0x03, ...HEIGHT_123456];

// 80-byte Bitcoin block header. Merkle root field lives at bytes [36, 68);
// other fields are zeroed (the verifier only reads the merkle root).
function makeHeader(merkleRoot) {
  assert.equal(merkleRoot.length, 32, "merkle_root field is exactly 32 bytes");
  const h = new Uint8Array(80);
  h.set(merkleRoot, 36);
  return h;
}

// ---- fixture builders -----------------------------------------------------

// Bitcoin proof with no ops; fileDigest IS the attested digest.
const proofBitcoin = (digest = DIGEST_SHA256_ABC) =>
  u8([...MAGIC, 0x01, 0x08, ...digest, 0x00, ...bitcoinAttestation]);

const proofPending = (digest = DIGEST_SHA256_ABC) =>
  u8([...MAGIC, 0x01, 0x08, ...digest, 0x00, ...pendingAttestation]);

const proofLitecoin = (digest = DIGEST_SHA256_ABC) =>
  u8([...MAGIC, 0x01, 0x08, ...digest, 0x00, ...litecoinAttestation]);

// Bitcoin attestation + litecoin sibling attestation on one node, no ops.
const proofBitcoinAndLitecoin = () =>
  u8([
    ...MAGIC, 0x01, 0x08, ...DIGEST_SHA256_ABC,
    0xff, 0x00, ...bitcoinAttestation,
    0x00, ...litecoinAttestation,
  ]);

// Pending attestation + litecoin sibling attestation on one node, no ops.
const proofPendingAndLitecoin = () =>
  u8([
    ...MAGIC, 0x01, 0x08, ...DIGEST_SHA256_ABC,
    0xff, 0x00, ...pendingAttestation,
    0x00, ...litecoinAttestation,
  ]);

// Keccak256 op (unsupported-in-v1) gates a pending attestation. The op
// blocks path evaluation; the pending attestation still exists structurally.
const proofKeccakThenPending = () =>
  u8([
    ...MAGIC, 0x01, 0x08, ...DIGEST_SHA256_ABC,
    0x67, // keccak256 — unsupported in v1
    0x00, ...pendingAttestation,
  ]);

// SHA-1 op (0x02) on one branch, a direct pending attestation on a sibling
// branch. SHA-1 is unsupported, so its path is unsupported-op; the sibling
// must still evaluate.
const proofSha1AndPendingSibling = (digest = DIGEST_RIPEMD160_ABC) =>
  u8([
    ...MAGIC, 0x01, 0x03, ...digest,
    0xff, 0x02, 0x00, ...pendingAttestation,
    0x00, ...pendingAttestation,
  ]);

// LEB128 varuint, written from the format definition (serialize.py).
const varuint = (n) => {
  const out = [];
  let v = BigInt(n);
  for (;;) {
    const b = Number(v & 0x7fn);
    v >>= 7n;
    if (v === 0n) {
      out.push(b);
      return out;
    }
    out.push(b | 0x80);
  }
};

// ---- tests ----------------------------------------------------------------

test("MATCHES_SUPPLIED_HEADER: no-op bitcoin att where fileDigest equals supplied header merkle root", async () => {
  const header = makeHeader(DIGEST_SHA256_ABC);
  const out = await verifyOts({ proofBytes: proofBitcoin(), header });
  assert.equal(out.result, "MATCHES_SUPPLIED_HEADER");
  assert.equal(out.summary.matches, 1);
  assert.equal(out.paths[0].outcome, "matches");
  assert.equal(out.fileHashOp, "sha256");
});

test("INVALID / mismatch: same proof, merkle root differs from fileDigest", async () => {
  const header = makeHeader(DIGEST_SHA256_EMPTY);
  const out = await verifyOts({ proofBytes: proofBitcoin(), header });
  assert.equal(out.result, "INVALID");
  assert.equal(out.summary.mismatch, 1);
  assert.equal(out.paths[0].outcome, "mismatch");
  assert.match(out.paths[0].detail, /merkle_root/i, "detail cites the merkle_root that disagreed");
});

test("PENDING: pending-only proof, no header", async () => {
  const out = await verifyOts({ proofBytes: proofPending(), header: null });
  assert.equal(out.result, "PENDING");
  assert.equal(out.summary.pending, 1);
  assert.equal(out.paths[0].outcome, "pending");
});

test("UNSUPPORTED: litecoin-only proof (no pending, no completed bitcoin)", async () => {
  const out = await verifyOts({ proofBytes: proofLitecoin(), header: null });
  assert.equal(out.result, "UNSUPPORTED");
  assert.equal(out.paths[0].outcome, "unsupported-attestation");
});

test("precedence rule 1: bitcoin match wins despite litecoin sibling", async () => {
  const header = makeHeader(DIGEST_SHA256_ABC);
  const out = await verifyOts({ proofBytes: proofBitcoinAndLitecoin(), header });
  assert.equal(out.result, "MATCHES_SUPPLIED_HEADER");
  assert.equal(out.summary.matches, 1);
  const outcomes = out.paths.map((p) => p.outcome);
  assert.ok(outcomes.includes("matches"), "matched bitcoin path recorded");
  assert.ok(outcomes.includes("unsupported-attestation"), "litecoin sibling recorded");
});

test("precedence rule 2: bitcoin mismatch + litecoin sibling → INVALID", async () => {
  const header = makeHeader(DIGEST_SHA256_EMPTY);
  const out = await verifyOts({ proofBytes: proofBitcoinAndLitecoin(), header });
  assert.equal(out.result, "INVALID");
  assert.equal(out.summary.mismatch, 1);
});

test("precedence rule 3: pending + litecoin → PENDING (no completed bitcoin evaluated)", async () => {
  const out = await verifyOts({ proofBytes: proofPendingAndLitecoin(), header: null });
  assert.equal(out.result, "PENDING");
  assert.ok(out.paths.find((p) => p.outcome === "pending"));
});

test("expectedDigest mismatch → overall INVALID / expected-digest", async () => {
  const out = await verifyOts({
    proofBytes: proofBitcoin(DIGEST_SHA256_ABC),
    header: null,
    expectedDigest: DIGEST_SHA256_EMPTY,
  });
  assert.equal(out.result, "INVALID");
  assert.equal(out.reason, "expected-digest");
});

test("pending behind an unsupported op is not reachable → UNSUPPORTED", async () => {
  const out = await verifyOts({ proofBytes: proofKeccakThenPending(), header: null });
  assert.equal(out.result, "UNSUPPORTED");
  assert.equal(out.paths[0].outcome, "unsupported-op");
  assert.equal(out.paths[0].opNames[0], "keccak256");
});

test("sha1 op is unsupported; a pending sibling still evaluates → PENDING", async () => {
  const out = await verifyOts({ proofBytes: proofSha1AndPendingSibling(), header: null });
  assert.equal(out.result, "PENDING");
  const outcomes = out.paths.map((p) => p.outcome);
  assert.ok(outcomes.includes("unsupported-op"), "sha1 path recorded as unsupported-op");
  assert.ok(outcomes.includes("pending"), "sibling pending path still evaluated");
});

test("bitcoin att with no supplied header → HEADER_REQUIRED with claimed heights", async () => {
  const out = await verifyOts({ proofBytes: proofBitcoin(), header: null });
  assert.equal(out.result, "HEADER_REQUIRED");
  assert.deepEqual(out.claimedHeights, [123456]);
  assert.equal(out.paths[0].outcome, "no-header");
});

test("header length != 80 → TypeError", async () => {
  await assert.rejects(
    () => verifyOts({ proofBytes: proofBitcoin(), header: new Uint8Array(79) }),
    (e) => e instanceof TypeError,
  );
});

test("wrong argument types → TypeError", async () => {
  await assert.rejects(() => verifyOts({ proofBytes: "nope" }), (e) => e instanceof TypeError);
  await assert.rejects(() => verifyOts({ proofBytes: proofBitcoin(), header: "nope" }), (e) => e instanceof TypeError);
  await assert.rejects(() => verifyOts({ proofBytes: proofBitcoin(), expectedDigest: "nope" }), (e) => e instanceof TypeError);
  await assert.rejects(() => verifyOts({ proofBytes: proofBitcoin(), originalFileBytes: "nope" }), (e) => e instanceof TypeError);
});

test("an append op that pushes the message past 4096 bytes → INVALID / op-too-long", async () => {
  // 32-byte digest + append(4096) = 4128 > 4096.
  const arg = new Array(4096).fill(0xaa);
  const bytes = u8([
    ...MAGIC, 0x01, 0x08, ...DIGEST_SHA256_ABC,
    0xf0, ...varuint(4096), ...arg,
    0x00, ...bitcoinAttestation,
  ]);
  const out = await verifyOts({ proofBytes: bytes, header: makeHeader(DIGEST_SHA256_ABC) });
  assert.equal(out.result, "INVALID");
  assert.equal(out.reason, "op-too-long");
});

test("originalFileBytes: sha256 match → 'matches', verdict unchanged", async () => {
  const out = await verifyOts({
    proofBytes: proofBitcoin(DIGEST_SHA256_EMPTY),
    header: makeHeader(DIGEST_SHA256_EMPTY),
    originalFileBytes: new Uint8Array(0),
  });
  assert.equal(out.original.status, "matches");
  assert.equal(out.result, "MATCHES_SUPPLIED_HEADER");
});

test("originalFileBytes: sha256 mismatch → INVALID / original-file", async () => {
  const out = await verifyOts({
    proofBytes: proofBitcoin(DIGEST_SHA256_EMPTY),
    header: makeHeader(DIGEST_SHA256_EMPTY),
    originalFileBytes: u8(ascii("x")),
  });
  assert.equal(out.original.status, "mismatch");
  assert.equal(out.result, "INVALID");
  assert.equal(out.reason, "original-file");
});

test("originalFileBytes: sha1 file hash op → unsupported-hash, verdict unchanged", async () => {
  const proof = u8([...MAGIC, 0x01, 0x02, ...DIGEST_SHA1_EMPTY, 0x00, ...bitcoinAttestation]);
  const out = await verifyOts({ proofBytes: proof, header: null, originalFileBytes: u8(ascii("anything")) });
  assert.equal(out.original.status, "unsupported-hash");
  assert.equal(out.result, "HEADER_REQUIRED");
});

test("originalFileBytes over MAX_ORIGINAL_BYTES → 'too-large', verdict unchanged", async () => {
  const big = new Uint8Array(OTS_LIMITS.MAX_ORIGINAL_BYTES + 1);
  const out = await verifyOts({
    proofBytes: proofBitcoin(DIGEST_SHA256_EMPTY),
    header: makeHeader(DIGEST_SHA256_EMPTY),
    originalFileBytes: big,
  });
  assert.equal(out.original.status, "too-large");
  assert.equal(out.result, "MATCHES_SUPPLIED_HEADER");
});

test("bitcoin att with valid header but attested digest wrong length (32B file + sha256 op mismatched) → mismatch", async () => {
  // fileDigest = sha256("abc") (32 bytes). Op = sha256 produces 32 bytes but
  // flips the digest. merkle_root = sha256("abc") so the op-applied digest
  // is sha256(sha256("abc")) which is NOT NIST-published, so we don't try
  // to predict it; we just verify a deterministic mismatch outcome instead.
  const header = makeHeader(DIGEST_SHA256_ABC); // sha256 of "abc"
  const out = await verifyOts({
    proofBytes: u8([...MAGIC, 0x01, 0x08, ...DIGEST_SHA256_ABC, 0x08, 0x00, ...bitcoinAttestation]),
    header,
  });
  assert.equal(out.result, "INVALID");
  assert.equal(out.paths[0].opNames[0], "sha256", "SHA-256 op was actually applied");
  assert.equal(out.paths[0].outcome, "mismatch");
});
