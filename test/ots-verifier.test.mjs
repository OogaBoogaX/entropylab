// OpenTimestamps verifier tests — issue #315, phase 2.
//
// Async because the verifier routes SHA-1 through `crypto.subtle.digest`
// (Promise). Node 19+ and all modern browsers expose `crypto.subtle`
// natively, so no module shim is needed.
//
// Fixture provenance: every byte string below is hand-constructed from the
// format spec; digest anchors are NIST-published SHA-256, SHA-1, and
// RIPEMD-160 test vectors. The SHA-1 wiring test cross-checks the
// verifier's output against `crypto.subtle.digest` directly (dispatcher
// wiring, not cross-implementation correctness).
//
// Run with: node --test test/ots-verifier.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";

import { verifyOts } from "../src/js/ots-verifier.js";

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

// SHA-1 op (0x02) feeding a pending attestation. Tests WebCrypto SHA-1
// wiring through the verifier dispatcher. file_hash_op = ripemd160 (0x03)
// so the 20-byte RIPEMD-160 digest matches the parser's digestLength.
const proofSha1ThenPending = (digest = DIGEST_RIPEMD160_ABC) =>
  u8([...MAGIC, 0x01, 0x03, ...digest, 0x02, 0x00, ...pendingAttestation]);

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

test("expectedDigest mismatch → overall INVALID (cryptographic failure, single path)", async () => {
  const out = await verifyOts({
    proofBytes: proofBitcoin(DIGEST_SHA256_ABC),
    header: null,
    expectedDigest: DIGEST_SHA256_EMPTY,
  });
  assert.equal(out.result, "INVALID");
  assert.equal(out.paths[0].outcome, "expected-digest-mismatch");
  assert.match(out.paths[0].detail, /ba78/, "detail cites both expected and actual digests");
});

test("precedence rule 3 with existence scan: pending behind keccak barrier → PENDING (NOT UNSUPPORTED)", async () => {
  const out = await verifyOts({ proofBytes: proofKeccakThenPending(), header: null });
  assert.equal(out.result, "PENDING");
  assert.equal(out.paths[0].outcome, "unsupported-op");
  assert.equal(out.paths[0].opNames[0], "keccak256");
});

test("SHA-1 op (WebCrypto) wired: fileDigest → sha1 → 20-byte pending attestation", async () => {
  // No NIST-published vector for sha1(ripemd160("abc")), so cross-check
  // against crypto.subtle.digest directly — validates dispatcher wiring.
  const out = await verifyOts({ proofBytes: proofSha1ThenPending(), header: null });
  assert.equal(out.paths[0].opNames[0], "sha1");
  assert.equal(out.paths[0].finalDigest.length, 20, "SHA-1 produces a 20-byte digest");
  const direct = new Uint8Array(await crypto.subtle.digest("SHA-1", DIGEST_RIPEMD160_ABC));
  assert.deepEqual(Array.from(out.paths[0].finalDigest), Array.from(direct), "verifier and WebCrypto produce identical SHA-1 output");
  assert.equal(out.result, "PENDING");
});

test("bitcoin att with no supplied header → 'no-header' outcome; falls to UNSUPPORTED", async () => {
  const out = await verifyOts({ proofBytes: proofBitcoin(), header: null });
  assert.equal(out.result, "UNSUPPORTED");
  assert.equal(out.paths[0].outcome, "no-header");
  assert.match(out.paths[0].detail, /no header/i);
});

test("header length != 80 → RangeError", async () => {
  await assert.rejects(
    () => verifyOts({ proofBytes: proofBitcoin(), header: new Uint8Array(79) }),
    (e) => e instanceof RangeError,
  );
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
