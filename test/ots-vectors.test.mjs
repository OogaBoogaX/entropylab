// OpenTimestamps end-to-end vector tests — issue #315 / PR #460.
//
// Drives every case in test/fixtures/ots/expected.json against the real
// fixture proofs and headers, plus derived cases and synthetic limit proofs.
// Synthetic proofs are built from the wire format as defined by the
// python-opentimestamps reference (serialize.py / op.py / timestamp.py /
// notary.py), never by running the code under test.
//
// Run with: node --test test/ots-vectors.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { verifyOts } from "../src/js/ots-verifier.js";
import { OTS_LIMITS } from "../src/js/ots-parser.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, "fixtures", "ots");

const readFixture = (rel) => new Uint8Array(readFileSync(join(FIXTURES, rel)));
const hexToBytes = (hex) => Uint8Array.from(hex.match(/../g).map((b) => parseInt(b, 16)));
const ascii = (s) => Array.from(s, (c) => c.charCodeAt(0));

const expected = JSON.parse(readFileSync(join(FIXTURES, "expected.json"), "utf8"));
const headers = JSON.parse(readFileSync(join(FIXTURES, "headers.json"), "utf8")).headers;

const headerFor = (height) => (height === null ? null : hexToBytes(headers[String(height)].header));

const RESULTS = new Set([
  "MATCHES_SUPPLIED_HEADER",
  "INVALID",
  "PENDING",
  "UNSUPPORTED",
  "HEADER_REQUIRED",
  "INCOMPLETE",
]);

// ---- fixture vectors ------------------------------------------------------

for (const c of expected.cases) {
  test(`vector: ${c.name}`, async () => {
    const proofBytes = readFixture(c.proof);
    const header = headerFor(c.header);
    const originalFileBytes = c.original ? readFixture(c.original) : null;
    const expectedDigest = c.expectedDigest ? hexToBytes(c.expectedDigest) : null;

    const out = await verifyOts({ proofBytes, header, expectedDigest, originalFileBytes });

    if (c.parseError) {
      assert.equal(out.result, "INVALID");
      assert.ok(
        typeof out.reason === "string" && out.reason.startsWith("parse:"),
        `expected a parse: reason, got ${out.reason}`,
      );
      return;
    }
    assert.equal(out.result, c.result);
    if (c.reason !== undefined) assert.equal(out.reason, c.reason);
    if (c.claimedHeights !== undefined) assert.deepEqual(out.claimedHeights, c.claimedHeights);
    if (c.fileHashOp !== undefined) assert.equal(out.fileHashOp, c.fileHashOp);
  });
}

// ---- derived cases --------------------------------------------------------

test("derived: 970791 header with merkle root bytes reversed → header-mismatch", async () => {
  const header = headerFor(970791);
  const reversed = Uint8Array.from(header);
  reversed.set(Uint8Array.from(header.slice(36, 68)).reverse(), 36);
  const out = await verifyOts({
    proofBytes: readFixture("entropylab-v1.0.0/entropylab.html.ots"),
    header: reversed,
  });
  assert.equal(out.result, "INVALID");
  assert.equal(out.reason, "header-mismatch");
});

test("derived: fabricated header carrying 970791's merkle root still matches", async () => {
  const real = headerFor(970791);
  const fabricated = new Uint8Array(80);
  fabricated.set(real.slice(36, 68), 36);
  const out = await verifyOts({
    proofBytes: readFixture("entropylab-v1.0.0/entropylab.html.ots"),
    header: fabricated,
  });
  assert.equal(out.result, "MATCHES_SUPPLIED_HEADER");
});

test("derived: tampered original file → INVALID / original-file", async () => {
  const original = readFixture("opentimestamps-client/hello-world.txt");
  const tampered = Uint8Array.from(original);
  tampered[tampered.length - 1] ^= 0x01;
  const out = await verifyOts({
    proofBytes: readFixture("opentimestamps-client/hello-world.txt.ots"),
    header: headerFor(358391),
    originalFileBytes: tampered,
  });
  assert.equal(out.result, "INVALID");
  assert.equal(out.reason, "original-file");
  assert.equal(out.original.status, "mismatch");
});

test("derived: sha1 file hash op → unsupported-hash, verdict unchanged", async () => {
  const out = await verifyOts({
    proofBytes: readFixture("opentimestamps-client/bitcoin.pdf.ots"),
    header: headerFor(465751),
    originalFileBytes: new Uint8Array([1, 2, 3]),
  });
  assert.equal(out.original.status, "unsupported-hash");
  assert.equal(out.result, "MATCHES_SUPPLIED_HEADER");
});

test("derived: 20-byte expectedDigest against a 32-byte file digest → expected-digest", async () => {
  const out = await verifyOts({
    proofBytes: readFixture("entropylab-v1.0.0/entropylab.html.ots"),
    header: headerFor(970791),
    expectedDigest: new Uint8Array(20),
  });
  assert.equal(out.result, "INVALID");
  assert.equal(out.reason, "expected-digest");
});

test("derived: 79-byte header → TypeError", async () => {
  await assert.rejects(
    () =>
      verifyOts({
        proofBytes: readFixture("opentimestamps-client/hello-world.txt.ots"),
        header: new Uint8Array(79),
      }),
    (e) => e instanceof TypeError,
  );
});

test("derived: headerTime is the uint32 LE at byte 68 of the supplied header", async () => {
  const header = headerFor(358391);
  const expectedTime = (header[68] | (header[69] << 8) | (header[70] << 16) | (header[71] << 24)) >>> 0;
  const out = await verifyOts({
    proofBytes: readFixture("opentimestamps-client/hello-world.txt.ots"),
    header,
  });
  assert.equal(out.headerTime, expectedTime);
});

// ---- synthetic proof builder ---------------------------------------------

const MAGIC = hexToBytes("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294");
const BTC_ATT_URI = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
const DIGEST = new Uint8Array(32).fill(0x11);

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

const varbytes = (bytes) => [...varuint(bytes.length), ...bytes];

const bitcoinAtt = (height) => [0x00, ...BTC_ATT_URI, ...varbytes(varuint(height))];

const proof = (timestamp) => [...MAGIC, 0x01, 0x08, ...DIGEST, ...timestamp];

const sha256Chain = (n, height = 1) => [...new Array(n).fill(0x08), ...bitcoinAtt(height)];

// A node with k children, each a chain of n sha256 ops ending in an attestation.
const forkOfChains = (k, n) => {
  const out = [];
  for (let i = 0; i < k; i++) {
    if (i < k - 1) out.push(0xff);
    out.push(...sha256Chain(n, i + 1));
  }
  return out;
};

// depth nested 0xff forks: each level is a fork whose first child is a
// sha256 op leading to the next level.
const nestedForks = (depth) => {
  if (depth === 0) return bitcoinAtt(1);
  return [0xff, 0x08, ...nestedForks(depth - 1), ...bitcoinAtt(1)];
};

const manyAttestations = (n) => {
  const out = [];
  for (let i = 0; i < n; i++) {
    if (i < n - 1) out.push(0xff);
    out.push(...bitcoinAtt(i + 1));
  }
  return out;
};

// A valid proof of exactly `size` bytes: append ops with 4096-byte args,
// finished with one smaller append op, then a Bitcoin attestation.
const proofOfSize = (size) => {
  const head = [...MAGIC, 0x01, 0x08, ...DIGEST];
  const tail = bitcoinAtt(1);
  let remaining = size - head.length - tail.length;
  const ops = [];
  while (remaining > 0) {
    let argLen = Math.min(4096, remaining - 3);
    if (argLen < 1) argLen = 1;
    let cost = 1 + varuint(argLen).length + argLen;
    while (cost > remaining && argLen > 1) {
      argLen -= 1;
      cost = 1 + varuint(argLen).length + argLen;
    }
    if (cost > remaining) throw new Error(`cannot fill ${remaining} bytes`);
    ops.push(0xf0, ...varuint(argLen), ...new Array(argLen).fill(0xaa));
    remaining -= cost;
  }
  return [...head, ...ops, ...tail];
};

// ---- resource limits ------------------------------------------------------

test("limit: MAX_OPS exactly parses, one over is INCOMPLETE/too-many-ops", async () => {
  const perPath = OTS_LIMITS.MAX_PATH_OPS;
  const paths = Math.floor(OTS_LIMITS.MAX_OPS / perPath);

  const atLimit = Uint8Array.from(proof(forkOfChains(paths, perPath)));
  const outAt = await verifyOts({ proofBytes: atLimit, header: null });
  assert.notEqual(outAt.reason, "too-many-ops");

  // Root cause: malformed test proof, not a parser bug. The old "over" proof
  // appended a fork after a completed sha256 chain, but the wire format has no
  // separator between a node's final child and EOF, so the parser stopped
  // after the first chain and reported TRAILING_GARBAGE (INVALID) before it
  // ever counted the 1025th op. Build a valid tree with exactly MAX_OPS + 1 op
  // nodes: one fork of `paths` full chains plus a single extra op, all within
  // MAX_PATH_OPS and MAX_FORK_NESTING.
  const overChildren = [
    ...Array.from({ length: paths }, (_, i) => sha256Chain(perPath, i + 1)),
    sha256Chain(1, 1),
  ];
  const over = Uint8Array.from(
    proof(overChildren.flatMap((c, i) => (i < overChildren.length - 1 ? [0xff, ...c] : c))),
  );
  const outOver = await verifyOts({ proofBytes: over, header: null });
  assert.equal(outOver.result, "INCOMPLETE");
  assert.equal(outOver.reason, "too-many-ops");
});

test("limit: MAX_PATH_OPS exactly parses, one over is INCOMPLETE/path-too-long", async () => {
  const atLimit = Uint8Array.from(proof(sha256Chain(OTS_LIMITS.MAX_PATH_OPS, 1)));
  const outAt = await verifyOts({ proofBytes: atLimit, header: null });
  assert.notEqual(outAt.reason, "path-too-long");

  const over = Uint8Array.from(proof(sha256Chain(OTS_LIMITS.MAX_PATH_OPS + 1, 1)));
  const outOver = await verifyOts({ proofBytes: over, header: null });
  assert.equal(outOver.result, "INCOMPLETE");
  assert.equal(outOver.reason, "path-too-long");
});

test("limit: MAX_FORK_NESTING exactly parses, one over is INCOMPLETE/fork-nesting", async () => {
  const atLimit = Uint8Array.from(proof(nestedForks(OTS_LIMITS.MAX_FORK_NESTING)));
  const outAt = await verifyOts({ proofBytes: atLimit, header: null });
  assert.notEqual(outAt.reason, "fork-nesting");

  const over = Uint8Array.from(proof(nestedForks(OTS_LIMITS.MAX_FORK_NESTING + 1)));
  const outOver = await verifyOts({ proofBytes: over, header: null });
  assert.equal(outOver.result, "INCOMPLETE");
  assert.equal(outOver.reason, "fork-nesting");
});

test("limit: MAX_ATTESTATIONS exactly parses, one over is INCOMPLETE/too-many-attestations", async () => {
  const atLimit = Uint8Array.from(proof(manyAttestations(OTS_LIMITS.MAX_ATTESTATIONS)));
  const outAt = await verifyOts({ proofBytes: atLimit, header: null });
  assert.notEqual(outAt.reason, "too-many-attestations");

  const over = Uint8Array.from(proof(manyAttestations(OTS_LIMITS.MAX_ATTESTATIONS + 1)));
  const outOver = await verifyOts({ proofBytes: over, header: null });
  assert.equal(outOver.result, "INCOMPLETE");
  assert.equal(outOver.reason, "too-many-attestations");
});

test("limit: MAX_PROOF_BYTES exactly parses, one byte over is INCOMPLETE/proof-too-large", async () => {
  const atLimit = Uint8Array.from(proofOfSize(OTS_LIMITS.MAX_PROOF_BYTES));
  assert.equal(atLimit.length, OTS_LIMITS.MAX_PROOF_BYTES);
  const outAt = await verifyOts({ proofBytes: atLimit, header: null });
  assert.notEqual(outAt.reason, "proof-too-large");

  const over = new Uint8Array(OTS_LIMITS.MAX_PROOF_BYTES + 1);
  over.set(atLimit, 0);
  const outOver = await verifyOts({ proofBytes: over, header: null });
  assert.equal(outOver.result, "INCOMPLETE");
  assert.equal(outOver.reason, "proof-too-large");
});

// ---- integers and errors --------------------------------------------------

test("a varbytes length encoded in 8 bytes above its limit → parse: reason", async () => {
  const bytes = Uint8Array.from([
    ...MAGIC, 0x01, 0x08, ...DIGEST, 0x00, ...BTC_ATT_URI,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
  ]);
  const out = await verifyOts({ proofBytes: bytes, header: null });
  assert.equal(out.result, "INVALID");
  assert.ok(out.reason.startsWith("parse:"), `got ${out.reason}`);
});

test("a 9-byte varuint → parse: reason", async () => {
  const bytes = Uint8Array.from([
    ...MAGIC, 0x01, 0x08, ...DIGEST, 0x00, ...BTC_ATT_URI,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  ]);
  const out = await verifyOts({ proofBytes: bytes, header: null });
  assert.equal(out.result, "INVALID");
  assert.ok(out.reason.startsWith("parse:"), `got ${out.reason}`);
});

test("a lone Bitcoin attestation with height 2^40 → UNSUPPORTED", async () => {
  const bytes = Uint8Array.from(proof(bitcoinAtt(2 ** 40)));
  const out = await verifyOts({ proofBytes: bytes, header: null });
  assert.equal(out.result, "UNSUPPORTED");
});

test("every proper prefix of hello-world.txt.ots is INVALID with a parse: reason", async () => {
  const full = readFixture("opentimestamps-client/hello-world.txt.ots");
  for (let n = 0; n < full.length; n++) {
    const out = await verifyOts({ proofBytes: full.slice(0, n), header: null });
    assert.equal(out.result, "INVALID", `prefix ${n}`);
    assert.ok(
      typeof out.reason === "string" && out.reason.startsWith("parse:"),
      `prefix ${n} gave ${out.reason}`,
    );
  }
});

test("one appended byte → parse: reason", async () => {
  const full = readFixture("opentimestamps-client/hello-world.txt.ots");
  const out = await verifyOts({ proofBytes: Uint8Array.from([...full, 0x00]), header: null });
  assert.equal(out.result, "INVALID");
  assert.ok(out.reason.startsWith("parse:"), `got ${out.reason}`);
});

// ---- fuzzing --------------------------------------------------------------

const mulberry32 = (seed) => () => {
  seed |= 0;
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};

for (const [name, proofPath, height] of [
  ["hello-world", "opentimestamps-client/hello-world.txt.ots", 358391],
  ["v1.0.0", "entropylab-v1.0.0/entropylab.html.ots", 970791],
]) {
  test(`fuzz: 2000 single-byte mutations of ${name} never throw`, async () => {
    const base = readFixture(proofPath);
    const header = headerFor(height);
    const rand = mulberry32(0x5eed);
    for (let i = 0; i < 2000; i++) {
      const mutated = Uint8Array.from(base);
      const pos = Math.floor(rand() * mutated.length);
      mutated[pos] ^= 1 + Math.floor(rand() * 255);
      const out = await verifyOts({ proofBytes: mutated, header });
      assert.ok(RESULTS.has(out.result), `mutation ${i} gave ${out.result}`);
    }
  });
}
