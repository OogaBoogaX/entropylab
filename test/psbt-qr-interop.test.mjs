// BCR-2024-001 / BCR-2020-005 independent interoperability acceptance
// tests for the bounded fountain collector (createUrCollector) in
// src/js/ur-fountain.js. These verify that EntropyLab reassembles the
// *reference* BCR-2024-001 streams correctly, independently of any in-repo
// output: the expected reassembled bytes are read from the BCR-2024-001
// reference vectors (test/fixtures/bc-ur/reference-vectors.json, BSD-2-Clause-
// Patent), never computed by the collector under test.
//
// Security contract: the collector only ever emits "complete" for a BCR-2024-
// 001 stream whose reassembled message passes the CRC-32 and zero-padding
// checks; malformed, conflicting, over-budget or non-progress input is refused
// with a status code and its owned buffers are zeroed on failure. A checksum
// is not authentication and never establishes transaction validity — it only
// gates the collector's "complete" status.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  findNominalFragmentLength,
  partitionMessage,
  chooseFragments,
  createUrCollector,
} from "../src/js/ur-fountain.js";
import {
  hodlCrc32,
  hodlBytewordsEncode,
  hodlUrPartCbor,
} from "../src/js/psbt-ur.js";

const vectors = JSON.parse(
  readFileSync(new URL("./fixtures/bc-ur/reference-vectors.json", import.meta.url)),
);

const hex = (s) => Uint8Array.from(s.match(/../g).map((b) => parseInt(b, 16)));
const concat = (...parts) => Uint8Array.from(parts.flatMap((p) => [...p]));
const xorInto = (target, source) => {
  for (let i = 0; i < target.length; i++) target[i] ^= source[i];
};
const crc32Number = (bytes) => {
  const crc = hodlCrc32(bytes);
  return ((crc[0] << 24) | (crc[1] << 16) | (crc[2] << 8) | crc[3]) >>> 0;
};

// Independent message bytes, taken from the BCR-2024-001 partition vector
// (not from the collector). The fountain vector's message is its first 256
// bytes; the CBOR-wrapped vector is a 3-byte in-repo byte-string header over
// those 256 bytes.
const message1024 = concat(...vectors.partition.fragments.map(hex)).slice(
  0,
  vectors.partition.messageLen,
);
const message256 = message1024.slice(0, 256);
const message50 = message1024.slice(0, 50);

// Independent construction of the in-repo CBOR byte-string header for a
// 256-byte payload (0x59 + 2-byte length in the in-repo convention), so the
// expected CBOR-wrapped bytes do not depend on the in-repo serializer.
const cborHeaderFor = (len) => {
  if (len < 24) return new Uint8Array([0x40 + len]);
  if (len < 256) return new Uint8Array([0x58, len]);
  if (len < 65536) return new Uint8Array([0x59, (len >>> 8) & 255, len & 255]);
  return new Uint8Array([
    0x5a,
    len >>> 24,
    (len >>> 16) & 255,
    (len >>> 8) & 255,
    len & 255,
  ]);
};
const message256Ur = concat(cborHeaderFor(256), message256);
const message50Ur = concat(cborHeaderFor(50), message50);

const fragmentLenFor = (message, maxFragmentLen) =>
  findNominalFragmentLength(message.length, 10, maxFragmentLen);

const makePart = (message, maxFragmentLen, seqNum) => {
  const fragmentLen = fragmentLenFor(message, maxFragmentLen);
  const fragments = partitionMessage(message, fragmentLen);
  const seqLen = fragments.length;
  const checksum = crc32Number(message);
  const indexes = chooseFragments(seqNum, seqLen, checksum);
  const data = new Uint8Array(fragmentLen);
  for (const idx of indexes) xorInto(data, fragments[idx]);
  return { seqNum, seqLen, messageLen: message.length, checksum, data };
};

const toUr = (part, type = "bytes") =>
  "ur:" +
  type +
  "/" +
  part.seqNum +
  "-" +
  part.seqLen +
  "/" +
  hodlBytewordsEncode(
    hodlUrPartCbor(part.seqNum, part.seqLen, part.messageLen, part.checksum, typeof part.data === "string" ? hex(part.data) : part.data),
    "minimal",
  );

const feed = (collector, parts) => {
  let completed, last;
  for (const part of parts) {
    last = collector.receive(part);
    if (last.status === "complete") completed = last;
    else assert.equal(last.status, completed ? "done" : "progress");
  }
  return completed ?? last;
};

// Build a stream that completes: systematic parts (1..seqLen) plus enough
// fountain parts (seqNum seqLen+1 ..) that the message reassembles. Returns
// the list of UR texts in emission order.
const completeStreamUr = (message, maxFragmentLen, maxTotal = 200) => {
  const checksum = crc32Number(message);
  const collector = createUrCollector({ types: ["bytes"] });
  const parts = [];
  for (let i = 0; i < maxTotal; i++) {
    const ur = toUr(makePart(message, maxFragmentLen, i + 1));
    const result = collector.receive(ur);
    parts.push(ur);
    if (result.status === "complete") break;
  }
  return parts;
};

test("systematic + fountain frames in order complete to the vector message (raw)", () => {
  const collector = createUrCollector({ types: ["bytes"] });
  const parts = vectors.fountainEncoder.parts.slice();
  assert.equal(parts.length, 20);
  const result = feed(collector, parts.map((part) => toUr(part)));
  assert.equal(result.status, "complete");
  // Expected bytes = the vector message (partition fragments), independent of
  // the collector.
  assert.deepEqual(
    Array.from(result.message),
    Array.from(message256),
    "reassembled bytes must equal the BCR-2024-001 vector message",
  );
});

test("systematic + fountain frames in order complete to the vector message (CBOR-wrapped)", () => {
  const collector = createUrCollector({ types: ["bytes"] });
  const parts = vectors.urEncoder.parts; // literal UR text from the vector file
  assert.equal(parts.length, 20);
  const result = feed(collector, parts);
  assert.equal(result.status, "complete");
  // The CBOR-wrapped vector message is [0x59,0x01,0x00] + message256; the
  // 256-byte payload must equal the vector message.
  assert.equal(result.message.length, 259);
  assert.deepEqual(Array.from(result.message.slice(0, 3)), [0x59, 0x01, 0x00]);
  assert.deepEqual(
    Array.from(result.message.slice(3)),
    Array.from(message256),
    "CBOR-wrapped payload must equal the vector message",
  );
});

test("fountain frames only (systematic skipped) complete to the vector message", () => {
  const collector = createUrCollector({ types: ["bytes"] });
  const seqLen = vectors.fountainEncoder.parts[0].seqLen;
  assert.equal(seqLen, 9);
  const result = feed(collector, vectors.fountainEncoder.parts.slice(seqLen).map((part) => toUr(part)));
  assert.equal(result.status, "complete");
  assert.deepEqual(Array.from(result.message), Array.from(message256));
});

test("the same stream in reversed order completes to the vector message", () => {
  const collector = createUrCollector({ types: ["bytes"] });
  const parts = vectors.fountainEncoder.parts.slice().reverse();
  const result = feed(collector, parts.map((part) => toUr(part)));
  assert.equal(result.status, "complete");
  assert.deepEqual(Array.from(result.message), Array.from(message256));
});

test("deterministic loss: dropping a single frame from the non-redundant core leaves the collector partial, never complete", () => {
  // The reference fountain is redundant, so dropping one of its frames is
  // usually recoverable. The "never complete" property holds for the
  // non-redundant systematic core (seqNum 1..seqLen), which is what a
  // deterministic single-frame loss must expose. Each frame is received at
  // most once; dropping any one leaves exactly one fragment unknown.
  const seqLen = vectors.fountainEncoder.parts[0].seqLen;
  const systematic = vectors.fountainEncoder.parts.slice(0, seqLen);
  for (let drop = 0; drop < seqLen; drop++) {
    const collector = createUrCollector({ types: ["bytes"] });
    let last;
    for (let i = 0; i < seqLen; i++) {
      if (i === drop) continue;
      last = collector.receive(toUr(systematic[i]));
    }
    assert.notEqual(last.status, "complete");
    assert.equal(last.status, "progress");
    assert.equal(collector.state().known, seqLen - 1);
  }
});

test("the full fountain stream recovers any single dropped frame (redundancy)", () => {
  // Complement of the loss test: the 20-part fountain stream has enough
  // redundancy that dropping exactly one frame still reassembles the vector
  // message.
  const parts = vectors.fountainEncoder.parts.slice();
  for (let drop = 0; drop < parts.length; drop++) {
    const collector = createUrCollector({ types: ["bytes"] });
    const result = feed(collector, parts.filter((_, index) => index !== drop).map((part) => toUr(part)));
    assert.equal(result.status, "complete", "fountain stream dropping frame " + (drop + 1));
    assert.deepEqual(Array.from(result.message), Array.from(message256));
  }
});

test("duplicates at multiple densities: repeat all / repeat half / triple complete where recoverable", () => {
  // Two densities (fragment size -> seqLen): the reference density (30 -> 9
  // fragments) and a high density (100 -> 3 fragments). For each, a base
  // stream that completes; duplicates are idempotent and must never trigger a
  // conflict while the stream still completes.
  for (const maxFragmentLen of [30, 100]) {
    const base = completeStreamUr(message256, maxFragmentLen);
    assert.ok(base.length > 0, "base stream produced for density " + maxFragmentLen);
    // The base stream completes on its own.
    {
      const collector = createUrCollector({ types: ["bytes"] });
      let result;
      for (const ur of base) result = collector.receive(ur);
      assert.equal(result.status, "complete", "base stream for density " + maxFragmentLen);
    }
    const assertComplete = (feed, label) => {
      const collector = createUrCollector({ types: ["bytes"] });
      let completed = false;
      for (const ur of feed) {
        const s = collector.receive(ur);
        if (s.status === "complete") completed = true;
        assert.notEqual(s.status, "conflict", label + ": duplicate must not conflict");
        assert.notEqual(s.status, "invalid", label + ": duplicate must not be invalid");
      }
      assert.ok(completed, label + ": stream must complete");
      assert.equal(
        collector.state().status,
        "complete",
        label + ": final collector status must be complete",
      );
    };
    assertComplete(base.flatMap((u) => [u, u]), "repeat all");
    assertComplete(
      base.slice(0, Math.floor(base.length / 2)).flatMap((u) => [u, u]).concat(
        base.slice(Math.floor(base.length / 2)),
      ),
      "repeat half",
    );
    assertComplete(base.flatMap((u) => [u, u, u]), "triple");
  }
});

test("a single-part vector UR completes to its vector message", () => {
  const collector = createUrCollector({ types: ["bytes"] });
  const result = collector.receive(vectors.singlePartUr.ur);
  assert.equal(result.status, "complete");
  // The vector's 50-byte single-part payload is the in-repo byte-string
  // header for a 50-byte payload plus the first 50 bytes of the partition
  // message.
  const header = cborHeaderFor(50);
  assert.equal(result.message.length, 50 + header.length);
  assert.deepEqual(Array.from(result.message.slice(0, header.length)), Array.from(header));
  assert.deepEqual(
    Array.from(result.message.slice(header.length)),
    Array.from(message50),
    "single-part payload must equal the vector message",
  );
});

test("the 1000-fragment boundary completes to independent published bytes", { timeout: 5000 }, () => {
  const expected = message1024.slice(0, 1000);
  // Python stdlib zlib.crc32 over those published bytes, independent of this decoder.
  const checksum = 0x3f6eba7f;
  const collector = createUrCollector({ types: ["bytes"] });
  let result;
  for (let index = 0; index < expected.length; index++) {
    result = collector.receive(toUr({ seqNum: index + 1, seqLen: 1000,
      messageLen: 1000, checksum, data: expected.slice(index, index + 1) }));
  }
  assert.equal(result.status, "complete");
  assert.deepEqual(result.message, expected);
});

test("duplicate floods cannot advance or grow retained collector state", () => {
  const tracked = [];
  const collector = createUrCollector({ types: ["bytes"], track: tracked });
  const part = vectors.urEncoder.parts[0];
  assert.equal(collector.receive(part).status, "progress");
  const before = collector.state();
  for (let index = 0; index < 10000; index++) assert.equal(collector.receive(part).status, "duplicate");
  assert.deepEqual(collector.state(), before);
  collector.reset();
  assert.ok(tracked.every((buffer) => buffer.every((byte) => byte === 0)));
});

test("non-progressing over-budget streams cap retained buffers", () => {
  const tracked = [];
  const collector = createUrCollector({ types: ["bytes"], workBudget: 1, track: tracked });
  for (let sequence = 100; sequence < 1100; sequence++) {
    const part = makePart(message256, 30, sequence);
    // Withhold all degree-one equations: the tiny cascade budget cannot
    // bootstrap any known fragments from this intentionally non-progress stream.
    if (chooseFragments(part.seqNum, part.seqLen, part.checksum).length === 1) continue;
    const result = collector.receive(toUr(part));
    assert.equal(result.status, "progress");
  }
  const fragmentLength = 29, count = 9;
  const retained = tracked.filter((buffer) => buffer.some((byte) => byte !== 0));
  assert.ok(retained.reduce((sum, buffer) => sum + buffer.length, 0) <= fragmentLength * (7 * count + 80));
  collector.reset();
  assert.ok(tracked.every((buffer) => buffer.every((byte) => byte === 0)));
});
