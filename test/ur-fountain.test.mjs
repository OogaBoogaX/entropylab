import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  hodlCrc32,
  hodlBytewordsEncode,
  hodlCborBstr,
  hodlUrPartCbor,
} from "../src/js/psbt-ur.js";
import {
  xoshiro256,
  seedFromString,
  seedFromUint32,
  randomSampler,
  shuffled,
  chooseDegree,
  chooseFragments,
  findNominalFragmentLength,
  partitionMessage,
  createUrCollector,
  retireUrCollectors,
} from "../src/js/ur-fountain.js";

const vectors = JSON.parse(readFileSync(new URL("./fixtures/bc-ur/reference-vectors.json", import.meta.url)));

const hex = (s) => Uint8Array.from(s.match(/../g).map((b) => parseInt(b, 16)));
const hexEncode = (b) => Buffer.from(b).toString("hex");
const concat = (...parts) => Uint8Array.from(parts.flatMap((part) => [...part]));
const xorInto = (target, source) => {
  for (let i = 0; i < target.length; i++) target[i] ^= source[i];
};
const crc32Number = (bytes) => {
  const crc = hodlCrc32(bytes);
  return ((crc[0] << 24) | (crc[1] << 16) | (crc[2] << 8) | crc[3]) >>> 0;
};
const allZero = (bytes) => bytes.every((byte) => byte === 0);

// The expected 1024-byte message is the partition vector's fragments joined
// and cut to 1024 bytes, so it is independent of this module's generator.
const message1024 = concat(...vectors.partition.fragments.map(hex)).slice(0, 1024);
const makeMessage = (n) => message1024.slice(0, n);
const message256 = makeMessage(256);
const message256Ur = hodlCborBstr(message256);

const encodePartObjects = (message, maxFragmentLen, firstSeqNum, count) => {
  const fragmentLen = findNominalFragmentLength(message.length, 10, maxFragmentLen);
  const fragments = partitionMessage(message, fragmentLen);
  const checksum = crc32Number(message);
  const seqLen = fragments.length;
  const parts = [];
  for (let i = 0; i < count; i++) {
    const seqNum = firstSeqNum + i;
    const indexes = chooseFragments(seqNum, seqLen, checksum);
    const data = new Uint8Array(fragmentLen);
    for (const index of indexes) xorInto(data, fragments[index]);
    parts.push({ seqNum, seqLen, messageLen: message.length, checksum, data });
  }
  return parts;
};

const toUr = (part, type = "bytes") =>
  "ur:" + type + "/" + part.seqNum + "-" + part.seqLen + "/" +
  hodlBytewordsEncode(hodlUrPartCbor(part.seqNum, part.seqLen, part.messageLen, part.checksum, part.data), "minimal");

// GF(2) solvability of the fragment equations, used only to pick a withheld
// pair for the fountain-recovery test. It uses chooseFragments (pinned by the
// reference vectors) and the message checksum, not the collector.
const solvable = (withheld, seqLen, checksum, seqNums) => {
  const rows = [];
  for (let i = 0; i < seqLen; i++) {
    if (!withheld.includes(i)) rows.push(1 << i);
  }
  for (const seqNum of seqNums) {
    let mask = 0;
    for (const index of chooseFragments(seqNum, seqLen, checksum)) mask |= 1 << index;
    rows.push(mask);
  }
  const pivots = new Map();
  for (let mask of rows) {
    while (mask) {
      const high = 31 - Math.clz32(mask);
      if (pivots.has(high)) mask ^= pivots.get(high);
      else { pivots.set(high, mask); break; }
    }
  }
  return pivots.size === seqLen;
};

test("crc32 matches the reference vectors", () => {
  for (const entry of vectors.crc32) {
    assert.equal(hexEncode(hodlCrc32(new TextEncoder().encode(entry.input))), entry.crc32);
  }
});

test("xoshiro256 next() matches the reference vectors", () => {
  const rng = xoshiro256(seedFromString(vectors.rngNextMod100.seed));
  const values = vectors.rngNextMod100.values.map(() => Number(rng.next() % 100n));
  assert.deepEqual(values, vectors.rngNextMod100.values);
});

test("xoshiro256 seeded from a uint32 matches the reference vectors", () => {
  const checksum = crc32Number(new TextEncoder().encode(vectors.rngChecksumSeedNextMod100.seedIsCrc32Of));
  const rng = xoshiro256(seedFromUint32(checksum));
  const values = vectors.rngChecksumSeedNextMod100.values.map(() => Number(rng.next() % 100n));
  assert.deepEqual(values, vectors.rngChecksumSeedNextMod100.values);
});

test("xoshiro256 nextInt matches the reference vectors", () => {
  const rng = xoshiro256(seedFromString(vectors.rngNextInt1to10.seed));
  const values = vectors.rngNextInt1to10.values.map(() => rng.nextInt(1, 10));
  assert.deepEqual(values, vectors.rngNextInt1to10.values);
});

test("findNominalFragmentLength matches the reference vectors", () => {
  for (const entry of vectors.findNominalFragmentLength) {
    assert.equal(findNominalFragmentLength(entry.messageLen, entry.minFragmentLen, entry.maxFragmentLen), entry.expected);
  }
});

test("randomSampler matches the reference vectors", () => {
  const rng = xoshiro256(seedFromString(vectors.randomSampler.seed));
  const sampler = randomSampler(vectors.randomSampler.probs);
  const samples = vectors.randomSampler.samples.map(() => sampler.next(() => rng.nextDouble()));
  assert.deepEqual(samples, vectors.randomSampler.samples);
});

test("shuffled matches the reference vectors", () => {
  const rng = xoshiro256(seedFromString(vectors.shuffle.seed));
  for (const expected of vectors.shuffle.rounds) {
    assert.deepEqual(shuffled(vectors.shuffle.values, rng), expected);
  }
});

test("partitionMessage matches the reference vectors", () => {
  const fragmentLen = findNominalFragmentLength(
    vectors.partition.messageLen,
    vectors.partition.minFragmentLen,
    vectors.partition.maxFragmentLen,
  );
  const fragments = partitionMessage(message1024, fragmentLen);
  assert.deepEqual(fragments.map(hexEncode), vectors.partition.fragments);
});

test("chooseDegree matches the reference vectors", () => {
  const degrees = vectors.chooseDegree.degrees.map((_, i) => {
    const rng = xoshiro256(seedFromString(vectors.chooseDegree.seedPrefix + (vectors.chooseDegree.firstNonce + i)));
    return chooseDegree(vectors.chooseDegree.seqLen, rng);
  });
  assert.deepEqual(degrees, vectors.chooseDegree.degrees);
});

test("chooseFragments matches the reference vectors", () => {
  const checksum = crc32Number(message1024);
  const indexes = vectors.chooseFragments.sortedIndexes.map((_, i) =>
    chooseFragments(vectors.chooseFragments.firstSeqNum + i, vectors.chooseFragments.seqLen, checksum),
  );
  assert.deepEqual(indexes, vectors.chooseFragments.sortedIndexes);
});

test("nextData matches the reference xor vector", () => {
  const rng = xoshiro256(seedFromString(vectors.xor.seed));
  const data1 = rng.nextData(10);
  const data2 = rng.nextData(10);
  assert.equal(hexEncode(data1), vectors.xor.data1);
  assert.equal(hexEncode(data2), vectors.xor.data2);
  const xored = data1.slice();
  xorInto(xored, data2);
  assert.equal(hexEncode(xored), vectors.xor.xor);
});

test("nextData(1024) matches the partition vector", () => {
  const rng = xoshiro256(seedFromString("Wolf"));
  assert.equal(hexEncode(rng.nextData(1024)), hexEncode(message1024));
});

test("the test encoder reproduces the reference fountain parts", () => {
  const parts = encodePartObjects(message256, 30, 1, 20);
  assert.equal(parts.length, vectors.fountainEncoder.parts.length);
  for (let i = 0; i < parts.length; i++) {
    const expected = vectors.fountainEncoder.parts[i];
    assert.equal(parts[i].seqNum, expected.seqNum);
    assert.equal(parts[i].seqLen, expected.seqLen);
    assert.equal(parts[i].messageLen, expected.messageLen);
    assert.equal(parts[i].checksum, expected.checksum);
    assert.equal(hexEncode(parts[i].data), expected.data);
  }
});

test("the test encoder reproduces the reference CBOR parts", () => {
  const parts = encodePartObjects(message256, 30, 1, 20);
  const cbor = parts.map((part) => hexEncode(hodlUrPartCbor(part.seqNum, part.seqLen, part.messageLen, part.checksum, part.data)));
  assert.deepEqual(cbor, vectors.fountainEncoderCbor.parts);
});

test("the test encoder reproduces the reference UR parts", () => {
  const parts = encodePartObjects(message256Ur, 30, 1, 20);
  const ur = parts.map((part) => toUr(part, "bytes"));
  assert.deepEqual(ur, vectors.urEncoder.parts);
});

test("sequential parts in reversed order complete", () => {
  const collector = createUrCollector({ types: ["bytes"] });
  const parts = vectors.urEncoder.parts.slice(0, 9).reverse();
  let result;
  for (const part of parts) result = collector.receive(part);
  assert.equal(result.status, "complete");
  assert.equal(hexEncode(result.message), hexEncode(message256Ur));
});

test("fountain recovery completes with two early parts withheld", () => {
  const checksum = crc32Number(message256Ur);
  const seqLen = 9;
  const fountainSeqNums = Array.from({ length: 10 }, (_, i) => 10 + i);
  // The reference suggests withholding parts 3 and 5; if that pair is not
  // solvable from parts 10..19, pick the smallest pair that is.
  let withheld = [2, 4];
  if (!solvable(withheld, seqLen, checksum, fountainSeqNums)) {
    let found = null;
    for (let i = 0; i < seqLen && !found; i++) {
      for (let j = i + 1; j < seqLen && !found; j++) {
        if (solvable([i, j], seqLen, checksum, fountainSeqNums)) found = [i, j];
      }
    }
    withheld = found;
  }
  assert.ok(withheld, "a working withheld pair exists");
  const collector = createUrCollector({ types: ["bytes"] });
  const parts = vectors.urEncoder.parts;
  let result;
  for (let i = 0; i < 9; i++) {
    if (withheld.includes(i)) continue;
    result = collector.receive(parts[i]);
  }
  let completedAt = -1;
  for (let i = 9; i < 20; i++) {
    result = collector.receive(parts[i]);
    if (result.status === "complete") { completedAt = i; break; }
  }
  assert.equal(result.status, "complete");
  assert.ok(completedAt < 19, "completes before part 20");
  assert.equal(hexEncode(result.message), hexEncode(message256Ur));
});

test("fountain-only parts never conflict", () => {
  const collector = createUrCollector({ types: ["bytes"] });
  let result;
  for (let i = 9; i < 20; i++) {
    result = collector.receive(vectors.urEncoder.parts[i]);
    assert.notEqual(result.status, "invalid");
    assert.notEqual(result.status, "conflict");
  }
  assert.ok(result.status === "complete" || result.status === "progress");
  if (result.status === "complete") {
    assert.equal(hexEncode(result.message), hexEncode(message256Ur));
  }
});

test("a single-part UR completes at once", () => {
  const collector = createUrCollector({ types: ["bytes"] });
  const result = collector.receive(vectors.singlePartUr.ur);
  assert.equal(result.status, "complete");
  assert.equal(hexEncode(result.message), hexEncode(hodlCborBstr(makeMessage(50))));
});

test("the reference multipart message completes within 3 * seqLen parts", () => {
  const message = hodlCborBstr(xoshiro256(seedFromString("Wolf")).nextData(32767));
  const parts = encodePartObjects(message, 1000, 101, 200);
  const seqLen = parts[0].seqLen;
  const collector = createUrCollector({ types: ["bytes"] });
  let result;
  let count = 0;
  for (const part of parts) {
    result = collector.receive(toUr(part, "bytes"));
    count += 1;
    if (result.status === "complete") break;
    assert.ok(count <= 3 * seqLen, "completes within 3 * seqLen parts");
  }
  assert.equal(result.status, "complete");
  assert.equal(hexEncode(result.message), hexEncode(message));
});

test("a different message gives mismatch and leaves progress untouched", () => {
  const collector = createUrCollector({ types: ["bytes"] });
  const parts = vectors.urEncoder.parts;
  let result = collector.receive(parts[0]);
  assert.equal(result.status, "progress");
  const known = result.known;
  const otherMessage = hodlCborBstr(xoshiro256(seedFromString("Fox")).nextData(256));
  const otherParts = encodePartObjects(otherMessage, 30, 1, 1);
  result = collector.receive(toUr(otherParts[0], "bytes"));
  assert.equal(result.status, "mismatch");
  assert.equal(collector.state().known, known);
});

test("a conflicting part kills the collection until reset", () => {
  const collector = createUrCollector({ types: ["bytes"] });
  const parts = vectors.urEncoder.parts;
  collector.receive(parts[0]);
  collector.receive(parts[1]);
  collector.receive(parts[2]);
  const original = encodePartObjects(message256Ur, 30, 1, 3)[2];
  const flipped = { ...original, data: original.data.slice() };
  flipped.data[0] ^= 0xff;
  assert.equal(collector.receive(toUr(flipped, "bytes")).status, "conflict");
  assert.equal(collector.receive(parts[3]).status, "conflict");
  collector.reset();
  assert.equal(collector.receive(parts[0]).status, "progress");
});

test("an identical repeat is a duplicate", () => {
  const collector = createUrCollector({ types: ["bytes"] });
  const parts = vectors.urEncoder.parts;
  collector.receive(parts[0]);
  assert.equal(collector.receive(parts[0]).status, "duplicate");
});

test("inconsistent seqLen is bad-part", () => {
  const collector = createUrCollector({ types: ["bytes"] });
  const part = encodePartObjects(message256Ur, 30, 1, 1)[0];
  const bad = { ...part, seqLen: part.seqLen + 1 };
  assert.equal(collector.receive(toUr(bad, "bytes")).status, "bad-part");
});

test("messageLen and seqLen over the maxima are too-large", () => {
  // Each limit on its own: the 259-byte message in 9 parts passes the other.
  const part = toUr(encodePartObjects(message256Ur, 30, 1, 1)[0], "bytes");
  const lenTracked = [];
  const byLength = createUrCollector({ types: ["bytes"], maxMessageLen: 258, track: lenTracked });
  assert.equal(byLength.receive(part).status, "too-large");
  const seqTracked = [];
  const bySeqLen = createUrCollector({ types: ["bytes"], maxSeqLen: 8, track: seqTracked });
  assert.equal(bySeqLen.receive(part).status, "too-large");
  assert.deepEqual([lenTracked.length, seqTracked.length], [0, 0], "nothing is allocated");
  assert.equal(createUrCollector({ types: ["bytes"], maxMessageLen: 259, maxSeqLen: 9 }).receive(part).status, "progress");
});

test("a fountain part that contradicts known fragments is a conflict", () => {
  // Strict addition (c): once every index a fountain part covers is known, it
  // must reduce to zero bytes. Pick one whose indexes are all in parts 1..8.
  const checksum = crc32Number(message256Ur);
  const all = encodePartObjects(message256Ur, 30, 1, 20);
  const covered = all.find((part) => part.seqNum > 9 && chooseFragments(part.seqNum, 9, checksum).every((index) => index < 8));
  assert.ok(covered, "a fountain part inside indexes 0..7 exists");
  const tracked = [];
  const collector = createUrCollector({ types: ["bytes"], track: tracked });
  for (const part of vectors.urEncoder.parts.slice(0, 8)) assert.equal(collector.receive(part).status, "progress");
  assert.equal(collector.receive(toUr(covered, "bytes")).status, "progress", "the honest part is consistent");
  const flipped = { ...covered, data: covered.data.slice() };
  flipped.data[0] ^= 1;
  // A fresh collector, so the seqNum-level duplicate check cannot catch it.
  const strict = createUrCollector({ types: ["bytes"], track: tracked });
  for (const part of vectors.urEncoder.parts.slice(0, 8)) strict.receive(part);
  assert.equal(strict.receive(toUr(flipped, "bytes")).status, "conflict");
  assert.equal(strict.receive(vectors.urEncoder.parts[8]).status, "conflict");
  collector.reset();
  for (const buffer of tracked) assert.ok(allZero(buffer));
});

test("a wrong checksum is invalid", () => {
  const collector = createUrCollector({ types: ["bytes"] });
  const parts = encodePartObjects(message256Ur, 30, 1, 9);
  const wrongChecksum = (parts[0].checksum ^ 1) >>> 0;
  let result;
  for (const part of parts) result = collector.receive(toUr({ ...part, checksum: wrongChecksum }, "bytes"));
  assert.equal(result.status, "invalid");
});

test("non-zero padding is invalid", () => {
  const collector = createUrCollector({ types: ["bytes"] });
  const fragmentLen = findNominalFragmentLength(message256Ur.length, 10, 30);
  const fragments = partitionMessage(message256Ur, fragmentLen);
  const last = fragments[fragments.length - 1];
  const padIndex = message256Ur.length - (fragments.length - 1) * fragmentLen;
  last[padIndex] = 0xff;
  const checksum = crc32Number(message256Ur);
  const seqLen = fragments.length;
  let result;
  for (let i = 0; i < seqLen; i++) {
    result = collector.receive(toUr({ seqNum: i + 1, seqLen, messageLen: message256Ur.length, checksum, data: fragments[i] }, "bytes"));
  }
  assert.equal(result.status, "invalid");
});

test("a sequential part without metadata is legacy", () => {
  const collector = createUrCollector({ types: ["bytes"] });
  const payload = new Uint8Array([1, 2, 3, 4]);
  const ur = "ur:bytes/1-2/" + hodlBytewordsEncode(payload, "minimal");
  assert.equal(collector.receive(ur).status, "legacy");
});

test("a type not in types is wrong-type", () => {
  const collector = createUrCollector({ types: ["crypto-psbt"] });
  assert.equal(collector.receive(vectors.urEncoder.parts[0]).status, "wrong-type");
});

test("uppercase UR text decodes", () => {
  const collector = createUrCollector({ types: ["bytes"] });
  assert.equal(collector.receive(vectors.singlePartUr.ur.toUpperCase()).status, "complete");
});

test("garbage text is bad-part", () => {
  const collector = createUrCollector({ types: ["bytes"] });
  assert.equal(collector.receive("not a ur").status, "bad-part");
});

test("a single-part UR while bound is mismatch", () => {
  const collector = createUrCollector({ types: ["bytes"] });
  collector.receive(vectors.urEncoder.parts[0]);
  assert.equal(collector.receive(vectors.singlePartUr.ur).status, "mismatch");
});

test("every tracked buffer is zeroed on completion", () => {
  const tracked = [];
  const collector = createUrCollector({ types: ["bytes"], track: tracked });
  let result;
  for (const part of vectors.urEncoder.parts.slice(0, 9)) result = collector.receive(part);
  assert.equal(result.status, "complete");
  assert.ok(tracked.length > 0);
  for (const buffer of tracked) assert.ok(allZero(buffer));
  assert.ok(!tracked.includes(result.message));
});

test("every tracked buffer is zeroed on reset", () => {
  const tracked = [];
  const collector = createUrCollector({ types: ["bytes"], track: tracked });
  collector.receive(vectors.urEncoder.parts[0]);
  collector.reset();
  for (const buffer of tracked) assert.ok(allZero(buffer));
});

test("every tracked buffer is zeroed on conflict", () => {
  const tracked = [];
  const collector = createUrCollector({ types: ["bytes"], track: tracked });
  collector.receive(vectors.urEncoder.parts[0]);
  collector.receive(vectors.urEncoder.parts[1]);
  collector.receive(vectors.urEncoder.parts[2]);
  const original = encodePartObjects(message256Ur, 30, 1, 3)[2];
  const flipped = { ...original, data: original.data.slice() };
  flipped.data[0] ^= 0xff;
  assert.equal(collector.receive(toUr(flipped, "bytes")).status, "conflict");
  for (const buffer of tracked) assert.ok(allZero(buffer));
});

test("every tracked buffer is zeroed on invalid", () => {
  const tracked = [];
  const collector = createUrCollector({ types: ["bytes"], track: tracked });
  const parts = encodePartObjects(message256Ur, 30, 1, 9);
  const wrongChecksum = (parts[0].checksum ^ 1) >>> 0;
  let result;
  for (const part of parts) result = collector.receive(toUr({ ...part, checksum: wrongChecksum }, "bytes"));
  assert.equal(result.status, "invalid");
  for (const buffer of tracked) assert.ok(allZero(buffer));
});

test("retireUrCollectors zeroes a live collector and it starts fresh", () => {
  const tracked = [];
  const collector = createUrCollector({ types: ["bytes"], track: tracked });
  collector.receive(vectors.urEncoder.parts[0]);
  retireUrCollectors();
  for (const buffer of tracked) assert.ok(allZero(buffer));
  assert.equal(collector.state().status, "idle");
  assert.equal(collector.receive(vectors.urEncoder.parts[1]).status, "progress");
});

// Review on 3e12704a (GLM 5.3, Kimi K3, MiniMax, DeepSeek V4.1 red team).
test("a single-part UR over maxMessageLen is too-large", () => {
  const collector = createUrCollector({ types: ["bytes"], maxMessageLen: 10 });
  assert.equal(collector.receive(vectors.singlePartUr.ur).status, "too-large");
  assert.equal(collector.state().status, "idle");
});

test("the default part cap is 1000", () => {
  const part = (seqLen) => toUr({ seqNum: 1, seqLen, messageLen: seqLen, checksum: 0, data: new Uint8Array(1) }, "bytes");
  assert.equal(createUrCollector({ types: ["bytes"] }).receive(part(1001)).status, "too-large");
  assert.equal(createUrCollector({ types: ["bytes"] }).receive(part(1000)).status, "progress");
});

// Review on 4017841c (GLM 5.3, Kimi K3).
test("a part over the work budget drops its cascade but never reports a false conflict or invalid", () => {
  // A budget of 1 stops every cascade after its first equation.
  const tracked = [];
  const collector = createUrCollector({ types: ["bytes"], workBudget: 1, track: tracked });
  // Fountain parts first, then the sequential ones (single equations, so
  // they finish the message even when every cascade is cut short).
  let completed = null;
  for (const part of [...vectors.urEncoder.parts.slice(9), ...vectors.urEncoder.parts.slice(0, 9)]) {
    const result = collector.receive(part);
    assert.ok(!["conflict", "invalid"].includes(result.status), result.status);
    if (result.status === "complete") completed = result;
  }
  assert.ok(completed, "the message completes");
  assert.equal(hexEncode(completed.message), hexEncode(message256Ur));
  for (const buffer of tracked) assert.ok(allZero(buffer));
});

test("the sampler stays in range when a draw rounds to exactly 1.0", () => {
  const sampler = randomSampler([1, 1, 1]);
  assert.ok([0, 1, 2].includes(sampler.next(() => 1)));
});
