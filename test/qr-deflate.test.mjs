// Security contract: accept complete RFC1951 streams with distances <=1024;
// refuse malformed/truncated/trailing data and output beyond the caller's cap.
// Node's independent zlib is the positive oracle; hand-packed negatives follow
// RFC1951 sections 3.1.1 and 3.2.4–3.2.7, not the implementation under test.
import test from "node:test";
import assert from "node:assert/strict";
import { constants, deflateRawSync, inflateRawSync } from "node:zlib";
import { inflateRawBounded } from "../src/js/qr-deflate.js";

const reject = (bytes, code = "bad-part", maxBytes = 1048576) => {
  const original = Uint8Array.from(bytes);
  assert.throws(() => inflateRawBounded(bytes, maxBytes), (error) => error.code === code);
  assert.deepEqual(Uint8Array.from(bytes), original, "caller input is never wiped or changed");
};
const matchesOracle = (bytes, expected, maxBytes = expected.length) => {
  assert.deepEqual(inflateRawSync(bytes), Buffer.from(expected));
  const original = Uint8Array.from(bytes);
  const actual = inflateRawBounded(bytes, maxBytes);
  assert.ok(actual instanceof Uint8Array);
  assert.deepEqual(Buffer.from(actual), Buffer.from(expected));
  assert.deepEqual(Uint8Array.from(bytes), original);
  return actual;
};

// A bit-packer and fixed-code *encoder* for explicit RFC boundary cases.
// No test derives expected data from the decoder being added.
function bits() {
  const bytes = [];
  let offset = 0;
  return {
    put(value, count) {
      for (let i = 0; i < count; i += 1, offset += 1) {
        const index = offset >>> 3;
        bytes[index] = (bytes[index] || 0) | (((value >>> i) & 1) << (offset & 7));
      }
    },
    code(value, count) {
      for (let i = count - 1; i >= 0; i -= 1) this.put((value >>> i) & 1, 1);
    },
    finish() { return Uint8Array.from(bytes); },
  };
}
function fixedSymbol(out, symbol) {
  if (symbol <= 143) out.code(0x30 + symbol, 8);
  else if (symbol <= 255) out.code(0x190 + symbol - 144, 9);
  else if (symbol <= 279) out.code(symbol - 256, 7);
  else out.code(0xc0 + symbol - 280, 8);
}
function fixedStream(write) {
  const out = bits();
  out.put(1, 1);
  out.put(1, 2);
  write(out);
  fixedSymbol(out, 256);
  return out.finish();
}
const ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
function dynamicHeader(codeLengths, { hlit = 0, hdist = 0, hclen = 15 } = {}) {
  const out = bits();
  out.put(1, 1);
  out.put(2, 2);
  out.put(hlit, 5);
  out.put(hdist, 5);
  out.put(hclen, 4);
  for (const symbol of ORDER.slice(0, hclen + 4)) out.put(codeLengths[symbol] || 0, 3);
  return out;
}

for (const [name, options, expected, blockType] of [
  ["stored", { level: 0 }, Buffer.from("PSBT stored block\0\xff", "latin1"), 0],
  ["fixed", { strategy: constants.Z_FIXED }, Buffer.from("PSBT fixed block ".repeat(20)), 1],
  ["dynamic", { level: 9 }, Buffer.from("BBQr PSBT transaction input output witness amount script ".repeat(3000)), 2],
  ["empty", {}, Buffer.alloc(0), 1],
]) {
  test(`zlib windowBits10 ${name} stream decodes exactly`, () => {
    const compressed = deflateRawSync(expected, { windowBits: 10, ...options });
    assert.equal((compressed[0] >>> 1) & 3, blockType, "fixture exercises the named block type");
    const actual = matchesOracle(compressed, expected);
    actual.fill(0);
    assert.deepEqual(inflateRawSync(compressed), expected, "returned output does not alias input");
    if (expected.length) reject(compressed, "too-large", expected.length - 1);
  });
}

test("stored multi-block input and nonzero input view offsets", () => {
  const expected = Buffer.from(Array.from({ length: 140000 }, (_, i) => i & 255));
  const compressed = deflateRawSync(expected, { level: 0, windowBits: 10 });
  const wrapped = Buffer.concat([Buffer.from([99, 98]), compressed, Buffer.from([97])]);
  matchesOracle(wrapped.subarray(2, -1), expected);
  reject(compressed.subarray(0, -1));
  reject(compressed, "too-large", expected.length - 1);
});

test("every proper prefix of representative streams is truncated", () => {
  for (const options of [{ level: 0 }, { strategy: constants.Z_FIXED }, { level: 9 }]) {
    const compressed = deflateRawSync(Buffer.from("bounded raw stream ".repeat(5)), { windowBits: 10, ...options });
    for (let size = 0; size < compressed.length; size += 1) reject(compressed.subarray(0, size));
  }
  const dynamic = deflateRawSync(Buffer.from("BBQr PSBT transaction input output witness amount script ".repeat(3000)), { windowBits: 10 });
  assert.equal((dynamic[0] >>> 1) & 3, 2);
  for (let size = 0; size < dynamic.length; size += 1) reject(dynamic.subarray(0, size));
});

test("output cap handles literal, stored, overlapping match and empty boundaries", () => {
  for (const options of [{ level: 0 }, { strategy: constants.Z_FIXED }, { level: 9 }]) {
    const expected = Buffer.alloc(65536, 65);
    const compressed = deflateRawSync(expected, { windowBits: 10, ...options });
    matchesOracle(compressed, expected);
    reject(compressed, "too-large", 65535);
    reject(compressed, "too-large", 0);
  }
  matchesOracle(Uint8Array.of(3, 0), Buffer.alloc(0), 0);
});

test("final unused bits are ignored but trailing bytes and concatenated streams are refused", () => {
  matchesOracle(Uint8Array.of(3, 252), Buffer.alloc(0), 0);
  reject(Uint8Array.of(3, 0, 0));
  reject(Uint8Array.of(3, 0, 3, 0));
  const stored = deflateRawSync(Buffer.from("x"), { level: 0 });
  reject(Buffer.concat([stored, Buffer.from([0])]));
});

test("reserved blocks, malformed stored lengths and unterminated blocks are refused", () => {
  for (const bytes of [[7], [1, 1, 0, 0, 0, 65], [1, 1, 0, 254, 255], [0, 0, 0, 255, 255]]) {
    reject(Uint8Array.from(bytes));
  }
});

test("fixed blocks reject reserved symbols and references before output start", () => {
  for (const symbol of [286, 287]) reject(fixedStream((out) => fixedSymbol(out, symbol)));
  for (const distance of [30, 31]) {
    reject(fixedStream((out) => {
      fixedSymbol(out, 65);
      fixedSymbol(out, 257);
      out.code(distance, 5);
    }));
  }
  reject(fixedStream((out) => { fixedSymbol(out, 257); out.code(0, 5); }));
});

test("BBQr allows distance 1024 but rejects otherwise valid distance 1025", () => {
  const make = (distance) => fixedStream((out) => {
    for (let i = 0; i < distance; i += 1) fixedSymbol(out, i & 255);
    fixedSymbol(out, 257); // length 3
    out.code(distance === 1024 ? 19 : 20, 5);
    out.put(distance === 1024 ? 255 : 0, distance === 1024 ? 8 : 9);
  });
  const expected = Buffer.from(Array.from({ length: 1027 }, (_, i) => i < 1024 ? i & 255 : i - 1024));
  matchesOracle(make(1024), expected);
  const wider = make(1025);
  assert.equal(inflateRawSync(wider).length, 1028, "valid general DEFLATE is not necessarily BBQr window10");
  reject(wider);
});

test("overlapping matches and cross-block history are preserved", () => {
  const out = bits();
  out.put(0, 1); out.put(1, 2);
  fixedSymbol(out, 65); fixedSymbol(out, 256);
  out.put(1, 1); out.put(1, 2);
  fixedSymbol(out, 285); // length 258
  out.code(0, 5); // distance 1
  fixedSymbol(out, 256);
  matchesOracle(out.finish(), Buffer.alloc(259, 65));
  reject(out.finish(), "too-large", 258);
});

test("dynamic code-length trees must be complete and not oversubscribed", () => {
  reject(dynamicHeader({}).finish());
  reject(dynamicHeader({ 0: 1, 16: 1, 17: 1 }).finish());
  reject(dynamicHeader({ 0: 2, 16: 2 }).finish());
  reject(dynamicHeader({ 0: 1, 1: 1 }, { hlit: 30 }).finish());
});

test("dynamic repeats cannot precede a length or overrun the combined tree", () => {
  const previous = dynamicHeader({ 0: 1, 16: 1 });
  previous.code(1, 1); previous.put(0, 2);
  reject(previous.finish());
  const overrun = dynamicHeader({ 0: 1, 18: 1 });
  overrun.code(1, 1); overrun.put(127, 7); // 138 zeros
  overrun.code(1, 1); overrun.put(127, 7); // exceeds 258 lengths
  reject(overrun.finish());
});

// Literal/length and distance lengths encoded directly using complete 0/1 CL
// alphabet. This includes the RFC's legal absent-distance/single-symbol cases.
function smallDynamic(lengths, distanceLength, write) {
  const out = dynamicHeader({ 0: 1, 1: 1 });
  for (let i = 0; i < 257; i += 1) out.code(lengths[i] || 0, 1);
  out.code(distanceLength, 1);
  write(out);
  return out.finish();
}
test("dynamic literal-only blocks allow absent distance and one-bit singleton trees", () => {
  matchesOracle(smallDynamic({ 256: 1 }, 0, (out) => out.code(0, 1)), Buffer.alloc(0));
  matchesOracle(smallDynamic({ 65: 1, 256: 1 }, 0, (out) => {
    out.code(0, 1); out.code(1, 1);
  }), Buffer.from("A"));
  matchesOracle(smallDynamic({ 256: 1 }, 1, (out) => out.code(0, 1)), Buffer.alloc(0));
});
test("dynamic blocks reject absent EOB, oversubscribed literal trees and unused singleton code", () => {
  reject(smallDynamic({ 65: 1 }, 0, (out) => out.code(0, 1)));
  reject(smallDynamic({ 65: 1, 66: 1, 256: 1 }, 0, (out) => out.code(0, 1)));
  reject(smallDynamic({ 256: 1 }, 0, (out) => out.code(1, 1)));
});
