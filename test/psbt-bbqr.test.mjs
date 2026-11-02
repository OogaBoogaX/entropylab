// Security contract: return byte-exact PSBTs only after complete bounded BBQr
// H/2/Z reassembly; reject malformed framing/encodings, conflicts, wrong types,
// invalid raw DEFLATE, and compressed or inflated data above the receive budget.
// Oracles: pinned Coinkite Python output, public PSBT fixtures and RFC 4648.
// Tests never fetch, run Python, or encode with the application under test.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { createPsbtQrReader } from "../src/js/psbt-qr-payload.js";

const root = new URL("./fixtures/psbt-qr/bbqr/", import.meta.url);
const manifest = JSON.parse(readFileSync(new URL("manifest.json", root), "utf8"));
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const partsFor = (entry) => readFileSync(new URL(entry.file, root), "ascii").trim().split("\n");
const sourceFor = (entry) => Buffer.from(readFileSync(new URL(`../${entry.source.path}`, import.meta.url), "ascii"), "base64");
const fixture = (encoding, mode = "multipart") => manifest.fixtures.find((entry) => entry.encoding === encoding && entry.mode === mode && entry.file.startsWith("p2wpkh-"));
const replaceHeader = (part, start, value) => part.slice(0, start) + value + part.slice(start + value.length);
const withoutBytes = (result, status) => {
  assert.equal(result.status, status);
  assert.equal(result.bytes, undefined, "only completion may expose bytes");
};
const exactCompletion = (result, expected) => {
  assert.equal(result.status, "complete");
  assert.ok(result.bytes instanceof Uint8Array);
  assert.deepEqual(Buffer.from(result.bytes), expected);
  result.bytes.fill(0);
};

for (const entry of manifest.fixtures) {
  test(`independent BBQr ${entry.file} recovers exact public PSBT bytes`, () => {
    const parts = partsFor(entry);
    const expected = sourceFor(entry);
    const reader = createPsbtQrReader();
    try {
      assert.equal(reader.progress(), null);
      assert.equal(parts.length, entry.parts);
      for (let i = 0; i < parts.length - 1; i++) {
        withoutBytes(reader.receive(parts[i]), "partial");
        assert.deepEqual(reader.progress(), { received: i + 1, total: parts.length });
      }
      exactCompletion(reader.receive(parts.at(-1)), expected);
      assert.equal(reader.progress(), null);
      withoutBytes(reader.receive(parts[0]), "done");
    } finally {
      reader.reset();
    }
  });
}

test("BBQr fixture provenance pins independent source and output digests", () => {
  assert.equal(manifest.reference.revision, "8dc7ef07d0d520763cc0001a885ca8d29ac8719a");
  for (const source of manifest.reference.sources) {
    assert.equal(sha256(readFileSync(new URL(source.file, root))), source.sha256);
  }
  assert.equal(sha256(readFileSync(new URL(`../${manifest.generator.file}`, import.meta.url))), manifest.generator.sha256);
  for (const entry of manifest.fixtures) {
    const encoded = readFileSync(new URL(entry.file, root));
    const sourceFile = readFileSync(new URL(`../${entry.source.path}`, import.meta.url));
    const source = sourceFor(entry);
    assert.equal(encoded.length, entry.bytes);
    assert.equal(sha256(encoded), entry.sha256);
    assert.equal(sha256(sourceFile), entry.source.fileSha256);
    assert.equal(source.length, entry.source.bytes);
    assert.equal(sha256(source), entry.source.sha256);
  }
  assert.equal(sha256(readFileSync(new URL(manifest.rejections.file, root))), manifest.rejections.sha256);
});

for (const encoding of ["H", "2", "Z"]) {
  for (const order of ["reverse", "final-first"]) {
    test(`BBQr ${encoding} ${order}, duplicate frames, and no early completion`, () => {
      const entry = fixture(encoding);
      const parts = partsFor(entry);
      const sequence = order === "reverse" ? [...parts].reverse() : [parts.at(-1), ...parts.slice(0, -1)];
      const reader = createPsbtQrReader();
      try {
        for (let i = 0; i < sequence.length - 1; i++) {
          withoutBytes(reader.receive(sequence[i]), "partial");
          withoutBytes(reader.receive(sequence[i]), "partial");
          assert.deepEqual(reader.progress(), { received: i + 1, total: parts.length });
        }
        exactCompletion(reader.receive(sequence.at(-1)), sourceFor(entry));
      } finally {
        reader.reset();
      }
    });
  }
}

test("BBQr refuses every non-PSBT type without binding a fresh reader", () => {
  const part = partsFor(fixture("H"))[0];
  const reader = createPsbtQrReader();
  try {
    for (const type of ["T", "J", "C", "U", "B", "X", "A"]) {
      withoutBytes(reader.receive(replaceHeader(part, 3, type)), "wrong-type");
      assert.equal(reader.progress(), null);
    }
    withoutBytes(reader.receive(part), "partial");
  } finally {
    reader.reset();
  }
});

test("BBQr same-index conflicting payload is terminal across static transport until reset", () => {
  const entry = fixture("H");
  const [part] = partsFor(entry);
  const reader = createPsbtQrReader();
  try {
    withoutBytes(reader.receive(part), "partial");
    const changed = part.slice(0, -2) + (part.endsWith("00") ? "01" : "00");
    withoutBytes(reader.receive(changed), "mismatch");
    withoutBytes(reader.receive(sourceFor(entry).toString("base64")), "mismatch");
    withoutBytes(reader.receive(partsFor(fixture("H", "single"))[0]), "mismatch");
    reader.reset();
    assert.equal(reader.progress(), null);
    exactCompletion(reader.receive(partsFor(fixture("H", "single"))[0]), sourceFor(entry));
  } finally {
    reader.reset();
  }
});

for (const [name, mutate] of [
  ["encoding", (part) => replaceHeader(partsFor(fixture("2"))[1], 4, part.slice(4, 6))],
  ["file type", (part) => replaceHeader(part, 3, "T")],
  ["total count", (part) => replaceHeader(part, 4, "09")],
]) {
  test(`BBQr mixed ${name} headers cannot join a bound session`, () => {
    const [a, b] = partsFor(fixture("H"));
    const reader = createPsbtQrReader();
    try {
      withoutBytes(reader.receive(a), "partial");
      withoutBytes(reader.receive(mutate(b)), "mismatch");
    } finally {
      reader.reset();
    }
  });
}

const malformed = [
  ["short header", "B$HP01"],
  ["unknown encoding", "B$QP010070736274FF"],
  ["lowercase encoding", "B$hP010070736274FF"],
  ["lowercase hex", "B$HP010070736274ff"],
  ["odd hex length", "B$HP010070736274F"],
  ["nonhex payload", "B$HP010070736274FG"],
  ["empty payload", "B$HP0100"],
  ["zero count", "B$HP000070736274FF"],
  ["index outside count", "B$HP010170736274FF"],
  ["lowercase base36 count", "B$HP0a0070736274FF"],
  ["lowercase base36 index", "B$HP0B0a70736274FF"],
  ["signed base36 index", "B$HP02+170736274FF"],
  ["space in base36 count", "B$HP 20070736274FF"],
  ["Base32 padding", "B$2P0100MY======"],
  ["Base32 lowercase", "B$2P0100my"],
  ["Base32 alphabet violation", "B$2P0100M0"],
  ["Base32 impossible length", "B$2P0100A"],
  ["Base32 impossible three-character tail", "B$2P0100AAA"],
  ["Base32 nonzero unused bits (RFC4648 f is MY)", "B$2P0100MZ"],
  ["Base32 nonzero unused bits (RFC4648 fo is MZXQ)", "B$2P0100MZXR"],
  ["Base32 nonfinal partial quintet group", "B$2P0200MY"],
  ["interior whitespace", "B$HP0100707362 74FF"],
];
for (const [name, frame] of malformed) {
  test(`BBQr refuses ${name}`, () => {
    const reader = createPsbtQrReader();
    try {
      withoutBytes(reader.receive(frame), "bad-part");
    } finally {
      reader.reset();
    }
  });
}

for (const finalFirst of [false, true]) {
  test(`BBQr unequal nonfinal lengths and oversized final are refused (final-first=${finalFirst})`, () => {
    const parts = partsFor(fixture("H"));
    const reader = createPsbtQrReader();
    try {
      if (finalFirst) withoutBytes(reader.receive(parts.at(-1)), "partial");
      withoutBytes(reader.receive(parts[0]), "partial");
      withoutBytes(reader.receive(parts[1].slice(0, -2)), "bad-part");
      reader.reset();
      const oversized = parts.at(-1).slice(0, 8) + "00".repeat((parts[0].length - 8) / 2 + 1);
      withoutBytes(reader.receive(finalFirst ? oversized : parts[0]), "partial");
      withoutBytes(reader.receive(finalFirst ? parts[0] : oversized), "bad-part");
    } finally {
      reader.reset();
    }
  });
}

const compressedCases = JSON.parse(readFileSync(new URL("compressed-rejections.json", root), "utf8"));
for (const entry of compressedCases) {
  test(`BBQr Z refuses ${entry.name}`, () => {
    const reader = createPsbtQrReader();
    try {
      let result;
      for (const frame of entry.frames) result = reader.receive(frame);
      withoutBytes(result, entry.status);
      if (entry.status !== "not-psbt") {
        const valid = partsFor(fixture("H", "single"))[0];
        withoutBytes(reader.receive(valid), entry.status);
        reader.reset();
        exactCompletion(reader.receive(valid), sourceFor(fixture("H", "single")));
      }
    } finally {
      reader.reset();
    }
  });
}

test("BBQr enforces default frame count and QR text size caps before collecting", () => {
  for (const frame of ["B$HPRT0070736274FF", "B$HP0100" + "00".repeat(2145)]) {
    const reader = createPsbtQrReader();
    try {
      withoutBytes(reader.receive(frame), "too-large");
    } finally {
      reader.reset();
    }
  }
});

for (const encoding of ["H", "2", "Z"]) {
  test(`BBQr ${encoding} exact decoded-byte budget succeeds and one less refuses`, () => {
    const entry = fixture(encoding, "single");
    const expected = sourceFor(entry);
    const frame = partsFor(entry)[0];
    for (const delta of [0, -1]) {
      const reader = createPsbtQrReader({ maxBytes: expected.length + delta });
      try {
        const result = reader.receive(frame);
        if (delta === 0) exactCompletion(result, expected);
        else withoutBytes(result, "too-large");
      } finally {
        reader.reset();
      }
    }
  });
}

test("BBQr compressed-input budget is independent of its smaller inflated output", () => {
  // RFC1951 final stored block containing PSBT magic: 5 header bytes + 5 data
  // bytes. RFC4648 Base32 for 01 05 00 FA FF 70 73 62 74 FF, independently
  // encoded with Python base64, is AECQB6X7OBZWE5H7 (10 compressed, 5 output).
  const reader = createPsbtQrReader({ maxBytes: 5 });
  try {
    withoutBytes(reader.receive("B$ZP0100AECQB6X7OBZWE5H7"), "too-large");
  } finally {
    reader.reset();
  }
});

test("BBQr type P still requires PSBT magic after uncompressed decoding", () => {
  const reader = createPsbtQrReader();
  try {
    // RFC4648's published f -> MY, and its equivalent uppercase hex.
    withoutBytes(reader.receive("B$2P0100MY"), "not-psbt");
    reader.reset();
    withoutBytes(reader.receive("B$HP010066"), "not-psbt");
  } finally {
    reader.reset();
  }
});

test("BBQr reset discards incomplete state and independent readers do not share it", () => {
  const entry = fixture("2");
  const parts = partsFor(entry);
  const a = createPsbtQrReader(), b = createPsbtQrReader();
  try {
    withoutBytes(a.receive(parts.at(-1)), "partial");
    assert.equal(b.progress(), null);
    a.reset();
    assert.equal(a.progress(), null);
    withoutBytes(a.receive(parts[0]), "partial");
    assert.deepEqual(a.progress(), { received: 1, total: parts.length });
    exactCompletion(b.receive(partsFor(fixture("Z", "single"))[0]), sourceFor(entry));
    assert.deepEqual(a.progress(), { received: 1, total: parts.length });
    a.reset();
    exactCompletion(a.receive(partsFor(fixture("H", "single"))[0]), sourceFor(entry));
  } finally {
    a.reset();
    b.reset();
  }
});

test("BBQr cannot authenticate same-header, same-length cross-transfer fragments", () => {
  // Deliberate protocol limitation, not an impossible rejection requirement:
  // no session ID or whole-message checksum exists. A caller must still parse
  // and independently review any recovered PSBT before trusting its contents.
  const entry = fixture("H");
  const parts = partsFor(entry);
  const expected = Buffer.from(sourceFor(entry));
  const offset = (parts[0].length - 8) / 2;
  expected[offset] ^= 1;
  parts[1] = parts[1].slice(0, 8) + expected.subarray(offset, offset * 2).toString("hex").toUpperCase();
  const reader = createPsbtQrReader();
  try {
    for (const part of parts.slice(0, -1)) withoutBytes(reader.receive(part), "partial");
    exactCompletion(reader.receive(parts.at(-1)), expected);
  } finally {
    reader.reset();
  }
});
