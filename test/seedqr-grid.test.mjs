// SeedQR copy check: the square-by-square reader in src/js/seedqr-grid.js.
//
// Security contract: a copy is reported as a seed only when its format
// information decodes unambiguously, its codewords decode within the
// level-L correction limit that keeps the specification's misdecode
// protection (2, 4 and 7 codewords for 21, 25 and 29 squares), and its
// payload is a Standard or Compact SeedQR with a valid BIP39 checksum;
// anything else is refused with no seed. Every square that differs from a
// fresh encoding is reported, and nothing else.
//
// Expected results come from outside the module under test: the SeedQR
// specification's own test vectors (words, digit streams, CompactSeedQR
// bitstreams, and the grids sampled from its PNGs, test/fixtures/seedqr),
// uqr as the independent encoder of rejection cases, and quircs (the Scan QR
// decoder, qr-wasm) as an independent reader of the same grids.
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { encode } from "uqr";
import { bip39English } from "../src/js/bip39.js";
import { QR_WASM_B64 } from "../src/js/qr-wasm-b64.js";
import {
  SEEDQR_GRID_SIZES,
  checkSeedQrGrid,
  parseSeedQrText,
  seedQrLayout,
  seedQrReferenceGrid,
} from "../src/js/seedqr-grid.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const spec = JSON.parse(readFileSync(join(root, "test/fixtures/seedqr/spec-vectors.json"), "utf8"));

const gridOf = (rows) => Uint8Array.from(rows.join(""), (character) => (character === "1" ? 1 : 0));
const wordsOf = (indices) => Array.from(indices, (index) => bip39English[index]).join(" ");
const hexOf = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
const cellsOf = (differences) => differences.map(({ row, col }) => `${row},${col}`).sort();

// uqr, border 0: the independent encoder for every grid that is not a spec
// vector.
const uqrGrid = (data, options = {}) => {
  const { size, data: modules, maskPattern } = encode(data, { ecc: "L", border: 0, ...options });
  const grid = new Uint8Array(size * size);
  for (let row = 0; row < size; row++) for (let col = 0; col < size; col++) grid[row * size + col] = modules[row][col] ? 1 : 0;
  return { size, grid, mask: maskPattern };
};

// A seeded xorshift picks the squares to flip, so every run injects the same
// errors. It chooses positions only; it is never key material.
const prng = (seed) => {
  let state = seed >>> 0 || 1;
  return (limit) => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) % limit;
  };
};

// ── quircs, the Scan QR decoder, as an independent reader ──────────────────

const wasm = (() => {
  const binary = atob(QR_WASM_B64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new WebAssembly.Instance(new WebAssembly.Module(bytes), {}).exports;
})();

function quircsDecode(grid, size) {
  const px = 4, border = 4, side = (size + border * 2) * px;
  const pixels = new Uint8Array(side * side).fill(255);
  for (let row = 0; row < size; row++) for (let col = 0; col < size; col++) {
    if (!grid[row * size + col]) continue;
    for (let dy = 0; dy < px; dy++) for (let dx = 0; dx < px; dx++) pixels[((border + row) * px + dy) * side + (border + col) * px + dx] = 0;
  }
  const outCap = 512;
  const gray = wasm.qr_alloc(pixels.length), out = wasm.qr_alloc(outCap);
  try {
    new Uint8Array(wasm.memory.buffer).set(pixels, gray);
    const code = wasm.qr_decode(gray, side, side, out, outCap);
    return code < 0 ? null : new Uint8Array(wasm.memory.buffer).slice(out, out + code);
  } finally {
    wasm.qr_free(gray, pixels.length);
    wasm.qr_free(out, outCap);
  }
}

// The payload a SeedQR carries, from the specification's own fields.
const specPayload = (vector) =>
  vector.kind === "standard" ? new TextEncoder().encode(vector.digits) : Uint8Array.from(vector.compactHex.match(/../g), (pair) => parseInt(pair, 16));

// ── Spec vectors ───────────────────────────────────────────────────────────

test("the fixture carries every SeedQR specification test vector", () => {
  assert.equal(spec.vectors.length, 16);
  const kinds = spec.vectors.map((vector) => `${vector.kind}-${vector.words.split(" ").length}-${vector.size}`);
  for (const expected of ["standard-12-25", "standard-24-29", "compact-12-21", "compact-24-25"]) assert.ok(kinds.includes(expected), expected);
  for (const vector of spec.vectors) assert.equal(vector.rows.length, vector.size, vector.name);
});

test("grid sizes follow the specification: 25 and 29 Standard, 21 and 25 Compact", () => {
  assert.deepEqual(SEEDQR_GRID_SIZES, { standard: { 12: 25, 24: 29 }, compact: { 12: 21, 24: 25 } });
});

for (const vector of spec.vectors) {
  test(`spec ${vector.name}: decodes to the specification's words, exact match`, () => {
    const result = checkSeedQrGrid(gridOf(vector.rows), vector.size);
    assert.equal(result.ok, true, result.reason);
    assert.equal(result.format, vector.kind === "standard" ? "standard-seedqr" : "compact-seedqr");
    assert.equal(result.words, vector.words.split(" ").length);
    assert.equal(wordsOf(result.indices), vector.words);
    assert.equal(result.correctedCodewords, 0);
    assert.equal(result.formatBitErrors, 0);
    assert.equal(result.ecc, "L");
    assert.deepEqual(result.differences, []);
  });

  test(`spec ${vector.name}: quircs reads the same grid to the specification's payload`, () => {
    assert.deepEqual(quircsDecode(gridOf(vector.rows), vector.size), specPayload(vector));
  });
}

test("a reference grid built from the spec words decodes back to the spec words", () => {
  for (const vector of spec.vectors) {
    const indices = Uint16Array.from(vector.words.split(" "), (word) => bip39English.indexOf(word));
    const format = vector.kind === "standard" ? "standard-seedqr" : "compact-seedqr";
    const reference = seedQrReferenceGrid(format, indices);
    assert.equal(reference.size, vector.size, vector.name);
    assert.deepEqual(quircsDecode(reference.grid, reference.size), specPayload(vector), vector.name);
    const result = checkSeedQrGrid(reference.grid, reference.size);
    assert.equal(wordsOf(result.indices), vector.words, vector.name);
    assert.deepEqual(result.differences, [], vector.name);
    // The same seed, the same mask, the same grid as the specification's PNG
    // when the mask agrees; otherwise only the mask-dependent squares differ.
    const forced = seedQrReferenceGrid(format, indices, checkSeedQrGrid(gridOf(vector.rows), vector.size).mask);
    assert.deepEqual(forced.grid, gridOf(vector.rows), vector.name);
  }
});

test("every mask pattern is read from the format information and decoded", () => {
  const vector = spec.vectors.find((entry) => entry.name === "vector 4 standard");
  for (let mask = 0; mask < 8; mask++) {
    const { size, grid } = uqrGrid(vector.digits, { maskPattern: mask });
    const result = checkSeedQrGrid(grid, size);
    assert.equal(result.mask, mask);
    assert.equal(wordsOf(result.indices), vector.words);
    assert.deepEqual(result.differences, []);
  }
});

// ── Pasted digits ──────────────────────────────────────────────────────────

test("pasted SeedQR digits and CompactSeedQR hex are read; anything else is refused", () => {
  const twelve = spec.vectors.find((entry) => entry.name === "vector 5 standard");
  const twentyFour = spec.vectors.find((entry) => entry.name === "vector 1 standard");
  const spaced = twelve.digits.match(/..../g).join(" ");
  assert.equal(wordsOf(parseSeedQrText(spaced).indices), twelve.words);
  assert.equal(parseSeedQrText(`\n${twelve.digits}\n`).format, "standard-seedqr");
  assert.equal(wordsOf(parseSeedQrText(twentyFour.digits).indices), twentyFour.words);
  assert.equal(parseSeedQrText(twentyFour.compactHex).format, "compact-seedqr");
  assert.equal(wordsOf(parseSeedQrText(twentyFour.compactHex.toUpperCase()).indices), twentyFour.words);
  // Wrong length, a bad checksum, an index past 2047, other text.
  assert.equal(parseSeedQrText(twelve.digits.slice(1)), null);
  assert.equal(parseSeedQrText("0".repeat(48)), null);
  assert.equal(parseSeedQrText(`2048${twelve.digits.slice(4)}`), null);
  assert.equal(parseSeedQrText(twelve.words), null);
  assert.equal(parseSeedQrText(""), null);
});

// ── Error injection ────────────────────────────────────────────────────────

// Data squares grouped by the codeword they belong to, in reading order.
const codewordCells = (size) => {
  const { order, regions } = seedQrLayout(size);
  const cells = [];
  for (let i = 0; i + 8 <= order.length; i += 8) cells.push(Array.from(order.slice(i, i + 8)));
  assert.ok(cells.every((group) => group.every((cell) => regions[cell] === 0)));
  return cells;
};
const LIMITS = { 21: { codewords: 26, max: 2 }, 25: { codewords: 44, max: 4 }, 29: { codewords: 70, max: 7 } };

// Flips one square in each of `count` distinct codewords.
function flipCodewords(grid, size, count, next) {
  const groups = codewordCells(size);
  const chosen = new Set();
  while (chosen.size < count) chosen.add(next(groups.length));
  const flipped = grid.slice();
  const cells = [];
  for (const group of chosen) {
    const cell = groups[group][next(8)];
    flipped[cell] ^= 1;
    cells.push(cell);
  }
  return { flipped, cells: cells.map((cell) => `${Math.floor(cell / size)},${cell % size}`).sort() };
}

test("codeword layout: SeedQR sizes have one level-L block each", () => {
  for (const size of [21, 25, 29]) assert.equal(codewordCells(size).length, LIMITS[size].codewords, `${size}`);
});

for (const vector of spec.vectors) {
  const { codewords, max } = LIMITS[vector.size];
  test(`spec ${vector.name}: 1..${max} wrong data squares are corrected, counted and listed exactly`, () => {
    const next = prng(vector.size * 7919 + vector.rows[9].length + vector.name.length);
    const grid = gridOf(vector.rows);
    for (let count = 1; count <= max; count++) for (let trial = 0; trial < 25; trial++) {
      const { flipped, cells } = flipCodewords(grid, vector.size, count, next);
      const result = checkSeedQrGrid(flipped, vector.size);
      assert.equal(result.ok, true, `${count} errors`);
      assert.equal(result.correctedCodewords, count);
      assert.equal(result.totalCodewords, codewords);
      assert.equal(result.maxCorrectable, max);
      assert.equal(wordsOf(result.indices), vector.words);
      assert.deepEqual(cellsOf(result.differences), cells);
      for (const difference of result.differences) {
        assert.equal(difference.region, "data");
        assert.equal(difference.dark, grid[difference.row * vector.size + difference.col] === 1);
      }
      // The independent reader agrees on the payload it corrects to.
      assert.deepEqual(quircsDecode(flipped, vector.size), specPayload(vector));
    }
  });

  test(`spec ${vector.name}: past ${max} wrong codewords the copy is refused with no seed`, () => {
    const next = prng(vector.size * 104729 + vector.name.length);
    const grid = gridOf(vector.rows);
    for (let count = max + 1; count <= max + 6; count++) for (let trial = 0; trial < 40; trial++) {
      const { flipped } = flipCodewords(grid, vector.size, count, next);
      const result = checkSeedQrGrid(flipped, vector.size);
      assert.equal(result.ok, false, `${count} errors decoded`);
      assert.equal(result.reason, "too-many-errors");
      assert.equal(result.indices, null);
      assert.equal(result.format, null);
    }
  });
}

test("several wrong squares inside one codeword count as one correction", () => {
  const vector = spec.vectors.find((entry) => entry.name === "vector 2 standard");
  const grid = gridOf(vector.rows);
  const [first] = codewordCells(vector.size);
  const flipped = grid.slice();
  for (const cell of first) flipped[cell] ^= 1;
  const result = checkSeedQrGrid(flipped, vector.size);
  assert.equal(result.correctedCodewords, 1);
  assert.equal(result.differences.length, 8);
  assert.equal(wordsOf(result.indices), vector.words);
});

test("wrong format squares: up to 3 per copy decode, and every wrong square is listed", () => {
  for (const vector of spec.vectors.filter((entry) => entry.kind === "standard")) {
    const { regions } = seedQrLayout(vector.size);
    const formatCells = [];
    for (let cell = 0; cell < regions.length; cell++) if (regions[cell] === 5) formatCells.push(cell);
    assert.equal(formatCells.length, 30, vector.name);
    const grid = gridOf(vector.rows);
    // Near the top-left finder: column 8 and row 8; the other copy sits by
    // the other two finders.
    const nearTopLeft = formatCells.filter((cell) => Math.floor(cell / vector.size) <= 8 && cell % vector.size <= 8);
    assert.equal(nearTopLeft.length, 15, vector.name);
    for (let count = 1; count <= 3; count++) {
      const flipped = grid.slice();
      const cells = nearTopLeft.slice(0, count);
      for (const cell of cells) flipped[cell] ^= 1;
      const result = checkSeedQrGrid(flipped, vector.size);
      assert.equal(result.ok, true, `${vector.name} ${count}`);
      assert.equal(result.formatBitErrors, count);
      assert.equal(result.correctedCodewords, 0);
      assert.deepEqual(cellsOf(result.differences), cells.map((cell) => `${Math.floor(cell / vector.size)},${cell % vector.size}`).sort());
      assert.ok(result.differences.every((difference) => difference.region === "format"));
    }
    // One copy left blank: the other copy still names the mask.
    const blanked = grid.slice();
    for (const cell of nearTopLeft) blanked[cell] = 0;
    const result = checkSeedQrGrid(blanked, vector.size);
    assert.equal(wordsOf(result.indices), vector.words);
    assert.ok(result.formatBitErrors > 3);
    // One copy inverted: the inverse of a format codeword is another format
    // codeword (the all-ones word is in the BCH(15,5) code), so the two
    // copies name different masks equally well. That is refused, not guessed.
    const inverted = grid.slice();
    for (const cell of nearTopLeft) inverted[cell] ^= 1;
    const refused = checkSeedQrGrid(inverted, vector.size);
    assert.equal(refused.ok, false);
    assert.equal(refused.reason, "format");
    assert.equal(refused.indices, null);
  }
});

test("format information too damaged in both copies is refused with no seed", () => {
  const vector = spec.vectors.find((entry) => entry.name === "vector 6 standard");
  const { regions } = seedQrLayout(vector.size);
  const flipped = gridOf(vector.rows);
  for (let cell = 0; cell < regions.length; cell++) if (regions[cell] === 5) flipped[cell] ^= 1;
  const result = checkSeedQrGrid(flipped, vector.size);
  assert.equal(result.ok, false);
  assert.equal(result.indices, null);
});

test("wrong finder, timing, alignment and dark squares are listed by area and do not change the seed", () => {
  for (const vector of spec.vectors) {
    const { regions } = seedQrLayout(vector.size);
    const grid = gridOf(vector.rows);
    const byRegion = new Map();
    for (let cell = 0; cell < regions.length; cell++) if ([1, 2, 3, 4].includes(regions[cell]) && !byRegion.has(regions[cell])) byRegion.set(regions[cell], cell);
    assert.equal(byRegion.has(3), vector.size > 21, `${vector.name}: alignment pattern`);
    const flipped = grid.slice();
    const expected = [];
    for (const cell of byRegion.values()) {
      flipped[cell] ^= 1;
      expected.push(`${Math.floor(cell / vector.size)},${cell % vector.size}`);
    }
    const result = checkSeedQrGrid(flipped, vector.size);
    assert.equal(result.ok, true, vector.name);
    assert.equal(result.correctedCodewords, 0);
    assert.equal(wordsOf(result.indices), vector.words);
    assert.deepEqual(cellsOf(result.differences), expected.sort());
    assert.deepEqual(result.differences.map((difference) => difference.region).sort(), [...byRegion.keys()].map((region) => ["data", "finder", "timing", "alignment", "dark"][region]).sort());
  }
});

test("the dark square sits at row size-8, column 8, and timing squares alternate", () => {
  for (const size of [21, 25, 29]) {
    const { regions, fixed } = seedQrLayout(size);
    assert.equal(regions[(size - 8) * size + 8], 4);
    assert.equal(fixed[(size - 8) * size + 8], 1);
    for (let i = 8; i <= size - 9; i++) {
      assert.equal(regions[6 * size + i], 2);
      assert.equal(fixed[6 * size + i], i % 2 === 0 ? 1 : 0);
      assert.equal(fixed[i * size + 6], i % 2 === 0 ? 1 : 0);
    }
    // uqr's function patterns sit on exactly the fixed squares of the layout.
    const { size: encodedSize, data: modules, types } = encode("0".repeat(size === 21 ? 10 : size === 25 ? 48 : 96), { ecc: "L", border: 0, minVersion: (size - 17) / 4, maxVersion: (size - 17) / 4 });
    assert.equal(encodedSize, size);
    for (let row = 0; row < size; row++) for (let col = 0; col < size; col++) {
      const region = regions[row * size + col];
      if (region >= 1 && region <= 4) assert.equal(modules[row][col] ? 1 : 0, fixed[row * size + col], `${size}: ${row},${col}`);
      // uqr marks every function square (finders, separators, timing,
      // alignment, format, dark) with a non-zero type and data squares 0.
      assert.equal(region !== 0 && region !== 6, Boolean(types[row][col]), `${size}: ${row},${col}`);
    }
  }
});

test("a wrong unused square is listed but needs no correction", () => {
  const vector = spec.vectors.find((entry) => entry.name === "vector 3 standard");
  const { regions } = seedQrLayout(vector.size);
  const remainder = [];
  for (let cell = 0; cell < regions.length; cell++) if (regions[cell] === 6) remainder.push(cell);
  assert.equal(remainder.length, 7);
  const flipped = gridOf(vector.rows);
  flipped[remainder[0]] ^= 1;
  const result = checkSeedQrGrid(flipped, vector.size);
  assert.equal(result.correctedCodewords, 0);
  assert.deepEqual(result.differences.map((difference) => difference.region), ["remainder"]);
});

// ── Rejections ─────────────────────────────────────────────────────────────

test("sizes outside SeedQR, and grids that are not 0/1 squares, are refused", () => {
  assert.equal(checkSeedQrGrid(new Uint8Array(33 * 33), 33).reason, "size");
  assert.equal(checkSeedQrGrid(new Uint8Array(24), 25).reason, "size");
  const grid = gridOf(spec.vectors[0].rows);
  grid[200] = 2;
  assert.throws(() => checkSeedQrGrid(grid, 25), /0 or 1/);
  assert.throws(() => checkSeedQrGrid([0, 1], 25), /Uint8Array/);
});

test("an empty grid is refused at the format information, with the fixed-pattern squares listed", () => {
  const result = checkSeedQrGrid(new Uint8Array(25 * 25), 25);
  assert.equal(result.ok, false);
  assert.equal(result.reason, "format");
  assert.equal(result.indices, null);
  const { fixed, regions } = seedQrLayout(25);
  let darkFixed = 0;
  for (let cell = 0; cell < fixed.length; cell++) if (regions[cell] >= 1 && regions[cell] <= 4 && fixed[cell]) darkFixed++;
  assert.equal(result.differences.length, darkFixed);
  assert.ok(result.differences.every((difference) => difference.dark === true));
});

test("valid QR codes that are not a SeedQR are refused with no seed", () => {
  const cases = [
    ["text", uqrGrid("https://example.com/seedqr", { minVersion: 2, maxVersion: 2 })],
    ["bad checksum", uqrGrid("0".repeat(48))],
    ["index past 2047", uqrGrid(`2048${"0".repeat(44)}`)],
    // A compressed mainnet WIF for the private key 1.
    ["WIF", uqrGrid("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")],
    ["words as text", uqrGrid(Array.from(new TextEncoder().encode(spec.vectors[0].words)), { minVersion: 3, maxVersion: 40 })],
  ];
  for (const [name, { size, grid }] of cases) {
    if (![21, 25, 29].includes(size)) continue;
    const result = checkSeedQrGrid(grid, size);
    assert.equal(result.ok, false, name);
    assert.equal(result.reason, "not-seedqr", name);
    assert.equal(result.indices, null, name);
  }
  assert.ok(cases.filter(([, { size }]) => [21, 25, 29].includes(size)).length >= 4);
});

test("a SeedQR at error correction level M is refused: the specification uses L", () => {
  const vector = spec.vectors.find((entry) => entry.name === "vector 4 standard");
  const { size, grid } = uqrGrid(vector.digits, { ecc: "M" });
  assert.equal(size, 25);
  const result = checkSeedQrGrid(grid, size);
  assert.equal(result.ok, false);
  assert.equal(result.reason, "ecc-level");
  assert.equal(result.ecc, "M");
  assert.equal(result.indices, null);
});

test("a SeedQR drawn mirrored is refused rather than read", () => {
  const vector = spec.vectors.find((entry) => entry.name === "vector 5 standard");
  const grid = gridOf(vector.rows), size = vector.size, mirrored = new Uint8Array(grid.length);
  for (let row = 0; row < size; row++) for (let col = 0; col < size; col++) mirrored[row * size + col] = grid[row * size + (size - 1 - col)];
  const result = checkSeedQrGrid(mirrored, size);
  assert.equal(result.ok, false);
  assert.equal(result.indices, null);
});
