// Checks a hand-copied SeedQR square by square. The reader below is written
// from ISO/IEC 18004 (format information, masks, module placement,
// Reed-Solomon over GF(256), numeric and byte modes) and shares no code with
// uqr, the encoder it is compared against, or with the wallet that drew the
// original. It covers only what SeedQR uses: 21, 25 and 29 squares
// (versions 1 to 3) at error correction level L, one block each.
//
// Security contract: a copy is reported as a seed only when its format
// information decodes unambiguously, its codewords decode within the
// level-L correction limit that keeps the specification's misdecode
// protection (2, 4 and 7 codewords), and its payload is a Standard or
// Compact SeedQR with a valid BIP39 checksum (qr-payload.js); anything else
// is refused with no seed. The caller owns `grid` and the returned
// `indices`; every other buffer here that holds payload bits is zeroed
// before it returns. The digit string handed to uqr for the re-encoding is
// immutable and cannot be zeroed, like the SeedQR digits the app already
// shows.

import { encode } from "uqr";
import { classifyQrPayload } from "./qr-payload.js";
import { entropyFromWordIndices } from "./bip39.js";

export const SEEDQR_GRID_SIZES = Object.freeze({
  standard: Object.freeze({ 12: 25, 24: 29 }),
  compact: Object.freeze({ 12: 21, 24: 25 }),
});

// Region codes for seedQrLayout().regions, named for the UI by
// SEEDQR_REGION_NAMES.
const DATA = 0, FINDER = 1, TIMING = 2, ALIGNMENT = 3, DARK = 4, FORMAT = 5, REMAINDER = 6;
export const SEEDQR_REGION_NAMES = Object.freeze(["data", "finder", "timing", "alignment", "dark", "format", "remainder"]);

// ISO/IEC 18004 Table 9, level L: total and data codewords, and the errors
// that may be corrected while keeping the misdecode-protection codewords.
const VERSIONS = Object.freeze({
  21: Object.freeze({ version: 1, total: 26, data: 19, maxErrors: 2, remainder: 0, alignment: 0 }),
  25: Object.freeze({ version: 2, total: 44, data: 34, maxErrors: 4, remainder: 7, alignment: 18 }),
  29: Object.freeze({ version: 3, total: 70, data: 55, maxErrors: 7, remainder: 7, alignment: 22 }),
});

const ECC_NAMES = ["M", "L", "H", "Q"]; // the 2-bit level indicator, in order

// Table 10, i = row, j = column: a square is inverted where the condition holds.
const MASKS = [
  (i, j) => (i + j) % 2 === 0,
  (i) => i % 2 === 0,
  (i, j) => j % 3 === 0,
  (i, j) => (i + j) % 3 === 0,
  (i, j) => (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0,
  (i, j) => ((i * j) % 2) + ((i * j) % 3) === 0,
  (i, j) => (((i * j) % 2) + ((i * j) % 3)) % 2 === 0,
  (i, j) => (((i + j) % 2) + ((i * j) % 3)) % 2 === 0,
];

// Format information: 5 data bits, a BCH(15,5) remainder from the generator
// x^10+x^8+x^5+x^4+x^2+x+1, XORed with 101010000010010 (Annex C).
const FORMAT_WORDS = Array.from({ length: 32 }, (_, value) => {
  let remainder = value << 10;
  for (let bit = 14; bit >= 10; bit--) if ((remainder >> bit) & 1) remainder ^= 0x537 << (bit - 10);
  return ((value << 10) | remainder) ^ 0x5412;
});

const popcount = (value) => {
  let count = 0;
  for (; value; value &= value - 1) count++;
  return count;
};

const wipe = (buffer) => {
  if (ArrayBuffer.isView(buffer)) buffer.fill(0);
};

const layouts = new Map();

// The fixed parts of a SeedQR-sized symbol: which area each square belongs
// to, the colour of every finder, separator, timing, alignment and dark
// square, both copies of the format information, and the order in which the
// data squares carry the codeword bits.
export function seedQrLayout(size) {
  const spec = VERSIONS[size];
  if (!spec) return null;
  if (layouts.has(size)) return layouts.get(size);
  const regions = new Uint8Array(size * size);
  const fixed = new Uint8Array(size * size);
  const set = (row, col, region, dark) => {
    regions[row * size + col] = region;
    fixed[row * size + col] = dark ? 1 : 0;
  };
  // Finder patterns with their light separators: rings 3 and 0..1 dark.
  for (const [top, left] of [[0, 0], [0, size - 7], [size - 7, 0]]) {
    for (let dr = -1; dr <= 7; dr++) for (let dc = -1; dc <= 7; dc++) {
      const row = top + dr, col = left + dc;
      if (row < 0 || col < 0 || row >= size || col >= size) continue;
      const ring = Math.max(Math.abs(dr - 3), Math.abs(dc - 3));
      set(row, col, FINDER, ring <= 1 || ring === 3);
    }
  }
  for (let i = 8; i <= size - 9; i++) {
    set(6, i, TIMING, i % 2 === 0);
    set(i, 6, TIMING, i % 2 === 0);
  }
  if (spec.alignment) {
    for (let dr = -2; dr <= 2; dr++) for (let dc = -2; dc <= 2; dc++) {
      set(spec.alignment + dr, spec.alignment + dc, ALIGNMENT, Math.max(Math.abs(dr), Math.abs(dc)) !== 1);
    }
  }
  set(size - 8, 8, DARK, true);
  // formatNear[i] / formatFar[i] hold format bit i, bit 0 least significant
  // (Figure 25): one copy around the top-left finder, the other split between
  // the top-right and bottom-left finders.
  const formatNear = new Array(15), formatFar = new Array(15);
  for (let i = 0; i <= 5; i++) formatNear[i] = i * size + 8;
  formatNear[6] = 7 * size + 8;
  formatNear[7] = 8 * size + 8;
  formatNear[8] = 8 * size + 7;
  for (let i = 9; i <= 14; i++) formatNear[i] = 8 * size + (14 - i);
  for (let i = 0; i <= 7; i++) formatFar[i] = 8 * size + (size - 1 - i);
  for (let i = 8; i <= 14; i++) formatFar[i] = (size - 15 + i) * size + 8;
  for (const cell of [...formatNear, ...formatFar]) regions[cell] = FORMAT;
  // Codeword bits run in two-square columns from the bottom right, up then
  // down, skipping the vertical timing column and every function square.
  const order = [];
  let upward = true;
  for (let right = size - 1; right > 0; right -= 2) {
    if (right === 6) right = 5;
    for (let step = 0; step < size; step++) {
      const row = upward ? size - 1 - step : step;
      for (const col of [right, right - 1]) if (regions[row * size + col] === DATA) order.push(row * size + col);
    }
    upward = !upward;
  }
  if (order.length !== spec.total * 8 + spec.remainder) throw new Error("SeedQR layout: data square count does not match the version");
  for (const cell of order.slice(spec.total * 8)) regions[cell] = REMAINDER;
  const layout = Object.freeze({ size, version: spec.version, regions, fixed, order: Uint16Array.from(order), formatNear, formatFar });
  layouts.set(size, layout);
  return layout;
}

// ── GF(256), primitive polynomial x^8+x^4+x^3+x^2+1 ──────────────────────

const EXP = new Uint8Array(510), LOG = new Uint8Array(256);
for (let i = 0, x = 1; i < 255; i++) {
  EXP[i] = EXP[i + 255] = x;
  LOG[x] = i;
  x <<= 1;
  if (x & 0x100) x ^= 0x11d;
}
const mul = (a, b) => (a && b ? EXP[LOG[a] + LOG[b]] : 0);
const div = (a, b) => (a ? EXP[LOG[a] + 255 - LOG[b]] : 0);
const alpha = (power) => EXP[((power % 255) + 255) % 255];
// Polynomials are coefficient arrays, lowest power first.
const evaluate = (poly, x) => {
  let y = 0;
  for (let i = poly.length - 1; i >= 0; i--) y = mul(y, x) ^ poly[i];
  return y;
};

// The codewords are a polynomial with the first codeword as its highest
// power; the generator's roots are alpha^0 .. alpha^(ec-1).
function syndromes(codewords, ecCount) {
  const out = new Uint8Array(ecCount);
  for (let i = 0; i < ecCount; i++) {
    const root = alpha(i);
    let y = 0;
    for (const codeword of codewords) y = mul(y, root) ^ codeword;
    out[i] = y;
  }
  return out;
}

// Corrects `codewords` in place: Berlekamp-Massey for the error locator,
// Chien search for the positions, Forney for the values. Returns the number
// of codewords corrected, or -1 past `maxErrors` or when the errors cannot be
// located consistently.
function correct(codewords, ecCount, maxErrors) {
  const n = codewords.length;
  const synd = syndromes(codewords, ecCount);
  try {
    if (synd.every((value) => value === 0)) return 0;
    let locator = [1], previous = [1], degree = 0, shift = 1, lastDiscrepancy = 1;
    for (let k = 0; k < ecCount; k++) {
      let discrepancy = synd[k];
      for (let i = 1; i <= degree; i++) discrepancy ^= mul(locator[i] ?? 0, synd[k - i]);
      if (discrepancy === 0) {
        shift++;
        continue;
      }
      const next = locator.slice();
      const scale = div(discrepancy, lastDiscrepancy);
      for (let i = 0; i < previous.length; i++) {
        while (next.length <= i + shift) next.push(0);
        next[i + shift] ^= mul(scale, previous[i]);
      }
      if (2 * degree <= k) {
        previous = locator;
        degree = k + 1 - degree;
        lastDiscrepancy = discrepancy;
        shift = 1;
      } else shift++;
      locator = next;
    }
    if (degree > maxErrors) return -1;
    // A root alpha^-p marks an error at power p, codeword n-1-p.
    const powers = [];
    for (let p = 0; p < n; p++) if (evaluate(locator, alpha(-p)) === 0) powers.push(p);
    if (powers.length !== degree) return -1;
    const evaluator = new Array(ecCount).fill(0);
    for (let i = 0; i < ecCount; i++) for (let j = 0; j <= i && j < locator.length; j++) evaluator[i] ^= mul(locator[j], synd[i - j]);
    const derivative = locator.slice(1).map((coefficient, i) => (i % 2 === 0 ? coefficient : 0));
    for (const p of powers) {
      const inverse = alpha(-p);
      const denominator = evaluate(derivative, inverse);
      if (!denominator) return -1;
      const value = mul(alpha(p), div(evaluate(evaluator, inverse), denominator));
      if (!value) return -1;
      codewords[n - 1 - p] ^= value;
    }
    evaluator.fill(0);
    const check = syndromes(codewords, ecCount);
    const clean = check.every((value) => value === 0);
    wipe(check);
    return clean ? degree : -1;
  } finally {
    wipe(synd);
  }
}

// Numeric and byte segments only, the two modes SeedQR uses. Returns
// { bytes, mode } with mode "numeric" or "byte", or null.
function readSegments(data) {
  const total = data.length * 8;
  let bit = 0;
  const take = (count) => {
    if (bit + count > total) return -1;
    let value = 0;
    for (let i = 0; i < count; i++, bit++) value = (value << 1) | ((data[bit >> 3] >> (7 - (bit & 7))) & 1);
    return value;
  };
  const out = [];
  const modes = new Set();
  try {
    while (total - bit >= 4) {
      const indicator = take(4);
      if (indicator === 0) break;
      if (indicator === 1) {
        let left = take(10);
        if (left < 0) return null;
        for (; left >= 3; left -= 3) {
          const group = take(10);
          if (group < 0 || group > 999) return null;
          out.push(48 + Math.floor(group / 100), 48 + (Math.floor(group / 10) % 10), 48 + (group % 10));
        }
        if (left === 2) {
          const pair = take(7);
          if (pair < 0 || pair > 99) return null;
          out.push(48 + Math.floor(pair / 10), 48 + (pair % 10));
        } else if (left === 1) {
          const digit = take(4);
          if (digit < 0 || digit > 9) return null;
          out.push(48 + digit);
        }
        modes.add("numeric");
      } else if (indicator === 4) {
        const count = take(8);
        if (count < 0) return null;
        for (let i = 0; i < count; i++) {
          const byte = take(8);
          if (byte < 0) return null;
          out.push(byte);
        }
        modes.add("byte");
      } else return null;
    }
    if (modes.size !== 1) return null;
    return { bytes: Uint8Array.from(out), mode: [...modes][0] };
  } finally {
    out.fill(0);
  }
}

const differencesFrom = (grid, expected, layout, onlyFixed) => {
  const { size, regions } = layout;
  const differences = [];
  for (let cell = 0; cell < grid.length; cell++) {
    const region = regions[cell];
    if (onlyFixed && (region < FINDER || region > DARK)) continue;
    if (grid[cell] !== expected[cell]) differences.push({ row: Math.floor(cell / size), col: cell % size, dark: expected[cell] === 1, region: SEEDQR_REGION_NAMES[region] });
  }
  return differences;
};

// Encodes `payload` (a digit string, numeric mode, or a byte array, byte
// mode) with uqr at this size, level and mask, as a 0/1 grid.
function reencode(payload, size, ecc, mask) {
  const version = VERSIONS[size].version;
  const { size: encodedSize, data: modules } = encode(payload, { ecc, border: 0, boostEcc: false, minVersion: version, maxVersion: version, maskPattern: mask });
  if (encodedSize !== size) throw new Error("SeedQR re-encoding changed size");
  const grid = new Uint8Array(size * size);
  for (let row = 0; row < size; row++) for (let col = 0; col < size; col++) grid[row * size + col] = modules[row][col] ? 1 : 0;
  for (const row of modules) row.fill(false);
  return grid;
}

// Reads a copy: `grid` holds size*size squares row by row, 1 filled and 0
// empty; rows and columns in the result count from 0.
//
// ok: the copy decodes to a seed. Then `differences` lists every square
// that differs from uqr's encoding of the decoded payload at the copy's own
// mask, and an exact copy has none. Otherwise `reason` says why ("size",
// "format", "ecc-level", "too-many-errors", "not-seedqr") and `differences`
// lists the finder, timing, alignment and dark squares that are wrong, plus
// the format squares when the format information was read.
export function checkSeedQrGrid(grid, size) {
  if (!(grid instanceof Uint8Array)) throw new TypeError("SeedQR grid must be a Uint8Array");
  const result = {
    ok: false, reason: "size", size, version: null, ecc: null, mask: null, formatBitErrors: 0,
    correctedCodewords: null, totalCodewords: null, maxCorrectable: null,
    format: null, words: null, indices: null, differences: [],
  };
  const layout = seedQrLayout(size);
  if (!layout || grid.length !== size * size) return result;
  for (const square of grid) if (square > 1) throw new RangeError("SeedQR grid squares must be 0 or 1");
  const spec = VERSIONS[size];
  Object.assign(result, { version: spec.version, totalCodewords: spec.total, maxCorrectable: spec.maxErrors });
  result.differences = differencesFrom(grid, layout.fixed, layout, true);

  // Format information: the nearest of the 32 codewords over either copy,
  // within the 3 bit errors BCH(15,5) corrects, and never a tie.
  const read = (cells) => cells.reduce((value, cell, i) => value | (grid[cell] << i), 0);
  const near = read(layout.formatNear), far = read(layout.formatFar);
  let best = -1, bestDistance = 16, tie = false;
  FORMAT_WORDS.forEach((word, value) => {
    const distance = Math.min(popcount(near ^ word), popcount(far ^ word));
    if (distance < bestDistance) [best, bestDistance, tie] = [value, distance, false];
    else if (distance === bestDistance) tie = true;
  });
  if (bestDistance > 3 || tie) {
    result.reason = "format";
    return result;
  }
  const formatWord = FORMAT_WORDS[best];
  result.ecc = ECC_NAMES[best >> 3];
  result.mask = best & 7;
  result.formatBitErrors = popcount(near ^ formatWord) + popcount(far ^ formatWord);
  const expectedFormat = layout.fixed.slice();
  layout.formatNear.forEach((cell, i) => (expectedFormat[cell] = (formatWord >> i) & 1));
  layout.formatFar.forEach((cell, i) => (expectedFormat[cell] = (formatWord >> i) & 1));
  for (const cell of [...layout.formatNear, ...layout.formatFar]) {
    if (grid[cell] !== expectedFormat[cell]) result.differences.push({ row: Math.floor(cell / size), col: cell % size, dark: expectedFormat[cell] === 1, region: "format" });
  }
  if (result.ecc !== "L") {
    result.reason = "ecc-level";
    return result;
  }

  // Unmask the data squares and read the codewords, most significant bit first.
  const codewords = new Uint8Array(spec.total);
  let segments = null, payload = null, expected = null;
  try {
    const flip = MASKS[result.mask];
    for (let i = 0; i < spec.total * 8; i++) {
      const cell = layout.order[i];
      const bit = grid[cell] ^ (flip(Math.floor(cell / size), cell % size) ? 1 : 0);
      codewords[i >> 3] |= bit << (7 - (i & 7));
    }
    const corrected = correct(codewords, spec.total - spec.data, spec.maxErrors);
    if (corrected < 0) {
      result.reason = "too-many-errors";
      return result;
    }
    result.correctedCodewords = corrected;
    segments = readSegments(codewords.subarray(0, spec.data));
    const classified = segments ? classifyQrPayload(segments.bytes) : null;
    if (!classified || (classified.format !== "standard-seedqr" && classified.format !== "compact-seedqr")) {
      if (classified?.indices) wipe(classified.indices);
      result.reason = "not-seedqr";
      return result;
    }
    if (segments.mode === "numeric") payload = String.fromCharCode(...segments.bytes);
    else payload = Array.from(segments.bytes);
    try {
      expected = reencode(payload, size, result.ecc, result.mask);
    } catch {
      wipe(classified.indices);
      result.reason = "not-seedqr";
      return result;
    }
    Object.assign(result, { ok: true, reason: null, format: classified.format, words: classified.words, indices: classified.indices });
    result.differences = differencesFrom(grid, expected, layout, false);
    return result;
  } finally {
    wipe(codewords);
    if (segments) wipe(segments.bytes);
    if (Array.isArray(payload)) payload.fill(0);
    if (expected) wipe(expected);
  }
}

// Pasted SeedQR digits (48 or 96, spacing ignored) or CompactSeedQR hex (32
// or 64 characters). Returns the classifier's { format, words, indices },
// or null. The caller owns `indices`.
export function parseSeedQrText(text) {
  const compact = String(text ?? "").replace(/\s+/g, "");
  let bytes = null;
  if (/^\d+$/.test(compact) && (compact.length === 48 || compact.length === 96)) bytes = new TextEncoder().encode(compact);
  else if (/^[0-9a-f]+$/i.test(compact) && (compact.length === 32 || compact.length === 64)) bytes = Uint8Array.from(compact.match(/../g), (pair) => parseInt(pair, 16));
  if (!bytes) return null;
  try {
    const classified = classifyQrPayload(bytes);
    if (classified.format === "standard-seedqr" || classified.format === "compact-seedqr") return classified;
    if (classified.indices) wipe(classified.indices);
    return null;
  } finally {
    wipe(bytes);
  }
}

// The SeedQR for `indices` as uqr draws it at level L: a Standard SeedQR's
// 4-digit word indices in numeric mode, or a CompactSeedQR's entropy bytes.
// `mask` -1 lets uqr choose, as the app's own SeedQR does.
export function seedQrReferenceGrid(format, indices, mask = -1) {
  if (!(indices instanceof Uint16Array) || (indices.length !== 12 && indices.length !== 24)) throw new RangeError("SeedQR needs 12 or 24 word indices");
  let payload;
  if (format === "standard-seedqr") payload = Array.from(indices, (index) => String(index).padStart(4, "0")).join("");
  else if (format === "compact-seedqr") {
    const entropy = entropyFromWordIndices(indices);
    payload = Array.from(entropy);
    wipe(entropy);
  } else throw new RangeError("Unknown SeedQR format");
  const { size, data: modules, maskPattern } = encode(payload, { ecc: "L", border: 0, boostEcc: false, maskPattern: mask });
  if (Array.isArray(payload)) payload.fill(0);
  const grid = new Uint8Array(size * size);
  for (let row = 0; row < size; row++) for (let col = 0; col < size; col++) grid[row * size + col] = modules[row][col] ? 1 : 0;
  for (const row of modules) row.fill(false);
  return { size, version: VERSIONS[size]?.version ?? null, mask: maskPattern, grid };
}
