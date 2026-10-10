// BIP-93 Codex32 calculator, MS1 only.
//
// Checksum completion, secret recovery, and deriving another share are
// deterministic: the user supplies the strings, and the same strings always
// produce the same result. This module does not generate a wallet, split a
// fresh seed, or read browser randomness. CW1 and CX1 are not implemented.
// Calculate Checksum appends a checksum to the header and payload that were
// typed. It does not search for a transcription error already in that payload.

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const CHAR_AT = new Map([...CHARSET].map((character, index) => [character, index]));
const MS32_CONST = 0x10ce0795c2fd1e62an;
const MS32_LONG_CONST = 0x43381e570bf4798ab26n;
const REGULAR_GEN = [
  0x19dc500ce73fde210n,
  0x1bfae00def77fe529n,
  0x1fbd920fffe7bee52n,
  0x1739640bdeee3fdadn,
  0x07729a039cfc75f5an,
];
const LONG_GEN = [
  0x3d59d273535ea62d897n,
  0x7a9becb6361c6c51507n,
  0x543f9b7e6c38d8a2a0en,
  0x0c577eaeccf1990d13cn,
  0x1887f74f8dc71b10651n,
];
const BECH32_INV = [
  0, 1, 20, 24, 10, 8, 12, 29, 5, 11, 4, 9, 6, 28, 26, 31,
  22, 18, 17, 23, 2, 25, 16, 19, 3, 21, 14, 30, 13, 7, 27, 15,
];
// Support 128-, 256-, and 512-bit seeds only. Complete and checksum-free
// lengths are disjoint, so a failed checksum cannot become a longer payload.
const COMPLETE_CHECKSUM = new Map([[48, 13], [74, 13], [127, 15]]);
const INCOMPLETE_CHECKSUM = new Map([[35, 13], [61, 13], [112, 15]]);
const SEED_LENGTHS = new Set([16, 32, 64]);

function polymod(values, { shift, mask, generators, target }) {
  let residue = 0x23181b3n;
  for (const value of values) {
    const top = residue >> shift;
    residue = ((residue & mask) << 5n) ^ BigInt(value);
    for (let i = 0; i < 5; i++) if ((top >> BigInt(i)) & 1n) residue ^= generators[i];
  }
  return residue === target;
}

function checksumResidue(values, { shift, mask, generators }) {
  let residue = 0x23181b3n;
  for (const value of values) {
    const top = residue >> shift;
    residue = ((residue & mask) << 5n) ^ BigInt(value);
    for (let i = 0; i < 5; i++) if ((top >> BigInt(i)) & 1n) residue ^= generators[i];
  }
  return residue;
}

const regularParams = { shift: 60n, mask: 0x0fffffffffffffffn, generators: REGULAR_GEN };
const longParams = { shift: 70n, mask: 0x3fffffffffffffffffn, generators: LONG_GEN };

function verifyChecksum(values) {
  const expanded = 5 + values.length;
  if (expanded >= 96) return expanded <= 1023 && polymod(values, { ...longParams, target: MS32_LONG_CONST });
  return expanded <= 93 && polymod(values, { ...regularParams, target: MS32_CONST });
}

function createChecksum(data) {
  const long = 5 + data.length + 13 > 93;
  const width = long ? 15 : 13;
  const params = long ? longParams : regularParams;
  const constant = long ? MS32_LONG_CONST : MS32_CONST;
  const residue = checksumResidue([...data, ...Array(width).fill(0)], params) ^ constant;
  const out = [];
  for (let i = 0; i < width; i++) out.push(Number((residue >> BigInt(5 * (width - 1 - i))) & 31n));
  return out;
}

function canonicalize(input) {
  const raw = String(input ?? "").trim().replace(/\s+/g, "");
  if (!raw) throw new Error("Enter an MS1 string.");
  if (raw.toLowerCase() !== raw && raw.toUpperCase() !== raw) {
    throw new Error("MS1 strings must be all lowercase or all uppercase.");
  }
  const text = raw.toLowerCase();
  if (text.startsWith("cw1") || text.startsWith("cx1")) {
    throw new Error("Only MS1 is supported.");
  }
  return text;
}

function dataValues(text) {
  if (!text.startsWith("ms1")) throw new Error("Codex32 MS1 strings start with ms1.");
  const body = text.slice(3);
  if (![...body].every((character) => CHAR_AT.has(character))) throw new Error("MS1 data is not bech32.");
  const threshold = body[0];
  if (!/[02-9]/.test(threshold)) throw new Error("Threshold must be a digit from 0 or 2 through 9.");
  const index = body[5];
  if (!index) throw new Error("MS1 header is incomplete.");
  if (threshold === "0" && index !== "s") throw new Error("A threshold of 0 requires share index s.");
  return [...body].map((character) => CHAR_AT.get(character));
}

function encodeData(values) {
  return "ms1" + [...values, ...createChecksum(values)].map((value) => CHARSET[value]).join("");
}

function seedHexFromData(data) {
  const payload = data.slice(6);
  let accumulator = 0;
  let bits = 0;
  const bytes = [];
  for (const value of payload) {
    accumulator = (accumulator << 5) | value;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      bytes.push((accumulator >> bits) & 255);
      accumulator &= (1 << bits) - 1;
    }
  }
  if (bits > 4) throw new Error("MS1 payload has an incomplete group larger than 4 bits.");
  if (!SEED_LENGTHS.has(bytes.length)) throw new Error("MS1 master seed length is not supported.");
  return bytes.map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function parseCodex32(input) {
  const text = canonicalize(input);
  const checksumLength = COMPLETE_CHECKSUM.get(text.length);
  if (!checksumLength) throw new Error("MS1 length is not a supported master-seed size.");
  const values = dataValues(text);
  if (!verifyChecksum(values)) throw new Error("Checksum does not match. This calculator does not search for a transcription error.");
  const data = values.slice(0, -checksumLength);
  const body = text.slice(3);
  return {
    text,
    threshold: Number(body[0]),
    identifier: body.slice(1, 5),
    index: body[5],
    data,
    masterSeedHex: body[5] === "s" ? seedHexFromData(data) : null,
  };
}

// Append a checksum to the header and payload the user typed. A string that
// already has a valid checksum is returned unchanged. A failed checksum on a
// length that is not a bare header+payload is rejected; characters are never
// substituted to hunt for a nearby valid string.
export function completeCodex32Checksum(input) {
  const text = canonicalize(input);
  if (COMPLETE_CHECKSUM.has(text.length)) {
    const values = dataValues(text);
    if (verifyChecksum(values)) return text;
    throw new Error("Checksum does not match. This calculator does not search for a transcription error.");
  }
  // A valid 24-byte complete string is also 61 characters. Refuse it rather
  // than treat its existing checksum as part of a 32-byte payload.
  if (text.length === 61 && verifyChecksum(dataValues(text))) {
    throw new Error("MS1 master seed length is not supported; use 16, 32, or 64 bytes.");
  }
  const checksumLength = INCOMPLETE_CHECKSUM.get(text.length);
  if (!checksumLength) throw new Error("That is not an MS1 header and payload, or a complete MS1 string.");
  const values = dataValues(text);
  const completed = encodeData(values);
  if (completed.slice(0, text.length) !== text) throw new Error("Checksum completion changed the payload.");
  return completed;
}

function bech32Mul(a, b) {
  let result = 0;
  for (let i = 0; i < 5; i++) {
    if ((b >> i) & 1) result ^= a;
    a <<= 1;
    if (a >= 32) a ^= 41;
  }
  return result;
}

function bech32Lagrange(indices, target) {
  let numerator = 1;
  const denominators = [];
  for (const index of indices) {
    numerator = bech32Mul(numerator, index ^ target);
    let denominator = 1;
    for (const other of indices) {
      denominator = bech32Mul(denominator, (index === other ? target : index) ^ other);
    }
    denominators.push(denominator);
  }
  return denominators.map((denominator) => bech32Mul(numerator, BECH32_INV[denominator]));
}

function interpolate(rows, target) {
  const weights = bech32Lagrange(rows.map((row) => row[5]), target);
  const result = [];
  for (let column = 0; column < rows[0].length; column++) {
    let value = 0;
    for (let row = 0; row < rows.length; row++) value ^= bech32Mul(weights[row], rows[row][column]);
    result.push(value);
  }
  return result;
}

function shareSet(shares) {
  const list = (Array.isArray(shares) ? shares : String(shares ?? "").split(/[\s,]+/)).map((share) => String(share).trim()).filter(Boolean);
  if (!list.length) throw new Error("Enter MS1 shares.");
  const parsed = list.map(parseCodex32);
  const first = parsed[0];
  if (first.threshold < 2 || first.threshold > 9) throw new Error("Share threshold must be 2 through 9.");
  if (parsed.length !== first.threshold) {
    throw new Error("Need exactly " + first.threshold + " strings for this threshold (have " + parsed.length + ").");
  }
  for (const share of parsed) {
    if (share.threshold !== first.threshold) throw new Error("Shares do not have the same threshold.");
    if (share.identifier !== first.identifier) throw new Error("Shares do not have the same identifier.");
    if (share.data.length !== first.data.length) throw new Error("Shares do not have the same length.");
  }
  const seen = new Set();
  for (const share of parsed) {
    if (seen.has(share.index)) throw new Error("Share index " + share.index + " is repeated.");
    seen.add(share.index);
  }
  return parsed;
}

export function recoverCodex32Secret(shares) {
  const parsed = shareSet(shares);
  const data = interpolate(parsed.map((share) => share.data), CHAR_AT.get("s"));
  const text = encodeData(data);
  const secret = parseCodex32(text);
  if (secret.index !== "s") throw new Error("Recovery did not produce the secret index s.");
  return { codex32: secret.text, masterSeedHex: secret.masterSeedHex };
}

export function deriveCodex32Share(shares, index) {
  const parsed = shareSet(shares);
  const character = canonicalize(index);
  if (character.length !== 1 || !CHAR_AT.has(character)) throw new Error("Share index must be one bech32 character.");
  if (character === "s") throw new Error("Deriving to index s recovers the secret; use Recover secret instead.");
  if (parsed.some((share) => share.index === character)) throw new Error("That share index is already in the set.");
  const data = interpolate(parsed.map((share) => share.data), CHAR_AT.get(character));
  const text = encodeData(data);
  const derived = parseCodex32(text);
  if (derived.index !== character) throw new Error("Derived share index does not match.");
  return { codex32: derived.text, masterSeedHex: derived.masterSeedHex };
}

function field(id) {
  return document.getElementById(id);
}

function clearResult() {
  const out = field("codex32-out");
  const error = field("codex32-error");
  if (out) out.textContent = "";
  if (error) error.textContent = "";
}

export function hodlCodex32Wipe() {
  const shares = field("codex32-shares");
  const index = field("codex32-index");
  if (shares) shares.value = "";
  if (index) index.value = "";
  clearResult();
}

function show(text) {
  clearResult();
  const out = field("codex32-out");
  if (out) out.textContent = text;
}

function fail(error) {
  clearResult();
  const node = field("codex32-error");
  if (node) node.textContent = error?.message || String(error);
}

export function hodlInitCodex32() {
  const shares = field("codex32-shares");
  if (!shares || shares.dataset.codex32Ready) return;
  shares.dataset.codex32Ready = "1";
  field("codex32-checksum")?.addEventListener("click", () => {
    try {
      const lines = shares.value.split(/\n/).map((line) => line.trim()).filter(Boolean);
      if (lines.length !== 1) throw new Error("Calculate Checksum takes one header and payload.");
      const completed = completeCodex32Checksum(lines[0]);
      const parsed = parseCodex32(completed);
      show(parsed.masterSeedHex ? completed + "\n" + parsed.masterSeedHex : completed);
    } catch (error) {
      fail(error);
    }
  });
  field("codex32-recover")?.addEventListener("click", () => {
    try {
      const result = recoverCodex32Secret(shares.value);
      show(result.codex32 + "\n" + result.masterSeedHex);
    } catch (error) {
      fail(error);
    }
  });
  field("codex32-derive")?.addEventListener("click", () => {
    try {
      const result = deriveCodex32Share(shares.value, field("codex32-index")?.value ?? "");
      show(result.masterSeedHex ? result.codex32 + "\n" + result.masterSeedHex : result.codex32);
    } catch (error) {
      fail(error);
    }
  });
  field("codex32-clear")?.addEventListener("click", hodlCodex32Wipe);
}

