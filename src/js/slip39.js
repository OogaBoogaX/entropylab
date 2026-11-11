// SLIP-39 share sets (SLIP-0039, "Shamir's Secret-Sharing for Mnemonic
// Codes"), written from the specification for the Verify tab's "Check a
// SLIP-39 backup" (preview builds only). It reads shares, combines a
// threshold set into the encrypted master secret, decrypts it with the
// passphrase, and reconstructs the random values a set was split with, for
// the randomness test. It never splits a secret and never makes a random
// value.
//
// Security contract (test/slip39.test.mjs): a share is read only with a
// valid RS1024 checksum, a valid length and zero padding. A set is combined
// only when every share agrees on identifier, extendable flag, iteration
// exponent, group threshold, group count and length, each group has exactly
// its member threshold of distinct members, there are exactly the group
// threshold of groups, and every digest verifies, at the member level and at
// the group level. Anything else is refused with a reason and returns no
// master secret, encrypted secret or random value. The passphrase must be
// printable ASCII, as the specification requires. Intermediate buffers are
// zeroed before return; callers zero what they are given (wipeSlip39).
import { hmacSha256 } from "./hsm-secret.js";
import { slip39Wordlist } from "./slip39-wordlist.js";

const METADATA_WORDS = 7; // identifier and exponent (2), share parameters (2), checksum (3)
const MIN_SECRET_BYTES = 16;
const MAX_SECRET_BYTES = 64; // a BIP32 seed is at most 512 bits
const SECRET_INDEX = 255;
const DIGEST_INDEX = 254;
const DIGEST_BYTES = 4;
const BASE_ITERATIONS = 10000;
const ROUNDS = 4;
// The randomness test reports a common run of this many bytes: two
// independent 32-byte values share one with odds near 2^-54.
const MIN_REPEAT_BYTES = 8;

const wordIndex = new Map(slip39Wordlist.map((word, index) => [word, index]));
const asciiCodes = (text) => Array.from(text, (character) => character.charCodeAt(0));
const CUSTOMIZATION = { original: asciiCodes("shamir"), extendable: asciiCodes("shamir_extendable") };

// ── RS1024 (the specification's Checksum section) ────────────────────────
const GENERATOR = [0xe0e040, 0x1c1c080, 0x3838100, 0x7070200, 0xe0e0009, 0x1c0c2412, 0x38086c24, 0x3090fc48, 0x21b1f890, 0x3f3f120];
function polymod(values) {
  let check = 1;
  for (const value of values) {
    const top = check >>> 20;
    check = ((check & 0xfffff) << 10) ^ value;
    for (let i = 0; i < 10; i++) if ((top >>> i) & 1) check ^= GENERATOR[i];
  }
  return check;
}
const checksumValid = (indices, extendable) => polymod([...(extendable ? CUSTOMIZATION.extendable : CUSTOMIZATION.original), ...indices]) === 1;

// ── GF(256), Rijndael polynomial x^8 + x^4 + x^3 + x + 1, generator x + 1 ─
const EXP = new Uint8Array(255);
const LOG = new Uint8Array(256);
for (let i = 0, poly = 1; i < 255; i++) {
  EXP[i] = poly;
  LOG[poly] = i;
  poly ^= poly << 1;
  if (poly & 0x100) poly ^= 0x11b;
}

// f(x) from points { x, y } with distinct x and equal-length y (Lagrange).
function interpolate(points, x) {
  const known = points.find((point) => point.x === x);
  if (known) return Uint8Array.from(known.y);
  const out = new Uint8Array(points[0].y.length);
  let logProduct = 0;
  for (const point of points) logProduct += LOG[point.x ^ x];
  for (const point of points) {
    let logBasis = logProduct - LOG[point.x ^ x];
    for (const other of points) if (other !== point) logBasis -= LOG[point.x ^ other.x];
    logBasis = ((logBasis % 255) + 255) % 255;
    for (let k = 0; k < out.length; k++) if (point.y[k]) out[k] ^= EXP[(LOG[point.y[k]] + logBasis) % 255];
  }
  return out;
}

const refuse = (reason, details = {}) => ({ ok: false, reason, ...details });

// ── Reading one share ────────────────────────────────────────────────────
// A share's words (any case, any whitespace between them) to its fields, or
// a refusal: "empty", "unknown-word" (with its 1-based position), "length",
// "checksum", "group-threshold" (greater than the group count) or "padding".
export function parseSlip39Share(text) {
  const words = String(text ?? "").trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return refuse("empty");
  const indices = new Uint16Array(words.length);
  try {
    for (let i = 0; i < words.length; i++) {
      const index = wordIndex.get(words[i]);
      if (index === undefined) return refuse("unknown-word", { position: i + 1 });
      indices[i] = index;
    }
    const valueWords = words.length - METADATA_WORDS;
    const padding = (valueWords * 10) % 16;
    const length = (valueWords * 10 - padding) / 8;
    if (valueWords < 1 || padding > 8 || length < MIN_SECRET_BYTES || length > MAX_SECRET_BYTES) return refuse("length", { words: words.length });
    const idExp = (indices[0] << 10) | indices[1];
    const extendable = ((idExp >>> 4) & 1) === 1;
    if (!checksumValid(indices, extendable)) return refuse("checksum");
    const params = (indices[2] << 10) | indices[3];
    const groupThreshold = ((params >>> 12) & 15) + 1, groupCount = ((params >>> 8) & 15) + 1;
    if (groupThreshold > groupCount) return refuse("group-threshold");
    // The value is big-endian base 1024 behind `padding` zero bits.
    const first = indices[4];
    if (first >>> (10 - padding)) return refuse("padding");
    const value = new Uint8Array(length);
    let acc = first & ((1 << (10 - padding)) - 1), bits = 10 - padding, out = 0;
    for (let i = 4; ; ) {
      while (bits >= 8) {
        bits -= 8;
        value[out++] = (acc >>> bits) & 0xff;
        acc &= (1 << bits) - 1;
      }
      if (++i >= words.length - 3) break;
      acc = (acc << 10) | indices[i];
      bits += 10;
    }
    acc = 0;
    return {
      ok: true,
      share: {
        identifier: idExp >>> 5,
        extendable,
        iterationExponent: idExp & 15,
        groupIndex: (params >>> 16) & 15,
        groupThreshold,
        groupCount,
        memberIndex: (params >>> 4) & 15,
        memberThreshold: (params & 15) + 1,
        value,
      },
    };
  } finally {
    indices.fill(0);
  }
}

// ── Combining ────────────────────────────────────────────────────────────
const COMMON = [["identifier", "identifier"], ["extendable", "extendable"], ["iterationExponent", "iteration-exponent"], ["groupThreshold", "group-threshold"], ["groupCount", "group-count"]];

// RecoverSecret: the secret at x = 255, checked against the digest at x = 254
// (its first 4 bytes are HMAC-SHA256(key = R, msg = secret), R the rest).
function recoverSecret(threshold, points) {
  if (threshold === 1) return { secret: Uint8Array.from(points[0].y), digest: null };
  const secret = interpolate(points, SECRET_INDEX);
  const digest = interpolate(points, DIGEST_INDEX);
  const check = hmacSha256(digest.subarray(DIGEST_BYTES), secret);
  let same = 0;
  for (let i = 0; i < DIGEST_BYTES; i++) same |= check[i] ^ digest[i];
  check.fill(0);
  if (same) {
    secret.fill(0);
    digest.fill(0);
    return null;
  }
  return { secret, digest };
}

// The random values one split drew: R (the digest share's bytes after the
// first 4) and, for a threshold of 3 or more, the random shares at x = 0 to
// threshold - 3.
function splitRandomValues(threshold, points, digest, label) {
  if (threshold === 1) return [];
  const values = [{ ...label, x: DIGEST_INDEX, bytes: digest.slice(DIGEST_BYTES) }];
  for (let x = 0; x < threshold - 2; x++) values.push({ ...label, x, bytes: interpolate(points, x) });
  return values;
}

function recover(shares, { withRandom }) {
  if (!shares?.length) return refuse("no-shares");
  const first = shares[0];
  for (let i = 1; i < shares.length; i++) {
    for (const [key, field] of COMMON) if (shares[i][key] !== first[key]) return refuse("mismatch", { field, share: i });
    if (shares[i].value.length !== first.value.length) return refuse("mismatch", { field: "length", share: i });
  }
  const groups = new Map();
  for (const [i, share] of shares.entries()) {
    const members = groups.get(share.groupIndex) ?? [];
    if (members.length && members[0].memberThreshold !== share.memberThreshold) return refuse("member-threshold", { group: share.groupIndex, share: i });
    if (members.some((member) => member.memberIndex === share.memberIndex)) return refuse("duplicate-member", { group: share.groupIndex, member: share.memberIndex, share: i });
    members.push(share);
    groups.set(share.groupIndex, members);
  }
  const need = first.groupThreshold;
  if (groups.size < need) return refuse("too-few-groups", { have: groups.size, need });
  if (groups.size > need) return refuse("too-many-groups", { have: groups.size, need });
  const ordered = [...groups.entries()].sort(([a], [b]) => a - b);
  for (const [group, members] of ordered) {
    const threshold = members[0].memberThreshold;
    if (members.length < threshold) return refuse("too-few-members", { group, have: members.length, need: threshold });
    if (members.length > threshold) return refuse("too-many-members", { group, have: members.length, need: threshold });
  }
  const groupPoints = [], values = [];
  const wipeAll = () => {
    for (const point of groupPoints) point.y.fill(0);
    for (const value of values) value.bytes.fill(0);
  };
  for (const [group, members] of ordered) {
    const threshold = members[0].memberThreshold;
    const points = members.map((member) => ({ x: member.memberIndex, y: member.value }));
    const recovered = recoverSecret(threshold, points);
    if (!recovered) {
      wipeAll();
      return refuse("digest", { level: "member", group });
    }
    if (withRandom) values.push(...splitRandomValues(threshold, points, recovered.digest, { level: "member", group }));
    recovered.digest?.fill(0);
    groupPoints.push({ x: group, y: recovered.secret });
  }
  const recovered = recoverSecret(need, groupPoints);
  if (!recovered) {
    wipeAll();
    return refuse("digest", { level: "group" });
  }
  if (withRandom) values.unshift(...splitRandomValues(need, groupPoints, recovered.digest, { level: "group", group: null }));
  recovered.digest?.fill(0);
  for (const point of groupPoints) point.y.fill(0);
  const result = {
    ok: true,
    identifier: first.identifier,
    extendable: first.extendable,
    iterationExponent: first.iterationExponent,
    groupThreshold: need,
    groupCount: first.groupCount,
    length: first.value.length,
    groups: ordered.map(([index, members]) => ({ index, threshold: members[0].memberThreshold, members: members.map((member) => member.memberIndex).sort((a, b) => a - b) })),
    ems: recovered.secret,
  };
  if (withRandom) result.values = values;
  return result;
}

// The set's shape and its encrypted master secret, or a refusal: "no-shares",
// "mismatch" (with the field and the first share that differs),
// "member-threshold", "duplicate-member", "too-few-groups",
// "too-many-groups", "too-few-members", "too-many-members" or "digest".
export const recoverSlip39 = (shares) => recover(shares, { withRandom: false });

// As recoverSlip39, plus every random value the set's splits drew, group
// level first: { level: "group" | "member", group, x, bytes }.
export const slip39RandomValues = (shares) => recover(shares, { withRandom: true });

// PBKDF2 (RFC 8018) with HMAC-SHA256 as its PRF, on the repository's sha256.
export function pbkdf2HmacSha256(password, salt, iterations, length) {
  if (!Number.isSafeInteger(iterations) || iterations < 1) throw new Error("PBKDF2 iterations must be a positive integer.");
  if (!Number.isSafeInteger(length) || length < 1 || length > 1024) throw new Error("PBKDF2 length must be between 1 and 1024 bytes.");
  const out = new Uint8Array(length);
  const first = new Uint8Array(salt.length + 4);
  first.set(salt);
  try {
    for (let block = 1, offset = 0; offset < length; block++, offset += 32) {
      new DataView(first.buffer).setUint32(salt.length, block);
      let u = hmacSha256(password, first);
      const t = Uint8Array.from(u);
      for (let i = 1; i < iterations; i++) {
        const next = hmacSha256(password, u);
        u.fill(0);
        u = next;
        for (let k = 0; k < 32; k++) t[k] ^= u[k];
      }
      u.fill(0);
      out.set(t.subarray(0, Math.min(32, length - offset)), offset);
      t.fill(0);
    }
    return out;
  } finally {
    first.fill(0);
  }
}

// The specification's Decryption: a four-round Feistel network with
// PBKDF2-HMAC-SHA256 as the round function, rounds 3 to 0.
function decrypt(ems, passphrase, { identifier, extendable, iterationExponent }) {
  const half = ems.length / 2;
  const prefix = extendable ? [] : [...CUSTOMIZATION.original, identifier >>> 8, identifier & 0xff];
  const iterations = (BASE_ITERATIONS << iterationExponent) / ROUNDS;
  let left = ems.slice(0, half), right = ems.slice(half);
  for (let round = ROUNDS - 1; round >= 0; round--) {
    const password = new Uint8Array(1 + passphrase.length);
    password[0] = round;
    password.set(passphrase, 1);
    const salt = new Uint8Array(prefix.length + half);
    salt.set(prefix);
    salt.set(right, prefix.length);
    const f = pbkdf2HmacSha256(password, salt, iterations, half);
    const next = new Uint8Array(half);
    for (let k = 0; k < half; k++) next[k] = left[k] ^ f[k];
    for (const buffer of [password, salt, f, left]) buffer.fill(0);
    left = right;
    right = next;
  }
  const secret = new Uint8Array(ems.length);
  secret.set(right);
  secret.set(left, half);
  left.fill(0);
  right.fill(0);
  return secret;
}

// A threshold set and the passphrase's bytes to the master secret (the BIP32
// seed itself), with the set's shape; or a refusal: "passphrase" (not
// printable ASCII), "iteration-exponent" (over `maxIterationExponent`: each
// step doubles the PBKDF2 work, which runs on the page's thread) or any of
// recoverSlip39's.
export function combineSlip39(shares, passphrase = new Uint8Array(0), { maxIterationExponent = 15 } = {}) {
  if (!passphrase.every((byte) => byte >= 32 && byte <= 126)) return refuse("passphrase");
  const recovered = recover(shares, { withRandom: false });
  if (!recovered.ok) return recovered;
  const { ems, ...shape } = recovered;
  if (shape.iterationExponent > maxIterationExponent) {
    ems.fill(0);
    return refuse("iteration-exponent", { exponent: shape.iterationExponent, max: maxIterationExponent });
  }
  try {
    return { ...shape, masterSecret: decrypt(ems, passphrase, shape) };
  } finally {
    ems.fill(0);
  }
}

// ── The randomness test ──────────────────────────────────────────────────
const label = ({ level, group, x }) => ({ level, group, x });
const equalBytes = (a, b) => a.length === b.length && a.every((byte, i) => byte === b[i]);

// The longest run of bytes both values contain, at any offsets.
function longestCommonRun(a, b) {
  let best = 0;
  let previous = new Uint16Array(b.length + 1), current = new Uint16Array(b.length + 1);
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      current[j] = a[i - 1] === b[j - 1] ? previous[j - 1] + 1 : 0;
      if (current[j] > best) best = current[j];
    }
    [previous, current] = [current, previous];
  }
  return best;
}

// A value no working generator gives: all zero, one byte repeated, a block
// of 2 to 4 bytes repeated, or a counter (1, 2 or 4-byte words, either byte
// order, rising or falling by one fixed step).
function trivialPattern(bytes) {
  if (bytes.every((byte) => byte === 0)) return "zero";
  if (bytes.every((byte) => byte === bytes[0])) return "repeated-byte";
  for (let period = 2; period <= 4; period++) {
    if (bytes.length >= 2 * period && bytes.every((byte, i) => i < period || byte === bytes[i - period])) return "repeated-block";
  }
  for (const size of [1, 2, 4]) {
    const count = Math.floor(bytes.length / size);
    if (count < 3) continue;
    for (const little of [false, true]) {
      const words = [];
      for (let w = 0; w < count; w++) {
        let word = 0;
        for (let k = 0; k < size; k++) word = word * 256 + bytes[w * size + (little ? size - 1 - k : k)];
        words.push(word);
      }
      const modulus = 2 ** (8 * size);
      const step = (words[1] - words[0] + modulus) % modulus;
      if (step && words.every((word, w) => w === 0 || (word - words[w - 1] + modulus) % modulus === step)) return "counter";
    }
  }
  return null;
}

// Two sets' random values (slip39RandomValues results) to findings:
// "same-backup" (same identifier and encrypted secret: nothing else is
// listed), "same-secret", "same-identifier", "repeat" (a run of 8 or more
// bytes in both sets), "repeat-within" (in one set) and "pattern".
export function compareSlip39Randomness(a, b) {
  const tally = (set) => ({ values: set.values.length, bytes: set.values.reduce((sum, value) => sum + value.bytes.length, 0) });
  const checked = { a: tally(a), b: tally(b) };
  const sameSecret = equalBytes(a.ems, b.ems), sameIdentifier = a.identifier === b.identifier;
  if (sameSecret && sameIdentifier) return { findings: [{ kind: "same-backup" }], checked };
  const findings = [];
  if (sameSecret) findings.push({ kind: "same-secret" });
  if (sameIdentifier) findings.push({ kind: "same-identifier" });
  const repeat = (kind, set, x, y) => {
    const length = longestCommonRun(x.bytes, y.bytes);
    if (length < MIN_REPEAT_BYTES) return;
    findings.push({ kind, ...(set ? { set } : {}), a: label(x), b: label(y), length, whole: length === x.bytes.length && length === y.bytes.length });
  };
  for (const x of a.values) for (const y of b.values) repeat("repeat", null, x, y);
  for (const [name, set] of [["a", a], ["b", b]]) {
    for (let i = 0; i < set.values.length; i++) for (let j = i + 1; j < set.values.length; j++) repeat("repeat-within", name, set.values[i], set.values[j]);
  }
  for (const [name, set] of [["a", a], ["b", b]]) {
    for (const value of set.values) {
      const pattern = trivialPattern(value.bytes);
      if (pattern) findings.push({ kind: "pattern", set: name, value: label(value), pattern });
    }
  }
  return { findings, checked };
}

const shapeOf = ({ identifier, extendable, iterationExponent, groupThreshold, groupCount, length, groups }) => ({ identifier, extendable, iterationExponent, groupThreshold, groupCount, length, groups });

// Two threshold sets, from two throwaway wallets, to the comparison of their
// random values; or a refusal naming the set ("a" or "b") that does not
// combine or has no random values. A share that is in both sets is not
// refused: a generator restarted from the same state gives two wallets the
// same random share, word for word, so it is compared like any other value
// (one set entered twice shows as "same-backup"). No passphrase is needed:
// the random values sit above the encryption.
export function testSlip39Randomness(sharesA, sharesB) {
  const a = slip39RandomValues(sharesA);
  if (!a.ok) return { ...a, set: "a" };
  const b = slip39RandomValues(sharesB);
  if (!b.ok) {
    wipeSlip39(a);
    return { ...b, set: "b" };
  }
  try {
    if (!a.values.length) return refuse("no-random-values", { set: "a" });
    if (!b.values.length) return refuse("no-random-values", { set: "b" });
    return { ok: true, ...compareSlip39Randomness(a, b), a: shapeOf(a), b: shapeOf(b) };
  } finally {
    wipeSlip39(a);
    wipeSlip39(b);
  }
}

// Zeroes what a result or a share holds.
export function wipeSlip39(result) {
  if (!result) return;
  result.masterSecret?.fill(0);
  result.ems?.fill(0);
  result.value?.fill(0);
  for (const value of result.values ?? []) value.bytes.fill(0);
}

