// SLIP-39 shares (src/js/slip39.js): reading, combining and decrypting a
// share set, and the randomness test's comparison of two sets.
//
// Security contract: a share is read only with a valid RS1024 checksum, a
// valid length and zero padding; a set is combined only when every share
// agrees on identifier, extendable flag, iteration exponent, group threshold,
// group count and length, each group has exactly its threshold of distinct
// members, there are exactly the group threshold of groups, and every digest
// (member level and group level) verifies. Any other set is refused with a
// reason and carries no master secret, encrypted secret or random value. The
// passphrase must be printable ASCII.
//
// Expected values come from outside the code under test: the official
// SLIP-0039 vectors (python-shamir-mnemonic v0.3.0 vectors.json, linked from
// the SLIP-0039 specification) for combine, decrypt and the BIP32 master key,
// the published wordlist's SHA-256, @noble/hashes for PBKDF2-HMAC-SHA256,
// @scure/bip32 for the master key, and the specification's stated rejection
// conditions. The comparison tests build their inputs by hand, so each
// expected finding holds by construction.
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { pbkdf2 as noblePbkdf2 } from "@noble/hashes/pbkdf2.js";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { HDKey as ScureHDKey } from "@scure/bip32";
import { HDKey } from "../src/js/hdkey.js";
import { slip39Wordlist } from "../src/js/slip39-wordlist.js";
import {
  combineSlip39,
  compareSlip39Randomness,
  parseSlip39Share,
  pbkdf2HmacSha256,
  recoverSlip39,
  slip39RandomValues,
  testSlip39Randomness,
} from "../src/js/slip39.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const vectorsText = readFileSync(join(root, "test/fixtures/slip39/vectors.json"), "utf8");
const vectors = JSON.parse(vectorsText);
const hex = (bytes) => Buffer.from(bytes).toString("hex");
const sha256Hex = (text) => createHash("sha256").update(text).digest("hex");
const ascii = (text) => new TextEncoder().encode(text);
// The passphrase the SLIP-0039 specification gives for every valid vector.
const VECTOR_PASSPHRASE = ascii("TREZOR");

const parseAll = (mnemonics) => {
  const shares = [];
  for (const [index, mnemonic] of mnemonics.entries()) {
    const parsed = parseSlip39Share(mnemonic);
    if (!parsed.ok) return { ok: false, reason: parsed.reason, share: index };
    shares.push(parsed.share);
  }
  return { ok: true, shares };
};
const refusalOf = (result) => (result.reason === "mismatch" ? `mismatch:${result.field}` : result.reason);
const SECRET_FIELDS = ["masterSecret", "ems", "values"];

// What each invalid official vector must be refused for, read from the
// vector's own description (vectors 21-35 repeat 2-16 at 256 bits).
const REFUSALS = {
  2: "checksum", 3: "padding", 5: "too-few-members", 6: "mismatch:identifier", 7: "mismatch:iteration-exponent",
  8: "mismatch:group-threshold", 9: "mismatch:group-count", 10: "group-threshold", 11: "duplicate-member",
  12: "member-threshold", 13: "digest", 14: "too-few-groups", 15: "too-few-groups", 16: "too-few-members",
  39: "length", 40: "length",
};
for (let n = 2; n <= 16; n++) if (REFUSALS[n]) REFUSALS[n + 19] = REFUSALS[n];

test("the wordlist is the published SLIP-0039 list", () => {
  assert.equal(slip39Wordlist.length, 1024);
  // SHA-256 of the specification's wordlist.txt (spec repository e2824d00, 2026-10-30).
  assert.equal(sha256Hex(`${slip39Wordlist.join("\n")}\n`), "bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3");
  // The specification's criteria: sorted, 4 to 8 letters, unique 4-letter prefixes.
  assert.deepEqual([...slip39Wordlist].sort(), [...slip39Wordlist]);
  assert.ok(slip39Wordlist.every((word) => /^[a-z]{4,8}$/.test(word)));
  assert.equal(new Set(slip39Wordlist.map((word) => word.slice(0, 4))).size, 1024);
});

test("the vectors file is the published one", () => {
  // SHA-256 of vectors.json in python-shamir-mnemonic v0.3.0 (08bbb74b).
  assert.equal(sha256Hex(vectorsText), "13ebecebdd869dd2bc2cdf69e7ce3a158cf106cac76c39d17682b1c6cdabbdc4");
  assert.equal(vectors.length, 45);
});

test("PBKDF2-HMAC-SHA256 matches @noble/hashes", () => {
  const cases = [
    [ascii("passwd"), ascii("salt"), 1, 64],
    [ascii("\x00passphrase"), ascii("shamir\x12\x34abcdefgh"), 2500, 8],
    [ascii("\x03"), new Uint8Array(16), 5000, 16],
    [new Uint8Array(100).fill(0x41), ascii("long password"), 3, 32],
  ];
  for (const [password, salt, iterations, length] of cases) {
    assert.equal(hex(pbkdf2HmacSha256(password, salt, iterations, length)), hex(noblePbkdf2(nobleSha256, password, salt, { c: iterations, dkLen: length })));
  }
});

for (const [index, [description, mnemonics, secret, xprv]] of vectors.entries()) {
  const n = index + 1;
  test(`official vector ${description}`, () => {
    const parsed = parseAll(mnemonics);
    if (secret === "") {
      assert.ok(REFUSALS[n], `vector ${n} has an expected refusal`);
      const result = parsed.ok ? combineSlip39(parsed.shares, VECTOR_PASSPHRASE) : parsed;
      assert.equal(result.ok, false);
      assert.equal(refusalOf(result), REFUSALS[n]);
      for (const field of SECRET_FIELDS) assert.equal(result[field], undefined, field);
      if (parsed.ok) {
        const random = slip39RandomValues(parsed.shares);
        assert.equal(random.ok, false);
        for (const field of SECRET_FIELDS) assert.equal(random[field], undefined, field);
      }
      return;
    }
    assert.equal(parsed.ok, true);
    const result = combineSlip39(parsed.shares, VECTOR_PASSPHRASE);
    assert.equal(result.ok, true, result.reason);
    assert.equal(hex(result.masterSecret), secret);
    // The master secret is the BIP32 seed itself.
    assert.equal(HDKey.fromMasterSeed(result.masterSecret).privateExtendedKey, xprv);
    assert.equal(ScureHDKey.fromMasterSeed(Buffer.from(secret, "hex")).privateExtendedKey, xprv);
  });
}

test("a share is read case-insensitively across any run of whitespace", () => {
  const [, [mnemonic]] = vectors[0];
  const loose = `  ${mnemonic.toUpperCase().split(" ").join(" \n\t ")}\n`;
  assert.equal(hex(parseSlip39Share(loose).share.value), hex(parseSlip39Share(mnemonic).share.value));
});

test("unknown words and empty fields are refused, naming the word's position", () => {
  const [, [mnemonic]] = vectors[0];
  const words = mnemonic.split(" ");
  words[4] = "abandon"; // a BIP39 word, not a SLIP-39 one
  assert.deepEqual(parseSlip39Share(words.join(" ")), { ok: false, reason: "unknown-word", position: 5 });
  assert.deepEqual(parseSlip39Share(" \n "), { ok: false, reason: "empty" });
});

test("RS1024: changing one, two or three words is always caught", () => {
  // The checksum is an MDS code that detects any error in at most 3 words.
  const [, [mnemonic]] = vectors[0];
  const words = mnemonic.split(" ");
  let checked = 0;
  for (let position = 0; position < words.length; position++) {
    for (const step of [1, 2, 511, 1023]) {
      const changed = [...words];
      changed[position] = slip39Wordlist[(slip39Wordlist.indexOf(words[position]) + step) % 1024];
      assert.equal(parseSlip39Share(changed.join(" ")).reason, "checksum", `word ${position + 1} +${step}`);
      checked++;
    }
  }
  for (let trial = 0; trial < 60; trial++) {
    const changed = [...words];
    for (let k = 0; k < 2 + (trial % 2); k++) {
      const position = (trial * 7 + k * 5) % words.length;
      changed[position] = slip39Wordlist[(slip39Wordlist.indexOf(changed[position]) + 1 + trial + k) % 1024];
    }
    assert.equal(parseSlip39Share(changed.join(" ")).reason, "checksum", `trial ${trial}`);
    checked++;
  }
  assert.ok(checked > 100);
});

test("the extendable flag is read from the share", () => {
  // Vectors 42-45 are extendable: their checksums verify only under
  // "shamir_extendable", which the official-vector tests above cover.
  const [, [mnemonic]] = vectors[41];
  assert.equal(parseSlip39Share(mnemonic).share.extendable, true);
  assert.equal(parseSlip39Share(vectors[0][1][0]).share.extendable, false);
});

test("the passphrase must be printable ASCII", () => {
  const parsed = parseAll(vectors[0][1]);
  for (const passphrase of ["café", "tab\there", "line\n", "\u0000"]) {
    const result = combineSlip39(parsed.shares, new TextEncoder().encode(passphrase));
    assert.equal(result.ok, false, JSON.stringify(passphrase));
    assert.equal(result.reason, "passphrase");
    assert.equal(result.masterSecret, undefined);
  }
  for (const passphrase of [" ", "~", "Aa1 !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"]) {
    assert.equal(combineSlip39(parsed.shares, ascii(passphrase)).ok, true, passphrase);
  }
});

test("a set whose iteration exponent is over the caller's limit is refused before decrypting", () => {
  // The official vectors use exponents 0, 2 and 3 (word 2 of each share).
  const byExponent = new Map();
  for (const [, mnemonics, secret] of vectors) {
    if (!secret) continue;
    const parsed = parseAll(mnemonics);
    byExponent.set(parsed.shares[0].iterationExponent, parsed.shares);
  }
  assert.deepEqual([...byExponent.keys()].sort(), [0, 2, 3]);
  const refused = combineSlip39(byExponent.get(3), VECTOR_PASSPHRASE, { maxIterationExponent: 2 });
  assert.deepEqual(refused, { ok: false, reason: "iteration-exponent", exponent: 3, max: 2 });
  assert.equal(combineSlip39(byExponent.get(2), VECTOR_PASSPHRASE, { maxIterationExponent: 2 }).ok, true);
});

test("recovering without a passphrase gives the set's shape and its encrypted secret only", () => {
  // Vector 17: a two-level set (the 5 shares span the group threshold).
  const parsed = parseAll(vectors[16][1]);
  const recovered = recoverSlip39(parsed.shares);
  assert.equal(recovered.ok, true);
  assert.equal(recovered.masterSecret, undefined);
  assert.equal(recovered.length, 16);
  assert.equal(recovered.ems.length, 16);
  assert.equal(recovered.groups.length, recovered.groupThreshold);
  assert.equal(recovered.groups.reduce((sum, group) => sum + group.members.length, 0), 5);
  for (const group of recovered.groups) assert.equal(group.members.length, group.threshold);
});

test("random values: a threshold-1 set has none, a 2-of-N group gives R alone", () => {
  // Vector 1 is 1-of-1; vector 4 is 2-of-3 in one group.
  const single = slip39RandomValues(parseAll(vectors[0][1]).shares);
  assert.equal(single.ok, true);
  assert.equal(single.values.length, 0);
  const pair = slip39RandomValues(parseAll(vectors[3][1]).shares);
  assert.equal(pair.ok, true);
  assert.deepEqual(pair.values.map(({ level, group, x, bytes }) => [level, group, x, bytes.length]), [["member", 0, 254, 12]]);
});

test("random values: a 256-bit set's R is 28 bytes", () => {
  const pair = slip39RandomValues(parseAll(vectors[22][1]).shares);
  assert.deepEqual(pair.values.map(({ x, bytes }) => [x, bytes.length]), [[254, 28]]);
});

// ── The comparison, on hand-built values ──────────────────────────────────

// Distinct, unpatterned bytes for hand-built random values.
const bytesOf = (label, length) => {
  const out = new Uint8Array(length);
  for (let block = 0; block * 32 < length; block++) out.set(createHash("sha256").update(`${label}/${block}`).digest().subarray(0, Math.min(32, length - block * 32)), block * 32);
  return out;
};
const value = (label, x, length, { level = "member", group = 0, bytes } = {}) => ({ level, group, x, bytes: bytes ?? bytesOf(label, length) });
const setOf = (name, values, { identifier = 1000, ems = bytesOf(`${name} ems`, 16) } = {}) => ({ identifier, ems, values });
const kinds = (findings) => findings.map((finding) => finding.kind);

test("two sets of independent values: no finding, and what was compared is counted", () => {
  const a = setOf("a", [value("a r", 254, 12), value("a s0", 0, 16)], { identifier: 1 });
  const b = setOf("b", [value("b r", 254, 12), value("b s0", 0, 16)], { identifier: 2 });
  const outcome = compareSlip39Randomness(a, b);
  assert.deepEqual(outcome.findings, []);
  assert.deepEqual(outcome.checked, { a: { values: 2, bytes: 28 }, b: { values: 2, bytes: 28 } });
});

test("a value repeated in the other set is reported with both places", () => {
  const shared = bytesOf("shared", 12);
  const a = setOf("a", [value("", 254, 12, { bytes: shared }), value("a s0", 0, 16)], { identifier: 1 });
  const b = setOf("b", [value("b s0", 0, 16), value("", 254, 12, { bytes: Uint8Array.from(shared) })], { identifier: 2 });
  const { findings } = compareSlip39Randomness(a, b);
  assert.deepEqual(kinds(findings), ["repeat"]);
  assert.deepEqual([findings[0].a.x, findings[0].b.x, findings[0].length, findings[0].whole], [254, 254, 12, true]);
});

test("a shifted overlap of 8 bytes or more is a repeat; 7 bytes is not", () => {
  const stream = bytesOf("stream", 40);
  const run = (offsetA, offsetB, length) => {
    const a = setOf("a", [value("", 0, 16, { bytes: stream.slice(offsetA, offsetA + 16) })], { identifier: 1 });
    const bBytes = bytesOf("b", 16);
    bBytes.set(stream.subarray(offsetB, offsetB + length), 16 - length);
    const b = setOf("b", [value("", 0, 16, { bytes: bBytes })], { identifier: 2 });
    return compareSlip39Randomness(a, b).findings;
  };
  const hit = run(0, 3, 8);
  assert.deepEqual(kinds(hit), ["repeat"]);
  assert.equal(hit[0].length, 8);
  assert.equal(hit[0].whole, false);
  assert.deepEqual(run(0, 3, 7), []);
});

test("a repeat inside one set is reported for that set", () => {
  const shared = bytesOf("inner", 16);
  const a = setOf("a", [value("", 0, 16, { bytes: shared }), value("", 1, 16, { bytes: Uint8Array.from(shared) }), value("a r", 254, 12)], { identifier: 1 });
  const b = setOf("b", [value("b r", 254, 12)], { identifier: 2 });
  const { findings } = compareSlip39Randomness(a, b);
  assert.deepEqual(kinds(findings), ["repeat-within"]);
  assert.equal(findings[0].set, "a");
  assert.deepEqual([findings[0].a.x, findings[0].b.x], [0, 1]);
});

test("trivial patterns: zero, one repeated byte, a short repeated block, counters", () => {
  const patterned = {
    zero: new Uint8Array(12),
    "repeated-byte": new Uint8Array(16).fill(0xa7),
    "repeated-block": Uint8Array.from({ length: 12 }, (_, i) => [0xde, 0xad, 0xbe][i % 3]),
    "counter up": Uint8Array.from({ length: 12 }, (_, i) => 0x10 + i),
    "counter down": Uint8Array.from({ length: 16 }, (_, i) => (0x03 - i) & 0xff),
    "counter 2-byte": Uint8Array.from({ length: 12 }, (_, i) => (i % 2 ? i >> 1 : 0x7a)),
    "counter 4-byte little-endian": Uint8Array.from({ length: 16 }, (_, i) => (i % 4 === 0 ? 5 + 3 * (i / 4) : 0)),
  };
  for (const [name, bytes] of Object.entries(patterned)) {
    const a = setOf("a", [value("", 254, bytes.length, { bytes })], { identifier: 1 });
    const b = setOf("b", [value("b r", 254, 12)], { identifier: 2 });
    const { findings } = compareSlip39Randomness(a, b);
    assert.deepEqual(kinds(findings), ["pattern"], name);
    assert.equal(findings[0].set, "a");
    assert.equal(findings[0].pattern, name.split(" ")[0], name);
  }
  // Unpatterned values raise none, at every length a share can have.
  for (const length of [12, 14, 16, 18, 28, 32, 60, 64]) {
    const a = setOf("a", [value(`plain ${length}`, 254, length)], { identifier: 1 });
    assert.deepEqual(compareSlip39Randomness(a, setOf("b", [value("b", 0, 16)], { identifier: 2 })).findings, [], String(length));
  }
});

test("the same identifier, the same secret, or both", () => {
  const values = (name) => [value(`${name} r`, 254, 12)];
  const ems = bytesOf("one ems", 16);
  // The same identifier alone: worth noting, 1 in 32,768 by chance.
  assert.deepEqual(kinds(compareSlip39Randomness(setOf("a", values("a"), { identifier: 7 }), setOf("b", values("b"), { identifier: 7 })).findings), ["same-identifier"]);
  // The same encrypted secret: one wallet, not two.
  assert.deepEqual(kinds(compareSlip39Randomness(setOf("a", values("a"), { identifier: 7, ems }), setOf("b", values("b"), { identifier: 8, ems: Uint8Array.from(ems) })).findings), ["same-secret"]);
  // Both: one backup entered twice, or a device that made the same wallet
  // twice. Its repeats say nothing more, so they are not listed.
  const same = compareSlip39Randomness(setOf("a", values("x"), { identifier: 7, ems }), setOf("b", values("x"), { identifier: 7, ems: Uint8Array.from(ems) }));
  assert.deepEqual(kinds(same.findings), ["same-backup"]);
});

test("the randomness test refuses a set that does not combine, naming the set", () => {
  const good = parseAll(vectors[3][1]).shares;
  const badDigest = parseAll(vectors[12][1]).shares;
  const outcome = testSlip39Randomness(good, badDigest);
  assert.equal(outcome.ok, false);
  assert.equal(outcome.set, "b");
  assert.equal(outcome.reason, "digest");
  assert.equal(outcome.findings, undefined);
});

test("one set entered twice is reported as one backup, never refused; a set with no random values is refused", () => {
  // The same share in both sets is not refused: a generator restarted from
  // the same state gives two wallets the same random share, word for word
  // (test/slip39-reference.test.mjs), and refusing it would hide that.
  const pair = parseAll(vectors[3][1]).shares;
  const twice = testSlip39Randomness(pair, parseAll(vectors[3][1]).shares);
  assert.equal(twice.ok, true);
  assert.deepEqual(twice.findings.map((finding) => finding.kind), ["same-backup"]);
  const single = testSlip39Randomness(parseAll(vectors[0][1]).shares, pair);
  assert.equal(single.ok, false);
  assert.equal(single.set, "a");
  assert.equal(single.reason, "no-random-values");
});

test("the randomness test compares two official 2-of-3 sets and finds nothing", () => {
  // Vectors 4 and 23 are different wallets (128 and 256 bits).
  const outcome = testSlip39Randomness(parseAll(vectors[3][1]).shares, parseAll(vectors[22][1]).shares);
  assert.equal(outcome.ok, true);
  assert.deepEqual(outcome.findings, []);
  assert.deepEqual(outcome.checked, { a: { values: 1, bytes: 12 }, b: { values: 1, bytes: 28 } });
});
