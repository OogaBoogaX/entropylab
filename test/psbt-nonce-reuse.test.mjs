// Issue #51: nonce-reuse detector must compare secp256k1 point identity and
// recoverable non-strict DER r values. Run with: npm run test:nonce
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const app = readFileSync(join(root, "..", "src/js/app.js"), "utf8");

function loadSlice(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let depth = 0;
  let end = -1;
  for (let i = app.indexOf("{", start); i < app.length; i++) {
    if (app[i] === "{") depth++;
    else if (app[i] === "}") {
      depth--;
      if (depth === 0) {
        end = i + 1;
        break;
      }
    }
  }
  assert.ok(end > start, name);
  return app.slice(start, end);
}

const hodlEq = new Function(`${loadSlice("hodlEq")}; return hodlEq;`)();
const hodlCompressedPubkey = new Function(
  "hodlPointFrom",
  "hodlPointBytes",
  `${loadSlice("hodlCompressedPubkey")}; return hodlCompressedPubkey;`,
)(
  () => {
    throw new Error("no curve");
  },
  () => {
    throw new Error("no curve");
  },
);
const hodlDerRLoose = new Function(`${loadSlice("hodlDerRLoose")}; return hodlDerRLoose;`)();
const { hex: hodlHex } = await import("../src/js/coders.js");
const hodlCompareNonces = new Function(
  "hodlEq",
  "hodlHex",
  `${loadSlice("hodlCompareNonces")}; return hodlCompareNonces;`,
)(hodlEq, hodlHex);

const GX = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const GY = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
const G_COMPRESSED = Uint8Array.from(Buffer.from("02" + GX, "hex"));
const G_UNCOMPRESSED = Uint8Array.from(Buffer.from("04" + GX + GY, "hex"));
const OTHER = Uint8Array.from(Buffer.from("03" + GX, "hex"));

function rOf(hex32) {
  return Uint8Array.from(Buffer.from(hex32.padStart(64, "0"), "hex"));
}

function derFromR(rBytes, padded = false) {
  const r = padded ? Uint8Array.of(0, ...rBytes) : rBytes;
  const s = new Uint8Array(32);
  s[31] = 1;
  const body = Uint8Array.of(0x02, r.length, ...r, 0x02, s.length, ...s);
  return Uint8Array.of(0x30, body.length, ...body);
}

test("compressed and uncompressed encodings of G compare as the same key", () => {
  const compressed = hodlCompressedPubkey(G_COMPRESSED);
  const uncompressed = hodlCompressedPubkey(G_UNCOMPRESSED);
  assert.equal(compressed.length, 33);
  assert.equal(uncompressed.length, 33);
  assert.ok(hodlEq(compressed, uncompressed));
  assert.equal(Buffer.from(compressed).toString("hex"), "02" + GX);
});

test("a different point with the same x is not treated as the same key", () => {
  assert.equal(hodlEq(hodlCompressedPubkey(G_COMPRESSED), hodlCompressedPubkey(OTHER)), false);
});

test("same key compressed vs uncompressed with the same r is reused nonce", () => {
  const r = rOf("11".repeat(32));
  const z1 = rOf("01".repeat(32));
  const z2 = rOf("02".repeat(32));
  const scan = hodlCompareNonces([
    { input: 0, r, pubkey: hodlCompressedPubkey(G_COMPRESSED), sighash: z1, valid: true },
    { input: 1, r, pubkey: hodlCompressedPubkey(G_UNCOMPRESSED), sighash: z2, valid: true },
  ]);
  assert.equal(scan.reused.length, 1);
  assert.equal(scan.possible.length, 0);
});

test("different claimed keys with the same r are cross-flagged, never silently skipped (issue #353)", () => {
  // The partial-sig keydata pubkey is attacker-controlled: a counterparty
  // hiding genuine nonce reuse mislabels one signature under another key,
  // and same-key grouping would never see the pair. The pair must surface.
  const r = rOf("11".repeat(32));
  const z1 = rOf("01".repeat(32));
  const z2 = rOf("02".repeat(32));
  const scan = hodlCompareNonces([
    { input: 0, r, pubkey: hodlCompressedPubkey(G_COMPRESSED), sighash: z1, valid: true },
    { input: 1, r, pubkey: hodlCompressedPubkey(OTHER), sighash: z2, valid: true },
  ]);
  assert.equal(scan.reused.length, 0);
  assert.equal(scan.possible.length, 0);
  assert.equal(scan.crossKey.length, 1, "same r under different claimed keys must be flagged");
  // The same flag fires when neither digest could be verified.
  const unverified = hodlCompareNonces([
    { input: 0, r, pubkey: hodlCompressedPubkey(G_COMPRESSED), sighash: null, valid: null },
    { input: 1, r, pubkey: hodlCompressedPubkey(OTHER), sighash: null, valid: null },
  ]);
  assert.equal(unverified.crossKey.length, 1);
});

test("non-minimal DER still yields the same r as the minimal encoding", () => {
  const r = rOf("11".repeat(32));
  const minimal = derFromR(r, false);
  const padded = derFromR(r, true);
  assert.ok(hodlEq(hodlDerRLoose(minimal), r));
  assert.ok(hodlEq(hodlDerRLoose(padded), r));
});

test("garbage signatures do not yield an r value", () => {
  assert.equal(hodlDerRLoose(Uint8Array.from([0xde, 0xad, 0xbe, 0xef])), null);
  assert.equal(hodlDerRLoose(new Uint8Array(0)), null);
});

test("same r without reconstructed digests is possible reuse, not a clean miss", () => {
  const r = rOf("aa".repeat(32));
  const scan = hodlCompareNonces([
    { input: 0, r, pubkey: hodlCompressedPubkey(G_COMPRESSED), sighash: null, valid: null },
    { input: 1, r, pubkey: hodlCompressedPubkey(G_UNCOMPRESSED), sighash: null, valid: null },
  ]);
  assert.equal(scan.reused.length, 0);
  assert.equal(scan.possible.length, 1);
});

test("same r on one input with an unreconstructed digest is possible reuse (audit C3-2)", () => {
  // Two signatures by one key on one input under different sighash types
  // (say ALL and SINGLE) commit to different digests: the same r leaks the
  // private key. Digest reconstruction covers SIGHASH_ALL only, so this pair
  // cannot be proven — but it must land in "possible", not drop silently to a
  // green verdict.
  const r = rOf("bb".repeat(32));
  const scan = hodlCompareNonces([
    { input: 0, r, pubkey: hodlCompressedPubkey(G_COMPRESSED), sighash: rOf("01".repeat(32)), valid: true },
    { input: 0, r, pubkey: hodlCompressedPubkey(G_COMPRESSED), sighash: null, valid: null },
  ]);
  assert.equal(scan.reused.length, 0);
  assert.equal(scan.possible.length, 1);
  // A same-input pair whose digests are both known and equal is one
  // signature copied, not reuse: it stays quiet.
  const duplicate = hodlCompareNonces([
    { input: 0, r, pubkey: hodlCompressedPubkey(G_COMPRESSED), sighash: rOf("01".repeat(32)), valid: true },
    { input: 0, r, pubkey: hodlCompressedPubkey(G_COMPRESSED), sighash: rOf("01".repeat(32)), valid: true },
  ]);
  assert.equal(duplicate.reused.length, 0);
  assert.equal(duplicate.possible.length, 0);
});

test("existing same-encoding strict detection still reports reused r", () => {
  const r = rOf("22".repeat(32));
  const scan = hodlCompareNonces([
    { input: 0, r, pubkey: G_COMPRESSED, sighash: rOf("01".repeat(32)), valid: true },
    { input: 1, r, pubkey: G_COMPRESSED, sighash: rOf("03".repeat(32)), valid: true },
  ]);
  assert.equal(scan.reused.length, 1);
});

test("grouped nonce comparison returns the same buckets as the all-pairs scan (audit C3-3)", () => {
  // The performance rewrite groups by r before comparing; the buckets must be
  // pair-for-pair identical to the all-pairs scan it replaces (the previous
  // implementation, kept here as the reference).
  const reference = (records) => {
    const reused = [], possible = [], crossKey = [];
    for (let first = 0; first < records.length; first++)
      for (let second = first + 1; second < records.length; second++) {
        const a = records[first], b = records[second];
        if (!hodlEq(a.r, b.r)) continue;
        if (!hodlEq(a.pubkey, b.pubkey)) {
          crossKey.push([a, b]);
          continue;
        }
        if (a.valid && b.valid && a.sighash && b.sighash && !hodlEq(a.sighash, b.sighash)) reused.push([a, b]);
        else if (a.input !== b.input || !a.sighash || !b.sighash) possible.push([a, b]);
      }
    return { reused, possible, crossKey };
  };
  const pairSet = (records, pairs) =>
    new Set(pairs.map(([a, b]) => `${records.indexOf(a)}:${records.indexOf(b)}`));
  let state = 42;
  const next = () => (state = (state * 1103515245 + 12345) & 0x7fffffff);
  for (let round = 0; round < 300; round++) {
    const records = [];
    for (let i = 0, count = next() % 40; i < count; i++) {
      records.push({
        input: next() % 6,
        r: rOf(String(next() % 4).repeat(2)),
        pubkey: [G_COMPRESSED, G_UNCOMPRESSED, OTHER][next() % 3],
        sighash: next() % 3 ? rOf(String(next() % 3).repeat(2)) : null,
        valid: [true, false, null][next() % 3],
      });
    }
    const expected = reference(records);
    const actual = hodlCompareNonces(records);
    for (const bucket of ["reused", "possible", "crossKey"]) {
      assert.deepEqual(pairSet(records, actual[bucket]), pairSet(records, expected[bucket]), `${bucket} diverged in round ${round}`);
    }
  }
});

test("nonce comparison refuses collision floods before constructing unbounded pair lists", () => {
  // Contract: preserve exact comparisons within the budget and reject larger
  // collision sets, rather than allocating n*(n-1)/2 pairs or returning clean.
  const records = (count, r = rOf("11".repeat(32))) => Array.from({ length: count }, (_, input) => ({
    input, r, pubkey: G_COMPRESSED, sighash: null, valid: null,
  }));
  const accepted = hodlCompareNonces(records(256));
  assert.equal(accepted.possible.length, 256 * 255 / 2);
  // 32640 + 120 + 6 + 1 + 1 reaches the exact whole-file boundary.
  const atLimit = [256, 16, 4, 2, 2].flatMap((count, i) => records(count, rOf((i + 1).toString(16))));
  assert.equal(hodlCompareNonces(atLimit).possible.length, 32768);
  assert.throws(() => hodlCompareNonces([...atLimit, ...records(2, rOf("06"))]), /nonce comparison limit/i);
  assert.throws(() => hodlCompareNonces(records(257)), /nonce comparison limit/i);
  // The limit covers the whole file, not each individually small group.
  assert.throws(() => hodlCompareNonces([
    ...records(200), ...records(200, rOf("22".repeat(32))),
  ]), /nonce comparison limit/i);
  // Many unique nonces require no pair comparisons and remain supported.
  const distinct = records(10000).map((record, i) => ({ ...record, r: rOf((i + 1).toString(16)) }));
  assert.deepEqual(hodlCompareNonces(distinct), { reused: [], possible: [], crossKey: [] });
});

test("render suppresses a clean verdict when a signature cannot be inspected", () => {
  const render = loadSlice("hodlRenderPsbt");
  assert.match(render, /uninspected\s*\+=\s*1/);
  assert.match(
    render,
    /else if\s*\(uninspected\)\s*nonceHtml\.push\("<p class='psbt-warn'><strong>"\s*\+\s*hodlT\("Incomplete nonce coverage\."\)/,
  );
  assert.match(render, /hodlCompressedPubkey\(signature\.pubkey\)/);
  assert.match(render, /hodlDerRLoose\(signature\.der\)/);
  assert.match(render, /hodlCompareNonces\(rValues\)/);
  assert.match(app, /RFC 6979 comparison currently covers/);
});
