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
const hodlCompareNonces = new Function(
  "hodlEq",
  `${loadSlice("hodlCompareNonces")}; return hodlCompareNonces;`,
)(hodlEq);

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

test("different keys with the same r are not same-key reuse", () => {
  const r = rOf("11".repeat(32));
  const z1 = rOf("01".repeat(32));
  const z2 = rOf("02".repeat(32));
  const scan = hodlCompareNonces([
    { input: 0, r, pubkey: hodlCompressedPubkey(G_COMPRESSED), sighash: z1, valid: true },
    { input: 1, r, pubkey: hodlCompressedPubkey(OTHER), sighash: z2, valid: true },
  ]);
  assert.equal(scan.reused.length, 0);
  assert.equal(scan.possible.length, 0);
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

test("existing same-encoding strict detection still reports reused r", () => {
  const r = rOf("22".repeat(32));
  const scan = hodlCompareNonces([
    { input: 0, r, pubkey: G_COMPRESSED, sighash: rOf("01".repeat(32)), valid: true },
    { input: 1, r, pubkey: G_COMPRESSED, sighash: rOf("03".repeat(32)), valid: true },
  ]);
  assert.equal(scan.reused.length, 1);
});

test("render suppresses a clean verdict when a signature cannot be inspected", () => {
  const render = loadSlice("hodlRenderPsbt");
  assert.match(render, /uninspected\s*\+=\s*1/);
  assert.match(
    render,
    /else if\s*\(uninspected\)\s*html\.push\("<p class='psbt-warn'><strong>Incomplete nonce coverage\.<\/strong>/,
  );
  assert.match(render, /hodlCompressedPubkey\(signature\.pubkey\)/);
  assert.match(render, /hodlDerRLoose\(signature\.der\)/);
  assert.match(render, /hodlCompareNonces\(rValues\)/);
  assert.match(app, /A clean verdict is not issued when a signature cannot be inspected/);
});
