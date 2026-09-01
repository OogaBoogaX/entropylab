// LifeHash differential fuzzer: EntropyLab's src/js/lifehash.js vs the
// official `lifehash` package (AndreasGassmann/lifehash, pinned in
// fuzzing/package.json).
//
// Every input goes through both full public pipelines and the rendered pixels
// must be byte-identical:
//   ours:    fromFingerprint(fp, moduleSize) -> PNG data URL -> decoded RGB
//   theirs:  LifeHash.makeFrom(hexToBytes(fp), version2, moduleSize, false).colors
// Both hash the RAW fingerprint bytes (Sparrow/toucan's convention), so the
// fuzzer also guards that the app stays Sparrow-compatible. Comparing the
// app's final PNG (rather than internals) also covers the hand-rolled PNG
// encoder and the module-size scaling.
//
// Deterministic: inputs come from a seeded xorshift64 PRNG, so a CI failure
// reproduces locally with the same FUZZ_SEED (and FUZZ_ITERATIONS). The app
// never sees this randomness — the harness only feeds it test inputs, which
// is policy-safe (deterministic transformations, no key material).
//
// Run: npm --prefix fuzzing run fuzz:lifehash
//      FUZZ_ITERATIONS=5000 FUZZ_SEED=0x1234 node fuzzing/lifehash/fuzz.mjs
import { readFileSync } from "node:fs";
import { createHash, webcrypto } from "node:crypto";
import { inflateSync } from "node:zlib";
import { LifeHash, LifeHashVersion } from "lifehash";

const ITERATIONS = Number.parseInt(process.env.FUZZ_ITERATIONS ?? "1000", 10);
const SEED = BigInt(process.env.FUZZ_SEED ?? "0x9e3779b97f4a7c15");
const MODULE_SIZES = [1, 2, 3]; // the app renders at 3; 1 and 2 cover the raw grid and scaling

// --- EntropyLab side: evaluate the shipped module with its browser globals,
// the same shim test/lifehash.test.mjs uses, so the fuzzer exercises the
// exact code the app ships.
const src = readFileSync(new URL("../../src/js/lifehash.js", import.meta.url), "utf8");
const btoa = (s) => Buffer.from(s, "binary").toString("base64");
const ours = new Function("crypto", "btoa", "TextEncoder", `${src}; return hodlLifeHash;`)(webcrypto, btoa, TextEncoder);

// --- PNG -> raw RGB. Our encoder writes one filter-0 scanline per row; a
// non-zero filter byte means the encoder changed and this harness is stale.
const decodePngRgb = (dataUrl) => {
  const png = Buffer.from(dataUrl.split(",")[1], "base64");
  const sig = [137, 80, 78, 71, 13, 10, 26, 10];
  if (!png.subarray(0, 8).equals(Buffer.from(sig))) throw new Error("bad PNG signature");
  let width = 0, height = 0;
  const idat = [];
  for (let at = 8; at < png.length;) {
    const length = png.readUInt32BE(at);
    const type = png.subarray(at + 4, at + 8).toString("ascii");
    const data = png.subarray(at + 8, at + 8 + length);
    if (type === "IHDR") {
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      if (data[8] !== 8 || data[9] !== 2) throw new Error("expected 8-bit truecolour PNG");
    }
    if (type === "IDAT") idat.push(data);
    at += 8 + length + 4; // skip CRC
  }
  const raw = inflateSync(Buffer.concat(idat));
  const stride = width * 3;
  if (raw.length !== (stride + 1) * height) throw new Error("unexpected inflated size");
  const rgb = new Uint8Array(stride * height);
  for (let y = 0; y < height; y += 1) {
    if (raw[y * (stride + 1)] !== 0) throw new Error(`unsupported PNG filter ${raw[y * (stride + 1)]}`);
    rgb.set(raw.subarray(y * (stride + 1) + 1, (y + 1) * (stride + 1)), y * stride);
  }
  return { width, height, rgb };
};

// --- Deterministic PRNG (xorshift64*).
let prngState = SEED & 0xffffffffffffffffn;
if (prngState === 0n) throw new Error("FUZZ_SEED must be non-zero");
const nextByte = () => {
  prngState ^= prngState << 13n; prngState &= 0xffffffffffffffffn;
  prngState ^= prngState >> 7n;
  prngState ^= prngState << 17n; prngState &= 0xffffffffffffffffn;
  return Number((prngState >> 56n) & 0xffn);
};
// The app only ever hashes 8-hex-digit master fingerprints, so that is the
// fuzz domain.
const nextFingerprint = () => [...Array(4)].map(() => nextByte().toString(16).padStart(2, "0")).join("");

const sha256Hex = (bytes) => createHash("sha256").update(Buffer.from(bytes)).digest("hex");

// Non-vacuity guard: the same vectors test/lifehash.test.mjs pins, generated
// from the canonical implementation over the raw fingerprint bytes (Sparrow's
// convention). Both sides must reproduce them before any fuzzing happens — a
// fuzzer whose comparisons silently no-op must fail here, loudly.
const VECTORS = [
  { input: "73c5da0a", rgb: "09da10ffd57a4f58616a5eda313d3f0c861e79b93e1b609a012f9c3530b427b5" },
  { input: "00000000", rgb: "9003d9fd366ec3aa06f54d6797485114ec00c61bf85c0efafa91bd2e40176d5b" },
  { input: "ffffffff", rgb: "e856f1b33dfd8eef83151de7407c3d4861581ce09f11f11f2dfc6b0219a1e51b" },
  { input: "b8688df1", rgb: "d44ba038c1389003c955a6f17accfb87c98fce4e8c98c9e2a44c71067b6521fe" },
];
// Edge inputs beyond the PRNG stream: boundary nibbles, repeated bytes, and
// uppercase variants (hex decoding is case-insensitive on both sides, so
// ours(UPPER) is compared against theirs(lower)).
const FIXED = [
  "00000000", "ffffffff", "01234567", "89abcdef", "deadbeef", "aaaaaaaa", "55555555", "0f0f0f0f", "f0f0f0f0",
  ...VECTORS.map((v) => v.input.toUpperCase()),
];

// Case-insensitive hex decode, mirroring Sparrow's Utils.hexToBytes.
const hexToBytes = (hex) => Uint8Array.from(Buffer.from(hex.toLowerCase(), "hex"));

let comparisons = 0;
const fail = (fingerprint, moduleSize, message) => {
  process.stderr.write(
    `LifeHash mismatch: fingerprint=${fingerprint} moduleSize=${moduleSize} ` +
    `seed=0x${SEED.toString(16)} iterations=${ITERATIONS}\n  ${message}\n`,
  );
  process.exit(1);
};

const compare = async (fingerprint, moduleSize, theirsFp = fingerprint) => {
  const oursPng = decodePngRgb(await ours.fromFingerprint(fingerprint, moduleSize));
  const theirs = LifeHash.makeFrom(hexToBytes(theirsFp), LifeHashVersion.version2, moduleSize, false);
  if (oursPng.width !== theirs.width || oursPng.height !== theirs.height) {
    fail(fingerprint, moduleSize, `dimensions ${oursPng.width}x${oursPng.height} vs ${theirs.width}x${theirs.height}`);
  }
  const rgb = Uint8Array.from(theirs.colors);
  for (let i = 0; i < rgb.length; i += 1) {
    if (oursPng.rgb[i] !== rgb[i]) {
      const pixel = Math.floor(i / 3), channel = "rgb"[i % 3];
      fail(
        fingerprint,
        moduleSize,
        `pixel (${pixel % oursPng.width}, ${Math.floor(pixel / oursPng.width)}) channel ${channel}: ` +
        `ours ${oursPng.rgb[i]} vs theirs ${rgb[i]}`,
      );
    }
  }
  comparisons += 1;
  return oursPng;
};

// 1. Pinned-vector guard on both sides (module size 1, raw 32x32 RGB).
for (const { input, rgb } of VECTORS) {
  const oursPng = await compare(input, 1);
  if (sha256Hex(oursPng.rgb) !== rgb) fail(input, 1, "EntropyLab no longer reproduces the pinned canonical vector");
  const theirs = LifeHash.makeFrom(hexToBytes(input), LifeHashVersion.version2, 1, false);
  if (sha256Hex(theirs.colors) !== rgb) fail(input, 1, "the pinned `lifehash` package no longer reproduces the canonical vector");
}

// 2. Fixed edge inputs, at every module size; uppercase variants compare
// against the lowercased reference input.
for (const fingerprint of FIXED) {
  const lower = fingerprint.toLowerCase();
  for (const moduleSize of MODULE_SIZES) await compare(fingerprint, moduleSize, lower);
}

// 3. The PRNG stream.
for (let i = 0; i < ITERATIONS; i += 1) {
  const fingerprint = nextFingerprint();
  for (const moduleSize of MODULE_SIZES) await compare(fingerprint, moduleSize);
}

process.stdout.write(
  `LifeHash fuzz OK: ${comparisons} comparisons ` +
  `(${FIXED.length} fixed + ${ITERATIONS} PRNG inputs x ${MODULE_SIZES.length} module sizes, ` +
  `seed=0x${SEED.toString(16)}), 0 mismatches\n`,
);
