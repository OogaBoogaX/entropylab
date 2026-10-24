// Shared harness for the LifeHash differential fuzzers (fuzz.mjs against the
// `lifehash` package, fuzz-cpp.mjs against the C++ reference): the shipped
// module, its PNG decoded back to RGB, and the deterministic input stream.
import { readFileSync } from "node:fs";
import { createHash, webcrypto } from "node:crypto";
import { inflateSync } from "node:zlib";

export const ITERATIONS = Number.parseInt(process.env.FUZZ_ITERATIONS ?? "1000", 10);
export const SEED = BigInt(process.env.FUZZ_SEED ?? "0x9e3779b97f4a7c15");
export const MODULE_SIZES = [1, 2, 3]; // the app renders at 3; 1 and 2 cover the raw grid and scaling

// --- EntropyLab side: evaluate the shipped module with its browser globals,
// the same shim test/lifehash.test.mjs uses, so the fuzzers exercise the
// exact code the app ships.
const src = readFileSync(new URL("../../src/js/lifehash.js", import.meta.url), "utf8");
const btoa = (s) => Buffer.from(s, "binary").toString("base64");
export const ours = new Function("crypto", "btoa", "TextEncoder", `${src}; return hodlLifeHash;`)(webcrypto, btoa, TextEncoder);

// --- PNG -> raw RGB. Our encoder writes one filter-0 scanline per row; a
// non-zero filter byte means the encoder changed and this harness is stale.
export const decodePngRgb = (dataUrl) => {
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
export const nextFingerprint = () => [...Array(4)].map(() => nextByte().toString(16).padStart(2, "0")).join("");

export const sha256Hex = (bytes) => createHash("sha256").update(Buffer.from(bytes)).digest("hex");

// Case-insensitive hex decode, mirroring Sparrow's Utils.hexToBytes.
export const hexToBytes = (hex) => Uint8Array.from(Buffer.from(hex.toLowerCase(), "hex"));

// First differing byte between our decoded PNG and a reference RGB buffer, as
// a message, or null when they are identical (dimensions included).
export const firstDifference = (oursPng, width, height, rgb) => {
  if (oursPng.width !== width || oursPng.height !== height) {
    return `dimensions ${oursPng.width}x${oursPng.height} vs ${width}x${height}`;
  }
  if (rgb.length !== oursPng.rgb.length) return `RGB length ${oursPng.rgb.length} vs ${rgb.length}`;
  for (let i = 0; i < rgb.length; i += 1) {
    if (oursPng.rgb[i] !== rgb[i]) {
      const pixel = Math.floor(i / 3), channel = "rgb"[i % 3];
      return `pixel (${pixel % width}, ${Math.floor(pixel / width)}) channel ${channel}: ours ${oursPng.rgb[i]} vs theirs ${rgb[i]}`;
    }
  }
  return null;
};
