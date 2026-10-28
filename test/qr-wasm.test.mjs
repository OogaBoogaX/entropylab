// test/qr-wasm.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { encode } from "uqr";
import { QR_WASM_B64 } from "../src/js/qr-wasm-b64.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

// ── Direct WASM bindings ────────────────────────────────────────────────────

const wasmBytes = (() => {
  const binary = atob(QR_WASM_B64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
})();
const wasm = new WebAssembly.Instance(new WebAssembly.Module(wasmBytes), {}).exports;
const heap = () => new Uint8Array(wasm.memory.buffer);

const QR_NOT_FOUND = -1;
const QR_MULTIPLE_CODES = -3;
const QR_OUT_TOO_SMALL = -5;
const QR_BAD_ARGS = -6;

const MODULE_PX = 4;
const BORDER = 4;

// Renders `data` (a string or a number[] of bytes) to an 8-bit luminance
// frame: dark 0, light 255, MODULE_PX pixels per module, BORDER light modules
// around. uqr is independent of the Rust `qrcode` crate the module was built
// against.
function render(data) {
  const { size, data: modules } = encode(data, { border: 0 });
  const side = (size + BORDER * 2) * MODULE_PX;
  const pixels = new Uint8Array(side * side).fill(255);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      if (!modules[y][x]) continue;
      for (let dy = 0; dy < MODULE_PX; dy++) {
        for (let dx = 0; dx < MODULE_PX; dx++) {
          const px = (BORDER + x) * MODULE_PX + dx;
          const py = (BORDER + y) * MODULE_PX + dy;
          pixels[py * side + px] = 0;
        }
      }
    }
  }
  return { pixels, width: side, height: side };
}

function blit(canvas, canvasWidth, frame, x0, y0) {
  for (let y = 0; y < frame.height; y++) {
    const dst = (y0 + y) * canvasWidth + x0;
    canvas.set(frame.pixels.subarray(y * frame.width, (y + 1) * frame.width), dst);
  }
}

// Copies `frame` into WASM memory, decodes it, and returns { code, out }.
// `heap()` is re-read after every call: memory can grow and detach views.
function decode(frame, outCap = 4096) {
  const { pixels, width, height } = frame;
  const grayPtr = wasm.qr_alloc(pixels.length);
  const outPtr = wasm.qr_alloc(outCap);
  try {
    heap().set(pixels, grayPtr);
    const code = wasm.qr_decode(grayPtr, width, height, outPtr, outCap);
    const out = heap().slice(outPtr, outPtr + outCap);
    return { code, out };
  } finally {
    wasm.qr_free(grayPtr, pixels.length);
    wasm.qr_free(outPtr, outCap);
  }
}

const COMPACT_SEEDQR = [0xf5, 0x5c, 0xf5, 0x87, 0xf2, 0x54, 0x3d, 0x01, 0x09, 0x0d, 0x0a, 0xe7, 0x10, 0xbd, 0x3b, 0x6d];

test("qr_version reports the ABI version", () => {
  assert.equal(wasm.qr_version(), 1);
});

test("decodes exact bytes: a 16-byte CompactSeedQR", () => {
  const { code, out } = decode(render(COMPACT_SEEDQR));
  assert.equal(code, COMPACT_SEEDQR.length);
  assert.deepEqual([...out.slice(0, COMPACT_SEEDQR.length)], COMPACT_SEEDQR);
});

test("decodes exact bytes: 32 bytes including 0x00, 0x0d and 0x0a", () => {
  const payload = [
    0x00, 0x0d, 0x0a, 0x11, 0x22, 0x33, 0x44, 0x55,
    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
    0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0b, 0x0c, 0x0e, 0x0f, 0x10,
  ];
  const { code, out } = decode(render(payload));
  assert.equal(code, payload.length);
  assert.deepEqual([...out.slice(0, payload.length)], payload);
});

test("decodes a Standard SeedQR numeric payload as ASCII digits", () => {
  const digits = "073318950739065415961602009907670428187212261116";
  const { code, out } = decode(render(digits));
  assert.equal(code, digits.length);
  assert.equal(Buffer.from(out.slice(0, digits.length)).toString("latin1"), digits);
});

test("a blank frame is not found", () => {
  const pixels = new Uint8Array(200 * 200).fill(255);
  const { code } = decode({ pixels, width: 200, height: 200 });
  assert.equal(code, QR_NOT_FOUND);
});

test("two different codes side by side are refused", () => {
  const a = render(COMPACT_SEEDQR);
  const b = render([
    0x0e, 0x59, 0xdd, 0xe2, 0x76, 0x00, 0x93, 0x17,
    0xf1, 0x27, 0x5f, 0x13, 0x89, 0x88, 0x80, 0x78,
    0xc9, 0x93, 0x68, 0xd1, 0xe8, 0x24, 0x89, 0xb5,
    0xf6, 0x29, 0x53, 0x1f, 0xc5, 0xb6, 0xa5, 0x6e,
  ]);
  const width = a.width + b.width;
  const height = Math.max(a.height, b.height);
  const pixels = new Uint8Array(width * height).fill(255);
  blit(pixels, width, a, 0, 0);
  blit(pixels, width, b, a.width, 0);
  const { code } = decode({ pixels, width, height });
  assert.equal(code, QR_MULTIPLE_CODES);
});

test("a too-small out buffer is refused and left untouched", () => {
  const frame = render(COMPACT_SEEDQR);
  const grayPtr = wasm.qr_alloc(frame.pixels.length);
  const outPtr = wasm.qr_alloc(3);
  try {
    heap().set(frame.pixels, grayPtr);
    heap().fill(0x55, outPtr, outPtr + 3);
    const code = wasm.qr_decode(grayPtr, frame.width, frame.height, outPtr, 3);
    assert.equal(code, QR_OUT_TOO_SMALL);
    assert.deepEqual([...heap().slice(outPtr, outPtr + 3)], [0x55, 0x55, 0x55]);
  } finally {
    wasm.qr_free(grayPtr, frame.pixels.length);
    wasm.qr_free(outPtr, 3);
  }
});

test("a frame narrower than 21 modules is bad args", () => {
  const pixels = new Uint8Array(20 * 20).fill(255);
  const { code } = decode({ pixels, width: 20, height: 20 });
  assert.equal(code, QR_BAD_ARGS);
});

test("committed QR WASM artifact is intact (sha256 in module header matches payload)", () => {
  const source = readFileSync(join(root, "src/js/qr-wasm-b64.js"), "utf8");
  const declared = source.match(/wasm sha256: ([0-9a-f]{64})/);
  assert.ok(declared, "module header carries the wasm sha256");
  const actual = createHash("sha256").update(Buffer.from(QR_WASM_B64, "base64")).digest("hex");
  assert.equal(actual, declared[1]);
});
