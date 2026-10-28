// test/qr-worker.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Worker } from "node:worker_threads";
import { encode } from "uqr";
import { QR_WASM_B64 } from "../src/js/qr-wasm-b64.js";
import { buildQrWorkerSource } from "../scripts/qr-worker-source.mjs";
import { createQrDecoder } from "../src/js/qr-scan.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

const wasmBytes = (() => {
  const binary = atob(QR_WASM_B64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
})();

const MODULE_PX = 4;
const BORDER = 4;

// Renders `data` (a string or a number[] of bytes) to an 8-bit luminance
// frame, exactly as test/qr-wasm.test.mjs does. uqr is independent of the
// Rust `qrcode` crate the module was built against.
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

const COMPACT_SEEDQR = [0xf5, 0x5c, 0xf5, 0x87, 0xf2, 0x54, 0x3d, 0x01, 0x09, 0x0d, 0x0a, 0xe7, 0x10, 0xbd, 0x3b, 0x6d];

const workerSource = await buildQrWorkerSource();

// The shipped worker string runs under node:worker_threads behind a minimal
// `self` shim, as test/lightning-worker.test.mjs does. With `echo`, the shim
// sets the worker's test flag so it posts each zeroed frame back.
const shim = (echo) => `
  const { parentPort } = require("node:worker_threads");
  globalThis.self = {
    onmessage: null,
    __entropyLabQrEcho: ${echo},
    postMessage(message, transfer) { parentPort.postMessage(message, transfer); },
  };
  parentPort.on("message", (data) => { if (self.onmessage) self.onmessage({ data }); });
`;

const once = (worker) => new Promise((resolve) => worker.once("message", resolve));

const startWorker = async ({ echo = false, wasm = wasmBytes } = {}) => {
  const worker = new Worker(shim(echo) + workerSource, { eval: true });
  const ready = once(worker);
  const bytes = wasm.slice();
  worker.postMessage({ type: "init", wasm: bytes.buffer }, [bytes.buffer]);
  assert.deepEqual(await ready, { type: "ready" });
  return worker;
};

const decodeFrame = (worker, frame, echo = false) => {
  const gray = frame.pixels.slice();
  const messages = [];
  return new Promise((resolve) => {
    const onMessage = (message) => {
      messages.push(message);
      if ((message.type === "decoded" || message.type === "error") && (!echo || messages.some((m) => m.type === "gray"))) {
        worker.off("message", onMessage);
        resolve(messages);
      }
    };
    worker.on("message", onMessage);
    worker.postMessage(
      { type: "decode", run: 1, width: frame.width, height: frame.height, gray: gray.buffer },
      [gray.buffer],
    );
  });
};

// A module with the decoder's exports whose qr_alloc traps, as the Rust
// module does when an allocation fails (it aborts on out-of-memory).
const TRAPPING_WASM = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
  // types: (i32) -> i32, (i32, i32) -> (), (i32 x5) -> i32
  0x01, 0x14, 0x03, 0x60, 0x01, 0x7f, 0x01, 0x7f, 0x60, 0x02, 0x7f, 0x7f, 0x00,
  0x60, 0x05, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7f,
  // three functions, one page of memory
  0x03, 0x04, 0x03, 0x00, 0x01, 0x02,
  0x05, 0x03, 0x01, 0x00, 0x01,
  // exports: memory, qr_alloc, qr_free, qr_decode
  0x07, 0x2b, 0x04,
  0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00,
  0x08, 0x71, 0x72, 0x5f, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x00, 0x00,
  0x07, 0x71, 0x72, 0x5f, 0x66, 0x72, 0x65, 0x65, 0x00, 0x01,
  0x09, 0x71, 0x72, 0x5f, 0x64, 0x65, 0x63, 0x6f, 0x64, 0x65, 0x00, 0x02,
  // code: qr_alloc is `unreachable`, qr_free does nothing, qr_decode returns 0
  0x0a, 0x0d, 0x03, 0x03, 0x00, 0x00, 0x0b, 0x02, 0x00, 0x0b, 0x04, 0x00, 0x41, 0x00, 0x0b,
]);

test("the worker decodes a 16-byte CompactSeedQR exactly", async () => {
  const worker = await startWorker();
  try {
    const [decoded] = await decodeFrame(worker, render(COMPACT_SEEDQR));
    assert.equal(decoded.code, COMPACT_SEEDQR.length);
    assert.deepEqual([...new Uint8Array(decoded.payload)], COMPACT_SEEDQR);
  } finally {
    worker.terminate();
  }
});

test("the worker refuses two different codes side by side", async () => {
  const worker = await startWorker();
  try {
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
    const [decoded] = await decodeFrame(worker, { pixels, width, height });
    assert.equal(decoded.code, -3);
    assert.equal(decoded.payload, null);
  } finally {
    worker.terminate();
  }
});

test("the worker reports a blank frame as not found", async () => {
  const worker = await startWorker();
  try {
    const pixels = new Uint8Array(200 * 200).fill(255);
    const [decoded] = await decodeFrame(worker, { pixels, width: 200, height: 200 });
    assert.equal(decoded.code, -1);
    assert.equal(decoded.payload, null);
  } finally {
    worker.terminate();
  }
});

test("the worker zeroes the received frame after a decode", async () => {
  const worker = await startWorker({ echo: true });
  try {
    const messages = await decodeFrame(worker, render(COMPACT_SEEDQR), true);
    const gray = messages.find((m) => m.type === "gray");
    assert.ok(gray, "the worker posts the zeroed frame back");
    assert.ok(new Uint8Array(gray.gray).every((byte) => byte === 0));
  } finally {
    worker.terminate();
  }
});

test("a decode message cannot turn the frame echo on", async () => {
  const worker = await startWorker();
  try {
    const frame = render(COMPACT_SEEDQR);
    const gray = frame.pixels.slice();
    const reply = once(worker);
    worker.postMessage({ type: "decode", run: 1, width: frame.width, height: frame.height, gray: gray.buffer, echo: true }, [gray.buffer]);
    assert.equal((await reply).type, "decoded", "the first reply is the result, not the frame");
  } finally {
    worker.terminate();
  }
});

test("a WASM trap during a decode zeroes the frame, replies DECODE_FAILED and drops the instance", async () => {
  assert.ok(WebAssembly.validate(TRAPPING_WASM), "the trapping test module is valid WASM");
  const worker = await startWorker({ echo: true, wasm: TRAPPING_WASM });
  try {
    const frame = render(COMPACT_SEEDQR);
    const messages = await decodeFrame(worker, frame, true);
    const gray = messages.find((m) => m.type === "gray");
    assert.ok(gray, "the worker posts the frame back");
    assert.ok(new Uint8Array(gray.gray).every((byte) => byte === 0), "the frame is zeroed after the trap");
    assert.equal(messages.find((m) => m.type === "error")?.error.code, "DECODE_FAILED");
    const [again] = await decodeFrame(worker, frame);
    assert.equal(again.error?.code, "BAD_MESSAGE", "the dropped instance decodes nothing more");
  } finally {
    worker.terminate();
  }
});

test("the worker answers scrub", async () => {
  const worker = await startWorker();
  try {
    const scrubbed = once(worker);
    worker.postMessage({ type: "scrub" });
    assert.deepEqual(await scrubbed, { type: "scrubbed" });
  } finally {
    worker.terminate();
  }
});

class FakeWorker {
  static instances = [];
  constructor(url) {
    this.url = url;
    this.messages = [];
    this.terminated = false;
    this.onmessage = null;
    this.onerror = null;
    FakeWorker.instances.push(this);
  }
  postMessage(message, transfer) {
    this.messages.push({ message, transfer });
  }
  terminate() {
    this.terminated = true;
  }
  emit(data) {
    this.onmessage?.({ data });
  }
  sent(type) {
    return this.messages.filter((m) => m.message?.type === type).map((m) => m.message);
  }
}

// The worker is spawned lazily on the first decode, so the instance is read
// only after decode() has been called.
const fakeDecoder = (options = {}) => {
  FakeWorker.instances = [];
  return createQrDecoder({ source: "x", wasmBytes: new Uint8Array([1]), Worker: FakeWorker, timeoutMs: 1000, scrubMs: 5, ...options });
};

test("a stale run reply is dropped and its payload zeroed", async () => {
  const decoder = fakeDecoder();
  try {
    const first = decoder.decode(new Uint8Array(21 * 21), 21, 21);
    const worker = FakeWorker.instances[0];
    const [request] = worker.sent("decode");
    const stalePayload = new Uint8Array([1, 2, 3]).buffer;
    worker.emit({ type: "decoded", run: request.run + 1, code: 3, payload: stalePayload });
    assert.ok(new Uint8Array(stalePayload).every((byte) => byte === 0), "the stale payload is zeroed");
    worker.emit({ type: "decoded", run: request.run, code: 0, payload: null });
    assert.deepEqual(await first, { code: 0, payload: null });
  } finally {
    decoder.stop();
  }
});

test("a concurrent decode is refused with BUSY", async () => {
  const decoder = fakeDecoder();
  try {
    const first = decoder.decode(new Uint8Array(21 * 21), 21, 21);
    const worker = FakeWorker.instances[0];
    await assert.rejects(decoder.decode(new Uint8Array(21 * 21), 21, 21), { code: "BUSY" });
    const [request] = worker.sent("decode");
    worker.emit({ type: "decoded", run: request.run, code: 0, payload: null });
    assert.deepEqual(await first, { code: 0, payload: null });
  } finally {
    decoder.stop();
  }
});

test("the watchdog terminates the worker and rejects TIMEOUT", async () => {
  const decoder = fakeDecoder({ timeoutMs: 10 });
  try {
    const pending = decoder.decode(new Uint8Array(21 * 21), 21, 21);
    const worker = FakeWorker.instances[0];
    await assert.rejects(pending, { code: "TIMEOUT" });
    assert.equal(worker.sent("scrub").length, 1, "the worker is asked to scrub");
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(worker.terminated, true, "the worker is terminated");
  } finally {
    decoder.stop();
  }
});

test("stop() posts scrub and terminates within scrubMs", async () => {
  const decoder = fakeDecoder();
  const pending = decoder.decode(new Uint8Array(21 * 21), 21, 21);
  const worker = FakeWorker.instances[0];
  decoder.stop();
  await assert.rejects(pending, { code: "STOPPED" });
  assert.equal(worker.sent("scrub").length, 1, "the worker is asked to scrub");
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(worker.terminated, true, "the worker is terminated");
});

test("a decode after stop() is refused with STOPPED", async () => {
  const decoder = fakeDecoder();
  decoder.stop();
  await assert.rejects(decoder.decode(new Uint8Array(21 * 21), 21, 21), { code: "STOPPED" });
});

test("a frame that is not width*height bytes is refused with BAD_ARGS", async () => {
  const decoder = fakeDecoder();
  try {
    await assert.rejects(decoder.decode(new Uint8Array(21 * 21 - 1), 21, 21), { code: "BAD_ARGS" });
    await assert.rejects(decoder.decode(new Uint8Array(20 * 20), 20, 20), { code: "BAD_ARGS" });
    await assert.rejects(decoder.decode(new Uint8Array(0), 4097, 4097), { code: "TOO_LARGE" });
  } finally {
    decoder.stop();
  }
});

test("every frame the wrapper refuses is zeroed", async () => {
  const decoder = fakeDecoder();
  const filled = (length) => new Uint8Array(length).fill(7);
  try {
    const short = filled(21 * 21 - 1);
    await assert.rejects(decoder.decode(short, 21, 21), { code: "BAD_ARGS" });
    const large = filled(16);
    await assert.rejects(decoder.decode(large, 4097, 4097), { code: "TOO_LARGE" });
    const first = decoder.decode(filled(21 * 21), 21, 21);
    const busy = filled(21 * 21);
    await assert.rejects(decoder.decode(busy, 21, 21), { code: "BUSY" });
    const worker = FakeWorker.instances[0];
    const [request] = worker.sent("decode");
    worker.emit({ type: "decoded", run: request.run, code: 0, payload: null });
    await first;
    decoder.stop();
    const stopped = filled(21 * 21);
    await assert.rejects(decoder.decode(stopped, 21, 21), { code: "STOPPED" });
    for (const [name, frame] of Object.entries({ short, large, busy, stopped })) {
      assert.ok(frame.every((byte) => byte === 0), `the ${name} frame is zeroed`);
    }
  } finally {
    decoder.stop();
  }
});

test("an error reply retires the worker and the next decode starts a fresh one", async () => {
  const decoder = fakeDecoder();
  try {
    const first = decoder.decode(new Uint8Array(21 * 21), 21, 21);
    const worker = FakeWorker.instances[0];
    const [request] = worker.sent("decode");
    worker.emit({ type: "error", run: request.run, error: { code: "DECODE_FAILED" } });
    await assert.rejects(first, { code: "DECODE_FAILED" });
    assert.equal(worker.sent("scrub").length, 1, "the failed worker is asked to scrub");
    const second = decoder.decode(new Uint8Array(21 * 21), 21, 21);
    assert.equal(FakeWorker.instances.length, 2, "a fresh worker takes the next decode");
    const fresh = FakeWorker.instances[1];
    const [next] = fresh.sent("decode");
    fresh.emit({ type: "decoded", run: next.run, code: 0, payload: null });
    assert.deepEqual(await second, { code: 0, payload: null });
  } finally {
    decoder.stop();
  }
});

test("a release build ships neither the QR WASM module nor the QR worker source", () => {
  const out = mkdtempSync(join(tmpdir(), "entropylab-release-"));
  try {
    // CI checks the repository out shallow, where build-commit.mjs refuses to
    // name a commit. The footer stamp is not under test: pointing GIT_DIR at
    // a missing directory makes the build stamp "unknown" instead.
    const env = { ...process.env, GIT_DIR: join(out, "no-git") };
    execFileSync(process.execPath, [join(root, "scripts/build.mjs"), "--out", out], { cwd: root, env, stdio: "pipe" });
    const page = readFileSync(join(out, "entropylab.html"), "utf8");
    // Fingerprints that survive minification: identifiers such as
    // QR_WASM_B64 are renamed, but a slice of the base64 module and the
    // decoder's export name (only the worker body calls qr_decode) are not.
    assert.ok(workerSource.includes("qr_decode"), "the worker fingerprint is in the bundled worker");
    assert.ok(!page.includes(QR_WASM_B64.slice(4096, 4160)), "the release build carries no QR WASM module");
    assert.ok(!page.includes("qr_decode"), "the release build carries no QR worker source");
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});
