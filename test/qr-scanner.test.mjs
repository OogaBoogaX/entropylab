import test from "node:test";
import assert from "node:assert/strict";
import { createQrScanner } from "../src/js/qr-scanner.js";

const tick = () => new Promise((resolve) => setImmediate(resolve));

const makeTrack = () => ({
  stopped: false,
  stop() {
    this.stopped = true;
  },
});

const makeStream = () => {
  const tracks = [makeTrack(), makeTrack()];
  return { tracks, getTracks: () => tracks };
};

const makeVideo = () => ({
  srcObject: null,
  videoWidth: 640,
  videoHeight: 480,
  muted: false,
  plays: 0,
  pauses: 0,
  play() {
    this.plays += 1;
    return Promise.resolve();
  },
  pause() {
    this.pauses += 1;
  },
});

const makeCanvas = () => {
  const state = { width: 0, height: 0, draws: 0, image: null };
  const ctx = {
    drawImage() {
      state.draws += 1;
    },
    getImageData(x, y, width, height) {
      const data = new Uint8ClampedArray(width * height * 4);
      data.fill(255);
      state.image = { data, width, height };
      return state.image;
    },
  };
  return {
    state,
    get width() {
      return state.width;
    },
    set width(value) {
      state.width = value;
    },
    get height() {
      return state.height;
    },
    set height(value) {
      state.height = value;
    },
    getContext: () => ctx,
  };
};

const makeFrames = () => {
  const queue = [];
  return {
    queue,
    requestFrame(callback) {
      queue.push(callback);
      return queue.length;
    },
    run() {
      const callback = queue.shift();
      if (callback) callback();
    },
  };
};

const makeMedia = () => {
  const calls = [];
  const pending = [];
  return {
    calls,
    pending,
    getUserMedia(constraints) {
      calls.push(constraints);
      return new Promise((resolve, reject) => pending.push({ resolve, reject }));
    },
  };
};

const makeDecoder = () => {
  const calls = [];
  const pending = [];
  return {
    calls,
    pending,
    decode(gray, width, height) {
      calls.push({ gray, width, height });
      return new Promise((resolve, reject) => pending.push({ resolve, reject }));
    },
  };
};

const build = (overrides = {}) => {
  const media = makeMedia();
  const video = makeVideo();
  const canvas = makeCanvas();
  const frames = makeFrames();
  const decoder = makeDecoder();
  const results = [];
  const statuses = [];
  const scanner = createQrScanner({
    decoder,
    mediaDevices: media,
    isSecureContext: true,
    video,
    canvas,
    requestFrame: frames.requestFrame,
    onResult: (payload) => results.push(payload),
    onStatus: (code) => statuses.push(code),
    ...overrides,
  });
  return { media, video, canvas, frames, decoder, results, statuses, scanner };
};

test("a decoded code stops the camera and hands the payload to onResult", async () => {
  const { media, video, canvas, frames, decoder, results, statuses, scanner } = build();
  scanner.start();
  const stream = makeStream();
  media.pending[0].resolve(stream);
  await tick();
  assert.deepEqual(statuses, ["scanning"]);
  assert.equal(video.plays, 1, "the stream is played, so frames advance");
  assert.equal(video.muted, true);
  frames.run();
  assert.equal(decoder.calls.length, 1);
  const payload = new Uint8Array([1, 2, 3]);
  decoder.pending[0].resolve({ code: 3, payload });
  await tick();
  assert.equal(results.length, 1);
  assert.equal(results[0], payload);
  assert.ok(stream.tracks.every((track) => track.stopped));
  assert.ok(video.pauses >= 1, "the video is paused when the camera stops");
  assert.equal(video.srcObject, null);
  assert.equal(canvas.width, 0);
  assert.equal(canvas.height, 0);
});

test("a reply whose code is not the payload length is an error, never a scan", async () => {
  const { media, frames, decoder, results, statuses, scanner } = build();
  scanner.start();
  media.pending[0].resolve(makeStream());
  await tick();
  frames.run();
  const payload = new Uint8Array([9, 9, 9]);
  decoder.pending[0].resolve({ code: 1, payload });
  await tick();
  assert.equal(results.length, 0, "a malformed reply never reaches onResult");
  assert.ok(payload.every((byte) => byte === 0), "its payload is wiped");
  assert.deepEqual(statuses.slice(-1), ["error"]);
});

test("the ImageData buffer is zeroed after a frame", async () => {
  const { media, canvas, frames, scanner } = build();
  scanner.start();
  media.pending[0].resolve(makeStream());
  await tick();
  frames.run();
  assert.ok(canvas.state.image);
  assert.ok(canvas.state.image.data.every((value) => value === 0));
});

test("a stream that resolves after stop() is stopped and never scanned", async () => {
  const { media, video, decoder, statuses, scanner } = build();
  scanner.start();
  scanner.stop();
  const stream = makeStream();
  media.pending[0].resolve(stream);
  await tick();
  assert.ok(stream.tracks.every((track) => track.stopped));
  assert.equal(video.srcObject, null);
  assert.equal(decoder.calls.length, 0);
  assert.deepEqual(statuses, ["stopped"]);
});

test("a denied camera reports denied", async () => {
  const { media, statuses, scanner } = build();
  scanner.start();
  media.pending[0].reject(Object.assign(new Error("denied"), { name: "NotAllowedError" }));
  await tick();
  assert.deepEqual(statuses, ["denied"]);
});

test("a missing camera reports no-camera", async () => {
  const { media, statuses, scanner } = build();
  scanner.start();
  media.pending[0].reject(Object.assign(new Error("missing"), { name: "NotFoundError" }));
  await tick();
  assert.deepEqual(statuses, ["no-camera"]);
});

test("no secure context reports unsupported", () => {
  const { media, statuses, scanner } = build({ isSecureContext: false });
  scanner.start();
  assert.deepEqual(statuses, ["unsupported"]);
  assert.equal(media.calls.length, 0);
});

test("a two-code frame reports two-codes and keeps scanning", async () => {
  const { media, frames, decoder, statuses, scanner } = build();
  scanner.start();
  media.pending[0].resolve(makeStream());
  await tick();
  frames.run();
  decoder.pending[0].resolve({ code: -3, payload: null });
  await tick();
  assert.deepEqual(statuses, ["scanning", "two-codes"]);
  frames.run();
  assert.equal(decoder.calls.length, 2);
});

test("the timeout stops the camera and start() resumes", async () => {
  const { media, video, statuses, scanner } = build({ timeoutMs: 5 });
  scanner.start();
  const first = makeStream();
  media.pending[0].resolve(first);
  await tick();
  assert.deepEqual(statuses, ["scanning"]);
  await new Promise((resolve) => setTimeout(resolve, 30));
  assert.deepEqual(statuses, ["scanning", "timeout"]);
  assert.ok(first.tracks.every((track) => track.stopped));
  assert.equal(video.srcObject, null);
  scanner.start();
  assert.equal(media.calls.length, 2);
  media.pending[1].resolve(makeStream());
  await tick();
  assert.deepEqual(statuses, ["scanning", "timeout", "scanning"]);
  scanner.stop();
  assert.deepEqual(statuses, ["scanning", "timeout", "scanning", "stopped"]);
});

test("only one decode is in flight", async () => {
  const { media, frames, decoder, scanner } = build();
  scanner.start();
  media.pending[0].resolve(makeStream());
  await tick();
  frames.run();
  assert.equal(decoder.calls.length, 1);
  frames.run();
  assert.equal(decoder.calls.length, 1);
  decoder.pending[0].resolve({ code: -1, payload: null });
  await tick();
  frames.run();
  assert.equal(decoder.calls.length, 2);
});

test("stop() is idempotent", async () => {
  const { media, statuses, scanner } = build();
  scanner.start();
  media.pending[0].resolve(makeStream());
  await tick();
  scanner.stop();
  scanner.stop();
  assert.deepEqual(statuses, ["scanning", "stopped"]);
});

test("scanImage refuses svg and oversize files", async () => {
  const { scanner } = build();
  await assert.rejects(
    scanner.scanImage({ size: 10, type: "image/svg+xml" }),
    (error) => error.code === "UNSUPPORTED_TYPE",
  );
  await assert.rejects(
    scanner.scanImage({ size: 10 * 1024 * 1024 + 1, type: "image/png" }),
    (error) => error.code === "TOO_LARGE",
  );
});

test("scanImage decodes a bitmap and zeroes the canvas", async () => {
  const { canvas, decoder, scanner } = build();
  const bitmap = {
    width: 100,
    height: 100,
    closed: false,
    close() {
      this.closed = true;
    },
  };
  const original = globalThis.createImageBitmap;
  globalThis.createImageBitmap = async () => bitmap;
  try {
    const pending = scanner.scanImage({ size: 100, type: "image/png" });
    await tick();
    assert.equal(decoder.calls.length, 1);
    const payload = new Uint8Array([7]);
    decoder.pending[0].resolve({ code: 1, payload });
    const result = await pending;
    assert.equal(result.code, 1);
    assert.equal(result.payload, payload);
    assert.ok(decoder.calls[0].gray.every((byte) => byte === 0), "the photo's grayscale frame is wiped");
    assert.equal(bitmap.closed, true);
    assert.equal(canvas.width, 0);
    assert.equal(canvas.height, 0);
  } finally {
    globalThis.createImageBitmap = original;
  }
});

test("scanImage refuses a reply whose code is not the payload length", async () => {
  const { decoder, scanner } = build();
  const original = globalThis.createImageBitmap;
  globalThis.createImageBitmap = async () => ({ width: 100, height: 100, close() {} });
  try {
    const pending = scanner.scanImage({ size: 100, type: "image/png" });
    await tick();
    const payload = new Uint8Array([5, 5, 5]);
    decoder.pending[0].resolve({ code: 5, payload });
    await assert.rejects(pending, (error) => error.code === "DECODE_FAILED");
    assert.ok(payload.every((byte) => byte === 0), "the malformed payload is wiped");
  } finally {
    globalThis.createImageBitmap = original;
  }
});

test("scanImage returns no bytes for a no-code reply and refuses an unknown one", async () => {
  const original = globalThis.createImageBitmap;
  globalThis.createImageBitmap = async () => ({ width: 100, height: 100, close() {} });
  try {
    const first = build();
    const noCode = first.scanner.scanImage({ size: 100, type: "image/png" });
    await tick();
    const stray = new Uint8Array([4, 4]);
    first.decoder.pending[0].resolve({ code: -1, payload: stray });
    const result = await noCode;
    assert.equal(result.code, -1);
    assert.equal(result.payload, null, "a no-code reply carries no bytes");
    assert.ok(stray.every((byte) => byte === 0), "a stray payload is wiped");

    const second = build();
    const unknown = second.scanner.scanImage({ size: 100, type: "image/png" });
    await tick();
    second.decoder.pending[0].resolve({ code: -5, payload: new Uint8Array([1]) });
    await assert.rejects(unknown, (error) => error.code === "DECODE_FAILED");
  } finally {
    globalThis.createImageBitmap = original;
  }
});

test("a reply that arrives after stop() is discarded and its payload wiped", async () => {
  const { media, frames, decoder, results, scanner } = build();
  scanner.start();
  media.pending[0].resolve(makeStream());
  await tick();
  frames.run();
  scanner.stop();
  const late = new Uint8Array([7, 7, 7]);
  decoder.pending[0].resolve({ code: 3, payload: late });
  await tick();
  assert.equal(results.length, 0, "a late scan never reaches onResult");
  assert.ok(late.every((byte) => byte === 0), "its payload is wiped");
});

test("a decoder retired under a running scan reports an error", async () => {
  const { media, frames, decoder, statuses, scanner } = build();
  scanner.start();
  media.pending[0].resolve(makeStream());
  await tick();
  frames.run();
  decoder.pending[0].reject(Object.assign(new Error("STOPPED"), { code: "STOPPED" }));
  await tick();
  assert.deepEqual(statuses.slice(-1), ["error"], "the caller is not left on scanning");
});
