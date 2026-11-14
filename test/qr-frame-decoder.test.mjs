import { test } from "node:test";
import assert from "node:assert/strict";
import { createQrFrameDecoder } from "../src/js/qr-frame-decoder.js";

const frame = () => new Uint8ClampedArray(21 * 21 * 4).fill(255);
test("camera adapter converts pixels and wipes owned frame and payload buffers", async () => {
  const rgba = frame();
  rgba.set([255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255]);
  const payload = new TextEncoder().encode("ur:bytes/test");
  let gray;
  const adapter = createQrFrameDecoder({ createDecoder: () => ({
    async decode(pixels, w, h) {
      gray = pixels;
      assert.deepEqual([w, h], [21, 21]);
      assert.deepEqual([...pixels.slice(0, 3)], [76, 149, 28]);
      assert.ok(rgba.every(v => v === 0));
      return { code: payload.length, payload };
    }, stop() {},
  }) });
  assert.equal(await adapter.decode(rgba, 21, 21), "ur:bytes/test");
  assert.ok(gray.every(v => v === 0));
  assert.ok(payload.every(v => v === 0));
  adapter.stop();
});

test("retiring a decode wipes its late reply and creates a fresh decoder on restart", async () => {
  let resolve, created = 0, stopped = 0;
  const adapter = createQrFrameDecoder({ createDecoder: () => {
    created++;
    return { decode: () => new Promise(r => { resolve = r; }), stop() { stopped++; } };
  } });
  const pending = adapter.decode(frame(), 21, 21);
  adapter.stop();
  const payload = new Uint8Array([65]);
  resolve({ code: 1, payload });
  assert.equal(await pending, null);
  assert.equal(payload[0], 0);
  const next = adapter.decode(frame(), 21, 21);
  resolve({ code: -1, payload: null });
  assert.equal(await next, null);
  assert.equal(created, 2);
  assert.equal(stopped, 1);
  adapter.stop();
});

for (const code of [-1, -2, -3, -4, 0, 4097, 1.5, 2]) {
  test(`decoder result ${code} cannot deliver mismatched payload`, async () => {
    const payload = new Uint8Array([65]);
    const adapter = createQrFrameDecoder({ createDecoder: () => ({
      decode: async () => ({ code, payload }), stop() {},
    }) });
    if ([-1, -2, -3, -4].includes(code)) assert.equal(await adapter.decode(frame(), 21, 21), null);
    else await assert.rejects(adapter.decode(frame(), 21, 21));
    assert.equal(payload[0], 0);
    adapter.stop();
  });
}

test("too-large QR result allows the next frame on the same decoder", async () => {
  let calls = 0, created = 0;
  const adapter = createQrFrameDecoder({ createDecoder: () => {
    created++;
    return { decode: async () => ++calls === 1 ? {code:-4,payload:null} :
      {code:1,payload:new Uint8Array([65])}, stop() {} };
  } });
  assert.equal(await adapter.decode(frame(), 21, 21), null);
  assert.equal(await adapter.decode(frame(), 21, 21), "A");
  assert.equal(created, 1);
  adapter.stop();
});

test("transferred frame buffers and worker rejection are handled without masking errors", async () => {
  const rgba = frame();
  const adapter = createQrFrameDecoder({ createDecoder: () => ({
    decode(gray) {
      structuredClone(gray, { transfer: [gray.buffer] });
      throw new Error("STOPPED");
    }, stop() {},
  }) });
  await assert.rejects(adapter.decode(rgba, 21, 21), /STOPPED/);
  assert.ok(rgba.every(v => v === 0));
  adapter.stop();
});

test("invalid dimensions are wiped without starting a worker", async () => {
  const rgba = frame();
  const adapter = createQrFrameDecoder({ createDecoder: () => { assert.fail("must not create"); } });
  await assert.rejects(adapter.decode(rgba, 5000, 21), /INVALID_CAMERA_FRAME/);
  assert.ok(rgba.every(v => v === 0));
});

test("invalid UTF-8 payload is wiped on rejection", async () => {
  const payload = new Uint8Array([255]);
  const adapter = createQrFrameDecoder({ createDecoder: () => ({
    decode: async () => ({ code: 1, payload }), stop() {},
  }) });
  await assert.rejects(adapter.decode(frame(), 21, 21));
  assert.equal(payload[0], 0);
  adapter.stop();
});
