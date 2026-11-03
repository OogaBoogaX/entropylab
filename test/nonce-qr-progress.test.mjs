import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { AexbCapture, UrCapture } from "../src/js/aexb-capture.js";
import { hashesReady } from "../src/js/hashes.js";
import { secp256k1Ready } from "../src/js/secp256k1.js";
await Promise.all([hashesReady, secp256k1Ready]);
const source = readFileSync(new URL("../src/js/nonce-qr-capture.js", import.meta.url), "utf8")
  .replace(/^import .*;\r?\n/gm, "").replace("export function", "function");
const demo = JSON.parse(readFileSync(new URL("./fixtures/aexb/camera-demo.json", import.meta.url)));
function element() {
  return { children: [], dataset: {}, attrs: {}, value: "", textContent: "",
    append(...items) { this.children.push(...items); },
    replaceChildren(...items) { this.children = items; },
    setAttribute(k, v) { this.attrs[k] = v; },
    getAttribute(k) { return this.attrs[k]; },
    dispatchEvent() {}, focus() {}, getContext() { return { clearRect() {} }; },
  };
}
// Boots the capture with a stub camera and scans stage 2 in full.
async function bootWithStage2(camera = {}) {
  const elements = new Map();
  const el = id => { if (!elements.has(id)) elements.set(id, element()); return elements.get(id); };
  const hooks = {};
  const context = vm.createContext({
    AexbCapture, UrCapture, Event,
    document: { getElementById: el, createElement: element, addEventListener() {} },
    addEventListener() {},
    navigator: { mediaDevices: {
      getUserMedia: async () => ({getTracks: () => [], getVideoTracks: () => []}),
      enumerateDevices: async () => [],
    } },
    createQrFrameDecoder: () => ({stop() {}}),
    createModal: () => ({show() {}, hide() {}}),
    CameraCapture: class {
      stop() { camera.stop?.(); }
      async start(video, selected, callback, error) { hooks.receive = callback; hooks.onError = error; return true; }
    },
  });
  vm.runInContext(source, context);
  const capture = context.initNonceQrCapture({translate: key => key, onClear() {}});
  await el("nonce-qr-access").onclick();
  await el("nonce-qr-start").onclick();
  for (const frame of demo.scenarios.success.messages.find(m => m.stage === 2).medium_ur_parts) hooks.receive(frame);
  assert.equal(el("nonce-qr-stage-2").dataset.captured, "true");
  return { el, capture, hooks };
}
for (const action of ["invalid", "stop", "stop-throws", "camera-error"]) {
  test(`discarded assembly resets progress and keeps completed stages: ${action}`, async () => {
    const camera = {};
    const { el, hooks } = await bootWithStage2(camera);
    await el("nonce-qr-start").onclick();
    hooks.receive(demo.scenarios.success.messages.find(m => m.stage === 3).medium_ur_parts[0]);
    const bars = el("nonce-qr-bars");
    assert.equal(bars.getAttribute("aria-valuenow"), "1");
    assert.ok(bars.children.length > 1);
    if (action === "stop-throws") camera.stop = () => { throw new Error("camera stop failed"); };
    if (action === "invalid") hooks.receive("ur:bytes/adamadam");
    else if (action.startsWith("stop")) el("nonce-qr-stop").onclick();
    else hooks.onError({code: "CAMERA_DISCONNECTED"});
    assert.equal(bars.getAttribute("aria-valuenow"), "0");
    assert.equal(bars.children.length, 0);
    assert.equal(el("nonce-qr-stage-2").dataset.captured, "true");
    assert.equal(el("nonce-qr-stage-3").dataset.captured, "false");
    assert.equal(el("nonce-qr-stop").disabled, true);
  });
}
// End Session and pagehide clear the capture: a camera that throws while
// stopping must not keep the stages, the preview or the busy flag, and a frame
// still being decoded must not bring a stage back (DeepSeek on #1311; GLM,
// DeepSeek and K3.1 on #1353).
test("Clear empties the capture and ends the scan even when stopping the camera throws", async () => {
  const camera = {};
  const { el, capture, hooks } = await bootWithStage2(camera);
  await el("nonce-qr-start").onclick();
  camera.stop = () => { throw new Error("camera stop failed"); };
  capture.clear();
  assert.equal(el("nonce-qr-stage-2").dataset.captured, "false");
  assert.equal(el("nonce-qr-video").hidden, true);
  assert.equal(el("nonce-qr-stop").disabled, true);
  for (const frame of demo.scenarios.success.messages.find(m => m.stage === 2).medium_ur_parts) hooks.receive(frame);
  assert.equal(el("nonce-qr-stage-2").dataset.captured, "false");
});
