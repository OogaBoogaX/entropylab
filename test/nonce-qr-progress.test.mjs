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
for (const action of ["invalid", "stop", "camera-error"]) {
  test(`discarded assembly resets progress and keeps completed stages: ${action}`, async () => {
    const elements = new Map();
    const el = id => { if (!elements.has(id)) elements.set(id, element()); return elements.get(id); };
    let receive, onError;
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
        stop() {}
        async start(video, selected, callback, error) { receive = callback; onError = error; return true; }
      },
    });
    vm.runInContext(source, context);
    context.initNonceQrCapture({translate: key => key, onClear() {}});
    await el("nonce-qr-access").onclick();
    await el("nonce-qr-start").onclick();
    for (const frame of demo.scenarios.success.messages.find(m => m.stage === 2).medium_ur_parts) receive(frame);
    assert.equal(el("nonce-qr-stage-2").dataset.captured, "true");
    await el("nonce-qr-start").onclick();
    receive(demo.scenarios.success.messages.find(m => m.stage === 3).medium_ur_parts[0]);
    const bars = el("nonce-qr-bars");
    assert.equal(bars.getAttribute("aria-valuenow"), "1");
    assert.ok(bars.children.length > 1);
    if (action === "invalid") receive("ur:bytes/adamadam");
    else if (action === "stop") el("nonce-qr-stop").onclick();
    else onError({code: "CAMERA_DISCONNECTED"});
    assert.equal(bars.getAttribute("aria-valuenow"), "0");
    assert.equal(bars.children.length, 0);
    assert.equal(el("nonce-qr-stage-2").dataset.captured, "true");
    assert.equal(el("nonce-qr-stage-3").dataset.captured, "false");
    assert.equal(el("nonce-qr-stop").disabled, true);
  });
}
