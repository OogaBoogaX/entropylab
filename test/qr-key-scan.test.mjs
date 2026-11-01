import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { mountKeyScan, retireQrDecoders } from "../src/js/qr-key-scan.js";
import { classifyQrPayload } from "../src/js/qr-payload.js";
import { bip39English } from "../src/js/bip39.js";
import { loadAppFunctions } from "./app-slice-harness.mjs";

// The published compressed mainnet WIF for private key 1.
const WIF = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
// The Standard SeedQR of the BIP39 all-zero entropy mnemonic ("abandon …
// about"): each word index as four decimal digits, so eleven 0000 then 0003.
const SEEDQR = "0000".repeat(11) + "0003";
const bytesOf = (text) => Uint8Array.from(text, (character) => character.charCodeAt(0));
const tick = () => new Promise((resolve) => setImmediate(resolve));

class FakeInputEvent {
  constructor(type, init = {}) {
    this.type = type;
    this.bubbles = !!init.bubbles;
    this.inputType = init.inputType ?? "";
    this.target = null;
  }
}

class FakeElement {
  constructor(doc, tag) {
    this.ownerDocument = doc;
    this.tagName = String(tag).toUpperCase();
    this.childNodes = [];
    this.parentNode = null;
    this.attributes = new Map();
    this.listeners = new Map();
    this._text = "";
    this._html = "";
    this.hidden = false;
    this.value = "";
    this.files = null;
    this.isConnected = true;
    this.id = "";
  }
  get textContent() {
    if (this.childNodes.length) return this.childNodes.map((child) => child.textContent).join("");
    return this._text;
  }
  set textContent(value) {
    this.childNodes = [];
    this._text = String(value ?? "");
    this._html = "";
  }
  get innerHTML() {
    return this._html;
  }
  set innerHTML(value) {
    this.childNodes = [];
    this._text = "";
    this._html = String(value ?? "");
  }
  appendChild(node) {
    node.parentNode = this;
    this.childNodes.push(node);
    return node;
  }
  replaceChildren(...nodes) {
    for (const child of this.childNodes) child.parentNode = null;
    this.childNodes = [];
    this._text = "";
    this._html = "";
    for (const node of nodes) this.appendChild(node);
  }
  setAttribute(name, value) {
    this.attributes.set(name, String(value));
    if (name === "id") this.id = String(value);
    if (name === "hidden") this.hidden = true;
  }
  getAttribute(name) {
    return this.attributes.has(name) ? this.attributes.get(name) : null;
  }
  removeAttribute(name) {
    this.attributes.delete(name);
  }
  get className() {
    return this.getAttribute("class") || "";
  }
  set className(value) {
    this.setAttribute("class", value);
  }
  addEventListener(type, handler) {
    const list = this.listeners.get(type) || [];
    list.push(handler);
    this.listeners.set(type, list);
  }
  removeEventListener(type, handler) {
    const list = this.listeners.get(type) || [];
    this.listeners.set(type, list.filter((entry) => entry !== handler));
  }
  dispatchEvent(event) {
    event.target = this;
    for (const handler of [...(this.listeners.get(event.type) || [])]) handler.call(this, event);
    return true;
  }
  focus() {
    this.ownerDocument.activeElement = this;
  }
}

const makeDocument = () => {
  const listeners = new Map();
  const doc = {
    visibilityState: "visible",
    activeElement: null,
    createElement(tag) {
      return new FakeElement(doc, tag);
    },
    addEventListener(type, handler) {
      const list = listeners.get(type) || [];
      list.push(handler);
      listeners.set(type, list);
    },
    removeEventListener(type, handler) {
      const list = listeners.get(type) || [];
      listeners.set(type, list.filter((entry) => entry !== handler));
    },
    dispatch(type) {
      for (const handler of [...(listeners.get(type) || [])]) handler({ type });
    },
    listenerCount(type) {
      return (listeners.get(type) || []).length;
    },
  };
  return doc;
};

const findById = (node, id) => {
  if (!node) return null;
  if (node.id === id) return node;
  for (const child of node.childNodes) {
    const found = findById(child, id);
    if (found) return found;
  }
  return null;
};

const flatten = (node, out = []) => {
  out.push(node);
  for (const child of node.childNodes) flatten(child, out);
  return out;
};

// Everything the host would put on screen, text and markup alike.
const markupOf = (node) => {
  if (!node) return "";
  let out = node._html || "";
  if (!node.childNodes.length) out += node._text || "";
  for (const child of node.childNodes) out += markupOf(child);
  return out;
};

const makeDecoder = () => {
  const calls = { stop: 0 };
  return {
    calls,
    decode() {
      return Promise.resolve({ code: -1 });
    },
    stop() {
      calls.stop += 1;
      return Promise.resolve({ scrubbed: true });
    },
  };
};

const makeScanner = (reply = async () => ({ code: -1, payload: null })) => {
  const calls = { start: 0, stop: 0, images: [], log: [] };
  return {
    calls,
    start() {
      calls.start += 1;
      calls.log.push("start");
    },
    stop() {
      calls.stop += 1;
      calls.log.push("stop");
    },
    scanImage(file) {
      calls.images.push(file);
      calls.log.push("scanImage");
      return reply(file);
    },
  };
};

const setup = (options = {}) => {
  const doc = makeDocument();
  const host = doc.createElement("div");
  host.id = "key-scan-host";
  const keyField = doc.createElement("textarea");
  const events = [];
  keyField.addEventListener("input", (event) => events.push(event));
  const decoder = makeDecoder();
  const scanner = makeScanner(options.reply);
  const created = { decoders: 0, scanners: 0, decoderArgs: null, scannerArgs: null };
  const panel = mountKeyScan(host, {
    keyField,
    accept: options.accept,
    idPrefix: options.idPrefix,
    beforeOpen: options.beforeOpen,
    replacesSeed: options.replacesSeed,
    onSeed: options.onSeed,
    wordlist: options.wordlist,
    translate: options.translate || ((text) => text),
    privateValue: (value, revealed) => (revealed ? value : "•".repeat(value.length)),
    beforeWrite: options.beforeWrite,
    createDecoder: (args) => {
      created.decoders += 1;
      created.decoderArgs = args;
      return decoder;
    },
    createScanner: (args) => {
      created.scanners += 1;
      created.scannerArgs = args;
      return scanner;
    },
    classify: options.classify || classifyQrPayload,
    wasmBytes: () => new Uint8Array([1, 2, 3]),
    doc,
    win: { InputEvent: FakeInputEvent },
  });
  return { doc, host, keyField, events, decoder, scanner, created, panel };
};

const openPanel = (ctx) => {
  findById(ctx.host, "key-scan-open").dispatchEvent({ type: "click" });
};

const stateOf = (ctx) => findById(ctx.host, "key-scan-status").getAttribute("data-scan-state");
const stateOfSeed = (ctx) => findById(ctx.host, "seed-scan-status").getAttribute("data-scan-state");
const openSeedPanel = (ctx) => findById(ctx.host, "seed-scan-open").dispatchEvent({ type: "click" });

test("opening the panel starts one scanner and the button follows it", () => {
  const ctx = setup();
  const open = findById(ctx.host, "key-scan-open");
  const panel = findById(ctx.host, "key-scan-panel");
  assert.equal(open.getAttribute("aria-expanded"), "false");
  assert.equal(panel.hidden, true);
  open.dispatchEvent({ type: "click" });
  assert.equal(open.getAttribute("aria-expanded"), "true");
  assert.equal(panel.hidden, false);
  assert.equal(ctx.created.decoders, 1);
  assert.equal(ctx.created.scanners, 1);
  assert.equal(ctx.scanner.calls.start, 1);
  assert.deepEqual([...ctx.created.decoderArgs.wasmBytes], [1, 2, 3]);
  open.dispatchEvent({ type: "click" });
  assert.equal(open.getAttribute("aria-expanded"), "false");
  assert.equal(panel.hidden, true);
  assert.equal(ctx.scanner.calls.stop, 1);
});

test("a WIF scan is concealed until Show key and its bytes are zeroed", () => {
  const ctx = setup();
  openPanel(ctx);
  const payload = bytesOf(WIF);
  ctx.created.scannerArgs.onResult(payload);
  assert.ok(payload.every((byte) => byte === 0), "the payload was not zeroed");
  assert.equal(stateOf(ctx), "wif");
  assert.equal(findById(ctx.host, "key-scan-confirm").hidden, false);
  assert.match(markupOf(findById(ctx.host, "key-scan-confirm-intro")), /cannot tell where a QR came from/);
  assert.equal(markupOf(ctx.host).includes(WIF), false, "the key was in the DOM while concealed");
  assert.equal(ctx.keyField.value, "");
  findById(ctx.host, "key-scan-reveal").dispatchEvent({ type: "click" });
  assert.ok(markupOf(ctx.host).includes(WIF), "Show key did not reveal the key");
});

test("Continue fills the key field with one paste-like input event", () => {
  const ctx = setup();
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf(WIF));
  findById(ctx.host, "key-scan-continue").dispatchEvent({ type: "click" });
  assert.equal(ctx.keyField.value, WIF);
  assert.equal(ctx.events.length, 1);
  assert.equal(ctx.events[0].type, "input");
  assert.equal(ctx.events[0].bubbles, true);
  assert.equal(ctx.events[0].inputType, "insertFromPaste");
  assert.equal(markupOf(ctx.host).includes(WIF), false, "the key stayed in the DOM");
});

test("beforeWrite runs before the field is written", () => {
  const seen = [];
  let ctx = null;
  ctx = setup({ beforeWrite: () => seen.push(ctx.keyField.value) });
  ctx.keyField.value = "old";
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf(WIF));
  findById(ctx.host, "key-scan-continue").dispatchEvent({ type: "click" });
  assert.deepEqual(seen, ["old"]);
  assert.equal(ctx.keyField.value, WIF);
  assert.equal(ctx.events.length, 1);
  assert.equal(ctx.events[0].inputType, "insertFromPaste");
});

test("a throwing beforeWrite leaves the field and the confirmation alone", () => {
  const ctx = setup({ beforeWrite: () => { throw new Error("no WIF radio"); } });
  ctx.keyField.value = "old";
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf(WIF));
  findById(ctx.host, "key-scan-continue").dispatchEvent({ type: "click" });
  assert.equal(ctx.keyField.value, "old");
  assert.equal(ctx.events.length, 0);
  assert.equal(findById(ctx.host, "key-scan-confirm").hidden, false);
  assert.equal(stateOf(ctx), "error");
  findById(ctx.host, "key-scan-discard").dispatchEvent({ type: "click" });
  assert.equal(findById(ctx.host, "key-scan-confirm").hidden, true);
});

test("Discard scan leaves the key field untouched", () => {
  const ctx = setup();
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf(WIF));
  findById(ctx.host, "key-scan-discard").dispatchEvent({ type: "click" });
  assert.equal(ctx.keyField.value, "");
  assert.equal(ctx.events.length, 0);
  assert.equal(markupOf(ctx.host).includes(WIF), false);
});

test("a seed QR is refused and its indices are zeroed", () => {
  let captured = null;
  const ctx = setup({
    classify: (bytes) => {
      captured = classifyQrPayload(bytes);
      return captured;
    },
  });
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf(SEEDQR));
  assert.equal(captured.format, "standard-seedqr");
  assert.ok(captured.indices.every((index) => index === 0), "the seed indices were not zeroed");
  assert.equal(stateOf(ctx), "seed");
  assert.match(markupOf(ctx.host), /Nothing was loaded/);
  assert.equal(ctx.keyField.value, "");
  assert.equal(findById(ctx.host, "key-scan-resume").hidden, false, "Resume is offered to scan again");
});

test("bytes that are not a key are refused without being echoed", () => {
  const ctx = setup();
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf("SECRETBYTES"));
  assert.equal(stateOf(ctx), "not-a-key");
  assert.match(markupOf(ctx.host), /Nothing was loaded/);
  assert.equal(markupOf(ctx.host).includes("SECRETBYTES"), false);
  assert.equal(ctx.keyField.value, "");
});

test("two codes are refused while the scan goes on", () => {
  const ctx = setup();
  openPanel(ctx);
  ctx.created.scannerArgs.onStatus("two-codes");
  assert.equal(stateOf(ctx), "two-codes");
  assert.match(markupOf(ctx.host), /Nothing was loaded/);
  assert.equal(findById(ctx.host, "key-scan-resume").hidden, true);
});

test("a timeout offers Resume, which starts the camera again", () => {
  const ctx = setup();
  openPanel(ctx);
  ctx.created.scannerArgs.onStatus("timeout");
  assert.equal(stateOf(ctx), "timeout");
  const resume = findById(ctx.host, "key-scan-resume");
  assert.equal(resume.hidden, false);
  resume.dispatchEvent({ type: "click" });
  assert.equal(ctx.scanner.calls.start, 2);
});

test("a photo stops the camera first and maps every refusal", async () => {
  const scanPhoto = async (reply) => {
    const ctx = setup({ reply });
    openPanel(ctx);
    const photo = findById(ctx.host, "key-scan-photo");
    photo.files = [{ size: 10, type: "image/png" }];
    photo.dispatchEvent({ type: "change" });
    await tick();
    return ctx;
  };

  const tooLarge = await scanPhoto(async () => { throw Object.assign(new Error("x"), { code: "TOO_LARGE" }); });
  assert.deepEqual(tooLarge.scanner.calls.log.slice(-2), ["stop", "scanImage"]);
  assert.equal(stateOf(tooLarge), "too-large");

  const unsupported = await scanPhoto(async () => { throw Object.assign(new Error("x"), { code: "UNSUPPORTED_TYPE" }); });
  assert.equal(stateOf(unsupported), "unsupported-type");

  const unreadable = await scanPhoto(async () => { throw Object.assign(new Error("x"), { code: "UNREADABLE" }); });
  assert.equal(stateOf(unreadable), "unreadable");

  const busy = await scanPhoto(async () => { throw Object.assign(new Error("x"), { code: "BUSY" }); });
  assert.equal(stateOf(busy), "error");
  assert.match(markupOf(busy.host), /Nothing was loaded/);

  const none = await scanPhoto(async () => ({ code: -1, payload: null }));
  assert.equal(stateOf(none), "no-code");

  const twoCodes = await scanPhoto(async () => ({ code: -3, payload: null }));
  assert.equal(stateOf(twoCodes), "two-codes");
  assert.match(markupOf(twoCodes.host), /Nothing was loaded/);

  const found = await scanPhoto(async () => ({ code: 1, payload: bytesOf(WIF) }));
  assert.equal(stateOf(found), "wif");
});

test("Scan a photo stops the camera before the file picker opens", () => {
  const ctx = setup();
  openPanel(ctx);
  const stops = ctx.scanner.calls.stop;
  let pickerOpened = 0;
  findById(ctx.host, "key-scan-photo").click = () => { pickerOpened += 1; };
  findById(ctx.host, "key-scan-photo-open").dispatchEvent({ type: "click" });
  assert.equal(ctx.scanner.calls.stop, stops + 1);
  assert.equal(pickerOpened, 1);
  assert.equal(ctx.scanner.calls.images.length, 0);
  assert.equal(findById(ctx.host, "key-scan-photo-open").hidden, false);
});

test("conceal re-hides a shown key and keeps the scan", () => {
  const ctx = setup();
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf(WIF));
  findById(ctx.host, "key-scan-reveal").dispatchEvent({ type: "click" });
  assert.ok(markupOf(ctx.host).includes(WIF));
  ctx.doc.dispatch("hodl:conceal");
  assert.equal(markupOf(ctx.host).includes(WIF), false);
  assert.ok(findById(ctx.host, "key-scan-continue"), "the scan was dropped");
});

test("leaving the page stops the camera and discards the confirmation", () => {
  const ctx = setup();
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf(WIF));
  ctx.doc.visibilityState = "hidden";
  ctx.doc.dispatch("visibilitychange");
  assert.equal(ctx.scanner.calls.stop, 1);
  assert.equal(markupOf(ctx.host).includes(WIF), false);
  assert.equal(findById(ctx.host, "key-scan-confirm").hidden, true);
});

test("destroy stops the scanner and the decoder once and empties the host", () => {
  const ctx = setup();
  openPanel(ctx);
  assert.equal(ctx.doc.listenerCount("hodl:conceal"), 1);
  assert.equal(ctx.doc.listenerCount("visibilitychange"), 1);
  ctx.panel.destroy();
  assert.equal(ctx.scanner.calls.stop, 1);
  assert.equal(ctx.decoder.calls.stop, 1);
  assert.equal(ctx.doc.listenerCount("hodl:conceal"), 0);
  assert.equal(ctx.doc.listenerCount("visibilitychange"), 0);
  assert.equal(ctx.host.childNodes.length, 0);
  ctx.panel.destroy();
  assert.equal(ctx.scanner.calls.stop, 1);
  assert.equal(ctx.decoder.calls.stop, 1);
});

test("the module re-exports retireQrDecoders", () => {
  assert.equal(typeof retireQrDecoders, "function");
});

test("Show key and Hide key update one button in place and keep focus", () => {
  const ctx = setup();
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf(WIF));
  const reveal = findById(ctx.host, "key-scan-reveal");
  reveal.focus();
  assert.equal(ctx.doc.activeElement, reveal);
  reveal.dispatchEvent({ type: "click" });
  assert.equal(findById(ctx.host, "key-scan-reveal"), reveal, "the button was replaced");
  assert.equal(ctx.doc.activeElement, reveal, "focus left the button");
  assert.ok(markupOf(ctx.host).includes(WIF), "Show key did not reveal the key");
  reveal.dispatchEvent({ type: "click" });
  assert.equal(findById(ctx.host, "key-scan-reveal"), reveal, "the button was replaced");
  assert.equal(ctx.doc.activeElement, reveal, "focus left the button");
  assert.equal(markupOf(ctx.host).includes(WIF), false, "Hide key did not conceal the key");
  reveal.dispatchEvent({ type: "click" });
  assert.ok(markupOf(ctx.host).includes(WIF));
  ctx.doc.dispatch("hodl:conceal");
  assert.equal(findById(ctx.host, "key-scan-reveal"), reveal, "conceal replaced the button");
  assert.equal(markupOf(ctx.host).includes(WIF), false, "conceal did not hide the key");
});

test("Discard scan returns focus to Scan QR", () => {
  const ctx = setup();
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf(WIF));
  const discard = findById(ctx.host, "key-scan-discard");
  discard.focus();
  discard.dispatchEvent({ type: "click" });
  assert.equal(ctx.doc.activeElement, findById(ctx.host, "key-scan-open"));
});

test("a WIF result hides acquisition controls and announces success", () => {
  const ctx = setup();
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf(WIF));
  for (const id of ["key-scan-video", "key-scan-stop", "key-scan-resume", "key-scan-photo-open", "key-scan-photo-note", "key-scan-cancel"]) {
    assert.equal(findById(ctx.host, id).hidden, true, `${id} was not hidden`);
  }
  assert.equal(stateOf(ctx), "wif");
  assert.equal(markupOf(ctx.host).includes(WIF), false);
});

test("a photo WIF result focuses the confirmation introduction", async () => {
  const ctx = setup({ reply: async () => ({ code: 1, payload: bytesOf(WIF) }) });
  openPanel(ctx);
  const photo = findById(ctx.host, "key-scan-photo");
  photo.files = [{ size: 10, type: "image/png" }];
  photo.dispatchEvent({ type: "change" });
  await tick();
  const intro = findById(ctx.host, "key-scan-confirm-intro");
  assert.ok(intro, "the confirmation introduction is missing");
  assert.equal(intro.getAttribute("tabindex"), "-1");
  assert.equal(ctx.doc.activeElement, intro);
});

const latePhoto = async (close) => {
  let resolveScan;
  const pending = new Promise((resolve) => { resolveScan = resolve; });
  const ctx = setup({ reply: () => pending });
  openPanel(ctx);
  const photo = findById(ctx.host, "key-scan-photo");
  photo.files = [{ size: 10, type: "image/png" }];
  photo.dispatchEvent({ type: "change" });
  close(ctx);
  const payload = bytesOf(WIF);
  resolveScan({ code: 1, payload });
  await tick();
  return { ctx, payload };
};

test("a late photo result is wiped after closing, cancelling or hiding", async () => {
  const closed = await latePhoto((ctx) => findById(ctx.host, "key-scan-open").dispatchEvent({ type: "click" }));
  assert.equal(findById(closed.ctx.host, "key-scan-confirm").hidden, true);
  assert.ok(closed.payload.every((byte) => byte === 0), "the late payload was not zeroed");
  assert.equal(markupOf(closed.ctx.host).includes(WIF), false);

  const cancelled = await latePhoto((ctx) => findById(ctx.host, "key-scan-cancel").dispatchEvent({ type: "click" }));
  assert.equal(findById(cancelled.ctx.host, "key-scan-confirm").hidden, true);
  assert.ok(cancelled.payload.every((byte) => byte === 0), "the late payload was not zeroed");
  assert.equal(markupOf(cancelled.ctx.host).includes(WIF), false);

  const hidden = await latePhoto((ctx) => {
    ctx.doc.visibilityState = "hidden";
    ctx.doc.dispatch("visibilitychange");
  });
  assert.equal(findById(hidden.ctx.host, "key-scan-confirm").hidden, true);
  assert.ok(hidden.payload.every((byte) => byte === 0), "the late payload was not zeroed");
  assert.equal(markupOf(hidden.ctx.host).includes(WIF), false);
});

test("closing the panel drops a pending WIF", () => {
  const ctx = setup();
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf(WIF));
  assert.equal(findById(ctx.host, "key-scan-confirm").hidden, false);
  findById(ctx.host, "key-scan-open").dispatchEvent({ type: "click" });
  assert.equal(findById(ctx.host, "key-scan-confirm").hidden, true);
  assert.equal(markupOf(ctx.host).includes(WIF), false);
  findById(ctx.host, "key-scan-open").dispatchEvent({ type: "click" });
  assert.equal(findById(ctx.host, "key-scan-confirm").hidden, true);
  assert.equal(markupOf(ctx.host).includes(WIF), false);
});

test("Cancel scan closes the panel, stops the scanner and focuses Scan QR", () => {
  const ctx = setup();
  openPanel(ctx);
  const cancel = findById(ctx.host, "key-scan-cancel");
  assert.equal(cancel.hidden, false);
  cancel.dispatchEvent({ type: "click" });
  assert.equal(findById(ctx.host, "key-scan-panel").hidden, true);
  assert.equal(ctx.scanner.calls.stop, 1);
  assert.equal(ctx.doc.activeElement, findById(ctx.host, "key-scan-open"));
});

test("Resume camera is offered only where the camera can work", () => {
  const unsupported = setup();
  openPanel(unsupported);
  unsupported.created.scannerArgs.onStatus("unsupported");
  assert.equal(findById(unsupported.host, "key-scan-resume").hidden, true);

  const noCamera = setup();
  openPanel(noCamera);
  noCamera.created.scannerArgs.onStatus("no-camera");
  assert.equal(findById(noCamera.host, "key-scan-resume").hidden, true);

  const denied = setup();
  openPanel(denied);
  denied.created.scannerArgs.onStatus("denied");
  assert.equal(findById(denied.host, "key-scan-resume").hidden, false);

  // A refusal after an unsupported camera still offers no Resume (GLM).
  const refusedAfterUnsupported = setup();
  openPanel(refusedAfterUnsupported);
  refusedAfterUnsupported.created.scannerArgs.onStatus("unsupported");
  refusedAfterUnsupported.created.scannerArgs.onResult(bytesOf("not-a-key"));
  assert.equal(stateOf(refusedAfterUnsupported), "not-a-key");
  assert.equal(findById(refusedAfterUnsupported.host, "key-scan-resume").hidden, true);
});

test("a camera result after destroy() is zeroed and ignored", () => {
  const ctx = setup();
  openPanel(ctx);
  const late = bytesOf(WIF);
  const { onResult } = ctx.created.scannerArgs;
  ctx.panel.destroy();
  onResult(late);
  assert.ok(late.every((byte) => byte === 0), "the late payload is wiped");
});

test("hiding the focused Stop camera moves focus to Resume camera", () => {
  const ctx = setup();
  openPanel(ctx);
  const stop = findById(ctx.host, "key-scan-stop");
  assert.equal(stop.hidden, false);
  stop.focus();
  ctx.created.scannerArgs.onStatus("timeout");
  assert.equal(stop.hidden, true);
  assert.equal(ctx.doc.activeElement, findById(ctx.host, "key-scan-resume"));
});

test("the photo button is described by the photo note", () => {
  const ctx = setup();
  const photo = findById(ctx.host, "key-scan-photo-open");
  const note = findById(ctx.host, "key-scan-photo-note");
  assert.ok(note, "the photo note has no id");
  assert.equal(photo.getAttribute("aria-describedby"), note.id);
  assert.match(markupOf(note), /copy of the secret/);
});

test("the panel reads status, video, actions, note, confirmation", () => {
  const ctx = setup();
  const nodes = flatten(findById(ctx.host, "key-scan-panel"));
  const index = (id) => nodes.findIndex((node) => node.id === id);
  assert.ok(index("key-scan-status") < index("key-scan-video"), "status is not before the video");
  assert.ok(index("key-scan-video") < index("key-scan-stop"), "video is not before the actions");
  assert.ok(index("key-scan-stop") < index("key-scan-photo-note"), "actions are not before the photo note");
  assert.ok(index("key-scan-photo-note") < index("key-scan-confirm"), "photo note is not before the confirmation");
});

test("a denied camera explains the browser permission and the photo fallback", () => {
  const ctx = setup();
  openPanel(ctx);
  ctx.created.scannerArgs.onStatus("denied");
  assert.equal(stateOf(ctx), "denied");
  assert.equal(findById(ctx.host, "key-scan-resume").hidden, false);
  assert.equal(findById(ctx.host, "key-scan-photo-open").hidden, false);
});

test("every visible string goes through translate", () => {
  const ctx = setup({ translate: (text) => "⟦" + text + "⟧" });
  const wrapped = (id) => {
    const text = findById(ctx.host, id).textContent;
    return text.startsWith("⟦") && text.endsWith("⟧");
  };
  for (const id of ["key-scan-open", "key-scan-stop", "key-scan-resume", "key-scan-photo-open", "key-scan-cancel", "key-scan-photo-note"]) {
    assert.ok(wrapped(id), `${id} was not translated`);
  }
  openPanel(ctx);
  assert.ok(wrapped("key-scan-status"), "the status line was not translated");
  ctx.created.scannerArgs.onResult(bytesOf(WIF));
  assert.ok(wrapped("key-scan-status"), "the WIF status was not translated");
  for (const id of ["key-scan-confirm-intro", "key-scan-reveal", "key-scan-continue", "key-scan-discard"]) {
    assert.ok(wrapped(id), `${id} was not translated`);
  }
});

test("hodlKeyScanSelectWif checks the WIF radio and fires one change", async () => {
  const { hodlKeyScanSelectWif } = await loadAppFunctions(["hodlKeyScanSelectWif"]);
  const realDocument = globalThis.document;
  const makeRadio = (checked) => {
    const events = [];
    return {
      checked,
      events,
      dispatchEvent(event) {
        events.push(event);
        return true;
      },
    };
  };
  try {
    const unchecked = makeRadio(false);
    globalThis.document = { querySelector: () => unchecked };
    hodlKeyScanSelectWif();
    assert.equal(unchecked.checked, true);
    assert.equal(unchecked.events.length, 1);
    assert.equal(unchecked.events[0].type, "change");
    assert.equal(unchecked.events[0].bubbles, true);

    const checked = makeRadio(true);
    globalThis.document = { querySelector: () => checked };
    hodlKeyScanSelectWif();
    assert.equal(checked.checked, true);
    assert.equal(checked.events.length, 0);

    globalThis.document = { querySelector: () => null };
    assert.throws(() => hodlKeyScanSelectWif(), /WIF key type is missing/);
  } finally {
    globalThis.document = realDocument;
  }
});

test("the app wires the scan panel behind the preview flag", () => {
  const app = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");
  // The host is rendered only when the preview flag is set.
  assert.match(app, /function hodlKeyScanHostMarkup\(\) \{\s*return typeof __ENTROPYLAB_PREVIEW__ !== "undefined" && __ENTROPYLAB_PREVIEW__ \? '<div id="key-scan-host"><\/div>' : "";\s*\}/);
  // It sits after the private-key shell and before the keyboard host.
  assert.match(app, /<\/textarea><\/div>\$\{hodlKeyScanHostMarkup\(\)\}<div class="passphrase-keyboard-host" id="private-keyboard-host" hidden>/);
  // The import sits inside the same guard, so release builds never load it.
  const start = app.indexOf("function hodlBindKeyScan()");
  assert.ok(start >= 0, "hodlBindKeyScan is missing");
  const body = app.slice(start, app.indexOf("\n}\n", start));
  assert.match(body, /if \(typeof __ENTROPYLAB_PREVIEW__ !== "undefined" && __ENTROPYLAB_PREVIEW__\) \{/);
  assert.ok(body.indexOf('import("./qr-key-scan.js")') > body.indexOf("typeof __ENTROPYLAB_PREVIEW__"), "the import is outside the preview guard");
  // A scan is written as a WIF whatever key type is selected (#1291 gate).
  assert.match(body, /beforeWrite: hodlKeyScanSelectWif,/);
  // The wipes drop the panel and retire its decoder.
  const wipeStart = app.indexOf("let clearSecretFields = () => {");
  assert.ok(wipeStart >= 0, "clearSecretFields is missing");
  const wipe = app.slice(wipeStart, app.indexOf("\n  };", wipeStart));
  assert.match(wipe, /try \{ hodlKeyScan\?\.destroy\(\); \} catch \{\}/);
  assert.match(wipe, /hodlKeyScan = null;/);
  assert.match(wipe, /try \{ hodlKeyScanModule\?\.retireQrDecoders\(\); \} catch \{\}/);
  // The wipe re-mounts the panel after retiring the decoders.
  const destroyAt = wipe.indexOf("hodlKeyScan?.destroy()");
  const retireAt = wipe.indexOf("hodlKeyScanModule?.retireQrDecoders()");
  const remountAt = wipe.indexOf("hodlBindKeyScan();");
  assert.ok(destroyAt >= 0 && retireAt > destroyAt && remountAt > retireAt, "the wipe does not re-mount the panel after retiring the decoders");
});

test("a Standard SeedQR in seed mode confirms, then Continue hands over the indices", () => {
  const calls = [];
  let captured = null;
  const ctx = setup({
    accept: "seed",
    idPrefix: "seed-scan",
    wordlist: bip39English,
    classify: (bytes) => {
      captured = classifyQrPayload(bytes);
      return captured;
    },
    onSeed: (indices, count) => {
      calls.push({ values: Array.from(indices), count });
      indices.fill(0);
    },
  });
  openSeedPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf(SEEDQR));
  assert.equal(stateOfSeed(ctx), "seed");
  assert.equal(findById(ctx.host, "seed-scan-confirm").hidden, false);
  // Copy is not pinned (AGENTS.md) except the approved safety phrase.
  assert.match(markupOf(findById(ctx.host, "seed-scan-confirm-intro")), /cannot tell where a QR came from/);
  // While the confirmation is pending, no acquisition control shows (Kimi,
  // autofix review: seed mode kept them).
  assert.equal(findById(ctx.host, "seed-scan-photo-open").hidden, true);
  assert.equal(findById(ctx.host, "seed-scan-cancel").hidden, true);
  assert.ok(captured.indices.every((index) => index === 0), "the classifier's indices were not zeroed");
  findById(ctx.host, "seed-scan-continue").dispatchEvent({ type: "click" });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].count, 12);
  assert.deepEqual(calls[0].values, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
  assert.equal(findById(ctx.host, "seed-scan-panel").hidden, true);
  assert.equal(markupOf(ctx.host).includes("abandon"), false);
});

test("the seed confirmation says when Continue replaces the key's words", () => {
  // DeepSeek red team, round 3: a key that already holds words loses them on
  // Continue. The note shows only then, and a failing check shows it too.
  const noteFor = (replacesSeed) => {
    const ctx = setup({ accept: "seed", idPrefix: "seed-scan", wordlist: bip39English, replacesSeed, onSeed: (indices) => indices.fill(0) });
    openSeedPanel(ctx);
    ctx.created.scannerArgs.onResult(bytesOf(SEEDQR));
    assert.equal(findById(ctx.host, "seed-scan-confirm").hidden, false);
    return findById(ctx.host, "seed-scan-confirm-replace");
  };
  assert.equal(noteFor(() => true).hidden, false, "a key holding words gets the note");
  assert.equal(noteFor(() => false).hidden, true, "an empty key gets none");
  assert.equal(noteFor(() => { throw new Error("state unavailable"); }).hidden, false, "a failing check shows the note");
});

test("words entered after the scan get the note at Continue, and the next Continue loads", () => {
  // GLM, round 4: the note was decided when the QR was read.
  let holds = false;
  const calls = [];
  const ctx = setup({
    accept: "seed",
    idPrefix: "seed-scan",
    wordlist: bip39English,
    replacesSeed: () => holds,
    onSeed: (indices, count) => {
      calls.push(count);
      indices.fill(0);
    },
  });
  openSeedPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf(SEEDQR));
  const note = findById(ctx.host, "seed-scan-confirm-replace");
  assert.equal(note.hidden, true);
  holds = true;
  findById(ctx.host, "seed-scan-continue").dispatchEvent({ type: "click" });
  assert.equal(calls.length, 0, "the first Continue only shows the note");
  assert.equal(note.hidden, false);
  findById(ctx.host, "seed-scan-continue").dispatchEvent({ type: "click" });
  assert.deepEqual(calls, [12], "the next Continue loads the words");
});

test("the app tells the seed panel when the key already holds words", () => {
  const source = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");
  assert.match(source, /onSeed: hodlSeedScanLoad,\n\s*replacesSeed: hodlSeedScanReplaces,/);
  const start = source.indexOf("function hodlSeedScanReplaces(");
  const body = source.slice(start, source.indexOf("\nfunction ", start + 1));
  assert.match(body, /hodlSecureSeedHasWords\(hodlSecureKeyOf\(state\)\)/, "secure words count");
  assert.match(body, /state\.fields\?\.seed/, "typed words count");
  const load = source.slice(source.indexOf("function hodlSeedScanLoad("), source.indexOf("\nfunction ", source.indexOf("function hodlSeedScanLoad(") + 1));
  assert.match(load, /state\.dplusLastWord = "";/, "the D++ final word goes with the old length");
});

test("Review words one by one shows one word at a time and turns the toggle off on a move", () => {
  const ctx = setup({ accept: "seed", idPrefix: "seed-scan", wordlist: bip39English });
  openSeedPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf(SEEDQR));
  findById(ctx.host, "seed-scan-review").dispatchEvent({ type: "click" });
  const heading = findById(ctx.host, "seed-scan-review-heading");
  const word = findById(ctx.host, "seed-scan-review-word");
  const show = findById(ctx.host, "seed-scan-review-show");
  const prev = findById(ctx.host, "seed-scan-review-prev");
  const next = findById(ctx.host, "seed-scan-review-next");
  // Copy is not pinned (AGENTS.md; GLM, #1364): the heading is checked for
  // presence, the position by the controls and the word shown.
  assert.ok(heading.textContent.trim());
  assert.equal(show.getAttribute("aria-pressed"), "false");
  assert.equal(markupOf(word).includes("abandon"), false);
  assert.equal(prev.disabled, true);
  assert.equal(next.disabled, false);
  show.dispatchEvent({ type: "click" });
  assert.equal(show.getAttribute("aria-pressed"), "true");
  assert.ok(markupOf(word).includes("abandon"));
  assert.equal(markupOf(word).includes("about"), false);
  next.dispatchEvent({ type: "click" });
  assert.equal(show.getAttribute("aria-pressed"), "false");
  assert.equal(markupOf(word).includes("abandon"), false);
  // A conceal hides the shown word and keeps the confirmation, as for a WIF
  // (Astra, GLM, Kimi, DeepSeek, #1364: clearing it left a dead panel).
  show.dispatchEvent({ type: "click" });
  assert.ok(markupOf(word).includes("abandon"));
  ctx.doc.dispatch("hodl:conceal");
  assert.equal(show.getAttribute("aria-pressed"), "false");
  assert.equal(markupOf(word).includes("abandon"), false);
  assert.equal(findById(ctx.host, "seed-scan-confirm").hidden, false);
  assert.equal(findById(ctx.host, "seed-scan-continue").hidden, false);
  for (let i = 0; i < 10; i += 1) next.dispatchEvent({ type: "click" });
  assert.equal(next.disabled, true);
  assert.equal(prev.disabled, false);
  show.dispatchEvent({ type: "click" });
  assert.ok(markupOf(word).includes("about"));
  assert.equal(markupOf(word).includes("abandon"), false);
});

test("seed mode refuses a WIF and an unknown payload without calling onSeed", () => {
  let seeds = 0;
  const ctx = setup({ accept: "seed", idPrefix: "seed-scan", wordlist: bip39English, onSeed: () => { seeds += 1; } });
  openSeedPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf(WIF));
  // The refusals are DRAFT copy: tests hook on the state, never the words.
  assert.equal(stateOfSeed(ctx), "key");
  assert.equal(seeds, 0);
  ctx.created.scannerArgs.onResult(bytesOf("SECRETBYTES"));
  assert.equal(stateOfSeed(ctx), "not-a-seed");
  assert.equal(markupOf(ctx.host).includes("SECRETBYTES"), false);
  assert.equal(seeds, 0);
});

test("beforeOpen can refuse the open, and open() skips it", async () => {
  let calls = 0;
  const ctx = setup({
    accept: "seed",
    idPrefix: "seed-scan",
    wordlist: bip39English,
    beforeOpen: async () => {
      calls += 1;
      return false;
    },
  });
  findById(ctx.host, "seed-scan-open").dispatchEvent({ type: "click" });
  await tick();
  assert.equal(calls, 1);
  assert.equal(findById(ctx.host, "seed-scan-panel").hidden, true);
  assert.equal(ctx.created.scanners, 0);
  ctx.panel.open();
  assert.equal(findById(ctx.host, "seed-scan-panel").hidden, false);
  assert.equal(calls, 1);
  assert.equal(ctx.created.scanners, 1);
});

test("Discard and destroy zero the held seed indices", () => {
  const originalFill = Uint16Array.prototype.fill;
  const fills = [];
  Uint16Array.prototype.fill = function (...args) {
    fills.push({ array: this, before: Array.from(this), args });
    return originalFill.apply(this, args);
  };
  try {
    const discarded = setup({ accept: "seed", idPrefix: "seed-scan", wordlist: bip39English });
    openSeedPanel(discarded);
    discarded.created.scannerArgs.onResult(bytesOf(SEEDQR));
    const beforeDiscard = fills.filter((call) => call.array.length === 12 && call.before[11] === 3 && call.args[0] === 0).length;
    findById(discarded.host, "seed-scan-discard").dispatchEvent({ type: "click" });
    const afterDiscard = fills.filter((call) => call.array.length === 12 && call.before[11] === 3 && call.args[0] === 0).length;
    assert.ok(afterDiscard > beforeDiscard, "Discard did not zero the panel's copy");

    const destroyed = setup({ accept: "seed", idPrefix: "seed-scan", wordlist: bip39English });
    openSeedPanel(destroyed);
    destroyed.created.scannerArgs.onResult(bytesOf(SEEDQR));
    const beforeDestroy = fills.filter((call) => call.array.length === 12 && call.before[11] === 3 && call.args[0] === 0).length;
    destroyed.panel.destroy();
    const afterDestroy = fills.filter((call) => call.array.length === 12 && call.before[11] === 3 && call.args[0] === 0).length;
    assert.ok(afterDestroy > beforeDestroy, "destroy() did not zero the panel's copy");
  } finally {
    Uint16Array.prototype.fill = originalFill;
  }
});

test("seed mode uses seed-scan ids and WIF mode keeps key-scan ids", () => {
  const seed = setup({ accept: "seed", idPrefix: "seed-scan", wordlist: bip39English });
  assert.ok(findById(seed.host, "seed-scan-open"));
  assert.equal(findById(seed.host, "key-scan-open"), null);
  const wif = setup();
  assert.ok(findById(wif.host, "key-scan-open"));
  assert.equal(findById(wif.host, "seed-scan-open"), null);
});
