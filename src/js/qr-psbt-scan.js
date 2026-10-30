// The PSBT scan panel (preview builds only). It owns the panel's DOM, one
// decoder, one camera scanner and one payload reader; the PSBT field belongs
// to the caller. A scan is only ever offered to the field: nothing is written
// until the field is empty or the user chooses Replace, and a payload that is
// not a PSBT is refused with nothing loaded.
//
// Security contract: only bytes that start with the PSBT magic are ever
// written to the field; every scanned buffer is zeroed as soon as it has been
// written or discarded, and a pending scan is dropped on conceal, close and
// destroy().

import { createQrDecoder, retireQrDecoders } from "./qr-scan.js";
import { createQrScanner } from "./qr-scanner.js";
import { createPsbtQrReader } from "./psbt-qr-payload.js";
import { QR_WASM_B64 } from "./qr-wasm-b64.js";

export { retireQrDecoders };

const defaultWasmBytes = () => Uint8Array.from(atob(QR_WASM_B64), (character) => character.charCodeAt(0));

const STATUS_TEXT = {
  scanning: "Point the camera at the PSBT QR code.",
  "two-codes": "Two different QR codes are in view, so the scan was refused. Show one code only and try again.",
  timeout: "No QR code was found, so the camera stopped.",
  stopped: "The camera is off.",
  unsupported: "This browser cannot open the camera here.",
  denied: "Camera access was blocked. Check this browser's camera permissions.",
  "no-camera": "No camera was found.",
  error: "The scan failed. Nothing was loaded.",
  "not-psbt": "This QR is not a PSBT.",
  mismatch: "Parts from two different QR codes; start again.",
  "too-large": "This QR is too large to load.",
  "bad-part": "This QR could not be read as a PSBT.",
  confirm: "Replace the PSBT in the field?",
  loaded: "PSBT loaded from the camera ({n} bytes).",
  kept: "The scan was discarded; the field was not changed.",
};

const toBase64 = (bytes) => {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
};

export function mountPsbtScan(host, {
  field,
  translate = (text) => text,
  onLoad = () => {},
  createDecoder = createQrDecoder,
  createScanner = createQrScanner,
  wasmBytes = defaultWasmBytes,
  doc = document,
  win = window,
} = {}) {
  // A translation may or may not fill {placeholders}; fill any it leaves.
  const say = (text, vars) => {
    const translated = String(translate(text, vars) ?? "");
    if (!vars) return translated;
    return translated.replace(/\{(\w+)\}/g, (match, name) => (Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : match));
  };

  const make = (tag, props) => {
    const node = doc.createElement(tag);
    if (props) for (const name of Object.keys(props)) {
      const value = props[name];
      if (name === "text") node.textContent = value;
      else if (name === "class") node.className = value;
      else if (name === "hidden") node.hidden = !!value;
      else node.setAttribute(name, value);
    }
    return node;
  };

  // Ids are prefixed with the host's id so three panels can coexist.
  const prefix = String(host.id ?? "");
  const openRow = make("div", { class: "row tool-actions" });
  const openButton = make("button", { type: "button", class: "btn secondary", id: `${prefix}-open`, "aria-expanded": "false", "aria-controls": `${prefix}-panel`, text: say("Scan PSBT QR") });
  const panel = make("div", { id: `${prefix}-panel`, hidden: true });
  const statusLine = make("p", { class: "field-note", id: `${prefix}-status`, role: "status", "aria-live": "polite" });
  const progressLine = make("p", { class: "field-note", id: `${prefix}-progress`, "aria-live": "polite", hidden: true });
  const video = make("video", { id: `${prefix}-video`, playsinline: "", muted: "", "aria-hidden": "true", hidden: true });
  const canvas = make("canvas", { id: `${prefix}-canvas`, hidden: true });
  const controls = make("div", { class: "row tool-actions" });
  const stopButton = make("button", { type: "button", class: "btn secondary", id: `${prefix}-stop`, hidden: true, text: say("Stop camera") });
  const closeButton = make("button", { type: "button", class: "btn secondary", id: `${prefix}-close`, text: say("Close") });
  const confirm = make("div", { id: `${prefix}-confirm`, hidden: true });
  const confirmText = make("p", { class: "field-note", id: `${prefix}-confirm-text`, text: say(STATUS_TEXT.confirm) });
  const confirmActions = make("div", { class: "row tool-actions" });
  const replaceButton = make("button", { type: "button", class: "btn primary", id: `${prefix}-replace`, text: say("Replace") });
  const keepButton = make("button", { type: "button", class: "btn secondary", id: `${prefix}-keep`, text: say("Keep") });

  confirmActions.appendChild(replaceButton);
  confirmActions.appendChild(keepButton);
  confirm.appendChild(confirmText);
  confirm.appendChild(confirmActions);
  controls.appendChild(stopButton);
  controls.appendChild(closeButton);
  panel.appendChild(statusLine);
  panel.appendChild(progressLine);
  panel.appendChild(video);
  panel.appendChild(canvas);
  panel.appendChild(controls);
  panel.appendChild(confirm);
  openRow.appendChild(openButton);
  host.replaceChildren(openRow, panel);

  const reader = createPsbtQrReader();
  let decoder = null;
  let scanner = null;
  let open = false;
  let destroyed = false;
  let cameraRunning = false;
  let pending = null;

  const updateAcquisition = () => {
    const acquiring = open && !pending;
    video.hidden = !(acquiring && cameraRunning);
    stopButton.hidden = !(acquiring && cameraRunning);
  };

  const showStatus = (code, vars) => {
    const key = Object.prototype.hasOwnProperty.call(STATUS_TEXT, code) ? code : "error";
    statusLine.setAttribute("data-scan-state", key);
    statusLine.textContent = say(STATUS_TEXT[key], vars);
    cameraRunning = key === "scanning" || key === "two-codes";
    updateAcquisition();
  };

  const updateProgress = () => {
    const progress = reader.progress();
    if (!progress) {
      progressLine.hidden = true;
      progressLine.textContent = "";
      return;
    }
    progressLine.hidden = false;
    progressLine.textContent = say("{received} of {total} parts", { received: progress.received, total: progress.total });
  };

  const dropPending = () => {
    const bytes = pending;
    pending = null;
    confirm.hidden = true;
    try { bytes?.fill?.(0); } catch {}
  };

  const write = (bytes) => {
    let text = null;
    try {
      text = toBase64(bytes);
    } catch {
      text = null;
    }
    let event = null;
    try {
      const InputEventCtor = (win && win.InputEvent) || globalThis.InputEvent;
      event = new InputEventCtor("input", { bubbles: true, inputType: "insertFromPaste" });
    } catch {
      event = null;
    }
    if (text == null || !event) {
      try { bytes.fill(0); } catch {}
      pending = null;
      confirm.hidden = true;
      showStatus("error");
      return;
    }
    const length = bytes.length;
    try {
      field.value = text;
      field.dispatchEvent(event);
    } catch {
      try { bytes.fill(0); } catch {}
      pending = null;
      confirm.hidden = true;
      showStatus("error");
      return;
    }
    try { bytes.fill(0); } catch {}
    pending = null;
    confirm.hidden = true;
    try { onLoad?.(); } catch {}
    progressLine.hidden = true;
    showStatus("loaded", { n: length });
  };

  const onComplete = (bytes) => {
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
      try { bytes?.fill?.(0); } catch {}
      showStatus("error");
      return;
    }
    try { scanner?.stop(); } catch {}
    progressLine.hidden = true;
    if (String(field.value ?? "") !== "") {
      pending = bytes;
      confirm.hidden = false;
      showStatus("confirm");
      return;
    }
    write(bytes);
  };

  const restartCamera = () => {
    if (destroyed || !open || pending) return;
    if (!ensureScanner()) return;
    try {
      scanner.start();
    } catch {
      showStatus("error");
    }
  };

  const onResult = (payload) => {
    // A result that arrives after the panel closed (or was destroyed) is
    // scrubbed and ignored.
    if (destroyed || !open) {
      try { payload?.fill?.(0); } catch {}
      return;
    }
    if (!(payload instanceof Uint8Array)) {
      showStatus("error");
      return;
    }
    let text = null;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(payload);
    } catch {
      text = null;
    } finally {
      try { payload.fill(0); } catch {}
    }
    if (text == null) {
      showStatus("not-psbt");
      return;
    }
    let result = null;
    try {
      result = reader.receive(text);
    } catch {
      result = null;
    }
    if (!result || typeof result !== "object") {
      showStatus("error");
      return;
    }
    if (result.status === "complete") {
      onComplete(result.bytes);
      return;
    }
    if (result.status === "partial") {
      updateProgress();
      restartCamera();
      return;
    }
    if (result.status === "done") return;
    const code = result.status === "wrong-type" ? "not-psbt" : result.status === "bad-cbor" ? "bad-part" : result.status;
    showStatus(code);
  };

  const onStatus = (code) => {
    if (destroyed || !open) return;
    showStatus(code);
  };

  const ensureScanner = () => {
    if (scanner) return true;
    try {
      if (!decoder) decoder = createDecoder({ wasmBytes: wasmBytes() });
      scanner = createScanner({ decoder, video, canvas, onResult, onStatus });
      return true;
    } catch {
      showStatus("error");
      return false;
    }
  };

  const openPanel = () => {
    if (open || destroyed) return;
    open = true;
    panel.hidden = false;
    openButton.setAttribute("aria-expanded", "true");
    reader.reset();
    progressLine.hidden = true;
    if (!ensureScanner()) return;
    showStatus("scanning");
    try {
      scanner.start();
    } catch {
      showStatus("error");
    }
  };

  const closePanel = () => {
    if (!open) return;
    open = false;
    try { scanner?.stop(); } catch {}
    panel.hidden = true;
    openButton.setAttribute("aria-expanded", "false");
    dropPending();
    progressLine.hidden = true;
    reader.reset();
    cameraRunning = false;
    updateAcquisition();
  };

  const onVisibility = () => {
    if (doc.visibilityState !== "hidden") return;
    try { scanner?.stop(); } catch {}
    dropPending();
    cameraRunning = false;
    updateAcquisition();
    if (open) showStatus("stopped");
  };

  // The app's leave signal: the same teardown as a hidden page, without the
  // visibility test.
  const onConceal = () => {
    try { scanner?.stop(); } catch {}
    dropPending();
    cameraRunning = false;
    updateAcquisition();
    if (open) showStatus("stopped");
  };

  openButton.addEventListener("click", () => {
    if (open) closePanel();
    else openPanel();
  });
  stopButton.addEventListener("click", () => {
    try { scanner?.stop(); } catch {}
  });
  closeButton.addEventListener("click", () => {
    closePanel();
    try { openButton.focus(); } catch {}
  });
  replaceButton.addEventListener("click", () => {
    const bytes = pending;
    if (!bytes) return;
    write(bytes);
  });
  keepButton.addEventListener("click", () => {
    const bytes = pending;
    pending = null;
    confirm.hidden = true;
    try { bytes?.fill?.(0); } catch {}
    showStatus("kept");
  });
  doc.addEventListener("visibilitychange", onVisibility);
  doc.addEventListener("hodl:conceal", onConceal);

  const destroy = () => {
    if (destroyed) return;
    destroyed = true;
    try { scanner?.stop(); } catch {}
    try {
      const stopping = decoder?.stop();
      if (stopping && typeof stopping.catch === "function") stopping.catch(() => {});
    } catch {}
    scanner = null;
    decoder = null;
    dropPending();
    try { reader.reset(); } catch {}
    try { doc.removeEventListener("visibilitychange", onVisibility); } catch {}
    try { doc.removeEventListener("hodl:conceal", onConceal); } catch {}
    try { host.replaceChildren(); } catch {}
  };

  updateAcquisition();

  return { destroy };
}
