// The PSBT scan panel. It owns the panel's DOM, one
// decoder, one camera scanner and one payload reader; the PSBT field belongs
// to the caller. A scan is only ever offered to the field: nothing is written
// until the field is empty or the user chooses Replace, and a payload that is
// not a PSBT is refused with nothing loaded.
//
// Security contract: only bytes that start with the PSBT magic are ever
// written to the field; every scanned buffer is zeroed as soon as it has been
// written or discarded, and a pending scan is dropped on conceal, close and
// destroy().
// Continuous capture belongs to at most one mounted panel. Ending capture
// invalidates its generation before stopping the scanner, so late results and
// statuses cannot revive it. A visible permission-prompt blur may leave a
// pending request alive only if focus returns before activation; active capture
// still stops on every conceal.

import { t } from "./i18n.js";
import { createQrDecoder, retireQrDecoders } from "./qr-scan.js";
import { createQrScanner } from "./qr-scanner.js";
import { createPsbtQrReader } from "./psbt-qr-payload.js";
import { QR_WASM_B64 } from "./qr-wasm-b64.js";

export { retireQrDecoders };

const defaultWasmBytes = () => Uint8Array.from(atob(QR_WASM_B64), (character) => character.charCodeAt(0));

let activeCapture = null;

// Each status is a thunk: the string is looked up when it is shown, so a
// language switch is honoured, and the catalog sweep still sees the literal.
const STATUS_TEXT = {
  scanning: () => t("Point the camera at the PSBT QR code."),
  "two-codes": () => t("Two different QR codes are in view, so the scan was refused. Show one code only and try again."),
  timeout: () => t("No QR code was found, so the camera stopped."),
  stopped: () => t("The camera is off."),
  unsupported: () => t("This browser cannot open the camera here."),
  denied: () => t("Camera access was blocked. Check this browser's camera permissions."),
  "no-camera": () => t("No camera was found."),
  error: () => t("The scan failed. Nothing was loaded."),
  "not-psbt": () => t("This QR is not a PSBT."),
  mismatch: () => t("Parts from two different QR codes; start again."),
  "too-large": () => t("This QR is too large to load."),
  "bad-part": () => t("This QR could not be read as a PSBT."),
  confirm: () => t("Replace the PSBT in the field?"),
  "field-changed": () => t("The PSBT field changed while confirmation was open. Review it, then choose Replace again or Keep."),
  loaded: (vars) => t("PSBT loaded from the camera ({n} bytes).", vars),
  kept: () => t("The scan was discarded; the field was not changed."),
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
  onLoad = () => {},
  createDecoder = createQrDecoder,
  createScanner = createQrScanner,
  wasmBytes = defaultWasmBytes,
  doc = document,
  win = window,
} = {}) {
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
  const openButton = make("button", { type: "button", class: "btn secondary", id: `${prefix}-open`, "aria-expanded": "false", "aria-controls": `${prefix}-panel`, text: t("Scan PSBT QR") });
  const panel = make("div", { id: `${prefix}-panel`, hidden: true });
  const statusLine = make("p", { class: "field-note", id: `${prefix}-status`, role: "status", "aria-live": "polite" });
  const progressLine = make("p", { class: "field-note", id: `${prefix}-progress`, "aria-live": "polite", hidden: true });
  const video = make("video", { id: `${prefix}-video`, playsinline: "", muted: "", "aria-hidden": "true", hidden: true });
  const canvas = make("canvas", { id: `${prefix}-canvas`, hidden: true });
  const controls = make("div", { class: "row tool-actions" });
  const stopButton = make("button", { type: "button", class: "btn secondary", id: `${prefix}-stop`, hidden: true, text: t("Stop camera") });
  const closeButton = make("button", { type: "button", class: "btn secondary", id: `${prefix}-close`, text: t("Close") });
  const confirm = make("div", { id: `${prefix}-confirm`, hidden: true });
  const confirmText = make("p", { class: "field-note", id: `${prefix}-confirm-text`, text: STATUS_TEXT.confirm() });
  const confirmActions = make("div", { class: "row tool-actions" });
  const replaceButton = make("button", { type: "button", class: "btn primary", id: `${prefix}-replace`, text: t("Replace") });
  const keepButton = make("button", { type: "button", class: "btn secondary", id: `${prefix}-keep`, text: t("Keep") });

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
  let pendingField = null;
  let scanGeneration = 0;
  let liveGeneration = null;
  let awaitingCamera = false;

  const updateAcquisition = () => {
    const acquiring = open && !pending;
    video.hidden = !(acquiring && cameraRunning);
    stopButton.hidden = !(acquiring && cameraRunning);
  };

  const showStatus = (code, vars) => {
    const key = Object.prototype.hasOwnProperty.call(STATUS_TEXT, code) ? code : "error";
    statusLine.setAttribute("data-scan-state", key);
    statusLine.textContent = STATUS_TEXT[key](vars);
    // Recoverable payload refusals change the message, not the live camera.
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
    progressLine.textContent = t("{received} of {total} parts", { received: progress.received, total: progress.total });
  };

  const dropPending = () => {
    const bytes = pending;
    pending = null;
    pendingField = null;
    confirm.hidden = true;
    try { bytes?.fill?.(0); } catch {}
  };

  const clearReader = () => {
    reader.reset();
    progressLine.hidden = true;
    progressLine.textContent = "";
  };

  const releaseSession = () => {
    liveGeneration = null;
    awaitingCamera = false;
    cameraRunning = false;
    if (activeCapture === stopByOther) activeCapture = null;
    clearReader();
    updateAcquisition();
  };

  const stopAcquisition = (code) => {
    releaseSession();
    // Invalidate first: stop() may synchronously emit a status.
    try { scanner?.stop(); } catch {}
    if (code && open && !destroyed) showStatus(code);
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
      pendingField = null;
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
      pendingField = null;
      confirm.hidden = true;
      showStatus("error");
      return;
    }
    try { bytes.fill(0); } catch {}
    pending = null;
    pendingField = null;
    confirm.hidden = true;
    try { onLoad?.(); } catch {}
    progressLine.hidden = true;
    showStatus("loaded", { n: length });
  };

  const onComplete = (bytes) => {
    stopAcquisition();
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
      try { bytes?.fill?.(0); } catch {}
      showStatus("error");
      return;
    }
    progressLine.hidden = true;
    if (String(field.value ?? "") !== "") {
      pending = bytes;
      pendingField = String(field.value ?? "");
      confirm.hidden = false;
      showStatus("confirm");
      return;
    }
    write(bytes);
  };

  const onResult = (payload) => {
    // Closed, stopped, completed and superseded captures never accept a frame.
    const generation = liveGeneration;
    if (destroyed || !open || generation === null || pending) {
      try { payload?.fill?.(0); } catch {}
      return;
    }
    if (!(payload instanceof Uint8Array)) {
      stopAcquisition("error");
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
      stopAcquisition("error");
      return;
    }
    if (generation !== liveGeneration) {
      try { result.bytes?.fill?.(0); } catch {}
      return;
    }
    if (result.status === "complete") {
      onComplete(result.bytes);
      return;
    }
    if (result.status === "partial") {
      updateProgress();
      // The same stream and deadline serve every part.
      return;
    }
    if (result.status === "wrong-type" || result.status === "not-psbt") {
      showStatus("not-psbt");
      return;
    }
    const code = result.status === "bad-cbor" ? "bad-part" : result.status === "done" ? "stopped" : result.status;
    stopAcquisition(code);
  };

  const onStatus = (code) => {
    if (destroyed || !open || liveGeneration === null) return;
    if (code === "scanning") {
      let focused = false;
      try { focused = doc.visibilityState === "visible" && doc.hasFocus() === true; } catch {}
      if (!focused) {
        stopAcquisition("stopped");
        return;
      }
    }
    awaitingCamera = false;
    if (code === "scanning" || code === "two-codes") cameraRunning = true;
    else releaseSession();
    showStatus(code);
  };

  const ensureScanner = () => {
    if (scanner) return true;
    try {
      if (!decoder) decoder = createDecoder({ wasmBytes: wasmBytes() });
      scanner = createScanner({ decoder, video, canvas, onResult, onStatus, continuous: true });
      return true;
    } catch {
      showStatus("error");
      return false;
    }
  };

  const stopByOther = () => {
    if (destroyed || liveGeneration === null) return;
    stopAcquisition("stopped");
  };

  const openPanel = () => {
    if (destroyed || liveGeneration !== null || pending) return;
    // A new capture releases even an unresolved permission request elsewhere.
    activeCapture?.();
    open = true;
    panel.hidden = false;
    openButton.setAttribute("aria-expanded", "true");
    clearReader();
    if (!ensureScanner()) return;
    scanGeneration += 1;
    liveGeneration = scanGeneration;
    activeCapture = stopByOther;
    awaitingCamera = true;
    cameraRunning = true;
    showStatus("scanning");
    try {
      scanner.start();
    } catch {
      stopAcquisition("error");
    }
  };

  const closePanel = () => {
    if (!open) return;
    open = false;
    stopAcquisition();
    panel.hidden = true;
    openButton.setAttribute("aria-expanded", "false");
    dropPending();
    updateAcquisition();
  };

  const onVisibility = () => {
    if (doc.visibilityState !== "hidden") return;
    onConceal();
  };

  // A permission prompt can blur a still-visible page before getUserMedia
  // settles. This exception never covers an active stream or a hidden page.
  const onConceal = (event) => {
    if (event?.detail?.reason === "blur" && awaitingCamera && doc.visibilityState === "visible") return;
    stopAcquisition("stopped");
    dropPending();
    updateAcquisition();
  };

  openButton.addEventListener("click", () => {
    if (open && (liveGeneration !== null || pending)) closePanel();
    else openPanel();
  });
  stopButton.addEventListener("click", () => {
    onConceal();
  });
  closeButton.addEventListener("click", () => {
    closePanel();
    try { openButton.focus(); } catch {}
  });
  replaceButton.addEventListener("click", () => {
    const bytes = pending;
    if (!bytes) return;
    const currentField = String(field.value ?? "");
    if (currentField !== "" && currentField !== pendingField) {
      // A prior confirmation does not authorize overwriting a newer edit.
      // Re-prompt against the current value; another explicit click may replace.
      pendingField = currentField;
      showStatus("field-changed");
      return;
    }
    write(bytes);
  });
  keepButton.addEventListener("click", () => {
    dropPending();
    showStatus("kept");
  });
  doc.addEventListener("visibilitychange", onVisibility);
  doc.addEventListener("hodl:conceal", onConceal);

  const destroy = () => {
    if (destroyed) return;
    destroyed = true;
    // Invalidate before any external stop callback, but also retire the visible
    // status before removing the panel so retained nodes never claim capture.
    releaseSession();
    if (open) showStatus("stopped");
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
