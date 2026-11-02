// One public-text scan panel. It owns the panel's DOM, one decoder, one
// camera scanner and one payload reader; the field belongs to the caller.
// Only a complete public result of this host's kind is written, and only to
// that field. A private key or seed is refused and never repeated.
import { t } from "./i18n.js";
import { createQrDecoder, retireQrDecoders } from "./qr-scan.js";
import { createQrScanner } from "./qr-scanner.js";
import { createTextQrReader, appendRecipient, TEXT_SCAN_KINDS } from "./text-qr-payload.js";
import { QR_WASM_B64 } from "./qr-wasm-b64.js";

export { retireQrDecoders };

const defaultWasmBytes = () => Uint8Array.from(atob(QR_WASM_B64), (character) => character.charCodeAt(0));

const openPanels = new Set();

function defaultIsShown(node) {
  if (node.isConnected === false) return false;
  if (typeof node.checkVisibility === "function") return node.checkVisibility();
  if (typeof node.getClientRects === "function") return node.getClientRects().length > 0;
  return true;
}

const STATUS_TEXT = {
  scanning: () => t("Point the camera at the QR code."),
  "two-codes": () => t("Two different QR codes are in view, so the scan was refused. Nothing was loaded. Show one code only and try again."),
  timeout: () => t("No QR code was found, so the camera stopped."),
  stopped: () => t("The camera is off."),
  unsupported: () => t("This browser cannot open the camera here."),
  denied: () => t("Camera access was blocked. Check this browser's camera permissions."),
  "no-camera": () => t("No camera was found."),
  error: () => t("The scan failed. Nothing was loaded."),
  mismatch: () => t("Parts from two different QR codes; start again."),
  "too-large": () => t("This QR is too large to load."),
  kept: () => t("The scan was discarded; the field was not changed."),
  confirm: () => t("Replace the text in this field with the scanned result?"),
  loaded: () => t("Loaded from the camera."),
  added: () => t("Added from the camera as a new recipient line."),
  "already-listed": () => t("This recipient is already in the list. Nothing was added."),
  "private-key": () => t("This QR contains a private key or seed. Only public data can be scanned here. Nothing was loaded."),
  "unsupported-format": () => t("This QR format cannot be read here. Nothing was loaded. Enter the text in the field instead."),
};

const OPEN_TEXT = {
  lightning: () => t("Scan invoice or offer QR"),
  sp: () => t("Scan recipient QR"),
  "payment-code": () => t("Scan payment code QR"),
  descriptor: () => t("Scan descriptor QR"),
  xpub: () => t("Scan xpub QR"),
};

const WRONG_KIND_TEXT = {
  lightning: () => t("This QR is not a Lightning invoice or offer. Nothing was loaded."),
  sp: () => t("This QR is not a silent payment address. Nothing was loaded."),
  "payment-code": () => t("This QR is not a BIP-47 payment code. Nothing was loaded."),
  descriptor: () => t("This QR is not an output descriptor. Nothing was loaded."),
  xpub: () => t("This QR is not an xpub. Nothing was loaded."),
};

const NAMED_STATES = new Set(["wrong-kind", "private-key", "unsupported-format", "mismatch", "too-large"]);

export function mountTextScan(host, {
  field,
  accept,
  mode = "replace",
  onLoad = () => {},
  createDecoder = createQrDecoder,
  createScanner = createQrScanner,
  wasmBytes = defaultWasmBytes,
  doc = document,
  win = window,
  isShown = defaultIsShown,
} = {}) {
  if (!host || !host.id) throw new Error("A text scan host needs an id.");
  if (!TEXT_SCAN_KINDS.includes(accept)) throw new Error("Unknown text scan kind.");
  if (mode !== "replace" && mode !== "append") throw new Error("Unknown text scan mode.");
  if (mode === "append" && accept !== "sp") throw new Error("Append mode is only for silent-payment recipients.");

  try { host.classList?.add("text-scan-host"); } catch {}

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

  const prefix = String(host.id);
  const openRow = make("div", { class: "row tool-actions" });
  const openButton = make("button", { type: "button", class: "btn secondary", id: `${prefix}-open`, "aria-expanded": "false", "aria-controls": `${prefix}-panel`, text: OPEN_TEXT[accept]() });
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

  const reader = createTextQrReader({ accept });
  let decoder = null;
  let scanner = null;
  let open = false;
  let destroyed = false;
  let cameraRunning = false;
  let pending = null;
  let hiddenTimer = null;

  const updateAcquisition = () => {
    const acquiring = open && pending == null;
    video.hidden = !(acquiring && cameraRunning);
    stopButton.hidden = !(acquiring && cameraRunning);
  };

  const showStatus = (code) => {
    let key = code;
    let text;
    if (code === "wrong-kind") {
      text = WRONG_KIND_TEXT[accept]();
    } else if (Object.prototype.hasOwnProperty.call(STATUS_TEXT, code)) {
      text = STATUS_TEXT[code]();
    } else {
      key = "error";
      text = STATUS_TEXT.error();
    }
    statusLine.setAttribute("data-scan-state", key);
    statusLine.textContent = text;
    if (key === "confirm") confirmText.textContent = STATUS_TEXT.confirm();
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
    progressLine.textContent = t("{received} of {total} parts", { received: progress.received, total: progress.total });
  };

  const dropPending = () => {
    pending = null;
    confirm.hidden = true;
  };

  const concealNow = () => {
    try { scanner?.stop(); } catch {}
    dropPending();
    cameraRunning = false;
    updateAcquisition();
    if (open) showStatus("stopped");
  };

  const disarmHiddenCheck = () => {
    if (hiddenTimer == null) return;
    const id = hiddenTimer;
    hiddenTimer = null;
    try { win?.clearInterval?.(id); } catch {}
  };

  const armHiddenCheck = () => {
    if (hiddenTimer != null || !win || typeof win.setInterval !== "function") return;
    hiddenTimer = win.setInterval(() => {
      if (destroyed || !open) return;
      if (!cameraRunning && pending == null) return;
      let shown = true;
      try { shown = isShown(panel); } catch { shown = true; }
      if (shown === false) concealNow();
    }, 500);
  };

  const write = (value, state) => {
    let event = null;
    try {
      const InputEventCtor = (win && win.InputEvent) || globalThis.InputEvent;
      event = new InputEventCtor("input", { bubbles: true, inputType: "insertFromPaste" });
    } catch {
      event = null;
    }
    if (!event) {
      pending = null;
      confirm.hidden = true;
      showStatus("error");
      return;
    }
    try {
      field.value = value;
      field.dispatchEvent(event);
    } catch {
      pending = null;
      confirm.hidden = true;
      showStatus("error");
      return;
    }
    pending = null;
    confirm.hidden = true;
    try { onLoad(); } catch {}
    showStatus(state);
  };

  const onComplete = (text) => {
    try { scanner?.stop(); } catch {}
    progressLine.hidden = true;
    if (mode === "append") {
      let result = null;
      try {
        result = appendRecipient(field.value, text);
      } catch {
        result = null;
      }
      // Each recipient is its own code. The reader latches one complete;
      // arm it again so the next code is classified, not ignored.
      try { reader.reset(); } catch {}
      if (!result || (result.status !== "ok" && result.status !== "already-listed")) {
        showStatus("error");
        return;
      }
      if (result.status === "already-listed") showStatus("already-listed");
      else write(result.value, "added");
      // The next recipient is another code. A failed write stays stopped.
      if (statusLine.getAttribute("data-scan-state") === "error") return;
      restartCamera();
      if (statusLine.getAttribute("data-scan-state") === "error") return;
      cameraRunning = true;
      updateAcquisition();
      return;
    }
    if (String(field.value ?? "") !== "") {
      pending = text;
      confirm.hidden = false;
      showStatus("confirm");
      return;
    }
    write(text, "loaded");
  };

  const restartCamera = () => {
    if (destroyed || !open || pending != null) return;
    if (!ensureScanner()) return;
    try {
      scanner.start();
    } catch {
      showStatus("error");
    }
  };

  const onResult = (payload) => {
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
      showStatus("wrong-kind");
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
      onComplete(result.text);
      return;
    }
    if (result.status === "partial") {
      updateProgress();
      restartCamera();
      return;
    }
    if (result.status === "done") return;
    if (NAMED_STATES.has(result.status)) {
      showStatus(result.status);
      return;
    }
    showStatus("error");
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

  const closePanel = () => {
    openPanels.delete(closePanel);
    disarmHiddenCheck();
    if (!open) return;
    open = false;
    try { scanner?.stop(); } catch {}
    panel.hidden = true;
    openButton.setAttribute("aria-expanded", "false");
    dropPending();
    progressLine.hidden = true;
    progressLine.textContent = "";
    try { reader.reset(); } catch {}
    cameraRunning = false;
    updateAcquisition();
  };

  const openPanel = () => {
    if (open || destroyed) return;
    for (const close of [...openPanels]) close();
    open = true;
    openPanels.add(closePanel);
    panel.hidden = false;
    openButton.setAttribute("aria-expanded", "true");
    try { reader.reset(); } catch {}
    progressLine.hidden = true;
    progressLine.textContent = "";
    armHiddenCheck();
    if (!ensureScanner()) return;
    showStatus("scanning");
    try {
      scanner.start();
    } catch {
      showStatus("error");
    }
  };

  const onVisibility = () => {
    if (doc.visibilityState !== "hidden") return;
    concealNow();
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
    const text = pending;
    if (text == null) return;
    write(text, "loaded");
  });
  keepButton.addEventListener("click", () => {
    pending = null;
    confirm.hidden = true;
    showStatus("kept");
  });
  doc.addEventListener("visibilitychange", onVisibility);
  doc.addEventListener("hodl:conceal", concealNow);

  const destroy = () => {
    if (destroyed) return;
    destroyed = true;
    open = false;
    openPanels.delete(closePanel);
    disarmHiddenCheck();
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
    try { doc.removeEventListener("hodl:conceal", concealNow); } catch {}
    try { host.replaceChildren(); } catch {}
  };

  updateAcquisition();

  return { destroy };
}
