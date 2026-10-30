// The Key Station's "Scan QR" panel (preview builds only). It owns the panel's
// DOM, one decoder and one camera scanner; the private-key field belongs to
// the caller. A scan is only ever offered to the field: nothing is written
// until Continue, and a seed or an unknown payload is refused with nothing
// loaded.
//
// Security contract: only a payload the classifier reports as a WIF private
// key is ever shown or offered to the field; every payload buffer and every
// seed index buffer is zeroed as soon as it has been classified; the WIF text
// lives in a closure (never in the DOM while concealed) and is dropped on
// Continue, Discard, conceal-on-leave and destroy().

import { createQrDecoder, retireQrDecoders } from "./qr-scan.js";
import { createQrScanner } from "./qr-scanner.js";
import { classifyQrPayload } from "./qr-payload.js";
import { QR_WASM_B64 } from "./qr-wasm-b64.js";

export { retireQrDecoders };

const defaultWasmBytes = () => Uint8Array.from(atob(QR_WASM_B64), (character) => character.charCodeAt(0));

const STATUS_TEXT = {
  scanning: "Point the camera at the QR code.",
  "two-codes": "Two different QR codes are in view, so the scan was refused. Nothing was loaded. Show one code only and try again.",
  timeout: "No QR code was found, so the camera stopped.",
  stopped: "The camera is off.",
  unsupported: "This browser cannot open the camera here. You can scan a photo instead.",
  denied: "Camera access was blocked. Check this browser's camera permissions, or scan a photo instead.",
  "no-camera": "No camera was found. You can scan a photo instead.",
  error: "The scan failed. Nothing was loaded.",
  wif: "WIF private key scanned. Review it before continuing.",
};

const CONFIRM_TEMPLATE = "{format}. Scanning cannot tell where a QR came from. If this QR is not from your own backup, it derives someone else's wallet.";
const PHOTO_NOTE = "A photo of this QR is a copy of the secret. The camera app, photo library, cloud sync or thumbnails may keep it. Prefer the live camera. If you use a photo, delete it, including from the recently deleted folder or trash. Other copies may remain.";
const SEED_REFUSAL = "This QR contains a seed. Only WIF private keys can be scanned here. Nothing was loaded.";
const NOT_A_KEY_REFUSAL = "This QR does not hold a WIF private key. Nothing was loaded.";
const NO_CODE_IN_PHOTO = "No QR code was found in this photo.";
const PHOTO_ERROR_TEXT = {
  TOO_LARGE: "This image is too large. The limit is 10 MB.",
  UNSUPPORTED_TYPE: "Use a PNG, JPEG, WebP or BMP image.",
  UNREADABLE: "This image could not be read.",
};
const PHOTO_ERROR_STATE = {
  TOO_LARGE: "too-large",
  UNSUPPORTED_TYPE: "unsupported-type",
  UNREADABLE: "unreadable",
};

export function mountKeyScan(host, {
  keyField,
  translate = (text) => text,
  privateValue = () => "",
  beforeWrite = () => {},
  createDecoder = createQrDecoder,
  createScanner = createQrScanner,
  classify = classifyQrPayload,
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

  // Layout follows docs/UI_Patterns.md: action rows are `.row.tool-actions`,
  // buttons are `.btn` variants, and the secret warnings are red edge notes.
  // Styles live in styles.css (#key-scan-*), including `[hidden]` for `.btn`.
  const openRow = make("div", { class: "row tool-actions" });
  const openButton = make("button", { type: "button", class: "btn secondary", id: "key-scan-open", "aria-expanded": "false", "aria-controls": "key-scan-panel", text: say("Scan QR") });
  const panel = make("div", { id: "key-scan-panel", hidden: true });
  const statusLine = make("p", { class: "field-note", id: "key-scan-status", role: "status", "aria-live": "polite" });
  // Shown only while the camera runs, so an idle or blocked camera leaves no
  // empty frame behind.
  const video = make("video", { id: "key-scan-video", playsinline: "", muted: "", "aria-hidden": "true", hidden: true });
  const canvas = make("canvas", { id: "key-scan-canvas", hidden: true });
  const controls = make("div", { class: "row tool-actions" });
  const stopButton = make("button", { type: "button", class: "btn secondary", id: "key-scan-stop", hidden: true, text: say("Stop camera") });
  const resumeButton = make("button", { type: "button", class: "btn secondary", id: "key-scan-resume", hidden: true, text: say("Resume camera") });
  // A styled button opens the file picker; the browser's own file control
  // stays hidden.
  const photoButton = make("button", { type: "button", class: "btn secondary", id: "key-scan-photo-open", "aria-describedby": "key-scan-photo-note", text: say("Scan a photo instead") });
  const photoInput = make("input", { type: "file", id: "key-scan-photo", accept: "image/png,image/jpeg,image/webp,image/bmp", hidden: true, tabindex: "-1", "aria-hidden": "true" });
  const cancelButton = make("button", { type: "button", class: "btn secondary", id: "key-scan-cancel", text: say("Cancel scan") });
  const photoNote = make("p", { class: "field-note edge-note is-private", id: "key-scan-photo-note", text: say(PHOTO_NOTE) });
  const confirm = make("div", { id: "key-scan-confirm", hidden: true });

  openRow.appendChild(openButton);
  controls.appendChild(stopButton);
  controls.appendChild(resumeButton);
  controls.appendChild(photoButton);
  controls.appendChild(photoInput);
  controls.appendChild(cancelButton);
  panel.appendChild(statusLine);
  panel.appendChild(video);
  panel.appendChild(canvas);
  panel.appendChild(controls);
  panel.appendChild(photoNote);
  panel.appendChild(confirm);
  host.replaceChildren(openRow, panel);

  let decoder = null;
  let scanner = null;
  let text = null;
  let revealed = false;
  let open = false;
  let destroyed = false;
  let cameraUsable = true;
  let cameraRunning = false;
  let cameraResumable = false;
  let op = 0;
  let confirmIntro = null;
  let confirmValue = null;
  let revealButton = null;

  const focusInsideHost = () => {
    let node = doc.activeElement;
    while (node) {
      if (node === host) return true;
      node = node.parentNode;
    }
    return false;
  };

  // The video and Stop show only while frames are read; Resume only once the
  // camera has stopped, can be started again, and the browser can open it.
  // While a confirmation is pending every acquisition control is hidden.
  const updateAcquisition = () => {
    const confirming = !!text;
    const acquiring = open && !confirming;
    const stopWasFocused = doc.activeElement === stopButton;
    const resumeWasFocused = doc.activeElement === resumeButton;
    const nextStop = acquiring && cameraRunning;
    const nextResume = acquiring && cameraResumable && cameraUsable;
    video.hidden = !nextStop;
    stopButton.hidden = !nextStop;
    resumeButton.hidden = !nextResume;
    photoButton.hidden = !acquiring;
    photoNote.hidden = !acquiring;
    cancelButton.hidden = !acquiring;
    // A control that disappears under the keyboard hands focus to its pair.
    if (stopWasFocused && !nextStop && nextResume) {
      try { resumeButton.focus(); } catch {}
    } else if (resumeWasFocused && !nextResume && nextStop) {
      try { stopButton.focus(); } catch {}
    }
  };

  // A refusal or a photo result leaves the camera stopped (a result stops it,
  // and the photo path stops it first), so Resume is offered to scan again.
  const setStatus = (code, value) => {
    statusLine.setAttribute("data-scan-state", code);
    statusLine.textContent = value;
    cameraRunning = false;
    cameraResumable = true;
    updateAcquisition();
  };

  const showStatus = (code) => {
    const key = Object.prototype.hasOwnProperty.call(STATUS_TEXT, code) ? code : "error";
    statusLine.setAttribute("data-scan-state", key);
    statusLine.textContent = say(STATUS_TEXT[key]);
    if (key === "unsupported" || key === "no-camera") cameraUsable = false;
    else if (key === "scanning") cameraUsable = true;
    cameraRunning = key === "scanning" || key === "two-codes";
    cameraResumable = key === "timeout" || key === "stopped" || key === "error" || key === "denied";
    updateAcquisition();
  };

  const clearConfirm = () => {
    text = null;
    revealed = false;
    confirmIntro = null;
    confirmValue = null;
    revealButton = null;
    confirm.replaceChildren();
    confirm.hidden = true;
  };

  // The confirmation is built once per scan; Show key / Hide key and a
  // conceal event only rewrite the value and the button's text, so the
  // focused button is never replaced.
  const updateConfirm = () => {
    if (!text || !confirmValue || !revealButton) return;
    let shown = "";
    try {
      shown = privateValue(text, revealed);
    } catch {
      shown = "";
    }
    // The classifier only reports a WIF whose bytes are all base58, so the
    // app's own display markup cannot carry anything but the key and its
    // conceal dots.
    confirmValue.replaceChildren();
    if (shown && typeof shown === "object" && typeof shown.nodeType === "number") confirmValue.appendChild(shown);
    else confirmValue.innerHTML = String(shown ?? "");
    revealButton.textContent = revealed ? say("Hide key") : say("Show key");
  };

  const buildConfirm = () => {
    confirm.replaceChildren();
    // The approved warning, as the red note for secrets and danger. It is
    // programmatically focusable so a photo result can land on it.
    confirmIntro = make("p", { class: "edge-note is-private", id: "key-scan-confirm-intro", tabindex: "-1", text: say(CONFIRM_TEMPLATE, { format: say("WIF private key") }) });
    confirmValue = make("div", { class: "key-scan-value" });
    revealButton = make("button", { type: "button", class: "btn secondary", id: "key-scan-reveal" });
    revealButton.addEventListener("click", () => {
      if (!text) return;
      revealed = !revealed;
      updateConfirm();
    });
    const continueButton = make("button", { type: "button", class: "btn primary", id: "key-scan-continue", text: say("Continue") });
    continueButton.addEventListener("click", onContinue);
    const discardButton = make("button", { type: "button", class: "btn secondary", id: "key-scan-discard", text: say("Discard scan") });
    discardButton.addEventListener("click", onDiscard);
    const actions = make("div", { class: "row tool-actions" });
    actions.appendChild(revealButton);
    actions.appendChild(continueButton);
    actions.appendChild(discardButton);
    confirm.appendChild(confirmIntro);
    confirm.appendChild(confirmValue);
    confirm.appendChild(actions);
    confirm.hidden = false;
    updateConfirm();
  };

  const closePanel = () => {
    if (!open) return;
    open = false;
    op += 1;
    try { scanner?.stop(); } catch {}
    panel.hidden = true;
    openButton.setAttribute("aria-expanded", "false");
    // Closing drops a pending WIF and any revealed key.
    clearConfirm();
    cameraRunning = false;
    cameraResumable = false;
    updateAcquisition();
  };

  // Continue, Discard scan and Cancel scan all end the panel the same way:
  // invalidate pending work, drop the key, close and return focus to Scan QR.
  const endPanel = () => {
    op += 1;
    clearConfirm();
    closePanel();
    try { openButton.focus(); } catch {}
  };

  const onContinue = () => {
    const value = text;
    if (value == null) return;
    let event = null;
    try {
      const InputEventCtor = (win && win.InputEvent) || globalThis.InputEvent;
      event = new InputEventCtor("input", { bubbles: true, inputType: "insertFromPaste" });
    } catch {
      event = null;
    }
    // Without the paste-like event the field would hold an unvalidated key.
    if (!event) {
      showStatus("error");
      return;
    }
    // The caller may need to put the field in the right mode first: a WIF
    // written into Brain wallet mode would be hashed as a passphrase. A
    // refusal there leaves the field and the confirmation untouched.
    try {
      beforeWrite();
    } catch {
      showStatus("error");
      return;
    }
    try {
      keyField.value = value;
      keyField.dispatchEvent(event);
    } catch {
      showStatus("error");
      return;
    }
    endPanel();
  };

  const onDiscard = () => endPanel();
  const onCancel = () => endPanel();

  const onResult = (payload, source = "camera") => {
    // A result that arrives after the panel closed (or was destroyed) is
    // scrubbed and ignored.
    if (destroyed || !open) {
      try { payload?.fill?.(0); } catch {}
      return;
    }
    const wasInside = focusInsideHost();
    clearConfirm();
    if (!(payload instanceof Uint8Array)) {
      showStatus("error");
      return;
    }
    let result = null;
    try {
      result = classify(payload);
    } catch {
      result = null;
    } finally {
      try { payload.fill(0); } catch {}
    }
    if (!result || typeof result !== "object") result = { format: "unknown" };
    if (result.format === "wif" && typeof result.text === "string" && result.text) {
      text = result.text;
      revealed = false;
      buildConfirm();
      statusLine.setAttribute("data-scan-state", "wif");
      statusLine.textContent = say(STATUS_TEXT.wif);
      cameraRunning = false;
      cameraResumable = false;
      updateAcquisition();
      // A photo result is user-initiated, so it may move focus; a camera
      // result only keeps focus that was already inside the panel.
      if (source === "photo" || wasInside) {
        try { confirmIntro.focus(); } catch {}
      }
      return;
    }
    if (result.indices && typeof result.indices.fill === "function") {
      try { result.indices.fill(0); } catch {}
    }
    if (result.format === "standard-seedqr" || result.format === "compact-seedqr" || result.format === "words") {
      setStatus("seed", say(SEED_REFUSAL));
      return;
    }
    setStatus("not-a-key", say(NOT_A_KEY_REFUSAL));
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
    if (!ensureScanner()) return;
    showStatus("scanning");
    try {
      scanner.start();
    } catch {
      showStatus("error");
    }
  };

  const runPhoto = async (file) => {
    if (!open || destroyed) return;
    if (!scanner) {
      showStatus("error");
      return;
    }
    // A running frame decode makes the decoder refuse with BUSY.
    const token = op;
    try { scanner.stop(); } catch {}
    let reply = null;
    try {
      reply = await scanner.scanImage(file);
    } catch (error) {
      if (token !== op || destroyed) return;
      const code = error && error.code;
      if (Object.prototype.hasOwnProperty.call(PHOTO_ERROR_TEXT, code)) setStatus(PHOTO_ERROR_STATE[code], say(PHOTO_ERROR_TEXT[code]));
      else showStatus("error");
      return;
    }
    // The panel was closed, cancelled or hidden while the photo decoded.
    if (token !== op || destroyed) {
      try { reply?.payload?.fill?.(0); } catch {}
      return;
    }
    const code = reply && reply.code;
    if (Number.isInteger(code) && code > 0) {
      onResult(reply.payload, "photo");
      return;
    }
    try { reply?.payload?.fill?.(0); } catch {}
    // A photo with two codes gets the approved two-codes refusal, not "none".
    setStatus(code === -3 ? "two-codes" : "no-code", say(code === -3 ? STATUS_TEXT["two-codes"] : NO_CODE_IN_PHOTO));
  };

  const onConceal = () => {
    if (!text) return;
    revealed = false;
    updateConfirm();
  };

  const onVisibility = () => {
    if (doc.visibilityState !== "hidden") return;
    op += 1;
    if (text) {
      endPanel();
      return;
    }
    try { scanner?.stop(); } catch {}
  };

  openButton.addEventListener("click", () => {
    if (open) closePanel();
    else openPanel();
  });
  stopButton.addEventListener("click", () => {
    try { scanner?.stop(); } catch {}
  });
  photoButton.addEventListener("click", () => {
    // The camera stops before the file picker opens, so no frame decode is
    // still running when the photo arrives (the decoder would refuse it with
    // BUSY). Resume is offered if the picker is cancelled.
    try { scanner?.stop(); } catch {}
    try { photoInput.click(); } catch {}
  });
  cancelButton.addEventListener("click", onCancel);
  resumeButton.addEventListener("click", () => {
    if (!ensureScanner()) return;
    showStatus("scanning");
    try {
      scanner.start();
    } catch {
      showStatus("error");
    }
  });
  photoInput.addEventListener("change", () => {
    const files = photoInput.files;
    const file = files && files[0] ? files[0] : null;
    try { photoInput.value = ""; } catch {}
    if (file) runPhoto(file);
  });
  doc.addEventListener("hodl:conceal", onConceal);
  doc.addEventListener("visibilitychange", onVisibility);

  const destroy = () => {
    if (destroyed) return;
    destroyed = true;
    op += 1;
    try { scanner?.stop(); } catch {}
    try {
      const stopping = decoder?.stop();
      if (stopping && typeof stopping.catch === "function") stopping.catch(() => {});
    } catch {}
    scanner = null;
    decoder = null;
    clearConfirm();
    try { doc.removeEventListener("hodl:conceal", onConceal); } catch {}
    try { doc.removeEventListener("visibilitychange", onVisibility); } catch {}
    try { host.replaceChildren(); } catch {}
  };

  updateAcquisition();

  return { destroy };
}
