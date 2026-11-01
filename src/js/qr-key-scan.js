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
// DRAFT (owner OK pending)
const SEED_MODE_KEY_REFUSAL = "This QR contains a private key. Only seeds can be scanned here. Nothing was loaded.";
// DRAFT (owner OK pending)
const SEED_MODE_NOT_A_SEED_REFUSAL = "This QR does not hold a seed. Nothing was loaded.";
// DRAFT (owner OK pending)
const SEED_REPLACE_NOTE = "This key already holds a seed phrase. Continue replaces it.";
const SEED_FORMAT_TEXT = {
  "standard-seedqr": "Standard SeedQR, {count} words",
  "compact-seedqr": "CompactSeedQR, {count} words",
  words: "BIP39 words, {count} words",
};
const SEED_WORD_COUNTS = new Set([12, 15, 18, 21, 24]);
const WORD_DOTS = "••••••";
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
  accept = "wif",
  idPrefix = "key-scan",
  beforeOpen = () => true,
  onSeed = () => {},
  replacesSeed = () => false,
  wordlist = null,
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
  if (accept !== "wif" && accept !== "seed") throw new Error("Unknown scan mode.");
  if (accept === "seed" && (!Array.isArray(wordlist) || wordlist.length !== 2048)) throw new Error("A seed scan needs the 2048-word BIP39 list.");
  const prefix = String(idPrefix);
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
  const openButton = make("button", { type: "button", class: "btn secondary", id: `${prefix}-open`, "aria-expanded": "false", "aria-controls": `${prefix}-panel`, text: say("Scan QR") });
  const panel = make("div", { id: `${prefix}-panel`, hidden: true });
  const statusLine = make("p", { class: "field-note", id: `${prefix}-status`, role: "status", "aria-live": "polite" });
  // Shown only while the camera runs, so an idle or blocked camera leaves no
  // empty frame behind.
  const video = make("video", { id: `${prefix}-video`, playsinline: "", muted: "", "aria-hidden": "true", hidden: true });
  const canvas = make("canvas", { id: `${prefix}-canvas`, hidden: true });
  const controls = make("div", { class: "row tool-actions" });
  const stopButton = make("button", { type: "button", class: "btn secondary", id: `${prefix}-stop`, hidden: true, text: say("Stop camera") });
  const resumeButton = make("button", { type: "button", class: "btn secondary", id: `${prefix}-resume`, hidden: true, text: say("Resume camera") });
  // A styled button opens the file picker; the browser's own file control
  // stays hidden.
  const photoButton = make("button", { type: "button", class: "btn secondary", id: `${prefix}-photo-open`, "aria-describedby": `${prefix}-photo-note`, text: say("Scan a photo instead") });
  const photoInput = make("input", { type: "file", id: `${prefix}-photo`, accept: "image/png,image/jpeg,image/webp,image/bmp", hidden: true, tabindex: "-1", "aria-hidden": "true" });
  const cancelButton = make("button", { type: "button", class: "btn secondary", id: `${prefix}-cancel`, text: say("Cancel scan") });
  const photoNote = make("p", { class: "field-note edge-note is-private", id: `${prefix}-photo-note`, text: say(PHOTO_NOTE) });
  const confirm = make("div", { id: `${prefix}-confirm`, hidden: true });

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
  let openRequest = 0;
  let confirmIntro = null;
  let confirmValue = null;
  let revealButton = null;
  let seedIndicesBuffer = null;
  let seedCount = 0;
  let seedFormat = "";
  let reviewing = false;
  let reviewPosition = 0;
  let reviewRevealed = false;
  let seedReview = null;
  let seedReviewHeading = null;
  let seedReviewWord = null;
  let replaceNote = null;
  let seedReviewShow = null;
  let seedReviewPrev = null;
  let seedReviewNext = null;

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
    const confirming = !!text || !!seedIndicesBuffer;
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
    if (seedIndicesBuffer) {
      try { seedIndicesBuffer.fill(0); } catch {}
    }
    seedIndicesBuffer = null;
    seedCount = 0;
    seedFormat = "";
    reviewing = false;
    reviewPosition = 0;
    reviewRevealed = false;
    seedReview = null;
    seedReviewHeading = null;
    seedReviewWord = null;
    replaceNote = null;
    seedReviewShow = null;
    seedReviewPrev = null;
    seedReviewNext = null;
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
    confirmIntro = make("p", { class: "edge-note is-private", id: `${prefix}-confirm-intro`, tabindex: "-1", text: say(CONFIRM_TEMPLATE, { format: say("WIF private key") }) });
    confirmValue = make("div", { class: "key-scan-value" });
    revealButton = make("button", { type: "button", class: "btn secondary", id: `${prefix}-reveal` });
    revealButton.addEventListener("click", () => {
      if (!text) return;
      revealed = !revealed;
      updateConfirm();
    });
    const continueButton = make("button", { type: "button", class: "btn primary", id: `${prefix}-continue`, text: say("Continue") });
    continueButton.addEventListener("click", onContinue);
    const discardButton = make("button", { type: "button", class: "btn secondary", id: `${prefix}-discard`, text: say("Discard scan") });
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

  const renderSeedReviewWord = () => {
    if (!seedReviewWord) return;
    seedReviewWord.replaceChildren();
    if (!reviewing || !seedIndicesBuffer || reviewPosition < 0 || reviewPosition >= seedCount || !reviewRevealed) {
      seedReviewWord.textContent = WORD_DOTS;
      return;
    }
    const index = seedIndicesBuffer[reviewPosition];
    const word = wordlist[index];
    if (typeof word !== "string") {
      seedReviewWord.textContent = WORD_DOTS;
      return;
    }
    let shown = "";
    try {
      shown = privateValue(word, true);
    } catch {
      shown = "";
    }
    // The app's display markup, as for a WIF (Kimi: as text it showed the
    // markup itself); the word comes from the BIP39 list, letters only.
    if (shown && typeof shown === "object" && typeof shown.nodeType === "number") seedReviewWord.appendChild(shown);
    else seedReviewWord.innerHTML = String(shown ?? "");
  };

  const renderSeedReview = () => {
    if (!seedReview || !seedReviewHeading) return;
    seedReview.hidden = !reviewing;
    if (!reviewing) {
      seedReviewWord?.replaceChildren();
      return;
    }
    seedReviewHeading.textContent = say("Word {n} of {total}", { n: reviewPosition + 1, total: seedCount });
    if (seedReviewPrev) seedReviewPrev.disabled = reviewPosition <= 0;
    if (seedReviewNext) seedReviewNext.disabled = reviewPosition >= seedCount - 1;
    renderSeedReviewWord();
  };

  const openSeedReview = () => {
    if (!seedIndicesBuffer) return;
    reviewing = true;
    reviewPosition = 0;
    reviewRevealed = false;
    if (seedReviewShow) seedReviewShow.setAttribute("aria-pressed", "false");
    renderSeedReview();
    try { seedReviewHeading?.focus(); } catch {}
  };

  const moveSeedReview = (delta) => {
    if (!reviewing) return;
    const next = reviewPosition + delta;
    if (next < 0 || next >= seedCount) return;
    reviewPosition = next;
    reviewRevealed = false;
    if (seedReviewShow) seedReviewShow.setAttribute("aria-pressed", "false");
    renderSeedReview();
    try { seedReviewHeading?.focus(); } catch {}
  };

  // A check that fails counts as holding words: the note shows.
  const keyHoldsWords = () => {
    try { return replacesSeed() !== false; } catch { return true; }
  };

  const onSeedContinue = () => {
    if (!seedIndicesBuffer) return;
    // Words entered after the scan: show the note first; the next Continue
    // replaces them (GLM, round 4).
    if (replaceNote?.hidden && keyHoldsWords()) {
      replaceNote.hidden = false;
      return;
    }
    let copy = null;
    try {
      copy = seedIndicesBuffer.slice(0, seedCount);
      onSeed(copy, seedCount);
    } catch {
      try { copy?.fill(0); } catch {}
      clearConfirm();
      showStatus("error");
      return;
    } finally {
      try { seedIndicesBuffer.fill(0); } catch {}
    }
    endPanel();
  };

  const buildSeedConfirm = () => {
    confirm.replaceChildren();
    confirmIntro = make("p", { class: "edge-note is-private", id: `${prefix}-confirm-intro`, tabindex: "-1", text: say(CONFIRM_TEMPLATE, { format: say(SEED_FORMAT_TEXT[seedFormat], { count: seedCount }) }) });
    seedReview = make("div", { id: `${prefix}-review-panel`, hidden: true });
    seedReviewHeading = make("p", { class: "label", id: `${prefix}-review-heading`, tabindex: "-1" });
    seedReviewWord = make("div", { id: `${prefix}-review-word` });
    seedReviewShow = make("button", { type: "button", class: "btn secondary", id: `${prefix}-review-show`, "aria-pressed": "false", text: say("Show this word") });
    seedReviewShow.addEventListener("click", () => {
      if (!reviewing) return;
      reviewRevealed = !reviewRevealed;
      seedReviewShow.setAttribute("aria-pressed", reviewRevealed ? "true" : "false");
      renderSeedReviewWord();
    });
    seedReviewPrev = make("button", { type: "button", class: "btn secondary", id: `${prefix}-review-prev`, text: say("Previous word") });
    seedReviewPrev.addEventListener("click", () => moveSeedReview(-1));
    seedReviewNext = make("button", { type: "button", class: "btn secondary", id: `${prefix}-review-next`, text: say("Next word") });
    seedReviewNext.addEventListener("click", () => moveSeedReview(1));
    const reviewActions = make("div", { class: "row tool-actions" });
    reviewActions.appendChild(seedReviewPrev);
    reviewActions.appendChild(seedReviewNext);
    seedReview.appendChild(seedReviewHeading);
    seedReview.appendChild(seedReviewWord);
    seedReview.appendChild(seedReviewShow);
    seedReview.appendChild(reviewActions);
    const reviewButton = make("button", { type: "button", class: "btn secondary", id: `${prefix}-review`, text: say("Review words one by one") });
    reviewButton.addEventListener("click", openSeedReview);
    const continueButton = make("button", { type: "button", class: "btn primary", id: `${prefix}-continue`, text: say("Continue") });
    continueButton.addEventListener("click", onSeedContinue);
    const discardButton = make("button", { type: "button", class: "btn secondary", id: `${prefix}-discard`, text: say("Discard scan") });
    discardButton.addEventListener("click", onDiscard);
    const actions = make("div", { class: "row tool-actions" });
    actions.appendChild(reviewButton);
    actions.appendChild(continueButton);
    actions.appendChild(discardButton);
    confirm.appendChild(confirmIntro);
    // Continue replaces the words the key already holds: say so before it.
    // The note is always built and shown when the key holds words; Continue
    // checks again, for words entered after the scan.
    replaceNote = make("p", { class: "edge-note is-private", id: `${prefix}-confirm-replace`, hidden: !keyHoldsWords(), text: say(SEED_REPLACE_NOTE) });
    confirm.appendChild(replaceNote);
    confirm.appendChild(seedReview);
    confirm.appendChild(actions);
    confirm.hidden = false;
    renderSeedReview();
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
    if (accept === "seed") {
      if (result.format === "wif") {
        try { result.text = ""; } catch {}
        setStatus("key", say(SEED_MODE_KEY_REFUSAL));
        return;
      }
      if (result.format === "standard-seedqr" || result.format === "compact-seedqr" || result.format === "words") {
        const count = Number(result.words);
        const indices = result.indices;
        if (!(indices instanceof Uint16Array) || !SEED_WORD_COUNTS.has(count) || indices.length !== count) {
          try { indices?.fill?.(0); } catch {}
          setStatus("not-a-seed", say(SEED_MODE_NOT_A_SEED_REFUSAL));
          return;
        }
        let copy = null;
        try {
          copy = new Uint16Array(count);
          for (let i = 0; i < count; i += 1) {
            const index = indices[i];
            if (!Number.isInteger(index) || index < 0 || index >= 2048) throw new Error("bad index");
            copy[i] = index;
          }
        } catch {
          try { copy?.fill(0); } catch {}
          try { indices.fill(0); } catch {}
          setStatus("not-a-seed", say(SEED_MODE_NOT_A_SEED_REFUSAL));
          return;
        } finally {
          try { indices.fill(0); } catch {}
        }
        seedIndicesBuffer = copy;
        seedCount = count;
        seedFormat = result.format;
        try {
          buildSeedConfirm();
        } catch {
          clearConfirm();
          showStatus("error");
          return;
        }
        statusLine.setAttribute("data-scan-state", "seed");
        statusLine.textContent = "";
        cameraRunning = false;
        cameraResumable = false;
        updateAcquisition();
        if (source === "photo" || wasInside) {
          try { confirmIntro.focus(); } catch {}
        }
        return;
      }
      try { result.indices?.fill?.(0); } catch {}
      setStatus("not-a-seed", say(SEED_MODE_NOT_A_SEED_REFUSAL));
      return;
    }
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
    // As for a WIF, a conceal hides the shown word and keeps the confirmation
    // (Astra, GLM, Kimi, DeepSeek: clearing it left an open panel with every
    // control hidden). Hiding the page still ends the panel (onVisibility).
    if (seedIndicesBuffer) {
      reviewRevealed = false;
      if (seedReviewShow) seedReviewShow.setAttribute("aria-pressed", "false");
      renderSeedReview();
      return;
    }
    if (!text) return;
    revealed = false;
    updateConfirm();
  };

  const onVisibility = () => {
    if (doc.visibilityState !== "hidden") return;
    op += 1;
    if (text || seedIndicesBuffer) {
      endPanel();
      return;
    }
    try { scanner?.stop(); } catch {}
  };

  openButton.addEventListener("click", () => {
    if (open) {
      closePanel();
      return;
    }
    if (destroyed) return;
    const request = ++openRequest;
    let allowed = false;
    try {
      allowed = beforeOpen();
    } catch {
      allowed = false;
    }
    if (allowed && typeof allowed.then === "function") {
      allowed.then((value) => {
        if (destroyed || request !== openRequest || open || !value) return;
        openPanel();
      }).catch(() => {});
      return;
    }
    if (allowed) openPanel();
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

  return { destroy, open: openPanel };
}
