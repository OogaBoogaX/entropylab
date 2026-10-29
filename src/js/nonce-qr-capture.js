import { createQrFrameDecoder } from "./qr-frame-decoder.js";
import { createModal } from "./modal.js";
import { AexbCapture, UrCapture } from "./aexb-capture.js";
import { CameraCapture } from "./qr-camera.js";
// UI state deliberately stays outside the Journal, history and preference stores.
export function initNonceQrCapture({ translate, onClear }) {
  const root = document.getElementById("nonce-qr-capture");
  if (!root) return null;
  const el = (id) => document.getElementById(id),
    video = el("nonce-qr-video"),
    status = el("nonce-qr-status"),
    progress = el("nonce-qr-progress");
  const start = el("nonce-qr-start"),
    stop = el("nonce-qr-stop"),
    select = el("nonce-qr-camera"),
    access = el("nonce-qr-access"),
    clearButton = el("nonce-qr-clear");
  const session = new AexbCapture(),
    transport = new UrCapture(),
    canvas = document.createElement("canvas");
  let completedResult = null;
  const snapshot = () => {
    if (completedResult) return completedResult;
    const state = session.snapshot();
    if (state.verdict?.ok) {
      const transaction = session.checkTransaction();
      return { ...state, transaction, verdict: transaction.ok ? state.verdict : { ok: false, reason: transaction.reason } };
    }
    return state;
  };
  const context = canvas.getContext("2d", { willReadFrequently: true });
  let generation = 0, failureShown = false, accessGranted = false, busy = false, accessStream = null, permissionPending = false;
  const resultModal = createModal({
    id: "nonce-qr-result-modal", className: "",
    card: `<div class="modal-card" id="nonce-qr-result-card" role="alertdialog" aria-modal="true" aria-labelledby="nonce-qr-result-title" aria-describedby="nonce-qr-result-message nonce-qr-result-detail nonce-qr-result-cleared">
      <h3 id="nonce-qr-result-title"></h3>
      <p id="nonce-qr-result-message"></p>
      <p id="nonce-qr-result-detail"></p>
      <p id="nonce-qr-result-cleared"></p>
      <div class="modal-actions"><button class="btn blue" id="nonce-qr-result-clear" type="button"></button></div>
    </div>`,
    focusables: () => [el("nonce-qr-result-clear")],
    // Require deliberate acknowledgement; messages are already wiped even if
    // the user walks away, presses Escape, or clicks the backdrop.
    onDismiss: () => {},
  });
  el("nonce-qr-result-clear").textContent = translate("Clear Capture");
  el("nonce-qr-result-cleared").textContent = translate("Captured messages have already been cleared automatically (best effort). Only this result remains.");
  const clearInstruction = document.createElement("strong");
  clearInstruction.textContent = translate("Click the Clear Capture button now to continue.");
  el("nonce-qr-result-cleared").append(document.createElement("br"), clearInstruction);
  const say = (key, kind = "info") => {
    status.textContent = translate(key);
    status.className = "edge-note is-" + kind;
  };
  const coverage = verdict => translate("Verified {slots} supplied signature(s) on {checked} of {total} transaction inputs (zero-based input indexes: {indexes}). Inputs without supplied slots were not signature-checked; this does not prove every expected signature was supplied.", { slots: verdict.checkedSlots, checked: verdict.checkedInputs.length, total: verdict.totalInputs, indexes: verdict.checkedInputs.join(", ") });
  const showPass = () => {
    say("", "public");
    const heading = document.createElement("h3"), body = document.createElement("p"), next = document.createElement("p");
    heading.textContent = translate("PASS: Anti-exfil checks passed.");
    body.textContent = translate("Protection depends on a correctly operated coordinator and keeping host randomness confidential, even after signing.");
    next.textContent = translate("The supplied signatures verified against signing hashes independently computed from the embedded PSBT. Captured messages have been cleared automatically. You can now scan the same Message 4 from your signer into Sparrow. This is not a broadcast authorization: confirm the destination and amount, and let Sparrow apply its wallet policy and broadcast checks.");
    const action = document.createElement("p"), emphasis = document.createElement("strong");
    emphasis.textContent = translate("Click the Clear Capture button now to continue.");
    action.append(emphasis);
    const detail = document.createElement("p");
    detail.textContent = coverage(completedResult.verdict);
    for (const block of [heading,body,next,detail,action]) block.append(document.createTextNode(" "));
    status.replaceChildren(heading, body, next, detail, action);
  };
  const viewer = el("nonce-qr-viewer"), bars = el("nonce-qr-bars"), scanLabel = el("nonce-qr-scan-label");
  const scanProgress = (have = 0, total = 0) => {
    if (bars.children.length !== total) {
      bars.replaceChildren();
      for (let i = 0; i < total; i++) bars.append(document.createElement("span"));
    }
    for (let i = 0; i < total; i++) bars.children[i].dataset.filled = String(i < have);
    bars.setAttribute("aria-valuemax", String(total || 1));
    bars.setAttribute("aria-valuenow", String(have));
    const label = total
      ? translate("QR pieces: {have} of {total}", { have, total })
      : translate("Point the camera at the QR code.");
    if (scanLabel.textContent !== label) scanLabel.textContent = label;
  };
  const syncControls = () => {
    const state = snapshot(), complete = !!state.verdict;
    const nextStage = [2, 3, 4].find(stage => !state.stages.includes(stage));
    access.disabled = busy || complete;
    access.className = !accessGranted && !access.disabled ? "btn blue" : "btn secondary";
    access.textContent = translate(accessGranted ? "Refresh cameras" : "Allow Camera Access");
    start.disabled = !accessGranted || busy || complete;
    start.className = start.disabled ? "btn secondary" : "btn blue";
    start.textContent = nextStage
      ? translate("Scan Message {stage}", { stage: nextStage })
      : translate("Capture complete");
    stop.disabled = !busy;
    select.disabled = !accessGranted || busy || complete;
    clearButton.className = complete ? "btn blue" : "btn secondary";
  };
  const paint = () => {
    const s = snapshot();
    const failed = s.verdict?.ok === false;
    syncControls();
    status.setAttribute("role", failed ? "alert" : "status");
    if (s.verdict && !failureShown) {
      failureShown = true;
      root.open = true;
      el("nonce-qr-result-card").className = failed ? "modal-card is-warning" : "modal-card";
      el("nonce-qr-result-title").className = failed ? "modal-warning-title" : "psbt-ok";
      el("nonce-qr-result-title").textContent = translate(failed ? "STOP! Do not broadcast!" : "PASS: Anti-exfil checks passed.");
      const finalized = s.verdict.reason === "TRANSACTION_ALREADY_FINALIZED";
      el("nonce-qr-result-message").textContent = translate(finalized
        ? "This PSBT contains an already-finalized input. Refusing it is a conservative limit of this prototype, not a finding of tampering. This observer cannot verify this session. Acknowledging the result does not authorize broadcast."
        : failed
        ? "Do not broadcast this transaction or approve this exchange. Anti-exfil or embedded-transaction verification did not pass. This may indicate tampering, a device fault, incorrect session data, or an unsupported transaction. Acknowledging this warning does not make that exchange safe."
        : "The supplied signatures also verified against the embedded PSBT. Protection depends on a correctly operated coordinator and keeping host randomness confidential, even after signing. You can now scan the same Message 4 from your signer into Sparrow. This is not broadcast authorization: confirm the destination and amount, and let Sparrow apply its wallet policy and broadcast checks.");
      el("nonce-qr-result-detail").textContent = failed
        ? translate("Reason: {reason}. The transcript contains {total} supplied signature(s). No complete verification succeeded.", { reason: s.verdict.reason, total: s.verdict.totalSlots })
        : coverage(s.verdict);
      resultModal.show(el("nonce-qr-result-clear"), clearButton);
    }
    const missing = [2, 3, 4].filter(stage => !s.stages.includes(stage));
    for (const stage of [2, 3, 4]) {
      const captured = s.stages.includes(stage), box = el("nonce-qr-stage-" + stage);
      box.dataset.captured = String(captured);
      box.textContent = translate(captured ? "Message {stage} — captured" : "Message {stage}", { stage });
    }
    el("nonce-qr-remaining").dataset.remaining = String(missing.length);
    el("nonce-qr-remaining").textContent = missing.length
      ? translate("{count} message(s) left to scan: {stages}.", { count: missing.length, stages: missing.join(", ") })
      : translate("All 3 messages checked; captured data cleared automatically. Acknowledge the result before scanning a new exchange.");
    progress.textContent = "";
    if (s.verdict?.ok) showPass();
    else if (failed) say("STOP! Do not broadcast! Anti-exfil or embedded-transaction verification did not pass. Do not approve this exchange. Scanning and transcript use are blocked. Clear capture only after you have stopped the exchange and investigated.", "private");
    else if (s.stages.length) say(translate("Scan successful. Keep going: this signing ceremony still needs message(s) {stages} from the same session. No complete verdict yet.", { stages: missing.join(", ") }));

  };
  const frameDecoder = createQrFrameDecoder();
  const camera = new CameraCapture({
    stopDecode: () => frameDecoder.stop(),
    getUserMedia: (constraints) =>
      navigator.mediaDevices.getUserMedia(constraints),
    decode: async (video) => {
      if (video.readyState < 2 || !video.videoWidth) return null;
      const scale = Math.min(
        1,
        1280 / video.videoWidth,
        960 / video.videoHeight,
      );
      canvas.width = Math.round(video.videoWidth * scale);
      canvas.height = Math.round(video.videoHeight * scale);
      context.drawImage(video, 0, 0, canvas.width, canvas.height);
      const frame = context.getImageData(0, 0, canvas.width, canvas.height);
      context.clearRect(0, 0, canvas.width, canvas.height);
      return frameDecoder.decode(frame.data, frame.width, frame.height);
    },
  });
  const pause = () => {
    generation++;
    permissionPending = false;
    camera.stop();
    video.hidden = true;
    viewer.hidden = true;
    for (const track of accessStream?.getTracks() || []) track.stop();
    accessStream = null;
    busy = false;
    syncControls();
    canvas.width = canvas.height = 0;
  };
  const receive = (raw) => {
    try {
      const result = transport.receive(raw);
      scanProgress(result.received, result.total);
      if (!result.complete) {
        progress.textContent = translate(
          "QR assembly: {have} of {total} recovered fragments",
          { have: result.received, total: result.total },
        );
        return;
      }
      try {
        session.accept(result.bytes);
      } finally {
        result.bytes.fill(0);
      }
      const finished = session.finish();
      if (finished) {
        // Keep only non-secret verdict metadata. Neither the modal nor this latch
        // retains a decoded message, QR text, signature, PSBT, key, or rho.
        completedResult = { stages: [2, 3, 4], verdict: finished };
        onClear();
      }
      pause();
      transport.clear();
      say("Message captured. Scan the next stage when it is displayed.");
      paint();
    } catch {
      // Do not render decoder errors: some include attacker-controlled payloads.
      pause();
      transport.clear();
      scanProgress();
      paint();
      say(
        "This QR was not added: it is invalid or conflicts with the current capture. Completed messages were kept, but partial QR fragments for the current message were discarded. Rescan the whole missing message from the same exchange. If you are switching exchanges or demo scenarios, Clear Capture first.",
      );
    }
  };
  const listCameras = (devices, selected) => {
    select.replaceChildren();
    for (const [index, device] of devices.filter(d => d.kind === "videoinput").entries()) {
      const option = document.createElement("option");
      option.value = device.deviceId;
      option.textContent = device.label || translate("Camera {n}", { n: index + 1 });
      select.append(option);
    }
    if (selected && [...select.options].some(option => option.value === selected)) select.value = selected;
    select.dispatchEvent(new Event("change", { bubbles: true }));
  };
  access.onclick = async () => {
    if (busy || snapshot().verdict) return;
    pause();
    transport.clear();
    scanProgress();
    const current = generation, selected = select.value;
    permissionPending = true;
    busy = true;
    syncControls();
    say("Allow camera access in the browser prompt. This step lists cameras; it does not scan or save images.");
    let stream;
    try {
      if (!navigator.mediaDevices?.getUserMedia) throw Error("camera unavailable");
      stream = await navigator.mediaDevices.getUserMedia({ audio: false, video: true });
      if (current !== generation) return;
      accessStream = stream;
      const devices = await navigator.mediaDevices.enumerateDevices();
      if (current !== generation) return;
      listCameras(devices, selected || stream.getVideoTracks()[0]?.getSettings().deviceId);
      accessGranted = true;
      say("Camera access is ready. Choose your camera, then click the Scan button when the QR is displayed.");
    } catch {
      if (current === generation) {
        accessGranted = false;
        say("Camera access was not granted or the camera is unavailable. Check browser and Windows permissions, then click Allow Camera Access to retry.");
      }
    } finally {
      // Permission is separate from scanning. Never retain a permission-probe stream,
      // including a late result after Stop, Clear, conceal, or pagehide.
      for (const track of stream?.getTracks() || []) track.stop();
      if (current === generation) {
        accessStream = null;
        permissionPending = false;
        busy = false;
        syncControls();
      }
    }
  };
  start.onclick = async () => {
    if (!accessGranted || busy || snapshot().verdict) return;
    pause();
    transport.clear();
    scanProgress();
    const current = generation;
    busy = true;
    syncControls();
    say("Starting the selected camera. No images or transcripts are saved.");
    try {
      if (!navigator.mediaDevices?.getUserMedia)
        throw Error("camera unavailable");
      video.hidden = false;
      viewer.hidden = false;
      if (
        !(await camera.start(video, select.value, receive, (error) => {
          pause();
          transport.clear();
          scanProgress();
          say(error?.code === "CAMERA_DISCONNECTED"
            ? "Camera disconnected. Captured stages were kept. Reconnect the camera and scan this message again."
            : "Camera stopped. Captured stages were kept. Retry or choose another camera.");
        }))
      )
        return;
      if (current !== generation) return;
      say(
        "Scan stage 2 or 4 from the signer, or stage 3 from Sparrow. The camera pauses after each message.",
      );
    } catch (error) {
      if (current === generation) {
        if (error?.name === "NotAllowedError" || error?.name === "SecurityError") accessGranted = false;
        pause();
        say(
          error?.name === "NotReadableError"
            ? "Camera could not start: it may be busy or disconnected. Captured stages were kept. Close other camera apps or reconnect it, then retry."
            : "Camera unavailable or permission denied. Captured stages were kept. Use a secure local browser context and check Windows camera permissions.",
        );
      }
    }
  };
  stop.onclick = () => {
    pause();
    transport.clear();
    scanProgress();
    paint();
    say("Camera stopped. Captured stages remain in memory.");
  };
  const clear = () => {
    pause();
    transport.clear();
    session.clear();
    completedResult = null;
    failureShown = false;
    resultModal.hide({ restoreFocus: false });
    scanProgress();
    onClear();
    paint();
    say(
      "Capture cleared from accessible memory (best effort). Nothing was automatically saved.",
    );
  };
  clearButton.onclick = clear;
  el("nonce-qr-result-clear").onclick = () => {
    clear();
    (accessGranted ? start : access).focus();
  };
  const concealPause = () => {
    if (permissionPending && !document.hidden) return;
    const wasBusy = busy, wasProbe = permissionPending;
    pause();
    transport.clear();
    scanProgress();
    if (!wasBusy) return;
    paint();
    if (wasProbe) say("Camera access was cancelled because the page was hidden. Click Allow Camera Access to retry.");
    else if (!completedResult) say("Camera paused when the page lost focus or was hidden. Captured messages were kept; click the Scan button to resume. Partial QR fragments were discarded. Use Clear Capture to discard the unfinished session.");
  };
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) concealPause();
  });
  // A browser permission popup may blur a visible page without starting a scan.
  document.addEventListener("hodl:conceal", concealPause);
  addEventListener("pagehide", clear);
  paint();
  return { clear };
}
