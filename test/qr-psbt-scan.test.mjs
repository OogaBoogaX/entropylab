// Security contract exercised here: the camera path captures only frames and
// never touches keys/WIF; every scanned buffer is zeroed on write or on
// discard; and the scanner is released on every termination path (complete,
// persistent reader error, stop, close, conceal, document hidden and destroy),
// so late decode results to a stopped/closed/destroyed panel are wiped and
// ignored. Two mounted panels never hold two camera streams at once.
import test from "node:test";
import assert from "node:assert/strict";
import { mountPsbtScan } from "../src/js/qr-psbt-scan.js";
import { createQrScanner } from "../src/js/qr-scanner.js";
import { MiniDocument } from "./mini-dom.mjs";
import { loadAppFunctions } from "./app-slice-harness.mjs";
import {
  hodlCrc32,
  hodlBytewordsEncode,
  hodlCborBstr,
  hodlUrPartCbor,
} from "../src/js/psbt-ur.js";
import {
  findNominalFragmentLength,
  partitionMessage,
  chooseFragments,
} from "../src/js/ur-fountain.js";

const PSBT_HEX = "70736274ff000000";
const PSBT = Uint8Array.from(PSBT_HEX.match(/../g).map((byte) => parseInt(byte, 16)));
const PSBT_BASE64 = Buffer.from(PSBT).toString("base64");
const bytesOf = (text) => new TextEncoder().encode(text);

// The multi-part UR builder test/psbt-qr-payload.test.mjs uses, so the parts
// here are the same shape the collector already accepts.
const crc32Number = (bytes) => {
  const crc = hodlCrc32(bytes);
  return ((crc[0] << 24) | (crc[1] << 16) | (crc[2] << 8) | crc[3]) >>> 0;
};

const xorInto = (target, source) => {
  for (let i = 0; i < target.length; i++) target[i] ^= source[i];
};

const encodeParts = (message, maxFragmentLen, count) => {
  const fragmentLen = findNominalFragmentLength(message.length, 10, maxFragmentLen);
  const fragments = partitionMessage(message, fragmentLen);
  const checksum = crc32Number(message);
  const seqLen = fragments.length;
  const parts = [];
  for (let i = 0; i < count; i++) {
    const seqNum = i + 1;
    const indexes = chooseFragments(seqNum, seqLen, checksum);
    const data = new Uint8Array(fragmentLen);
    for (const index of indexes) xorInto(data, fragments[index]);
    parts.push({ seqNum, seqLen, messageLen: message.length, checksum, data });
  }
  return parts;
};

const partUr = (part) =>
  "ur:crypto-psbt/" + part.seqNum + "-" + part.seqLen + "/" +
  hodlBytewordsEncode(hodlUrPartCbor(part.seqNum, part.seqLen, part.messageLen, part.checksum, part.data), "minimal");

class FakeInputEvent {
  constructor(type, init = {}) {
    this.type = type;
    this.bubbles = !!init.bubbles;
    this.inputType = init.inputType ?? "";
  }
}

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

const makeScanner = () => {
  const calls = { start: 0, stop: 0 };
  return {
    calls,
    start() {
      calls.start += 1;
    },
    stop() {
      calls.stop += 1;
    },
  };
};

const setup = (options = {}) => {
  const doc = new MiniDocument();
  const host = doc.createElement("div");
  host.id = options.id || "psbt-scan";
  doc.body.appendChild(host);
  const field = doc.createElement("textarea");
  const events = [];
  field.addEventListener("input", (event) => events.push(event));
  const decoder = makeDecoder();
  const scanner = makeScanner();
  const created = { decoders: 0, scanners: 0, scannerArgs: null };
  const loads = { count: 0 };
  const panel = mountPsbtScan(host, {
    field,
    translate: options.translate || ((text) => text),
    onLoad: () => {
      loads.count += 1;
    },
    createDecoder: () => {
      created.decoders += 1;
      return decoder;
    },
    createScanner: (args) => {
      created.scanners += 1;
      created.scannerArgs = args;
      if (options.createScanner) return options.createScanner(args);
      // Mirror the real scanner: stop() on an active session emits "stopped".
      scanner.stop = () => {
        scanner.calls.stop += 1;
        try { args.onStatus("stopped"); } catch {}
      };
      return scanner;
    },
    wasmBytes: () => new Uint8Array([1, 2, 3]),
    doc,
    win: { InputEvent: FakeInputEvent },
  });
  return { doc, host, field, events, decoder, scanner, created, loads, panel };
};

const byId = (ctx, suffix) => ctx.host.querySelector(`#${ctx.host.id}-${suffix}`);
const openPanel = (ctx) => byId(ctx, "open").dispatchEvent({ type: "click" });

test("an empty field is filled from the camera", () => {
  const ctx = setup();
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf(PSBT_BASE64));
  assert.equal(ctx.field.value, PSBT_BASE64);
  assert.equal(ctx.events.length, 1);
  assert.equal(ctx.events[0].type, "input");
  assert.equal(ctx.events[0].bubbles, true);
  assert.equal(ctx.loads.count, 1);
  assert.equal(ctx.scanner.calls.stop, 1);
});

test("a non-empty field asks before replacing", () => {
  const ctx = setup();
  ctx.field.value = "old";
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf(PSBT_BASE64));
  assert.equal(ctx.field.value, "old");
  assert.equal(ctx.events.length, 0);
  assert.equal(ctx.loads.count, 0);
  assert.equal(byId(ctx, "confirm").hidden, false);
  byId(ctx, "keep").dispatchEvent({ type: "click" });
  assert.equal(ctx.field.value, "old");
  assert.equal(ctx.events.length, 0);
  assert.equal(byId(ctx, "confirm").hidden, true);
});

test("Replace re-checks the field and refuses to overwrite a non-empty one", () => {
  const ctx = setup();
  ctx.field.value = "old";
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf(PSBT_BASE64));
  assert.equal(byId(ctx, "confirm").hidden, false);
  byId(ctx, "replace").dispatchEvent({ type: "click" });
  assert.equal(ctx.field.value, "old", "a pre-filled field is never clobbered");
  assert.equal(ctx.events.length, 0, "nothing was written");
  assert.equal(ctx.loads.count, 0, "nothing was loaded");
  assert.equal(byId(ctx, "confirm").hidden, false, "the dialog re-prompts");
  assert.equal(byId(ctx, "status").getAttribute("data-scan-state"), "field-nonempty");
});

test("Replace writes when the field is empty at click time", () => {
  const ctx = setup();
  ctx.field.value = "old";
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf(PSBT_BASE64));
  assert.equal(byId(ctx, "confirm").hidden, false);
  // The user clears the field while the dialog is open, then replaces.
  ctx.field.value = "";
  byId(ctx, "replace").dispatchEvent({ type: "click" });
  assert.equal(ctx.field.value, PSBT_BASE64);
  assert.equal(ctx.events.length, 1);
  assert.equal(ctx.loads.count, 1);
  assert.equal(byId(ctx, "confirm").hidden, true);
});

test("a refusal leaves the field unchanged", () => {
  const ctx = setup();
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf("not a psbt"));
  assert.equal(ctx.field.value, "");
  assert.equal(ctx.events.length, 0);
  assert.equal(byId(ctx, "status").getAttribute("data-scan-state"), "not-psbt");
});

test("destroy empties the host and is idempotent", () => {
  const ctx = setup();
  openPanel(ctx);
  ctx.panel.destroy();
  assert.equal(ctx.host.childNodes.length, 0);
  assert.equal(ctx.scanner.calls.stop, 1);
  assert.equal(ctx.decoder.calls.stop, 1);
  ctx.panel.destroy();
  assert.equal(ctx.scanner.calls.stop, 1);
  assert.equal(ctx.decoder.calls.stop, 1);
});

test("two panels with different host ids do not share ids", () => {
  const a = setup({ id: "psbt-a" });
  const b = setup({ id: "psbt-b" });
  assert.ok(a.host.querySelector("#psbt-a-open"));
  assert.ok(b.host.querySelector("#psbt-b-open"));
  assert.equal(a.host.querySelector("#psbt-b-open"), null);
  assert.equal(b.host.querySelector("#psbt-a-open"), null);
});

test("every visible string goes through translate", () => {
  const ctx = setup({ translate: (text) => "⟦" + text + "⟧" });
  const wrapped = (suffix) => {
    const text = byId(ctx, suffix).textContent;
    return text.startsWith("⟦") && text.endsWith("⟧");
  };
  for (const suffix of ["open", "stop", "close", "replace", "keep", "confirm-text"]) {
    assert.ok(wrapped(suffix), `${suffix} was not translated`);
  }
});

test("the progress line is announced politely", () => {
  const ctx = setup();
  assert.equal(byId(ctx, "progress").getAttribute("aria-live"), "polite");
});

test("leaving the page drops the pending scan", () => {
  const ctx = setup();
  ctx.field.value = "old";
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf(PSBT_BASE64));
  assert.equal(byId(ctx, "confirm").hidden, false);
  const stops = ctx.scanner.calls.stop;
  ctx.doc.visibilityState = "hidden";
  ctx.doc.dispatchEvent({ type: "visibilitychange" });
  assert.equal(ctx.scanner.calls.stop, stops + 1);
  assert.equal(byId(ctx, "confirm").hidden, true);
  assert.equal(ctx.field.value, "old");
  // Dropped, not merely hidden: Replace has nothing left to write (GLM).
  byId(ctx, "replace").dispatchEvent({ type: "click" });
  assert.equal(ctx.field.value, "old");
  assert.equal(ctx.events.length, 0);
  assert.equal(ctx.loads.count, 0);
  ctx.doc.visibilityState = "visible";
  if (byId(ctx, "panel").hidden) openPanel(ctx);
  assert.equal(ctx.field.value, "old");
  assert.equal(byId(ctx, "confirm").hidden, true);
});

test("the app's conceal signal drops the pending scan", () => {
  const ctx = setup();
  ctx.field.value = "old";
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf(PSBT_BASE64));
  assert.equal(byId(ctx, "confirm").hidden, false);
  const stops = ctx.scanner.calls.stop;
  ctx.doc.dispatchEvent({ type: "hodl:conceal" });
  assert.equal(ctx.scanner.calls.stop, stops + 1);
  assert.equal(byId(ctx, "confirm").hidden, true);
  assert.equal(ctx.field.value, "old");
  byId(ctx, "replace").dispatchEvent({ type: "click" });
  assert.equal(ctx.field.value, "old");
  assert.equal(ctx.events.length, 0);
  assert.equal(ctx.loads.count, 0);
  if (byId(ctx, "panel").hidden) openPanel(ctx);
  assert.equal(ctx.field.value, "old");
  assert.equal(byId(ctx, "confirm").hidden, true);
});

test("destroy removes both conceal listeners", () => {
  const ctx = setup();
  openPanel(ctx);
  assert.equal(ctx.doc.listenerCount("visibilitychange"), 1);
  assert.equal(ctx.doc.listenerCount("hodl:conceal"), 1);
  ctx.panel.destroy();
  assert.equal(ctx.doc.listenerCount("visibilitychange"), 0);
  assert.equal(ctx.doc.listenerCount("hodl:conceal"), 0);
  const stops = ctx.scanner.calls.stop;
  ctx.doc.visibilityState = "hidden";
  ctx.doc.dispatchEvent({ type: "visibilitychange" });
  ctx.doc.dispatchEvent({ type: "hodl:conceal" });
  assert.equal(ctx.scanner.calls.stop, stops);
});

// In continuous mode a partial part must NOT re-open the camera (no full
// getUserMedia re-negotiation); the stream and frame loop keep running, and the
// reader keeps accumulating parts.
test("a partial part keeps the camera running in continuous mode", () => {
  const ctx = setup();
  openPanel(ctx);
  const starts = ctx.scanner.calls.start;
  const big = new Uint8Array(80);
  big.set(PSBT);
  const parts = encodeParts(hodlCborBstr(big), 30, 3);
  assert.equal(parts.length, 3);
  ctx.created.scannerArgs.onResult(bytesOf(partUr(parts[0])));
  assert.equal(ctx.scanner.calls.start, starts, "no re-open between parts");
  assert.equal(ctx.scanner.calls.stop, 0, "the stream is still running");
  assert.equal(byId(ctx, "progress").hidden, false);
});

// The reader is done once a scan completes, so a later part is ignored before
// restartCamera; its pending guard is defensive (GLM). This pins the behaviour:
// nothing restarts, nothing is written, the confirmation stays.
test("a part fed while a confirmation is pending changes nothing", () => {
  const ctx = setup();
  ctx.field.value = "old";
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf(PSBT_BASE64));
  assert.equal(byId(ctx, "confirm").hidden, false);
  const starts = ctx.scanner.calls.start;
  const big = new Uint8Array(80);
  big.set(PSBT);
  const parts = encodeParts(hodlCborBstr(big), 30, 3);
  ctx.created.scannerArgs.onResult(bytesOf(partUr(parts[0])));
  assert.equal(ctx.scanner.calls.start, starts);
  assert.equal(ctx.field.value, "old");
  assert.equal(byId(ctx, "confirm").hidden, false);
});

// --- shared capture (§4B): two panels never hold two camera streams ---

test("opening a panel releases every other panel's active capture", () => {
  const a = setup({ id: "a" });
  const b = setup({ id: "b" });
  openPanel(a);
  assert.equal(a.scanner.calls.start, 1, "a begins its capture");
  // b opens: it releases a's active stream and takes the camera.
  openPanel(b);
  assert.equal(a.scanner.calls.stop, 1, "b's open stopped a's scanner");
  assert.equal(a.scanner.calls.start, 1, "a does not re-open");
  assert.equal(byId(a, "status").getAttribute("data-scan-state"), "stopped");
  // a is not destroyed: its panel stays mounted and its single scanner reused.
  assert.ok(!a.panel.destroyed, "a is not destroyed");
  assert.equal(a.created.scanners, 1, "a keeps its one scanner");
  assert.equal(byId(a, "panel").hidden, false, "a's panel stays visible");

  // b captures a full single-part stream and completes.
  b.created.scannerArgs.onResult(bytesOf(PSBT_BASE64));
  assert.equal(b.field.value, PSBT_BASE64);
  assert.equal(b.loads.count, 1);
  assert.equal(byId(b, "status").getAttribute("data-scan-state"), "loaded");

  // a's late result is discarded: nothing written, nothing loaded, wiped.
  const late = bytesOf(PSBT_BASE64);
  a.created.scannerArgs.onResult(late);
  assert.equal(a.field.value, "", "a's field is never overwritten");
  assert.equal(a.events.length, 0);
  assert.equal(a.loads.count, 0);
  assert.ok(late.every((v) => v === 0), "a's late payload is zeroed");
});

test("re-opening a panel after it was stopped reuses its scanner", () => {
  const a = setup({ id: "a" });
  const b = setup({ id: "b" });
  openPanel(a);            // a's scanner created and started
  openPanel(b);            // stops a's capture
  byId(a, "open").dispatchEvent({ type: "click" });  // restart a in one click
  assert.equal(a.created.scanners, 1, "no second scanner is created for a");
  assert.equal(a.scanner.calls.start, 2, "the reused scanner started twice");
});

test("a panel stopped by another gets a fresh reader on re-open", () => {
  const a = setup({ id: "a" });
  const b = setup({ id: "b" });
  const makeMsg = (seed) => {
    const big = new Uint8Array(80);
    big.set(PSBT);
    big.fill(seed, PSBT.length, 80);
    return big;
  };
  const m1 = encodeParts(hodlCborBstr(makeMsg(1)), 30, 3);
  const m2 = encodeParts(hodlCborBstr(makeMsg(2)), 30, 3);
  openPanel(a);
  // a's reader binds to m1 (1 of 3 received).
  a.created.scannerArgs.onResult(bytesOf(partUr(m1[0])));
  assert.equal(byId(a, "progress").hidden, false, "a's reader bound to m1");
  // b opens: a is stopped and its reader must reset.
  openPanel(b);
  assert.equal(byId(a, "status").getAttribute("data-scan-state"), "stopped");
  // Re-open a; only a fresh reader lets a different complete scan finish.
  byId(a, "open").dispatchEvent({ type: "click" });
  a.created.scannerArgs.onResult(bytesOf(partUr(m2[0])));
  a.created.scannerArgs.onResult(bytesOf(partUr(m2[1])));
  a.created.scannerArgs.onResult(bytesOf(partUr(m2[2])));
  assert.equal(
    a.field.value,
    Buffer.from(makeMsg(2)).toString("base64"),
    "a completed a fresh scan of m2, not a stale m1 state",
  );
  assert.equal(a.loads.count, 1);
});

// --- lifecycle: session end discards late results and releases the stream ---

test("a late result after completion is wiped and ignored", () => {
  const ctx = setup();
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf(PSBT_BASE64));
  assert.equal(ctx.scanner.calls.stop, 1, "completion released the scanner");
  assert.equal(ctx.scanner.calls.start, 1, "the stream was not re-opened");
  // The panel stays open, but its session ended; a late decode must not
  // be written even though the panel is still open.
  const late = bytesOf(PSBT_BASE64);
  ctx.created.scannerArgs.onResult(late);
  assert.equal(ctx.events.length, 1, "only the original write fired");
  assert.equal(ctx.loads.count, 1);
  assert.ok(late.every((v) => v === 0), "the late payload is zeroed");
});

test("a persistent reader error stops the camera and shows stopped", () => {
  const ctx = setup();
  openPanel(ctx);
  // A part advertising a messageLen beyond the 1 MiB reader limit is a
  // terminal "too-large" refusal.
  const tooLarge = {
    seqNum: 1,
    seqLen: 3,
    messageLen: 2000000,
    checksum: crc32Number(new Uint8Array(80)),
    data: new Uint8Array(26),
  };
  ctx.created.scannerArgs.onResult(bytesOf(partUr(tooLarge)));
  assert.equal(ctx.scanner.calls.stop, 1, "the stream was released");
  assert.equal(byId(ctx, "status").getAttribute("data-scan-state"), "stopped");
  assert.equal(ctx.field.value, "");
});

test("a mismatched reader state stops the camera", () => {
  const ctx = setup();
  openPanel(ctx);
  const makeBig = (seed) => {
    const big = new Uint8Array(80);
    big.set(PSBT);
    big.fill(seed, PSBT.length, 80);
    return big;
  };
  // Two distinct 3-part messages; part 1 of each has seqNum=1, seqLen=3.
  const partsA = encodeParts(hodlCborBstr(makeBig(1)), 30, 3);
  const partsB = encodeParts(hodlCborBstr(makeBig(2)), 30, 3);
  assert.equal(partsA.length, 3);
  // part 1 of message A binds seqLen=3 (partial, 1 received).
  ctx.created.scannerArgs.onResult(bytesOf(partUr(partsA[0])));
  assert.equal(byId(ctx, "progress").hidden, false);
  // part 1 of message B (same seqNum/seqLen, different data) -> collector
  // conflict -> reader "mismatch" -> terminal.
  ctx.created.scannerArgs.onResult(bytesOf(partUr(partsB[0])));
  assert.equal(ctx.scanner.calls.stop, 1, "mismatch released the scanner");
  assert.equal(byId(ctx, "status").getAttribute("data-scan-state"), "stopped");
});

test("recoverable QR refusal preserves live camera controls", () => {
  const ctx = setup();
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf("https://example.invalid/"));
  assert.equal(byId(ctx, "stop").hidden, false);
  assert.equal(byId(ctx, "video").hidden, false);
  assert.equal(ctx.scanner.calls.stop, 0);
  ctx.panel.destroy();
});

test("cancellation clears incomplete multipart progress", () => {
  for (const boundary of ["stop", "hidden", "conceal"]) {
    const ctx = setup();
    const big = new Uint8Array(80);
    big.set(PSBT);
    const parts = encodeParts(hodlCborBstr(big), 30, 3);
    openPanel(ctx);
    ctx.created.scannerArgs.onResult(bytesOf(partUr(parts[0])));
    assert.equal(byId(ctx, "progress").hidden, false);
    if (boundary === "stop") byId(ctx, "stop").dispatchEvent({ type: "click" });
    else if (boundary === "hidden") {
      ctx.doc.visibilityState = "hidden";
      ctx.doc.dispatchEvent({ type: "visibilitychange" });
    } else ctx.doc.dispatchEvent({ type: "hodl:conceal" });
    assert.equal(byId(ctx, "progress").hidden, true, boundary);
    ctx.panel.destroy();
  }
});

test("changing PSBT tools cancels capture before a late result can fill the old field", async () => {
  const ctx = setup();
  openPanel(ctx);
  const app = await loadAppFunctions(["hodlShowPsbtTool"], { stubs: {
    __ENTROPYLAB_PREVIEW__: true,
    hodlPsbtScans: [ctx.panel],
    hodlSyncPsbtTool: () => {},
    hodlJournalLog: () => {},
  } });
  app.hodlShowPsbtTool("editor");
  const late = bytesOf(PSBT_BASE64);
  ctx.created.scannerArgs.onResult(late);
  assert.equal(ctx.field.value, "");
  assert.equal(byId(ctx, "panel").hidden, true);
  assert.ok(late.every((byte) => byte === 0));
  ctx.panel.destroy();
});

test("camera timeout clears partial state and refuses late payloads", () => {
  const ctx = setup();
  const big = new Uint8Array(80);
  big.set(PSBT);
  const parts = encodeParts(hodlCborBstr(big), 30, 3);
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf(partUr(parts[0])));
  ctx.created.scannerArgs.onStatus("timeout");
  assert.equal(byId(ctx, "progress").hidden, true);
  const late = bytesOf(PSBT_BASE64);
  ctx.created.scannerArgs.onResult(late);
  assert.equal(ctx.field.value, "");
  assert.ok(late.every((byte) => byte === 0));
  ctx.panel.destroy();
});

test("a visible permission-prompt blur preserves the pending camera grant", async () => {
  let grant;
  const track = { stopped: false, stop() { this.stopped = true; } };
  const stream = { getTracks: () => [track] };
  let scannerArgs;
  const ctx = setup({ createScanner(args) {
    scannerArgs = args;
    return createQrScanner({ ...args, isSecureContext: true,
      mediaDevices: { getUserMedia: () => new Promise((resolve) => { grant = resolve; }) },
      requestFrame: () => 1 });
  } });
  const key = { reveal: true };
  const app = await loadAppFunctions(["hodlConcealPrivateValues"], { stubs: {
    document: ctx.doc, hodlBip47Conceal: () => {},
    hodlKeys: [key], hodlBip85Children: [], hodlSpAddresses: [], hodlSpVerifyMatches: null,
  } });
  openPanel(ctx);
  app.hodlConcealPrivateValues({ reason: "blur" });
  assert.equal(key.reveal, false, "the permission exception must not preserve revealed secrets");
  grant(stream);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(track.stopped, false, "grant was cancelled by the browser prompt's blur");
  assert.equal(scannerArgs.video.srcObject, stream);
  ctx.doc.visibilityState = "hidden";
  ctx.doc.dispatchEvent({ type: "visibilitychange" });
  assert.equal(track.stopped, true, "an actually hidden page must release capture");
  ctx.panel.destroy();
});

test("blur after capture starts still cancels the scan", () => {
  const ctx = setup();
  openPanel(ctx);
  ctx.created.scannerArgs.onStatus("scanning");
  ctx.doc.dispatchEvent({ type: "hodl:conceal", detail: { reason: "blur" } });
  assert.equal(ctx.scanner.calls.stop, 1);
  const late = bytesOf(PSBT_BASE64);
  ctx.created.scannerArgs.onResult(late);
  assert.equal(ctx.field.value, "");
  assert.ok(late.every((byte) => byte === 0));
  ctx.panel.destroy();
});

test("one Scan click restarts a stopped acquisition", () => {
  const ctx = setup();
  openPanel(ctx);
  byId(ctx, "stop").dispatchEvent({ type: "click" });
  const starts = ctx.scanner.calls.start;
  openPanel(ctx);
  assert.equal(ctx.scanner.calls.start, starts + 1);
  assert.equal(byId(ctx, "panel").hidden, false);
  ctx.panel.destroy();
});

test("hidden, print and explicit cancellation discard a pending camera grant", async () => {
  for (const boundary of ["hidden", "print", "idle", "close", "destroy"]) {
    let grant;
    const track = { stopped: false, stop() { this.stopped = true; } };
    const ctx = setup({ createScanner(args) {
      return createQrScanner({ ...args, isSecureContext: true,
        mediaDevices: { getUserMedia: () => new Promise((resolve) => { grant = resolve; }) },
        requestFrame: () => 1 });
    } });
    openPanel(ctx);
    if (boundary === "hidden") {
      ctx.doc.visibilityState = "hidden";
      ctx.doc.dispatchEvent({ type: "hodl:conceal", detail: { reason: "blur" } });
    } else if (boundary === "close") byId(ctx, "close").dispatchEvent({ type: "click" });
    else if (boundary === "destroy") ctx.panel.destroy();
    else ctx.doc.dispatchEvent({ type: "hodl:conceal", detail: { reason: boundary } });
    grant({ getTracks: () => [track] });
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(track.stopped, true, `${boundary} must reject a late grant`);
    assert.equal(ctx.field.value, "");
    ctx.panel.destroy();
  }
});
