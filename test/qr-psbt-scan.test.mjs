import test from "node:test";
import assert from "node:assert/strict";
import { mountPsbtScan } from "../src/js/qr-psbt-scan.js";
import { createQrScanner } from "../src/js/qr-scanner.js";
import { MiniDocument } from "./mini-dom.mjs";
import { readFileSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { collectSources } from "../scripts/i18n-sources.mjs";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const SOURCE = readFileSync(new URL("../src/js/qr-psbt-scan.js", import.meta.url), "utf8");
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
  doc.visibilityState = "visible";
  doc.focused = true;
  doc.hasFocus = () => doc.focused;
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
      return options.createScanner ? options.createScanner(args) : scanner;
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

test("Replace writes the scanned PSBT", () => {
  const ctx = setup();
  ctx.field.value = "old";
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf(PSBT_BASE64));
  byId(ctx, "replace").dispatchEvent({ type: "click" });
  assert.equal(ctx.field.value, PSBT_BASE64);
  assert.equal(ctx.events.length, 1);
  assert.equal(ctx.loads.count, 1);
  assert.equal(byId(ctx, "confirm").hidden, true);
});

test("Replace rechecks a field edited while confirmation was open", () => {
  const ctx = setup();
  ctx.field.value = "old";
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf(PSBT_BASE64));
  ctx.field.value = "newer user edit";
  byId(ctx, "replace").dispatchEvent({ type: "click" });
  assert.equal(ctx.field.value, "newer user edit", "a stale confirmation never clobbers an edit");
  assert.equal(ctx.events.length, 0);
  assert.equal(ctx.loads.count, 0);
  assert.equal(byId(ctx, "confirm").hidden, false);
  // The next explicit confirmation now refers to the current field.
  byId(ctx, "replace").dispatchEvent({ type: "click" });
  assert.equal(ctx.field.value, PSBT_BASE64);
  assert.equal(ctx.events.length, 1);
  ctx.panel.destroy();
});

test("Replace accepts a field emptied while confirmation was open", () => {
  const ctx = setup();
  ctx.field.value = "old";
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf(PSBT_BASE64));
  ctx.field.value = "";
  byId(ctx, "replace").dispatchEvent({ type: "click" });
  assert.equal(ctx.field.value, PSBT_BASE64);
  assert.equal(ctx.events.length, 1);
  ctx.panel.destroy();
});

test("a refusal leaves the field unchanged", () => {
  const ctx = setup();
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf("not a psbt"));
  assert.equal(ctx.field.value, "");
  assert.equal(ctx.events.length, 0);
  assert.equal(byId(ctx, "status").getAttribute("data-scan-state"), "not-psbt");
});

test("destroy marks capture stopped before removing the host and is reentrancy-safe", () => {
  let ctx;
  let stops = 0;
  ctx = setup({ createScanner(args) {
    return {
      start() {},
      stop() {
        stops += 1;
        args.onStatus("scanning");
        args.onResult(bytesOf(PSBT_BASE64));
        ctx.panel.destroy();
        openPanel(ctx);
      },
    };
  } });
  openPanel(ctx);
  const status = byId(ctx, "status");
  const video = byId(ctx, "video");
  const stop = byId(ctx, "stop");
  ctx.panel.destroy();
  assert.equal(ctx.host.childNodes.length, 0);
  assert.equal(status.getAttribute("data-scan-state"), "stopped");
  assert.equal(video.hidden, true);
  assert.equal(stop.hidden, true);
  assert.equal(ctx.field.value, "");
  assert.equal(ctx.events.length, 0);
  assert.equal(stops, 1);
  assert.equal(ctx.decoder.calls.stop, 1);
  ctx.panel.destroy();
  assert.equal(stops, 1);
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

// The panel ships in every build, so its text goes through t() from
// ./i18n.js like every other module's, as literals the catalog sweep sees
// (copy is content, not contract: the tests hook on the structure, never on
// the wording).
test("every visible string is a t() literal the catalog sweep collects", async () => {
  assert.match(SOURCE, /import \{ t \} from "\.\/i18n\.js";/, "the panel must translate through the page catalog");
  assert.doesNotMatch(SOURCE, /\btranslate\b/, "no translator option: the module reads the catalog itself");
  // Each status is a thunk around a t() literal, looked up when it is shown.
  const statusBlock = SOURCE.match(/const STATUS_TEXT = \{\n([\s\S]*?)\n\};/)?.[1];
  assert.ok(statusBlock, "STATUS_TEXT is missing");
  const statusLines = statusBlock.split("\n");
  assert.ok(statusLines.length >= 10);
  for (const line of statusLines) assert.match(line, /^  (?:"[\w-]+"|\w+): \((?:vars)?\) => t\("[^"]+"(?:, vars)?\),$/, `not a t() literal thunk: ${line.trim()}`);
  // The controls' text and the progress line are t() literals too.
  for (const literal of SOURCE.matchAll(/text: ([^,}]+)/g)) assert.match(literal[1].trim(), /^(?:t\("[^"]+"\)|STATUS_TEXT\.\w+\(\))$/, `control text is not translated: ${literal[1]}`);
  assert.match(SOURCE, /progressLine\.textContent = t\("[^"]+", \{/);
  assert.match(SOURCE, /statusLine\.textContent = STATUS_TEXT\[key\]\(vars\);/);
  // The sweep that feeds the translation run sees them.
  const sources = await collectSources(ROOT);
  for (const line of statusLines) assert.ok(sources.has(line.match(/t\("([^"]+)"/)[1]), `the catalog sweep misses: ${line.trim()}`);
  for (const literal of SOURCE.matchAll(/\bt\("([^"]+)"/g)) assert.ok(sources.has(literal[1]), `the catalog sweep misses: ${literal[1]}`);
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

test("multipart collection uses one continuous camera session", () => {
  const ctx = setup();
  openPanel(ctx);
  assert.equal(ctx.created.scannerArgs.continuous, true);
  const big = new Uint8Array(80);
  big.set(PSBT);
  const parts = encodeParts(hodlCborBstr(big), 30, 3);
  ctx.created.scannerArgs.onResult(bytesOf(partUr(parts[0])));
  assert.equal(ctx.scanner.calls.start, 1, "partial frames never renegotiate camera access");
  assert.equal(ctx.scanner.calls.stop, 0);
  assert.equal(byId(ctx, "progress").hidden, false);
  for (const part of parts.slice(1)) ctx.created.scannerArgs.onResult(bytesOf(partUr(part)));
  assert.equal(ctx.scanner.calls.start, 1);
  assert.equal(ctx.scanner.calls.stop, 1, "completion releases the single camera session");
  assert.equal(ctx.field.value, Buffer.from(big).toString("base64"));
  assert.equal(ctx.loads.count, 1);
  ctx.panel.destroy();
});

// A completed capture has no live acquisition, even while Replace is pending.
// Late frames must not restart the camera, write the field or disturb the prompt.
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

const multipart = (seed = 0) => {
  const bytes = new Uint8Array(80);
  bytes.set(PSBT);
  bytes.fill(seed, PSBT.length);
  return { bytes, parts: encodeParts(hodlCborBstr(bytes), 30, 3) };
};

test("opening another panel releases active or permission-pending capture", () => {
  for (const granted of [false, true]) {
    const a = setup({ id: "psbt-a" });
    const b = setup({ id: "psbt-b" });
    openPanel(a);
    if (granted) a.created.scannerArgs.onStatus("scanning");
    openPanel(b);
    assert.equal(a.scanner.calls.stop, 1);
    assert.equal(byId(a, "panel").hidden, false, "the released panel remains usable");
    assert.equal(byId(a, "status").getAttribute("data-scan-state"), "stopped");
    assert.equal(byId(a, "stop").hidden, true);
    assert.equal(byId(a, "video").hidden, true);
    a.created.scannerArgs.onStatus("scanning");
    assert.equal(byId(a, "status").getAttribute("data-scan-state"), "stopped", "late activation cannot revive the visible status");
    const late = bytesOf(PSBT_BASE64);
    a.created.scannerArgs.onResult(late);
    assert.equal(a.field.value, "");
    assert.ok(late.every((byte) => byte === 0));
    openPanel(a);
    assert.equal(a.scanner.calls.start, 2, "one click retakes capture");
    assert.equal(a.created.scanners, 1, "the panel reuses its scanner");
    assert.equal(b.scanner.calls.stop, 1);
    a.panel.destroy();
    b.panel.destroy();
  }
});

test("recoverable refusal keeps continuous acquisition and stop controls available", () => {
  const ctx = setup();
  openPanel(ctx);
  ctx.created.scannerArgs.onStatus("scanning");
  ctx.created.scannerArgs.onResult(bytesOf("https://example.invalid/"));
  assert.equal(byId(ctx, "status").getAttribute("data-scan-state"), "not-psbt");
  assert.equal(byId(ctx, "stop").hidden, false);
  assert.equal(byId(ctx, "video").hidden, false);
  assert.equal(ctx.scanner.calls.stop, 0);
  ctx.created.scannerArgs.onResult(bytesOf(PSBT_BASE64));
  assert.equal(ctx.field.value, PSBT_BASE64);
  ctx.panel.destroy();
});

test("terminal reader refusals release capture and discard late results", () => {
  for (const kind of ["too-large", "mismatch"]) {
    const ctx = setup();
    openPanel(ctx);
    if (kind === "too-large") {
      ctx.created.scannerArgs.onResult(bytesOf(partUr({
        seqNum: 1, seqLen: 3, messageLen: 2_000_000,
        checksum: crc32Number(new Uint8Array(80)), data: new Uint8Array(26),
      })));
    } else {
      ctx.created.scannerArgs.onResult(bytesOf(partUr(multipart(1).parts[0])));
      ctx.created.scannerArgs.onResult(bytesOf(partUr(multipart(2).parts[0])));
    }
    assert.equal(ctx.scanner.calls.stop, 1, kind);
    assert.equal(byId(ctx, "status").getAttribute("data-scan-state"), kind);
    assert.equal(byId(ctx, "progress").hidden, true);
    const late = bytesOf(PSBT_BASE64);
    ctx.created.scannerArgs.onResult(late);
    assert.equal(ctx.field.value, "");
    assert.ok(late.every((byte) => byte === 0));
    ctx.panel.destroy();
  }
});

test("cancellation clears partial state and rejects frames until an explicit retry", () => {
  for (const boundary of ["stop", "hidden", "blur", "print", "idle", "conceal", "close"]) {
    const ctx = setup();
    openPanel(ctx);
    ctx.created.scannerArgs.onStatus("scanning");
    ctx.created.scannerArgs.onResult(bytesOf(partUr(multipart(1).parts[0])));
    assert.equal(byId(ctx, "progress").hidden, false);
    if (boundary === "stop" || boundary === "close") byId(ctx, boundary).dispatchEvent({ type: "click" });
    else if (boundary === "hidden") {
      ctx.doc.visibilityState = "hidden";
      ctx.doc.dispatchEvent({ type: "visibilitychange" });
    } else ctx.doc.dispatchEvent({ type: "hodl:conceal", detail: { reason: boundary } });
    assert.equal(byId(ctx, "progress").hidden, true, boundary);
    const late = bytesOf(PSBT_BASE64);
    ctx.created.scannerArgs.onResult(late);
    assert.equal(ctx.field.value, "", boundary);
    assert.ok(late.every((byte) => byte === 0), boundary);
    ctx.doc.visibilityState = "visible";
    const starts = ctx.scanner.calls.start;
    openPanel(ctx);
    assert.equal(ctx.scanner.calls.start, starts + 1, `${boundary}: one click restarts`);
    const fresh = multipart(2);
    for (const part of fresh.parts) ctx.created.scannerArgs.onResult(bytesOf(partUr(part)));
    assert.equal(ctx.field.value, Buffer.from(fresh.bytes).toString("base64"), `${boundary}: reader reset`);
    ctx.panel.destroy();
  }
});

test("terminal camera statuses clear partial state and permit one-click retry", () => {
  for (const code of ["timeout", "stopped", "denied", "no-camera", "unsupported", "error"]) {
    const ctx = setup();
    openPanel(ctx);
    ctx.created.scannerArgs.onResult(bytesOf(partUr(multipart(1).parts[0])));
    ctx.created.scannerArgs.onStatus(code);
    assert.equal(byId(ctx, "progress").hidden, true, code);
    const late = bytesOf(PSBT_BASE64);
    ctx.created.scannerArgs.onResult(late);
    ctx.created.scannerArgs.onStatus("scanning");
    assert.equal(ctx.field.value, "", code);
    assert.ok(late.every((byte) => byte === 0), code);
    assert.equal(byId(ctx, "status").getAttribute("data-scan-state"), code, "late statuses cannot revive capture");
    openPanel(ctx);
    assert.equal(ctx.scanner.calls.start, 2, code);
    const fresh = multipart(2);
    for (const part of fresh.parts) ctx.created.scannerArgs.onResult(bytesOf(partUr(part)));
    assert.equal(ctx.field.value, Buffer.from(fresh.bytes).toString("base64"), code);
    ctx.panel.destroy();
  }
});

test("visible permission blur accepts a focused grant, but active blur still stops capture", async () => {
  let grant;
  let starts = 0;
  const track = { stopped: false, stop() { this.stopped = true; } };
  const stream = { getTracks: () => [track] };
  const ctx = setup({ createScanner(args) {
    return createQrScanner({
      ...args, isSecureContext: true,
      mediaDevices: { getUserMedia() {
        starts += 1;
        return new Promise((resolve) => { grant = resolve; });
      } },
      requestFrame: () => 1,
    });
  } });
  try {
    openPanel(ctx);
    ctx.doc.focused = false;
    ctx.doc.dispatchEvent({ type: "hodl:conceal", detail: { reason: "blur" } });
    ctx.doc.focused = true;
    grant(stream);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(starts, 1);
    assert.equal(track.stopped, false, "the browser's permission prompt did not cancel its own grant");
    assert.equal(ctx.created.scannerArgs.video.srcObject, stream);
    assert.equal(byId(ctx, "status").getAttribute("data-scan-state"), "scanning");
    ctx.doc.focused = false;
    ctx.doc.dispatchEvent({ type: "hodl:conceal", detail: { reason: "blur" } });
    assert.equal(track.stopped, true, "blur after the grant releases active capture");
    const late = bytesOf(PSBT_BASE64);
    ctx.created.scannerArgs.onResult(late);
    assert.equal(ctx.field.value, "");
    assert.ok(late.every((byte) => byte === 0));
  } finally {
    ctx.panel.destroy();
  }
});

test("camera activation refuses unfocused, unavailable-focus and hidden grants without writing", async () => {
  for (const focus of ["unfocused", "missing", "throws", "hidden"]) {
    let grant;
    const track = { stopped: false, stop() { this.stopped = true; } };
    const ctx = setup({ createScanner(args) {
      return createQrScanner({
        ...args, isSecureContext: true,
        mediaDevices: { getUserMedia: () => new Promise((resolve) => { grant = resolve; }) },
        requestFrame: () => 1,
      });
    } });
    try {
      openPanel(ctx);
      ctx.doc.focused = false;
      ctx.doc.dispatchEvent({ type: "hodl:conceal", detail: { reason: "blur" } });
      assert.equal(track.stopped, false, "permission-prompt blur alone leaves the request pending");
      if (focus === "missing") delete ctx.doc.hasFocus;
      if (focus === "throws") ctx.doc.hasFocus = () => { throw new Error("focus unavailable"); };
      if (focus === "hidden") {
        ctx.doc.focused = true;
        ctx.doc.visibilityState = "hidden";
      }
      grant({ getTracks: () => [track] });
      await new Promise((resolve) => setImmediate(resolve));
      assert.equal(track.stopped, true, `${focus}: the grant must release its tracks`);
      assert.equal(byId(ctx, "status").getAttribute("data-scan-state"), "stopped", focus);
      assert.equal(byId(ctx, "stop").hidden, true, focus);
      assert.equal(byId(ctx, "video").hidden, true, focus);
      assert.equal(ctx.created.scannerArgs.video.srcObject, null, focus);
      const late = bytesOf(PSBT_BASE64);
      ctx.created.scannerArgs.onStatus("scanning");
      ctx.created.scannerArgs.onResult(late);
      assert.ok(late.every((byte) => byte === 0), focus);
      assert.equal(ctx.field.value, "", focus);
      assert.equal(ctx.events.length, 0, focus);
      assert.equal(ctx.loads.count, 0, focus);
      assert.equal(byId(ctx, "status").getAttribute("data-scan-state"), "stopped", "late status cannot revive capture");
    } finally {
      ctx.panel.destroy();
    }
  }
});

test("hidden, print, idle and explicit cancellation reject pending camera grants", async () => {
  for (const boundary of ["hidden", "hidden-blur", "print", "idle", "conceal", "stop", "close", "destroy", "other-panel"]) {
    let grant;
    const track = { stopped: false, stop() { this.stopped = true; } };
    const ctx = setup({ createScanner(args) {
      return createQrScanner({
        ...args, isSecureContext: true,
        mediaDevices: { getUserMedia: () => new Promise((resolve) => { grant = resolve; }) },
        requestFrame: () => 1,
      });
    } });
    let other = null;
    try {
      openPanel(ctx);
      if (boundary === "hidden" || boundary === "hidden-blur") {
        ctx.doc.visibilityState = "hidden";
        ctx.doc.dispatchEvent(boundary === "hidden" ? { type: "visibilitychange" } : { type: "hodl:conceal", detail: { reason: "blur" } });
      } else if (boundary === "stop" || boundary === "close") byId(ctx, boundary).dispatchEvent({ type: "click" });
      else if (boundary === "destroy") ctx.panel.destroy();
      else if (boundary === "other-panel") {
        other = setup({ id: "other-panel" });
        openPanel(other);
      } else ctx.doc.dispatchEvent({ type: "hodl:conceal", detail: { reason: boundary } });
      grant({ getTracks: () => [track] });
      await new Promise((resolve) => setImmediate(resolve));
      assert.equal(track.stopped, true, `${boundary} rejects a late grant`);
      assert.equal(ctx.field.value, "");
    } finally {
      ctx.panel.destroy();
      other?.panel.destroy();
    }
  }
});
