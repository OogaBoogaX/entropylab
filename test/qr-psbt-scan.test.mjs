import test from "node:test";
import assert from "node:assert/strict";
import { mountPsbtScan } from "../src/js/qr-psbt-scan.js";
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

test("a partial part restarts the camera", () => {
  const ctx = setup();
  openPanel(ctx);
  const starts = ctx.scanner.calls.start;
  const big = new Uint8Array(80);
  big.set(PSBT);
  const parts = encodeParts(hodlCborBstr(big), 30, 3);
  assert.equal(parts.length, 3);
  ctx.created.scannerArgs.onResult(bytesOf(partUr(parts[0])));
  assert.equal(ctx.scanner.calls.start, starts + 1);
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
