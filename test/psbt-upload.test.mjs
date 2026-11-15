// Upload support for the PSBT editor. Wallets (Sparrow, Coldcard, …) save a
// PSBT as a binary .psbt file that starts with the "psbt\xff" magic, while a
// "copy PSBT" export saved to disk is base64 (or hex) text.
// psbtBytesFromUpload accepts both: it sniffs the magic first, then falls
// back to the paste-box text rules, so a Sparrow binary loads as-is and a
// text export never needs re-encoding by hand. Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { psbtBytesFromText, psbtBytesFromUpload } from "../src/js/psbt-editor.js";
import { psbtInspectDoc } from "../src/js/psbt-wasm.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

// A real editor fixture doubles as the "Sparrow binary": the decoded bytes
// of the .b64 file are exactly what Sparrow writes into a .psbt file.
const fixtureB64 = read("test/fixtures/psbt/p2wpkh-1in-2out.b64").trim();
const fixtureBytes = Uint8Array.from(atob(fixtureB64), (char) => char.charCodeAt(0));
const fixtureHex = [...fixtureBytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");

test("a binary .psbt upload (Sparrow) passes through untouched and parses", () => {
  assert.deepEqual(psbtBytesFromUpload(fixtureBytes), fixtureBytes);
  const doc = psbtInspectDoc(psbtBytesFromUpload(fixtureBytes));
  assert.equal(doc.psbtVersion, 0);
  assert.ok(doc.tx.inputs.length >= 1, "fixture should carry inputs");
});

test("a base64 text export saved to disk decodes like the paste box", () => {
  assert.deepEqual(psbtBytesFromUpload(new TextEncoder().encode(fixtureB64)), fixtureBytes);
  assert.deepEqual(psbtBytesFromUpload(new TextEncoder().encode(`\n ${fixtureB64} \n`)), fixtureBytes);
});

test("a hex text file decodes like the paste box", () => {
  assert.deepEqual(psbtBytesFromUpload(new TextEncoder().encode(fixtureHex)), fixtureBytes);
  assert.deepEqual(psbtBytesFromUpload(new TextEncoder().encode(fixtureHex.toUpperCase())), fixtureBytes);
});

test("a UTF-8 BOM ahead of a text export is stripped by the text decode", () => {
  const bom = Uint8Array.of(0xef, 0xbb, 0xbf);
  const body = new TextEncoder().encode(fixtureB64);
  const bytes = new Uint8Array(bom.length + body.length);
  bytes.set(bom);
  bytes.set(body, bom.length);
  assert.deepEqual(psbtBytesFromUpload(bytes), fixtureBytes);
});

test("upload rejects what the paste box rejects, with its messages", () => {
  assert.throws(() => psbtBytesFromUpload(new Uint8Array()), /Choose a PSBT file/);
  assert.throws(() => psbtBytesFromUpload(new TextEncoder().encode("not a psbt at all")), /base64 or hex/);
  assert.throws(() => psbtBytesFromUpload(new Uint8Array(5e6 + 1)), /too large/);
  // A binary file without the magic is not assumed to be a PSBT.
  const corrupt = fixtureBytes.slice();
  corrupt[0] = 0x00;
  assert.throws(() => psbtBytesFromUpload(corrupt), /base64 or hex/);
});

test("upload and paste routes agree on the same PSBT", () => {
  assert.deepEqual(psbtBytesFromUpload(fixtureBytes), psbtBytesFromText(fixtureB64));
});

test("both markups carry the upload control, and the editor wires it", () => {
  const editor = read("src/js/psbt-editor.js");
  for (const markup of [read("src/shell.html")]) {
    assert.match(markup, /<button class="btn secondary" id="psbted-upload" type="button">/);
    assert.match(markup, /<input type="file" id="psbted-file" /);
  }
  assert.match(editor, /getElementById\("psbted-file"\)|\$\("psbted-file"\)/);
  assert.match(editor, /getElementById\("psbted-upload"\)|\$\("psbted-upload"\)/);
  assert.match(editor, /psbtBytesFromUpload\(upload\)/);
});

test("the PSBT / Nonce inspector also uploads and downloads the file", () => {
  const shell = read("src/shell.html");
  const app = read("src/js/app.js");
  assert.match(shell, /<button class="btn secondary" id="psbt-upload" type="button">Upload \.psbt File<\/button>/);
  assert.match(shell, /<input type="file" id="psbt-file" accept="\.psbt,\.txn,\.txt,\.hex" hidden>/);
  assert.match(shell, /<button class="btn secondary" id="psbt-download" type="button"[^>]*>Download \.psbt<\/button>/);
  assert.match(app, /import \{[^}]*psbtBytesFromUpload[^}]*\} from "\.\/psbt-editor\.js"/);
  assert.match(app, /getElementById\("psbt-upload"\)/);
  assert.match(app, /getElementById\("psbt-file"\)/);
  assert.match(app, /getElementById\("psbt-download"\)/);
  assert.match(app, /hodlPsbtInspectorBytesFromUpload\(upload\)/);
  assert.match(app, /hodlBytesToB64\(bytes\)/);
  assert.match(app, /"inspected\.psbt"/);
  assert.match(app, /"inspected\.txn"/);
  assert.match(app, /Paste or upload a PSBT or raw transaction first/);
  assert.match(app, /"psbt-upload": \["psbt", "upload", "psbt-file"\]/);
  assert.match(app, /"psbt-download": \["psbt", "download", "inspected-psbt"\]/);
});

test("the result panel offers a binary .psbt download", () => {
  const editor = read("src/js/psbt-editor.js");
  assert.match(editor, /id="psbted-download"/);
  assert.match(editor, /new Blob\(\[resultBytes\]/);
  assert.match(editor, /link\.download = "edited\.psbt"/);
});

test("editor rejects an oversized selected file before reading it", async () => {
  const { initPsbtEditor } = await import("../src/js/psbt-editor.js");
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, {
      value: "", textContent: "", innerHTML: "", dataset: {}, files: [],
      addEventListener(type, fn) { this[`on${type}`] = fn; },
      setAttribute() {}, querySelectorAll() { return []; },
    });
    return elements.get(id);
  };
  const previousDocument = globalThis.document, previousWindow = globalThis.window;
  globalThis.window = { addEventListener() {} };
  globalThis.document = { getElementById: element, addEventListener() {}, dispatchEvent() {} };
  try {
    initPsbtEditor();
    let reads = 0;
    element("psbted-file").files = [{ size: 5e6 + 1, arrayBuffer: async () => { reads++; return new ArrayBuffer(0); } }];
    element("psbted-file").onchange();
    await new Promise((resolve) => setTimeout(resolve, 0));
    assert.equal(reads, 0, "oversized file must not be read");
    assert.ok(element("psbted-error").textContent);
    element("psbted-file").files = [{ size: 5e6, arrayBuffer: async () => { reads++; return fixtureBytes.buffer; } }];
    element("psbted-file").onchange();
    await new Promise((resolve) => setTimeout(resolve, 0));
    assert.equal(reads, 1, "a file at the limit must be read");
    assert.equal(element("psbted-text").value, fixtureB64);
  } finally { globalThis.document = previousDocument; globalThis.window = previousWindow; }
});

// The inspector's own file handlers and session end, run against a small DOM.
// The counters are what the tests read: inspections run and errors shown.
const inspectorHarness = () => {
  const source = read("src/js/app.js");
  const handlers = source.slice(source.indexOf('  const nonceFile = document.getElementById("nonce-file");'), source.indexOf('  // The sent PSBT for the signer audit'));
  const end = source.slice(source.indexOf("function hodlEndPsbtSession()"), source.indexOf("\n// The Nonce Inspector", source.indexOf("function hodlEndPsbtSession()")));
  const retire = source.match(/function hodlPsbtRetireInspectorUploads\(\) \{[^}]*\}/)?.[0] || "";
  const elements = new Map();
  const get = (id) => {
    if (!elements.has(id)) elements.set(id, { value: "", innerHTML: "", files: [], addEventListener(type, fn) { this[`on${type}`] = fn; } });
    return elements.get(id);
  };
  const counters = { errors: 0, runs: 0 };
  const ctx = vm.createContext({
    document: { getElementById: get }, Uint8Array,
    hodlPsbtInspectorBytesFromUpload: (bytes) => bytes,
    hodlBytesToB64: (bytes) => Buffer.from(bytes).toString("base64"),
    hodlRunPsbt: () => counters.runs++, hodlRunNonce: () => counters.runs++,
    hodlSetPsbtError: (e) => { if (e) counters.errors++; }, hodlSetNonceError: (e) => { if (e) counters.errors++; },
    hodlSyncPsbtControls() {}, hodlPsbtWipeMem() {}, hodlPsbtClearNonceHistory() {},
    hodlPsbtRetireAuditUploads() {}, hodlPsbtRetireRbfUploads() {},
    hodlPsbtInspectorUploadGeneration: 0, hodlNonceQrCapture: null, hodlNonceHistoryConfirmDialog: null,
    hodlNote: () => ({}), hodlClearStationPassphrase() {}, hodlPaintPsbtSession() {}, hodlRefreshStationKeyPickers() {},
  });
  vm.runInContext(`${retire}\n${handlers}\n${end}`, ctx);
  return { ctx, get, counters };
};

test("pending inspector imports cannot restore a cleared session", async () => {
  for (const prefix of ["psbt", "nonce"]) {
    for (const reject of [false, true]) {
      const { ctx, get, counters } = inspectorHarness();
      let resolve, rejectRead;
      get(`${prefix}-file`).files = [{ arrayBuffer: async () => Uint8Array.of(4, 5).buffer }];
      get(`${prefix}-file`).onchange();
      await new Promise((done) => setTimeout(done, 0));
      assert.equal(get(`${prefix}-text`).value, "BAU=");
      assert.equal(counters.runs, 1);
      ctx.hodlEndPsbtSession();
      counters.runs = 0;
      get(`${prefix}-file`).files = [{ arrayBuffer: () => new Promise((yes, no) => { resolve = yes; rejectRead = no; }) }];
      get(`${prefix}-file`).onchange();
      ctx.hodlEndPsbtSession();
      if (reject) rejectRead(new Error("synthetic read failure")); else resolve(Uint8Array.of(1, 2, 3).buffer);
      await new Promise((done) => setTimeout(done, 0));
      assert.equal(get(`${prefix}-text`).value, "", `${prefix}: stale import restored data`);
      assert.equal(counters.runs, 0, `${prefix}: stale import ran inspection`);
      assert.equal(counters.errors, 0, `${prefix}: stale import showed an error`);
    }
  }
});

test("inspector rejects an oversized selected file before reading it", async () => {
  for (const prefix of ["psbt", "nonce"]) {
    const { get, counters } = inspectorHarness();
    let reads = 0;
    get(`${prefix}-file`).files = [{ size: 5e6 + 1, arrayBuffer: async () => { reads++; return new ArrayBuffer(0); } }];
    get(`${prefix}-file`).onchange();
    await new Promise((done) => setTimeout(done, 0));
    assert.equal(reads, 0, `${prefix}: oversized file must not be read`);
    assert.equal(counters.errors, 1, `${prefix}: oversized file showed no error`);
    assert.equal(counters.runs, 0, `${prefix}: oversized file ran inspection`);
    get(`${prefix}-file`).files = [{ size: 5e6, arrayBuffer: async () => { reads++; return Uint8Array.of(4, 5).buffer; } }];
    get(`${prefix}-file`).onchange();
    await new Promise((done) => setTimeout(done, 0));
    assert.equal(reads, 1, `${prefix}: a file at the limit must be read`);
    assert.equal(get(`${prefix}-text`).value, "BAU=");
    assert.equal(counters.runs, 1);
  }
});

test("editor Clear retires a pending file read and its error", async () => {
  const { initPsbtEditor } = await import("../src/js/psbt-editor.js");
  for (const reject of [false, true]) {
    const elements = new Map();
    const element = (id) => {
      if (!elements.has(id)) elements.set(id, { value: "", textContent: "", innerHTML: "", dataset: {}, files: [],
        addEventListener(type, fn) { this[`on${type}`] = fn; }, setAttribute() {}, querySelectorAll() { return []; } });
      return elements.get(id);
    };
    const previousDocument = globalThis.document, previousWindow = globalThis.window;
    globalThis.document = { getElementById: element, addEventListener() {}, dispatchEvent() {} };
    globalThis.window = { addEventListener() {} };
    try {
      initPsbtEditor();
      let resolve, rejectRead;
      element("psbted-file").files = [{ size: 6, arrayBuffer: () => new Promise((yes, no) => { resolve = yes; rejectRead = no; }) }];
      element("psbted-file").onchange();
      await new Promise((done) => setTimeout(done, 0));
      element("psbted-wipe").onclick();
      if (reject) rejectRead(new Error("synthetic read failure"));
      else resolve(Uint8Array.of(0x70, 0x73, 0x62, 0x74, 0xff, 0).buffer);
      await new Promise((done) => setTimeout(done, 0));
      assert.equal(element("psbted-text").value, "");
      assert.equal(element("psbted-error").textContent, "");
    } finally { globalThis.document = previousDocument; globalThis.window = previousWindow; }
  }
});

test("editor Clear before WASM readiness prevents the retired file read", async () => {
  let ready;
  globalThis.__psbtTestReady = new Promise((resolve) => { ready = resolve; });
  let editor = read("src/js/psbt-editor.js");
  const fakeWasm = 'export const psbtWasmReady = globalThis.__psbtTestReady; export const psbtInspectDoc = () => ({}); export const psbtBuildBytes = () => new Uint8Array();';
  editor = editor.replace('"./psbt-wasm.js"', JSON.stringify(`data:text/javascript,${encodeURIComponent(fakeWasm)}`));
  editor = editor.replace(/from "\.\/([\w.-]+)"/g, (_, path) => `from ${JSON.stringify(new URL(`../src/js/${path}`, import.meta.url).href)}`);
  const { initPsbtEditor } = await import(`data:text/javascript;base64,${Buffer.from(editor).toString("base64")}`);
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, { value: "", textContent: "", innerHTML: "", dataset: {}, files: [],
      addEventListener(type, fn) { this[`on${type}`] = fn; }, setAttribute() {}, querySelectorAll() { return []; } });
    return elements.get(id);
  };
  const previousDocument = globalThis.document, previousWindow = globalThis.window;
  globalThis.document = { getElementById: element, addEventListener() {}, dispatchEvent() {} };
  globalThis.window = { addEventListener() {} };
  try {
    initPsbtEditor();
    let reads = 0;
    element("psbted-file").files = [{ size: 6, arrayBuffer: async () => { reads++; return new ArrayBuffer(6); } }];
    element("psbted-file").onchange();
    element("psbted-wipe").onclick();
    ready();
    await new Promise((done) => setTimeout(done, 0));
    assert.equal(reads, 0);
    assert.equal(element("psbted-text").value, "");
    assert.equal(element("psbted-error").textContent, "");
  } finally {
    globalThis.document = previousDocument;
    globalThis.window = previousWindow;
    delete globalThis.__psbtTestReady;
  }
});
