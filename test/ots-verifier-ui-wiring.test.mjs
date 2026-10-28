// OpenTimestamps verifier UI wiring tests — issue #460.
//
// Exercises the DOM wiring in src/js/ots-verifier-ui.js without a browser:
// a tiny fake DOM stands in for the document, and the tests hook only on
// ids and data-* attributes (never on English wording).

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { applyPreviewBlocks } from "../scripts/preview-blocks.mjs";

import {
  renderOtsResult,
  renderOtsError,
  initOtsVerifier,
} from "../src/js/ots-verifier-ui.js";

const rootDir = dirname(fileURLToPath(import.meta.url));

// ---- tiny fake DOM --------------------------------------------------------

class FakeNode {
  constructor(tagName) {
    this.tagName = String(tagName).toUpperCase();
    this.attributes = new Map();
    this.childNodes = [];
    this._text = "";
    this.hidden = false;
    this.value = "";
    this.files = [];
    this.listeners = new Map();
    this.parentNode = null;
  }
  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }
  getAttribute(name) {
    return this.attributes.has(name) ? this.attributes.get(name) : null;
  }
  hasAttribute(name) {
    return this.attributes.has(name);
  }
  removeAttribute(name) {
    this.attributes.delete(name);
  }
  appendChild(child) {
    child.parentNode = this;
    this.childNodes.push(child);
    return child;
  }
  removeChild(child) {
    const index = this.childNodes.indexOf(child);
    if (index >= 0) this.childNodes.splice(index, 1);
    child.parentNode = null;
    return child;
  }
  get firstChild() {
    return this.childNodes.length ? this.childNodes[0] : null;
  }
  set textContent(value) {
    this._text = String(value);
    this.childNodes = [];
  }
  get textContent() {
    if (this.childNodes.length === 0) return this._text;
    return this.childNodes.map((child) => child.textContent).join("");
  }
  addEventListener(type, listener) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(listener);
  }
  dispatchEvent(type) {
    const event = { type, target: this };
    for (const listener of this.listeners.get(type) || []) listener(event);
    return event;
  }
  click() {
    this.dispatchEvent("click");
  }
}

const WIRING_IDS = [
  "verify-card",
  "ots-proof-file",
  "ots-proof-choose",
  "ots-proof-name",
  "ots-proof-hex",
  "ots-original-file",
  "ots-original-choose",
  "ots-original-name",
  "ots-header-hex",
  "ots-expected-digest",
  "ots-verify",
  "ots-clear",
  "ots-result",
];

function makeDoc() {
  const elements = new Map();
  for (const id of WIRING_IDS) {
    const el = new FakeNode(id === "ots-result" ? "div" : "input");
    el.id = id;
    elements.set(id, el);
  }
  const requested = [];
  return {
    getElementById(id) {
      requested.push(id);
      return elements.get(id) || null;
    },
    createElement(tagName) {
      return new FakeNode(tagName);
    },
    _elements: elements,
    _requested: requested,
  };
}

function walk(node, visit) {
  visit(node);
  for (const child of node.childNodes) walk(child, visit);
}

function findAll(root, attribute) {
  const found = [];
  walk(root, (node) => {
    if (node.getAttribute && node.getAttribute(attribute) !== null) found.push(node);
  });
  return found;
}

function path(overrides = {}) {
  return {
    outcome: "bitcoin",
    opNames: ["sha256", "append"],
    attestation: { type: "bitcoin", height: 700000 },
    finalDigest: new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
    ...overrides,
  };
}

// ---- renderOtsResult: one test per verdict --------------------------------

test("renderOtsResult: MATCHES_SUPPLIED_HEADER carries the verdict and warning hook", () => {
  const doc = makeDoc();
  const resultEl = doc._elements.get("ots-result");
  renderOtsResult(doc, resultEl, { result: "MATCHES_SUPPLIED_HEADER", paths: [path()] });
  assert.equal(resultEl.getAttribute("data-ots-verdict"), "MATCHES_SUPPLIED_HEADER");
  assert.notEqual(resultEl.getAttribute("data-ots-warning"), null);
});

test("renderOtsResult: INVALID carries the verdict and reason", () => {
  const doc = makeDoc();
  const resultEl = doc._elements.get("ots-result");
  renderOtsResult(doc, resultEl, { result: "INVALID", reason: "header-mismatch", paths: [path()] });
  assert.equal(resultEl.getAttribute("data-ots-verdict"), "INVALID");
  assert.equal(resultEl.getAttribute("data-ots-reason"), "header-mismatch");
  assert.equal(resultEl.getAttribute("data-ots-warning"), "invalid");
});

test("renderOtsResult: PENDING carries the verdict and warning hook", () => {
  const doc = makeDoc();
  const resultEl = doc._elements.get("ots-result");
  renderOtsResult(doc, resultEl, { result: "PENDING", paths: [] });
  assert.equal(resultEl.getAttribute("data-ots-verdict"), "PENDING");
  assert.notEqual(resultEl.getAttribute("data-ots-warning"), null);
});

test("renderOtsResult: HEADER_REQUIRED carries the verdict and warning hook", () => {
  const doc = makeDoc();
  const resultEl = doc._elements.get("ots-result");
  renderOtsResult(doc, resultEl, { result: "HEADER_REQUIRED", paths: [path()] });
  assert.equal(resultEl.getAttribute("data-ots-verdict"), "HEADER_REQUIRED");
  assert.notEqual(resultEl.getAttribute("data-ots-warning"), null);
});

test("renderOtsResult: UNSUPPORTED carries the verdict and warning hook", () => {
  const doc = makeDoc();
  const resultEl = doc._elements.get("ots-result");
  renderOtsResult(doc, resultEl, { result: "UNSUPPORTED", paths: [] });
  assert.equal(resultEl.getAttribute("data-ots-verdict"), "UNSUPPORTED");
  assert.notEqual(resultEl.getAttribute("data-ots-warning"), null);
});

test("renderOtsResult: INCOMPLETE carries the verdict and limit", () => {
  const doc = makeDoc();
  const resultEl = doc._elements.get("ots-result");
  renderOtsResult(doc, resultEl, { result: "INCOMPLETE", limit: "max-ops", paths: [] });
  assert.equal(resultEl.getAttribute("data-ots-verdict"), "INCOMPLETE");
  assert.equal(resultEl.getAttribute("data-ots-limit"), "max-ops");
  assert.equal(resultEl.getAttribute("data-ots-warning"), "limit");
});

// ---- claims, paths, original file -----------------------------------------

test("renderOtsResult: claimed heights render in data-ots-claim elements", () => {
  const doc = makeDoc();
  const resultEl = doc._elements.get("ots-result");
  renderOtsResult(doc, resultEl, {
    result: "MATCHES_SUPPLIED_HEADER",
    paths: [path({ attestation: { type: "bitcoin", height: 700000 } })],
  });
  const claims = findAll(resultEl, "data-ots-claim");
  assert.ok(claims.length >= 1, "at least one claim element");
  assert.ok(claims.some((el) => el.textContent.includes("700000")));
});

test("renderOtsResult: each path renders data-ots-path with data-ots-path-outcome", () => {
  const doc = makeDoc();
  const resultEl = doc._elements.get("ots-result");
  renderOtsResult(doc, resultEl, {
    result: "MATCHES_SUPPLIED_HEADER",
    paths: [path({ outcome: "bitcoin" }), path({ outcome: "pending" })],
  });
  const rows = findAll(resultEl, "data-ots-path");
  assert.equal(rows.length, 2);
  const outcomes = rows.map((row) => {
    const outcomeEl = findAll(row, "data-ots-path-outcome")[0];
    return outcomeEl ? outcomeEl.getAttribute("data-ots-path-outcome") : null;
  });
  assert.deepEqual(outcomes, ["bitcoin", "pending"]);
});

test("renderOtsResult: original file not checked is reflected", () => {
  const doc = makeDoc();
  const resultEl = doc._elements.get("ots-result");
  renderOtsResult(
    doc,
    resultEl,
    { result: "MATCHES_SUPPLIED_HEADER", paths: [path()] },
    { originalFileProvided: false },
  );
  const original = findAll(resultEl, "data-ots-original-file");
  assert.equal(original.length, 1);
  assert.equal(original[0].getAttribute("data-ots-original-file"), "not-checked");
});

test("renderOtsResult: an unsupported original-file hash is reported as not checked", () => {
  const doc = makeDoc();
  const resultEl = doc._elements.get("ots-result");
  renderOtsResult(
    doc,
    resultEl,
    { result: "MATCHES_SUPPLIED_HEADER", paths: [path()], original: { status: "unsupported-hash" } },
    { originalFileProvided: true },
  );
  const unsupported = findAll(resultEl, "data-ots-original-file");
  assert.equal(unsupported.length, 1);
  assert.equal(unsupported[0].getAttribute("data-ots-original-file"), "not-checked");

  renderOtsResult(
    doc,
    resultEl,
    { result: "MATCHES_SUPPLIED_HEADER", paths: [path()], original: { status: "too-large" } },
    { originalFileProvided: true },
  );
  assert.equal(findAll(resultEl, "data-ots-original-file").length, 1, "an oversized original is not checked either");

  renderOtsResult(
    doc,
    resultEl,
    { result: "MATCHES_SUPPLIED_HEADER", paths: [path()], original: { status: "matches" } },
    { originalFileProvided: true },
  );
  assert.equal(findAll(resultEl, "data-ots-original-file").length, 0);
});

// ---- result layout --------------------------------------------------------

test("renderOtsResult: MATCHES with 3 paths lays out headline, caution, and a closed paths disclosure", () => {
  const doc = makeDoc();
  const resultEl = doc._elements.get("ots-result");
  renderOtsResult(doc, resultEl, {
    result: "MATCHES_SUPPLIED_HEADER",
    paths: [path(), path(), path()],
  });
  assert.equal(findAll(resultEl, "data-ots-headline").length, 1);
  const cautions = findAll(resultEl, "data-ots-caution");
  assert.equal(cautions.length, 1);
  assert.equal(cautions[0].childNodes.length, 2);
  for (const child of cautions[0].childNodes) assert.equal(child.tagName, "P");
  const details = findAll(resultEl, "data-ots-paths").filter((el) => el.tagName === "DETAILS");
  assert.equal(details.length, 1);
  assert.equal(details[0].getAttribute("open"), null);
  const summary = details[0].childNodes.find((el) => el.tagName === "SUMMARY");
  assert.ok(summary, "the disclosure has a summary");
  assert.ok(summary.textContent.includes("3"));
  assert.ok(findAll(details[0], "data-ots-claim").length >= 1);
});

test("renderOtsResult: HEADER_REQUIRED keeps claimed heights outside the paths disclosure", () => {
  const doc = makeDoc();
  const resultEl = doc._elements.get("ots-result");
  renderOtsResult(doc, resultEl, {
    result: "HEADER_REQUIRED",
    paths: [path({ attestation: { type: "bitcoin", height: 700000 } })],
  });
  const details = findAll(resultEl, "data-ots-paths").filter((el) => el.tagName === "DETAILS");
  assert.equal(details.length, 1);
  assert.equal(findAll(details[0], "data-ots-claim").length, 0);
  assert.ok(findAll(resultEl, "data-ots-claim").length >= 1);
});

test("renderOtsResult: PENDING puts its limitation in one caution note", () => {
  const doc = makeDoc();
  const resultEl = doc._elements.get("ots-result");
  renderOtsResult(doc, resultEl, { result: "PENDING", paths: [] });
  const cautions = findAll(resultEl, "data-ots-caution");
  assert.equal(cautions.length, 1);
  assert.equal(cautions[0].childNodes.length, 1);
  assert.equal(cautions[0].childNodes[0].tagName, "P");
});

test("renderOtsResult: INVALID has no caution note", () => {
  const doc = makeDoc();
  const resultEl = doc._elements.get("ots-result");
  renderOtsResult(doc, resultEl, { result: "INVALID", reason: "header-mismatch", paths: [path()] });
  assert.equal(findAll(resultEl, "data-ots-caution").length, 0);
});

test("renderOtsResult: zero paths renders a plain line, not a disclosure", () => {
  const doc = makeDoc();
  const resultEl = doc._elements.get("ots-result");
  renderOtsResult(doc, resultEl, { result: "PENDING", paths: [] });
  assert.equal(findAll(resultEl, "data-ots-paths").filter((el) => el.tagName === "DETAILS").length, 0);
  const lines = findAll(resultEl, "data-ots-paths").filter((el) => el.tagName === "P");
  assert.equal(lines.length, 1);
});

// ---- escaping -------------------------------------------------------------

test("renderOtsResult: path detail is rendered as text, not HTML", () => {
  const doc = makeDoc();
  const resultEl = doc._elements.get("ots-result");
  const payload = '<img src=x onerror=alert(1)>';
  renderOtsResult(doc, resultEl, {
    result: "MATCHES_SUPPLIED_HEADER",
    paths: [path({ detail: payload })],
  });
  const tags = [];
  walk(resultEl, (node) => tags.push(node.tagName));
  assert.ok(!tags.includes("IMG"), "no img element should be created");
  const detail = findAll(resultEl, "data-ots-path-detail")[0];
  assert.ok(detail, "detail element exists");
  assert.equal(detail.textContent, payload);
});

test("renderOtsResult: INVALID reason is rendered as text, not HTML", () => {
  const doc = makeDoc();
  const resultEl = doc._elements.get("ots-result");
  const payload = '<img src=x onerror=alert(1)>';
  renderOtsResult(doc, resultEl, { result: "INVALID", reason: payload, paths: [] });
  const tags = [];
  walk(resultEl, (node) => tags.push(node.tagName));
  assert.ok(!tags.includes("IMG"), "no img element should be created");
  assert.ok(resultEl.textContent.includes(payload));
});

// ---- renderOtsError -------------------------------------------------------

test("renderOtsError: sets ERROR verdict and clears previous verdict hooks", () => {
  const doc = makeDoc();
  const resultEl = doc._elements.get("ots-result");
  renderOtsResult(doc, resultEl, { result: "MATCHES_SUPPLIED_HEADER", paths: [path()] });
  assert.equal(resultEl.getAttribute("data-ots-verdict"), "MATCHES_SUPPLIED_HEADER");
  assert.notEqual(resultEl.getAttribute("data-ots-warning"), null);

  renderOtsError(doc, resultEl, new Error("x"));

  assert.equal(resultEl.getAttribute("data-ots-verdict"), "ERROR");
  assert.equal(resultEl.getAttribute("data-ots-warning"), null);
  assert.equal(resultEl.getAttribute("data-ots-reason"), null);
  assert.equal(resultEl.getAttribute("data-ots-limit"), null);
});

test("renderOtsError: the error is a titled note with the headline inside", () => {
  const doc = makeDoc();
  const resultEl = doc._elements.get("ots-result");
  renderOtsError(doc, resultEl, new Error("x"));
  const errors = findAll(resultEl, "data-ots-error");
  assert.equal(errors.length, 1);
  assert.equal(findAll(errors[0], "data-ots-headline").length, 1);
  assert.equal(resultEl.getAttribute("data-ots-verdict"), "ERROR");
});

// ---- initOtsVerifier ------------------------------------------------------

test("initOtsVerifier: looks up every wiring id", () => {
  const doc = makeDoc();
  initOtsVerifier(doc);
  for (const id of [
    "ots-proof-file",
    "ots-proof-choose",
    "ots-proof-hex",
    "ots-original-file",
    "ots-header-hex",
    "ots-expected-digest",
    "ots-verify",
    "ots-clear",
    "ots-result",
  ]) {
    assert.ok(doc._requested.includes(id), `looked up #${id}`);
  }
});

test("initOtsVerifier: clear empties inputs and clears the result", () => {
  const doc = makeDoc();
  initOtsVerifier(doc);
  const proofHex = doc._elements.get("ots-proof-hex");
  const headerHex = doc._elements.get("ots-header-hex");
  const expectedDigest = doc._elements.get("ots-expected-digest");
  const proofFile = doc._elements.get("ots-proof-file");
  const originalFile = doc._elements.get("ots-original-file");
  const resultEl = doc._elements.get("ots-result");
  const clearBtn = doc._elements.get("ots-clear");

  proofHex.value = "deadbeef";
  headerHex.value = "00";
  expectedDigest.value = "11";
  proofFile.value = "C:\\fake.ots";
  originalFile.value = "C:\\fake.txt";
  renderOtsResult(doc, resultEl, { result: "PENDING", paths: [] });
  assert.equal(resultEl.getAttribute("data-ots-verdict"), "PENDING");

  clearBtn.click();

  assert.equal(proofHex.value, "");
  assert.equal(headerHex.value, "");
  assert.equal(expectedDigest.value, "");
  assert.equal(proofFile.value, "");
  assert.equal(originalFile.value, "");
  assert.equal(resultEl.getAttribute("data-ots-verdict"), null);
  assert.equal(resultEl.hidden, true);
  assert.equal(resultEl.childNodes.length, 0);
});

test("initOtsVerifier: the original-file chooser opens the hidden input and shows the chosen name", () => {
  const doc = makeDoc();
  initOtsVerifier(doc);
  const choose = doc._elements.get("ots-original-choose");
  const input = doc._elements.get("ots-original-file");
  const name = doc._elements.get("ots-original-name");
  let clicked = 0;
  input.click = () => {
    clicked += 1;
  };
  choose.click();
  assert.equal(clicked, 1, "the chooser clicks the hidden input");
  input.files = [{ name: "a.txt" }];
  input.dispatchEvent("change");
  assert.equal(name.textContent, "a.txt");
  assert.equal(name.hidden, false);
  doc._elements.get("ots-clear").click();
  assert.equal(name.textContent, "");
  assert.equal(name.hidden, true);
});

test("initOtsVerifier: changing the proof hex clears a stale result", () => {
  const doc = makeDoc();
  initOtsVerifier(doc);
  const proofHex = doc._elements.get("ots-proof-hex");
  const resultEl = doc._elements.get("ots-result");

  renderOtsResult(doc, resultEl, { result: "PENDING", paths: [] });
  assert.equal(resultEl.getAttribute("data-ots-verdict"), "PENDING");

  proofHex.value = "00";
  proofHex.dispatchEvent("change");

  assert.equal(resultEl.getAttribute("data-ots-verdict"), null);
  assert.equal(resultEl.hidden, true);
});

// The Verify click handler is async; dispatchEvent drops its promise, so the
// tests call the listener and wait for it.
async function clickVerify(doc) {
  const [run] = doc._elements.get("ots-verify").listeners.get("click");
  await run({ type: "click" });
  return doc._elements.get("ots-result");
}

// Review on the UI round (Claude): a proof whose file hash is SHA-1 or
// RIPEMD-160 has a 20-byte digest, which the expected-digest box must accept.
test("initOtsVerifier: a 20-byte expected digest is compared, not refused", async () => {
  const proof = readFileSync(join(rootDir, "fixtures", "ots", "opentimestamps-client", "bitcoin.pdf.ots"));
  assert.equal(proof[32], 0x02, "the fixture's file hash op is SHA-1");
  const digest = proof.subarray(33, 53).toString("hex");
  const doc = makeDoc();
  initOtsVerifier(doc);
  doc._elements.get("ots-proof-hex").value = proof.toString("hex");
  doc._elements.get("ots-expected-digest").value = digest;
  let resultEl = await clickVerify(doc);
  assert.notEqual(resultEl.getAttribute("data-ots-verdict"), "ERROR");
  assert.notEqual(resultEl.getAttribute("data-ots-verdict"), "INVALID");
  // A different 20-byte digest reaches the verifier and fails there.
  doc._elements.get("ots-expected-digest").value = "00".repeat(20);
  resultEl = await clickVerify(doc);
  assert.equal(resultEl.getAttribute("data-ots-verdict"), "INVALID");
  // Any other length is still refused before verifying.
  doc._elements.get("ots-expected-digest").value = "00".repeat(16);
  resultEl = await clickVerify(doc);
  assert.equal(resultEl.getAttribute("data-ots-verdict"), "ERROR");
});

// Review on the UI round (Claude): the parser's and verifier's limits only
// apply to bytes in memory, so an oversized file is refused before it is read.
test("initOtsVerifier: an oversized proof or original file is refused unread", async () => {
  for (const [id, size] of [["ots-proof-file", 1048577], ["ots-original-file", 67108865]]) {
    const doc = makeDoc();
    initOtsVerifier(doc);
    if (id === "ots-original-file") doc._elements.get("ots-proof-hex").value = "00";
    let read = false;
    doc._elements.get(id).files = [{ size, arrayBuffer: async () => { read = true; return new ArrayBuffer(0); } }];
    const resultEl = await clickVerify(doc);
    assert.equal(read, false, `${id} is not read`);
    assert.equal(resultEl.getAttribute("data-ots-verdict"), "ERROR");
  }
});

test("initOtsVerifier: an oversized pasted proof is refused before parsing", async () => {
  const doc = makeDoc();
  let verified = false;
  const verifier = {
    verify: () => {
      verified = true;
      return Promise.resolve({ result: "PENDING", paths: [] });
    },
    stop: () => {},
  };
  initOtsVerifier(doc, { createVerifier: () => verifier });
  doc._elements.get("ots-proof-hex").value = "00".repeat(2 * 1048576 + 1);
  const resultEl = await clickVerify(doc);
  assert.equal(verified, false, "the verifier is never called");
  assert.equal(resultEl.getAttribute("data-ots-verdict"), "ERROR");
  assert.ok(resultEl.textContent.includes("1048576"), "the size limit is reported");
});

test("initOtsVerifier: Clear during a run calls stop() and leaves no result", async () => {
  const doc = makeDoc();
  let stopped = 0;
  let rejectRun;
  let started;
  const running = new Promise((resolve) => {
    started = resolve;
  });
  const verifier = {
    verify: () => {
      started();
      return new Promise((_, reject) => {
        rejectRun = reject;
      });
    },
    stop: () => {
      stopped += 1;
    },
  };
  initOtsVerifier(doc, { createVerifier: () => verifier });
  doc._elements.get("ots-proof-hex").value = "00";
  const [run] = doc._elements.get("ots-verify").listeners.get("click");
  const pending = run({ type: "click" });
  await running;
  doc._elements.get("ots-clear").click();
  assert.equal(stopped, 1, "Clear stopped the running verifier");
  rejectRun(Object.assign(new Error("cancelled"), { code: "CANCELLED" }));
  await pending;
  const resultEl = doc._elements.get("ots-result");
  assert.equal(resultEl.getAttribute("data-ots-verdict"), null);
  assert.equal(resultEl.hidden, true);
  assert.equal(resultEl.childNodes.length, 0);
});

test("initOtsVerifier: an edit during a run cancels it and renders nothing", async () => {
  const doc = makeDoc();
  let stopped = 0;
  let resolveRun;
  let started;
  const running = new Promise((resolve) => {
    started = resolve;
  });
  const verifier = {
    verify: () => {
      started();
      return new Promise((resolve) => {
        resolveRun = resolve;
      });
    },
    stop: () => {
      stopped += 1;
    },
  };
  initOtsVerifier(doc, { createVerifier: () => verifier });
  doc._elements.get("ots-proof-hex").value = "00";
  const [run] = doc._elements.get("ots-verify").listeners.get("click");
  const pending = run({ type: "click" });
  await running;
  doc._elements.get("ots-header-hex").dispatchEvent("input");
  assert.equal(stopped, 1, "the edit stopped the running verifier");
  resolveRun({ result: "MATCHES_SUPPLIED_HEADER", paths: [] });
  await pending;
  const resultEl = doc._elements.get("ots-result");
  assert.equal(resultEl.getAttribute("data-ots-verdict"), null);
  assert.equal(resultEl.hidden, true);
});

// Review on the tests round (Muse): the fake DOM cannot parse HTML, so pin
// at the source that the module never assigns markup.
test("ots-verifier-ui.js never assigns HTML to the page", () => {
  const source = readFileSync(join(rootDir, "..", "src", "js", "ots-verifier-ui.js"), "utf8");
  assert.doesNotMatch(source, /\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write/);
});

// ---- release build --------------------------------------------------------

test("release shell drops preview-only OTS markup", () => {
  const shell = readFileSync(join(rootDir, "..", "src", "shell.html"), "utf8");
  // The build's own stripper (review on the tests round, Muse).
  const release = applyPreviewBlocks(shell, false);
  assert.ok(!release.includes('id="verify-card"'), "release shell must not contain #verify-card");
  assert.ok(
    !release.includes('aria-controls="verify-card"'),
    "release shell must not reference #verify-card",
  );
  assert.ok(!release.includes('id="ots-station"'), "release shell must not contain #ots-station");
});

// Review on the tests round (Muse): a backwards scan could credit an earlier,
// unrelated if (PREVIEW). Every call must carry its own guard on its line.
test("release app.js does not call initOtsVerifier outside an if (PREVIEW) guard", () => {
  const app = readFileSync(join(rootDir, "..", "src", "js", "app.js"), "utf8");
  const calls = app.split("\n").filter((line) => /initOtsVerifier\s*\(/.test(line));
  assert.ok(calls.length > 0, "app.js calls initOtsVerifier");
  for (const line of calls) {
    assert.match(line, /^\s*if\s*\(\s*PREVIEW\s*\)\s*initOtsVerifier\s*\(\s*document\s*\)\s*;\s*$/, line);
  }
});

// Review on 19d228b2 (Kimi K3): the verifier transfers its inputs, which
// detached the page's header bytes, so the header-time claim never rendered.
test("initOtsVerifier: the header-time claim survives a verifier that transfers its inputs", async () => {
  const doc = makeDoc();
  const verifier = {
    verify: (input) => {
      // Transfer, as the worker client does: the passed buffers are detached.
      structuredClone(input, { transfer: [input.proofBytes.buffer, input.header.buffer] });
      return Promise.resolve({ result: "MATCHES_SUPPLIED_HEADER", paths: [path()] });
    },
    stop: () => {},
  };
  initOtsVerifier(doc, { createVerifier: () => verifier });
  doc._elements.get("ots-proof-hex").value = "00";
  doc._elements.get("ots-header-hex").value = "00".repeat(80);
  const resultEl = await clickVerify(doc);
  const claims = findAll(resultEl, "data-ots-claim").filter((node) => node.getAttribute("data-ots-claim") === "header-time");
  assert.equal(claims.length, 1);
});

// Review on 2edfabe8 (MiniMax): a chosen file must not win over a proof
// pasted afterwards, nor pasted hex over a file chosen afterwards.
test("initOtsVerifier: the proof entered last is the one verified", () => {
  const doc = makeDoc();
  initOtsVerifier(doc, { createVerifier: () => ({ verify: () => Promise.resolve({ result: "PENDING", paths: [] }), stop: () => {} }) });
  const file = doc._elements.get("ots-proof-file");
  const hex = doc._elements.get("ots-proof-hex");
  hex.value = "0011";
  file.files = [{ name: "a.ots" }];
  file.value = "C:\fakepath\a.ots";
  file.dispatchEvent("change");
  assert.equal(hex.value, "", "choosing a file clears the pasted hex");
  hex.value = "2233";
  hex.dispatchEvent("input");
  assert.equal(file.value, "", "pasting hex clears the chosen file");
});
