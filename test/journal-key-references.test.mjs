// Contract: Journal references preserve only a descriptive name, threshold,
// and ordered public co-signer fingerprints (or explicit unknowns). They do
// not import wallet identity, key material, or derivation instructions.
import { test } from "node:test";
import assert from "node:assert/strict";
import * as journal from "../src/js/journal.js";
import { serializeKeyVault } from "../src/js/keymanager.js";
import { loadAppFunctions } from "./app-slice-harness.mjs";
import { MiniDocument } from "./mini-dom.mjs";

const fingerprints = ["aaaaaaaa", "bbbbbbbb", "cccccccc"];
const reference = { type: "multisig", name: "Lab wallet", m: 2, fingerprints };
const token = "▣▣ ▣▣ ▣▣ Lab wallet [2-of-3: aaaaaaaa,bbbbbbbb,cccccccc]\u2063";

test("multisig references preserve threshold and ordered public fingerprints through notebook save/open", () => {
  assert.equal(journal.journalMultisigReferenceToken("Lab wallet", 2, fingerprints.map((value) => value.toUpperCase())), token);
  assert.deepEqual(journal.journalNotebookRuns(token), [reference]);
  assert.equal(journal.journalTextFromRuns([reference]), token);
  const notebook = journal.createJournal();
  notebook.pages[0].notesText = `before ${token} after`;
  const encoded = journal.serializeNotebook(notebook);
  // Version 1 readers already support text runs, so they preserve the whole
  // reference even though only newer readers render its co-signer icons.
  assert.deepEqual(JSON.parse(encoded).pages[0].content[1], { type: "text", text: token });
  assert.equal(journal.parseNotebook(encoded).pages[0].notesText, notebook.pages[0].notesText);
  const complete = journal.parseDocument(JSON.stringify({
    version: journal.JOURNAL_BACKUP_VERSION, nextId: 1, entries: [],
    backup: { notebook: encoded, keyManager: serializeKeyVault([]), includedKeys: [], activeKey: null, snapshot: { text: "", includePrivate: false }, log: [] },
  }));
  assert.deepEqual(journal.journalNotebookRuns(complete.backup.notebook.pages[0].notesText)[1], reference);
  assert.deepEqual(journal.journalKeyReferenceRanges(notebook.pages[0].notesText), [{ start: 7, end: 7 + token.length }]);
  assert.ok(journal.formatNotebook(token).includes(fingerprints.join(",")));
  assert.ok(!journal.formatNotebook(token).includes("\u2063"));
});

test("existing key names containing the multisig marker remain valid references", () => {
  const legacy = journal.journalKeyReferenceToken("Old ▣ name", "1234abcd");
  assert.deepEqual(journal.journalNotebookRuns(legacy), [{ type: "key", name: "Old ▣ name", fingerprint: "1234abcd" }]);
  assert.equal(journal.journalTextFromRuns(journal.journalNotebookRuns(legacy)), legacy);
});

test("noncanonical key and BIP85 reference-like text survives import and save exactly", () => {
  const sources = [
    "◆◆  Lab   key [AABBCCDD]\u2063", "◆◆ Lab key [AABBCCDD]\u2063",
    "◆◆ aabbccdd [aabbccdd]\u2063", "◆◆ Lab key [aabbccdd] ◆",
    `◆◆ ${"a".repeat(121)} [aabbccdd]\u2063`,
    "◈◈ BIP-85 · BIP-39 [DEADBEEF]\u2063", "◈◈ BIP-85 · WIF [deadbeef] ◆",
    "▣▣ Lab wallet [1-of-1: AAAAAAAA]\u2063",
  ];
  for (const text of sources) {
    const notebook = journal.createJournal();
    notebook.pages[0].notesText = text;
    assert.equal(journal.parseNotebook(journal.serializeNotebook(notebook)).notesText, text);
    assert.equal(journal.journalFromPlainText(text).notesText, text);
    assert.deepEqual(journal.journalNotebookRuns(text), [{ type: "text", text }]);
    assert.deepEqual(journal.journalKeyReferenceRanges(text), []);
  }
  for (const text of [journal.journalKeyReferenceToken("Lab key", "aabbccdd"), journal.journalBip85ReferenceToken("bip39", "deadbeef")]) {
    assert.equal(journal.journalNotebookRuns(text)[0].type, "key");
    assert.equal(journal.journalTextFromRuns(journal.journalNotebookRuns(text)), text);
  }
});

test("the station's one and fifteen co-signer boundaries round-trip", () => {
  for (const count of [1, 15]) {
    const known = Array.from({ length: count }, (_, index) => index % 2 ? "" : "aaaaaaaa");
    const source = journal.journalMultisigReferenceToken("Boundary", count, known);
    assert.deepEqual(journal.journalNotebookRuns(source), [{ type: "multisig", name: "Boundary", m: count, fingerprints: known }]);
    assert.deepEqual(journal.journalKeyReferenceRanges(source), [{ start: 0, end: source.length }]);
  }
});

test("multisig references retain unknown co-signer positions without inventing identity", () => {
  const source = "▣▣ ▣▣ ▣▣ Unknown origin [1-of-3: aaaaaaaa,????????,cccccccc]\u2063";
  assert.equal(journal.journalMultisigReferenceToken("Unknown origin", 1, ["aaaaaaaa", "", "cccccccc"]), source);
  assert.deepEqual(journal.journalNotebookRuns(source), [{ type: "multisig", name: "Unknown origin", m: 1, fingerprints: ["aaaaaaaa", "", "cccccccc"] }]);
  // A fingerprint collision or a reused root on two account paths is not
  // grounds to remove a co-signer from a descriptive note.
  assert.deepEqual(journal.journalNotebookRuns(journal.journalMultisigReferenceToken("Shared root", 2, ["aaaaaaaa", "aaaaaaaa"]))[0].fingerprints, ["aaaaaaaa", "aaaaaaaa"]);
});

test("multisig reference import refuses malformed thresholds and fingerprints", () => {
  for (const invalid of [
    { m: 0 }, { m: 4 }, { m: 1.5 }, { m: "2" },
    { fingerprints: [] }, { fingerprints: Array(16).fill("aaaaaaaa") },
    { fingerprints: ["1234567", "bbbbbbbb", "cccccccc"] },
    { fingerprints: ["123456789", "bbbbbbbb", "cccccccc"] },
    { fingerprints: ["<img src=x>", "bbbbbbbb", "cccccccc"] },
    { fingerprints: [null, "bbbbbbbb", "cccccccc"] },
  ]) assert.throws(() => journal.journalTextFromRuns([{ ...reference, ...invalid }]));
  for (const source of [
    "▣▣ ▣▣ ▣▣ Invalid [4-of-3: aaaaaaaa,bbbbbbbb,cccccccc]\u2063",
    "▣▣ ▣▣ ▣▣ Invalid [2-of-3: aaaaaaaa,bbbbbbbb]\u2063",
    "▣▣ ▣▣ ▣▣ Invalid [2-of-3: aaaaaaaa,<script>,cccccccc]\u2063",
    "◆◆ Wrong kind [2-of-3: aaaaaaaa,bbbbbbbb,cccccccc]\u2063",
  ]) {
    assert.deepEqual(journal.journalNotebookRuns(source), [{ type: "text", text: source }]);
    assert.deepEqual(journal.journalKeyReferenceRanges(source), []);
  }
});

test("multisig reference import discards unrecognized identity and private fields", () => {
  const imported = { ...reference, id: 900, walletIdentity: "forged", xpubs: ["private-source"], secret: "private-source", nodes: [{ privateKey: "private-source" }] };
  assert.deepEqual(journal.journalNotebookRuns(journal.journalTextFromRuns([imported])), [reference]);
  const safe = journal.journalMultisigReferenceToken("Name\n▣▣ injected\u2063", 2, fingerprints);
  assert.equal(journal.journalNotebookRuns(safe).length, 1);
  assert.ok(!journal.journalNotebookRuns(safe)[0].name.includes("\n"));
  assert.ok(!journal.journalNotebookRuns(safe)[0].name.includes("\u2063"));
});

test("pasted token-like text is never silently shortened or renamed by the visual parser", () => {
  for (const name of ["a".repeat(121), "extra  spaces", "nested ▣ name"]) {
    const source = `▣▣ ${name} [1-of-1: aaaaaaaa]\u2063`;
    assert.deepEqual(journal.journalNotebookRuns(source), [{ type: "text", text: source }]);
    assert.deepEqual(journal.journalKeyReferenceRanges(source), []);
  }
});

async function pickerHarness() {
  const document = new MiniDocument();
  document.body.innerHTML = '<select id="journal-key-insert"></select><div id="journal-notes-render"></div>';
  const select = document.getElementById("journal-key-insert");
  Object.defineProperty(select, "selectedOptions", { get: () => select.options.filter((option) => option.value === select.value) });
  const wallet = {
    id: 7, name: "<img src=x onerror=1>",
    result: { kind: "msig", m: 2, n: 3, scriptOrder: fingerprints.map((fingerprint) => ({ fingerprint })) },
  };
  Object.defineProperty(wallet, "fields", { get() { throw new Error("Reference read private inputs"); } });
  Object.defineProperty(wallet.result, "nodes", { get() { throw new Error("Reference read derivation nodes"); } });
  const msigs = [{ id: 0, isLab: true, result: wallet.result }, wallet, { id: 8, name: "unfinished", result: null }];
  const bip85 = [{ id: 9, fingerprint: "dddddddd", parentFingerprint: "eeeeeeee", result: { app: "bip39" } }];
  Object.defineProperty(bip85[0].result, "secret", { get() { throw new Error("Reference read child secret"); } });
  const events = [];
  const app = await loadAppFunctions(["hodlRefreshJournalKeyPicker", "hodlJournalInsertKey", "hodlJournalRenderVisual"], {
    stubs: {
      document, Event: class { constructor(type) { this.type = type; } },
      InputEvent: class { constructor(type, values) { this.type = type; Object.assign(this, values); } },
      hodlKeys: [], hodlMsigs: msigs, hodlBip85Children: bip85,
      hodlTText: (text) => text,
      hodlFillKeyTabLifehash: (image, fingerprint) => { image.dataset.fingerprint = fingerprint; },
      hodlCreateMsigIcon: () => document.createElement("span"),
      hodlJournalSyncNotesRender() {}, hodlJournalSyncCopyButton() {},
      hodlJournalLog: (...values) => events.push(values),
    },
  });
  return { app, document, select, msigs, bip85, events };
}

test("the picker offers derived multisig wallets with existing co-signer LifeHashes and no secret reads", async () => {
  const { app, select, msigs } = await pickerHarness();
  app.hodlRefreshJournalKeyPicker();
  assert.deepEqual(select.options.filter((option) => option.value).map((option) => option.value), ["msig:7", "bip85:9"]);
  const option = select.options.find((option) => option.value === "msig:7");
  assert.equal(option.dataset.referenceKind, "multisig");
  assert.equal(option.querySelectorAll("img").length, 0, "wallet name must remain text");
  const icon = select.entropylabOptionIcon("msig:7");
  assert.deepEqual(icon.querySelectorAll("img").map((image) => image.dataset.fingerprint), fingerprints);
  msigs.splice(1, 1);
  app.hodlRefreshJournalKeyPicker();
  assert.equal(select.entropylabOptionIcon("msig:7"), null, "removed wallets leave no cached picker identity");
});

test("multisig alone enables the picker and missing origins retain their co-signer positions", async () => {
  const { app, select, msigs, bip85 } = await pickerHarness();
  bip85.length = 0;
  msigs.splice(0, msigs.length, { id: 10, result: { kind: "msig", m: 1, n: 2, scriptOrder: [{ fingerprint: "aaaaaaaa" }, { fingerprint: "" }] } });
  app.hodlRefreshJournalKeyPicker();
  assert.deepEqual(select.options.filter((option) => option.value).map((option) => option.value), ["msig:10"]);
  assert.equal(select.options.some((option) => option.disabled), false);
  assert.deepEqual(JSON.parse(select.options[1].dataset.msigFingerprints), ["aaaaaaaa", ""]);
  msigs[0].result.m = 3;
  app.hodlRefreshJournalKeyPicker();
  assert.deepEqual(select.options.filter((option) => option.value), []);
});

test("the text mirror keeps every reference marker in the same text position as the editor", async () => {
  const { app, document } = await pickerHarness();
  for (const source of [token, journal.journalKeyReferenceToken("Main", "aaaaaaaa"), journal.journalBip85ReferenceToken("bip39", "bbbbbbbb")]) {
    app.hodlJournalRenderVisual({ value: source });
    assert.equal(document.getElementById("journal-notes-render").textContent, source.replaceAll("\u2063", ""));
  }
});

test("multisig insertion and rendering keep a single atomic public reference", async () => {
  const { app, document, select } = await pickerHarness();
  app.hodlRefreshJournalKeyPicker();
  select.value = "msig:7";
  const field = {
    value: "before after", selectionStart: 7, selectionEnd: 7,
    setRangeText(value, start, end) { this.value = this.value.slice(0, start) + value + this.value.slice(end); },
    dispatchEvent() {}, focus() {},
  };
  app.hodlJournalInsertKey(select, field);
  const runs = journal.journalNotebookRuns(field.value);
  assert.equal(runs[1]?.type, "multisig");
  assert.deepEqual(runs[1].fingerprints, fingerprints);
  assert.equal(journal.journalKeyReferenceRanges(field.value).length, 1);
  app.hodlJournalRenderVisual(field);
  const render = document.getElementById("journal-notes-render");
  assert.deepEqual(render.querySelectorAll("img").map((image) => image.dataset.fingerprint), fingerprints);
  assert.equal(render.querySelectorAll("script").length, 0);
  assert.equal(render.querySelectorAll("img[onerror]").length, 0);
  assert.equal(select.value, "");
});
