// Journal view sink safety (release plan W1). A passwordless journal file is
// authenticated by nothing (audit L6), so every entry field it carries -
// label, created, walletName, fingerprint, method, input, phrase, notes - is
// attacker-controlled. The entry list and the entry view render those fields
// into innerHTML, so each one must reach the DOM through hodlEscapeHtml or
// the field helpers, and the helpers must escape. The expected escaped forms
// below are the HTML standard's entity escaping of the payload, not output
// copied from the code under test.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadAppFunctions } from "./app-slice-harness.mjs";
import { MiniDocument, MiniElement } from "./mini-dom.mjs";
import { entryMethodLabel, parseDocument, removeEntry, replaceEntry, searchEntries } from "../src/js/journal.js";
import { initJournalPageDeleteConfirm } from "../src/js/journal-page-delete-confirm.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");

// Slice one function out of app.js by brace matching, the way
// test/journal-open-acknowledge.test.mjs loads the unlock path.
function functionSource(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let depth = 0, end = -1;
  for (let index = app.indexOf("{", start); index < app.length; index++) {
    if (app[index] === "{") depth++;
    else if (app[index] === "}") {
      depth--;
      if (depth === 0) { end = index + 1; break; }
    }
  }
  assert.ok(end > start, name);
  return app.slice(start, end);
}

// The fields a crafted file controls. hodlJournalEntryMethodLabel(entry)
// reads the method and its variant, and the view builds its wallet line from
// the local `wallet`, so those count as field references too. entry.id joins
// the list as defense in depth: journal.js normalizeEntry coerces it to a
// positive safe integer or 0 today, but the sink must stay escaped if that
// ever changes.
const FIELD_REFERENCE = /\bentry\.(?:id|label|created|walletName|fingerprint|method|input|phrase|notes)\b|\bwallet\b|\bhodlJournalEntryMethodLabel\(\s*entry\s*\)/;
// The only sinks a field may be rendered through.
const ESCAPING_HELPER = /\bhodl(?:EscapeHtml|MetadataFieldHtml|PublicFieldHtml|PrivateFieldHtml|PrivateFieldMarkup|JournalPrivateValue)\s*\(/;

for (const view of ["hodlJournalRenderList", "hodlJournalOpenView"]) {
  test(`${view} routes every entry field through an escaping helper`, () => {
    const unescaped = [];
    // One level of nested braces, so an options object does not truncate the match.
    for (const match of functionSource(view).matchAll(/\$\{((?:[^{}]|\{[^{}]*\})*)\}/g)) {
      const expression = match[1];
      if (FIELD_REFERENCE.test(expression) && !ESCAPING_HELPER.test(expression)) {
        unescaped.push(expression.replace(/\s+/g, " ").trim());
      }
    }
    assert.deepEqual(unescaped, [], "an entry field reaches innerHTML without escaping");
  });
}

// The helpers, executed in Node through the same app-slice harness
// test/secret-clear.test.mjs uses.
const { hodlEscapeHtml, hodlMetadataFieldHtml, hodlPublicFieldHtml, hodlPrivateFieldHtml, hodlPrivateFieldMarkup, hodlPrivateValue } =
  await loadAppFunctions(["hodlEscapeHtml", "hodlMetadataFieldHtml", "hodlPublicFieldHtml", "hodlPrivateFieldHtml", "hodlPrivateFieldMarkup", "hodlPrivateValue"]);

// The journal's own masked-value helper closes over the module's reveal flag,
// so it is sliced by hand and given its real collaborators: the flag, the
// escaper and the translation helper. The entry view renders the phrase
// through this helper, so this — not only the generic hodlPrivateValue — is
// what must be exercised.
const journalPrivateValue = (revealed) => new Function(
  "hodlJournalReveal", "hodlEscapeHtml", "hodlT",
  `${functionSource("hodlJournalPrivateValue")}; return hodlJournalPrivateValue;`,
)(revealed, hodlEscapeHtml, (text) => text);

const payload = "<img src=x onerror=1>";
const escapedPayload = "&lt;img src=x onerror=1&gt;";
// Bidi override, zero-width space, word joiner, BOM: inert characters, never markup.
const silent = "‮​⁠﻿";
const evil = payload + silent;

test("hodlEscapeHtml escapes the five HTML special characters and keeps the rest as data", () => {
  assert.equal(hodlEscapeHtml(`&<>"'`), "&amp;&lt;&gt;&quot;&#39;");
  assert.equal(hodlEscapeHtml(evil), escapedPayload + silent);
});

test("the entry-view helpers render markup, bidi and zero-width characters as inert text", () => {
  const metadata = hodlMetadataFieldHtml("Recorded", evil, void 0, "muted");
  assert.ok(metadata.includes(escapedPayload + silent), "the metadata value is escaped, not stripped");
  assert.doesNotMatch(metadata, /<img\b/, "the metadata value cannot form an element");

  const publicField = hodlPublicFieldHtml("Master fingerprint", evil, void 0, "muted");
  assert.ok(!publicField.includes(payload), "the public field keeps no raw markup");
  assert.ok(publicField.includes("img src=x onerror=1"), "the public field keeps the value as visible text");

  const revealed = hodlPrivateValue(evil, void 0, true);
  assert.ok(revealed.includes(escapedPayload + silent), "a revealed private value is escaped, not stripped");
  assert.doesNotMatch(revealed, /<img\b/);

  const field = hodlPrivateFieldHtml("Notes", evil, void 0, "muted", true);
  assert.ok(field.includes(escapedPayload + silent), "a revealed private field is escaped, not stripped");
  assert.doesNotMatch(field, /<img\b/);
});

test("a concealed private field renders none of its value", () => {
  for (const html of [hodlPrivateValue(evil, void 0, false), hodlPrivateFieldHtml("Notes", evil, void 0, "muted", false)]) {
    assert.ok(!html.includes("onerror"), "a masked value leaked into the placeholder");
    assert.doesNotMatch(html, /<img\b/);
  }
});

test("the journal's own private-value helper escapes a revealed value and hides a concealed one", () => {
  const revealed = journalPrivateValue(true)(evil);
  assert.ok(revealed.includes(escapedPayload + silent), "a revealed journal value is escaped, not stripped");
  assert.doesNotMatch(revealed, /<img\b/);
  const concealed = journalPrivateValue(false)(evil);
  assert.ok(!concealed.includes("onerror"), "a masked journal value leaked into the placeholder");
  assert.doesNotMatch(concealed, /<img\b/);
});

test("the field helpers escape their labels as well as their values", () => {
  assert.doesNotMatch(hodlMetadataFieldHtml(evil, "value", void 0, "muted"), /<img\b/);
  assert.doesNotMatch(hodlPrivateFieldHtml(evil, "value", void 0, "muted", true), /<img\b/);
});

const savedRecord = {
  id: 7, method: "dice", diceMethod: "coldcard", input: "654321 secret rolls",
  phrase: "legacy secret phrase", label: "Saved record", notes: "private legacy note",
  created: "2026-01-02T03:04:05.000Z", walletId: 12, walletName: "Old wallet", fingerprint: "deadbeef",
};
function savedRecordHarness(version, t) {
  const raw = { version, nextId: 8, entries: [{ ...savedRecord }] };
  if (version === 3) raw.backup = {
    notebook: '{"format":"entropylab-notebook","version":1,"activePage":0,"pages":[{"number":1,"name":"Page 1","content":[{"type":"text","text":"saved notes"}]}]}',
    keyManager: '{"format":"entropylab-key-manager","version":2,"keys":[],"ignoredKeys":[]}',
    includedKeys: [], activeKey: null, snapshot: { text: "saved report", includePrivate: false }, log: [],
  };
  const doc = parseDocument(JSON.stringify(raw)), page = new MiniDocument();
  const previousDocument = globalThis.document, previousFocus = MiniElement.prototype.focus;
  globalThis.document = page;
  MiniElement.prototype.focus = function () { this.ownerDocument.activeElement = this; };
  t.after(() => { globalThis.document = previousDocument; MiniElement.prototype.focus = previousFocus; });
  page.body.innerHTML = '<button id="journal-keymanager-tab"></button><div id="journal-editor" hidden><select id="journal-method"><option value="dice">Dice</option><option value="seed">Seed</option></select><textarea id="journal-input"></textarea><textarea id="journal-phrase"></textarea><input id="journal-label"><textarea id="journal-entry-notes"></textarea><button id="journal-commit"></button><button id="journal-cancel"></button></div><div id="journal-list"></div><div id="journal-view"></div><p id="journal-error"></p>';
  const view = page.getElementById("journal-view"), tab = page.getElementById("journal-keymanager-tab"), editor = page.getElementById("journal-editor"), events = [];
  view.contains = (element) => element === view || view.querySelectorAll("*").includes(element);
  editor.contains = (element) => element === editor || editor.querySelectorAll("*").includes(element);
  tab.focus = () => { page.activeElement = tab; };
  let pending;
  const initConfirm = () => {
    const dialog = initJournalPageDeleteConfirm();
    return { hide: dialog.hide, show(options) { pending = options; dialog.show(options); } };
  };
  const api = new Function("document", "hodlJournalDoc", "helpers", "initJournalPageDeleteConfirm", "events", `
    const { hodlEscapeHtml, hodlMetadataFieldHtml, hodlPublicFieldHtml, hodlPrivateFieldHtml,
      hodlPrivateFieldMarkup, hodlJournalEntryMethodLabel, hodlJournalRemoveEntry, hodlJournalReplaceEntry, hodlJournalSearch } = helpers;
    const hodlT = text => text, hodlTText = text => text, requestAnimationFrame = fn => fn();
    const hodlJournalLog = (...args) => { events.push(args); hodlJournalDirty = true; }, hodlJournalShowWork = () => {}, hodlJournalFillWallets = () => {}, hodlJournalFillFingerprint = () => {};
    const hodlJournalUnlocked = () => Boolean(hodlJournalDoc), hodlJournalError = text => { document.getElementById("journal-error").textContent = text; };
    const hodlSyncSelect = (select, value) => { if (select) select.value = value; };
    let hodlJournalEditingId = null, hodlJournalReveal = false,
      hodlJournalDirty = false, hodlJournalEntryVariants = {}, hodlJournalPageDeleteConfirm = null, hodlJournalGeneration = 0;
    ${["hodlJournalPrivateValue", "hodlJournalRenderList", "hodlJournalHideEditor", "hodlJournalOpenView", "hodlJournalShowEditor", "hodlJournalCommit"].map(functionSource).join("\n")}
    return { open: hodlJournalOpenView, close: hodlJournalHideEditor, render: hodlJournalRenderList,
      edit: hodlJournalShowEditor, dirty: () => hodlJournalDirty,
      replace(doc) { hodlJournalDoc = doc; hodlJournalGeneration++; },
    };
  `)(page, doc, { hodlEscapeHtml, hodlMetadataFieldHtml, hodlPublicFieldHtml, hodlPrivateFieldHtml,
    hodlPrivateFieldMarkup, hodlJournalEntryMethodLabel: entryMethodLabel, hodlJournalRemoveEntry: removeEntry,
    hodlJournalReplaceEntry: replaceEntry, hodlJournalSearch: searchEntries }, initConfirm, events);
  api.render();
  const el = (name) => page.getElementById(`journal-page-delete-${name}`);
  const click = (name) => el(name).dispatchEvent({ type: "click", target: el(name) });
  return { api, page, doc, view, editor, events, tab, el, click, pending: () => pending };
}

for (const version of [2, 3]) test(`v${version} saved records start masked and remain explicitly deletable`, (t) => {
  const { api, page, doc, view, tab, el, click } = savedRecordHarness(version, t);
  assert.deepEqual(doc.entries, [savedRecord], "opening changed the stored record");
  api.open(7);
  for (const text of [savedRecord.input, savedRecord.phrase, savedRecord.notes])
    assert.ok(!view.innerHTML.includes(text), "opening a record revealed private text");
  assert.equal(page.getElementById("journal-editor").hidden, true);
  for (const id of ["journal-input", "journal-phrase", "journal-label", "journal-entry-notes"]) assert.equal(page.getElementById(id).value, "", "opening populated a hidden editor");
  assert.equal(page.getElementById("journal-copy-phrase"), null, "concealed records offer private copying");
  const reveal = page.getElementById("journal-reveal");
  reveal.checked = true;
  reveal.dispatchEvent({ type: "change", target: reveal });
  for (const text of [savedRecord.input, savedRecord.phrase, savedRecord.notes]) assert.ok(view.textContent.includes(text));
  const copy = page.getElementById("journal-copy-phrase");
  assert.ok(copy?.hasAttribute("data-private-copy"), "revealed records must use the shared private-copy path");
  assert.equal(copy.closest("[data-private-field]").querySelector("[data-private-value]").textContent, savedRecord.phrase);
  assert.deepEqual(doc.entries, [savedRecord], "viewing or revealing changed the stored record");
  const retained = doc.entries[0], deletion = page.getElementById("journal-delete");
  page.activeElement = deletion;
  deletion.click();
  assert.equal(doc.entries.length, 1, "the first delete press discarded the record");
  assert.ok(el("dialog"), "record deletion must use the shared confirmation dialog");
  assert.equal(page.activeElement, el("cancel"));
  click("confirm");
  assert.equal(doc.entries.length, 0);
  for (const field of ["input", "phrase", "notes"]) assert.equal(retained[field], "", `deleted ${field} survived in memory`);
  assert.equal(view.innerHTML, "", "deleted record text stayed rendered");
  assert.equal(page.activeElement, tab, "closing the deleted record lost keyboard focus");
});

// Only an explicitly opened, still-current record may be replaced. Invalid
// edits leave the original intact; closing wipes every temporary editor field.
test("saved-record editing changes validated fields without creating a new record or losing identity", (t) => {
  const { api, page, doc, editor, view, events } = savedRecordHarness(3, t);
  api.open(7);
  page.getElementById("journal-edit").click();
  assert.equal(editor.hidden, false);
  assert.equal(view.innerHTML, "");
  assert.equal(page.activeElement, page.getElementById("journal-label"));
  const previous = doc.entries[0];
  assert.equal(page.getElementById("journal-input").value, savedRecord.input);
  assert.equal(page.getElementById("journal-phrase").value, savedRecord.phrase);
  page.getElementById("journal-label").value = evil;
  page.getElementById("journal-entry-notes").value = "corrected private note";
  page.getElementById("journal-commit").click();
  assert.deepEqual(doc.entries, [{ ...savedRecord, label: evil.trim(), notes: "corrected private note" }]);
  assert.equal(doc.nextId, 8);
  assert.equal(previous.input, "", "replacing a record retained its old secret object");
  assert.equal(editor.hidden, true);
  for (const id of ["journal-input", "journal-phrase", "journal-label", "journal-entry-notes"]) assert.equal(page.getElementById(id).value, "");
  assert.ok(!view.innerHTML.includes("corrected private note"), "saving returned to a revealed view");
  assert.ok(!view.querySelector("[onerror]"));
  assert.equal(api.dirty(), true);
  assert.deepEqual(events, [["entry-edit", "entry-7"]], "editing logged user-supplied secret text");
});

test("invalid saved-record edits remain editable without mutating or marking the record saved", (t) => {
  const { api, page, doc, editor } = savedRecordHarness(2, t);
  api.open(7);
  page.getElementById("journal-edit").click();
  page.getElementById("journal-label").value = "   ";
  page.getElementById("journal-commit").click();
  assert.deepEqual(doc.entries, [savedRecord]);
  assert.equal(editor.hidden, false);
  assert.ok(page.getElementById("journal-error").textContent.trim());
  assert.equal(api.dirty(), false);
});

for (const [field, value] of [["journal-input", "corrected raw input"], ["journal-phrase", "corrected phrase"], ["journal-method", "seed"]]) {
  test(`changing saved recovery material in ${field} removes its old wallet attribution`, (t) => {
    const { api, page, doc } = savedRecordHarness(3, t);
    api.open(7);
    page.getElementById("journal-edit").click();
    page.getElementById(field).value = value;
    page.getElementById("journal-commit").click();
    const entry = doc.entries[0];
    assert.equal(entry.id, savedRecord.id);
    assert.equal(entry.created, savedRecord.created);
    assert.equal(entry.walletId, null);
    assert.equal(entry.walletName, "");
    assert.equal(entry.fingerprint, "");
    assert.equal(entry[field === "journal-input" ? "input" : field === "journal-phrase" ? "phrase" : "method"], value);
    if (field === "journal-method") assert.equal(entry.diceMethod, undefined);
  });
}

test("an obsolete saved-record callback cannot save or clear a newer edit", (t) => {
  const { api, page, doc, editor } = savedRecordHarness(3, t);
  api.open(7);
  page.getElementById("journal-edit").click();
  const save = page.getElementById("journal-commit").onclick;
  page.getElementById("journal-cancel").click();
  page.getElementById("journal-edit").click();
  page.getElementById("journal-input").value = "newer unfinished input";
  save();
  assert.deepEqual(doc.entries, [savedRecord]);
  assert.equal(editor.hidden, false);
  assert.equal(page.getElementById("journal-input").value, "newer unfinished input");
});

for (const close of ["cancel", "escape", "back"]) test(`saved-record ${close} discards and wipes only the temporary edit`, (t) => {
  const { api, page, doc, editor } = savedRecordHarness(3, t);
  api.open(7);
  page.getElementById("journal-edit").click();
  page.getElementById("journal-input").value = "unfinished secret correction";
  if (close === "cancel") page.getElementById("journal-cancel").click();
  else if (close === "escape") editor.onkeydown({ key: "Escape", preventDefault() {}, stopPropagation() {} });
  else api.close();
  assert.deepEqual(doc.entries, [savedRecord]);
  assert.equal(api.dirty(), false);
  assert.equal(editor.hidden, true);
  assert.equal(editor.hodlJournalEdit, undefined);
  for (const id of ["journal-input", "journal-phrase", "journal-label", "journal-entry-notes"]) assert.equal(page.getElementById(id).value, "");
});

test("saved-record edits refuse stale documents, generations, replacement records, and dismissed callbacks", (t) => {
  const { api, page, doc, editor } = savedRecordHarness(3, t);
  for (const change of ["clear", "document", "generation", "record", "cancel"]) {
    doc.entries = [{ ...savedRecord }];
    api.replace(doc);
    api.open(7);
    page.getElementById("journal-edit").click();
    page.getElementById("journal-input").value = "stale private edit";
    const save = page.getElementById("journal-commit").onclick;
    if (change === "clear") api.replace(null);
    else if (change === "document") api.replace({ entries: [{ ...savedRecord }] });
    else if (change === "generation") api.replace(doc);
    else if (change === "record") doc.entries = [{ ...savedRecord }];
    else page.getElementById("journal-cancel").click();
    save();
    assert.deepEqual(doc.entries, [savedRecord], `${change} committed a stale edit`);
    assert.equal(editor.hidden, true);
    assert.equal(page.getElementById("journal-input").value, "");
  }
});

test("saved-record editing never creates an entry for a missing ID", (t) => {
  const { api, doc, editor } = savedRecordHarness(3, t);
  for (const id of [null, undefined, 0, 8]) api.edit(id);
  assert.deepEqual(doc.entries, [savedRecord]);
  assert.equal(editor.hidden, true);
});

test("opening and closing a saved record keeps keyboard focus on visible controls", (t) => {
  const { api, page, view } = savedRecordHarness(3, t);
  const selected = page.querySelector('[data-journal-id="7"]');
  selected.focus();
  selected.click();
  const back = page.getElementById("journal-back");
  assert.equal(page.activeElement, back, "opening must move focus out of the hidden list");
  assert.equal(back.getAttribute("aria-controls"), "journal-list");
  assert.ok(page.getElementById(back.getAttribute("aria-describedby")));
  assert.equal(selected.getAttribute("aria-controls"), "journal-view");
  back.click();
  assert.equal(view.hidden, true);
  assert.equal(page.activeElement, page.querySelector('[data-journal-id="7"]'), "Back returns to the selected record after rerendering the list");
  assert.equal(page.activeElement.isConnected, true);
  api.close();
  assert.equal(page.activeElement.isConnected, true, "closing an already closed record must not move focus");
});

test("record reveal preserves its control focus without stealing focus during conceal", (t) => {
  const { api, page } = savedRecordHarness(3, t);
  api.open(7);
  let reveal = page.getElementById("journal-reveal");
  reveal.focus();
  reveal.checked = true;
  reveal.dispatchEvent({ type: "change", target: reveal });
  assert.equal(page.activeElement, page.getElementById("journal-reveal"));
  assert.equal(page.activeElement.isConnected, true);
  const outside = page.createElement("button");
  page.body.append(outside);
  outside.focus();
  reveal = page.getElementById("journal-reveal");
  reveal.checked = false;
  reveal.dispatchEvent({ type: "change", target: reveal });
  assert.equal(page.activeElement, outside, "a conceal sweep must not steal outside focus");
});

test("Cancel, Escape and backdrop retain a saved record and restore Delete focus", (t) => {
  const { api, page, doc, el, click } = savedRecordHarness(3, t);
  api.open(7);
  for (const dismiss of [
    () => click("cancel"),
    () => el("modal").dispatchEvent({ type: "keydown", key: "Escape" }),
    () => el("modal").dispatchEvent({ type: "click", target: el("modal") }),
  ]) {
    const deletion = page.getElementById("journal-delete");
    deletion.focus();
    deletion.click();
    assert.ok(el("dialog"), "deletion must await a dialog decision");
    assert.equal(el("dialog").getAttribute("role"), "dialog");
    assert.equal(el("dialog").getAttribute("aria-modal"), "true");
    for (const attr of ["aria-labelledby", "aria-describedby"]) assert.ok(page.getElementById(el("dialog").getAttribute(attr)));
    dismiss();
    assert.deepEqual(doc.entries, [savedRecord]);
    assert.equal(page.activeElement, deletion);
    click("confirm");
    assert.deepEqual(doc.entries, [savedRecord], "a dismissed confirmation cannot replay");
  }
});

test("a stale record confirmation cannot delete after close, Clear, or Journal replacement", (t) => {
  const { api, page, doc, pending, el } = savedRecordHarness(3, t);
  for (const change of ["close", "clear", "replace", "reuse-id"]) {
    doc.entries = [{ ...savedRecord }];
    api.replace(doc);
    api.open(7);
    page.getElementById("journal-delete").click();
    assert.ok(pending(), "deletion must wait before changing the session");
    const confirm = pending().onConfirm;
    if (change === "close") api.close();
    else if (change === "clear") { api.replace(null); api.close(); }
    else if (change === "replace") api.replace({ entries: [{ ...savedRecord }] });
    else doc.entries = [{ ...savedRecord }];
    confirm();
    assert.deepEqual(doc.entries, [savedRecord], `${change}: an obsolete callback removed or wiped the wrong record`);
    if (change === "close" || change === "clear") assert.equal(el("modal").hidden, true);
    api.close();
  }
});

test("the journal shell keeps saved records inside Keys and the status note as a live region", () => {
  const shell = readFileSync(join(root, "src/shell.html"), "utf8");
  const page = new MiniDocument();
  page.body.innerHTML = shell;
  const card = page.getElementById("journal-keymanager-card"), records = page.getElementById("journal-saved-records");
  assert.equal(card?.getAttribute("role"), "tabpanel");
  assert.equal(records?.closest("#journal-keymanager-card"), card, "saved records must stay reachable in Keys");
  const note = /<p\b[^>]*\bid="journal-status-note"[^>]*>/.exec(shell)?.[0] || "";
  assert.ok(/\brole="status"/.test(note), "#journal-status-note announces status changes politely");
});

test("the Journal opening screen remains a named workspace tab panel", () => {
  const page = new MiniDocument();
  page.body.innerHTML = readFileSync(join(root, "src/shell.html"), "utf8");
  const panel = page.getElementById("journal-card");
  assert.equal(panel.getAttribute("role"), "tabpanel");
  assert.ok(panel.getAttribute("aria-label") || panel.getAttribute("aria-labelledby"));
  assert.ok(panel.querySelector("#journal-gate-modes"));
});
