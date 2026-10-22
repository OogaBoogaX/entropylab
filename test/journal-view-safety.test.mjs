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
import { MiniDocument } from "./mini-dom.mjs";
import { entryMethodLabel, parseDocument, removeEntry } from "../src/js/journal.js";

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
function savedRecordHarness(version) {
  const raw = { version, nextId: 8, entries: [{ ...savedRecord }] };
  if (version === 3) raw.backup = {
    notebook: '{"format":"entropylab-notebook","version":1,"activePage":0,"pages":[{"number":1,"name":"Page 1","content":[{"type":"text","text":"saved notes"}]}]}',
    keyManager: '{"format":"entropylab-key-manager","version":2,"keys":[],"ignoredKeys":[]}',
    includedKeys: [], activeKey: null, snapshot: { text: "saved report", includePrivate: false }, log: [],
  };
  const doc = parseDocument(JSON.stringify(raw)), page = new MiniDocument();
  // The legacy editor exists only so the pre-removal implementation can
  // reach the read-only contract assertion rather than fail during setup.
  page.body.innerHTML = '<button id="journal-keymanager-tab"></button><div id="journal-editor"></div><div id="journal-list"></div><div id="journal-view"></div>';
  const view = page.getElementById("journal-view"), tab = page.getElementById("journal-keymanager-tab");
  view.contains = (element) => element === view || view.querySelectorAll("*").includes(element);
  tab.focus = () => { page.activeElement = tab; };
  const api = new Function("document", "hodlJournalDoc", "helpers", `
    const { hodlEscapeHtml, hodlMetadataFieldHtml, hodlPublicFieldHtml, hodlPrivateFieldHtml,
      hodlPrivateFieldMarkup, hodlJournalEntryMethodLabel, hodlJournalRemoveEntry } = helpers;
    const hodlT = text => text, hodlTText = text => text, requestAnimationFrame = fn => fn();
    const hodlJournalLog = () => {}, hodlJournalShowWork = () => {}, hodlJournalRenderList = () => {}, hodlJournalFillWallets = () => {};
    let hodlJournalEditingId = null, hodlJournalReveal = false, hodlJournalDeleteArmed = false,
      hodlJournalDirty = false, hodlJournalEntryVariants = {};
    ${["hodlJournalPrivateValue", "hodlJournalHideEditor", "hodlJournalOpenView"].map(functionSource).join("\n")}
    return { open: hodlJournalOpenView, close: hodlJournalHideEditor };
  `)(page, doc, { hodlEscapeHtml, hodlMetadataFieldHtml, hodlPublicFieldHtml, hodlPrivateFieldHtml,
    hodlPrivateFieldMarkup, hodlJournalEntryMethodLabel: entryMethodLabel, hodlJournalRemoveEntry: removeEntry });
  return { api, page, doc, view, tab };
}

for (const version of [2, 3]) test(`v${version} saved records stay read-only, masked, and explicitly deletable`, () => {
  const { api, page, doc, view, tab } = savedRecordHarness(version);
  assert.deepEqual(doc.entries, [savedRecord], "opening changed the stored record");
  api.open(7);
  for (const text of [savedRecord.input, savedRecord.phrase, savedRecord.notes])
    assert.ok(!view.innerHTML.includes(text), "opening a record revealed private text");
  assert.equal(page.getElementById("journal-edit"), null, "saved records still offer an editor");
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
  deletion.click();
  assert.equal(doc.entries.length, 0);
  for (const field of ["input", "phrase", "notes"]) assert.equal(retained[field], "", `deleted ${field} survived in memory`);
  assert.equal(view.innerHTML, "", "deleted record text stayed rendered");
  assert.equal(page.activeElement, tab, "closing the deleted record lost keyboard focus");
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
