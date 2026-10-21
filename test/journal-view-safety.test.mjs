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
// the local `wallet`, so those count as field references too.
const FIELD_REFERENCE = /\bentry\.(?:label|created|walletName|fingerprint|method|input|phrase|notes)\b|\bwallet\b|\bhodlJournalEntryMethodLabel\(\s*entry\s*\)/;
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
const { hodlEscapeHtml, hodlMetadataFieldHtml, hodlPublicFieldHtml, hodlPrivateFieldHtml, hodlPrivateValue } =
  await loadAppFunctions(["hodlEscapeHtml", "hodlMetadataFieldHtml", "hodlPublicFieldHtml", "hodlPrivateFieldHtml", "hodlPrivateValue"]);

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

test("the field helpers escape their labels as well as their values", () => {
  assert.doesNotMatch(hodlMetadataFieldHtml(evil, "value", void 0, "muted"), /<img\b/);
  assert.doesNotMatch(hodlPrivateFieldHtml(evil, "value", void 0, "muted", true), /<img\b/);
});

test("the journal shell wires the entries card as a tab panel and the status note as a live region", () => {
  const shell = readFileSync(join(root, "src/shell.html"), "utf8");
  const card = /<section\b[^>]*\bid="journal-card"[^>]*>/.exec(shell)?.[0] || "";
  assert.ok(/\brole="tabpanel"/.test(card), "#journal-card is its tool tab's panel, like its sibling cards");
  const note = /<p\b[^>]*\bid="journal-status-note"[^>]*>/.exec(shell)?.[0] || "";
  assert.ok(/\brole="status"/.test(note), "#journal-status-note announces status changes politely");
});
