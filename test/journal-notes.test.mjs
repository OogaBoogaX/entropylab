import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import {
  createJournal, formatNotebook, journalFromPlainText, journalKeyReferenceRanges,
  journalKeyReferenceToken, mergeNotebookImport, parseNotebook, serializeNotebook,
} from "../src/js/journal.js";

// Notes are user-authored text: copying and importing must preserve a
// standalone timestamp, and only a truly empty page may be replaced.
test("copying notes preserves standalone timestamps and surrounding note lines", () => {
  assert.equal(formatNotebook("2026-10-22 10:00:00  "), "2026-10-22 10:00:00");
  assert.equal(formatNotebook("2026-10-22 10:00:00  \n\nCheck recovery copy."), "2026-10-22 10:00:00  \n\nCheck recovery copy.");
});

test("import retains a timestamp-only page and replaces a genuinely empty page", () => {
  const incoming = journalFromPlainText("Imported notes");
  const current = journalFromPlainText("2026-10-22 10:00:00  ");
  const merged = mergeNotebookImport(current, incoming);
  assert.deepEqual(merged.pages.map((page) => page.notesText), ["2026-10-22 10:00:00  ", "Imported notes"]);
  assert.equal(merged.activePage, 1);
  assert.deepEqual(mergeNotebookImport(journalFromPlainText(" \n\t"), incoming).pages.map((page) => page.notesText), ["Imported notes"]);
});

test("notebook round trips retain editable legacy timestamps, page styles, and key references", () => {
  const journal = journalFromPlainText("2026-10-22 10:00:00  \n\nOriginal note");
  journal.pages[0].name = "Recovery";
  journal.pages[0].style = { font: "serif", size: "large", spacing: "compact" };
  journal.pages[0].notesText += "\n" + journalKeyReferenceToken("Cold wallet", "1234abcd");
  const restored = parseNotebook(serializeNotebook(journal));
  assert.equal(restored.pages[0].name, "Recovery");
  assert.deepEqual(restored.pages[0].style, { font: "serif", size: "large", spacing: "compact" });
  assert.equal(formatNotebook(restored.pages[0].notesText), "2026-10-22 10:00:00  \n\nOriginal note\n[Key: Cold wallet · 1234abcd]");
});

const app = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");
function sourceFunction(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  const end = app.indexOf("\n}\n", start);
  assert.ok(end > start, name);
  return app.slice(start, end + 2);
}

function notesHarness(value = "") {
  const journal = createJournal();
  journal.notesText = journal.pages[0].notesText = value;
  let dirty = 0;
  const field = {
    value, selectionStart: value.length, selectionEnd: value.length, focused: false,
    setSelectionRange(start, end) { this.selectionStart = start; this.selectionEnd = end; },
    setRangeText(text, start, end) {
      this.value = this.value.slice(0, start) + text + this.value.slice(end);
      this.setSelectionRange(start + text.length, start + text.length);
    },
    focus() { this.focused = true; },
    dispatchEvent(event) { context.hodlJournalUpdateNotesText(this, event); },
  };
  const context = {
    hodlJournal: journal,
    hodlJournalMarkDirty() { dirty++; },
    hodlJournalRenderVisual() {},
    hodlJournalApplyPageStyle() {},
    hodlJournalStamp: () => "2026-10-22 10:00:01",
    hodlJournalKeyReferenceRanges: journalKeyReferenceRanges,
    InputEvent: class { constructor(type, options) { this.type = type; Object.assign(this, options); } },
  };
  for (const name of ["hodlJournalActivePage", "hodlJournalStoreNotesText", "hodlJournalRestorePage", "hodlJournalUpdateNotesText", "hodlJournalNotesClick", "hodlJournalNotesKeydown", "hodlJournalDeleteKeyReference", "hodlJournalKeyReferenceKeydown", "hodlJournalInsertTimestamp"]) {
    runInNewContext(sourceFunction(name), context);
  }
  return { field, journal, context, dirty: () => dirty };
}

test("typing and restoring plain notes preserve exact text without inserting timestamps", () => {
  const { field, journal, context, dirty } = notesHarness();
  field.value = "First line\n\n2020-01-02 03:04:05  Old note\nLast line";
  context.hodlJournalUpdateNotesText(field, { inputType: "insertFromPaste" });
  assert.equal(journal.pages[0].notesText, "First line\n\n2020-01-02 03:04:05  Old note\nLast line");
  assert.equal(field.value, journal.pages[0].notesText);
  assert.equal(dirty(), 1);
  field.value = "";
  context.hodlJournalRestorePage(field);
  assert.equal(field.value, "First line\n\n2020-01-02 03:04:05  Old note\nLast line");
  assert.equal(dirty(), 1, "restoring an existing page does not edit it");
  journal.pages[0].notesText = "";
  context.hodlJournalRestorePage(field);
  assert.equal(field.value, "", "empty pages stay empty");
});

test("ordinary typing keys and clicks do not protect or rewrite legacy timestamps", () => {
  const { field, context, dirty } = notesHarness("2026-10-22 10:00:00  \n\nOriginal note");
  for (const key of ["Enter", "Backspace", "Delete"]) {
    field.setSelectionRange(5, 5);
    let prevented = false;
    context.hodlJournalNotesKeydown({ key, preventDefault() { prevented = true; } }, field);
    assert.equal(prevented, false, `${key} uses normal textarea editing`);
  }
  for (const caret of [5, 21]) {
    field.setSelectionRange(caret, caret);
    context.hodlJournalNotesClick(field);
    assert.equal(field.selectionStart, caret);
    assert.equal(field.selectionEnd, caret);
    assert.equal(field.value, "2026-10-22 10:00:00  \n\nOriginal note");
  }
  assert.equal(dirty(), 0);
});

test("new notes append timestamped blocks without replacing selected text", () => {
  const { field, journal, context, dirty } = notesHarness("Before\nreplace\nAfter");
  field.setSelectionRange(7, 14);
  context.hodlJournalInsertTimestamp(field);
  assert.equal(field.value, "Before\nreplace\nAfter\n\n2026-10-22 10:00:01  ");
  assert.equal(journal.pages[0].notesText, field.value);
  assert.equal(field.selectionStart, 43);
  assert.equal(field.selectionEnd, 43);
  assert.equal(field.focused, true);
  assert.equal(dirty(), 1);
});

test("new notes work on empty pages and retain existing separators and key references", () => {
  const { field, context, dirty } = notesHarness();
  context.hodlJournalInsertTimestamp(field);
  assert.equal(field.value, "2026-10-22 10:00:01  ");
  context.hodlJournalInsertTimestamp(field);
  assert.equal(field.value, "2026-10-22 10:00:01  \n\n2026-10-22 10:00:01  ");
  assert.equal(dirty(), 2);
  const token = journalKeyReferenceToken("Cold wallet", "1234abcd");
  for (const trailing of ["", "\n", "\n\n", "\n\n\n"]) {
    const saved = `Keep ${token}${trailing}`;
    const { field, context } = notesHarness(saved);
    field.setSelectionRange(6, 10);
    context.hodlJournalInsertTimestamp(field);
    assert.equal(field.value, `Keep ${token}${trailing.length > 2 ? trailing : "\n\n"}2026-10-22 10:00:01  `);
    assert.equal(journalKeyReferenceRanges(field.value).length, 1);
  }
});

test("Ctrl or Command Enter starts a note but ordinary and composing Enter stay native", () => {
  for (const modifiers of [{ ctrlKey: true }, { metaKey: true }]) {
    const { field, context } = notesHarness("Keep this note");
    field.setSelectionRange(0, 4);
    let prevented = false;
    context.hodlJournalNotesKeydown({ key: "Enter", ...modifiers, preventDefault() { prevented = true; } }, field);
    assert.equal(prevented, true);
    assert.equal(field.value, "Keep this note\n\n2026-10-22 10:00:01  ");
  }
  for (const modifiers of [{}, { shiftKey: true }, { ctrlKey: true, shiftKey: true }, { ctrlKey: true, altKey: true }, { ctrlKey: true, isComposing: true }, { metaKey: true, keyCode: 229 }]) {
    const { field, context, dirty } = notesHarness("Keep this note");
    let prevented = false;
    context.hodlJournalNotesKeydown({ key: "Enter", ...modifiers, preventDefault() { prevented = true; } }, field);
    assert.equal(prevented, false);
    assert.equal(field.value, "Keep this note");
    assert.equal(dirty(), 0);
  }
});

test("key references still select and delete atomically in plain notes", () => {
  const token = journalKeyReferenceToken("Cold wallet", "1234abcd");
  const { field, journal, context } = notesHarness(`Before ${token} after`);
  field.setSelectionRange(9, 9);
  context.hodlJournalNotesClick(field);
  assert.equal(field.value.slice(field.selectionStart, field.selectionEnd), token);
  let prevented = false;
  context.hodlJournalNotesKeydown({ key: "Backspace", preventDefault() { prevented = true; } }, field);
  assert.equal(prevented, true);
  assert.equal(field.value, "Before after");
  assert.equal(journal.pages[0].notesText, "Before after");
});

test("copy availability depends on actual note content rather than empty-state wording", () => {
  const button = { disabled: true, dataset: {} }, field = { value: "No notes." };
  const context = { button, field, hodlJournalFormatNotebook: formatNotebook };
  runInNewContext(sourceFunction("hodlJournalSyncCopyButton") + "\nhodlJournalSyncCopyButton(field, button);", context);
  assert.equal(button.disabled, false);
  assert.equal(button.dataset.phrase, "No notes.");
  field.value = " \n\t";
  runInNewContext("hodlJournalSyncCopyButton(field, button);", context);
  assert.equal(button.disabled, true);
  assert.equal(button.dataset.phrase, undefined);
});
