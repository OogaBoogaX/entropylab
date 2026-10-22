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
  let dirty = 0, stamp = "2026-10-22 10:00:01";
  const listeners = new Map();
  const field = {
    value, selectionStart: value.length, selectionEnd: value.length, focused: false,
    selectionDirection: "none", scrollTop: 0, scrollLeft: 0, scrollHeight: 400,
    setSelectionRange(start, end, direction = "none") { this.selectionStart = start; this.selectionEnd = end; this.selectionDirection = direction; },
    setRangeText(text, start, end) {
      this.value = this.value.slice(0, start) + text + this.value.slice(end);
      this.setSelectionRange(start + text.length, start + text.length);
    },
    focus() { this.focused = true; },
    dispatchEvent(event) { context.hodlJournalUpdateNotesText(this, event); },
    addEventListener(type, listener) { listeners.set(type, listener); },
  };
  Object.defineProperty(field, "value", {
    get: () => value,
    set(next) {
      value = String(next);
      this.setSelectionRange(value.length, value.length);
      this.scrollTop = this.scrollLeft = 0;
    },
  });
  const context = {
    hodlJournal: journal,
    hodlJournalMarkDirty() { dirty++; },
    hodlJournalRenderVisual() {},
    hodlJournalApplyPageStyle() {},
    hodlJournalStamp: () => stamp,
    hodlJournalKeyReferenceRanges: journalKeyReferenceRanges,
    InputEvent: class { constructor(type, options) { this.type = type; Object.assign(this, options); } },
  };
  for (const name of ["hodlJournalActivePage", "hodlJournalStoreNotesText", "hodlJournalRestorePage", "hodlJournalUpdateNotesText", "hodlJournalNotesClick", "hodlJournalNotesKeydown", "hodlJournalDeleteKeyReference", "hodlJournalKeyReferenceKeydown", "hodlJournalInsertTimestamp", "hodlJournalTickNoteClock", "hodlJournalFreezeNoteClock"]) {
    runInNewContext(sourceFunction(name), context);
  }
  return { field, journal, context, listeners, dirty: () => dirty, setStamp(value) { stamp = value; } };
}

test("a new note's live clock advances without changing selection, scroll, or dirty state", () => {
  const { field, journal, context, dirty, setStamp } = notesHarness("Earlier note");
  context.hodlJournalInsertTimestamp(field);
  assert.equal(field.value, "Earlier note\n\n2026-10-22 10:00:01  ");
  assert.equal(journal.pages[0].pendingStamp.start, 14);
  assert.equal(journal.pages[0].pendingStamp.stamp, "2026-10-22 10:00:01");
  field.setSelectionRange(2, 8, "backward");
  field.scrollTop = 73;
  field.scrollLeft = 9;
  setStamp("2026-10-22 10:00:02");
  context.hodlJournalTickNoteClock(field);
  assert.equal(field.value, "Earlier note\n\n2026-10-22 10:00:02  ");
  assert.equal(journal.pages[0].notesText, field.value);
  assert.equal(journal.notesText, field.value);
  assert.equal(journal.pages[0].pendingStamp.stamp, "2026-10-22 10:00:02");
  assert.deepEqual([field.selectionStart, field.selectionEnd, field.selectionDirection], [2, 8, "backward"]);
  assert.deepEqual([field.scrollTop, field.scrollLeft], [73, 9]);
  assert.equal(dirty(), 1, "only creating the note needs a backup");
  context.hodlJournalTickNoteClock(field);
  assert.equal(dirty(), 1, "the same clock second does not edit the journal");
});

test("typing, pasting, cutting, deleting, and undo freeze the note clock and never rearm it", () => {
  const changes = [
    ["insertText", (value) => value + "A"],
    ["insertFromPaste", (value) => "Pasted\n" + value],
    ["deleteByCut", (value) => value.slice(3)],
    ["deleteContentBackward", (value) => value.slice(0, -1)],
    ["deleteContentForward", () => ""],
    ["historyUndo", () => "Earlier note"],
    ["historyRedo", (value) => value],
  ];
  for (const [inputType, change] of changes) {
    const { field, journal, context, setStamp } = notesHarness("Earlier note");
    context.hodlJournalInsertTimestamp(field);
    const unedited = field.value;
    field.value = change(field.value);
    context.hodlJournalUpdateNotesText(field, { inputType });
    assert.equal(journal.pages[0].pendingStamp, undefined, inputType);
    const edited = field.value;
    setStamp("2026-10-22 10:00:02");
    context.hodlJournalTickNoteClock(field);
    assert.equal(field.value, edited, inputType);
    field.value = unedited;
    context.hodlJournalUpdateNotesText(field, { inputType: "historyUndo" });
    context.hodlJournalTickNoteClock(field);
    assert.equal(field.value, unedited, `${inputType}: undo must not restart a clock`);
    assert.equal(journal.pages[0].pendingStamp, undefined, inputType);
  }
});

test("clicking within an empty note leaves its live clock running without adding text", () => {
  const { field, context, dirty, setStamp } = notesHarness("Earlier note");
  context.hodlJournalInsertTimestamp(field);
  field.setSelectionRange(17, 17);
  context.hodlJournalNotesClick(field);
  assert.equal(field.selectionStart, 17);
  setStamp("2026-10-22 10:00:02");
  context.hodlJournalTickNoteClock(field);
  assert.equal(field.value, "Earlier note\n\n2026-10-22 10:00:02  ");
  assert.equal(field.selectionStart, 17);
  assert.equal(dirty(), 1);
});

test("only the newest explicit note ticks, and a page switch preserves its pending clock", () => {
  const { field, journal, context, setStamp } = notesHarness();
  context.hodlJournalInsertTimestamp(field);
  setStamp("2026-10-22 10:00:02");
  context.hodlJournalInsertTimestamp(field);
  const firstPage = journal.pages[0];
  assert.equal(firstPage.pendingStamp.start, 23);
  journal.pages.push({ id: 2, number: 2, name: "Other", notesText: "2026-10-22 09:00:00  " });
  journal.activePage = 1;
  context.hodlJournalRestorePage(field);
  setStamp("2026-10-22 10:00:03");
  context.hodlJournalTickNoteClock(field);
  assert.equal(field.value, "2026-10-22 09:00:00  ", "a historical timestamp is not a live note");
  assert.equal(firstPage.notesText, "2026-10-22 10:00:01  \n\n2026-10-22 10:00:02  ");
  journal.activePage = 0;
  context.hodlJournalRestorePage(field);
  context.hodlJournalTickNoteClock(field);
  assert.equal(field.value, "2026-10-22 10:00:01  \n\n2026-10-22 10:00:03  ");
});

test("restoring or importing a timestamp never arms the clock and backups omit pending metadata", () => {
  const { field, journal, context, setStamp } = notesHarness();
  context.hodlJournalInsertTimestamp(field);
  const exported = serializeNotebook(journal);
  const restored = parseNotebook(exported);
  assert.equal(JSON.parse(exported).pages[0].pendingStamp, undefined);
  assert.equal(restored.pages[0].pendingStamp, undefined);
  journal.pages = restored.pages;
  journal.activePage = restored.activePage;
  context.hodlJournalRestorePage(field);
  setStamp("2026-10-22 10:00:02");
  context.hodlJournalTickNoteClock(field);
  assert.equal(field.value, "2026-10-22 10:00:01  ");
  const imported = journalFromPlainText("2026-10-22 09:00:00  ");
  journal.pages = imported.pages;
  journal.activePage = 0;
  context.hodlJournalRestorePage(field);
  context.hodlJournalTickNoteClock(field);
  assert.equal(field.value, "2026-10-22 09:00:00  ");
});

test("a clock never overwrites unsynchronized edits or a removed or replaced page", () => {
  for (const invalidate of [
    ({ field }) => { field.value += "unreported edit"; },
    ({ journal }) => { journal.pages[0].notesText += "stored edit"; },
    ({ field, journal }) => { field.value += "content"; journal.pages[0].notesText = field.value; },
    ({ journal }) => { journal.pages.length = 0; },
    ({ journal }) => { journal.pages[0] = { id: 2, number: 2, name: "Replacement", notesText: "Other page" }; },
  ]) {
    const harness = notesHarness();
    const { field, journal, context, dirty, setStamp } = harness;
    context.hodlJournalInsertTimestamp(field);
    invalidate(harness);
    const before = field.value, stored = journal.pages[0]?.notesText;
    setStamp("2026-10-22 10:00:02");
    context.hodlJournalTickNoteClock(field);
    assert.equal(field.value, before);
    assert.equal(journal.pages[0]?.notesText, stored);
    assert.equal(dirty(), 1);
  }
});

test("a malformed clock value cannot change the note's text length or caret offsets", () => {
  const { field, journal, context, setStamp } = notesHarness();
  context.hodlJournalInsertTimestamp(field);
  field.setSelectionRange(3, 8, "backward");
  setStamp("2026-10-22 10:00:002");
  context.hodlJournalTickNoteClock(field);
  assert.equal(field.value, "2026-10-22 10:00:01  ");
  assert.equal(journal.pages[0].notesText, field.value);
  assert.deepEqual([field.selectionStart, field.selectionEnd, field.selectionDirection], [3, 8, "backward"]);
});

test("edit intentions and composition freeze the clock before input, and its timer respects journal closure", () => {
  const { field, journal, context, listeners, setStamp } = notesHarness();
  const intervals = [];
  let unlocked = true;
  Object.assign(context, {
    document: { querySelectorAll: () => [], getElementById: (id) => id === "journal-notes-text" ? field : null },
    hodlInitTabDrag() {}, hodlJournalAppend() {}, hodlInitJournalActionAudit() {},
    hodlRenderJournalPageTabs() {}, hodlRefreshJournalKeyPicker() {}, hodlSyncJournalTool() {},
    hodlJournalUnlocked: () => unlocked,
    setInterval(callback, delay) { intervals.push({ callback, delay }); },
  });
  runInNewContext(sourceFunction("hodlInitJournalToolTabs"), context);
  context.hodlInitJournalToolTabs();
  assert.equal(intervals.length, 1);
  assert.equal(intervals[0].delay, 1000);
  for (const eventType of ["beforeinput", "compositionstart"]) {
    context.hodlJournalInsertTimestamp(field);
    assert.equal(typeof listeners.get(eventType), "function", eventType);
    listeners.get(eventType)({ target: field });
    assert.equal(journal.pages[0].pendingStamp, undefined, eventType);
    const before = field.value;
    setStamp("2026-10-22 10:00:02");
    intervals[0].callback();
    assert.equal(field.value, before, eventType);
  }
  context.hodlJournalInsertTimestamp(field);
  const openText = field.value;
  setStamp("2026-10-22 10:00:03");
  unlocked = false;
  intervals[0].callback();
  assert.equal(field.value, openText, "a closed journal does not run the live clock");
  unlocked = true;
  intervals[0].callback();
  assert.equal(field.value.endsWith("2026-10-22 10:00:03  "), true);
});

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
