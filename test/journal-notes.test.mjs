import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import { MiniDocument } from "./mini-dom.mjs";
import * as journalModule from "../src/js/journal.js";
import {
  createJournal, formatNotebook, formatNotebookPages, journalFromPlainText, journalKeyReferenceRanges,
  journalKeyReferenceToken, journalNotebookRuns, mergeNotebookImport, parseNotebook, serializeNotebook,
} from "../src/js/journal.js";

// Notes are user-authored text: copying and importing must preserve a
// standalone timestamp, and only an empty page or a trusted untouched
// starter may be replaced.
test("copying notes preserves standalone timestamps and surrounding note lines", () => {
  assert.equal(formatNotebook("2026-10-22 10:00:00  "), "2026-10-22 10:00:00");
  assert.equal(formatNotebook("2026-10-22 10:00:00  \n\nCheck recovery copy."), "2026-10-22 10:00:00  \n\nCheck recovery copy.");
});

test("notebook exports and readable copies preserve the visible clock preview without changing editing history state", () => {
  const raw = "Earlier note\n\n2020-01-02 03:04:05  ", visible = "Earlier note\n\n2026-10-23 09:08:07  ";
  const journal = journalFromPlainText(raw), page = journal.pages[0];
  page.pendingStamp = { start: 14, stamp: "2020-01-02 03:04:05", preview: "2026-10-23 09:08:07" };
  page.editorView = { start: 2, end: 5, direction: "backward", top: 40, left: 0 };
  const pending = page.pendingStamp, previous = structuredClone(journal);
  const exported = serializeNotebook(journal), restored = parseNotebook(exported);
  assert.equal(restored.pages[0].notesText, visible);
  assert.equal(formatNotebookPages(journal.pages), visible.trimEnd());
  assert.equal(formatNotebookPages([{ name: "Other page", notesText: "Other notes" }, page]), "Other page\nOther notes\n\nPage 1\n" + visible.trimEnd());
  assert.equal(journalModule.journalPageNotesText(page), visible);
  assert.deepEqual(journal, previous, "reading and saving the preview must not mutate raw text, selection metadata, or pending clock state");
  assert.equal(page.pendingStamp, pending);
  const document = JSON.parse(exported);
  assert.equal(document.pages[0].pendingStamp, undefined);
  assert.equal(restored.pages[0].pendingStamp, undefined);
  document.pages[0].pendingStamp = { start: 14, stamp: "2026-10-23 09:08:07", preview: "2030-01-02 03:04:05" };
  const forged = parseNotebook(JSON.stringify(document));
  assert.equal(journalModule.journalPageNotesText(forged.pages[0]), visible, "imported metadata cannot rewrite a historical timestamp");
  assert.equal(forged.pages[0].pendingStamp, undefined);
});

test("visible note text applies only a valid matching pending preview and otherwise preserves the raw page", () => {
  assert.equal(typeof journalModule.journalPageNotesText, "function");
  const stamp = "2020-01-02 03:04:05", preview = "2026-10-23 09:08:07", raw = stamp + "  ";
  const pendingStamp = { start: 0, stamp, preview };
  assert.equal(journalModule.journalPageNotesText({ notesText: raw, pendingStamp }), preview + "  ");
  assert.equal(journalModule.journalPageNotesText(undefined), "");
  for (const pending of [undefined, { start: 0, stamp }, ...[
    { preview: "" }, { preview: "short" }, { preview: "2026-10-23 09:08:07 extra" }, { preview: 19 },
    { stamp: "short" }, { stamp: "2020-01-02 03:04:06" }, { start: -1 }, { start: 0.5 }, { start: 1 }, { start: 22 },
  ].map((override) => ({ ...pendingStamp, ...override }))]) {
    assert.equal(journalModule.journalPageNotesText({ notesText: raw, pendingStamp: pending }), raw);
  }
  for (const text of [raw + "written", raw + "\n", "", "Historical note"]) {
    assert.equal(journalModule.journalPageNotesText({ notesText: text, pendingStamp }), text);
  }
  assert.equal(journalModule.journalPageNotesText({ notesText: "body" + raw, pendingStamp: { ...pendingStamp, start: 4 } }), "body" + raw, "a preview cannot modify a timestamp embedded in body text");
});

test("import retains a timestamp-only page and replaces a genuinely empty page", () => {
  const incoming = journalFromPlainText("Imported notes");
  const current = journalFromPlainText("2026-10-22 10:00:00  ");
  const merged = mergeNotebookImport(current, incoming);
  assert.deepEqual(merged.pages.map((page) => page.notesText), ["2026-10-22 10:00:00  ", "Imported notes"]);
  assert.equal(merged.activePage, 1);
  assert.deepEqual(mergeNotebookImport(journalFromPlainText(" \n\t"), incoming).pages.map((page) => page.notesText), ["Imported notes"]);
});

test("importing pages retains the visible timestamp and editing state of existing pages", () => {
  const prefix = "Earlier note\n\n", current = journalFromPlainText(prefix + "2026-10-22 10:00:00  ");
  current.pages[0].pendingStamp = { start: prefix.length, stamp: "2026-10-22 10:00:00", preview: "2026-10-22 10:00:09" };
  const merged = mergeNotebookImport(current, journalFromPlainText("Imported notes"));
  assert.equal(journalModule.journalPageNotesText(merged.pages[0]), prefix + "2026-10-22 10:00:09  ");
  assert.equal(merged.pages[0], current.pages[0]);
  assert.equal(current.pages[0].notesText, prefix + "2026-10-22 10:00:00  ");
});

test("import reuses a trusted untouched starter without discarding historical timestamps or note content", () => {
  const incoming = journalFromPlainText("Imported notes"), h = notesHarness();
  h.context.hodlJournalStartPage();
  const starter = h.journal.pages[0], stamp = starter.pendingStamp.stamp;
  let merged = mergeNotebookImport(h.journal, incoming);
  assert.deepEqual(merged.pages.map((page) => page.notesText), ["Imported notes"]);
  assert.equal(merged.pages[0].id, starter.id);
  assert.equal(merged.pages[0].pendingStamp, undefined, "incoming content cannot inherit the replaced page's live clock");
  assert.equal(merged.activePage, 0);

  // The app must still preserve a note if runtime metadata is stale.
  for (const text of [stamp + "  Written note", "2020-01-02 03:04:05  ", "Earlier note\n\n" + stamp + "  "]) {
    starter.notesText = text;
    merged = mergeNotebookImport(h.journal, incoming);
    assert.deepEqual(merged.pages.map((page) => page.notesText), [text, "Imported notes"]);
  }
  starter.notesText = stamp + "  ";
  const serialized = JSON.parse(serializeNotebook(h.journal));
  serialized.pages[0].pendingStamp = { start: 0, stamp };
  const historical = parseNotebook(JSON.stringify(serialized));
  assert.equal(historical.pages[0].pendingStamp, undefined, "file metadata cannot claim an imported timestamp is an untouched starter");
  assert.deepEqual(mergeNotebookImport(historical, incoming).pages.map((page) => page.notesText), [stamp + "  ", "Imported notes"]);

  h.journal.pages.push(...Array.from({ length: 99 }, (_, index) => ({ id: index + 2, number: index + 2, name: `Page ${index + 2}`, notesText: `Existing note ${index + 2}` })));
  merged = mergeNotebookImport(h.journal, incoming);
  assert.equal(merged.pages.length, 100, "a starter replacement must fit at the page limit");
  assert.equal(merged.pages[0].notesText, "Imported notes");
  assert.equal(merged.pages[99].notesText, "Existing note 100");
  delete starter.pendingStamp;
  assert.throws(() => mergeNotebookImport(h.journal, incoming), /100/, "a historical timestamp at capacity must be retained and refuse the extra page");
});

test("notebook round trips retain legacy timestamps, page styles, and key references", () => {
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
  let start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  if (app.slice(start - 6, start) === "async ") start -= 6;
  const end = app.indexOf("\n}\n", start);
  assert.ok(end > start, name);
  return app.slice(start, end + 2);
}

test("adding a page stops at the 100-page backup limit without losing the current page", () => {
  const journal = createJournal(), messages = [], events = [];
  journal.pages = Array.from({ length: 99 }, (_, index) => ({
    id: index + 1, number: index + 1, name: `Page ${index + 1}`, notesText: `Note ${index + 1}`,
  }));
  journal.nextPageId = journal.nextPageNumber = 100;
  const field = { value: "Note 1" };
  const context = {
    hodlJournal: journal, hodlJournalMaxPages: 100,
    hodlJournalStamp: () => "2026-10-22 10:00:01",
    hodlTText: (message) => message,
    hodlJournalSetStatus: (...args) => messages.push(args),
    document: { getElementById: (id) => id === "journal-notes-text" ? field : null },
    hodlJournalStoreNotesText() { journal.pages[journal.activePage].notesText = field.value; },
    hodlJournalActivePageStyle: () => ({ font: "mono", size: "medium", spacing: "comfortable" }),
    hodlJournalDefaultPageName: (number) => `Page ${number}`,
    hodlRenderJournalPageTabs() {},
    hodlJournalRestorePage() { field.value = journal.pages[journal.activePage].notesText; },
    hodlJournalLog: (...args) => events.push(args),
  };
  for (const name of ["hodlJournalActivePage", "hodlJournalStartPage", "hodlAddJournalPage"]) runInNewContext(sourceFunction(name), context);
  context.hodlAddJournalPage();
  assert.equal(journal.pages.length, 100);
  assert.equal(journal.activePage, 99);
  assert.equal(journal.nextPageId, 101);
  assert.deepEqual(messages, [[""]], "adding a page clears an earlier page-limit error");
  messages.length = 0;
  field.value = journal.pages[99].notesText = "Last page's unsaved note";
  context.hodlAddJournalPage();
  assert.equal(journal.pages.length, 100);
  assert.equal(journal.activePage, 99);
  assert.equal(field.value, "Last page's unsaved note");
  assert.equal(journal.pages[99].notesText, field.value);
  assert.equal(journal.nextPageId, 101);
  assert.equal(journal.nextPageNumber, 101);
  assert.equal(events.length, 1, "refusal must not record a page addition");
  assert.equal(messages.length, 1);
  assert.equal(typeof messages[0][0], "string");
  assert.ok(messages[0][0].length);
  assert.equal(messages[0][1], true);
});

function notesHarness(value = "") {
  const journal = createJournal();
  journal.notesText = journal.pages[0].notesText = value;
  let dirty = 0, stamp = "2026-10-22 10:00:01";
  const messages = [], events = [];
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
      value = String(next).replace(/\r\n?/g, "\n");
      this.setSelectionRange(value.length, value.length);
      this.scrollTop = this.scrollLeft = 0;
    },
  });
  const context = {
    hodlJournal: journal,
    hodlJournalMaxPages: 100, hodlJournalSetStatus: (...args) => messages.push(args), hodlTText: (text) => text,
    hodlJournalActivePageStyle: () => ({ font: "mono", size: "medium", spacing: "comfortable" }),
    hodlJournalDefaultPageName: (number) => `Page ${number}`,
    document: { getElementById: (id) => id === "journal-notes-text" ? field : null },
    hodlJournalMarkDirty() { dirty++; },
    hodlJournalRenderVisual() {},
    hodlJournalSyncNotesRender() {},
    hodlRenderJournalPageTabs() {},
    hodlJournalLog: (...args) => events.push(args),
    hodlJournalApplyPageStyle() {},
    hodlJournalStamp: () => stamp,
    hodlJournalKeyReferenceRanges: journalKeyReferenceRanges,
    hodlJournalPageNotesText: journalModule.journalPageNotesText,
    InputEvent: class { constructor(type, options) { this.type = type; Object.assign(this, options); } },
  };
  for (const name of ["hodlJournalActivePage", "hodlJournalStartPage", "hodlAddJournalPage", "hodlJournalStoreNotesText", "hodlJournalRestorePage", "hodlSelectJournalPage", "hodlJournalUpdateNotesText", "hodlJournalNotesClick", "hodlJournalNotesKeydown", "hodlJournalDeleteKeyReference", "hodlJournalKeyReferenceKeydown", "hodlJournalInsertTimestamp", "hodlJournalTickNoteClock", "hodlJournalCommitNoteClock", "hodlJournalFreezeNoteClock", "hodlJournalStampRanges", "hodlJournalSelectEmptyStamp", "hodlJournalLogNoteChange", "hodlJournalNoteEditAllowed", "hodlJournalNotesBeforeInput", "hodlJournalNotesCompositionStart", "hodlJournalRejectNoteEdit", "hodlJournalRememberNotesEdit", "hodlJournalBeginNoteDrag", "hodlJournalFinishNoteDrag"]) {
    runInNewContext(sourceFunction(name), context);
  }
  return { field, journal, context, listeners, messages, events, dirty: () => dirty, setStamp(value) { stamp = value; } };
}

function notesPromptHarness() {
  const h = notesHarness(), document = new MiniDocument();
  const render = document.createElement("div");
  render.id = "journal-notes-render";
  document.body.append(render);
  h.field.placeholder = "A translated <note> hint";
  Object.assign(h.context, {
    document: {
      getElementById: (id) => id === "journal-notes-text" ? h.field : document.getElementById(id),
      createElement: (tag) => document.createElement(tag),
      createTextNode: (text) => document.createTextNode(text),
    },
    hodlJournalNotebookRuns: journalNotebookRuns,
    hodlJournalSyncCopyButton() {},
    hodlTText: () => h.field.placeholder,
  });
  runInNewContext(sourceFunction("hodlJournalRenderVisual"), h.context);
  return { ...h, document, render };
}

test("the fresh-page hint follows the live timestamp without entering copied or saved notes", () => {
  const { field, journal, context, document, render, setStamp } = notesPromptHarness();
  context.hodlJournalStartPage();
  context.hodlJournalRestorePage(field);
  const prompt = () => document.getElementById("journal-notes-prompt");
  assert.equal(prompt()?.textContent, field.placeholder);
  assert.equal(prompt().children.length, 0, "translated prompt stays inert text");
  assert.equal(render.textContent, field.value + field.placeholder);
  field.setSelectionRange(4, 7, "backward");
  setStamp("2026-10-22 10:00:02");
  context.hodlJournalTickNoteClock(field);
  assert.equal(render.textContent, field.value + field.placeholder);
  assert.deepEqual([field.selectionStart, field.selectionEnd], [4, 7]);
  assert.equal(formatNotebook(field.value), "2026-10-22 10:00:02");
  const saved = serializeNotebook(journal);
  assert.equal(saved.includes(field.placeholder), false);
  journal.pages = parseNotebook(saved).pages;
  context.hodlJournalRestorePage(field);
  assert.equal(prompt(), null, "historical timestamp-only pages have no live hint");
});

test("each pending note suffix shows an inert hint until edited, without changing copied or saved text", () => {
  const { field, journal, context, document, render, setStamp } = notesPromptHarness();
  field.value = "Earlier note";
  context.hodlJournalUpdateNotesText(field);
  context.hodlJournalInsertTimestamp(field);
  const prompt = () => document.getElementById("journal-notes-prompt");
  assert.equal(prompt()?.textContent, field.placeholder);
  assert.equal(render.textContent, field.value + field.placeholder);
  assert.equal(prompt().children.length, 0);
  setStamp("2026-10-22 10:00:02");
  context.hodlJournalTickNoteClock(field);
  assert.equal(render.textContent, field.value + field.placeholder);
  assert.equal(formatNotebook(field.value).includes(field.placeholder), false);
  assert.equal(serializeNotebook(journal).includes(field.placeholder), false);
  field.value += "Written note";
  context.hodlJournalRenderVisual(field);
  assert.equal(prompt(), null, "stale pending metadata cannot append a hint after actual note content");
  context.hodlJournalUpdateNotesText(field);
  context.hodlJournalInsertTimestamp(field);
  assert.equal(prompt()?.textContent, field.placeholder);
  context.hodlJournalFreezeNoteClock();
  assert.equal(prompt(), null);
});

test("starting an edit removes the hint and undo or clearing cannot recreate it", () => {
  const { field, context, document } = notesPromptHarness();
  context.hodlJournalStartPage();
  context.hodlJournalRestorePage(field);
  const original = field.value;
  assert.ok(document.getElementById("journal-notes-prompt"));
  context.hodlJournalFreezeNoteClock();
  assert.equal(document.getElementById("journal-notes-prompt"), null, "composition start removes the hint before an input event");
  for (const value of [original + " ", original + "\n", "", original]) {
    field.value = value;
    context.hodlJournalUpdateNotesText(field);
    assert.equal(document.getElementById("journal-notes-prompt"), null);
  }
  field.value = "";
  context.hodlJournalUpdateNotesText(field);
  context.hodlJournalInsertTimestamp(field);
  assert.equal(document.getElementById("journal-notes-prompt")?.textContent, field.placeholder, "an explicit first note shows its hint immediately");
});

test("a fresh page begins with a live timestamp and deleting it never rearms the clock", () => {
  const { field, journal, context, setStamp } = notesHarness("Existing page text");
  context.hodlAddJournalPage();
  assert.equal(journal.pages[0].notesText, "Existing page text");
  assert.equal(field.value, "2026-10-22 10:00:01  ");
  assert.equal(field.selectionStart, field.value.length);
  setStamp("2026-10-22 10:00:02");
  context.hodlJournalTickNoteClock(field);
  assert.equal(field.value, "2026-10-22 10:00:02  ");
  field.value = "";
  context.hodlJournalUpdateNotesText(field);
  context.hodlSelectJournalPage(0);
  context.hodlSelectJournalPage(1);
  setStamp("2026-10-22 10:00:03");
  context.hodlJournalTickNoteClock(field);
  assert.equal(field.value, "");
  assert.equal(journal.pages[1].pendingStamp, undefined);
});

test("switching note pages restores each selection and scroll without editing or exporting that view", () => {
  const { field, journal, context, dirty } = notesHarness("First page with existing notes");
  journal.pages.push({ id: 2, number: 2, name: "Other", notesText: "Second page text" });
  field.setSelectionRange(2, 8, "backward");
  field.scrollTop = 90;
  field.scrollLeft = 15;
  context.hodlSelectJournalPage(1);
  assert.equal(field.value, "Second page text");
  assert.equal(field.selectionStart, field.value.length, "an unvisited page starts at the end");
  field.setSelectionRange(3, 3);
  field.scrollTop = 30;
  field.scrollLeft = 5;
  context.hodlSelectJournalPage(0);
  assert.equal(field.value, "First page with existing notes");
  assert.deepEqual([field.selectionStart, field.selectionEnd, field.selectionDirection], [2, 8, "backward"]);
  assert.deepEqual([field.scrollTop, field.scrollLeft], [90, 15]);
  context.hodlSelectJournalPage(1);
  assert.deepEqual([field.selectionStart, field.selectionEnd, field.selectionDirection], [3, 3, "none"]);
  assert.deepEqual([field.scrollTop, field.scrollLeft], [30, 5]);
  assert.equal(dirty(), 0);
  const exported = serializeNotebook(journal), restored = parseNotebook(exported);
  for (const page of JSON.parse(exported).pages) assert.equal(page.editorView, undefined);
  for (const page of restored.pages) assert.equal(page.editorView, undefined);
});

test("restoring a page selection remains stable through its pending timestamp tick", () => {
  const { field, journal, context, setStamp, dirty } = notesHarness("Earlier note");
  context.hodlJournalInsertTimestamp(field);
  field.setSelectionRange(1, 5, "backward");
  field.scrollTop = 45;
  journal.pages.push({ id: 2, number: 2, name: "Other", notesText: "Other text" });
  context.hodlSelectJournalPage(1);
  context.hodlSelectJournalPage(0);
  setStamp("2026-10-22 10:00:02");
  context.hodlJournalTickNoteClock(field);
  assert.equal(field.value, "Earlier note\n\n2026-10-22 10:00:02  ");
  assert.deepEqual([field.selectionStart, field.selectionEnd, field.selectionDirection], [1, 5, "backward"]);
  assert.equal(field.scrollTop, 45);
  assert.equal(dirty(), 1);
});

function renameHarness() {
  const document = new MiniDocument(), journal = createJournal(), messages = [], events = [];
  journal.pages.push({ id: 2, number: 2, name: "Other page", notesText: "" });
  const create = document.createElement.bind(document);
  document.createElement = (tag) => {
    const element = create(tag);
    element.replaceWith = function (replacement) { this.after(replacement); this.remove(); };
    element.focus = () => { document.activeElement = element; };
    return element;
  };
  const box = document.createElement("div");
  box.id = "journal-page-tabs";
  const panel = document.createElement("div");
  panel.id = "journal-page-panel";
  document.body.append(box, panel);
  const context = {
    document, hodlJournal: journal, hodlTText: (text) => text, hodlSizeKeyTabEditor() {},
    hodlJournalSetStatus: (...args) => messages.push(args),
    hodlJournalLog: (...args) => events.push(args),
    hodlCreateJournalPageTab(index) {
      const button = document.createElement("button");
      button.id = `journal-page-tab-${journal.pages[index].id}`;
      button.textContent = journal.pages[index].name;
      return button;
    },
  };
  for (const name of ["hodlJournalNormalizePageName", "hodlJournalPageNameTaken", "hodlBeginJournalPageRename"]) runInNewContext(sourceFunction(name), context);
  box.append(context.hodlCreateJournalPageTab(0), context.hodlCreateJournalPageTab(1));
  context.hodlBeginJournalPageRename(0);
  return { document, journal, context, box, input: box.querySelector("input"), messages, events };
}

test("invalid page renames explain the problem and stay editable until corrected or canceled", () => {
  for (const name of [" \t ", " other   PAGE "]) {
    const h = renameHarness();
    h.input.value = name;
    h.input.onkeydown({ key: "Enter", preventDefault() {} });
    assert.equal(h.journal.pages[0].name, "Page 1");
    assert.equal(h.input.isConnected, true);
    assert.equal(h.input.getAttribute("aria-invalid"), "true");
    assert.equal(h.messages.at(-1)[1], true);
    assert.ok(h.messages.at(-1)[0].length);
    assert.equal(h.events.length, 0);
    h.input.value = "  Lab   notes  ";
    h.input.onkeydown({ key: "Enter", preventDefault() {} });
    assert.equal(h.journal.pages[0].name, "Lab notes");
    assert.equal(h.input.isConnected, false);
    assert.equal(h.document.activeElement, h.box.children[0]);
    assert.equal(h.events.length, 1);
    assert.equal(h.messages.at(-1)[0], "");
  }
  const canceled = renameHarness();
  canceled.input.value = "Other page";
  canceled.input.onkeydown({ key: "Enter", preventDefault() {} });
  canceled.input.onkeydown({ key: "Escape", preventDefault() {} });
  assert.equal(canceled.journal.pages[0].name, "Page 1");
  assert.equal(canceled.input.isConnected, false);
  assert.equal(canceled.messages.at(-1)[0], "");
  assert.equal(canceled.events.length, 0);
});

test("an invalid rename on blur keeps the original page name and explains the refusal", () => {
  const h = renameHarness();
  h.input.value = "Other page";
  h.input.onblur();
  assert.equal(h.journal.pages[0].name, "Page 1");
  assert.equal(h.input.isConnected, false, "blur must not trap navigation in the rename input");
  assert.ok(h.messages.length, "the rejected rename must explain why the name was kept");
  assert.equal(h.messages.at(-1)[1], true);
  assert.ok(h.messages.at(-1)[0].length);
  assert.equal(h.events.length, 0);
});

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

test("unrelated edits, whole-note deletion, and history replay freeze the note clock", () => {
  const changes = [
    ["insertText", (value) => value + "A"],
    ["insertFromPaste", (value) => "Pasted\n" + value],
    ["deleteByCut", (value) => value.slice(3)],
    ["deleteContentBackward", (value) => value.replace("Earlier note", "Earlier not")],
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
  const copyEvent = { type: "copy" }, selectionCopies = [];
  context.hodlJournalCopyNotesSelection = (event, target) => selectionCopies.push({ event, target });
  assert.equal(typeof listeners.get("copy"), "function");
  listeners.get("copy")(copyEvent);
  assert.deepEqual(selectionCopies, [{ event: copyEvent, target: field }]);
  const cut = { defaultPrevented: false, preventDefault() { this.defaultPrevented = true; } };
  field.value = journal.notesText = journal.pages[0].notesText = stampA;
  journal.pages[0].pendingStamp = { start: 0, stamp: stampA.slice(0, -2), preview: "2026-10-22 10:00:09" };
  field.setSelectionRange(0, stampA.length);
  listeners.get("cut")(cut);
  assert.equal(field.value, "2026-10-22 10:00:09  ", "native Cut must read the visible timestamp");
  assert.equal(cut.defaultPrevented, false, "Cut retains its native deletion and undo");
  assert.deepEqual([field.selectionStart, field.selectionEnd], [0, stampA.length]);
  for (const eventType of ["beforeinput", "compositionstart"]) {
    context.hodlJournalInsertTimestamp(field);
    assert.equal(typeof listeners.get(eventType), "function", eventType);
    listeners.get(eventType)({ target: field, inputType: "insertText", data: "A", cancelable: true, preventDefault() {} });
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

test("navigation and selection leave legacy timestamps unchanged until an edit is attempted", () => {
  const { field, context, dirty } = notesHarness("2026-10-22 10:00:00  \n\nOriginal note");
  for (const key of ["Enter", "Backspace", "Delete"]) {
    field.setSelectionRange(5, 5);
    let prevented = false;
    context.hodlJournalNotesKeydown({ key, preventDefault() { prevented = true; } }, field);
    assert.equal(prevented, false, `${key} defers editing decisions to beforeinput`);
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

// Whole timestamped notes can be removed, but dates and their two separating
// spaces cannot be partially edited. The expected boundaries come from these
// literal notebook examples, independently of the application parser.
const stampA = "2026-10-22 10:00:00  ", stampB = "2026-10-22 11:00:00  ";

function noteBeforeInput(h, inputType, start, end, data = "", options = {}) {
  h.field.setSelectionRange(start, end, options.direction || "none");
  const event = {
    inputType, data, cancelable: true, defaultPrevented: false,
    preventDefault() { if (this.cancelable) this.defaultPrevented = true; },
    ...options,
  };
  const allowed = h.context.hodlJournalNotesBeforeInput(event, h.field);
  return { event, allowed };
}

function rearmedNotesHarness() {
  const h = notesHarness(stampA + "Previous note\ncontinued body");
  const deletion = noteBeforeInput(h, "deleteByCut", stampA.length, h.field.value.length, null);
  assert.equal(deletion.allowed, true);
  h.field.setRangeText("", h.field.selectionStart, h.field.selectionEnd);
  h.context.hodlJournalUpdateNotesText(h.field, deletion.event);
  return h;
}

test("deleting a complete note body rearms only a preview and timer ticks preserve raw editor state", () => {
  const h = rearmedNotesHarness();
  assert.equal(h.field.value, stampA);
  assert.deepEqual(JSON.parse(JSON.stringify(h.journal.pages[0].pendingStamp)), { start: 0, stamp: stampA.slice(0, -2), preview: stampA.slice(0, -2) });
  assert.deepEqual(h.events, [["note-delete", "1", "journal"]], "Activity records only a completed-block count, never its text");
  h.field.setSelectionRange(2, 8, "backward");
  h.field.scrollTop = 40; h.field.scrollLeft = 7;
  h.setStamp("2026-10-22 10:00:09");
  h.context.hodlJournalTickNoteClock(h.field);
  assert.equal(h.field.value, stampA);
  assert.equal(h.journal.pages[0].notesText, stampA);
  assert.equal(h.journal.notesText, stampA);
  assert.equal(journalModule.journalPageNotesText(h.journal.pages[0]), "2026-10-22 10:00:09  ");
  assert.deepEqual([h.field.selectionStart, h.field.selectionEnd, h.field.selectionDirection, h.field.scrollTop, h.field.scrollLeft], [2, 8, "backward", 40, 7]);
  assert.equal(h.dirty(), 1);
  assert.equal(h.events.length, 1);
  h.field.value = stampA + "Previous note\ncontinued body";
  h.context.hodlJournalUpdateNotesText(h.field, { inputType: "historyUndo" });
  assert.equal(h.journal.pages[0].pendingStamp, undefined);
  h.context.hodlJournalTickNoteClock(h.field);
  assert.equal(h.field.value, stampA + "Previous note\ncontinued body");
});

test("resumed typing, paste, and composition commit the preview through a native edit before adding body text", () => {
  for (const native of [true, false]) for (const inputType of ["insertText", "insertFromPaste", "insertCompositionText"]) {
    const h = rearmedNotesHarness(), nextPrefix = "2026-10-22 10:00:09  ", body = inputType === "insertCompositionText" ? "漢字" : "New body\ncontinued";
    const nativeEdits = [];
    if (native) h.context.document.execCommand = (command, _showUI, text) => {
      nativeEdits.push({ command, text, start: h.field.selectionStart, end: h.field.selectionEnd });
      h.field.setRangeText(text, h.field.selectionStart, h.field.selectionEnd);
      // Native execCommand can emit input without beforeinput, as in Chromium.
      h.field.dispatchEvent({ inputType: "insertText", data: text });
      return true;
    };
    h.setStamp(nextPrefix.slice(0, -2));
    h.context.hodlJournalTickNoteClock(h.field);
    h.field.setSelectionRange(stampA.length, stampA.length);
    h.field.scrollTop = 40; h.field.scrollLeft = 7;
    let edit;
    if (inputType === "insertCompositionText") {
      h.context.hodlJournalNotesCompositionStart(h.field);
      edit = { inputType, data: body, isComposing: true };
    } else edit = noteBeforeInput(h, inputType, stampA.length, stampA.length, body).event;
    assert.equal(h.field.value, nextPrefix, `${inputType}, native=${native}: the visible timestamp must commit when writing resumes`);
    assert.deepEqual([h.field.selectionStart, h.field.selectionEnd, h.field.scrollTop, h.field.scrollLeft], [stampA.length, stampA.length, 40, 7]);
    if (native) assert.deepEqual(nativeEdits, [{ command: "insertText", text: nextPrefix, start: 0, end: stampA.length }]);
    h.field.setRangeText(body, h.field.selectionStart, h.field.selectionEnd);
    h.context.hodlJournalUpdateNotesText(h.field, edit);
    assert.equal(h.field.value, nextPrefix + body);
    assert.equal(h.journal.pages[0].notesText, nextPrefix + body);
    assert.equal(h.journal.pages[0].pendingStamp, undefined);
    assert.deepEqual(h.events.at(-1), ["note-add", "1", "journal"]);
  }
});

test("Backspace selects an empty timestamp as one native deletion but keeps a nonempty prefix protected", () => {
  const h = rearmedNotesHarness();
  h.field.setSelectionRange(stampA.length, stampA.length);
  let prevented = false;
  h.context.hodlJournalNotesKeydown({ key: "Backspace", preventDefault() { prevented = true; } }, h.field);
  assert.equal(prevented, false, "the browser must own the deletion and undo transaction");
  assert.equal(h.field.value, stampA);
  assert.deepEqual([h.field.selectionStart, h.field.selectionEnd], [0, stampA.length]);
  const deletion = noteBeforeInput(h, "deleteContentBackward", 0, stampA.length, null);
  assert.equal(deletion.allowed, true);
  h.field.value = "";
  h.context.hodlJournalUpdateNotesText(h.field, deletion.event);
  h.setStamp("2026-10-22 10:00:09");
  h.context.hodlJournalTickNoteClock(h.field);
  assert.equal(h.field.value, "");
  assert.equal(h.journal.pages[0].pendingStamp, undefined);
  const written = notesHarness(stampA + "Existing body");
  written.field.setSelectionRange(stampA.length, stampA.length);
  written.context.hodlJournalNotesKeydown({ key: "Backspace", preventDefault() {} }, written.field);
  assert.deepEqual([written.field.selectionStart, written.field.selectionEnd], [stampA.length, stampA.length]);
  assert.equal(noteBeforeInput(written, "deleteContentBackward", stampA.length, stampA.length, null).allowed, false);
  assert.equal(written.field.value, stampA + "Existing body");
});

test("backward deletion without keydown also selects an empty timestamp as one unit", () => {
  const h = notesHarness(stampA);
  const deletion = noteBeforeInput(h, "deleteContentBackward", stampA.length, stampA.length, null);
  assert.equal(deletion.allowed, true);
  assert.deepEqual([h.field.selectionStart, h.field.selectionEnd], [0, stampA.length]);
  h.field.setRangeText("", h.field.selectionStart, h.field.selectionEnd);
  h.context.hodlJournalUpdateNotesText(h.field, deletion.event);
  assert.equal(h.field.value, "");
  assert.equal(h.journal.pages[0].pendingStamp, undefined);
});

test("copying a restarted clock uses its visible preview without changing the raw text", async () => {
  const h = rearmedNotesHarness(), copied = [], button = { disabled: false, dataset: {} };
  h.setStamp("2026-10-22 10:00:09");
  h.context.hodlJournalTickNoteClock(h.field);
  Object.assign(h.context, {
    hodlReadoutIsShown: () => true, hodlJournalFormatNotebook: formatNotebook,
    copyText: async (text) => { copied.push(text); return true; },
    hodlShowCopiedIcon() {}, hodlClipboardIconMarkup: () => "", hodlCopiedIconMarkup: () => "",
  });
  runInNewContext(sourceFunction("hodlJournalCopyContent"), h.context);
  await h.context.hodlJournalCopyContent(button, h.field, true);
  assert.deepEqual(copied, ["2026-10-22 10:00:09"]);
  assert.equal(parseNotebook(serializeNotebook(h.journal)).pages[0].notesText, "2026-10-22 10:00:09  ");
  assert.equal(h.field.value, stampA);
  assert.equal(h.journal.pages[0].notesText, stampA);
  assert.equal(h.dirty(), 1);
});

test("native selection Copy writes only the visible selected clock text without editing or caching notes", async () => {
  const h = rearmedNotesHarness(), copies = [];
  h.field.dataset = {};
  h.setStamp("2026-10-22 10:00:09");
  h.context.hodlJournalTickNoteClock(h.field);
  Object.assign(h.context, { hodlReadoutIsShown: () => true, copyText: async (text) => { copies.push(text); return true; } });
  runInNewContext(sourceFunction("hodlJournalCopyNotesSelection"), h.context);
  for (const [start, end, expected] of [[17, 19, "09"], [0, stampA.length, "2026-10-22 10:00:09  "]]) {
    h.field.setSelectionRange(start, end, "backward");
    const before = JSON.stringify(h.journal), dirty = h.dirty();
    const event = { type: "copy", cancelable: true, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; } };
    assert.equal(await h.context.hodlJournalCopyNotesSelection(event, h.field), true);
    assert.equal(event.defaultPrevented, true);
    assert.equal(copies.at(-1), expected);
    assert.equal(h.field.value, stampA);
    assert.equal(JSON.stringify(h.journal), before);
    assert.deepEqual([h.field.selectionStart, h.field.selectionEnd, h.field.selectionDirection], [start, end, "backward"]);
    assert.deepEqual(h.field.dataset, {});
    assert.equal(h.dirty(), dirty);
  }
  h.context.copyText = async () => false;
  const failed = { type: "copy", cancelable: true, prevented: false, preventDefault() { this.prevented = true; } };
  assert.equal(await h.context.hodlJournalCopyNotesSelection(failed, h.field), false);
  assert.equal(failed.prevented, true, "a failed projected copy must not fall through to copying the wrong timestamp");
  assert.equal(h.field.value, stampA);
});

test("native selection Copy leaves unchanged selections, historical text, hidden notes, and Cut to the browser", async () => {
  for (const scenario of ["unchanged", "empty", "historical", "hidden", "cut", "canceled", "uncancelable", "stale"]) {
    const h = rearmedNotesHarness();
    h.setStamp("2026-10-22 10:00:09");
    h.context.hodlJournalTickNoteClock(h.field);
    h.field.setSelectionRange(0, stampA.length);
    if (scenario === "unchanged") h.field.setSelectionRange(0, 4);
    if (scenario === "empty") h.field.setSelectionRange(19, 19);
    if (scenario === "historical") delete h.journal.pages[0].pendingStamp;
    if (scenario === "stale") h.field.value += "Unsynchronized writing";
    Object.assign(h.context, {
      hodlReadoutIsShown: () => scenario !== "hidden",
      copyText: async () => assert.fail("An unchanged or unavailable native copy was intercepted"),
    });
    runInNewContext(sourceFunction("hodlJournalCopyNotesSelection"), h.context);
    const event = {
      type: scenario === "cut" ? "cut" : "copy", cancelable: scenario !== "uncancelable", defaultPrevented: scenario === "canceled",
      preventDefault() { assert.fail("Native selection behavior was prevented: " + scenario); },
    };
    assert.equal(await h.context.hodlJournalCopyNotesSelection(event, h.field), false, scenario);
  }
});

test("key insertion and the new-note shortcut commit a restarted preview in the textarea before their edits", () => {
  for (const action of ["key", "timestamp"]) {
    const h = rearmedNotesHarness(), previewPrefix = "2026-10-22 10:00:09  ";
    const select = {
      value: "key-1", selectedOptions: [{ dataset: { keyName: "Cold wallet", fingerprint: "1234abcd" } }],
      hodlJournalInsertionRange: { start: stampA.length, end: stampA.length }, dispatchEvent() {},
    };
    const nativeEdits = [];
    h.context.document.activeElement = select;
    h.field.focus = () => { h.field.focused = true; h.context.document.activeElement = h.field; };
    h.context.document.execCommand = (command, _showUI, text) => {
      assert.equal(h.context.document.activeElement, h.field, "the clock commit must not edit the focused key picker");
      nativeEdits.push({ command, text });
      h.field.setRangeText(text, h.field.selectionStart, h.field.selectionEnd);
      h.field.dispatchEvent({ inputType: "insertText", data: text });
      return true;
    };
    h.setStamp(previewPrefix.slice(0, -2));
    h.context.hodlJournalTickNoteClock(h.field);
    h.setStamp("2026-10-22 10:00:10");
    h.field.setSelectionRange(4, 8, "backward");
    if (action === "key") {
      Object.assign(h.context, { hodlJournalKeyReferenceToken: journalKeyReferenceToken, Event: class { constructor(type) { this.type = type; } } });
      runInNewContext(sourceFunction("hodlJournalInsertKey"), h.context);
      h.context.hodlJournalInsertKey(select, h.field);
      assert.equal(h.field.value, previewPrefix + journalKeyReferenceToken("Cold wallet", "1234abcd") + " ");
      assert.equal(h.journal.pages[0].pendingStamp, undefined);
      assert.equal(select.value, "");
    } else {
      let prevented = false;
      h.context.hodlJournalNotesKeydown({ key: "Enter", ctrlKey: true, preventDefault() { prevented = true; } }, h.field);
      assert.equal(prevented, true);
      assert.equal(h.field.value, previewPrefix + "\n\n2026-10-22 10:00:10  ");
      assert.equal(h.journal.pages[0].pendingStamp.start, previewPrefix.length + 2);
      h.setStamp("2026-10-22 10:00:11");
      h.context.hodlJournalTickNoteClock(h.field);
      assert.equal(h.field.value, previewPrefix + "\n\n2026-10-22 10:00:11  ");
    }
    assert.deepEqual(nativeEdits, [{ command: "insertText", text: previewPrefix }]);
    assert.equal(h.context.document.activeElement, h.field);
    assert.equal(h.journal.pages[0].notesText, h.field.value);
  }
});

test("timestamp ranges protect exact line-start prefixes and identify complete note bodies", () => {
  const { context } = notesHarness();
  const firstBody = "Alpha\ncontinued", secondBody = "Beta";
  const text = "Intro\n" + stampA + firstBody + " \n\n" + stampB + secondBody + "  \n";
  const secondStart = 6 + stampA.length + firstBody.length + 3;
  assert.deepEqual(JSON.parse(JSON.stringify(context.hodlJournalStampRanges(text))), [
    { start: 6, end: 6 + stampA.length, noteEnd: 6 + stampA.length + firstBody.length },
    { start: secondStart, end: secondStart + stampB.length, noteEnd: secondStart + stampB.length + secondBody.length },
  ]);
  assert.equal(context.hodlJournalStampRanges("Embedded " + stampA + "text").length, 0);
  assert.equal(context.hodlJournalStampRanges(stampA.slice(0, -1) + "only one separator").length, 0);
  assert.equal(context.hodlJournalStampRanges("2026-10-22 10:00  Missing seconds").length, 0);
  assert.deepEqual(JSON.parse(JSON.stringify(context.hodlJournalStampRanges(stampA + " \n"))), [
    { start: 0, end: stampA.length, noteEnd: stampA.length },
  ]);
});

test("partial timestamp prefixes are protected while whole notes and normal body edits remain editable", () => {
  const { context } = notesHarness();
  const first = stampA + "Alpha\ncontinued", separator = "\n\n", second = stampB + "Beta";
  const text = first + separator + second, secondStart = first.length + separator.length;
  const accepted = [
    [stampA.length, stampA.length, "new body "],
    [stampA.length, first.length, "Replacement body\ncontinued"],
    [first.length, first.length + 1, ""],
    [0, 0, "Introduction\n"],
    [0, first.length, ""],
    [0, secondStart, ""],
    [secondStart, text.length, ""],
    [0, text.length, ""],
    [0, text.length, "Entirely replaced page"],
    [0, 4, "2026"],
  ];
  for (const args of accepted) assert.equal(context.hodlJournalNoteEditAllowed(text, ...args), true, `allowed edit ${JSON.stringify(args)}`);
  const rejected = [
    [0, 1, ""], [3, 4, "9"], [10, 11, "T"], [19, 20, ""], [20, 21, ""],
    [5, 5, "x"], [0, 0, "prefix"], [0, stampA.length, ""],
    [0, first.length - 1, ""], [stampA.length, secondStart + 2, ""],
    [first.length, secondStart, ""], [secondStart, secondStart + stampB.length, ""],
  ];
  for (const args of rejected) assert.equal(context.hodlJournalNoteEditAllowed(text, ...args), false, `forbidden edit ${JSON.stringify(args)}`);
  assert.equal(context.hodlJournalNoteEditAllowed(stampA, 0, stampA.length, ""), true, "an empty note's entire prefix can be deleted");
  assert.equal(context.hodlJournalNoteEditAllowed("Unstructured notes", 0, 6, "Ordinary"), true);
});

test("imported CRLF and CR notes use the textarea newline representation before editing", () => {
  for (const separator of ["\r\n", "\r"]) {
    const source = stampA + "first" + separator + stampB + "second", expected = stampA + "first\n" + stampB + "second";
    const payload = JSON.stringify({ format: "entropylab-notebook", version: 1, pages: [{ content: [{ type: "text", text: source }] }] });
    for (const imported of [journalFromPlainText(source), parseNotebook(payload)]) {
      assert.equal(imported.notesText, expected);
      assert.equal(imported.pages[0].notesText, expected);
      const h = notesHarness(imported.notesText);
      h.context.hodlJournalRestorePage(h.field);
      const position = expected.indexOf("second") + 2;
      const { event, allowed } = noteBeforeInput(h, "insertText", position, position, "!");
      assert.equal(allowed, true);
      h.field.setRangeText("!", position, position);
      h.context.hodlJournalUpdateNotesText(h.field, event);
      assert.equal(h.field.value, expected.slice(0, position) + "!" + expected.slice(position));
      assert.equal(h.journal.pages[0].notesText, h.field.value);
    }
  }
});

test("Unicode line and paragraph separators remain editable body text rather than inconsistent timestamp boundaries", () => {
  const { context } = notesHarness();
  for (const separator of ["\u2028", "\u2029"]) {
    const text = stampA + "first" + separator + stampB + "second";
    assert.equal(context.hodlJournalStampRanges(text).length, 1);
    assert.equal(context.hodlJournalNoteEditAllowed(text, text.length, text.length, "!"), true);
    assert.equal(context.hodlJournalNoteEditAllowed(text, 3, 4, "9"), false, "the genuine LF/start-of-page prefix stays protected");
    assert.equal(parseNotebook(serializeNotebook(journalFromPlainText(text))).notesText, text);
  }
});

test("a drag deletion followed by a refused timestamp drop preserves the complete original note", () => {
  const first = stampA + "Alpha\n\n", second = stampB + "Beta", text = first + second;
  for (const [start, end] of [[stampA.length, stampA.length + 5], [0, first.length]]) {
    const h = notesHarness(text), moved = text.slice(start, end);
    const deletion = noteBeforeInput(h, "deleteByDrag", start, end, null);
    assert.equal(deletion.allowed, true);
    h.field.setRangeText("", start, end);
    h.context.hodlJournalUpdateNotesText(h.field, deletion.event);
    const drop = noteBeforeInput(h, "insertFromDrop", 5, 5, moved);
    assert.equal(drop.event.defaultPrevented, true);
    assert.equal(h.field.value, text, "a refused drop must undo the source deletion");
    assert.equal(h.journal.pages[0].notesText, text);
    assert.equal(h.dirty(), 0, "an incomplete move must not become a saved content change");
    assert.deepEqual(h.events, []);
  }
});

test("accepted body drag moves commit both halves together and preserve timestamp prefixes", () => {
  const text = stampA + "Alpha\n\n" + stampB + "Beta", start = stampA.length, end = start + 5;
  const h = notesHarness(text), deletion = noteBeforeInput(h, "deleteByDrag", start, end, null);
  h.field.setRangeText("", start, end);
  h.context.hodlJournalUpdateNotesText(h.field, deletion.event);
  assert.equal(h.journal.pages[0].notesText, text, "the source remains owned until the move is complete");
  const destination = h.field.value.length, drop = noteBeforeInput(h, "insertFromDrop", destination, destination, "Alpha");
  assert.equal(drop.allowed, true);
  h.field.setRangeText("Alpha", destination, destination);
  h.context.hodlJournalUpdateNotesText(h.field, drop.event);
  assert.equal(h.field.value, stampA + "\n\n" + stampB + "BetaAlpha");
  assert.equal(h.journal.pages[0].notesText, h.field.value);
  assert.equal(h.dirty(), 1);
});

test("insertion-first drag moves and copy drops preserve their original source until completion", () => {
  const text = stampA + "Alpha\n\n" + stampB + "Beta", start = stampA.length, end = start + 5;
  for (const move of [true, false]) {
    const h = notesHarness(text);
    h.field.setSelectionRange(start, end);
    h.context.hodlJournalBeginNoteDrag(h.field);
    const destination = text.length, insertion = noteBeforeInput(h, "insertFromDrop", destination, destination, "Alpha");
    h.field.setRangeText("Alpha", destination, destination);
    h.context.hodlJournalUpdateNotesText(h.field, insertion.event);
    assert.equal(h.journal.pages[0].notesText, text);
    if (move) {
      const deletion = noteBeforeInput(h, "deleteByDrag", start, end, null);
      h.field.setRangeText("", start, end);
      h.context.hodlJournalUpdateNotesText(h.field, deletion.event);
    } else h.context.hodlJournalFinishNoteDrag(h.field, true);
    assert.equal(h.field.value, (move ? stampA + "\n\n" + stampB + "Beta" : text) + "Alpha");
    assert.equal(h.journal.pages[0].notesText, h.field.value);
    assert.equal(h.field.hodlJournalDrag, undefined);
    assert.equal(h.dirty(), 1);
  }
});

test("cancelled drags, backup collection, and page switching never retain half a move", () => {
  const text = stampA + "Alpha\n\n" + stampB + "Beta", start = stampA.length, end = start + 5;
  for (const finish of [
    h => h.context.hodlJournalFinishNoteDrag(h.field),
    h => h.context.hodlJournalStoreNotesText(h.field),
    h => h.context.hodlSelectJournalPage(1),
  ]) {
    const h = notesHarness(text);
    h.journal.pages.push({ id: 2, number: 2, notesText: "Other page", style: {} });
    const deletion = noteBeforeInput(h, "deleteByDrag", start, end, null);
    h.field.setRangeText("", start, end);
    h.context.hodlJournalUpdateNotesText(h.field, deletion.event);
    finish(h);
    assert.equal(h.journal.pages[0].notesText, text);
    assert.equal(h.field.value, h.journal.activePage === 1 ? "Other page" : text);
    assert.equal(h.field.hodlJournalDrag, undefined);
    assert.equal(h.dirty(), 0);
  }
});

test("a completed move to an external destination commits its validated source deletion once", () => {
  const text = stampA + "Alpha\n\n" + stampB + "Beta", start = stampA.length, end = start + 5;
  const h = notesHarness(text), deletion = noteBeforeInput(h, "deleteByDrag", start, end, null);
  h.field.setRangeText("", start, end);
  h.context.hodlJournalUpdateNotesText(h.field, deletion.event);
  assert.equal(h.journal.pages[0].notesText, text);
  h.context.hodlJournalFinishNoteDrag(h.field, true);
  assert.equal(h.journal.pages[0].notesText, stampA + "\n\n" + stampB + "Beta");
  assert.equal(h.field.value, h.journal.pages[0].notesText);
  assert.equal(h.field.hodlJournalDrag, undefined);
  assert.equal(h.dirty(), 1);
});

test("a stale drag cannot restore its source into a replacement Journal page", () => {
  const text = stampA + "Alpha", h = notesHarness(text);
  h.field.setSelectionRange(stampA.length, text.length);
  h.context.hodlJournalBeginNoteDrag(h.field);
  const replacement = createJournal();
  replacement.notesText = replacement.pages[0].notesText = "Replacement content";
  h.context.hodlJournal = replacement;
  h.field.value = replacement.notesText;
  h.context.hodlJournalFinishNoteDrag(h.field, true);
  assert.equal(h.field.value, "Replacement content");
  assert.equal(replacement.pages[0].notesText, "Replacement content");
  assert.equal(h.field.hodlJournalDrag, undefined);
});

test("a browser drag deletion without beforeinput still rolls back a refused destination", () => {
  const text = stampA + "Alpha\n\n" + stampB + "Beta", h = notesHarness(text);
  h.field.setRangeText("", stampA.length, stampA.length + 5);
  h.context.hodlJournalUpdateNotesText(h.field, { inputType: "deleteByDrag" });
  const drop = noteBeforeInput(h, "insertFromDrop", 5, 5, "Alpha");
  assert.equal(drop.event.defaultPrevented, true);
  assert.equal(h.field.value, text);
  assert.equal(h.journal.pages[0].notesText, text);
  assert.equal(h.dirty(), 0);
});

test("beforeinput blocks partial-prefix typing, paste, drop, cut and deletion without changing the live clock", () => {
  for (const [inputType, start, end, data, extra] of [
    ["insertText", 4, 5, "9"], ["insertLineBreak", 8, 8, null],
    ["insertFromPaste", 7, 9, "paste"],
    ["insertFromDrop", 9, 9, null, { dataTransfer: { getData: () => "drop" } }],
    ["deleteByCut", 1, 5, null],
    ["deleteContentForward", 19, 19, null], ["insertCompositionText", 14, 15, "字"],
  ]) {
    const h = notesHarness();
    h.context.hodlJournalStartPage();
    h.context.hodlJournalRestorePage(h.field);
    const previous = h.field.value, pending = h.journal.pages[0].pendingStamp;
    const { event, allowed } = noteBeforeInput(h, inputType, start, end, data, extra);
    assert.equal(allowed, false, inputType);
    assert.equal(event.defaultPrevented, true, inputType);
    assert.equal(h.field.value, previous);
    assert.equal(h.journal.pages[0].pendingStamp, pending, "a blocked edit must not freeze an untouched note");
    assert.equal(h.dirty(), 0);
    assert.ok(h.messages.at(-1)?.[0], "blocked editing needs accessible feedback");
  }
});

test("body typing, paste, drop and line breaks freeze the clock once and preserve timestamp prefixes", () => {
  for (const [inputType, data, replacement, extra] of [
    ["insertText", "Text", "Text"], ["insertFromPaste", "Paste\nmore", "Paste\nmore"],
    ["insertFromDrop", null, "Dropped", { dataTransfer: { getData: () => "Dropped" } }],
    ["insertLineBreak", null, "\n"], ["insertCompositionText", "字", "字"],
  ]) {
    const h = notesHarness();
    h.context.hodlJournalStartPage();
    h.context.hodlJournalRestorePage(h.field);
    const original = h.field.value;
    const { event, allowed } = noteBeforeInput(h, inputType, original.length, original.length, data, extra);
    assert.equal(allowed, true, inputType);
    assert.equal(event.defaultPrevented, false);
    assert.equal(h.journal.pages[0].pendingStamp, undefined);
    h.field.value = original + replacement;
    h.context.hodlJournalUpdateNotesText(h.field, event);
    assert.equal(h.field.value, original + replacement);
    assert.equal(h.journal.pages[0].notesText, h.field.value);
    assert.equal(h.field.hodlJournalEdit, undefined, "completed edits must release remembered selection metadata");
    h.setStamp("2026-10-22 10:00:09");
    h.context.hodlJournalTickNoteClock(h.field);
    assert.equal(h.field.value, original + replacement);
  }
});

test("complete-note deletion with or without trailing separators and Select All deletion stay deleted", () => {
  const first = stampA + "Alpha\ncontinued", second = stampB + "Beta", text = first + "\n\n" + second;
  for (const [start, end] of [[0, first.length], [0, first.length + 2], [first.length + 2, text.length], [0, text.length]]) {
    const h = notesHarness(text);
    const { event, allowed } = noteBeforeInput(h, "deleteByCut", start, end, null);
    assert.equal(allowed, true);
    assert.equal(event.defaultPrevented, false);
    const expected = text.slice(0, start) + text.slice(end);
    h.field.value = expected;
    h.context.hodlJournalUpdateNotesText(h.field, event);
    h.setStamp("2026-10-22 10:00:09");
    h.context.hodlJournalTickNoteClock(h.field);
    assert.equal(h.field.value, expected);
    assert.equal(h.journal.pages[0].notesText, expected);
    assert.equal(h.journal.pages[0].pendingStamp, undefined);
  }
});

test("recorded whole-note replacement is accepted when its minimal text diff overlaps only part of a prefix", () => {
  const original = stampA + "Same body", replacement = stampB + "Same body", h = notesHarness(original);
  const { event, allowed } = noteBeforeInput(h, "insertFromPaste", 0, original.length, replacement);
  assert.equal(allowed, true);
  h.field.value = replacement;
  h.context.hodlJournalUpdateNotesText(h.field, event);
  assert.equal(h.field.value, replacement);
  assert.equal(h.journal.pages[0].notesText, replacement);
  assert.equal(h.field.hodlJournalEdit, undefined);
});

test("deleting complete notes without beforeinput recognizes shared prefixes without permitting partial date deletion", () => {
  const first = "2020-01-02 03:04:05  first\n\n", second = "2020-01-03 04:05:06  next";
  const repeated = stampA + "Same body", last = "2020-01-04 05:06:07  last";
  for (const [previous, changed, accepted] of [
    [first + second, second, true],
    [repeated + "\n\n" + repeated, repeated, true],
    [first + second + "\n\n" + last, last, true],
    [first + second, (first + second).slice(1), false],
  ]) {
    const h = notesHarness(previous), expected = accepted ? changed : previous;
    h.field.setSelectionRange(0, previous.length - changed.length);
    h.field.value = changed;
    h.context.hodlJournalUpdateNotesText(h.field, { inputType: "deleteContentBackward", data: null });
    assert.equal(h.field.value, expected, accepted ? "a common timestamp prefix disguised a complete-note deletion as a partial edit" : "a partial date deletion was treated as a whole note");
    assert.equal(h.journal.pages[0].notesText, expected);
    assert.equal(h.dirty(), accepted ? 1 : 0);
  }
});

test("an unfinished edit on one page cannot authorize a partial timestamp change on another page", () => {
  const first = stampA + "First note", second = stampB + "Other note", h = notesHarness(first);
  h.journal.pages.push({ id: 2, number: 2, name: "Other", notesText: second });
  h.field.setSelectionRange(0, first.length);
  h.context.hodlJournalNotesCompositionStart(h.field);
  h.context.hodlSelectJournalPage(1);
  assert.equal(h.field.value, second);
  h.field.value = second.replace("2026", "2029");
  h.context.hodlJournalUpdateNotesText(h.field, { inputType: "insertReplacementText", data: "9" });
  assert.equal(h.field.value, second, "the prior page's whole-note selection allowed a partial timestamp edit");
  assert.equal(h.journal.pages[0].notesText, first);
  assert.equal(h.journal.pages[1].notesText, second);
});

test("native undo and redo replay accepted history without creating a replacement timestamp", () => {
  const original = stampA + "Recorded note", h = notesHarness(original);
  const deletion = noteBeforeInput(h, "deleteContentBackward", 0, original.length, null);
  h.field.value = "";
  h.context.hodlJournalUpdateNotesText(h.field, deletion.event);
  for (const [inputType, text] of [["historyUndo", original], ["historyRedo", ""]]) {
    const { event, allowed } = noteBeforeInput(h, inputType, 0, 0, null);
    assert.equal(allowed, true);
    h.field.value = text;
    h.context.hodlJournalUpdateNotesText(h.field, event);
    assert.equal(h.field.value, text);
    assert.equal(h.journal.pages[0].notesText, text);
    assert.equal(h.journal.pages[0].pendingStamp, undefined);
  }
});

test("composition redirects a partial prefix edit to its body but preserves whole-note selection", () => {
  for (const [start, end] of [[4, 4], [4, 8], [0, stampA.length], [19, stampA.length + 3]]) {
    const original = stampA + "Existing body", h = notesHarness(original);
    h.field.setSelectionRange(start, end, "backward");
    h.context.hodlJournalNotesCompositionStart(h.field);
    assert.deepEqual([h.field.selectionStart, h.field.selectionEnd], [stampA.length, stampA.length]);
    assert.equal(h.field.value, original);
    const edit = noteBeforeInput(h, "insertCompositionText", h.field.selectionStart, h.field.selectionEnd, "字", { cancelable: false });
    h.field.value = stampA + "字Existing body";
    h.context.hodlJournalUpdateNotesText(h.field, edit.event);
    assert.equal(h.field.value, stampA + "字Existing body");
  }
  const original = stampA + "Whole note", h = notesHarness(original);
  h.field.setSelectionRange(0, original.length, "backward");
  h.context.hodlJournalNotesCompositionStart(h.field);
  assert.deepEqual([h.field.selectionStart, h.field.selectionEnd, h.field.selectionDirection], [0, original.length, "backward"]);
  const edit = noteBeforeInput(h, "insertCompositionText", 0, original.length, "新", { cancelable: false });
  h.field.value = "新";
  h.context.hodlJournalUpdateNotesText(h.field, edit.event);
  assert.equal(h.field.value, "新");
});

test("uncancelable partial timestamp changes restore the previous text and editor view", () => {
  for (const recorded of [false, true]) for (const [start, end, replacement, inputType] of [
    [3, 4, "9", "insertText"], [19, 20, "", "deleteContentForward"],
    [0, stampA.length, "", "deleteByCut"], [7, 9, "paste", "insertFromPaste"],
    [9, 9, "drop", "insertFromDrop"], [14, 15, "字", "insertCompositionText"],
  ]) {
    const previous = stampA + "Keep this note";
    const { field, journal, context, dirty } = notesHarness(previous);
    field.setSelectionRange(start, end, "backward");
    field.scrollTop = 73;
    field.scrollLeft = 9;
    context.hodlJournalStoreNotesText(field, false);
    if (recorded) {
      const event = { inputType, data: replacement, cancelable: false, preventDefault() { assert.fail("a noncancelable edit cannot be prevented"); } };
      context.hodlJournalNotesBeforeInput(event, field);
    }
    field.value = previous.slice(0, start) + replacement + previous.slice(end);
    context.hodlJournalUpdateNotesText(field, { inputType, data: replacement });
    assert.equal(field.value, previous, `${inputType} changed part of an existing timestamp prefix`);
    assert.equal(journal.pages[0].notesText, previous);
    assert.equal(journal.notesText, previous);
    assert.deepEqual([field.selectionStart, field.selectionEnd, field.selectionDirection], [start, end, "backward"]);
    assert.deepEqual([field.scrollTop, field.scrollLeft], [73, 9]);
    assert.equal(dirty(), 0, "refused edits must not mark the notebook changed");
  }
});

test("deleting a key reference immediately after a timestamp preserves both prefix spaces", () => {
  const token = journalKeyReferenceToken("Cold wallet", "1234abcd");
  for (const suffix of ["", " next words"]) {
    const { field, journal, context } = notesHarness(stampA + token + suffix);
    field.setSelectionRange(stampA.length, stampA.length + token.length);
    let prevented = false;
    context.hodlJournalNotesKeydown({ key: "Backspace", preventDefault() { prevented = true; } }, field);
    assert.equal(prevented, true);
    assert.equal(field.value, stampA + suffix.trimStart());
    assert.equal(journal.pages[0].notesText, field.value);
  }
});

test("inserting a key reference refuses partial timestamp selections and preserves the prefix at its body", () => {
  const token = journalKeyReferenceToken("Cold wallet", "1234abcd"), original = stampA + "Keep this note";
  for (const savedRange of [false, true]) {
    const h = notesHarness(original), events = [], mutations = [];
    Object.assign(h.context, {
      hodlJournalKeyReferenceToken: journalKeyReferenceToken,
      hodlJournalLog: (...args) => mutations.push(args),
      Event: class { constructor(type) { this.type = type; } },
    });
    runInNewContext(sourceFunction("hodlJournalInsertKey"), h.context);
    const select = {
      value: "key-1", selectedOptions: [{ dataset: { keyName: "Cold wallet", fingerprint: "1234abcd" } }],
      dispatchEvent(event) { events.push(event.type); },
    };
    h.field.setSelectionRange(4, 8);
    if (savedRange) {
      select.hodlJournalInsertionRange = { start: 4, end: 8 };
      h.field.setSelectionRange(original.length, original.length);
    }
    h.context.hodlJournalInsertKey(select, h.field);
    assert.equal(h.field.value, original, "key insertion damaged the timestamp prefix");
    assert.equal(h.journal.pages[0].notesText, original);
    assert.equal(h.dirty(), 0);
    assert.equal(select.value, "");
    assert.equal(select.hodlJournalInsertionRange, undefined);
    assert.equal(h.field.focused, true);
    assert.equal(events.length, 1, "a refused insertion must reset the picker");
    assert.equal(mutations.length, 0);
    assert.ok(h.messages.at(-1)?.[0]);
    h.field.setSelectionRange(stampA.length, stampA.length);
    h.context.hodlJournalInsertKey(select, h.field);
    assert.equal(h.field.value, stampA + token + " Keep this note");
    assert.equal(h.journal.pages[0].notesText, h.field.value);
    assert.equal(mutations.length, 1);
  }
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

test("copy availability depends on note content without caching it on the control", () => {
  const button = { disabled: true, dataset: { phrase: "Stale private note" } }, field = { value: "No notes." };
  const context = { button, field, hodlJournalFormatNotebook: formatNotebook };
  runInNewContext(sourceFunction("hodlJournalSyncCopyButton") + "\nhodlJournalSyncCopyButton(field, button);", context);
  assert.equal(button.disabled, false);
  assert.equal(button.dataset.phrase, undefined);
  field.value = " \n\t";
  runInNewContext("hodlJournalSyncCopyButton(field, button);", context);
  assert.equal(button.disabled, true);
  assert.equal(button.dataset.phrase, undefined);
});
