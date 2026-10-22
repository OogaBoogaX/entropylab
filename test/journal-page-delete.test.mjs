import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import { MiniDocument } from "./mini-dom.mjs";

// A populated page must survive until its own deletion is confirmed; a
// confirmation from a cleared or replaced Journal must never delete a page.
const app = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");
const start = app.indexOf("function hodlDeleteActiveJournalPage(");
const source = app.slice(start, app.indexOf("\n}\n", start) + 2);

function pageHarness(text = "Saved private note") {
  const first = { id: 1, number: 1, notesText: "Keep this page" };
  const target = { id: 2, number: 2, notesText: text };
  const journal = { pages: [first, target], activePage: 1, notesText: text };
  const field = { value: text };
  const events = [];
  let pending, focused = false;
  const context = {
    hodlJournal: journal,
    hodlJournalPageDeleteConfirm: null,
    initJournalPageDeleteConfirm: () => ({ show(options) { pending = options; } }),
    document: { getElementById(id) {
      if (id === "journal-notes-text") return field;
      if (id === "journal-page-tabs") return { children: [{ focus() { focused = true; } }] };
      return {};
    } },
    hodlJournalStoreNotesText() { journal.pages[journal.activePage].notesText = field.value; },
    hodlSyncJournalPageDeleteButton() {},
    hodlRenderJournalPageTabs() {},
    hodlJournalRestorePage() { field.value = context.hodlJournal.pages[context.hodlJournal.activePage].notesText; },
    hodlJournalLog(...args) { events.push(args); },
  };
  runInNewContext(source, context);
  return { context, journal, first, target, field, events, pending: () => pending, focused: () => focused };
}

test("populated page deletion waits for confirmation and removes the captured page", () => {
  const h = pageHarness();
  h.context.hodlDeleteActiveJournalPage();
  assert.deepEqual(h.journal.pages, [h.first, h.target]);
  assert.equal(h.field.value, "Saved private note");
  assert.equal(h.events.length, 0);
  assert.ok(h.pending());
  h.journal.activePage = 0;
  h.field.value = h.first.notesText;
  h.pending().onConfirm();
  assert.deepEqual(h.journal.pages, [h.first]);
  assert.equal(h.field.value, "Keep this page");
  assert.deepEqual(h.events, [["page-delete", "page-2", "journal"]]);
  assert.equal(h.focused(), true);
});

test("empty pages delete directly, but the sole page cannot be deleted", () => {
  const h = pageHarness("");
  h.context.hodlDeleteActiveJournalPage();
  assert.deepEqual(h.journal.pages, [h.first]);
  assert.equal(h.pending(), undefined);
  h.context.hodlDeleteActiveJournalPage();
  assert.deepEqual(h.journal.pages, [h.first]);
  assert.equal(h.events.length, 1);
});

test("stale page confirmations cannot delete a replacement Journal or reused page ID", () => {
  for (const replaceJournal of [false, true]) {
    const h = pageHarness();
    h.context.hodlDeleteActiveJournalPage();
    assert.ok(h.pending(), "deletion must wait before replacing the page");
    const replacement = { id: 2, number: 2, notesText: "New page with reused ID" };
    if (replaceJournal) h.context.hodlJournal = { pages: [h.first, replacement], activePage: 1 };
    else h.journal.pages = [h.first, replacement];
    h.pending().onConfirm();
    assert.deepEqual(h.context.hodlJournal.pages, [h.first, replacement]);
    assert.equal(h.events.length, 0);
  }
});

async function withDialog(run) {
  const { initJournalPageDeleteConfirm } = await import("../src/js/journal-page-delete-confirm.js");
  const previous = globalThis.document;
  const document = new MiniDocument();
  globalThis.document = document;
  const opener = document.createElement("button");
  document.body.append(opener);
  let confirmed = 0;
  try {
    const dialog = initJournalPageDeleteConfirm();
    for (const button of document.querySelectorAll("button")) {
      button.focus = () => { document.activeElement = button; };
      button.click = () => button.dispatchEvent({ type: "click", target: button });
    }
    const el = (name) => document.getElementById(`journal-page-delete-${name}`);
    const show = () => dialog.show({ opener, onConfirm: () => confirmed++ });
    show();
    await run({ dialog, document, opener, el, show, confirmed: () => confirmed });
  } finally {
    globalThis.document = previous;
  }
}

test("page deletion defaults to Cancel and returns focus without deleting", async () => {
  await withDialog(({ document, opener, el, confirmed }) => {
    assert.equal(document.activeElement, el("cancel"));
    assert.equal(el("dialog").getAttribute("role"), "dialog");
    assert.equal(el("dialog").getAttribute("aria-modal"), "true");
    for (const name of ["labelledby", "describedby"]) assert.ok(document.getElementById(el("dialog").getAttribute(`aria-${name}`)));
    el("cancel").click();
    assert.ok(el("modal").hidden);
    assert.equal(document.activeElement, opener);
    el("confirm").click();
    assert.equal(confirmed(), 0);
  });
});

test("Escape, backdrop, and teardown invalidate the pending deletion", async () => {
  await withDialog(({ dialog, el, show, confirmed }) => {
    for (const dismiss of [
      () => el("modal").dispatchEvent({ type: "keydown", key: "Escape" }),
      () => el("modal").dispatchEvent({ type: "click", target: el("modal") }),
      () => dialog.hide({ restoreFocus: false }),
    ]) {
      show();
      dismiss();
      assert.ok(el("modal").hidden);
      el("confirm").click();
      assert.equal(confirmed(), 0);
    }
  });
});

test("confirm is one-shot and reopening cannot replay the previous callback", async () => {
  await withDialog(({ el, show, confirmed }) => {
    el("confirm").click();
    el("confirm").click();
    assert.equal(confirmed(), 1);
    assert.ok(el("modal").hidden);
    show();
    el("cancel").click();
    el("confirm").click();
    assert.equal(confirmed(), 1);
  });
});
