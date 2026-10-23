import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import { MiniDocument } from "./mini-dom.mjs";
import { formatLog, formatLogField, logUsage } from "../src/js/journal.js";

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

test("an untouched initial live timestamp does not require page deletion confirmation", () => {
  const stamp = "2026-10-22 10:00:01";
  const h = pageHarness(stamp + "  ");
  h.target.pendingStamp = { start: 0, stamp };
  h.context.hodlDeleteActiveJournalPage();
  assert.equal(h.pending(), undefined);
  assert.deepEqual(h.journal.pages, [h.first]);
});

test("edited, imported, and later timestamps still require page deletion confirmation", () => {
  const stamp = "2026-10-22 10:00:01";
  for (const [text, pending] of [
    [stamp + "  ", undefined],
    [stamp + "  note", { start: 0, stamp }],
    ["Earlier note\n\n" + stamp + "  ", { start: 14, stamp }],
  ]) {
    const h = pageHarness(text);
    if (pending) h.target.pendingStamp = pending;
    h.context.hodlDeleteActiveJournalPage();
    assert.ok(h.pending());
    assert.deepEqual(h.journal.pages, [h.first, h.target]);
  }
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
    const show = (options = {}) => dialog.show({ opener, onConfirm: () => confirmed++, ...options });
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

test("the shared deletion dialog renders custom content as text and resets it for Notes", async () => {
  await withDialog(({ dialog, el, show }) => {
    const defaults = ["title", "message", "confirm"].map((name) => el(name).textContent);
    assert.ok(defaults.every((text) => text.trim()));
    dialog.hide();
    const content = { title: "<img src=x onerror=1>", message: "Private <record> details", confirmLabel: "Remove <record>" };
    show(content);
    for (const [name, key] of [["title", "title"], ["message", "message"], ["confirm", "confirmLabel"]]) {
      assert.equal(el(name).textContent, content[key]);
      assert.equal(el(name).children.length, 0, "custom content must not become markup");
    }
    dialog.hide();
    show();
    assert.deepEqual(["title", "message", "confirm"].map((name) => el(name).textContent), defaults, "a later Notes deletion must restore its own content");
  });
});

function appFunction(name) {
  const start = app.indexOf(`function ${name}(`);
  return start < 0 ? "" : app.slice(start, app.indexOf("\n}\n", start) + 2);
}

function activityHarness({ document, dialog, download = async () => true } = {}) {
  const log = [{ at: "2026-10-22T12:00:00Z", tool: "journal", action: "page-add", detail: "page-2" }];
  const journal = { log, logDiscarded: 7 };
  const button = document?.getElementById("journal-log-clear") || {};
  const events = [];
  let pending;
  const context = {
    hodlJournal: journal,
    hodlJournalKeys: { passwordProtected: true },
    hodlJournalGeneration: 1,
    unlocked: true,
    hodlJournalUnlocked: () => context.unlocked,
    hodlJournalClearConfirm: dialog || null,
    initJournalClearConfirm: () => ({ show(opener, options) { pending = { opener, ...options }; } }),
    hodlJournalDownloadLog: download,
    hodlJournalSaveFile() { assert.fail("Debug log export must not export the complete Journal"); },
    hodlJournalWipeMem() { assert.fail("Debug log Clear must not clear the complete Journal"); },
    hodlTText: (text) => text,
    document: document || { querySelectorAll: () => [], getElementById: (id) => id === "journal-log-clear" ? button : null },
    hodlInitTabDrag() {},
    hodlJournalAppend() {},
    hodlInitJournalActionAudit() {},
    hodlRefreshJournalKeyPicker() {},
    hodlSyncJournalTool() {},
    hodlRenderJournalLog() {},
    hodlJournalLog(action, detail, tool) {
      events.push([action, detail, tool]);
      context.hodlJournal.log.push({ at: "2026-10-22T12:01:00Z", action, detail, tool });
    },
  };
  runInNewContext(["hodlJournalGetClearConfirm", "hodlJournalClearLog", "hodlInitJournalToolTabs"].map(appFunction).join("\n"), context);
  context.hodlInitJournalToolTabs();
  return { context, journal, log, button, events, pending: () => pending };
}

test("Activity Clear waits for confirmation, then records only the clear metadata", () => {
  const h = activityHarness();
  const original = h.log.slice();
  h.button.onclick();
  assert.deepEqual(h.log, original, "opening Clear must preserve existing activity");
  assert.equal(h.events.length, 0);
  assert.equal(h.pending().opener, h.button);
  const retainedEvent = h.log[0];
  h.pending().onDiscard();
  assert.deepEqual(h.events, [["clear", "session-log", "journal"]]);
  assert.notEqual(h.journal.log, h.log, "clearing must invalidate work captured against the old log");
  assert.equal(h.log.length, 0);
  for (const name of ["at", "tool", "action", "detail"]) assert.equal(retainedEvent[name], "", "clearing must release imported text held by an old event reference");
  assert.equal(h.journal.log.length, 1);
  assert.equal(h.journal.log[0].action, "clear");
  assert.equal(h.journal.log[0].detail, "session-log");
  assert.equal(h.journal.logDiscarded, 0, "Clear must also reset history truncation metadata");
  h.pending().onDiscard();
  assert.equal(h.events.length, 1, "a retained callback must not clear the replacement log again");
});

test("Debug log Clear discloses when its export has no password protection", () => {
  const h = activityHarness();
  h.context.hodlJournalKeys = { passwordProtected: false };
  h.button.onclick();
  assert.match(h.pending().message, /no password protection/i);
  assert.match(h.pending().message, /anyone with the file/i);
  assert.doesNotMatch(h.pending().preparingMessage, /encrypted|protected/i);
  assert.equal(h.log.length, 1);
  assert.equal(h.events.length, 0);
});

test("Debug log Export first uses the captured log and requires a separate Clear", async () => {
  let suppliedGuard, finish;
  const h = activityHarness({ download: (isCurrent) => { suppliedGuard = isCurrent; return new Promise((resolve) => { finish = resolve; }); } });
  const original = h.log.slice();
  h.button.onclick();
  assert.equal(typeof h.pending().onDownload, "function", "Clear must offer the existing protected Debug log export");
  let modalCurrent = true;
  const pending = h.pending().onDownload(() => modalCurrent);
  assert.equal(suppliedGuard(), true);
  assert.deepEqual(h.log, original);
  assert.equal(h.events.length, 0);
  finish(true);
  assert.equal(await pending, true);
  assert.deepEqual(h.log, original, "download handoff is not permission to remove the log");
  assert.equal(h.events.length, 0);
  modalCurrent = false;
  assert.equal(suppliedGuard(), false, "dismissing the modal must invalidate a pending export");
  h.pending().onDiscard();
  assert.equal(h.journal.log.length, 1);
  assert.equal(h.journal.log[0].action, "clear");
});

test("a stale Debug log export cannot start or clear a replacement log", async () => {
  for (const replace of [
    (h) => { h.context.hodlJournal = { log: h.log.slice() }; },
    (h) => { h.journal.log = h.log.slice(); },
    (h) => { h.context.hodlJournalGeneration++; },
    (h) => { h.context.unlocked = false; },
  ]) {
    let downloads = 0;
    const h = activityHarness({ download: async () => { downloads++; return true; } });
    h.button.onclick();
    assert.equal(typeof h.pending().onDownload, "function");
    const original = h.log.slice();
    replace(h);
    assert.equal(await h.pending().onDownload(() => true), false);
    h.pending().onDiscard();
    assert.equal(downloads, 0);
    assert.equal(h.events.length, 0);
    assert.deepEqual(h.log, original);
  }
});

test("Activity Clear cannot apply after a Journal, log, generation, or unlocked-state change", () => {
  for (const replace of [
    (h) => { h.context.hodlJournal = { log: h.log.slice() }; },
    (h) => { h.journal.log = h.log.slice(); },
    (h) => { h.context.hodlJournalGeneration++; },
    (h) => { h.context.unlocked = false; },
  ]) {
    const h = activityHarness();
    const original = h.log.slice();
    h.button.onclick();
    assert.deepEqual(h.log, original);
    assert.ok(h.pending());
    replace(h);
    h.pending().onDiscard();
    assert.deepEqual(h.log, original);
    assert.deepEqual(h.context.hodlJournal.log, original);
    assert.equal(h.events.length, 0);
  }
});

test("empty or closed Journals do not offer Activity Clear", () => {
  for (const empty of [false, true]) {
    const h = activityHarness();
    if (empty) h.log.length = 0;
    else h.context.unlocked = false;
    const original = h.log.slice();
    h.button.onclick();
    assert.deepEqual(h.log, original);
    assert.equal(h.pending(), undefined);
    assert.equal(h.events.length, 0);
  }
});

async function withLogDialog(run, download) {
  const { initJournalClearConfirm } = await import("../src/js/journal-clear-confirm.js");
  const previous = globalThis.document;
  const document = new MiniDocument();
  globalThis.document = document;
  const opener = document.createElement("button");
  opener.id = "journal-log-clear";
  document.body.append(opener);
  const dialog = initJournalClearConfirm({
    onDownload() { assert.fail("Debug log export must not use the complete Journal callback"); },
    onDiscard() { assert.fail("Debug log Clear must not use the complete Journal callback"); },
  });
  for (const button of document.querySelectorAll("button")) {
    button.focus = () => { document.activeElement = button; };
    button.click = () => { if (!button.disabled) button.dispatchEvent({ type: "click", target: button }); };
  }
  try {
    const h = activityHarness({ document, dialog, download });
    await run({ ...h, dialog, document, opener, el: (name) => document.getElementById(`journal-clear-${name}`) });
  } finally {
    globalThis.document = previous;
  }
}

test("cancelling the Activity confirmation preserves its log and restores focus", async () => {
  await withLogDialog((h) => {
    const { document, opener, el } = h;
    const original = h.log.slice();
    h.button.onclick();
    assert.equal(document.activeElement, el("cancel"));
    el("cancel").click();
    assert.equal(document.activeElement, opener);
    el("discard").click();
    assert.deepEqual(h.log, original);
    assert.equal(h.events.length, 0);
  });
});

test("Debug log Export first retains content through export outcomes until explicit Clear", async () => {
  for (const result of [true, false]) {
    let finish, calls = 0;
    await withLogDialog(async (h) => {
      const original = h.log.slice();
      h.button.onclick();
      h.el("download").click();
      h.el("download").click();
      h.el("discard").click();
      assert.equal(calls, 1);
      assert.deepEqual(h.log, original);
      assert.equal(h.events.length, 0);
      finish(result);
      await new Promise((resolve) => setImmediate(resolve));
      assert.equal(h.el("modal").hidden, false);
      assert.ok(h.el("status").textContent.trim());
      assert.deepEqual(h.log, original);
      assert.equal(h.events.length, 0);
      h.el("discard").click();
      assert.equal(h.el("modal").hidden, true);
      assert.equal(h.journal.log.length, 1);
      assert.equal(h.journal.log[0].action, "clear");
      assert.equal(h.journal.logDiscarded, 0);
    }, () => { calls++; return new Promise((resolve) => { finish = resolve; }); });
  }
});

test("cancelling an in-flight Debug log export invalidates its handoff and keeps the log", async () => {
  let finish, current;
  await withLogDialog(async (h) => {
    const original = h.log.slice();
    h.button.onclick();
    h.el("download").click();
    assert.equal(current(), true);
    h.el("modal").dispatchEvent({ type: "keydown", key: "Escape" });
    assert.equal(current(), false);
    finish(false);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(h.el("modal").hidden, true);
    assert.equal(h.el("status").textContent, "");
    assert.deepEqual(h.log, original);
    assert.equal(h.events.length, 0);
  }, (isCurrent) => { current = isCurrent; return new Promise((resolve) => { finish = resolve; }); });
});

function logRenderHarness({ top = 300, height = 100, unchanged = false } = {}) {
  const log = [{ at: "2026-10-22T12:00:00Z", tool: "imported", action: "<img src=x onerror=1>" }];
  let content = unchanged ? formatLog(log) : "", writes = 0, scrollTop = top;
  const output = {
    clientHeight: height,
    scrollHeight: 400,
    scrollLeft: 20,
    get scrollTop() { return scrollTop; },
    set scrollTop(value) { scrollTop = Math.max(0, Math.min(value, this.scrollHeight - this.clientHeight)); },
    get textContent() { return content; },
    set textContent(value) {
      writes++;
      content = value;
      this.scrollHeight = 500;
      this.scrollTop = scrollTop;
    },
    set innerHTML(_value) { assert.fail("Activity content must only be rendered as text"); },
  };
  const context = { document: { getElementById: (id) => id === "journal-log-out" ? output : null }, hodlJournal: { log }, hodlJournalFormatLog: formatLog, hodlJournalFormatLogField: formatLogField, hodlJournalLogUsage: logUsage };
  runInNewContext(appFunction("hodlRenderJournalLog"), context);
  return { context, output, log, writes: () => writes };
}

test("Activity refresh follows new entries only when the visible reader is at the end", () => {
  for (const [top, height, expected] of [[300, 100, 400], [75, 100, 75], [400, 0, 400]]) {
    const h = logRenderHarness({ top, height });
    h.context.hodlRenderJournalLog();
    assert.equal(h.output.scrollTop, expected);
    assert.equal(h.output.scrollLeft, 20);
    assert.equal(h.output.textContent, formatLog(h.log));
  }
});

test("Activity refresh leaves unchanged text nodes intact for reading and selection", () => {
  const h = logRenderHarness({ unchanged: true });
  h.context.hodlRenderJournalLog();
  assert.equal(h.writes(), 0);
  assert.equal(h.output.scrollTop, 300);
});
