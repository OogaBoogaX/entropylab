// Journal secret lifecycle, disclosure copy, and error/focus wiring
// (release plan W3-W5, round 2).
//
// Two kinds of pin live here, and the difference matters:
//
// - Executable pins run the real app.js functions, sliced out of the source
//   the way test/journal-wipe-race.test.mjs and test/secret-clear.test.mjs do
//   it, over a stub DOM. They prove what the shipped function does to every
//   store it touches: each assertion fails if the wipe it checks is removed
//   from the function. They cannot prove what a real browser retains (string
//   copies, bfcache, the clipboard) — the wipe is best-effort by design — and
//   they cannot prove the browser fires the events that call these functions.
// - Source-level pins prove a wiring exists in the shipped source (a
//   listener, a guard, an attribute). Alone they say nothing about runtime
//   behaviour; where an executable proof of the same contract lives in
//   another file, the comment says so.
//
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import { addEntry, appendLog, createJournal, emptyDocument, formatStamp, journalNotebookRuns, journalPageNotesText, mergeLogHistory, wipeDocument, wipeJournal } from "../src/js/journal.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");
const shell = readFileSync(join(root, "src/shell.html"), "utf8");

// Distinct markers, so one leftover copy can be told apart from another.
const SECRET_PHRASE = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const SECRET_NOTES = "the safe combination is 42-17-99";
const SECRET_STATE = "xprv9s21ZrQH143K-session-snapshot";
const FIRST_NOTE_STAMP = "2026-10-22 09:08:07";

// Slice one function out of app.js by brace matching, the way
// test/journal-wipe-race.test.mjs loads the unlock path.
function loadSlice(name) {
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

// The module-level session declarations the sliced functions close over,
// pulled from app.js so the test tracks the real declarations.
const varLine = (name) => {
  const line = app.match(new RegExp(`var ${name} = [^\\n]+;`));
  assert.ok(line, `var ${name}`);
  return line[0];
};

// The real Clear and saved-record close paths, with the note renderer
// that re-renders the notepad's mirror, over a stub DOM whose elements start
// full of marker text. The journal store and document wipes come from the
// real journal.js; the Key Manager reset and the tab renderers are spies (the
// reset's own byte wiping is pinned in test/secret-clear.test.mjs).
const LIFECYCLE_SLICES = [
  "hodlJournalUnlocked", "hodlJournalMarkDirty", "hodlJournalNoteText",
  "hodlJournalActivePage", "hodlJournalStoreNotesText", "hodlJournalRenderVisual",
  "hodlJournalSyncNotesRender", "hodlJournalSyncCopyButton", "hodlJournalSetGateBusy", "hodlJournalClearReport", "hodlJournalWipeNotebook",
  "hodlJournalClearFields", "hodlJournalHideEditor", "hodlJournalLog", "hodlJournalWipeMem",
];

function journalLifecycleHarness({ onShowWork = () => {} } = {}) {
  const calls = [];
  const elements = new Map();
  const add = (id, element) => {
    elements.set(id, element);
    return element;
  };
  const field = (value = "") => ({
    value, dataset: {}, hidden: false, textContent: "", focused: false,
    selectionStart: 0, selectionEnd: 0, selectionDirection: "none",
    clientWidth: 0, clientHeight: 0, scrollTop: 0, scrollLeft: 0,
    setSelectionRange(start, end) { this.selectionStart = start; this.selectionEnd = end; },
    focus() { this.focused = true; },
  });
  for (const id of ["journal-create-password", "journal-create-confirm", "journal-open-password", "journal-search", "journal-input", "journal-phrase", "journal-label", "journal-entry-notes"])
    add(id, field(SECRET_PHRASE));
  add("journal-file", { value: "entropylab-journal.json" });
  add("journal-list", { innerHTML: `<button>${SECRET_PHRASE}</button>`, hidden: false, querySelector: () => null });
  add("journal-view", { innerHTML: `<span>${SECRET_PHRASE}</span>`, hidden: false, contains: () => false });
  add("journal-editor", { hidden: false, hodlJournalEdit: { entry: { input: SECRET_PHRASE } }, contains: () => false });
  add("journal-error", { textContent: "old error" });
  add("journal-state-text", { textContent: SECRET_STATE, removeAttribute() {} });
  add("journal-saved-state-text", { textContent: SECRET_STATE, removeAttribute() {} });
  add("journal-saved-state-private", { checked: true });
  add("journal-state-private", { checked: true });
  add("journal-notes-text", field(SECRET_NOTES));
  add("journal-notes-render", {
    children: [{ text: SECRET_NOTES }], style: {}, scrollTop: 0, scrollLeft: 0,
    replaceChildren() { this.children = []; },
    appendChild(node) { this.children.push(node); },
  });
  add("journal-log-out", { textContent: SECRET_STATE });
  add("journal-status-note", { textContent: "" });
  add("journal-gate-status", { textContent: "" });
  add("journal-create", { focused: false, focus() { this.focused = true; } });
  add("journal-keymanager-tab", { focused: false, focus() { this.focused = true; } });
  add("journal-open-ready", { hidden: true });
  // The wipe asks the work panel and global toolbar whether the active
  // element sits inside them, so the stubs track their descendants.
  for (const id of ["journal-work-panel", "journal-global-actions"])
    add(id, { hidden: false, descendants: new Set(), contains(element) { return this.descendants.has(element); } });
  const documentStub = {
    activeElement: null,
    getElementById: (id) => elements.get(id) ?? null,
    createTextNode: (text) => ({ text }),
  };
  const journal = createJournal();
  journal.notesText = SECRET_NOTES;
  journal.pages[0].notesText = SECRET_NOTES;
  journal.log.push({ at: "2026-01-01 00:00:00", tool: "journal", action: "entry-add", detail: SECRET_PHRASE });
  journal.stateText = SECRET_STATE;
  const doc = emptyDocument();
  addEntry(doc, { method: "seed", input: "6 1 3 5 2", phrase: SECRET_PHRASE, label: "savings", notes: SECRET_NOTES });
  const entry = doc.entries[0];
  const source = [
    varLine("hodlJournalKeys"), varLine("hodlJournalGeneration"), varLine("hodlJournalFileRead"),
    varLine("hodlJournalOpenReadyFor"), varLine("hodlJournalTool"), varLine("hodlJournalUnlockBusy"),
    varLine("hodlJournalKeyDerivation"),
    varLine("hodlJournalReportViewer"),
    ...LIFECYCLE_SLICES.map(loadSlice),
  ].join("\n");
  const api = new Function(
    "document", "hodlJournal", "wipeJournal", "hodlJournalWipeDocument", "hodlJournalAppend",
    "hodlJournalStamp", "hodlJournalNotebookRuns", "hodlJournalPageNotesText", "hodlTText", "hodlWorkspace", "hodlKeyManagerReset",
    "hodlJournalSetGate", "hodlJournalShowWork", "hodlSyncJournalTool", "hodlRenderJournalPageTabs",
    "hodlJournalApplyPageStyle", "hodlJournalSetStatus",
    "hodlScheduleJournalStateRefresh", "hodlRenderJournalLog", "hodlFillKeyTabLifehash", "hodlKeyManagerCancelDerivation",
    `${source}; return {
      wipeMem: hodlJournalWipeMem,
      hideEditor: hodlJournalHideEditor,
      openNotebook: (keys, doc) => { hodlJournalKeys = keys; hodlJournalDoc = doc; },
      notebook: () => ({ keys: hodlJournalKeys, doc: hodlJournalDoc, reveal: hodlJournalReveal, fileText: hodlJournalFileText, openReadyFor: hodlJournalOpenReadyFor }),
    };`,
  )(
    documentStub, journal, wipeJournal, wipeDocument, appendLog,
    formatStamp, journalNotebookRuns, journalPageNotesText, (text) => text, "calc", () => calls.push("key-manager-reset"),
    () => {}, () => onShowWork(documentStub, elements), () => {}, () => {},
    () => {}, () => {},
    () => {}, () => {}, () => {}, () => {},
  );
  return { api, elements, journal, doc, entry, calls, documentStub };
}

// Clear drops every store the plan names —
// entries, phrases, notes, notepad text, session-state text, session-log
// text, key-manager rows, and the password fields. Each one fails if the wipe
// it checks is removed from the function under test.
function assertNoJournalPlaintext({ api, elements, journal, doc, entry, calls }) {
  // The encrypted session: keys dropped, the document wiped in place and then
  // dropped, and the armed passwordless acknowledgement (a full copy of the
  // file's bytes) forgotten.
  assert.deepEqual(api.notebook(), { keys: null, doc: null, reveal: false, fileText: "", openReadyFor: "" });
  assert.equal(doc.entries.length, 0, "the document kept its entries");
  for (const field of ["input", "phrase", "label", "notes"]) assert.equal(entry[field], "", `the wiped document kept an entry's ${field}`);
  // Password fields, saved-record search, and temporary recovery edits.
  for (const id of ["journal-create-password", "journal-create-confirm", "journal-open-password", "journal-search", "journal-input", "journal-phrase", "journal-label", "journal-entry-notes"])
    assert.equal(elements.get(id).value, "", `#${id} kept its text`);
  assert.equal(elements.get("journal-editor").hidden, true);
  assert.equal(elements.get("journal-editor").hodlJournalEdit, undefined);
  assert.equal(elements.get("journal-file").value, "", "the file picker kept its choice");
  // Rendered copies: the entry list, the entry view, the error line.
  assert.equal(elements.get("journal-list").innerHTML, "", "the entry list kept its rows");
  assert.equal(elements.get("journal-view").innerHTML, "", "a revealed entry stayed on screen");
  assert.equal(elements.get("journal-error").textContent, "", "the error line kept its message");
  // The session snapshot, on screen and in memory.
  assert.equal(elements.get("journal-state-text").textContent, "", "the session snapshot stayed on screen");
  assert.equal(elements.get("journal-state-private").checked, false, "the private box stayed ticked");
  assert.equal(elements.get("journal-saved-state-text").textContent, "", "the saved snapshot stayed on screen");
  assert.equal(elements.get("journal-saved-state-private").checked, false, "saved reveal stayed checked");
  assert.equal(journal.stateText, "", "the snapshot's in-memory text survived");
  // The log may show a new empty-state message, but none of its old secrets.
  for (const secret of [SECRET_PHRASE, SECRET_NOTES, SECRET_STATE])
    assert.ok(!elements.get("journal-log-out").textContent.includes(secret), "the session log kept secret text on screen");
  // The notepad: the field, its rendered mirror, and the in-memory pages.
  assert.equal(elements.get("journal-notes-text").value, "", "the notepad kept its text");
  assert.ok(!elements.get("journal-notes-render").children.map((node) => node.text).join("").includes(SECRET_NOTES), "the notepad's rendered mirror kept its text");
  assert.equal(journal.pages.length, 1, "extra notepad pages survived");
  assert.ok(!journal.pages[0].notesText.includes(SECRET_NOTES) && !journal.notesText.includes(SECRET_NOTES), "the notepad's in-memory text survived");
  // The Key Manager's rows go with the journal.
  assert.deepEqual(calls.filter((call) => call === "key-manager-reset"), ["key-manager-reset"], "the Key Manager was not reset");
}

test("the global Clear leaves no journal plaintext behind (plan W3)", () => {
  // Executable: the real hodlJournalWipeMem, which is also what End Session
  // and pagehide reach through clearSecretFields (wired in the next test).
  const harness = journalLifecycleHarness();
  harness.api.openNotebook({ passwordProtected: true }, harness.doc);
  harness.documentStub.activeElement = {};
  harness.api.wipeMem();
  assertNoJournalPlaintext(harness);
  assert.deepEqual(harness.journal.log, [], "log events survived in memory");
  // The status note hides with the toolbar; the gate's live region stays
  // visible and carries Clear's audible announcement (plan W5).
  assert.ok(harness.elements.get("journal-status-note").textContent.trim(), "Clear did not announce through #journal-status-note");
  assert.ok(harness.elements.get("journal-gate-status").textContent.trim(), "Clear did not announce through the gate's live region");
  // Focus outside the work panel and global toolbar is left alone.
  assert.equal(harness.elements.get("journal-create").focused, false, "Clear moved focus");
});

test("clearing a Journal forgets an unfinished note edit before another session opens", () => {
  const harness = journalLifecycleHarness(), field = harness.elements.get("journal-notes-text");
  field.hodlJournalEdit = { start: 0, end: field.value.length, direction: "none", top: 0, left: 0 };
  harness.api.wipeMem();
  assert.equal(field.hodlJournalEdit, undefined);
});

test("Clear asks for confirmation while End Session and pagehide wipe directly (plan W3)", () => {
  // Source-level: proves the wiring exists in the shipped source, not that a
  // browser fires the events (the browser suite's job) — what the wipe does
  // once reached is proven executable above. End Session dispatches a
  // pagehide (pinned in test/end-session.test.mjs), so both lifecycle paths
  // reach clearSecretFields without waiting for confirmation.
  assert.match(app, /getElementById\("journal-global-clear"\)\?\.addEventListener\("click", hodlJournalConfirmClear\)/);
  const start = app.indexOf("function hodlInitSecretFieldAutoClear()");
  const lifecycle = app.slice(start, app.indexOf("\nfunction hodlBoot()", start));
  // In try/catch: one failing wipe must not skip the wipes after it.
  assert.match(lifecycle, /try \{\s*hodlJournalWipeMem\(\);\s*\} catch \{\}/);
  assert.match(lifecycle, /addEventListener\("pagehide", clearSecretFields\)/);
  assert.match(lifecycle, /event\.persisted\) clearSecretFields\(\)/);
});

test("conceal-on-leave masks a revealed journal entry (plan W3)", () => {
  // Executable half: the real sweep against a revealed toggle wired the way
  // the journal entry view wires #journal-reveal. Proves the sweep drops the
  // journal's reveal flag and unticks every data-private-reveal control
  // through its own change event (which is what re-renders the view masked).
  // Cannot prove the browser delivers blur/hidden/print: that those signals —
  // including beforeprint and the print media-query fallback (audit L5) —
  // call this same sweep is pinned in test/conceal-on-leave.test.mjs.
  const dispatched = [];
  const toggle = {
    checked: true,
    isConnected: true,
    dispatchEvent(event) { dispatched.push(event.type); },
  };
  const documentStub = {
    getElementById: () => null,
    querySelectorAll: (selector) => selector === "input[data-private-reveal]" ? [toggle] : [],
    dispatchEvent: (event) => dispatched.push(event.type),
  };
  class FakeEvent {
    constructor(type) { this.type = type; }
  }
  const source = [
    "var hodlRevealPrivate = true, hodlBip85Reveal = true, hodlVanityReveal = true, hodlJournalReveal = true;",
    loadSlice("hodlConcealPrivateValues"),
  ].join("\n");
  const api = new Function(
    "document", "Event", "hodlKeys", "hodlBip85Children", "hodlSpAddresses", "hodlSpVerifyMatches",
    `${source}; return { conceal: hodlConcealPrivateValues, journalRevealed: () => hodlJournalReveal };`,
  )(documentStub, FakeEvent, [], [], [], null);
  api.conceal();
  assert.equal(toggle.checked, false, "the sweep left a revealed private toggle ticked");
  assert.ok(dispatched.includes("change"), "the sweep unticked without the change event that re-renders masked");
  assert.equal(api.journalRevealed(), false, "the sweep left the journal's reveal flag set");
  // Source half: the entry view's reveal switch is one of those toggles, and
  // its change handler re-renders the view from the (now cleared) flag.
  const view = loadSlice("hodlJournalOpenView");
  assert.match(view, /id="journal-reveal" data-private-reveal/, "the entry view's reveal switch must join the sweep");
  assert.match(view, /hodlJournalReveal = event\.target\.checked/, "the reveal switch must drive the mask");
  assert.match(view, /hodlJournalOpenView\(id\)/, "unticking must re-render the view masked");
});

test("unticking the session-state private box drops the private snapshot text (plan W3)", () => {
  // Source-level wiring pin: the box re-renders the snapshot on every change,
  // not only when the tab opens. The executable proof that the re-render
  // leaves no private material in #journal-state-text lives in
  // test/secret-clear.test.mjs ("the session-state private box re-renders the
  // snapshot on change").
  assert.match(app, /for \(let id of \["journal-state-private", "journal-saved-state-private"\]\) \{\s*document\.getElementById\(id\)\?\.addEventListener\("change", \(\) => hodlJournalRefreshSessionState\(\)\)/);
  const refresh = loadSlice("hodlJournalRefreshSessionState");
  assert.match(refresh, /includePrivate = Boolean\(document\.getElementById\("journal-state-private"\)\?\.checked\)/);
  assert.match(refresh, /hodlRenderAnnotatedPrivateText\(field, text,/, "snapshots must use the shared literal-text renderer");
});

test("Key Station activity has no duplicate saved-record capture path", () => {
  assert.doesNotMatch(app, /hodlJournalSyncDerivedKeys|hodlJournalCaptureDerivedKey|hodlJournalBackfillDerivedKeys/);
});

test("the journal intro discloses passwordless readability (plan W4)", () => {
  // Owner-approved disclosure copy, pinned by its stable substrings only
  // (AGENTS.md: safety-critical wording may be pinned by a short stable
  // substring; the rest of the sentence stays free to reword).
  const intro = shell.slice(shell.indexOf('id="journal-tool-intro"'), shell.indexOf('id="journal-manager"'));
  assert.ok(intro.includes("anyone with the file"), "the intro must disclose who can read a passwordless journal");
  assert.match(intro, /password protects/i, "the intro must explain password protection");
});

test("every journal open failure routes to #journal-error, an alert region (plan W5)", () => {
  // Source-level: proves each failure state reaches the alert region as text.
  // The messages themselves (wrong password, corrupt, wrong kind) are thrown
  // by journal.js's openDocument/parseFile and pinned in
  // test/journal.test.mjs; this pins that the open path surfaces them.
  const tag = /<p\b[^>]*\bid="journal-error"[^>]*>/.exec(shell)?.[0] || "";
  assert.ok(/\brole="alert"/.test(tag), "#journal-error must be an alert region");
  assert.match(loadSlice("hodlJournalError"), /error\.textContent = message/, "the error line is text, never markup");
  const unlock = loadSlice("hodlJournalUnlock");
  // Current wrong-password/corrupt-file errors share one region. Obsolete
  // requests are silent, exercised by the gate race tests below.
  const catchBody = unlock.slice(unlock.indexOf("catch (exception)"), unlock.indexOf("finally"));
  assert.match(catchBody, /hodlJournalError\(exception\.message \|\| String\(exception\)\)/);
  // Too large is refused before the file is read.
  assert.match(loadSlice("hodlJournalChooseFile"), /hodlJournalError\(hodlTText\("That journal file is too large/);
  // A passwordless file's first press arms the acknowledgement and announces
  // why nothing was installed yet (audit L6).
  const armStart = unlock.indexOf("if (!opened.keys.passwordProtected");
  const armEnd = unlock.indexOf("hodlJournalDiscardOpened(opened);", armStart);
  assert.ok(armEnd > armStart, "the passwordless acknowledgement arm is gone");
  assert.match(unlock.slice(armStart, armEnd), /hodlJournalError\(/, "the passwordless first press must announce through #journal-error");
});

test("Clear announces through the #journal-status-note live region (plan W5)", () => {
  // Source-level: the region is polite (also pinned in
  // test/journal-view-safety.test.mjs) and Clear writes to it. The executable
  // half of this contract is in the lifecycle test above.
  const tag = /<p\b[^>]*\bid="journal-status-note"[^>]*>/.exec(shell)?.[0] || "";
  assert.ok(/\brole="status"/.test(tag), "#journal-status-note must be a live region");
  assert.match(loadSlice("hodlJournalWipeMem"), /getElementById\("journal-status-note"\)[\s\S]*?hodlTText\(/);
});

test("closing a saved record returns focus to Keys (plan W5)", () => {
  const hide = loadSlice("hodlJournalHideEditor");
  assert.match(hide, /document\.activeElement/);
  assert.match(hide, /getElementById\("journal-keymanager-tab"\)\?\.focus\(\)/);
  // Executable: focus inside the closing view moves to Keys; focus
  // anywhere else is left alone.
  const harness = journalLifecycleHarness();
  const child = {};
  harness.elements.get("journal-view").contains = (element) => element === child;
  harness.documentStub.activeElement = child;
  harness.api.hideEditor();
  assert.equal(harness.elements.get("journal-keymanager-tab").focused, true, "closing the view left focus to fall back to <body>");
  const again = journalLifecycleHarness();
  again.api.hideEditor();
  assert.equal(again.elements.get("journal-keymanager-tab").focused, false, "closing the saved record stole focus it did not own");
});

test("the global Clear rescues focus stranded inside the hidden work panel (plan W5)", () => {
  // Executable: focus starts inside a saved record. hideEditor hands it to
  // Keys, which Clear then hides, so the wipe
  // must park it on the gate's primary action — never leave it on a hidden
  // control, and never let it fall to <body>.
  const harness = journalLifecycleHarness();
  harness.api.openNotebook({ passwordProtected: true }, harness.doc);
  const child = {};
  harness.elements.get("journal-view").contains = (element) => element === child;
  harness.elements.get("journal-work-panel").descendants.add(child);
  harness.documentStub.activeElement = child;
  harness.api.wipeMem();
  assert.equal(harness.elements.get("journal-create").focused, true, "Clear left focus on a control hidden with the work panel");
});

test("the global Clear remembers toolbar focus before hiding its controls", () => {
  for (const fallback of [null, { tagName: "BODY" }]) {
    const harness = journalLifecycleHarness({
      onShowWork(documentStub, elements) {
        elements.get("journal-global-actions").hidden = true;
        documentStub.activeElement = fallback;
      },
    });
    harness.api.openNotebook({ passwordProtected: true }, harness.doc);
    const clear = {};
    harness.elements.get("journal-global-actions").descendants.add(clear);
    harness.documentStub.activeElement = clear;
    harness.api.wipeMem();
    assert.equal(harness.elements.get("journal-global-actions").hidden, true);
    assert.equal(harness.elements.get("journal-create").focused, true, "Clear lost toolbar focus when hiding its controls");
  }
});

test("the Clear announcement also lands in a live region outside the hidden global toolbar (plan W5)", () => {
  // #journal-status-note is inside #journal-global-actions, which Clear
  // hides, so a write to it is outside the accessibility tree and announces
  // nothing. The audible copy goes to #journal-gate-status, a polite live
  // region inside #journal-locked-panel — the panel Clear leaves
  // visible (hodlJournalShowWork unhides it while locked).
  const tag = /<p\b[^>]*\bid="journal-gate-status"[^>]*>/.exec(shell)?.[0] || "";
  assert.ok(/\brole="status"/.test(tag) || /\baria-live=/.test(tag), "#journal-gate-status must be a live region");
  const lockedPanel = shell.slice(shell.indexOf('id="journal-locked-panel"'), shell.indexOf('id="journal-work-panel"'));
  assert.ok(lockedPanel.includes('id="journal-gate-status"'), "the announcement region must live in the panel that stays visible");
  const workPanel = shell.slice(shell.indexOf('id="journal-work-panel"'), shell.indexOf('id="journal-error"'));
  assert.ok(!workPanel.includes('id="journal-gate-status"'), "the announcement region must not sit inside the hidden work panel");
  assert.match(loadSlice("hodlJournalShowWork"), /locked\.hidden = unlocked/, "the locked panel is the one shown while locked");
  assert.match(loadSlice("hodlJournalWipeMem"), /getElementById\("journal-gate-status"\)/);
});

test("the Sources section discloses the released journal's encryption design (plan W4)", () => {
  // The disclosure was held back with the Journal tab (#511) and ships
  // alongside it. Pinned by stable substrings, with comments stripped so a
  // commented-out paragraph cannot count.
  const sources = shell.slice(shell.indexOf('id="sources"'), shell.indexOf('id="important"')).replace(/<!--[\s\S]*?-->/g, "");
  assert.ok(sources.includes("Entropy Journal"), "the Sources section must name the Entropy Journal");
  assert.ok(sources.includes("no access protection"), "the Sources section must say a passwordless file has no access protection");
});

test("the static tab strip no longer marks the released Journal tab as held back", () => {
  // The strip is re-rendered from hodlWorkspaceTabs at boot; its placeholder
  // comment must not contradict the released tab.
  const strip = shell.slice(shell.indexOf('id="workspace-tabs"'), shell.indexOf('id="workspace-panel"'));
  assert.ok(!strip.includes("Journal are held back"), "the tab-strip comment still holds the Journal back");
});

// Gate operations install only their own current generation. A previous
// request may neither overwrite the current notebook nor unlock its controls
// or report an obsolete failure after a wipe and a newer request.
function gateHarness() {
  const fields = new Map(), requests = [], stamps = [], resets = [];
  for (const id of ["journal-create", "journal-unlock", "journal-create-password", "journal-create-confirm", "journal-open-password", "journal-file", "journal-error", "journal-gate-status", "journal-locked-panel", "journal-notes-tab", "journal-open-ready"]) {
    fields.set(id, { value: "fixture password", disabled: false, textContent: "", listeners: {},
      addEventListener(type, fn) { this.listeners[type] = fn; }, focus() { context.document.activeElement = this; } });
  }
  fields.get("journal-open-ready").querySelector = () => ({ textContent: "fixture no-password acknowledgement" });
  const begin = (mode) => new Promise((resolve, reject) => requests.push({ mode, resolve, reject }));
  const context = vm.createContext({
    document: { getElementById: (id) => fields.get(id) ?? null, querySelectorAll: () => [], activeElement: null },
    hodlJournalKeys: null, hodlJournalDoc: null, hodlJournal: createJournal(), hodlJournalGeneration: 0,
    hodlJournalReportViewer: null, hodlJournalReportRequest: 0,
    hodlJournalUnlockBusy: false, hodlJournalFileRead: null, hodlJournalFileText: "selected file", hodlJournalOpenReadyFor: "",
    hodlJournalDirty: false, hodlJournalReveal: false, hodlJournalEditingId: null, hodlJournalDeleteArmed: false,
    hodlJournalCreateDocument: () => begin("create"), hodlJournalOpenDocument: () => begin("open"),
    hodlJournalStamp: () => { stamps.push(FIRST_NOTE_STAMP); return FIRST_NOTE_STAMP; },
    hodlJournalWipeDocument: wipeDocument, wipeJournal, hodlJournalMergeLogHistory: mergeLogHistory,
    hodlActiveDerivation: null, hodlJournalKeyDerivation: null, hodlWorkspace: "calc",
    hodlKeys: [], hodlKeyManagerPending: [], hodlKeyManagerIgnored: [], hodlKeyVaultMaxKeys: 100,
    keyVaultIdentity: state => String(state.id), hodlCaptureKey() {},
    hodlKeyManagerReset() { resets.push("reset"); }, hodlJournalRestoreBackup() {}, hodlJournalHideEditor() {}, hodlJournalShowWork() {}, hodlJournalLog() {},
    hodlShowJournalTool(id, focus) { if (id === "notes" && focus) fields.get("journal-notes-tab").focus(); },
    hodlSyncJournalCreatePasswordValidation() {}, hodlJournalSetGate() {}, hodlJournalChooseFile() {},
    hodlJournalSaveFile() {}, hodlJournalConfirmClear() {}, hodlJournalRenderList() {},
    hodlTText: (text) => text,
  });
  for (const name of ["hodlKeyManagerHasInputs", "hodlKeyManagerStates", "hodlKeyManagerCapacityError", "hodlJournalCheckInventory", "hodlJournalActivePage", "hodlJournalStartPage", "hodlJournalError", "hodlJournalSetGateBusy", "hodlJournalClearReport", "hodlJournalWipeNotebook", "hodlJournalDiscardOpened", "hodlJournalCreate", "hodlJournalUnlock", "hodlJournalCreatePasswordKeydown", "hodlInitJournalNotebook"]) {
    const match = app.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^}`, "m"));
    if (match) vm.runInContext(match[0], context);
  }
  return { context, fields, requests, stamps, resets };
}
const gateResult = () => ({ keys: { passwordProtected: true }, doc: emptyDocument() });

// Security contract: Create/Open accept only a quiescent resulting inventory
// within the existing 100-input bound, preserve the previous session on
// refusal, and wipe newly decrypted documents rejected after asynchronous work.
const gateStation = count => Array.from({ length: count }, (_, index) => ({ id: index + 1, fields: { seed: SECRET_PHRASE } }));
const gateRun = (ui, mode) => ui.context[mode === "create" ? "hodlJournalCreate" : "hodlJournalUnlock"]();
for (const mode of ["create", "open"]) {
  for (const busy of ["hodlActiveDerivation", "hodlJournalKeyDerivation"]) test(`${mode} refuses an active derivation before starting crypto: ${busy}`, async () => {
    const ui = gateHarness(), previous = gateResult();
    ui.context.hodlJournalDoc = previous.doc; ui.context.hodlJournalKeys = previous.keys;
    ui.context[busy] = {};
    const pending = gateRun(ui, mode);
    const started = ui.requests.length;
    ui.requests.forEach(request => request.resolve(gateResult()));
    await pending;
    assert.equal(started, 0, "a gate operation started crypto while key derivation was active");
    assert.equal(ui.context.hodlJournalDoc, previous.doc);
    assert.deepEqual(ui.resets, []);
    assert.ok(ui.fields.get("journal-error").textContent);
  });
  test(`${mode} from Journal preserves the verified station result without recapturing hidden calculator state`, async () => {
    const ui = gateHarness(), state = gateStation(1)[0];
    const result = { masterIdentity: "verified fixture identity", network: "mainnet" };
    state.result = result;
    ui.context.hodlKeys = [state];
    ui.context.hodlWorkspace = "journal";
    // Leaving Key Station clears the shared renderer result. CaptureKey
    // reads that renderer; it is valid only while the calculator is active.
    ui.context.hodlCaptureKey = () => { state.result = null; };
    const pending = gateRun(ui, mode), opened = gateResult();
    ui.requests[0].resolve(opened);
    await pending;
    assert.equal(ui.context.hodlJournalDoc, opened.doc);
    assert.equal(state.result, result, "a hidden calculator capture withdrew the retained verified result");
    assert.equal(state.fields.seed, SECRET_PHRASE);
  });
  test(`${mode} captures an unfinished Lab draft before the capacity preflight`, async () => {
    const ui = gateHarness(), lab = { id: 0, isLab: true, fields: {} };
    ui.context.hodlKeys = [lab, ...gateStation(100)];
    ui.context.hodlCaptureKey = () => { lab.fields.seed = SECRET_PHRASE; };
    const pending = gateRun(ui, mode), started = ui.requests.length;
    ui.requests.forEach(request => request.resolve(gateResult()));
    await pending;
    assert.equal(started, 0, "the uncaptured draft was omitted from the resulting inventory");
    assert.equal(lab.fields.seed, SECRET_PHRASE);
    assert.deepEqual(ui.resets, []);
    assert.ok(ui.fields.get("journal-error").textContent);
  });
  for (const change of ["inventory", "derivation"]) test(`${mode} rechecks ${change} after crypto and wipes only the rejected document`, async () => {
    const ui = gateHarness(), previous = gateResult(), opened = gateResult();
    const retained = addEntry(previous.doc, { method: "seed", input: SECRET_PHRASE, label: "Existing record" });
    const rejected = addEntry(opened.doc, { method: "seed", input: SECRET_PHRASE, label: "Rejected record" });
    ui.context.hodlJournalDoc = previous.doc; ui.context.hodlJournalKeys = previous.keys;
    const pending = gateRun(ui, mode);
    assert.equal(ui.requests.length, 1);
    if (change === "inventory") ui.context.hodlKeys = gateStation(101);
    else ui.context.hodlActiveDerivation = {};
    ui.requests[0].resolve(opened);
    await pending;
    assert.equal(ui.context.hodlJournalDoc, previous.doc, "the previous Journal was replaced on refusal");
    assert.equal(retained.input, SECRET_PHRASE);
    assert.equal(rejected.input, "", "rejected decrypted input was left in memory");
    assert.equal(opened.doc.entries.length, 0);
    assert.deepEqual(ui.resets, []);
    assert.ok(ui.fields.get("journal-error").textContent);
  });
  test(`${mode} accepts the boundary including a meaningful Lab draft and replaces old pending inputs`, async () => {
    const ui = gateHarness();
    ui.context.hodlKeys = [{ id: 0, isLab: true, fields: { seed: SECRET_PHRASE } }, ...gateStation(99)];
    ui.context.hodlKeyManagerPending = gateStation(100).map(state => ({ ...state, id: state.id + 100 }));
    ui.context.hodlKeyManagerIgnored = gateStation(100);
    const pending = gateRun(ui, mode), opened = gateResult();
    ui.requests[0].resolve(opened);
    await pending;
    assert.equal(ui.context.hodlJournalDoc, opened.doc);
    assert.deepEqual(ui.resets, ["reset"]);
  });
}

test("opening a complete backup counts the retained Lab draft alongside its restored inputs", async () => {
  const ui = gateHarness(), opened = gateResult();
  ui.context.hodlKeys = [{ id: 0, isLab: true, fields: { seed: SECRET_PHRASE } }];
  const incoming = { fields: { seed: SECRET_PHRASE } };
  opened.doc.backup = { keyManager: { keys: [incoming, ...gateStation(99)], ignoredKeys: [] } };
  const pending = gateRun(ui, "open");
  ui.requests[0].resolve(opened);
  await pending;
  assert.equal(ui.context.hodlJournalDoc, null);
  assert.equal(incoming.fields.seed, "");
  assert.deepEqual(ui.resets, []);
  assert.ok(ui.fields.get("journal-error").textContent);
});

test("legacy Journal open preserves current Debug history through notebook wiping", async () => {
  const ui = gateHarness(), original = appendLog(ui.context.hodlJournal, { at: FIRST_NOTE_STAMP, tool: "calc", action: "derive" });
  ui.context.hodlJournal.logDiscarded = 7;
  const pending = gateRun(ui, "open"), opened = gateResult();
  ui.requests[0].resolve(opened);
  await pending;
  assert.equal(ui.context.hodlJournalDoc, opened.doc);
  assert.equal(ui.context.hodlJournal.log.length, 1);
  assert.equal(ui.context.hodlJournal.log[0].action, "derive");
  assert.equal(ui.context.hodlJournal.logDiscarded, 7);
  assert.notEqual(ui.context.hodlJournal.log[0], original, "history must survive wiping its original objects");
  original.action = "changed after open";
  assert.equal(ui.context.hodlJournal.log[0].action, "derive");
});

test("successful Journal creation starts exactly one live timestamp on its first Notes page", async () => {
  const ui = gateHarness(), pending = ui.context.hodlJournalCreate();
  assert.equal(ui.context.hodlJournal.notesText, "", "the pending creation must not start a note");
  assert.equal(ui.stamps.length, 0);
  const created = gateResult();
  ui.requests[0].resolve(created);
  await pending;
  assert.equal(ui.context.hodlJournalDoc, created.doc);
  assert.equal(ui.context.hodlJournal.pages.length, 1);
  const page = ui.context.hodlJournal.pages[0];
  assert.equal(page.notesText, `${FIRST_NOTE_STAMP}  `);
  assert.equal(ui.context.hodlJournal.notesText, page.notesText);
  assert.deepEqual({ ...page.pendingStamp }, { start: 0, stamp: FIRST_NOTE_STAMP });
  assert.deepEqual(ui.stamps, [FIRST_NOTE_STAMP]);
});

for (const mode of ["create", "open"]) test(`${mode} is one visible busy operation and moves successful keyboard focus to Notes`, async () => {
  const ui = gateHarness(), run = ui.context[mode === "create" ? "hodlJournalCreate" : "hodlJournalUnlock"];
  const first = run(), second = run();
  try {
    assert.equal(ui.requests.length, 1, "a repeated action started another KDF operation");
    assert.equal(ui.fields.get("journal-create").disabled, true);
    assert.equal(ui.fields.get("journal-unlock").disabled, true);
    assert.equal(ui.fields.get("journal-locked-panel").ariaBusy, "true");
    assert.ok(ui.fields.get("journal-gate-status").textContent);
  } finally {
    ui.requests.forEach((request) => request.resolve(gateResult()));
    await Promise.all([first, second]);
  }
  assert.equal(ui.fields.get("journal-create").disabled, false);
  assert.equal(ui.fields.get("journal-unlock").disabled, false);
  assert.equal(ui.context.document.activeElement, ui.fields.get("journal-notes-tab"));
});

for (const mode of ["create", "open"]) for (const reject of [false, true]) test(`obsolete ${mode} ${reject ? "failure" : "completion"} cannot release a newer request`, async () => {
  const ui = gateHarness(), run = ui.context[mode === "create" ? "hodlJournalCreate" : "hodlJournalUnlock"];
  const old = run();
  ui.context.hodlJournalWipeNotebook();
  ui.context.hodlJournalFileText = "replacement file";
  const current = run(), result = gateResult();
  try {
    assert.equal(ui.requests.length, 2, "a wiped request prevented the new request from starting");
    if (reject) ui.requests[0].reject(new Error("obsolete error"));
    else ui.requests[0].resolve(result);
    await old;
    assert.equal(ui.context.hodlJournalKeys, null);
    assert.equal(ui.context.hodlJournal.notesText, "", "the obsolete operation started a note");
    assert.equal(ui.context.hodlJournal.pages[0].notesText, "");
    assert.equal(ui.context.hodlJournal.pages[0].pendingStamp, undefined);
    assert.equal(ui.stamps.length, 0);
    assert.equal(ui.fields.get("journal-error").textContent, "");
    assert.equal(ui.fields.get("journal-create").disabled, true, "the older request unlocked the newer request's controls");
    assert.equal(ui.fields.get("journal-unlock").disabled, true);
  } finally {
    ui.requests.forEach((request) => request.resolve(gateResult()));
    await Promise.all([old, current]);
  }
  assert.ok(ui.context.hodlJournalKeys);
  assert.equal(ui.fields.get("journal-create").disabled, false);
  assert.equal(ui.stamps.length, mode === "create" ? 1 : 0, "only a successful current creation starts a note");
});

test("Open password Enter uses the same guarded keyboard flow as Create", async () => {
  const ui = gateHarness();
  ui.context.hodlInitJournalNotebook();
  const input = ui.fields.get("journal-open-password"), listener = input.listeners.keydown;
  assert.equal(typeof listener, "function", "Open password has no keyboard submission");
  for (const options of [{ key: "a" }, { key: "Enter", isComposing: true }, { key: "Enter", repeat: true }, { key: "Enter", ctrlKey: true }, { key: "Enter", metaKey: true }, { key: "Enter", altKey: true }]) {
    listener({ ...options, currentTarget: input, preventDefault() { throw new Error("an editing key was intercepted"); } });
    assert.equal(ui.requests.length, 0);
  }
  let prevented = false;
  listener({ key: "Enter", currentTarget: input, preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
  assert.equal(ui.requests.length, 1);
  ui.requests[0].resolve(gateResult());
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(ui.context.document.activeElement, ui.fields.get("journal-notes-tab"));
});

test("a current gate failure releases controls and retains the password for correction", async () => {
  const ui = gateHarness(), pending = ui.context.hodlJournalCreate();
  ui.requests[0].reject(new Error("passwords differ"));
  await pending;
  assert.equal(ui.fields.get("journal-error").textContent, "passwords differ");
  assert.equal(ui.fields.get("journal-create").disabled, false);
  assert.equal(ui.fields.get("journal-create-password").value, "fixture password");
  assert.equal(ui.context.document.activeElement, ui.fields.get("journal-create"));
  assert.equal(ui.context.hodlJournal.notesText, "", "a failed creation must not start a note");
  assert.equal(ui.context.hodlJournal.pages[0].notesText, "");
  assert.equal(ui.context.hodlJournal.pages[0].pendingStamp, undefined);
  assert.equal(ui.stamps.length, 0);
});

test("replacing a file during decryption discards the replaced file's failure", async () => {
  const ui = gateHarness(), pending = ui.context.hodlJournalUnlock();
  ui.context.hodlJournalFileRead = Promise.resolve({ text: "newly selected file" });
  ui.requests[0].reject(new Error("replaced file's password failed"));
  await pending;
  assert.equal(ui.fields.get("journal-error").textContent, "");
  assert.equal(ui.context.hodlJournalKeys, null);
  assert.equal(ui.fields.get("journal-unlock").disabled, false);
  assert.equal(ui.context.document.activeElement, ui.fields.get("journal-unlock"));
});

test("passwordless acknowledgement returns focus to Open without installing the file", async () => {
  const ui = gateHarness(), pending = ui.context.hodlJournalUnlock(), opened = gateResult();
  opened.keys.passwordProtected = false;
  ui.requests[0].resolve(opened);
  await pending;
  assert.equal(ui.context.hodlJournalKeys, null);
  assert.equal(ui.fields.get("journal-open-ready").hidden, false);
  assert.equal(ui.fields.get("journal-error").textContent, "fixture no-password acknowledgement", "finishing the busy state erased the acknowledgement announcement");
  assert.equal(ui.context.document.activeElement, ui.fields.get("journal-unlock"));
});

test("note Activity counts completed timestamp blocks without recording their contents", () => {
  const events = [], context = vm.createContext({ hodlJournalLog: (...args) => events.push(args) });
  vm.runInContext(["hodlJournalStampRanges", "hodlJournalLogNoteChange"].map(loadSlice).join("\n"), context);
  const first = `${FIRST_NOTE_STAMP}  `, second = "2026-10-22 10:11:12  ";
  const secret = `${first}${SECRET_NOTES}\ncontinued private text\n\n${second}${SECRET_PHRASE}`;
  context.hodlJournalLogNoteChange("", first);
  context.hodlJournalLogNoteChange(first, first + " \n\t");
  context.hodlJournalLogNoteChange(first, "2026-10-22 09:08:08  ");
  context.hodlJournalLogNoteChange("", "legacy plain text\nwithout a timestamp");
  assert.deepEqual(events, [], "blank starters, clock ticks, and plain text are not completed notes");

  context.hodlJournalLogNoteChange(first, secret);
  assert.deepEqual(events, [["note-add", "2", "journal"]]);
  context.hodlJournalLogNoteChange(secret, secret + "\nthird line\n\n");
  context.hodlJournalLogNoteChange(secret, secret.replace(SECRET_NOTES, "renamed content"));
  assert.equal(events.length, 1, "continuation lines and body edits are not new notes");
  context.hodlJournalLogNoteChange(secret, `${first}${SECRET_NOTES}\n\n${second}`);
  context.hodlJournalLogNoteChange(`${first}${SECRET_NOTES}`, first);
  context.hodlJournalLogNoteChange(secret, "");
  assert.deepEqual(events, [
    ["note-add", "2", "journal"], ["note-delete", "1", "journal"],
    ["note-delete", "1", "journal"], ["note-delete", "2", "journal"],
  ]);
  assert.ok(events.every(([, detail]) => /^\d+$/.test(detail)), "Activity must retain only the delta count");
});

test("Journal section Activity logs only actual unlocked transitions to known sections", () => {
  const events = [], focused = [], synced = [];
  const context = vm.createContext({
    hodlJournalTool: "notes", unlocked: true,
    hodlJournalUnlocked: () => context.unlocked,
    hodlSyncJournalTool: () => synced.push(context.hodlJournalTool),
    hodlJournalLog: (...args) => events.push(args),
    document: { querySelector: (selector) => ({ focus() { focused.push(selector); } }) },
  });
  vm.runInContext(loadSlice("hodlShowJournalTool"), context);
  context.hodlShowJournalTool("notes");
  context.hodlShowJournalTool("keymanager", true);
  context.hodlShowJournalTool("keymanager");
  context.hodlShowJournalTool("session");
  context.hodlShowJournalTool(SECRET_NOTES);
  assert.deepEqual(events, [
    ["tool-tab", "keymanager", "journal"], ["tool-tab", "session", "journal"],
    ["tool-tab", "notes", "journal"],
  ]);
  assert.deepEqual(focused, ['#journal-tool-tabs [data-journal-tool="keymanager"]']);
  assert.equal(synced.length, 5);
  context.unlocked = false;
  context.hodlShowJournalTool("session", true);
  assert.equal(context.hodlJournalTool, "notes");
  assert.equal(events.length, 3);
  assert.equal(synced.length, 5);
  assert.equal(focused.length, 1);
});

function settingAuditHarness() {
  const listeners = new Map(), journal = createJournal();
  class Input {
    constructor(id, { type = "text", value = "", checked = false, privateReveal = false, tool = "calc", name = "" } = {}) {
      Object.assign(this, { id, type, value, checked, privateReveal, tool, name, dataset: {} });
    }
    hasAttribute(name) { return name === "data-private-reveal" && this.privateReveal; }
    closest(selector) { return this.tool === "calc" && selector.includes("#calc-card") ? this : null; }
  }
  class Select extends Input {}
  class Textarea extends Input {}
  const context = vm.createContext({
    HTMLInputElement: Input, HTMLSelectElement: Select, HTMLTextAreaElement: Textarea,
    hodlJournalActionAuditReady: false, hodlJournalSuppressSettingAudit: false,
    hodlJournal: journal, hodlJournalAppend: appendLog, hodlWorkspace: "calc", hodlJournalTool: "notes",
    dirtyCount: 0,
    hodlJournalMarkDirty: () => context.dirtyCount++,
    hodlScheduleJournalStateRefresh: () => {}, hodlRenderJournalLog: () => {},
    document: { addEventListener: (type, listener) => listeners.set(type, listener) },
  });
  vm.runInContext(app.match(/^var hodlJournalAuditedClicks = \{[^]*?^\};/m)[0], context);
  vm.runInContext(["hodlJournalLog", "hodlJournalAuditedClick", "hodlJournalSettingDetail", "hodlJournalControlTool", "hodlInitJournalActionAudit"].map(loadSlice).join("\n"), context);
  context.hodlInitJournalActionAudit();
  return { context, journal, Input, Select, Textarea,
    change: (control) => listeners.get("change")({ target: control }),
    click: (id) => listeners.get("click")({ target: { id, disabled: false, dataset: {}, closest() { return this; } } }),
  };
}

// Security contract: freeform path edits never enter the log; public setting
// values remain useful, and privacy events retain only state without dirtying.
test("Debug log records derivation-path changes without retaining valid or invalid free text", () => {
  const ui = settingAuditHarness();
  const values = [SECRET_PHRASE, SECRET_NOTES, "m/84'/0'/0'/{0-1}/{0-9}", "", SECRET_STATE];
  for (const value of values) ui.change(new ui.Input("derivation-path", { value }));
  assert.equal(ui.journal.log.length, values.length, "each changed path still needs debug metadata");
  assert.ok(ui.journal.log.every(({ action, detail, tool }) => action === "setting" && detail.includes("derivation-path") && tool === "calc"));
  assert.equal(new Set(ui.journal.log.map(({ detail }) => detail)).size, 1, "path contents affected the debug metadata");
  const recorded = JSON.stringify(ui.journal.log);
  for (const value of values.filter(Boolean)) assert.equal(recorded.includes(value), false, "the log retained path input");
  assert.equal(ui.context.dirtyCount, values.length, "changing a derivation setting is still a content change");
});

test("Debug log keeps public enum, numeric and checkbox settings but omits private text controls", () => {
  const ui = settingAuditHarness();
  ui.change(new ui.Select("script-type", { type: "select-one", value: "p2wpkh" }));
  ui.change(new ui.Input("address-range", { type: "number", value: "10" }));
  ui.change(new ui.Input("account", { value: "7'" }));
  ui.change(new ui.Input("account-harden", { type: "checkbox", checked: true, value: SECRET_PHRASE }));
  ui.change(new ui.Input("account-harden", { type: "checkbox", checked: false, value: SECRET_NOTES }));
  ui.change(new ui.Input("", { type: "radio", name: "dm", checked: false, value: "coleman" }));
  for (const [id, type] of [["phrase", "password"], ["journal-label", "text"], ["journal-search", "search"]])
    ui.change(new ui.Input(id, { type, value: SECRET_PHRASE }));
  ui.change(new ui.Textarea("journal-notes-text", { value: SECRET_NOTES }));
  assert.deepEqual(ui.journal.log.map(({ action, detail }) => [action, detail]), [
    ["setting", "script-type=p2wpkh"], ["setting", "address-range=10"], ["setting", "account=7'"],
    ["setting", "account-harden=on"], ["setting", "account-harden=off"],
  ]);
  assert.equal(ui.context.dirtyCount, 5);
});

test("Debug log records reveal and conceal metadata without marking Journal content changed", () => {
  const ui = settingAuditHarness();
  const ids = ["reveal", "bip85-reveal", "sp-reveal", "ln-reveal", "journal-reveal"];
  for (const id of ids) for (const checked of [true, false])
    ui.change(new ui.Input(id, { type: "checkbox", checked, value: SECRET_PHRASE, privateReveal: true }));
  assert.equal(ui.journal.log.length, ids.length * 2);
  assert.ok(ui.journal.log.every(({ action, detail }) => action === "privacy" && /=(on|off)$/.test(detail)));
  assert.equal(JSON.stringify(ui.journal.log).includes(SECRET_PHRASE), false);
  assert.equal(ui.context.dirtyCount, 0, "revealing or automatically concealing private data changed the save status");
  for (const id of ["journal-state-private", "journal-saved-state-private", "journal-report-reveal"])
    for (const checked of [true, false]) ui.change(new ui.Input(id, { type: "checkbox", checked, privateReveal: true }));
  assert.equal(ui.journal.log.length, ids.length * 2, "independent read-only report reveals entered the content audit");
  assert.equal(ui.context.dirtyCount, 0);
});

test("Debug log capture records copy, download and import requests without claiming completion", () => {
  const ui = settingAuditHarness();
  for (const id of ["bip85-copy", "journal-notes-download", "psbt-upload", "msig-descriptor-import"]) ui.click(id);
  assert.deepEqual(ui.journal.log.map(({ tool, action, detail }) => [tool, action, detail]), [
    ["bip85", "copy-request", "derived-child"], ["journal", "download-request", "notebook"],
    ["psbt", "upload-request", "psbt-file"], ["msig", "import-request", "descriptor"],
  ]);
  assert.equal(ui.context.dirtyCount, 0, "opening a picker or attempting an export changed the save status");
  ui.context.hodlJournalLog("derive", "key-1", "calc");
  assert.equal(ui.journal.log.at(-1).action, "derive", "completed operations were rewritten as requests");
  assert.equal(ui.context.dirtyCount, 1);
});

// Security contract: lifecycle diagnostics retain only operation names,
// public counters and fixed outcomes; cancelled/stale work must not add a
// completion to a replacement Journal or copy raw input/error text to it.
function auditSlice(name) {
  const start = app.search(new RegExp(`^(?:async )?function ${name}\\(`, "m"));
  assert.ok(start >= 0, name);
  return app.slice(start, app.indexOf("\n}", start) + 2);
}

function derivationAuditHarness() {
  const events = [], calls = [], pauses = [];
  class Cancelled extends Error {}
  const context = vm.createContext({
    hodlActiveDerivation: null, hodlJournalGeneration: 0,
    hodlDerivationProgressTimers: {}, HodlDerivationCancelledError: Cancelled,
    document: { getElementById: () => null },
    hodlJournalLog: (...event) => events.push(event),
    hodlResetDerivationProgress: () => {}, hodlSetDerivationButtonState: () => {},
    hodlSyncDeriveButton: () => {}, hodlSyncMsigDeriveButton: () => {},
    hodlKeyManagerSyncDerivationUI: () => {}, hodlSyncPurposeMatchControls: () => {},
    hodlSettleDerivationKeys: () => calls.push("settled"),
    hodlDerivationPause: () => new Promise(resolve => pauses.push(resolve)),
    hodlCreateDerivationTracker: () => ({ complete() { calls.push("complete"); } }),
    setTimeout: () => 1,
  });
  vm.runInContext(["hodlDeriveWithProgress", "hodlStopDerivation"].map(auditSlice).join("\n"), context);
  const resume = async () => { pauses.shift()(); await new Promise(setImmediate); pauses.shift()(); await new Promise(setImmediate); };
  return { context, events, calls, resume };
}

test("Debug derivation starts and stops use the originating tool and preserve cancellation", async () => {
  for (const [kind, button, tool] of [["key", "go", "calc"], ["msig", "msig-go", "msig"], ["key", "journal-keymanager-derive", "journal"]]) {
    const h = derivationAuditHarness();
    let derived = false;
    const pending = h.context.hodlDeriveWithProgress(kind, () => { derived = true; return true; }, button);
    h.context.hodlStopDerivation(kind);
    await h.resume(); await pending;
    assert.equal(derived, false);
    assert.deepEqual(h.events.map(([action, detail, owner]) => [action, detail, owner]), [["derive-start", "", tool], ["derive-cancel", "", tool]]);
    assert.deepEqual(h.calls, ["settled"]);
    assert.equal(h.context.hodlActiveDerivation, null);
  }
});

test("Debug derivation outcomes do not repopulate a replaced Journal", async () => {
  const h = derivationAuditHarness();
  const pending = h.context.hodlDeriveWithProgress("key", () => true, "go");
  h.context.hodlStopDerivation("key");
  h.context.hodlJournalGeneration++;
  h.events.length = 0;
  await h.resume(); await pending;
  assert.deepEqual(h.events, []);
  assert.equal(h.context.hodlActiveDerivation, null);
});

function vanityAuditHarness({ rejected = false } = {}) {
  const events = [], runs = [], fields = new Map(), input = {
    method: "derivation", script: "p2wpkh", sourceId: 1,
    sourceLabel: SECRET_NOTES, sourceFingerprint: "73c5da0a", passphrase: SECRET_PHRASE,
    accountHardened: true, pathPrefix: [], path: [0], node: new Uint8Array([1, 2]),
  };
  const context = vm.createContext({
    hodlJournalGeneration: 0, hodlWorkspace: "vanity", hodlVanityRunning: false,
    hodlVanityGrinder: null, hodlVanityMatches: [], hodlVanityFound: 0,
    hodlVanityDisplayLimit: 100, hodlVanityStopFirst: false, hodlVanityLiveRate: 0,
    document: { getElementById: (id) => fields.get(id) || null },
    hodlJournalLog: (...event) => events.push(event),
    hodlSetVanityError: () => {}, hodlErrorSpecFrom: (error) => ({ raw: error.message }),
    hodlVanityParseInputs: () => { if (rejected) throw new Error(SECRET_STATE); return input; },
    hodlVanitySourceState: () => null, hodlRenderVanityOut: () => {},
    hodlVanitySyncControls: () => {}, hodlVanitySetStatus: () => {},
    hodlNote: () => ({}), hodlVanityEstimate: () => {},
    hodlVanityFormatCount: String, vanityPathString: () => "m/0",
    VanityGrinder: class {
      constructor(callbacks) { this.callbacks = callbacks; runs.push(this); }
      start(value) { this.input = value; }
      stop() { this.stopped = true; }
      cancel() { this.cancelled = true; }
    },
  });
  vm.runInContext(["hodlRunVanity", "hodlVanityStop", "hodlVanityCancel"].map(auditSlice).join("\n"), context);
  return { context, events, runs, input };
}

test("Debug Vanity lifecycle records bounded outcomes without candidate, input or error text", () => {
  const h = vanityAuditHarness();
  h.context.hodlRunVanity();
  h.context.hodlWorkspace = "journal";
  h.runs[0].callbacks.onMatch({ passphrase: SECRET_PHRASE, address: SECRET_STATE });
  h.runs[0].callbacks.onDone({ done: 10n, stopped: false, nextStart: 10n });
  assert.deepEqual(h.events.map(([action, , tool]) => [action, tool]), [["grind-start", "vanity"], ["grind-complete", "vanity"]]);
  assert.ok(h.events.at(-1)[1].includes("10") && h.events.at(-1)[1].includes("1"), "processed and match counts are useful debug metadata");
  assert.deepEqual(Array.from(h.input.node), [0, 0], "logging changed the existing node cleanup");
  const serialized = JSON.stringify(h.events);
  for (const secret of [SECRET_PHRASE, SECRET_NOTES, SECRET_STATE]) assert.ok(!serialized.includes(secret));

  const invalid = vanityAuditHarness({ rejected: true }); invalid.context.hodlRunVanity();
  assert.deepEqual(invalid.events, [["grind-error", "invalid-input", "vanity"]]);
  assert.equal(invalid.runs.length, 0);
  const failed = vanityAuditHarness(); failed.context.hodlRunVanity();
  failed.runs[0].callbacks.onError(SECRET_STATE);
  failed.runs[0].callbacks.onDone({ done: 0n, stopped: true, nextStart: 0n });
  assert.deepEqual(failed.events.at(-1), ["grind-error", "worker", "vanity"]);
  assert.equal(JSON.stringify(failed.events).includes(SECRET_STATE), false);
});

test("Debug Vanity cancellation and stale completion do not invent successful runs", () => {
  const h = vanityAuditHarness(); h.context.hodlRunVanity();
  h.context.hodlVanityStop();
  assert.equal(h.runs[0].stopped, true);
  h.runs[0].callbacks.onDone({ done: 3n, stopped: true, nextStart: 3n });
  assert.equal(h.events.at(-1)?.[0], "grind-cancel");
  const cancelled = vanityAuditHarness(); cancelled.context.hodlRunVanity(); cancelled.context.hodlVanityCancel();
  assert.equal(cancelled.events.at(-1)?.[0], "grind-cancel");
  const stale = vanityAuditHarness(); stale.context.hodlRunVanity();
  stale.context.hodlJournalGeneration++; stale.events.length = 0;
  stale.runs[0].callbacks.onDone({ done: 3n, stopped: false, nextStart: 3n });
  stale.runs[0].callbacks.onError(SECRET_STATE);
  assert.deepEqual(stale.events, []);
});

test("Debug setting and privacy metadata identify Lightning and Vanity tools", () => {
  const ui = settingAuditHarness();
  for (const [id, tool] of [["ln-format", "ln"], ["vanity-script", "vanity"]])
    ui.change(new ui.Select(id, { type: "select-one", value: "public-enum", tool }));
  assert.deepEqual(ui.journal.log.map(({ tool }) => tool), ["ln", "vanity"]);
});

test("Debug import decisions record only fixed choices, preserving existing wallet decisions", async () => {
  const events = [], existing = { name: SECRET_NOTES, accountId: "bip84", result: { root: "same", network: "mainnet" } };
  const context = vm.createContext({
    hodlKeys: [existing], hodlJournalGeneration: 0,
    hodlKeyWalletIdentity: (result) => result?.root,
    hodlKeyResultSetup: (result, script) => ({ network: result.network, script }),
    hodlJournalLog: (...event) => events.push(event),
    hodlKeyManagerResultPaths: () => SECRET_STATE,
    hodlScriptDefinition: () => ({ label: "script" }), hodlTText: value => value,
    hodlResultHasSeed: () => true, hodlResultHasRoot: () => true,
    hodlKeyManagerDecision: async () => "keep", hodlKeyManagerCancelDerivation: () => {},
    HodlDerivationCancelledError: class extends Error {},
  });
  vm.runInContext(auditSlice("hodlKeyManagerDecideCommit"), context);
  const input = { name: SECRET_PHRASE };
  assert.equal((await context.hodlKeyManagerDecideCommit(null, input, { root: "different", network: "mainnet" }, "bip84")).kind, "append");
  assert.equal((await context.hodlKeyManagerDecideCommit(null, input, { root: "same", network: "mainnet" }, "bip84")).kind, "reuse");
  for (const [choice, kind] of [["keep", "skip"], ["append", "append"], [null, "skip"]]) {
    context.hodlKeyManagerDecision = async () => choice;
    assert.equal((await context.hodlKeyManagerDecideCommit(null, input, { root: "same", network: "testnet" }, "bip84")).kind, kind);
  }
  assert.deepEqual(events, ["new-setup", "reuse", "keep", "append", "cancel"].map(choice => ["key-import-decision", choice, "journal"]));
  for (const secret of [SECRET_PHRASE, SECRET_NOTES, SECRET_STATE]) assert.ok(!JSON.stringify(events).includes(secret));
  context.hodlKeyManagerDecision = async () => { context.hodlJournalGeneration++; return null; };
  const previous = events.length;
  await context.hodlKeyManagerDecideCommit(null, input, { root: "same", network: "testnet" }, "bip84");
  assert.equal(events.length, previous, "an obsolete confirmation must not log into the new Journal");
});

const psbtEditor = readFileSync(join(root, "src/js/psbt-editor.js"), "utf8");
function editorAuditHarness() {
  const events = [], listeners = new Map();
  const builder = { value: SECRET_PHRASE, dataset: { buildScript: "0" }, addEventListener(type, callback) { listeners.set(`field-${type}`, callback); } };
  const button = { dataset: { buildApply: "0" }, addEventListener(type, callback) { listeners.set(`button-${type}`, callback); } };
  const context = vm.createContext({
    doc: { tx: { outputs: [{ scriptPubKey: "original" }] } }, pristineTx: null, stale: false, resultBytes: null,
    text: { value: SECRET_PHRASE }, buildFails: false, rebuildFails: false, parseFails: false, addedPairs: new Map(),
    out: {
      querySelector: selector => selector.startsWith("[data-build-script=") ? builder : { value: "auto" },
      querySelectorAll: selector => selector === "[data-build-apply]" ? [button] : selector === "[data-build-script]" ? [builder] : [],
    },
    network: () => "mainnet", journalLog: (...event) => events.push(event),
    buildOutputScript: () => { if (context.buildFails) throw new Error(SECRET_STATE); return { scriptHex: "6a00" }; },
    psbtBytesFromText: () => { if (context.parseFails) throw new Error(SECRET_NOTES); return new Uint8Array([1]); },
    psbtInspectDoc: () => ({ tx: { outputs: [{ scriptPubKey: "loaded" }] } }),
    rebuild: () => { if (context.buildFails || context.rebuildFails) throw new Error(SECRET_STATE); },
    setError: () => {}, clearCompareReport: () => {}, render: () => {}, showBuildError: () => {}, markResultStale: () => {},
  });
  const closure = name => {
    const start = psbtEditor.indexOf(`  const ${name} = (`);
    assert.ok(start >= 0, name);
    return psbtEditor.slice(start, psbtEditor.indexOf("\n  };", start) + 5);
  };
  const begin = psbtEditor.indexOf("    const applyBuiltScript = (index) => {");
  const end = psbtEditor.indexOf("\n    // Flow-diagram", begin);
  vm.runInContext(`${closure("liveRebuild")}\n${closure("loadFromText")}\n${psbtEditor.slice(begin, end)}\nthis.load = loadFromText;`, context);
  return { context, events, listeners };
}

test("PSBT Debug load and Set Script report validation outcomes with keyboard parity and no raw text", () => {
  const h = editorAuditHarness();
  h.context.load();
  h.context.parseFails = true; h.context.load(); h.context.parseFails = false;
  h.context.doc = { tx: { outputs: [{ scriptPubKey: "original" }] } };
  h.listeners.get("button-click")();
  h.listeners.get("field-keydown")({ key: "Enter", preventDefault() {} });
  h.context.buildFails = true; h.listeners.get("button-click")();
  assert.deepEqual(h.events, [
    ["load-request", "editor-text", "psbt"], ["load", "editor-text", "psbt"],
    ["load-request", "editor-text", "psbt"], ["load-error", "editor-text", "psbt"],
    ["editor-set-request", "output-script", "psbt"], ["editor-set", "output-script", "psbt"],
    ["editor-set-request", "output-script", "psbt"], ["editor-set", "output-script", "psbt"],
    ["editor-set-request", "output-script", "psbt"], ["editor-set-error", "output-script", "psbt"],
  ]);
  assert.equal(h.context.doc.tx.outputs[0].scriptPubKey, "6a00", "rejected script must leave the previous script intact");
  for (const secret of [SECRET_PHRASE, SECRET_NOTES, SECRET_STATE]) assert.ok(!JSON.stringify(h.events).includes(secret));
});

test("PSBT Debug distinguishes a built script from a rejected resulting transaction", () => {
  const h = editorAuditHarness();
  h.context.rebuildFails = true;
  h.listeners.get("field-keydown")({ key: "Enter", preventDefault() {} });
  assert.deepEqual(h.events, [["editor-set-request", "output-script", "psbt"], ["editor-set-error", "output-script", "psbt"]]);
  assert.equal(h.context.doc.tx.outputs[0].scriptPubKey, "6a00", "logging must preserve the existing editable draft on rebuild rejection");
  h.events.length = 0; h.context.load();
  assert.deepEqual(h.events, [["load-request", "editor-text", "psbt"], ["load-error", "editor-text", "psbt"]]);
});

test("async Notes import and Journal gate completion retain Journal attribution", async () => {
  let release;
  const events = [], context = vm.createContext({
    hodlJournalGeneration: 0, hodlWorkspace: "journal", hodlJournal: createJournal(), hodlJournalMaxFileLength: 1024,
    hodlJournalLog: (...event) => events.push(event),
    hodlJournalFromPlainText: () => ({ pages: [{ notesText: SECRET_NOTES }] }),
    hodlMergeNotebookImport: (_journal, imported) => ({ ...imported, activePage: 0, nextPageId: 2, nextPageNumber: 2, notesText: SECRET_NOTES }),
    document: { getElementById: () => null }, hodlRenderJournalPageTabs() {}, hodlJournalRestorePage() {}, hodlJournalSetStatus() {}, hodlTText: text => text,
  });
  vm.runInContext(auditSlice("hodlJournalImportFile"), context);
  const pending = context.hodlJournalImportFile({ size: 1, name: "private-filename.txt", text: () => new Promise(resolve => { release = resolve; }) });
  context.hodlWorkspace = "msig"; release(SECRET_NOTES); await pending;
  assert.deepEqual(events, [["notebook-import", "1 page", "journal"]]);
  for (const mode of ["create", "open"]) {
    const gate = gateHarness(), recorded = [];
    gate.context.hodlJournalLog = (...event) => recorded.push(event);
    const opening = gate.context[mode === "create" ? "hodlJournalCreate" : "hodlJournalUnlock"]();
    gate.context.hodlWorkspace = "msig";
    gate.requests[0].resolve(gateResult()); await opening;
    assert.equal(recorded.at(-1)[2], "journal");
  }
});

test("Debug requests, failures and decision metadata do not falsely dirty content", () => {
  const ui = settingAuditHarness();
  for (const action of ["derive-start", "derive-cancel", "derive-error", "key-import-decision", "key-import-summary", "grind-start", "grind-complete", "grind-cancel", "grind-error", "load-request", "load-error", "editor-set-request", "editor-set-error"])
    ui.context.hodlJournalLog(action, "", "journal");
  assert.equal(ui.context.dirtyCount, 0);
});

test("shared copy Debug metadata captures its tool, rejects stale outcomes and never reads labels or payloads", () => {
  const events = [], journal = createJournal();
  const context = vm.createContext({
    hodlJournal: journal, hodlJournalGeneration: 0,
    hodlJournalLog: (...event) => events.push(event),
    hodlJournalControlTool: control => control.tool,
  });
  vm.runInContext(auditSlice("hodlJournalCopyStart"), context);
  const control = { tool: "ln", hasAttribute: name => name === "data-private-copy",
    get textContent() { throw new Error("diagnostics read the secret"); },
    get dataset() { throw new Error("diagnostics read the label"); } };
  const finish = context.hodlJournalCopyStart(control);
  control.tool = "journal"; finish(true);
  assert.deepEqual(events, [["copy-request", "private-readout", "ln"], ["copy", "private-readout", "ln"]]);
  control.hasAttribute = () => false;
  context.hodlJournalCopyStart(control)(false);
  assert.deepEqual(events.slice(-2), [["copy-request", "public-readout", "journal"], ["copy-error", "public-readout", "journal"]]);
  for (const invalidate of [() => context.hodlJournalGeneration++, () => journal.log = []]) {
    const obsolete = context.hodlJournalCopyStart(control);
    invalidate(); events.length = 0; obsolete(true);
    assert.deepEqual(events, []);
  }
});
