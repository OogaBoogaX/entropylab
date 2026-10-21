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
import { addEntry, appendLog, createJournal, emptyDocument, formatStamp, journalNotebookRuns, wipeDocument, wipeJournal } from "../src/js/journal.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");
const shell = readFileSync(join(root, "src/shell.html"), "utf8");

// Distinct markers, so one leftover copy can be told apart from another.
const SECRET_PHRASE = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const SECRET_NOTES = "the safe combination is 42-17-99";
const SECRET_STATE = "xprv9s21ZrQH143K-session-snapshot";

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

// The real Lock, Clear and editor-close paths, with the pending-note chain
// that re-renders the notepad's mirror, over a stub DOM whose elements start
// full of marker text. The journal store and document wipes come from the
// real journal.js; the Key Manager reset and the tab renderers are spies (the
// reset's own byte wiping is pinned in test/secret-clear.test.mjs).
const LIFECYCLE_SLICES = [
  "hodlJournalActivePage", "hodlJournalStoreNotesText", "hodlJournalRenderVisual",
  "hodlJournalSyncPendingPrompt", "hodlJournalSyncCopyButton", "hodlJournalRenderPendingPrompt",
  "hodlJournalRefreshPendingNote", "hodlJournalResetPendingNote", "hodlJournalPendingLineIndex",
  "hodlJournalPendingLineStart", "hodlJournalLineStartAt", "hodlJournalWipeNotebook",
  "hodlJournalClearFields", "hodlJournalHideEditor", "hodlJournalLog", "hodlJournalLock", "hodlJournalWipeMem",
];

function journalLifecycleHarness() {
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
  for (const id of ["journal-create-password", "journal-create-confirm", "journal-open-password", "journal-input", "journal-phrase", "journal-label", "journal-entry-notes", "journal-search"])
    add(id, field(SECRET_PHRASE));
  add("journal-file", { value: "entropylab-journal.json" });
  add("journal-list", { innerHTML: `<button>${SECRET_PHRASE}</button>`, hidden: false });
  add("journal-view", { innerHTML: `<span>${SECRET_PHRASE}</span>`, hidden: false, contains: () => false });
  add("journal-editor", { hidden: false, contains: () => false });
  add("journal-error", { textContent: "old error" });
  add("journal-method", { value: "seed" });
  add("journal-state-text", { textContent: SECRET_STATE });
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
  add("journal-add", { focused: false, focus() { this.focused = true; } });
  add("journal-open-ready", { hidden: true });
  // The wipe asks the work panel whether the active element sits inside it,
  // so the stub tracks its descendants.
  add("journal-work-panel", { hidden: false, descendants: new Set(), contains(element) { return this.descendants.has(element); } });
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
    varLine("hodlJournalOpenReadyFor"), varLine("hodlJournalTool"), varLine("hodlJournalEncryptDownloads"),
    ...LIFECYCLE_SLICES.map(loadSlice),
  ].join("\n");
  const api = new Function(
    "document", "hodlJournal", "wipeJournal", "hodlJournalWipeDocument", "hodlJournalAppend",
    "hodlJournalStamp", "hodlJournalNotebookRuns", "hodlTText", "hodlWorkspace", "hodlKeyManagerReset",
    "hodlJournalSetGate", "hodlJournalShowWork", "hodlSyncJournalTool", "hodlRenderJournalPageTabs",
    "hodlJournalApplyPageStyle", "hodlJournalSetStatus", "hodlJournalSyncEncryptDownloads",
    "hodlScheduleJournalStateRefresh", "hodlRenderJournalLog", "hodlJournalFillWallets", "hodlFillKeyTabLifehash",
    `${source}; return {
      lock: hodlJournalLock,
      wipeMem: hodlJournalWipeMem,
      hideEditor: hodlJournalHideEditor,
      openNotebook: (keys, doc) => { hodlJournalKeys = keys; hodlJournalDoc = doc; },
      notebook: () => ({ keys: hodlJournalKeys, doc: hodlJournalDoc, reveal: hodlJournalReveal, fileText: hodlJournalFileText, openReadyFor: hodlJournalOpenReadyFor }),
    };`,
  )(
    documentStub, journal, wipeJournal, wipeDocument, appendLog,
    formatStamp, journalNotebookRuns, (text) => text, "calc", () => calls.push("key-manager-reset"),
    () => {}, () => {}, () => {}, () => {},
    () => {}, () => {}, () => calls.push("sync-encrypt-downloads"),
    () => {}, () => {}, () => {}, () => {},
  );
  return { api, elements, journal, doc, entry, calls, documentStub };
}

// The assertions Lock and the global Clear share: every store the plan names —
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
  // The password fields and the entry editor's fields.
  for (const id of ["journal-create-password", "journal-create-confirm", "journal-open-password", "journal-input", "journal-phrase", "journal-label", "journal-entry-notes", "journal-search"])
    assert.equal(elements.get(id).value, "", `#${id} kept its text`);
  assert.equal(elements.get("journal-file").value, "", "the file picker kept its choice");
  // Rendered copies: the entry list, the entry view, the error line.
  assert.equal(elements.get("journal-list").innerHTML, "", "the entry list kept its rows");
  assert.equal(elements.get("journal-view").innerHTML, "", "a revealed entry stayed on screen");
  assert.equal(elements.get("journal-error").textContent, "", "the error line kept its message");
  // The session snapshot, on screen and in memory.
  assert.equal(elements.get("journal-state-text").textContent, "", "the session snapshot stayed on screen");
  assert.equal(elements.get("journal-state-private").checked, false, "the private box stayed ticked");
  assert.equal(journal.stateText, "", "the snapshot's in-memory text survived");
  // The notepad: the field, its rendered mirror, and the in-memory pages.
  // After the wipe the field holds only a fresh pending-note stamp, never the
  // old text, so these assert the marker is gone rather than exact content.
  assert.ok(!elements.get("journal-notes-text").value.includes(SECRET_NOTES), "the notepad kept its text");
  assert.ok(!elements.get("journal-notes-render").children.map((node) => node.text).join("").includes(SECRET_NOTES), "the notepad's rendered mirror kept its text");
  assert.equal(journal.pages.length, 1, "extra notepad pages survived");
  assert.ok(!journal.pages[0].notesText.includes(SECRET_NOTES) && !journal.notesText.includes(SECRET_NOTES), "the notepad's in-memory text survived");
  // The Key Manager's rows go with the journal.
  assert.deepEqual(calls.filter((call) => call === "key-manager-reset"), ["key-manager-reset"], "the Key Manager was not reset");
}

test("journal Lock leaves no journal plaintext behind (plan W3)", () => {
  // Executable: the real hodlJournalLock over the stub DOM. Proves every
  // store above is emptied by Lock itself; cannot prove what the browser
  // retains outside the page (the wipe is best-effort by design).
  const harness = journalLifecycleHarness();
  harness.api.openNotebook({ passwordProtected: true }, harness.doc);
  harness.api.lock();
  assertNoJournalPlaintext(harness);
  // The session log, on screen and in memory: only Lock's own event remains.
  assert.equal(harness.elements.get("journal-log-out").textContent, "No events yet.", "the session log stayed on screen");
  assert.deepEqual(harness.journal.log.map((event) => event.action), ["journal-lock"], "earlier log events survived in memory");
  // Lock announces through the live region and parks focus on the locked
  // panel's primary action, not <body> (plan W5).
  assert.ok(harness.elements.get("journal-status-note").textContent.startsWith("Journal locked"), "Lock did not announce through #journal-status-note");
  // The status note is hidden with the work panel, so the audible copy goes
  // to the gate panel's live region, which stays visible (plan W5).
  assert.ok(harness.elements.get("journal-gate-status").textContent.startsWith("Journal locked"), "Lock did not announce through the gate's live region");
  assert.equal(harness.elements.get("journal-create").focused, true, "Lock left focus to fall back to <body>");
});

test("the global Clear leaves no journal plaintext behind (plan W3)", () => {
  // Executable: the real hodlJournalWipeMem, which is also what End Session
  // and pagehide reach through clearSecretFields (wired in the next test).
  const harness = journalLifecycleHarness();
  harness.api.openNotebook({ passwordProtected: true }, harness.doc);
  harness.api.wipeMem();
  assertNoJournalPlaintext(harness);
  assert.equal(harness.elements.get("journal-log-out").textContent, "No events yet.", "the session log stayed on screen");
  assert.deepEqual(harness.journal.log, [], "log events survived in memory");
  assert.ok(harness.calls.includes("sync-encrypt-downloads"), "the download-encryption default was not restored");
  // Clear announces through the same live region as Lock (plan W5), but must
  // not move focus: it also runs on pagehide, where focusing is meaningless.
  assert.ok(harness.elements.get("journal-status-note").textContent.startsWith("Journal cleared"), "Clear did not announce through #journal-status-note");
  assert.ok(harness.elements.get("journal-gate-status").textContent.startsWith("Journal cleared"), "Clear did not announce through the gate's live region");
  // Focus that was not inside the work panel is left alone.
  assert.equal(harness.elements.get("journal-create").focused, false, "Clear moved focus");
});

test("the Clear button, End Session and pagehide all reach the journal wipe (plan W3)", () => {
  // Source-level: proves the wiring exists in the shipped source, not that a
  // browser fires the events (the browser suite's job) — what the wipe does
  // once reached is proven executable above. End Session dispatches a
  // pagehide (pinned in test/end-session.test.mjs), so all three land in
  // clearSecretFields.
  assert.match(app, /getElementById\("journal-global-clear"\)\?\.addEventListener\("click", hodlJournalWipeMem\)/);
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
  assert.match(app, /getElementById\("journal-state-private"\)\?\.addEventListener\("change", \(\) => hodlJournalRefreshSessionState\(\)\)/);
  const refresh = loadSlice("hodlJournalRefreshSessionState");
  assert.match(refresh, /includePrivate = Boolean\(document\.getElementById\("journal-state-private"\)\?\.checked\)/);
  assert.match(refresh, /field\.textContent = text/, "the snapshot must render as text, never markup");
});

test("auto-capture is a no-op while the journal is locked (plan W3)", () => {
  // Executable: the real hodlJournalSyncDerivedKeys/hodlJournalCaptureDerivedKey
  // with every collaborator a recording stub. If the locked guard is removed,
  // the capture reaches the stubs and the calls array fills — so the test
  // fails even though the returned counts would still be zero.
  const calls = [];
  const source = [loadSlice("hodlJournalSyncDerivedKeys"), loadSlice("hodlJournalCaptureDerivedKey")].join("\n");
  const api = new Function(
    "hodlJournalUnlocked", "hodlJournalKeySnapshot", "hodlResultMnemonic", "hodlJournalSyncKeySnapshots",
    "hodlJournalError", "hodlJournalLog", "hodlJournalShowWork", "hodlTText",
    `${source}; return { sync: hodlJournalSyncDerivedKeys, capture: hodlJournalCaptureDerivedKey };`,
  )(
    () => false,
    () => { calls.push("snapshot"); },
    () => { calls.push("mnemonic"); },
    () => { calls.push("sync-snapshots"); },
    () => { calls.push("error"); },
    () => { calls.push("log"); },
    () => { calls.push("show-work"); },
    (text) => text,
  );
  const state = { isLab: false, name: "Key 1", result: { masterFingerprint: "deadbeef" } };
  assert.deepEqual(api.sync([state]), { added: 0, updated: 0, matched: 0 });
  api.capture(state);
  assert.deepEqual(calls, [], "a locked journal read, recorded or reported a derived key");
  // The guard is the function's first statement, before any document access.
  assert.match(loadSlice("hodlJournalSyncDerivedKeys"), /\{\s*if \(!hodlJournalUnlocked\(\)\) return \{ added: 0, updated: 0, matched: 0 \};/);
});

test("the journal intro discloses auto-capture and passwordless readability (plan W4)", () => {
  // Owner-approved disclosure copy, pinned by its stable substrings only
  // (AGENTS.md: safety-critical wording may be pinned by a short stable
  // substring; the rest of the sentence stays free to reword).
  const intro = shell.slice(shell.indexOf('id="journal-tool-intro"'), shell.indexOf('id="journal-manager"'));
  assert.ok(intro.includes("while the journal is unlocked"), "the intro must say derived keys are captured while the journal is unlocked");
  assert.ok(intro.includes("anyone with the file can open it"), "the intro must say a passwordless journal is readable by anyone with the file");
  assert.ok(intro.includes("encrypted with your password"), "the intro must say the journal file is encrypted with the password");
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
  // Wrong password, corrupt file, wrong kind of file: one catch, one region.
  assert.match(unlock, /catch \(exception\) \{\s*hodlJournalError\(exception\.message \|\| String\(exception\)\)/);
  // Too large is refused before the file is read.
  assert.match(loadSlice("hodlJournalChooseFile"), /hodlJournalError\(hodlTText\("That journal file is too large/);
  // A passwordless file's first press arms the acknowledgement and announces
  // why nothing was installed yet (audit L6).
  const armStart = unlock.indexOf("if (!opened.keys.passwordProtected");
  const armEnd = unlock.indexOf("hodlJournalDiscardOpened(opened);", armStart);
  assert.ok(armEnd > armStart, "the passwordless acknowledgement arm is gone");
  assert.match(unlock.slice(armStart, armEnd), /hodlJournalError\(/, "the passwordless first press must announce through #journal-error");
});

test("Lock and Clear announce through the #journal-status-note live region (plan W5)", () => {
  // Source-level: the region is polite (also pinned in
  // test/journal-view-safety.test.mjs) and both teardowns write to it. The
  // executable half of this contract is in the two lifecycle tests above.
  const tag = /<p\b[^>]*\bid="journal-status-note"[^>]*>/.exec(shell)?.[0] || "";
  assert.ok(/\brole="status"/.test(tag), "#journal-status-note must be a live region");
  assert.match(loadSlice("hodlJournalLock"), /getElementById\("journal-status-note"\)\.textContent = hodlTText\("Journal locked/);
  assert.match(loadSlice("hodlJournalWipeMem"), /getElementById\("journal-status-note"\)[\s\S]*?hodlTText\("Journal cleared/);
});

test("closing the editor or locking moves focus to a control, not <body> (plan W5)", () => {
  assert.match(loadSlice("hodlJournalLock"), /getElementById\("journal-create"\)\?\.focus\(\)/);
  const hide = loadSlice("hodlJournalHideEditor");
  assert.match(hide, /document\.activeElement/);
  assert.match(hide, /getElementById\("journal-add"\)\?\.focus\(\)/);
  // Executable: focus inside the closing view moves to Add entry; focus
  // anywhere else is left alone. (Lock's own focus target is asserted in the
  // Lock lifecycle test above.)
  const harness = journalLifecycleHarness();
  const child = {};
  harness.elements.get("journal-view").contains = (element) => element === child;
  harness.documentStub.activeElement = child;
  harness.api.hideEditor();
  assert.equal(harness.elements.get("journal-add").focused, true, "closing the view left focus to fall back to <body>");
  const again = journalLifecycleHarness();
  again.api.hideEditor();
  assert.equal(again.elements.get("journal-add").focused, false, "closing the editor stole focus it did not own");
});

test("the global Clear rescues focus stranded inside the hidden work panel (plan W5)", () => {
  // Executable: focus starts inside the editor. hideEditor hands it to
  // #journal-add, which the Clear then hides with the work panel, so the wipe
  // must park it on the gate's primary action — never leave it on a hidden
  // control, and never let it fall to <body>.
  const harness = journalLifecycleHarness();
  harness.api.openNotebook({ passwordProtected: true }, harness.doc);
  const child = {};
  harness.elements.get("journal-editor").contains = (element) => element === child;
  harness.elements.get("journal-work-panel").descendants.add(child);
  harness.documentStub.activeElement = child;
  harness.api.wipeMem();
  assert.equal(harness.elements.get("journal-create").focused, true, "Clear left focus on a control hidden with the work panel");
});

test("the Lock/Clear announcement also lands in a live region outside the hidden work panel (plan W5)", () => {
  // #journal-status-note is inside #journal-work-panel, which Lock and Clear
  // hide, so a write to it is outside the accessibility tree and announces
  // nothing. The audible copy goes to #journal-gate-status, a polite live
  // region inside #journal-locked-panel — the panel both actions leave
  // visible (hodlJournalShowWork unhides it while locked).
  const tag = /<p\b[^>]*\bid="journal-gate-status"[^>]*>/.exec(shell)?.[0] || "";
  assert.ok(/\brole="status"/.test(tag) || /\baria-live=/.test(tag), "#journal-gate-status must be a live region");
  const lockedPanel = shell.slice(shell.indexOf('id="journal-locked-panel"'), shell.indexOf('id="journal-work-panel"'));
  assert.ok(lockedPanel.includes('id="journal-gate-status"'), "the announcement region must live in the panel that stays visible");
  const workPanel = shell.slice(shell.indexOf('id="journal-work-panel"'), shell.indexOf('id="journal-error"'));
  assert.ok(!workPanel.includes('id="journal-gate-status"'), "the announcement region must not sit inside the hidden work panel");
  assert.match(loadSlice("hodlJournalShowWork"), /locked\.hidden = unlocked/, "the locked panel is the one shown while locked");
  assert.match(loadSlice("hodlJournalLock"), /getElementById\("journal-gate-status"\)/);
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
