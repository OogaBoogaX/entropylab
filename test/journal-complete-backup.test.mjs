// A complete Journal backup must preserve every section as data, restore
// key inputs only as unverified, and refuse drafts or stale save sessions.
// The controllers below are app.js source, exercised over a small DOM stub;
// crypto and payload validation are covered in journal-backup.test.mjs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";
import { JOURNAL_MAX_FILE_LENGTH, JOURNAL_MIN_ITERATIONS, appendLog, createJournal, deriveJournalKeys, normalizeJournalPageStyle, openDocument, parseNotebook, sealBackup, serializeNotebook, snapshotSession, wipeDocument, wipeJournal } from "../src/js/journal.js";
import { keyVaultIdentity, parseKeyVault, serializeKeyVault } from "../src/js/keymanager.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");
const WORDS = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const SNAPSHOT = "ENTROPYLAB SESSION STATE\nPrivate material: INCLUDED\nSaved recovery information";
const EVENTS = [
  { at: "2026-10-22 10:00:00", tool: "journal", action: "page-add", detail: "page-2" },
  { at: "2026-10-22 10:01:00", tool: "calc", action: "derive", detail: "73c5da0a" },
];
const plain = (value) => JSON.parse(JSON.stringify(value));

function loadSlice(name) {
  let start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, `app.js must implement ${name}`);
  if (app.slice(start - 6, start) === "async ") start -= 6;
  let depth = 0, end = -1;
  for (let index = app.indexOf("{", start); index < app.length; index++) {
    if (app[index] === "{") depth++;
    else if (app[index] === "}" && --depth === 0) { end = index + 1; break; }
  }
  assert.ok(end > start, name);
  return app.slice(start, end);
}

function loadFunctions(context, names) {
  for (const name of names) runInNewContext(loadSlice(name), context);
}

// Fixtures are literal content and expected source inputs, not answers
// obtained by collecting and copying a backup made by the implementation.
const notebookFile = () => ({
  format: "entropylab-notebook", version: 1, activePage: 1,
  pages: [
    { number: 1, name: "Preparation", style: { font: "mono", size: "small", spacing: "compact" }, content: [{ type: "text", text: "Keep this first page." }] },
    { number: 2, name: "Recovery", style: { font: "serif", size: "large", spacing: "spacious" }, content: [{ type: "text", text: "Newest unsaved notepad text." }] },
  ],
});
const vaultEntry = (name, pass = "") => ({
  name, mode: "seed", seedMethod: "words", targetWords: 12,
  diceCoinPositions: [0, 3, 7],
  fields: { seed: WORDS, pass, network: "mainnet", derivationPath: "m/84'/0'/0'/0/0" },
});
const vaultFile = () => ({
  format: "entropylab-key-manager", version: 2,
  keys: [vaultEntry("Included key", "TREZOR"), vaultEntry("Excluded key")],
  ignoredKeys: [vaultEntry("Ignored key", "ignored passphrase")],
});
const normalizedBackup = () => ({
  notebook: parseNotebook(JSON.stringify(notebookFile())),
  keyManager: parseKeyVault(JSON.stringify(vaultFile())),
  includedKeys: [0], activeKey: 1,
  snapshot: { text: SNAPSHOT, includePrivate: true },
  log: plain(EVENTS),
});

function sectionHarness() {
  const journal = createJournal();
  const fields = new Map([
    ["journal-notes-text", { value: "Newest unsaved notepad text." }],
    ["journal-state-private", { checked: true }],
    ["journal-state-text", { textContent: SNAPSHOT }],
    ["journal-editor", { hidden: true }],
  ]);
  const context = {
    document: { getElementById: (id) => fields.get(id) ?? null, querySelector: () => null },
    hodlJournal: journal,
    hodlJournalBackupRevision: 0, hodlJournalDirty: false,
    hodlJournalKeys: {}, hodlJournalDoc: { entries: [] },
    hodlKeys: [], hodlKeyManagerPending: [], hodlKeyManagerIgnored: [],
    hodlKeyManagerIds: new Set(), hodlKeyManagerActiveId: "",
    hodlNextKeyId: 100, hodlNextKeyNumber: 100,
    TextEncoder, TextDecoder, ArrayBuffer, Uint8Array,
    keyVaultIdentity, serializeKeyVault, parseKeyVault,
    hodlSerializeNotebook: serializeNotebook, hodlParseNotebook: parseNotebook,
    wipeJournal, hodlJournalWipeDocument: wipeDocument,
    hodlTypedText: (value) => new TextDecoder().decode(value),
    hodlDefaultCoinType: () => 0, hodlNetworkDefault: "mainnet",
    hodlDefaultKeyName: (number) => `Key ${number}`, hodlKeyColor: (id) => String(id),
    hodlJournalRenderVisual() {}, hodlRenderJournalPageTabs() {},
    hodlJournalRestorePage() {}, hodlJournalApplyPageStyle() {},
    hodlKeyManagerRender() {}, hodlRenderJournalLog() {},
    hodlJournalRefreshSessionState() { journal.stateText = SNAPSHOT; return SNAPSHOT; },
    hodlKeyManagerStatus() {}, hodlJournalSetStatus() {},
    hodlJournalNoteText: () => "",
    hodlTText: (text) => text,
  };
  loadFunctions(context, [
    "hodlJournalActivePage", "hodlJournalStoreNotesText", "hodlKeyManagerStates",
    "hodlKeyManagerEntry", "hodlPassphraseText", "hodlStoredPassphraseBytes",
    "hodlNewKeyState", "hodlKeyManagerImportedState",
    "hodlJournalUnlocked", "hodlJournalMarkDirty",
  ]);
  return { context, journal, fields };
}

test("complete collection includes current notes and all managed keys, including excluded and ignored inputs", () => {
  const { context: c, journal } = sectionHarness();
  Object.assign(journal, parseNotebook(JSON.stringify(notebookFile())));
  journal.pages[1].notesText = "Older stored text.";
  journal.notesText = "Older stored text.";
  journal.log = plain(EVENTS);
  const included = { ...vaultEntry("Included key"), id: 1,
    result: { masterIdentity: "trusted-wallet-A", masterFingerprint: "73c5da0a", privateOutput: "never export a cached output" } };
  included.fields.pass = new TextEncoder().encode("TREZOR");
  const excluded = { ...vaultEntry("Excluded key"), id: 2, result: null, needsDerivation: true };
  c.hodlKeys.push(included);
  c.hodlKeyManagerPending.push(excluded);
  c.hodlKeyManagerIgnored.push(vaultEntry("Ignored key", "ignored passphrase"));
  c.hodlKeyManagerIds.add("trusted-wallet-A");
  c.hodlKeyManagerActiveId = "2";
  loadFunctions(c, ["hodlJournalCollectBackup"]);
  const backup = c.hodlJournalCollectBackup();

  assert.deepEqual(JSON.parse(backup.notebook), notebookFile());
  const vault = JSON.parse(backup.keyManager);
  assert.deepEqual(vault.keys.map((key) => key.name), ["Included key", "Excluded key"]);
  assert.deepEqual(vault.ignoredKeys.map((key) => key.name), ["Ignored key"]);
  assert.equal(vault.keys[0].fields.seed, WORDS);
  assert.equal(vault.keys[0].fields.pass, "TREZOR");
  assert.equal(vault.ignoredKeys[0].fields.pass, "ignored passphrase");
  for (const key of [...vault.keys, ...vault.ignoredKeys]) {
    assert.equal(key.result, null);
    assert.equal(key.needsDerivation, true);
    assert.equal(key.reveal, false);
  }
  assert.deepEqual(plain(backup.includedKeys), [0]);
  assert.equal(backup.activeKey, 1);
  assert.deepEqual(plain(backup.snapshot), { text: SNAPSHOT, includePrivate: true });
  assert.deepEqual(plain(backup.log), EVENTS);
  assert.deepEqual([...c.hodlKeyManagerIds], ["trusted-wallet-A"], "collecting must not auto-include excluded keys");
  assert.equal(new TextDecoder().decode(included.fields.pass), "TREZOR", "collection must not wipe the live passphrase");
  journal.log[0].detail = "later event change";
  assert.equal(backup.log[0].detail, "page-2", "the captured log must not change during encryption");
});

test("complete restore reinstalls pages, history, selection and unverified inputs without injecting live wallets", () => {
  const { context: c, journal, fields } = sectionHarness();
  const liveKey = { id: 1, name: "Current live key", result: { masterIdentity: "trusted-wallet-A" } };
  c.hodlKeys.push(liveKey);
  const backup = normalizedBackup();
  loadFunctions(c, ["hodlJournalRestoreBackup"]);
  c.hodlJournalRestoreBackup(backup);

  assert.equal(journal.activePage, 1);
  assert.deepEqual(plain(journal.pages.map(({ name, notesText, style }) => ({ name, notesText, style }))), [
    { name: "Preparation", notesText: "Keep this first page.", style: { font: "mono", size: "small", spacing: "compact" } },
    { name: "Recovery", notesText: "Newest unsaved notepad text.", style: { font: "serif", size: "large", spacing: "spacious" } },
  ]);
  assert.deepEqual(plain(journal.log), EVENTS);
  assert.equal(journal.backup.snapshot.text, SNAPSHOT, "the saved snapshot must survive separately from live refreshes");
  assert.equal(fields.get("journal-state-private").checked, false, "restore must not reveal saved private material automatically");
  assert.equal(c.hodlKeys.length, 1);
  assert.equal(c.hodlKeys[0], liveKey, "restore must not replace an existing trusted wallet");
  assert.deepEqual(plain(c.hodlKeyManagerPending.map((key) => key.name)), ["Included key", "Excluded key"]);
  assert.deepEqual(plain(c.hodlKeyManagerIgnored.map((key) => key.name)), ["Ignored key"]);
  const restored = [...c.hodlKeyManagerPending, ...c.hodlKeyManagerIgnored];
  assert.equal(new Set(restored.map((key) => key.id)).size, 3, "restored inputs need independent runtime IDs");
  for (const key of restored) {
    assert.notEqual(key.id, liveKey.id);
    assert.equal(key.result, null);
    assert.equal(key.needsDerivation, true);
    assert.equal(key.reveal, false);
    assert.equal(key.fields.seed, WORDS);
    assert.deepEqual(plain(key.diceCoinPositions), [0, 3, 7], "wiping staged backup inputs must not wipe restored input arrays");
  }
  assert.equal(new TextDecoder().decode(restored[0].fields.pass), "TREZOR");
  assert.equal(new TextDecoder().decode(restored[2].fields.pass), "ignored passphrase");
  assert.deepEqual([...c.hodlKeyManagerIds], [keyVaultIdentity(restored[0])]);
  assert.equal(c.hodlKeyManagerActiveId, keyVaultIdentity(restored[1]));
});

test("collecting a reopened Journal preserves its historical snapshot even when current private visibility is off", () => {
  const { context: c, journal, fields } = sectionHarness();
  journal.backup = { snapshot: { text: "Historical private snapshot that must survive a second backup.", includePrivate: true } };
  fields.get("journal-state-private").checked = false;
  c.hodlJournalRefreshSessionState = () => { journal.stateText = "Different live session without saved recovery information."; return journal.stateText; };
  loadFunctions(c, ["hodlJournalCollectBackup"]);
  const backup = c.hodlJournalCollectBackup();
  assert.ok(backup.snapshot.text.includes("Historical private snapshot that must survive a second backup."));
  assert.ok(backup.snapshot.text.includes("Different live session without saved recovery information."));
  assert.equal(backup.snapshot.includePrivate, true, "the historical snapshot remains private even while concealed");
  assert.equal(journal.backup.snapshot.text, "Historical private snapshot that must survive a second backup.");
});

test("saved snapshot text is untrusted and appears only while private recovery material is revealed", () => {
  for (const includePrivate of [true, false]) {
    const { context: c, journal, fields } = sectionHarness();
    const savedText = "Saved private snapshot <img src=x onerror=alert(1)> seed marker";
    journal.backup = { snapshot: { text: savedText, includePrivate } };
    Object.assign(c, {
      hodlMsigs: [], hodlBip85Children: [], hodlSpKeys: null,
      hodlPsbtNonceInspected: false, hodlPsbtNonceVerdict: "", hodlPsbtNonceVerdictKind: "",
      hodlPsbtNonceHistory: [], hodlPsbtNonceHistoryVerdict: "",
      hodlJournalStamp: () => "2026-10-22 11:00:00", hodlJournalSnapshot: snapshotSession,
    });
    Object.defineProperty(fields.get("journal-state-text"), "innerHTML", {
      set() { assert.fail("imported snapshot text must never become an HTML sink"); },
    });
    loadFunctions(c, ["hodlJournalRefreshSessionState"]);
    const privacy = fields.get("journal-state-private"), readout = fields.get("journal-state-text");
    privacy.checked = false;
    c.hodlJournalRefreshSessionState();
    assert.ok(!journal.stateText.includes(savedText), `the imported includePrivate=${includePrivate} claim must not bypass concealment`);
    assert.ok(!readout.textContent.includes(savedText));
    privacy.checked = true;
    c.hodlJournalRefreshSessionState();
    assert.ok(journal.stateText.includes(savedText), "the saved snapshot is available after an explicit reveal");
    assert.ok(readout.textContent.includes(savedText), "historical text must be rendered literally");
    privacy.checked = false;
    c.hodlJournalRefreshSessionState();
    assert.ok(!journal.stateText.includes(savedText));
    assert.ok(!readout.textContent.includes(savedText), "concealing drops the rendered private copy");
    assert.equal(journal.backup.snapshot.text, savedText, "concealing must not destroy the backed-up data");
  }
});

test("notes, page settings and log events mark the complete Journal dirty while unchanged values do not", () => {
  const { context: c, journal, fields } = sectionHarness();
  Object.assign(c, {
    hodlNormalizeJournalPageStyle: normalizeJournalPageStyle,
    hodlJournalAppend: appendLog, hodlScheduleJournalStateRefresh() {},
    hodlWorkspace: "journal", hodlJournalTool: "book",
  });
  loadFunctions(c, ["hodlJournalSetPageStyle", "hodlJournalLog"]);
  c.hodlJournalStoreNotesText(fields.get("journal-notes-text"));
  assert.equal(journal.pages[0].notesText, "Newest unsaved notepad text.");
  assert.equal(c.hodlJournalDirty, true);
  let revision = c.hodlJournalBackupRevision;
  c.hodlJournalDirty = false;
  c.hodlJournalStoreNotesText(fields.get("journal-notes-text"));
  assert.equal(c.hodlJournalDirty, false);
  assert.equal(c.hodlJournalBackupRevision, revision, "collecting unchanged notes must not invalidate its own save");

  c.hodlJournalSetPageStyle("font", "serif");
  assert.equal(journal.pages[0].style.font, "serif");
  assert.equal(c.hodlJournalDirty, true);
  assert.ok(c.hodlJournalBackupRevision > revision);
  revision = c.hodlJournalBackupRevision;
  c.hodlJournalDirty = false;
  c.hodlJournalSetPageStyle("font", "serif");
  assert.equal(c.hodlJournalDirty, false);
  assert.equal(c.hodlJournalBackupRevision, revision);

  c.hodlJournalLog("page-add", "page-2", "journal");
  assert.equal(journal.log.at(-1).action, "page-add");
  assert.equal(c.hodlJournalDirty, true);
  assert.ok(c.hodlJournalBackupRevision > revision);
  revision = c.hodlJournalBackupRevision;
  c.hodlJournalDirty = false;
  c.hodlJournalKeys = null;
  c.hodlJournalDoc = null;
  c.hodlJournalMarkDirty();
  assert.equal(c.hodlJournalDirty, false, "a locked Journal cannot acquire unsaved state");
  assert.equal(c.hodlJournalBackupRevision, revision);
});

test("an untouched pending-note clock stays clean after save while typing a note marks it dirty", () => {
  const { context: c, journal, fields } = sectionHarness();
  const field = fields.get("journal-notes-text");
  Object.assign(field, {
    value: "2026-10-22 10:00:00  ",
    dataset: { pendingNote: "Add new note", pendingNoteMode: "line", pendingNoteLine: "0" },
    selectionStart: 21, selectionEnd: 21,
    setSelectionRange(start, end) { this.selectionStart = start; this.selectionEnd = end; },
  });
  journal.notesText = field.value;
  journal.pages[0].notesText = field.value;
  Object.assign(c, {
    hodlJournalDirty: false, hodlJournalBackupRevision: 13,
    hodlJournalStamp: () => "2026-10-22 10:00:01",
    hodlJournalAppend: appendLog, hodlScheduleJournalStateRefresh() {},
    hodlWorkspace: "journal", hodlJournalTool: "notes",
  });
  runInNewContext(app.match(/^var hodlJournalNoteStampPattern = .*;$/m)[0], c);
  loadFunctions(c, [
    "hodlJournalLineStartAt", "hodlJournalLineIndexAt", "hodlJournalPendingLineIndex",
    "hodlJournalPendingLineStart", "hodlJournalRefreshPendingNote", "hodlJournalRenderPendingPrompt",
    "hodlJournalNoteCount", "hodlJournalFinishPendingNote", "hodlJournalResetPendingNote",
    "hodlJournalUpdateNotesText", "hodlJournalLog",
  ]);
  // Register and invoke the actual callback installed at startup, so the
  // timer's suppression argument is exercised rather than restated here.
  let tick;
  c.notesText = field;
  c.setInterval = (callback) => { tick = callback; };
  const timer = loadSlice("hodlInitJournalToolTabs").split("\n").find((line) => line.includes("setInterval(") && line.includes("hodlJournalRefreshPendingNote"));
  assert.ok(timer, "the Journal initializer must install its pending-note timer");
  runInNewContext(timer, c);
  tick();
  assert.equal(field.value, "2026-10-22 10:00:01  ", "the pending clock still refreshes");
  assert.equal(journal.pages[0].notesText, field.value);
  assert.equal(c.hodlJournalDirty, false, "automatic timestamp refresh must not make a completed backup look unsaved");
  assert.equal(c.hodlJournalBackupRevision, 13, "an untouched timestamp must not invalidate an in-flight save");

  field.value += "Checked dice sequence.";
  field.setSelectionRange(field.value.length, field.value.length);
  c.hodlJournalUpdateNotesText(field, { inputType: "insertText" });
  assert.equal(journal.pages[0].notesText, "2026-10-22 10:00:01  Checked dice sequence.");
  assert.equal(c.hodlJournalDirty, true, "a real user edit still needs a fresh backup");
  assert.ok(c.hodlJournalBackupRevision > 13);
});

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function saveHarness({ editorOpen = false, gate = null } = {}) {
  const downloads = [], seals = [], events = [], blobs = new Map();
  const fields = new Map([
    ["journal-editor", { hidden: !editorOpen }],
    ["journal-error", { textContent: "" }],
  ]);
  const captured = {
    notebook: JSON.stringify(notebookFile()), keyManager: JSON.stringify(vaultFile()),
    includedKeys: [0], activeKey: 1, snapshot: { text: SNAPSHOT, includePrivate: true }, log: plain(EVENTS),
  };
  const capturedBefore = plain(captured);
  const seal = async (kind, doc, keys, backup) => {
    seals.push({ kind, doc, keys, backup, backupSnapshot: backup && plain(backup) });
    if (gate) return gate.promise;
    return { ciphertext: "sealed complete journal" };
  };
  const context = {
    document: {
      getElementById: (id) => fields.get(id) ?? null,
      createElement(tag) {
        assert.equal(tag, "a");
        return { href: "", download: "", click() { downloads.push({ filename: this.download, blob: blobs.get(this.href) }); } };
      },
    },
    Blob,
    URL: {
      createObjectURL(blob) { const url = `blob:test-${blobs.size}`; blobs.set(url, blob); return url; },
      revokeObjectURL() {},
    },
    setTimeout() {},
    hodlJournalKeys: { passwordProtected: true },
    hodlJournalDoc: { version: 2, nextId: 2, entries: [{ id: 1, label: "Saved entry", phrase: WORDS }] },
    hodlJournalDirty: true, hodlJournalGeneration: 4, hodlJournalBackupRevision: 7, hodlJournalTool: "book",
    hodlJournalCollectBackup: () => captured,
    hodlJournalWipeDocument: wipeDocument,
    hodlJournalSealBackup: (doc, keys, backup) => seal("complete", doc, keys, backup),
    hodlJournalSealDocument: (doc, keys) => seal("entries-only", doc, keys),
    hodlJournalDownload: (filename, text, type) => downloads.push({ filename, blob: new Blob([text], { type }) }),
    hodlJournalShowWork: () => events.push("show-work"),
    hodlShowJournalTool(tool) { context.hodlJournalTool = tool; events.push(["show-tool", tool]); },
    hodlJournalLog: (...args) => events.push(args),
    hodlTText: (text) => text,
  };
  loadFunctions(context, ["hodlJournalUnlocked", "hodlJournalError", "hodlJournalSaveFile"]);
  return { context, captured, capturedBefore, downloads, seals, events, fields };
}

function assertCollectedPlaintextCleared(backup) {
  assert.equal(backup.notebook, "", "the caller's serialized notepad must be cleared after encryption settles");
  assert.equal(backup.keyManager, "", "the caller's serialized private key inputs must be cleared");
  assert.equal(backup.snapshot.text, "", "the caller's recovery snapshot must be cleared");
  for (const event of backup.log) {
    for (const field of ["at", "tool", "action", "detail"]) assert.equal(event[field], "", `the caller's log ${field} must be cleared`);
  }
}

test("Save file encrypts the complete collected Journal and marks an unchanged capture saved", async () => {
  const { context: c, captured, capturedBefore, downloads, seals } = saveHarness();
  assert.equal(await c.hodlJournalSaveFile(), true);
  assert.equal(seals.length, 1);
  assert.equal(seals[0].kind, "complete", "the old entries-only download omits the other Journal sections");
  assert.deepEqual(seals[0].backupSnapshot, capturedBefore);
  assert.equal(downloads.length, 1);
  assert.deepEqual(JSON.parse(await downloads[0].blob.text()), { ciphertext: "sealed complete journal" });
  assert.equal(c.hodlJournalDirty, false);
  assertCollectedPlaintextCleared(captured);
});

test("Save file refuses an open entry draft rather than downloading an incomplete backup", async () => {
  const { context: c, downloads, seals, fields } = saveHarness({ editorOpen: true });
  assert.equal(await c.hodlJournalSaveFile(), false);
  assert.equal(seals.length, 0, "an unfinished entry must be saved or canceled before encryption starts");
  assert.equal(downloads.length, 0);
  assert.equal(c.hodlJournalDirty, true);
  assert.ok(fields.get("journal-error").textContent.trim(), "explain why the draft prevented a backup");
});

test("canceling the clear confirmation suppresses its pending backup without clearing the Journal", async () => {
  const gate = deferred();
  const { context: c, captured, downloads, fields } = saveHarness({ gate });
  let current = true;
  const doc = c.hodlJournalDoc, keys = c.hodlJournalKeys;
  const saving = c.hodlJournalSaveFile({ isCurrent: () => current });
  current = false;
  gate.resolve({ ciphertext: "canceled backup" });
  await saving;
  assert.equal(downloads.length, 0, "Cancel must stop a pending confirmation download");
  assert.equal(c.hodlJournalDoc, doc);
  assert.equal(c.hodlJournalKeys, keys);
  assert.equal(c.hodlJournalDirty, true);
  assert.equal(fields.get("journal-error").textContent, "");
  assertCollectedPlaintextCleared(captured);
});

test("a save that finishes after Journal clear cannot download or announce success", async () => {
  const gate = deferred();
  const { context: c, captured, downloads, seals, events, fields } = saveHarness({ gate });
  const saving = c.hodlJournalSaveFile();
  assert.equal(seals.length, 1);
  // Clear advances this generation and drops the notebook. Its complete wipe
  // is exercised separately by journal-lifecycle.test.mjs.
  c.hodlJournalGeneration++;
  c.hodlJournalKeys = null;
  c.hodlJournalDoc = null;
  c.hodlJournalDirty = false;
  gate.resolve({ ciphertext: "obsolete encrypted content" });
  await saving;
  assert.equal(downloads.length, 0, "a locked session must not finish its pending download");
  assert.equal(events.length, 0, "the obsolete operation must not redraw or log save success");
  assert.equal(fields.get("journal-error").textContent, "", "a canceled save must not replace the lock announcement with an error");
  assertCollectedPlaintextCleared(captured);
});

test("changes made during encryption keep the current Journal dirty after the older capture downloads", async () => {
  const gate = deferred();
  const { context: c, downloads } = saveHarness({ gate });
  const saving = c.hodlJournalSaveFile();
  c.hodlJournalBackupRevision++;
  c.hodlJournalDirty = true;
  gate.resolve({ ciphertext: "earlier capture" });
  await saving;
  assert.equal(downloads.length, 1, "the completed capture remains a usable backup");
  assert.equal(c.hodlJournalDirty, true, "later edits are not present in the downloaded capture");
});

test("a failed encryption preserves unsaved state and reports an error without downloading", async () => {
  const gate = deferred();
  const { context: c, captured, downloads, fields } = saveHarness({ gate });
  const saving = c.hodlJournalSaveFile();
  gate.reject(new Error("encryption failed"));
  await saving;
  assert.equal(downloads.length, 0);
  assert.equal(c.hodlJournalDirty, true);
  assert.ok(fields.get("journal-error").textContent.trim());
  assertCollectedPlaintextCleared(captured);
});

test("save errors from another Journal station reveal the panel containing the error", async () => {
  for (const editorOpen of [true, false]) {
    const gate = deferred();
    const { context: c, downloads, fields } = saveHarness({ editorOpen, gate });
    c.hodlJournalTool = "notes";
    const saving = c.hodlJournalSaveFile();
    if (!editorOpen) gate.reject(new Error("backup exceeds file size limit"));
    await saving;
    assert.ok(fields.get("journal-error").textContent.trim());
    assert.equal(c.hodlJournalTool, "book", "draft and encryption errors must not stay in a hidden panel");
    assert.equal(downloads.length, 0);
  }
});

function unlockHarness({ password = "backup password", onOpen = openDocument } = {}) {
  const env = sectionHarness(), c = env.context;
  env.fields.set("journal-open-password", { value: password });
  env.fields.set("journal-file", { value: "chosen-backup.json" });
  env.fields.set("journal-error", { textContent: "" });
  env.fields.set("journal-open-ready", {
    hidden: true,
    querySelector: () => ({ textContent: "Passwordless acknowledgement" }),
  });
  Object.assign(c, {
    hodlJournalKeys: null, hodlJournalDoc: null, hodlJournalGeneration: 0,
    hodlJournalUnlockBusy: false, hodlJournalFileRead: null,
    hodlJournalFileText: "", hodlJournalOpenReadyFor: "",
    hodlJournalKeyEntries: new Map(), hodlJournalTool: "book", hodlWorkspace: "journal",
    hodlJournalMaxFileLength: JOURNAL_MAX_FILE_LENGTH,
    hodlJournalOpenDocument: onOpen, hodlJournalAppend: appendLog,
    hodlScheduleJournalStateRefresh() {},
    hodlKeyManagerReset() {
      c.hodlKeyManagerPending = [];
      c.hodlKeyManagerIgnored = [];
      c.hodlKeyManagerIds.clear();
      c.hodlKeyManagerActiveId = "";
    },
    hodlJournalBackfillDerivedKeys() {},
    hodlJournalHideEditor() {}, hodlJournalShowWork() {}, hodlShowJournalTool() {},
  });
  loadFunctions(c, [
    "hodlJournalError", "hodlJournalWipeNotebook", "hodlJournalDiscardOpened",
    "hodlJournalChooseFile", "hodlJournalUnlock", "hodlJournalRestoreBackup", "hodlJournalLog",
  ]);
  return env;
}

const completeFiles = new Map();
function completeFile(password) {
  if (!completeFiles.has(password)) completeFiles.set(password, (async () => {
    const keys = await deriveJournalKeys(password, JOURNAL_MIN_ITERATIONS);
    const doc = { version: 2, nextId: 2, entries: [{
      id: 1, method: "seed", input: WORDS, phrase: WORDS, label: "Saved entry",
      created: "2026-10-22T10:00:00.000Z", notes: "Entry notes", walletId: null,
    }] };
    return JSON.stringify(await sealBackup(doc, keys, {
      notebook: JSON.stringify(notebookFile()), keyManager: JSON.stringify(vaultFile()),
      includedKeys: [0], activeKey: 1, snapshot: { text: SNAPSHOT, includePrivate: true }, log: plain(EVENTS),
    }));
  })());
  return completeFiles.get(password);
}

test("opening a protected complete file restores its Journal sections through the real decrypt and controller", async () => {
  const { context: c, journal, fields } = unlockHarness();
  c.hodlJournalFileText = await completeFile("backup password");
  await c.hodlJournalUnlock();
  assert.equal(fields.get("journal-error").textContent, "");
  assert.equal(c.hodlJournalDoc.entries[0].phrase, WORDS);
  assert.equal(journal.pages[1].notesText, "Newest unsaved notepad text.");
  assert.deepEqual(plain(journal.log.slice(0, 2)), EVENTS);
  assert.equal(journal.backup.snapshot.text, SNAPSHOT);
  assert.equal(c.hodlKeyManagerPending.length, 2);
  assert.equal(c.hodlKeyManagerIgnored.length, 1);
  assert.ok(c.hodlKeyManagerPending.every((key) => key.needsDerivation && key.result === null));
  assert.equal(c.hodlKeys.length, 0);
  assert.equal(fields.get("journal-state-private").checked, false);
});

test("a passwordless complete file installs no sections until the file is explicitly acknowledged", async () => {
  const opened = [];
  const { context: c, journal, fields } = unlockHarness({
    password: "",
    onOpen: async (file, password) => {
      const result = await openDocument(file, password);
      opened.push(result);
      return result;
    },
  });
  c.hodlJournalFileText = await completeFile("");
  await c.hodlJournalUnlock();
  assert.equal(c.hodlJournalDoc, null);
  assert.equal(c.hodlJournalKeys, null);
  assert.equal(c.hodlKeyManagerPending.length, 0);
  assert.equal(journal.pages[0].notesText, "");
  assert.equal(fields.get("journal-open-ready").hidden, false);
  assert.equal(opened[0].doc.entries.length, 0, "the first decrypt is wiped after acknowledgement is offered");
  assert.equal(opened[0].doc.backup, null);
  await c.hodlJournalUnlock();
  assert.equal(c.hodlJournalDoc.entries[0].phrase, WORDS);
  assert.equal(journal.pages[1].notesText, "Newest unsaved notepad text.");
  assert.equal(c.hodlKeyManagerPending.length, 2);
  assert.equal(fields.get("journal-open-ready").hidden, true);
});

test("choosing a different file while decryption is pending discards the obsolete complete backup", async () => {
  const gate = deferred();
  const staged = { keys: { passwordProtected: true }, doc: { entries: [{ input: WORDS, phrase: WORDS, label: "obsolete", notes: "" }], backup: normalizedBackup() } };
  const { context: c, journal, fields } = unlockHarness({ onOpen: () => gate.promise });
  c.hodlJournalFileText = "old file bytes";
  const opening = c.hodlJournalUnlock();
  c.hodlJournalChooseFile({ size: 14, text: async () => "new file bytes" });
  await c.hodlJournalFileRead;
  gate.resolve(staged);
  await opening;
  assert.equal(c.hodlJournalDoc, null, "the old file must not install over the newer choice");
  assert.equal(c.hodlJournalKeys, null);
  assert.equal(c.hodlKeyManagerPending.length, 0);
  assert.equal(journal.pages[0].notesText, "");
  assert.equal(staged.doc.entries.length, 0, "the discarded decrypt must clear its entries");
  assert.equal(staged.doc.backup, null, "the discarded decrypt must clear every staged Journal section");
  assert.equal(c.hodlJournalFileText, "new file bytes");
  assert.equal(fields.get("journal-error").textContent, "");
});

test("a complete decrypt that outlives its Journal generation wipes the staged backup without restoring", async () => {
  const gate = deferred();
  const staged = { keys: { passwordProtected: true }, doc: { entries: [{ input: WORDS, phrase: WORDS, label: "obsolete", notes: "" }], backup: normalizedBackup() } };
  const { context: c, journal } = unlockHarness({ onOpen: () => gate.promise });
  c.hodlJournalFileText = "complete backup bytes";
  const opening = c.hodlJournalUnlock();
  c.hodlJournalWipeNotebook();
  gate.resolve(staged);
  await opening;
  assert.equal(c.hodlJournalDoc, null);
  assert.equal(c.hodlJournalKeys, null);
  assert.equal(c.hodlKeyManagerPending.length, 0);
  assert.equal(journal.pages[0].notesText, "");
  assert.equal(staged.doc.entries.length, 0);
  assert.equal(staged.doc.backup, null);
});
