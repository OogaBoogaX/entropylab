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
import { JOURNAL_MAX_FILE_LENGTH, JOURNAL_MIN_ITERATIONS, appendLog, mergeLogHistory, combineSnapshots, createJournal, deriveJournalKeys, normalizeJournalPageStyle, openDocument, parseNotebook, sealBackup, serializeNotebook, snapshotPrivateSpans, snapshotSession, wipeDocument, wipeJournal } from "../src/js/journal.js";
import { KEY_VAULT_MAX_KEYS, keyVaultIdentity, parseKeyVault, serializeKeyVault } from "../src/js/keymanager.js";
import { renderAnnotatedPrivateText } from "../src/js/private-data.js";

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
    ["journal-saved-state-private", { checked: false }],
    ["journal-saved-state-text", { textContent: "" }],
    ["journal-state-text", { textContent: SNAPSHOT }],
    ["journal-editor", { hidden: true }],
  ]);
  for (const id of ["journal-state-text", "journal-saved-state-text"]) {
    fields.get(id).toggleAttribute = () => {};
  }
  const context = {
    document: { getElementById: (id) => fields.get(id) ?? null, querySelector: () => null },
    hodlJournal: journal,
    hodlJournalBackupRevision: 0, hodlJournalDirty: false,
    hodlJournalKeys: {}, hodlJournalDoc: { entries: [] },
    hodlWorkspace: "calc", hodlActiveDerivation: null, hodlJournalKeyDerivation: null,
    // No key holds Secure entry words here; secure-entry-wiring.test.mjs covers the refusal.
    hodlSecureEntryBackupRefusal: () => null,
    hodlMsigs: [], hodlBip85Children: [], hodlSpKeys: null, hodlCaptureKey() {},
    hodlJournalFinishNoteDrag() {}, hodlJournalMergeLogHistory: mergeLogHistory, hodlJournalCombineSnapshots: combineSnapshots,
    hodlKeys: [], hodlKeyManagerPending: [], hodlKeyManagerIgnored: [],
    hodlKeyManagerIds: new Set(), hodlKeyManagerActiveId: "",
    hodlNextKeyId: 100, hodlNextKeyNumber: 100,
    TextEncoder, TextDecoder, ArrayBuffer, Uint8Array,
    keyVaultIdentity, serializeKeyVault, parseKeyVault, hodlKeyVaultMaxKeys: KEY_VAULT_MAX_KEYS,
    hodlSerializeNotebook: serializeNotebook, hodlParseNotebook: parseNotebook,
    wipeJournal, hodlJournalWipeDocument: wipeDocument,
    hodlTypedText: (value) => new TextDecoder().decode(value),
    hodlDefaultCoinType: () => 0, hodlNetworkDefault: "mainnet", hodlNetworkChoice: "mainnet",
    hodlDefaultKeyName: (number) => `Key ${number}`, hodlKeyColor: (id) => String(id),
    hodlJournalRenderVisual() {}, hodlRenderJournalPageTabs() {},
    hodlJournalRestorePage() {}, hodlJournalApplyPageStyle() {},
    hodlKeyManagerRender() {}, hodlRenderJournalLog() {},
    hodlJournalSessionSnapshot() { return SNAPSHOT; },
    hodlRenderAnnotatedPrivateText: renderAnnotatedPrivateText,
    hodlJournalSnapshotPrivateSpans: snapshotPrivateSpans,
    hodlKeyManagerStatus() {}, hodlJournalSetStatus() {},
    hodlJournalNoteText: () => "",
    hodlTText: (text) => text,
  };
  loadFunctions(context, [
    "hodlJournalActivePage", "hodlJournalStoreNotesText", "hodlKeyManagerStates",
    "hodlKeyManagerEntry", "hodlKeyManagerArchiveEntry", "hodlKeyManagerHasInputs", "hodlKeyManagerCapacityError", "hodlPassphraseText", "hodlStoredPassphraseBytes",
    "hodlNewKeyState", "hodlKeyManagerImportedState",
    "hodlJournalUnlocked", "hodlJournalMarkDirty", "hodlNetworkFamily",
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
  c.hodlKeyManagerIds.add(keyVaultIdentity(included));
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
  assert.deepEqual([...c.hodlKeyManagerIds], [keyVaultIdentity(included)], "collecting must not auto-include excluded keys");
  assert.equal(new TextDecoder().decode(included.fields.pass), "TREZOR", "collection must not wipe the live passphrase");
  journal.log[0].detail = "later event change";
  assert.equal(backup.log[0].detail, "page-2", "the captured log must not change during encryption");
});

test("complete backup retains distinct setups of one wallet with their selection across cold restore", async () => {
  const { context: c } = sectionHarness();
  const mainnet = { ...vaultEntry("Mainnet setup"), id: 11, result: { masterIdentity: "same-wallet", network: "mainnet" } };
  const testnet = { ...vaultEntry("Testnet setup"), id: 12, result: { masterIdentity: "same-wallet", network: "testnet" } };
  testnet.fields.network = "testnet";
  testnet.fields.derivationPath = "m/84'/1'/0'/0/0";
  c.hodlKeys.push(mainnet, testnet);
  c.hodlKeyManagerPending.push(mainnet);
  c.hodlKeyManagerActiveId = keyVaultIdentity(testnet);
  c.hodlKeyManagerIds.add(keyVaultIdentity(testnet));
  loadFunctions(c, ["hodlJournalCollectBackup"]);
  const backup = c.hodlJournalCollectBackup();
  const vault = parseKeyVault(backup.keyManager);
  assert.equal(vault.keys.length, 2, "collection omitted an alternate wallet setup or repeated the same entry");
  assert.deepEqual(vault.keys.map((key) => [key.name, key.fields.network, key.fields.derivationPath]), [
    ["Mainnet setup", "mainnet", "m/84'/0'/0'/0/0"],
    ["Testnet setup", "testnet", "m/84'/1'/0'/0/0"],
  ]);
  assert.equal(backup.activeKey, 1);
  assert.deepEqual(plain(backup.includedKeys), [1]);
  const keys = await deriveJournalKeys("backup test", JOURNAL_MIN_ITERATIONS);
  const sealed = await sealBackup({ version: 2, nextId: 1, entries: [] }, keys, backup);
  const opened = await openDocument(JSON.stringify(sealed), "backup test");
  const { context: restored } = sectionHarness();
  loadFunctions(restored, ["hodlJournalRestoreBackup"]);
  restored.hodlJournalRestoreBackup(opened.doc.backup);
  const states = restored.hodlKeyManagerStates();
  assert.equal(states.length, 2);
  assert.deepEqual(plain(states.map((key) => [key.name, key.fields.network, key.fields.derivationPath])), [
    ["Mainnet setup", "mainnet", "m/84'/0'/0'/0/0"],
    ["Testnet setup", "testnet", "m/84'/1'/0'/0/0"],
  ]);
  assert.notEqual(keyVaultIdentity(states[0]), keyVaultIdentity(states[1]));
  assert.ok(states.every((key) => key.result === null && key.needsDerivation));
  assert.equal(restored.hodlKeyManagerActiveId, keyVaultIdentity(states[1]));
  assert.deepEqual([...restored.hodlKeyManagerIds], [keyVaultIdentity(states[1])]);
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
  assert.equal(fields.get("journal-state-private").checked, false);
  assert.equal(fields.get("journal-saved-state-private").checked, false, "restore must not reveal saved private material automatically");
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
  c.hodlKeys.push({ ...vaultEntry("Current derived key"), id: 7, result: {} });
  fields.get("journal-state-private").checked = false;
  c.hodlJournalSessionSnapshot = () => { journal.stateText = "Different live session without saved recovery information."; return journal.stateText; };
  loadFunctions(c, ["hodlJournalCollectBackup"]);
  const backup = c.hodlJournalCollectBackup();
  assert.ok(backup.snapshot.text.includes("Historical private snapshot that must survive a second backup."));
  assert.ok(backup.snapshot.text.includes("Different live session without saved recovery information."));
  assert.equal(backup.snapshot.includePrivate, true, "the historical snapshot remains private even while concealed");
  assert.equal(journal.backup.snapshot.text, "Historical private snapshot that must survive a second backup.");
});

test("complete backup preserves private recovery data without revealing it on screen", () => {
  for (const reveal of [false, true]) {
    const { context: c, journal, fields } = sectionHarness();
    fields.get("journal-state-private").checked = reveal;
    fields.get("journal-state-text").textContent = "Displayed snapshot unchanged";
    journal.stateText = "Displayed snapshot unchanged";
    c.hodlBip85Children = [{ name: "Recovery child", fingerprint: "12345678", result: { app: "bip39", secret: WORDS } }];
    Object.assign(c, {
      hodlMsigs: [], hodlSpKeys: null, hodlPsbtNonceInspected: false,
      hodlPsbtNonceVerdict: "", hodlPsbtNonceVerdictKind: "", hodlPsbtNonceHistory: [], hodlPsbtNonceHistoryVerdict: "",
      hodlJournalStamp: () => "2026-10-22 11:00:00", hodlJournalSnapshot: snapshotSession,
    });
    loadFunctions(c, ["hodlJournalSessionSnapshot", "hodlJournalRefreshSessionState", "hodlJournalCollectBackup"]);
    const backup = c.hodlJournalCollectBackup();
    assert.ok(backup.snapshot.text.includes(WORDS), "complete backup omitted recovery data because the display was concealed");
    assert.equal(backup.snapshot.includePrivate, true);
    assert.equal(fields.get("journal-state-private").checked, reveal);
    assert.equal(fields.get("journal-state-text").textContent, "Displayed snapshot unchanged");
    assert.equal(journal.stateText, "Displayed snapshot unchanged");
  }
});

// Security contract: each reveal exposes only its own report; imported flags
// cannot bypass concealment, and unchecking removes the rendered secret.
test("current and saved snapshot reveals are independent and saved text stays literal", () => {
  for (const includePrivate of [true, false]) {
    const { context: c, journal, fields } = sectionHarness();
    const savedText = "Saved private snapshot <img src=x onerror=alert(1)> seed marker";
    const currentSecret = "current private recovery marker";
    journal.backup = { snapshot: { text: savedText, includePrivate } };
    c.hodlJournalSessionSnapshot = (revealed) => revealed ? currentSecret : "Public current report";
    for (const id of ["journal-state-text", "journal-saved-state-text"]) {
      Object.defineProperty(fields.get(id), "innerHTML", {
        set() { assert.fail("snapshot text must never become an HTML sink"); },
      });
    }
    loadFunctions(c, ["hodlJournalRefreshSessionState"]);
    const currentBox = fields.get("journal-state-private"), savedBox = fields.get("journal-saved-state-private");
    const currentOut = fields.get("journal-state-text"), savedOut = fields.get("journal-saved-state-text");
    for (const [current, saved] of [[false, false], [true, false], [false, true], [true, true], [false, false]]) {
      currentBox.checked = current;
      savedBox.checked = saved;
      c.hodlJournalRefreshSessionState();
      assert.equal(currentOut.textContent.includes(currentSecret), current);
      assert.ok(!currentOut.textContent.includes(savedText), "current reveal exposed historical material");
      assert.equal(savedOut.textContent.includes(savedText), saved, `saved reveal must ignore imported includePrivate=${includePrivate}`);
      assert.ok(!savedOut.textContent.includes(currentSecret));
      assert.equal(journal.stateText, currentOut.textContent, "current export must match only the current report");
      assert.equal(journal.backup.snapshot.text, savedText, "concealing must preserve backed-up data");
    }
  }
});

// Saved history is retained unless its own current Journal confirmation is
// accepted. Removal must never alter live wallets, notes or a replacement
// Journal, and removed history must disappear from display and future backups.
function savedSnapshotHarness() {
  const h = sectionHarness(), { context: c, journal, fields } = h;
  const saved = { text: "Historical recovery marker", includePrivate: true };
  journal.backup = { snapshot: saved };
  journal.pages[0].notesText = fields.get("journal-notes-text").value;
  journal.notesText = journal.pages[0].notesText;
  fields.set("journal-state-history", { hidden: true });
  fields.set("journal-state-delete-history", {});
  fields.get("journal-saved-state-private").checked = true;
  fields.set("journal-state-summary", { focus() { c.document.activeElement = this; } });
  fields.get("journal-state-private").focus = () => {}; // Unfocusable inside a closed disclosure.
  let decision;
  Object.assign(c, {
    hodlJournalGeneration: 9, hodlJournalPageDeleteConfirm: null,
    initJournalPageDeleteConfirm: () => ({ show(options) { decision = options; } }),
    hodlJournalLog(action, detail, tool) {
      appendLog(journal, { action, detail, tool });
      c.hodlJournalMarkDirty();
    },
  });
  loadFunctions(c, ["hodlJournalRefreshSessionState", "hodlJournalRemoveSavedSnapshot", "hodlJournalCollectBackup"]);
  return { ...h, saved, decision: () => decision };
}

test("Session binds saved-history removal to its confirmation controller", () => {
  const control = {}, c = {
    document: { querySelectorAll: () => [], getElementById: id => id === "journal-state-delete-history" ? control : null },
    hodlJournal: {}, hodlJournalAppend() {}, hodlInitTabDrag() {},
    hodlInitJournalActionAudit() {}, hodlRefreshJournalKeyPicker() {}, hodlSyncJournalTool() {},
    hodlJournalRemoveSavedSnapshot() { c.requested = true; },
  };
  loadFunctions(c, ["hodlInitJournalToolTabs"]);
  c.hodlInitJournalToolTabs();
  assert.equal(typeof control.onclick, "function");
  control.onclick();
  assert.equal(c.requested, true);
});

test("snapshot export controls use only their own report and cannot export concealed history", async () => {
  const { context: c, journal, fields } = sectionHarness(), downloads = [];
  const currentDownload = {}, savedDownload = {};
  fields.delete("journal-notes-text");
  fields.set("journal-state-download", currentDownload);
  fields.set("journal-saved-state-download", savedDownload);
  for (const id of ["journal-state-private", "journal-saved-state-private"]) fields.get(id).addEventListener = () => {};
  c.document.querySelectorAll = () => [];
  journal.backup = { snapshot: { text: "Saved recovery only", includePrivate: false } };
  Object.assign(c, {
    hodlJournalAppend() {}, hodlInitTabDrag() {}, hodlInitJournalActionAudit() {},
    hodlRefreshJournalKeyPicker() {}, hodlSyncJournalTool() {},
    hodlJournalRemoveSavedSnapshot() {},
    hodlJournalDownloadContent(...args) { downloads.push(args); },
  });
  loadFunctions(c, ["hodlJournalRefreshSessionState", "hodlInitJournalToolTabs"]);
  c.hodlInitJournalToolTabs();
  await savedDownload.onclick();
  assert.equal(downloads.length, 0);
  fields.get("journal-saved-state-private").checked = true;
  await savedDownload.onclick();
  assert.deepEqual(downloads[0], ["session-state", "entropylab-saved-session.txt", "Saved recovery only"]);
  await currentDownload.onclick();
  assert.deepEqual(downloads[1], ["session-state", "entropylab-session.txt", SNAPSHOT]);
  fields.get("journal-saved-state-private").checked = false;
  await savedDownload.onclick();
  assert.equal(downloads.length, 2, "unchecked saved report still exported");
  fields.get("journal-saved-state-private").checked = true;
  journal.backup.snapshot = null;
  await savedDownload.onclick();
  assert.equal(downloads.length, 2, "removed saved report still exported");
});

test("saved-history action appears only while a historical snapshot exists", () => {
  const { context: c, journal, fields, saved } = savedSnapshotHarness();
  c.hodlJournalRefreshSessionState();
  assert.equal(fields.get("journal-state-history").hidden, false);
  fields.get("journal-state-private").checked = false;
  c.hodlJournalRefreshSessionState();
  assert.equal(fields.get("journal-state-history").hidden, false, "concealed history must still be removable");
  assert.ok(!fields.get("journal-state-text").textContent.includes(saved.text));
  journal.backup.snapshot = null;
  c.hodlJournalRefreshSessionState();
  assert.equal(fields.get("journal-state-history").hidden, true);
});

test("saved-history removal waits for confirmation and preserves history by default", () => {
  const { context: c, journal, saved, decision } = savedSnapshotHarness();
  c.hodlJournalRemoveSavedSnapshot();
  assert.ok(decision());
  assert.equal(journal.backup.snapshot, saved);
  assert.equal(c.hodlJournalDirty, false);
  assert.equal(c.hodlJournalBackupRevision, 0);
  assert.ok(c.hodlJournalCollectBackup().snapshot.text.includes(saved.text), "an unconfirmed removal lost history from the backup");
});

test("confirmed history removal clears its text and future backups while preserving current content", () => {
  const { context: c, journal, saved, fields, decision } = savedSnapshotHarness();
  const live = { ...vaultEntry("Current key"), id: 30, result: { masterIdentity: "current-wallet" } };
  c.hodlKeys.push(live);
  const notes = serializeNotebook(journal), key = JSON.stringify(live);
  c.hodlJournalRefreshSessionState();
  assert.ok(fields.get("journal-saved-state-text").textContent.includes(saved.text));
  c.hodlJournalRemoveSavedSnapshot();
  decision().onConfirm();
  assert.equal(journal.backup.snapshot, null);
  assert.equal(saved.text, "", "a retained snapshot reference still holds removed history");
  assert.equal(journal.stateText, SNAPSHOT);
  assert.equal(fields.get("journal-state-text").textContent, SNAPSHOT);
  assert.equal(fields.get("journal-saved-state-text").textContent, "");
  assert.equal(fields.get("journal-state-history").hidden, true);
  assert.equal(c.document.activeElement, fields.get("journal-state-summary"), "focus must return to the visible summary even when current report is collapsed");
  assert.equal(c.hodlJournalDirty, true);
  assert.equal(c.hodlJournalBackupRevision, 1);
  assert.equal(serializeNotebook(journal), notes);
  assert.equal(c.hodlKeys[0], live);
  assert.equal(JSON.stringify(live), key);
  assert.equal(c.hodlJournalCollectBackup().snapshot.text, SNAPSHOT);
  decision().onConfirm();
  assert.equal(c.hodlJournalBackupRevision, 1, "an old callback removed history twice");
});

test("saved-history confirmation cannot act after Clear, reopen, or replacement", () => {
  for (const change of ["clear", "generation", "journal", "snapshot"]) {
    const { context: c, journal, saved, decision } = savedSnapshotHarness();
    c.hodlJournalRemoveSavedSnapshot();
    const replacement = { text: "Replacement history marker", includePrivate: true };
    if (change === "clear") { c.hodlJournalKeys = null; c.hodlJournalDoc = null; }
    if (change === "generation") c.hodlJournalGeneration++;
    if (change === "journal") c.hodlJournal = { ...journal, backup: { snapshot: replacement } };
    if (change === "snapshot") journal.backup.snapshot = replacement;
    decision().onConfirm();
    assert.equal(saved.text, "Historical recovery marker", `${change}: an obsolete confirmation changed the captured history`);
    assert.equal(replacement.text, "Replacement history marker");
    assert.equal(c.hodlJournalDirty, false);
    assert.equal(c.hodlJournalBackupRevision, 0);
  }
});

test("saved-history removal has no decision when the Journal is closed or has no history", () => {
  for (const closed of [false, true]) {
    const { context: c, journal, decision } = savedSnapshotHarness();
    if (closed) { c.hodlJournalKeys = null; c.hodlJournalDoc = null; }
    else journal.backup = null;
    c.hodlJournalRemoveSavedSnapshot();
    assert.equal(decision(), undefined);
    assert.equal(c.hodlJournalDirty, false);
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

test("browsing Journal sections leaves saved content clean while mutations require backup", () => {
  const { context: c, journal } = sectionHarness();
  Object.assign(c, {
    hodlJournalAppend: appendLog, hodlScheduleJournalStateRefresh() {},
    hodlWorkspace: "journal", hodlJournalTool: "notes",
  });
  loadFunctions(c, ["hodlJournalLog"]);
  for (const action of ["workspace", "tool-tab", "station-select", "page-select", "theme", "copy", "download", "journal-unlock"]) {
    c.hodlJournalLog(action, "", "journal");
    assert.equal(c.hodlJournalDirty, false, `${action} must not pretend content changed`);
    assert.equal(c.hodlJournalBackupRevision, 0);
  }
  c.hodlJournalLog("key-manager-rename", "key-1", "journal");
  assert.equal(c.hodlJournalDirty, true);
  assert.equal(journal.log.at(-1).action, "key-manager-rename");
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

test("a complete download refuses an open saved-record edit without losing the draft", async () => {
  const { context: c, downloads, seals, fields } = saveHarness({ editorOpen: true });
  fields.set("journal-input", { value: "unfinished recovery correction" });
  assert.equal(await c.hodlJournalSaveFile(), false);
  assert.deepEqual(seals, []);
  assert.deepEqual(downloads, []);
  assert.equal(fields.get("journal-editor").hidden, false);
  assert.equal(fields.get("journal-input").value, "unfinished recovery correction");
  assert.ok(fields.get("journal-error").textContent.trim());
  assert.equal(c.hodlJournalDirty, true);
});

test("opening a record editor during encryption suppresses that pending download", async () => {
  const gate = deferred();
  const { context: c, captured, downloads, fields } = saveHarness({ gate });
  const saving = c.hodlJournalSaveFile();
  fields.get("journal-editor").hidden = false;
  fields.set("journal-input", { value: "new unfinished recovery correction" });
  gate.resolve({ ciphertext: "older capture" });
  assert.equal(await saving, false);
  assert.deepEqual(downloads, []);
  assert.equal(fields.get("journal-editor").hidden, false);
  assert.equal(fields.get("journal-input").value, "new unfinished recovery correction");
  assert.ok(fields.get("journal-error").textContent.trim());
  assert.equal(c.hodlJournalDirty, true);
  assertCollectedPlaintextCleared(captured);
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
  events.length = 0; // Clear has erased events recorded before it.
  gate.resolve({ ciphertext: "obsolete encrypted content" });
  await saving;
  assert.equal(downloads.length, 0, "a locked session must not finish its pending download");
  assert.equal(events.length, 0, "the obsolete operation must not redraw or log save success");
  assert.equal(fields.get("journal-error").textContent, "", "a canceled save must not replace the lock announcement with an error");
  assertCollectedPlaintextCleared(captured);
});

test("complete backup Debug events distinguish browser handoff from failure without retaining errors", async () => {
  const success = saveHarness();
  assert.equal(await success.context.hodlJournalSaveFile(), true);
  assert.deepEqual(success.events.filter(Array.isArray), [
    ["export-request", "journal-backup", "journal"], ["download-started", "journal-backup", "journal"],
  ]);
  const gate = deferred(), failed = saveHarness({ gate });
  const saving = failed.context.hodlJournalSaveFile();
  gate.reject(new Error(WORDS));
  assert.equal(await saving, false);
  assert.deepEqual(failed.events.filter(Array.isArray), [
    ["export-request", "journal-backup", "journal"], ["export-error", "journal-backup", "journal"],
  ]);
  assert.equal(JSON.stringify(failed.events).includes(WORDS), false);
  assert.equal(failed.downloads.length, 0);
  assertCollectedPlaintextCleared(failed.captured);
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

test("backup errors use global feedback without changing the active Journal section", async () => {
  const gate = deferred();
  const { context: c, downloads, fields } = saveHarness({ gate });
  c.hodlJournalTool = "notes";
  const saving = c.hodlJournalSaveFile();
  gate.reject(new Error("backup exceeds file size limit"));
  await saving;
  assert.ok(fields.get("journal-error").textContent.trim());
  assert.equal(c.hodlJournalTool, "notes");
  assert.equal(downloads.length, 0);
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
    hodlJournalReportViewer: null, hodlJournalReportRequest: 0,
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
    "hodlJournalError", "hodlJournalSetGateBusy", "hodlJournalClearReport", "hodlJournalWipeNotebook", "hodlJournalDiscardOpened",
    "hodlJournalCheckInventory", "hodlJournalChooseFile", "hodlJournalUnlock", "hodlJournalRestoreBackup", "hodlJournalLog", "hodlKeyManagerCapacityError",
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

// Security contract: backups retain unfinished source inputs verbatim but
// restore them only as unverified inputs, never cached results or trusted IDs.
test("complete backup captures unfinished lab inputs and cold-restores them unverified", async () => {
  const { context: c } = sectionHarness();
  const draft = { ...vaultEntry("Lab"), id: 44, isLab: true, fields: { seed: "abandon abandon", pass: new TextEncoder().encode(" exact pass "), network: "signet", derivationPath: "m/84'/1'/3'/0/8", addressRange: "1000", privateKeys: { wif: "unfinished-wif" } }, result: { forgedCached: "never restore" } };
  c.hodlKeys.push(draft);
  let captures = 0;
  c.hodlCaptureKey = () => { captures++; draft.fields.dice = "1624"; };
  loadFunctions(c, ["hodlJournalCollectBackup"]);
  const collected = c.hodlJournalCollectBackup();
  const inputs = parseKeyVault(collected.keyManager).keys;
  assert.equal(inputs.length, 1, "unfinished lab inputs were omitted");
  assert.equal(captures, 1, "the visible form must be captured before backup");
  assert.equal(inputs[0].fields.seed, "abandon abandon");
  assert.equal(inputs[0].fields.pass, " exact pass ");
  assert.equal(inputs[0].fields.dice, "1624");
  assert.equal(inputs[0].fields.network, "signet");
  assert.equal(inputs[0].fields.derivationPath, "m/84'/1'/3'/0/8");
  assert.equal(inputs[0].fields.privateKeys.wif, "unfinished-wif");
  assert.equal(inputs[0].result, null);
  assert.equal(new TextDecoder().decode(draft.fields.pass), " exact pass ");
  const keys = await deriveJournalKeys("draft backup", JOURNAL_MIN_ITERATIONS);
  const sealed = await sealBackup({ version: 2, nextId: 1, entries: [] }, keys, collected);
  const opened = await openDocument(JSON.stringify(sealed), "draft backup");
  const { context: restored } = sectionHarness();
  const activeLab = { id: 4, isLab: true, fields: { seed: "keep my current work" } };
  restored.hodlKeys.push(activeLab);
  loadFunctions(restored, ["hodlJournalRestoreBackup"]);
  restored.hodlJournalRestoreBackup(opened.doc.backup);
  assert.equal(restored.hodlKeys[0], activeLab);
  assert.equal(activeLab.fields.seed, "keep my current work");
  const pending = restored.hodlKeyManagerPending[0];
  assert.notEqual(pending.id, draft.id);
  assert.equal(pending.result, null);
  assert.equal(pending.needsDerivation, true);
  assert.equal(pending.fields.seed, "abandon abandon");
  assert.equal(new TextDecoder().decode(pending.fields.pass), " exact pass ");
});

test("empty lab settings consume no backup slot but an unfinished draft counts at the limit", () => {
  const { context: c } = sectionHarness();
  const lab = { id: 999, isLab: true, fields: { network: "signet", derivationPath: "m/84'/1'/0'/0/0", pass: new Uint8Array() } };
  c.hodlKeys.push(lab);
  c.hodlKeyManagerPending = Array.from({ length: KEY_VAULT_MAX_KEYS }, (_, i) => ({ ...vaultEntry(`Inputs ${i}`), id: i + 1 }));
  loadFunctions(c, ["hodlJournalCollectBackup"]);
  assert.equal(parseKeyVault(c.hodlJournalCollectBackup().keyManager).keys.length, KEY_VAULT_MAX_KEYS);
  lab.fields.seed = "unfinished";
  assert.throws(() => c.hodlJournalCollectBackup(), error => error.name === "Error" && error.message.length > 0, "a full inventory must refuse rather than omit its draft");
  assert.equal(lab.fields.seed, "unfinished");
  assert.equal(c.hodlKeyManagerPending.length, KEY_VAULT_MAX_KEYS);
});

test("complete collection refuses an in-flight derivation", () => {
  for (const busy of ["hodlActiveDerivation", "hodlJournalKeyDerivation"]) {
    const { context: c } = sectionHarness();
    c[busy] = {};
    loadFunctions(c, ["hodlJournalCollectBackup"]);
    assert.throws(() => c.hodlJournalCollectBackup(), error => error.name === "Error" && error.message.length > 0);
  }
});

test("restoring a complete backup preserves earlier events from this browser session", () => {
  const { context: c, journal } = sectionHarness();
  const current = { at: "2026-10-23 12:00:00", tool: "calc", action: "derive", detail: "current session" };
  journal.log = [current];
  journal.logDiscarded = 2;
  const backup = normalizedBackup();
  backup.logDiscarded = 3;
  loadFunctions(c, ["hodlJournalRestoreBackup"]);
  c.hodlJournalRestoreBackup(backup);
  assert.deepEqual(plain(journal.log), [...EVENTS, { at: "2026-10-23 12:00:00", tool: "calc", action: "derive", detail: "current session" }]);
  assert.equal(journal.logDiscarded, 5);
  assert.notEqual(journal.log.at(-1), current, "wiping replaced state must not wipe transferred history");
});

test("key source input changes invalidate a pending backup without logging their values", () => {
  const { context: c, journal } = sectionHarness();
  const listeners = {};
  c.hodlJournalActionAuditReady = false;
  c.hodlJournalSuppressSettingAudit = 0;
  c.document.addEventListener = (name, fn) => { listeners[name] = fn; };
  loadFunctions(c, ["hodlInitJournalActionAudit"]);
  c.hodlInitJournalActionAudit();
  const secret = { value: "private unfinished input", closest: selector => selector === "#calc-card" ? {} : null };
  listeners.input?.({ target: secret });
  assert.equal(c.hodlJournalDirty, true);
  assert.equal(c.hodlJournalBackupRevision, 1);
  assert.equal(journal.log.length, 0);
  c.hodlJournalSuppressSettingAudit = 1;
  listeners.input({ target: secret });
  assert.equal(c.hodlJournalBackupRevision, 1, "restoring a form is not a user edit");
});

test("cold restore and resave preserves the historical snapshot without nesting empty reports", () => {
  const { context: c, journal } = sectionHarness();
  const original = { text: "Private historical recovery that only exists in this saved report", includePrivate: true };
  journal.backup = { snapshot: plain(original) };
  loadFunctions(c, ["hodlJournalCollectBackup", "hodlJournalRestoreBackup"]);
  for (let i = 0; i < 4; i++) {
    const collected = c.hodlJournalCollectBackup();
    assert.deepEqual(plain(collected.snapshot), original);
    const restored = normalizedBackup();
    restored.snapshot = collected.snapshot;
    c.hodlJournalRestoreBackup(restored);
  }
});

test("collecting from Journal does not recapture a hidden Key Station form or discard its verified result", () => {
  const { context: c } = sectionHarness();
  c.hodlWorkspace = "journal";
  const key = { ...vaultEntry("Verified key"), id: 1, result: { masterFingerprint: "73c5da0a" } };
  c.hodlKeys.push(key);
  const result = key.result;
  c.hodlCaptureKey = () => { key.result = null; };
  loadFunctions(c, ["hodlJournalCollectBackup"]);
  c.hodlJournalCollectBackup();
  assert.equal(key.result, result, "hidden form globals must not overwrite the captured station state");
});

test("restoring a Key Station field does not invalidate the Journal backup", () => {
  const { context: c } = sectionHarness();
  const listeners = {};
  c.hodlJournalActionAuditReady = false;
  c.hodlJournalSuppressSettingAudit = false;
  c.document.addEventListener = (name, fn) => { listeners[name] = fn; };
  loadFunctions(c, ["hodlInitJournalActionAudit"]);
  c.hodlInitJournalActionAudit();
  const field = { hodlRestoring: true, closest: () => ({}) };
  listeners.input({ target: field });
  assert.equal(c.hodlJournalDirty, false);
  assert.equal(c.hodlJournalBackupRevision, 0);
});

// Saving a draft must preserve the same explicit chain that its next fresh
// derivation will use, including an invalid family conflict for later review.
test("unfinished backup inputs preserve reviewed and global chain choices without changing source fields", () => {
  for (const [choice, family, reviewed, expected] of [
    ["mainnet", "testnet", "signet", "signet"],
    ["signet", "testnet", "regtest", "regtest"],
    ["regtest", "testnet", null, "regtest"],
    ["signet", "testnet", null, "signet"],
    ["signet", "mainnet", null, "mainnet"],
    ["mainnet", "mainnet", "regtest", "regtest"],
  ]) {
    const { context: c } = sectionHarness();
    c.hodlWorkspace = "journal";
    c.hodlNetworkChoice = choice;
    const draft = { ...vaultEntry("Lab"), id: 0, isLab: true };
    draft.fields.network = family;
    if (reviewed) Object.assign(draft, { importedKeyId: 51, importedNetworkChoice: reviewed });
    c.hodlKeys.push(draft);
    loadFunctions(c, ["hodlJournalCollectBackup", "hodlJournalRestoreBackup"]);
    const collected = c.hodlJournalCollectBackup();
    const exported = parseKeyVault(collected.keyManager);
    assert.equal(exported.keys[0].fields.network, expected, `${choice}/${family}/${reviewed}`);
    assert.equal(draft.fields.network, family, "export must not mutate the live draft");
    const restored = normalizedBackup();
    restored.keyManager = exported; restored.includedKeys = []; restored.activeKey = null;
    c.hodlJournalRestoreBackup(restored);
    assert.equal(c.hodlKeyManagerPending[0].fields.network, expected);
    assert.equal(c.hodlKeyManagerPending[0].needsDerivation, true);
    assert.equal(c.hodlKeyManagerPending[0].result, null);
  }
});
