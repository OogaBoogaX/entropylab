// Section exports use the open Journal's protection and cannot finish after
// its generation ends. Key exports contain every active and archived input
// set; old UI selections must neither filter exports nor mutate on download.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { copyText } from "../src/js/clipboard.js";
import { MiniDocument } from "./mini-dom.mjs";
import { KEY_VAULT_MAX_KEYS, keyVaultIdentity, parseKeyVault, serializeKeyVault } from "../src/js/keymanager.js";
import { JOURNAL_LOG_LIMIT, JOURNAL_LOG_MAX_BYTES, JOURNAL_MAX_FILE_LENGTH, JOURNAL_MIN_ITERATIONS, appendLog, createJournal, deriveJournalKeys, formatLog, formatLogField, logUsage, journalFromPlainText, mergeNotebookImport, openExport, parseNotebook, sealExport, serializeNotebook } from "../src/js/journal.js";

const source = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");
const extract = (name) => {
  const match = source.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^}`, "m"));
  assert.ok(match, name);
  return match[0];
};
const input = (id, name) => ({ id, name, fields: { seed: `${name} secret inputs` } });
function harness({ unlocked = true, encrypted = true, selected = ["1"], states = [input(1, "First"), input(2, "Second")] } = {}) {
  let resolve, reject;
  const pending = new Promise((yes, no) => { resolve = yes; reject = no; });
  const seals = [], downloads = [], effects = [];
  const keys = { passwordProtected: true };
  const context = vm.createContext({
    hodlJournalKeys: keys, hodlJournalGeneration: 0, hodlJournalEncryptDownloads: encrypted,
    hodlJournalUnlocked: () => unlocked,
    hodlKeyManagerIds: new Set(selected), hodlKeyManagerIgnored: [input(3, "Archived")],
    hodlKeyManagerStates: () => states, hodlKeyManagerEntry: (state) => structuredClone(state),
    keyVaultIdentity, serializeKeyVault,
    hodlJournalSealExport: (...args) => { seals.push(args); return pending; },
    hodlJournalDownload: (...args) => downloads.push(args),
    hodlJournalError: (...args) => effects.push(["error", ...args]),
    hodlJournalSetStatus: (...args) => effects.push(["notes-status", ...args]),
    hodlKeyManagerStatus: (...args) => effects.push(["key-status", ...args]),
    hodlKeyManagerRender: () => effects.push(["render"]),
    hodlJournalLog: (...args) => effects.push(["log", ...args]),
    hodlTText: (text) => text,
    // No key holds Secure entry words here; secure-entry-wiring.test.mjs covers the refusal.
    hodlSecureEntryBackupRefusal: () => null,
  });
  vm.runInContext(["hodlJournalDownloadContent", "hodlKeyManagerDownload"].map(extract).join("\n"), context);
  return { context, keys, seals, downloads, effects, resolve, reject };
}

for (const encrypted of [true, false]) test(`section export uses Journal protection with old encryption flag ${encrypted}`, async () => {
  const ui = harness({ encrypted });
  const run = ui.context.hodlJournalDownloadContent("notebook", "notes.json", "private notes");
  assert.equal(ui.seals.length, 1, "section content bypassed Journal protection");
  assert.deepEqual(ui.seals[0], ["notebook", "private notes", ui.keys]);
  assert.equal(ui.downloads.length, 0, "download happened before encryption completed");
  ui.resolve({ sealed: "opaque ciphertext" });
  await run;
  assert.equal(ui.downloads.length, 1);
  assert.ok(!ui.downloads[0][1].includes("private notes"), "section export contains plaintext");
});

test("a valid export retry clears its prior failure before sealing and stays clear after handoff", async () => {
  const ui = harness(), seal = ui.context.hodlJournalSealExport;
  let error = "", attempts = 0;
  ui.context.hodlJournalError = (message) => { error = message; };
  ui.context.hodlJournalSealExport = (...args) => attempts++ === 0 ? Promise.reject(new Error("fixture export failed")) : seal(...args);
  assert.equal(await ui.context.hodlJournalDownloadContent("session-log", "report.txt", "first report"), false);
  assert.equal(error, "fixture export failed");
  const retry = ui.context.hodlJournalDownloadContent("session-log", "report.txt", "second report");
  const duringRetry = error;
  ui.resolve({ sealed: "opaque ciphertext" });
  assert.equal(await retry, true);
  assert.equal(duringRetry, "", "a pending retry still displayed the previous failure");
  assert.equal(error, "", "a successful retry left a stale export error");
  assert.equal(ui.downloads.length, 1);
});

test("an obsolete export cannot start sealing or clear the current Journal's error", async () => {
  const ui = harness();
  let error = "current Journal error";
  ui.context.hodlJournalError = (message) => { error = message; };
  const run = ui.context.hodlJournalDownloadContent("session-log", "report.txt", "old report", () => false);
  ui.resolve({ sealed: "old ciphertext" });
  assert.equal(await run, false);
  assert.deepEqual(ui.seals, [], "an already obsolete export started work");
  assert.deepEqual(ui.downloads, []);
  assert.equal(error, "current Journal error");
});

function activityHarness(options) {
  const ui = harness(options), button = {};
  ui.context.document = { getElementById: () => button };
  ui.context.hodlJournal = { log: [{ at: "2026-10-22 09:08:07", tool: "imported", action: "note", detail: "imported private recovery text" }] };
  ui.context.hodlJournalFormatLog = formatLog;
  vm.runInContext(extract("hodlJournalDownloadLog"), ui.context);
  const listener = source.slice(source.indexOf('  let logDownload = document.getElementById("journal-log-download");'), source.indexOf('  let logOut = document.getElementById("journal-log-out")'));
  vm.runInContext(listener, ui.context);
  return { ...ui, button };
}

function debugLogHarness() {
  const ui = harness(), listeners = new Map(), copies = [], feedback = [], appended = [];
  let resolveCopy, clearDecision;
  const copyResult = new Promise((resolve) => { resolveCopy = resolve; });
  const button = (id) => ({ id, disabled: false, dataset: {}, closest() { return this; }, matches: () => false });
  const output = { textContent: "", scrollTop: 0, scrollLeft: 0, scrollHeight: 100, clientHeight: 100 };
  const elements = new Map([
    ["journal-log-out", output],
    ["journal-log-copy", button("journal-log-copy")],
    ["journal-log-download", button("journal-log-download")],
    ["journal-log-clear", button("journal-log-clear")],
    ["journal-log-earlier", button("journal-log-earlier")],
    ["journal-log-newer", button("journal-log-newer")],
    ["journal-log-latest", button("journal-log-latest")],
    ["journal-log-navigation", { hidden: true }],
    ["journal-log-status", { textContent: "", dataset: {} }],
    ["journal-log-range", { textContent: "" }],
    ["journal-log-truncated", { textContent: "", hidden: true }],
  ]);
  const journal = { log: [{ at: "2026-10-22 09:08:07", tool: "imported", action: "note", detail: "  literal <private> text\nnext line  " }] };
  Object.assign(ui.context, {
    hodlJournal: journal, hodlWorkspace: "journal", hodlJournalTool: "session",
    hodlJournalClearConfirm: null,
    initJournalClearConfirm: () => ({ show(_opener, options) { clearDecision = options; } }),
    hodlJournalSaveFile() {}, hodlJournalWipeMem() {},
    hodlJournalActionAuditReady: false, hodlJournalSuppressSettingAudit: false,
    hodlJournalFormatLog: formatLog,
    hodlJournalFormatLogField: formatLogField,
    hodlJournalLogUsage: logUsage,
    hodlJournalLogMaxBytes: JOURNAL_LOG_MAX_BYTES, hodlJournalLogLimit: JOURNAL_LOG_LIMIT,
    hodlJournalAppend(value, event) { appended.push(event); return appendLog(value, event); },
    hodlJournalMarkDirty() { feedback.push("dirty"); }, hodlScheduleJournalStateRefresh() {},
    hodlInitTabDrag() {}, hodlRefreshJournalKeyPicker() {},
    hodlSyncJournalTool() { ui.context.hodlRenderJournalLog(); },
    hodlReadoutIsShown: () => true,
    copyText(text) { copies.push(text); return copyResult; },
    hodlShowCopiedIcon() { feedback.push("copied"); },
    hodlClipboardIconMarkup: () => "", hodlCopiedIconMarkup: () => "",
    document: {
      querySelectorAll: () => [], getElementById: (id) => elements.get(id) || null,
      addEventListener(type, listener) { listeners.set(type, listener); },
    },
  });
  const mappings = source.slice(source.indexOf("var hodlJournalAuditedClicks ="), source.indexOf("var hodlJournalActionAuditReady ="));
  const functions = ["hodlJournalLog", "hodlJournalAuditedClick", "hodlInitJournalActionAudit", "hodlInitJournalToolTabs", "hodlRenderJournalLog", "hodlJournalGetClearConfirm", "hodlJournalClearLog", "hodlJournalCopyContent", "hodlJournalCopyLog", "hodlJournalDownloadLog"];
  vm.runInContext(mappings + functions.filter((name) => source.includes(`function ${name}(`)).map(extract).join("\n"), ui.context);
  ui.context.hodlInitJournalToolTabs();
  appended.length = 0;
  const click = (id) => {
    const target = elements.get(id);
    listeners.get("click")({ target });
    return target.onclick();
  };
  return { ...ui, journal, output, elements, copies, feedback, appended, resolveCopy, click, clearDecision: () => clearDecision };
}

test("Debug log ranges cannot render imported timestamp control characters", () => {
  const ui = debugLogHarness();
  ui.context.hodlTText = (text, params = {}) => text.replace(/\{(\w+)\}/g, (_match, key) => String(params[key]));
  ui.journal.log[0].at = "date\nforged\tcolumn\u202e";
  ui.context.hodlRenderJournalLog();
  const range = ui.elements.get("journal-log-range").textContent;
  assert.ok(range.includes("date\\nforged\\tcolumn\\u202e"));
  assert.doesNotMatch(range, /[\n\t\u202e]/);
});

test("Debug log pages keep older events readable while Copy and Export capture all retained history", async () => {
  const ui = debugLogHarness();
  ui.journal.log = Array.from({ length: 950 }, (_, index) => ({ at: "2026-10-23 09:00:00", tool: "app", action: "fixture", detail: `event-${index}` }));
  ui.context.hodlRenderJournalLog();
  assert.equal(ui.output.textContent, formatLog(ui.journal.log.slice(-400)));
  assert.equal(ui.elements.get("journal-log-navigation").hidden, false);
  ui.click("journal-log-earlier");
  assert.equal(ui.output.textContent, formatLog(ui.journal.log.slice(150, 550)));
  const reading = ui.output.textContent;
  ui.context.hodlJournalLog("theme", "dark", "app");
  assert.equal(ui.output.textContent, reading, "new events must not shift the older page being read");
  ui.click("journal-log-earlier");
  assert.equal(ui.output.textContent, formatLog(ui.journal.log.slice(0, 150)));
  assert.equal(ui.elements.get("journal-log-earlier").disabled, true);
  const entireLog = formatLog(ui.journal.log);
  const copying = ui.click("journal-log-copy");
  assert.deepEqual(ui.copies, [entireLog], "Copy must not be limited to the visible page");
  ui.resolveCopy(true);
  await copying;
  const beforeExport = formatLog(ui.journal.log);
  const exporting = ui.click("journal-log-download");
  assert.equal(ui.seals[0][1], beforeExport, "Export must not be limited to the visible page");
  ui.resolve({ sealed: "opaque ciphertext" });
  await exporting;
  ui.click("journal-log-latest");
  assert.equal(ui.output.textContent, formatLog(ui.journal.log.slice(-400)));
  assert.equal(ui.elements.get("journal-log-newer").disabled, true);
});

test("Debug log paging resets for replacement history and remains a literal text sink", () => {
  const ui = debugLogHarness();
  ui.journal.log = Array.from({ length: 850 }, (_, index) => ({ at: "fixture", tool: "app", action: "fixture", detail: String(index) }));
  ui.context.hodlRenderJournalLog();
  ui.click("journal-log-earlier");
  ui.journal.log = [{ at: "fixture", tool: "imported", action: "<img src=x onerror=1>", detail: "replacement" }];
  ui.context.hodlRenderJournalLog();
  assert.equal(ui.output.textContent, formatLog(ui.journal.log));
  assert.equal(ui.elements.get("journal-log-navigation").hidden, true);
  assert.equal(ui.output.innerHTML, undefined);
});

test("a hidden Debug reader continues the latest page rather than freezing at the last visible event", () => {
  const ui = debugLogHarness();
  ui.journal.log = Array.from({ length: 600 }, (_, index) => ({ at: "fixture", tool: "app", action: "fixture", detail: String(index) }));
  ui.context.hodlRenderJournalLog();
  ui.output.clientHeight = 0;
  ui.context.hodlJournalLog("theme", "dark", "app");
  assert.equal(ui.output.textContent, formatLog(ui.journal.log.slice(-400)));
  assert.equal(ui.elements.get("journal-log-newer").disabled, true);
});

test("a paused reader can return to new events even when fewer than one page is retained", () => {
  const ui = debugLogHarness();
  ui.journal.log = Array.from({ length: 100 }, (_, index) => ({ at: "fixture", tool: "app", action: "fixture", detail: String(index) }));
  ui.context.hodlRenderJournalLog();
  ui.output.scrollHeight = 500;
  ui.output.scrollTop = 0;
  const reading = ui.output.textContent;
  ui.context.hodlJournalLog("theme", "dark", "app");
  assert.equal(ui.output.textContent, reading);
  assert.equal(ui.elements.get("journal-log-navigation").hidden, false);
  assert.equal(ui.elements.get("journal-log-latest").disabled, false);
  ui.click("journal-log-latest");
  assert.equal(ui.output.textContent, formatLog(ui.journal.log));
  assert.equal(ui.elements.get("journal-log-navigation").hidden, true);
});

test("returning to the bottom of the current latest page resumes following new events", () => {
  const ui = debugLogHarness();
  ui.output.scrollHeight = 500;
  ui.output.scrollTop = 0;
  ui.context.hodlRenderJournalLog();
  ui.output.scrollTop = 400;
  ui.context.hodlJournalLog("theme", "dark", "app");
  assert.equal(ui.output.textContent, formatLog(ui.journal.log));
  assert.equal(ui.elements.get("journal-log-navigation").hidden, true);
});

test("discarded history is disclosed in the reader and in full copied and exported reports", async () => {
  const ui = debugLogHarness();
  ui.journal.logDiscarded = 37;
  ui.context.hodlRenderJournalLog();
  const warning = ui.elements.get("journal-log-truncated");
  assert.equal(warning.hidden, false);
  assert.ok(warning.textContent.trim());
  assert.equal(warning.innerHTML, undefined);
  const expectedCopy = formatLog(ui.journal.log, 37);
  const copying = ui.click("journal-log-copy");
  assert.deepEqual(ui.copies, [expectedCopy]);
  ui.resolveCopy(true);
  await copying;
  const expectedExport = formatLog(ui.journal.log, 37);
  const exporting = ui.click("journal-log-download");
  assert.equal(ui.seals[0][1], expectedExport);
  ui.resolve({ sealed: "bounded report" });
  await exporting;
  ui.click("journal-log-clear");
  ui.clearDecision().onDiscard();
  assert.equal(ui.journal.logDiscarded, 0);
  assert.equal(warning.hidden, true);
  assert.equal(warning.textContent, "");
});

test("cancelling Export first prevents the pending debug log download and its completion event", async () => {
  const ui = debugLogHarness();
  let allowed = true;
  const exporting = ui.context.hodlJournalDownloadLog(() => allowed);
  assert.deepEqual(ui.appended.map(({ action }) => action), ["export-request"]);
  allowed = false;
  ui.resolve({ sealed: "cancelled report" });
  assert.equal(await exporting, false);
  assert.deepEqual(ui.downloads, []);
  assert.deepEqual(ui.appended.map(({ action }) => action), ["export-request"]);
  assert.ok(ui.journal.log.length > 1, "cancelling export must preserve the history");
});

for (const outcome of ["success", "failure", "stale"]) test(`Debug log Copy captures the displayed report and records its ${outcome} only after the clipboard settles`, async () => {
  const ui = debugLogHarness(), visible = ui.output.textContent;
  const original = JSON.stringify(ui.journal.log);
  const run = ui.click("journal-log-copy");
  const pendingText = ui.output.textContent, pendingEvents = ui.appended.slice();
  if (outcome === "stale") {
    ui.context.hodlJournalGeneration++;
    ui.context.hodlJournal = { log: [] };
  }
  ui.resolveCopy(outcome !== "failure");
  await run;
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(ui.copies, [visible], "Copy must capture exactly the report visible before its click");
  assert.equal(pendingText, visible, "Copy must not change the report before the clipboard result");
  assert.deepEqual(pendingEvents, []);
  if (outcome === "stale") {
    assert.equal(JSON.stringify(ui.journal.log), original);
    assert.deepEqual(ui.context.hodlJournal.log, []);
    assert.deepEqual(ui.appended, []);
    assert.deepEqual(ui.feedback, []);
  } else {
    const action = outcome === "success" ? "copy" : "copy-error";
    assert.deepEqual(ui.appended.map(({ tool, action, detail }) => [tool, action, detail]), [["journal", action, "session-log"]]);
    assert.deepEqual(ui.feedback, outcome === "success" ? ["copied"] : []);
    assert.equal(ui.output.textContent, formatLog(ui.journal.log));
    assert.equal(JSON.stringify(ui.journal.log.slice(0, -1)), original);
  }
});

for (const outcome of ["success", "failure", "stale"]) test(`Debug log Export captures the report before recording its request and ${outcome}`, async () => {
  const ui = debugLogHarness(), visible = ui.output.textContent;
  const run = ui.click("journal-log-download");
  const pendingActions = ui.appended.map(({ action }) => action);
  const pendingEffects = ui.effects.slice();
  if (outcome === "stale") {
    ui.context.hodlJournalGeneration++;
    ui.context.hodlJournal = { log: [] };
  }
  if (outcome === "failure") ui.reject(new Error("fixture encryption failure"));
  else ui.resolve({ sealed: "opaque ciphertext" });
  await run;
  assert.deepEqual(ui.seals, [["session-log", visible, ui.keys]], "Export must seal the displayed report before recording its request");
  assert.deepEqual(pendingActions, ["export-request"]);
  assert.deepEqual(ui.appended.map(({ action }) => action), outcome === "stale" ? ["export-request"] : ["export-request", outcome === "success" ? "download-started" : "export-error"]);
  assert.ok(ui.appended.every(({ tool, detail }) => tool === "journal" && detail === "session-log"), "outcome events must carry only metadata");
  assert.deepEqual(ui.feedback, [], "export outcomes must not dirty user content");
  if (outcome === "success") {
    assert.equal(ui.downloads.length, 1);
    assert.equal(ui.downloads[0][0], "entropylab-debug-log.encrypted.json");
    assert.ok(!ui.downloads[0][1].includes("literal <private> text"));
  } else assert.deepEqual(ui.downloads, []);
  if (outcome === "stale") {
    assert.deepEqual(ui.context.hodlJournal.log, []);
    assert.deepEqual(ui.effects, pendingEffects, "stale completion must not change the current error status");
  } else assert.equal(ui.output.textContent, formatLog(ui.journal.log));
});

for (const action of ["copy", "export"]) for (const outcome of ["success", "failure"]) test(`Debug log Clear cancels pending ${action} ${outcome} without reviving its old report`, async () => {
  const ui = debugLogHarness();
  const oldLog = ui.journal.log, retainedEvent = oldLog[0];
  const run = ui.click(action === "copy" ? "journal-log-copy" : "journal-log-download");
  ui.click("journal-log-clear");
  ui.clearDecision().onDiscard();
  const cleared = JSON.stringify(ui.journal.log);
  const clearedEffects = ui.effects.slice();
  if (action === "copy") ui.resolveCopy(outcome === "success");
  else if (outcome === "success") ui.resolve({ sealed: "old report" });
  else ui.reject(new Error("old report failure"));
  await run;
  await new Promise((resolve) => setImmediate(resolve));
  assert.notEqual(ui.journal.log, oldLog);
  assert.equal(oldLog.length, 0);
  for (const name of ["at", "tool", "action", "detail"]) assert.equal(retainedEvent[name], "");
  assert.equal(JSON.stringify(ui.journal.log), cleared, "a completed request resurrected old-history events");
  assert.deepEqual(ui.downloads, [], "a cleared report must not be handed to the browser after encryption completes");
  assert.deepEqual(ui.effects, clearedEffects, "a cleared report failure must not surface in the current Journal");
  assert.deepEqual(ui.feedback, ["dirty"], "clearing must prevent stale clipboard confirmation");
  assert.equal(ui.journal.log.length, 1);
  assert.equal(ui.journal.log[0].action, "clear");
  assert.equal(ui.output.textContent, formatLog(ui.journal.log));
});

for (const clear of [false, true]) test(`Debug log ${clear ? "Clear prevents a rejected native copy from falling back to old text" : "copy retains the shared fallback while its source is current"}`, async () => {
  const ui = debugLogHarness(), visible = ui.output.textContent;
  const originalDocument = Object.getOwnPropertyDescriptor(globalThis, "document");
  const originalNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  const document = new MiniDocument(), submitted = [], fallbacks = [];
  let reject;
  const native = new Promise((_resolve, no) => { reject = no; });
  document.execCommand = (command) => {
    assert.equal(command, "copy");
    fallbacks.push(document.querySelector("textarea[readonly]")?.value);
    return true;
  };
  Object.defineProperty(globalThis, "document", { configurable: true, value: document });
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: { clipboard: { writeText: (text) => { submitted.push(text); return native; } } } });
  ui.context.copyText = copyText;
  try {
    const pending = ui.click("journal-log-copy");
    if (clear) {
      ui.click("journal-log-clear");
      ui.clearDecision().onDiscard();
    }
    reject(new Error("NotAllowedError"));
    const copied = await pending;
    assert.deepEqual(submitted, [visible], "the native write was already submitted before Clear");
    assert.deepEqual(fallbacks, clear ? [] : [visible], "an invalidated source must never start a second clipboard write");
    assert.equal(copied, !clear);
    assert.equal(document.querySelector("textarea[readonly]"), null);
    assert.deepEqual(ui.feedback, clear ? ["dirty"] : ["copied"]);
    assert.equal(ui.journal.log.at(-1).action, clear ? "clear" : "copy");
  } finally {
    if (originalDocument) Object.defineProperty(globalThis, "document", originalDocument);
    else delete globalThis.document;
    if (originalNavigator) Object.defineProperty(globalThis, "navigator", originalNavigator);
    else delete globalThis.navigator;
  }
});

for (const protectedJournal of [true, false]) test(`Activity download uses the current Journal envelope with password protection ${protectedJournal}`, async () => {
  const ui = activityHarness();
  ui.keys.passwordProtected = protectedJournal;
  const run = ui.button.onclick();
  assert.equal(ui.seals.length, 1, "the Activity action bypassed the protected section export path");
  assert.deepEqual(ui.seals[0], ["session-log", "2026-10-22 09:08:07\timported\tnote  imported private recovery text", ui.keys]);
  assert.deepEqual(ui.downloads, [], "Activity plaintext downloaded before the Journal envelope was ready");
  ui.resolve({ sealed: "opaque ciphertext" });
  await run;
  assert.equal(ui.downloads.length, 1);
  assert.equal(ui.downloads[0][0], "entropylab-debug-log.encrypted.json");
  assert.ok(!ui.downloads[0][1].includes("imported private recovery text"));
});

test("Activity download refuses a closed Journal", async () => {
  const ui = activityHarness({ unlocked: false });
  await ui.button.onclick();
  assert.deepEqual(ui.seals, []);
  assert.deepEqual(ui.downloads, []);
  assert.equal(ui.effects[0]?.[0], "error");
});

for (const result of ["success", "failure"]) test(`Activity download drops stale encryption ${result} after Journal replacement`, async () => {
  const ui = activityHarness(), run = ui.button.onclick();
  assert.equal(ui.seals.length, 1, "Activity did not start the Journal encryption helper");
  ui.context.hodlJournalGeneration++;
  ui.context.hodlJournalKeys = { passwordProtected: false };
  ui.effects.length = 0;
  if (result === "success") ui.resolve({ sealed: "opaque ciphertext" });
  else ui.reject(new Error("old Journal encryption failed"));
  await assert.doesNotReject(run);
  assert.deepEqual(ui.downloads, []);
  assert.deepEqual(ui.effects, []);
});

for (const action of ["section", "keys"]) test(`${action} export refuses a closed Journal before encryption`, async () => {
  const ui = harness({ unlocked: false });
  const run = action === "section" ? ui.context.hodlJournalDownloadContent("notebook", "notes.json", "private notes") : ui.context.hodlKeyManagerDownload();
  // Let even the old implementation settle so a missing guard is measured
  // by encryption/download calls rather than an unresolved fixture promise.
  ui.resolve({ sealed: "opaque ciphertext" });
  await Promise.resolve(run).catch(() => {});
  assert.equal(ui.seals.length, 0, "a closed Journal started encryption");
  assert.equal(ui.downloads.length, 0, "a closed Journal exported content");
});

for (const action of ["section", "keys"]) for (const result of ["success", "failure"]) {
  test(`${action} export drops a stale encryption ${result} without download or UI effects`, async () => {
    const ui = harness();
    const run = action === "section" ? ui.context.hodlJournalDownloadContent("notebook", "notes.json", "private notes") : ui.context.hodlKeyManagerDownload();
    assert.equal(ui.seals.length, 1);
    ui.context.hodlJournalGeneration++;
    ui.effects.length = 0;
    if (result === "success") ui.resolve({ sealed: "opaque ciphertext" });
    else ui.reject(new Error("stale encryption failure"));
    await assert.doesNotReject(run, "a stale export leaked its failure after teardown");
    assert.deepEqual(ui.downloads, [], "a stale export still downloaded");
    assert.deepEqual(ui.effects, [], "a stale export changed the new session's UI");
  });
}

for (const selected of [["1"], []]) test(`key export includes all inputs with ${selected.length} old selections`, async () => {
  const ui = harness({ selected });
  const run = ui.context.hodlKeyManagerDownload();
  assert.equal(ui.seals.length, 1);
  assert.equal(ui.seals[0][0], "key-manager");
  assert.equal(ui.seals[0][2], ui.keys);
  const vault = JSON.parse(ui.seals[0][1]);
  assert.deepEqual(vault.keys.map((entry) => entry.name), ["First", "Second"]);
  assert.deepEqual(vault.ignoredKeys.map((entry) => entry.name), ["Archived"]);
  assert.deepEqual([...ui.context.hodlKeyManagerIds], selected, "export changed old selection state");
  ui.resolve({ sealed: "opaque ciphertext" });
  await run;
  assert.equal(ui.downloads.length, 1);
});

test("an archived-only key collection remains exportable", async () => {
  const ui = harness({ states: [], selected: [] });
  const run = ui.context.hodlKeyManagerDownload();
  assert.equal(ui.seals.length, 1, "archived inputs were omitted from export");
  const vault = JSON.parse(ui.seals[0][1]);
  assert.deepEqual(vault.keys, []);
  assert.deepEqual(vault.ignoredKeys.map((entry) => entry.name), ["Archived"]);
  ui.resolve({ sealed: "opaque ciphertext" });
  await run;
  assert.equal(ui.downloads.length, 1);
});

function importHarness(keys = {}) {
  const messages = [];
  const journal = createJournal();
  const context = vm.createContext({
    hodlJournal: journal, hodlJournalKeys: keys, hodlJournalGeneration: 0,
    hodlKeyManagerFileRequest: 0, hodlKeyVaultMaxKeys: KEY_VAULT_MAX_KEYS,
    hodlActiveDerivation: null, hodlJournalKeyDerivation: null,
    hodlJournalDirty: false, hodlJournalBackupRevision: 0,
    hodlJournalMaxFileLength: JOURNAL_MAX_FILE_LENGTH,
    hodlWorkspace: "journal", hodlJournalTool: "notes",
    hodlJournalUnlocked: () => true,
    hodlJournalAppend: appendLog,
    hodlJournalNoteText: () => "",
    hodlScheduleJournalStateRefresh() {}, hodlRenderJournalLog() {},
    hodlJournalOpenExport: openExport,
    hodlJournalFromPlainText: journalFromPlainText,
    hodlParseNotebook: parseNotebook, hodlMergeNotebookImport: mergeNotebookImport,
    hodlJournalStoreNotesText() {}, hodlRenderJournalPageTabs() {}, hodlJournalRestorePage() {},
    hodlJournalSetStatus: (text, error) => messages.push({ text, error }),
    hodlKeyManagerStatus: (text, error) => messages.push({ text, error }),
    hodlKeyManagerPending: [], hodlKeyManagerIgnored: [], hodlKeyManagerIds: new Set(), hodlKeyManagerActiveId: "",
    hodlKeyManagerImportedState: (entry) => ({ ...entry, id: 1 }),
    hodlKeyManagerStates: () => [], hodlKeyManagerRender() {}, keyVaultIdentity, parseKeyVault,
    hodlTText: (text) => text,
    document: { getElementById: () => null },
  });
  vm.runInContext(["hodlJournalImportFile", "hodlKeyManagerImportFile", "hodlKeyManagerCapacityError", "hodlJournalLog", "hodlJournalMarkDirty"].map(extract).join("\n"), context);
  return { context, journal, messages };
}

// The accepted payload is a literal maximum-length text field, independent
// of the encryption implementation. Both real export and UI import must
// preserve it; the envelope's shared cap remains enforced before file reads.
for (const kind of ["notebook", "key-manager"]) test(`${kind} UI imports its valid encrypted export above the old 2 MiB cap`, async () => {
  const text = "x".repeat(1024 * 1024);
  const journal = createJournal();
  journal.pages[0].notesText = text;
  const content = kind === "notebook" ? serializeNotebook(journal)
    : serializeKeyVault([{ name: "Large imported input", fields: { seed: text } }]);
  const keys = await deriveJournalKeys("fixture password", JOURNAL_MIN_ITERATIONS);
  const exported = JSON.stringify(await sealExport(kind, content, keys), null, 2) + "\n";
  assert.ok(Buffer.byteLength(exported) > 2 * 1024 * 1024);
  assert.ok(Buffer.byteLength(exported) <= JOURNAL_MAX_FILE_LENGTH);
  const ui = importHarness(keys);
  const file = { name: "export.json", size: Buffer.byteLength(exported), text: async () => exported };
  await ui.context[kind === "notebook" ? "hodlJournalImportFile" : "hodlKeyManagerImportFile"](file);
  assert.equal(ui.messages.some((message) => message.error), false, "a valid exported file was refused");
  assert.equal(kind === "notebook" ? ui.journal.pages[0].notesText : ui.context.hodlKeyManagerPending[0]?.fields.seed, text);
  assert.equal(ui.context.hodlJournalDirty, true, "the installed content needs a new complete backup");
});

for (const name of ["hodlJournalImportFile", "hodlKeyManagerImportFile"]) {
  test(`${name} refuses oversized files before reading or changing saved content`, async () => {
    const ui = importHarness();
    let read = false;
    await ui.context[name]({ size: JOURNAL_MAX_FILE_LENGTH + 1, text: async () => { read = true; return ""; } });
    assert.equal(read, false);
    assert.equal(ui.messages.at(-1)?.error, true);
    assert.equal(ui.context.hodlJournalDirty, false, "a refused import changed backup status");
  });
  test(`${name} preserves saved content when the picker is canceled or a file fails`, async () => {
    const ui = importHarness();
    await ui.context[name](undefined);
    assert.equal(ui.context.hodlJournalDirty, false);
    await ui.context[name]({ name: "invalid.json", size: 6, text: async () => "broken" });
    assert.equal(ui.messages.at(-1)?.error, true);
    assert.equal(ui.context.hodlJournalDirty, false, "a failed import changed backup status");
    assert.equal(ui.context.hodlJournalBackupRevision, 0);
  });
}

test("opening a Journal file picker does not count as a content mutation", () => {
  const ui = importHarness();
  const map = source.match(/^var hodlJournalAuditedClicks = \{[^]*?^};/m)?.[0];
  assert.ok(map);
  vm.runInContext(map + "\n" + extract("hodlJournalAuditedClick"), ui.context);
  for (const id of ["journal-notes-upload", "journal-keymanager-upload"]) {
    const audited = ui.context.hodlJournalAuditedClick({ id, matches: () => false });
    if (audited) ui.context.hodlJournalLog(audited[1], audited[2], audited[0]);
    assert.equal(ui.context.hodlJournalDirty, false, "canceling the picker would leave a false unsaved state");
  }
});

test("Notes download reports serialization failure without a download or rejected event handler", async () => {
  const button = {}, messages = [], downloads = [];
  const context = vm.createContext({
    notesText: { value: "oversized notes remain editable" },
    document: { getElementById: () => button },
    hodlJournal: createJournal(), hodlJournalStoreNotesText() {},
    hodlSerializeNotebook() { throw new Error("notebook boundary rejected"); },
    hodlJournalSetStatus: (...args) => messages.push(args),
    hodlJournalError: (...args) => messages.push(args),
    hodlJournalDownloadContent: (...args) => downloads.push(args), hodlTText: (text) => text,
  });
  const listener = source.slice(source.indexOf('  let notesDownload = document.getElementById("journal-notes-download");'), source.indexOf('  let notesFile = document.getElementById("journal-notes-file")'));
  vm.runInContext(listener, context);
  await assert.doesNotReject(() => button.onclick());
  assert.equal(downloads.length, 0);
  assert.equal(messages.at(-1)?.[0], "notebook boundary rejected");
  assert.equal(context.notesText.value, "oversized notes remain editable");
});

function reportHarness({ unlocked = true } = {}) {
  const opened = [], shown = [], errors = [], clears = [];
  const requests = [], journal = createJournal(), keys = { fixture: "current Journal key handle" };
  journal.log = [{ at: "2026-10-22 09:08:07", tool: "journal", action: "fixture", detail: "" }];
  const fileInput = { value: "report.encrypted.json" }, opener = {};
  const viewer = { show: (report) => shown.push({ ...report }), clear: (options) => clears.push(options) };
  const context = vm.createContext({
    hodlJournal: journal, hodlJournalKeys: keys, hodlJournalGeneration: 0,
    hodlJournalReportRequest: 0, hodlJournalReportViewer: viewer,
    hodlJournalMaxFileLength: JOURNAL_MAX_FILE_LENGTH,
    hodlJournalUnlocked: () => unlocked,
    hodlJournalOpenExport: (text, usedKeys) => {
      opened.push([text, usedKeys]);
      return new Promise((resolve, reject) => requests.push({ resolve, reject }));
    },
    hodlJournalError: (error) => errors.push(error), hodlTText: (text) => text,
    document: { getElementById: (id) => id === "journal-report-file" ? fileInput : opener },
  });
  vm.runInContext(["hodlJournalOpenReportFile", "hodlJournalClearReport"].map(extract).join("\n"), context);
  return { context, journal, keys, opened, shown, errors, clears, requests, fileInput, opener };
}
const reportFile = { size: 16, text: async () => "encrypted report" };

for (const kind of ["session-state", "session-log"]) test(`${kind} report opens read-only using the current Journal keys and releases temporary plaintext`, async () => {
  const ui = reportHarness(), before = JSON.stringify(ui.journal), payload = { kind, content: "literal private report <script>" };
  const run = ui.context.hodlJournalOpenReportFile(reportFile);
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(ui.opened, [["encrypted report", ui.keys]]);
  ui.requests[0].resolve(payload);
  await run;
  assert.deepEqual(ui.shown, [{ kind, content: "literal private report <script>", opener: ui.opener }]);
  assert.equal(payload.content, "", "the temporary decrypted object retained its plaintext");
  assert.equal(JSON.stringify(ui.journal), before, "viewing a report changed notebook, snapshot, or Activity state");
});

for (const failure of ["closed", "oversized"]) test(`report opening refuses ${failure} before reading or decrypting`, async () => {
  const ui = reportHarness({ unlocked: failure !== "closed" });
  let reads = 0;
  await ui.context.hodlJournalOpenReportFile({ size: failure === "oversized" ? JOURNAL_MAX_FILE_LENGTH + 1 : 16, text: async () => { reads++; return "encrypted report"; } });
  assert.equal(reads, 0);
  assert.deepEqual(ui.opened, []);
  assert.deepEqual(ui.shown, []);
  assert.ok(ui.errors.at(-1));
});

for (const kind of ["notebook", "key-manager", "unknown"]) test(`report opening rejects ${kind} without installing its contents`, async () => {
  const ui = reportHarness(), before = JSON.stringify(ui.journal), payload = { kind, content: "private rejected payload" };
  const run = ui.context.hodlJournalOpenReportFile(reportFile);
  await new Promise((resolve) => setImmediate(resolve));
  ui.requests[0].resolve(payload);
  await run;
  assert.deepEqual(ui.shown, []);
  assert.ok(ui.errors.at(-1));
  assert.equal(payload.content, "");
  assert.equal(JSON.stringify(ui.journal), before);
});

test("a report decryption error is shown without exposing or installing content", async () => {
  const ui = reportHarness(), run = ui.context.hodlJournalOpenReportFile(reportFile);
  await new Promise((resolve) => setImmediate(resolve));
  ui.requests[0].reject(new Error("fixture password mismatch"));
  await run;
  assert.equal(ui.errors.at(-1), "fixture password mismatch");
  assert.deepEqual(ui.shown, []);
});

for (const boundary of ["read", "decrypt"]) for (const outcome of ["success", "failure"]) test(`report ${boundary} ${outcome} cannot revive a cleared or concealed report`, async () => {
  const ui = reportHarness();
  let resolveRead, rejectRead;
  const read = new Promise((resolve, reject) => { resolveRead = resolve; rejectRead = reject; });
  const run = ui.context.hodlJournalOpenReportFile(boundary === "read" ? { size: 16, text: () => read } : reportFile);
  await new Promise((resolve) => setImmediate(resolve));
  ui.context.hodlJournalClearReport();
  ui.errors.length = 0;
  const payload = { kind: "session-log", content: "stale private text" };
  if (boundary === "read") outcome === "success" ? resolveRead("old encrypted report") : rejectRead(new Error("old read failed"));
  else outcome === "success" ? ui.requests[0].resolve(payload) : ui.requests[0].reject(new Error("old decrypt failed"));
  await run;
  assert.deepEqual(ui.shown, []);
  assert.deepEqual(ui.errors, []);
  assert.equal(ui.fileInput.value, "");
  assert.equal(ui.clears.length, 1);
  if (boundary === "read") assert.deepEqual(ui.opened, []);
  else if (outcome === "success") assert.equal(payload.content, "");
});

test("a newer report request and a changed Journal generation retire older decrypted results", async () => {
  const ui = reportHarness(), first = ui.context.hodlJournalOpenReportFile(reportFile);
  await new Promise((resolve) => setImmediate(resolve));
  const second = ui.context.hodlJournalOpenReportFile(reportFile);
  await new Promise((resolve) => setImmediate(resolve));
  const old = { kind: "session-log", content: "old private text" };
  ui.requests[0].resolve(old);
  await first;
  assert.equal(old.content, "");
  assert.deepEqual(ui.shown, []);
  ui.context.hodlJournalGeneration++;
  const stale = { kind: "session-state", content: "different session private text" };
  ui.requests[1].resolve(stale);
  await second;
  assert.equal(stale.content, "");
  assert.deepEqual(ui.shown, []);
});

test("report opening reads actual protected envelopes, and rejects other passwords and plaintext", async () => {
  const ui = reportHarness(), keys = await deriveJournalKeys("report fixture password", JOURNAL_MIN_ITERATIONS);
  ui.context.hodlJournalKeys = keys;
  ui.context.hodlJournalOpenExport = openExport;
  for (const kind of ["session-state", "session-log"]) {
    const content = "literal report fixture <script>\nwith preserved whitespace  ";
    const encoded = JSON.stringify(await sealExport(kind, content, keys));
    await ui.context.hodlJournalOpenReportFile({ size: Buffer.byteLength(encoded), text: async () => encoded });
    assert.deepEqual(ui.shown.at(-1), { kind, content, opener: ui.opener });
  }
  const otherKeys = await deriveJournalKeys("different fixture password", JOURNAL_MIN_ITERATIONS);
  const wrong = JSON.stringify(await sealExport("session-log", "wrong password report", otherKeys));
  for (const encoded of [wrong, "unencrypted report", '{"kind":"session-log","content":"unsealed report"}']) {
    await ui.context.hodlJournalOpenReportFile({ size: Buffer.byteLength(encoded), text: async () => encoded });
    assert.equal(ui.shown.length, 2, "an unprotected or differently protected report reached the viewer");
    assert.ok(ui.errors.at(-1));
  }
});

test("the report controls wire file opening and teardown for conceal, pagehide, and Journal clear", async () => {
  const ui = reportHarness(), listeners = new Map();
  let pickerClicks = 0;
  ui.fileInput.click = () => { pickerClicks++; };
  ui.fileInput.files = [reportFile];
  ui.context.document.addEventListener = (type, listener) => listeners.set(`document:${type}`, listener);
  ui.context.addEventListener = (type, listener) => listeners.set(`window:${type}`, listener);
  const start = source.indexOf('  let reportFile = document.getElementById("journal-report-file")');
  const end = source.indexOf("  // The snapshot must follow", start);
  vm.runInContext(source.slice(start, end), ui.context);
  ui.opener.onclick();
  assert.equal(pickerClicks, 1);
  for (const type of ["document:hodl:conceal", "window:pagehide"]) {
    const run = ui.fileInput.onchange();
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(typeof listeners.get(type), "function");
    listeners.get(type)();
    const payload = { kind: "session-log", content: "concealed pending report" };
    ui.requests.at(-1).resolve(payload);
    await run;
    assert.equal(payload.content, "");
    assert.deepEqual(ui.shown, []);
    assert.equal(ui.fileInput.value, "");
  }
  Object.assign(ui.context, { hodlJournalDoc: null, hodlJournalSetGateBusy() {}, hodlJournalWipeDocument() {} });
  vm.runInContext(extract("hodlJournalWipeNotebook"), ui.context);
  const before = ui.clears.length;
  ui.context.hodlJournalWipeNotebook();
  assert.equal(ui.clears.length, before + 1, "clearing the Journal left the report viewer alive");
  assert.equal(ui.context.hodlJournalKeys, null);
});

test("report privacy changes bypass the global content audit while real settings still log", () => {
  const listeners = new Map(), events = [];
  class Input { constructor(id) { this.id = id; this.type = "checkbox"; this.checked = true; } }
  const context = vm.createContext({
    HTMLInputElement: Input, HTMLSelectElement: class {}, HTMLTextAreaElement: class {},
    hodlJournalActionAuditReady: false, hodlJournalSuppressSettingAudit: false,
    document: { addEventListener: (type, listener) => listeners.set(type, listener) },
    hodlJournalLog: (...args) => events.push(args),
  });
  vm.runInContext(["hodlJournalSettingDetail", "hodlJournalControlTool", "hodlInitJournalActionAudit"].map(extract).join("\n"), context);
  context.hodlInitJournalActionAudit();
  for (const checked of [true, false]) {
    const control = new Input("journal-report-reveal");
    control.checked = checked;
    listeners.get("change")({ target: control });
  }
  assert.deepEqual(events, [], "viewing report text changed the Journal's Activity and dirty state");
  listeners.get("change")({ target: new Input("journal-fixture-setting") });
  assert.deepEqual(events, [["setting", "journal-fixture-setting=on", "journal"]]);
});
