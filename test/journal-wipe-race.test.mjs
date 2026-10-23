// Issue #389: the asynchronous Journal unlock/create used to install the
// decrypted notebook unconditionally when it completed. Clearing the wallet
// secrets mid-decryption (the Clear button, or the lifecycle handler, both of
// which run hodlJournalWipeMem) left the Journal locked only until the
// pending decryption resolved — then the keys and entries came straight back.
// A session generation counter now invalidates pending operations on every
// notebook teardown, and the obsolete completion wipes what it decrypted.
//
// The real app.js functions run under a stub DOM; the real journal.js crypto
// runs against a low-cost test file (the on-disk iteration floor is honored).
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  JOURNAL_MAX_FILE_LENGTH,
  JOURNAL_MIN_ITERATIONS,
  addEntry,
  createDocument,
  createJournal,
  deriveJournalKeys,
  emptyDocument,
  openDocument,
  mergeLogHistory,
  sealDocument,
  wipeBytes,
  wipeDocument,
  wipeJournal,
} from "../src/js/journal.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");

function loadSlice(name) {
  let start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  if (app.slice(start - 6, start) === "async ") start -= 6;
  let depth = 0;
  let end = -1;
  for (let i = app.indexOf("{", start); i < app.length; i++) {
    if (app[i] === "{") depth++;
    else if (app[i] === "}") {
      depth--;
      if (depth === 0) {
        end = i + 1;
        break;
      }
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

const source = [
  varLine("hodlJournalKeys"),
  varLine("hodlJournalGeneration"),
  varLine("hodlJournalUnlockBusy"),
  varLine("hodlJournalFileRead"),
  varLine("hodlJournalTool"),
  varLine("hodlJournalKeyDerivation"),
  varLine("hodlJournalReportViewer"),
  loadSlice("hodlJournalClearReport"),
  loadSlice("hodlJournalActivePage"),
  loadSlice("hodlJournalStartPage"),
  loadSlice("hodlJournalError"),
  loadSlice("hodlJournalSetGateBusy"),
  loadSlice("hodlJournalWipeNotebook"),
  loadSlice("hodlJournalDiscardOpened"),
  loadSlice("hodlJournalChooseFile"),
  loadSlice("hodlJournalUnlock"),
  loadSlice("hodlJournalCreate"),
  loadSlice("hodlJournalWipeMem"),
].join("\n");

const PASSWORD = "correct horse battery staple";
const FIRST_NOTE_STAMP = "2026-10-22 09:08:07";
const noop = () => {};

// Every DOM and cross-module touch the sliced functions make, stubbed neutral.
const loadApp = ({ onOpen = (file, password) => openDocument(file, password), onCreate = (password, confirm) => createDocument(password, confirm) } = {}) => {
  const journal = createJournal(), stamps = [];
  const fields = {
    "journal-open-password": { value: PASSWORD },
    "journal-create-password": { value: PASSWORD },
    "journal-create-confirm": { value: PASSWORD },
    "journal-file": { value: "" },
    "journal-error": { textContent: "" },
  };
  const documentStub = { getElementById: (id) => fields[id] ?? null };
  const api = new Function(
    "wipeJournal", "hodlJournal", "hodlJournalWipeDocument", "hodlJournalWipeBytes",
    "hodlJournalOpenDocument", "hodlJournalCreateDocument", "hodlJournalMaxFileLength", "document",
    "hodlKeyManagerReset", "hodlJournalClearFields", "hodlJournalHideEditor", "hodlJournalSetGate",
    "hodlJournalShowWork", "hodlSyncJournalTool",
    "hodlRenderJournalPageTabs", "hodlJournalApplyPageStyle", "hodlJournalSetStatus",
    "hodlShowJournalTool", "hodlJournalLog", "hodlTText", "hodlKeyManagerCancelDerivation", "hodlJournalStamp",
    "hodlJournalCheckInventory", "hodlJournalMergeLogHistory",
    `${source}; return {
      choose: hodlJournalChooseFile,
      unlock: hodlJournalUnlock,
      create: hodlJournalCreate,
      wipeMem: hodlJournalWipeMem,
      setFileText: (text) => { hodlJournalFileText = text; },
      state: () => ({ keys: hodlJournalKeys, doc: hodlJournalDoc }),
    };`,
  )(
    wipeJournal, journal, wipeDocument, wipeBytes,
    onOpen, onCreate, JOURNAL_MAX_FILE_LENGTH, documentStub,
    noop, noop, noop, noop,
    noop, noop,
    noop, noop, noop,
    noop, noop,
    (text) => text, noop, () => { stamps.push(FIRST_NOTE_STAMP); return FIRST_NOTE_STAMP; },
    noop, mergeLogHistory,
  );
  return { ...api, journal, stamps, error: () => fields["journal-error"].textContent };
};

// An encrypted test notebook holding one seed entry, at the on-disk iteration
// floor so the test stays fast.
const fileText = await (async () => {
  const keys = await deriveJournalKeys(PASSWORD, JOURNAL_MIN_ITERATIONS);
  const doc = emptyDocument();
  addEntry(doc, { method: "seed", input: "", phrase: "abandon ".repeat(11).trim() + " about", label: "seed entry" });
  return JSON.stringify(await sealDocument(doc, keys));
})();

test("an unlock that completes after a wipe discards the decrypted notebook (issue #389)", async () => {
  let captured = null;
  const env = loadApp({
    onOpen: async (file, password) => {
      const opened = await openDocument(file, password);
      captured = opened;
      return opened;
    },
  });
  env.setFileText(fileText);
  const pending = env.unlock(); // decryption is in flight once this returns
  env.wipeMem(); // the Clear button and the lifecycle handler both run this
  await pending;
  assert.deepEqual(env.state(), { keys: null, doc: null }, "the journal stays locked");
  assert.ok(captured, "decryption did complete");
  assert.equal(captured.doc.entries.length, 0, "the discarded document was wiped, not kept");
});

test("an undisturbed unlock still installs the notebook", async () => {
  let captured = null;
  const env = loadApp({
    onOpen: async (file, password) => {
      const opened = await openDocument(file, password);
      captured = opened;
      return opened;
    },
  });
  env.setFileText(fileText);
  await env.unlock();
  assert.ok(env.state().keys && env.state().doc, "unlocked");
  assert.equal(env.state().doc.entries.length, 1);
  assert.equal(env.state().doc.entries[0].label, "seed entry");
  assert.ok(captured.keys, "the discarded keys object still existed to be dropped");
  assert.equal(env.journal.notesText, "", "opening a legacy Journal must preserve its empty Notes page");
  assert.equal(env.journal.pages[0].notesText, "");
  assert.equal(env.journal.pages[0].pendingStamp, undefined, "opening must not turn an imported page into a live note");
  assert.deepEqual(env.stamps, []);
});

test("a create that completes after a wipe discards the new notebook (issue #389)", async () => {
  let captured = null;
  const env = loadApp({
    onCreate: async (password, confirm) => {
      const created = await createDocument(password, confirm);
      captured = created;
      return created;
    },
  });
  const pending = env.create();
  env.wipeMem();
  await pending;
  assert.deepEqual(env.state(), { keys: null, doc: null }, "the journal stays locked");
  assert.ok(captured, "the create did complete and its keys object was dropped");
  assert.equal(env.journal.notesText, "", "a stale creation must not repopulate the wiped notes");
  assert.equal(env.journal.pages[0].notesText, "");
  assert.equal(env.journal.pages[0].pendingStamp, undefined);
  assert.deepEqual(env.stamps, []);
});

test("an undisturbed create installs the notebook with its first live timestamp", async () => {
  const env = loadApp();
  await env.create();
  assert.ok(env.state().keys && env.state().doc, "unlocked");
  assert.equal(env.state().doc.entries.length, 0);
  assert.equal(env.journal.pages.length, 1);
  assert.equal(env.journal.notesText, `${FIRST_NOTE_STAMP}  `);
  assert.equal(env.journal.pages[0].notesText, env.journal.notesText);
  assert.deepEqual(env.journal.pages[0].pendingStamp, { start: 0, stamp: FIRST_NOTE_STAMP });
  assert.deepEqual(env.stamps, [FIRST_NOTE_STAMP]);
});

test("a stale unlock cannot displace a freshly opened session", async () => {
  const env = loadApp();
  env.setFileText(fileText);
  const first = env.unlock();
  await first;
  assert.ok(env.state().keys, "first session open");
  // The second unlock's own pre-install teardown invalidates the first; a
  // late completion of either side must leave exactly one live session.
  env.setFileText(fileText);
  const second = env.unlock();
  env.wipeMem();
  await second;
  assert.deepEqual(env.state(), { keys: null, doc: null }, "the wiped session stays gone");
});

// #889: choosing a journal file starts an asynchronous read, and Open must act
// on the file chosen last, however that read interleaves with the click.
// Contract: Open never reports "no file" for a chosen file whose read is
// pending; a file chosen while Open waits replaces the read it waits for; a
// reset while it waits cancels it without writing any error; and only the
// newest choice's read failure is reported. The reads are controlled promises
// so each interleaving is exact.
const pendingFile = () => {
  let resolve, reject;
  const promise = new Promise((ok, fail) => { resolve = ok; reject = fail; });
  return { file: { text: () => promise }, resolve, reject };
};
const settle = () => new Promise((resolve) => setImmediate(resolve));

test("Open waits for a pending file read instead of reporting no file (#889)", async () => {
  const env = loadApp();
  const a = pendingFile();
  env.choose(a.file);
  const pending = env.unlock();
  await settle();
  assert.equal(env.error(), "", "no error while the read is pending");
  a.resolve(fileText);
  await pending;
  assert.equal(env.error(), "");
  assert.equal(env.state().doc?.entries[0]?.label, "seed entry", "unlocked");
});

test("a file chosen while Open waits replaces the read it waits for (#889)", async () => {
  let opened = null;
  const env = loadApp({ onOpen: (file, password) => { opened = file; return openDocument(file, password); } });
  const a = pendingFile(), b = pendingFile();
  env.choose(a.file);
  const pending = env.unlock();
  env.choose(b.file);
  a.resolve("the replaced choice");
  await settle();
  assert.equal(env.error(), "", "the replaced read reports nothing");
  assert.equal(opened, null, "nothing is opened from the replaced read");
  b.resolve(fileText);
  await pending;
  assert.equal(env.error(), "");
  assert.equal(opened, fileText, "the newest choice is the one opened");
  assert.equal(env.state().doc?.entries[0]?.label, "seed entry", "unlocked");
});

test("a reset while Open waits cancels it without a late error (#889)", async () => {
  const env = loadApp();
  const a = pendingFile();
  env.choose(a.file);
  const pending = env.unlock();
  env.wipeMem(); // the Clear button and the lifecycle handler both run this
  a.resolve(fileText);
  await pending;
  assert.equal(env.error(), "", "the cancelled Open writes no error");
  assert.deepEqual(env.state(), { keys: null, doc: null }, "the journal stays locked");
});

test("only the newest choice's read failure is reported (#889)", async () => {
  const env = loadApp();
  const a = pendingFile(), b = pendingFile();
  env.choose(a.file);
  const pending = env.unlock();
  env.choose(b.file);
  a.reject(new Error("the replaced file could not be read"));
  await settle();
  assert.equal(env.error(), "", "the replaced read's failure is not reported");
  b.reject(new Error("the chosen file could not be read"));
  await pending;
  assert.equal(env.error(), "the chosen file could not be read");
  assert.deepEqual(env.state(), { keys: null, doc: null }, "the journal stays locked");
});
