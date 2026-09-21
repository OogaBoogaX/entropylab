// Issue #389: the asynchronous Journal unlock/create used to install the
// decrypted Journal access context unconditionally when it completed. Clearing the wallet
// secrets mid-decryption (the Clear button, or the lifecycle handler, both of
// which run hodlJournalWipeMem) left the Journal locked only until the
// pending decryption resolved — then the keys came straight back.
// A session generation counter now invalidates pending operations on every
// access teardown, and the obsolete completion wipes what it decrypted.
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
  JOURNAL_MIN_ITERATIONS,
  createAccess,
  createJournal,
  deriveJournalKeys,
  openAccessFile,
  sealAccessFile,
  wipeBytes,
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
  varLine("hodlJournalTool"),
  varLine("hodlJournalEncryptDownloads"),
  loadSlice("hodlJournalError"),
  loadSlice("hodlJournalCloseAccess"),
  loadSlice("hodlJournalDiscardOpened"),
  loadSlice("hodlJournalClearFields"),
  loadSlice("hodlJournalUnlock"),
  loadSlice("hodlJournalCreate"),
  loadSlice("hodlJournalWipeMem"),
].join("\n");

const PASSWORD = "correct horse battery staple";
const noop = () => {};

// Every DOM and cross-module touch the sliced functions make, stubbed neutral.
const loadApp = ({ onOpen = (file, password) => openAccessFile(file, password), onCreate = (password, confirm) => createAccess(password, confirm) } = {}) => {
  const fields = {
    "journal-open-password": { value: PASSWORD },
    "journal-create-password": { value: PASSWORD },
    "journal-create-confirm": { value: PASSWORD },
    "journal-file": { value: "" },
  };
  const documentStub = { getElementById: (id) => fields[id] ?? null };
  return new Function(
    "wipeJournal", "hodlJournal", "hodlJournalWipeBytes",
    "hodlJournalOpenAccessFile", "hodlJournalCreateAccess", "document",
    "hodlKeyManagerReset", "hodlJournalSetGate",
    "hodlJournalSyncEncryptDownloads", "hodlSyncJournalAccess", "hodlSyncJournalTool",
    "hodlRenderJournalPageTabs", "hodlJournalApplyPageStyle", "hodlJournalSetStatus",
    "hodlJournalLog", "hodlJournalResetPendingNote",
    `${source}; return {
      unlock: hodlJournalUnlock,
      create: hodlJournalCreate,
      wipeMem: hodlJournalWipeMem,
      setFileText: (text) => { hodlJournalFileText = text; },
      state: () => ({ keys: hodlJournalKeys }),
    };`,
  )(
    wipeJournal, createJournal(), wipeBytes,
    onOpen, onCreate, documentStub,
    noop, noop,
    noop, noop, noop,
    noop, noop, noop,
    noop, noop,
  );
};

// An encrypted access file at the on-disk iteration floor so the test stays fast.
const fileText = await (async () => {
  const keys = await deriveJournalKeys(PASSWORD, JOURNAL_MIN_ITERATIONS);
  return JSON.stringify(await sealAccessFile(keys));
})();

test("an unlock that completes after a wipe discards the decrypted access context (issue #389)", async () => {
  let captured = null;
  const env = loadApp({
    onOpen: async (file, password) => {
      const opened = await openAccessFile(file, password);
      captured = opened;
      return opened;
    },
  });
  env.setFileText(fileText);
  const pending = env.unlock(); // decryption is in flight once this returns
  env.wipeMem(); // the Clear button and the lifecycle handler both run this
  await pending;
  assert.deepEqual(env.state(), { keys: null }, "the journal stays locked");
  assert.ok(captured, "decryption did complete");
  assert.ok(captured.keys.verify.every((byte) => byte === 0), "the discarded verify digest was wiped");
});

test("an undisturbed unlock still installs the access context", async () => {
  let captured = null;
  const env = loadApp({
    onOpen: async (file, password) => {
      const opened = await openAccessFile(file, password);
      captured = opened;
      return opened;
    },
  });
  env.setFileText(fileText);
  await env.unlock();
  assert.ok(env.state().keys, "unlocked");
  assert.ok(captured.keys.verify.some((byte) => byte !== 0), "a live session keeps its digest");
});

test("a create that completes after a wipe discards the new access context (issue #389)", async () => {
  let captured = null;
  const env = loadApp({
    onCreate: async (password, confirm) => {
      const created = await createAccess(password, confirm);
      captured = created;
      return created;
    },
  });
  const pending = env.create();
  env.wipeMem();
  await pending;
  assert.deepEqual(env.state(), { keys: null }, "the journal stays locked");
  assert.ok(captured?.keys.verify.every((byte) => byte === 0), "the discarded verify digest was wiped");
});

test("an undisturbed create still installs the access context", async () => {
  const env = loadApp();
  await env.create();
  assert.ok(env.state().keys, "unlocked");
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
  assert.deepEqual(env.state(), { keys: null }, "the wiped session stays gone");
});
