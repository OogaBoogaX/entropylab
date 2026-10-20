// Audit finding L6: a passwordless journal envelope is keyed by PBKDF2 over
// the empty password with a public fixed salt, so anyone can forge a file the
// open path accepts. The create flow already makes the user acknowledge a
// passwordless journal ("Ready to create without a password"); the open flow
// accepted a passwordless file silently. Opening without a password now
// requires one explicit acknowledgement before the entries are installed:
// the first press of "Open journal" reveals the no-protection notice and
// installs nothing; the second press on the same file completes the open.
// Choosing a different file or wiping the journal forgets a pending
// acknowledgement. Password-protected opens are unchanged — AES-GCM
// already fails closed on forged files, wrong passwords, and iterations
// tampering.
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
  deriveJournalKeys,
  emptyDocument,
  openDocument,
  sealDocument,
  wipeBytes,
  wipeDocument,
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

const varLine = (name) => {
  const line = app.match(new RegExp(`var ${name} = [^\\n]+;`)) || app.match(new RegExp(`var hodlJournalKeys = null, hodlJournalDoc = null[^\\n]*;`));
  assert.ok(line, `var ${name}`);
  return line[0];
};

const source = [
  varLine("hodlJournalKeys"),
  varLine("hodlJournalDoc"),
  varLine("hodlJournalFileText"),
  varLine("hodlJournalOpenReadyFor"),
  varLine("hodlJournalUnlockBusy"),
  varLine("hodlJournalGeneration"),
  varLine("hodlJournalFileRead"),
  varLine("hodlJournalTool"),
  loadSlice("hodlJournalError"),
  loadSlice("hodlJournalChooseFile"),
  loadSlice("hodlJournalUnlock"),
  loadSlice("hodlJournalWipeNotebook"),
].join("\n");

const PASSWORD = "correct horse battery staple";
const noop = () => {};

const loadApp = ({ password = "", onOpen = (file, password) => openDocument(file, password) } = {}) => {
  const fields = {
    "journal-open-password": { value: password },
    "journal-error": { textContent: "" },
    "journal-open-ready": { hidden: true },
  };
  const documentStub = { getElementById: (id) => fields[id] ?? null };
  const api = new Function(
    "hodlJournalOpenDocument", "hodlJournalMaxFileLength", "document",
    "hodlJournalWipeDocument", "hodlJournalWipeBytes",
    "hodlKeyManagerReset", "hodlJournalHideEditor",
    "hodlJournalShowWork", "hodlShowJournalTool", "hodlJournalLog",
    "hodlJournalBackfillDerivedKeys", "hodlJournalDiscardOpened",
    `${source}; return {
      choose: hodlJournalChooseFile,
      unlock: hodlJournalUnlock,
      wipe: hodlJournalWipeNotebook,
      setFileText: (text) => { hodlJournalFileText = text; },
      state: () => ({ keys: hodlJournalKeys, doc: hodlJournalDoc }),
      openReadyFor: () => hodlJournalOpenReadyFor,
      openReadyVisible: () => { const el = document.getElementById("journal-open-ready"); return el ? !el.hidden : false; },
    };`,
  )(
    onOpen, JOURNAL_MAX_FILE_LENGTH, documentStub,
    wipeDocument, wipeBytes,
    noop,
    noop, noop, noop,
    noop, noop,
  );
  return { ...api, error: () => fields["journal-error"].textContent };
};

const sealFile = async (password, label) => {
  const keys = await deriveJournalKeys(password, JOURNAL_MIN_ITERATIONS);
  const doc = emptyDocument();
  addEntry(doc, { method: "seed", input: "", phrase: "abandon ".repeat(11).trim() + " about", label });
  return JSON.stringify(await sealDocument(doc, keys));
};

const passwordlessFile = await sealFile("", "passwordless entry");
const otherPasswordlessFile = await sealFile("", "other entry");
const protectedFile = await sealFile(PASSWORD, "protected entry");

assert.notEqual(otherPasswordlessFile, passwordlessFile,
  "the second fixture must differ byte-for-byte — labels sit inside the AES-GCM ciphertext, so a string replace on the sealed envelope would be a no-op");

test("a passwordless file is not installed until the open is acknowledged (audit L6)", async () => {
  const env = loadApp();
  env.setFileText(passwordlessFile);
  await env.unlock();
  assert.deepEqual(env.state(), { keys: null, doc: null }, "the first open installs nothing");
  assert.ok(env.openReadyVisible(), "the no-protection acknowledgement is shown");
  await env.unlock();
  assert.ok(env.state().keys, "the acknowledged open installs the journal");
  assert.ok(!env.openReadyVisible(), "the acknowledgement clears once accepted");
});

test("a double-press cannot open a passwordless file without its acknowledgement (audit L6)", async () => {
  // Two presses before the first decrypt returns both run the open path; the
  // second must not see the first's armed token and install the file. It must
  // also not start a second, redundant decrypt.
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  let opens = 0;
  const env = loadApp({
    onOpen: async (file, password) => {
      opens++;
      await gate;
      return openDocument(file, password);
    },
  });
  env.setFileText(passwordlessFile);
  const first = env.unlock();
  const second = env.unlock();
  release();
  await Promise.all([first, second]);
  assert.equal(opens, 1, "the second press started a second decrypt");
  assert.deepEqual(env.state(), { keys: null, doc: null }, "a concurrent open installed the passwordless file without acknowledgement");
  assert.ok(env.openReadyVisible(), "the acknowledgement row was not armed");
});

test("a password-protected file opens on the first press, as before (audit L6)", async () => {
  const env = loadApp({ password: PASSWORD });
  env.setFileText(protectedFile);
  await env.unlock();
  assert.ok(env.state().keys, "the protected open installs the journal");
  assert.ok(!env.openReadyVisible(), "no acknowledgement is offered for a protected file");
});

test("a fresh file choice resets a pending passwordless acknowledgement (audit L6)", async () => {
  const env = loadApp();
  env.setFileText(passwordlessFile);
  await env.unlock();
  assert.ok(env.openReadyVisible(), "armed for the first file");
  await env.choose({ text: async () => otherPasswordlessFile });
  await new Promise((resolve) => setTimeout(resolve, 0));
  await env.unlock();
  assert.deepEqual(env.state(), { keys: null, doc: null }, "the second file is not installed on its first open");
  assert.ok(env.openReadyVisible(), "the acknowledgement is armed for the new file, not inherited");
});

test("a journal wipe forgets a pending passwordless acknowledgement (audit L6)", async () => {
  const env = loadApp();
  env.setFileText(passwordlessFile);
  await env.unlock();
  assert.ok(env.openReadyVisible(), "armed before the wipe");
  env.wipe();
  assert.ok(!env.openReadyVisible(), "a wipe also hides the acknowledgement row");
  assert.equal(env.openReadyFor(), "", "a wipe drops the armed file bytes");
  env.setFileText(passwordlessFile);
  await env.unlock();
  assert.deepEqual(env.state(), { keys: null, doc: null }, "a wiped session installs nothing without a fresh acknowledgement");
  assert.ok(env.openReadyVisible(), "the acknowledgement must be earned again after a wipe");
});

// The reader caps the decoded text at JOURNAL_MAX_FILE_LENGTH UTF-16 units.
// Reading first and refusing after means an arbitrarily large file is pulled
// into memory; the byte size is checked before file.text() instead. Three
// bytes per unit is the reachable bound, so a file that passes can still be
// refused by the text cap and one that fails could never pass it.
test("an oversized file is refused from its size before text() runs", async () => {
  const env = loadApp();
  let calls = 0;
  const oversized = { size: JOURNAL_MAX_FILE_LENGTH * 3 + 4, text: async () => { calls += 1; return passwordlessFile; } };
  await env.choose(oversized);
  assert.match(env.error(), /too large/);
  assert.equal(calls, 0, "the read must not start");
  const boundary = { size: JOURNAL_MAX_FILE_LENGTH * 3 + 3, text: async () => { calls += 1; return passwordlessFile; } };
  await env.choose(boundary);
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(calls, 1, "the exact byte bound is still read");
  await env.unlock();
  assert.ok(env.openReadyVisible(), "and the file that replaced the refusal opens");
});
