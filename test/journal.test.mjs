import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  JOURNAL_ITERATIONS,
  JOURNAL_LOG_LIMIT,
  JOURNAL_VERSION,
  METHODS,
  addEntry,
  addNote,
  appendLog,
  assertPassword,
  createDocument,
  createJournal,
  deleteNote,
  emptyDocument,
  encodeFile,
  formatLog,
  formatNotes,
  formatStamp,
  openDocument,
  parseFile,
  removeEntry,
  searchEntries,
  sealDocument,
  snapshotFromKeyState,
  snapshotSession,
  updateNote,
  wipeDocument,
  wipeJournal,
} from "../src/js/journal.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

const password = "correct horse battery staple";
const otherPassword = "Tr0ub4dor & 3 ponies";
const fixedNow = new Date("2026-09-01T15:04:05.000Z");
const fill = (length, start = 1) => Uint8Array.from({ length }, (_, i) => (start + i) & 255);

test("formatStamp is local wall-clock, not UTC ISO", () => {
  let stamp = formatStamp(new Date(2026, 8, 2, 9, 5, 7));
  assert.equal(stamp, "2026-09-02 09:05:07");
  assert.doesNotMatch(stamp, /T|Z/);
});

test("notes get incrementing ids and keep the typed time", () => {
  let journal = createJournal();
  let first = addNote(journal, { text: "dice from the kitchen table" }, new Date(2026, 8, 2, 10, 0, 0));
  let second = addNote(journal, { at: "2026-09-02 11:00:00", text: "passphrase hint is the dog" });
  assert.equal(first.id, 1);
  assert.equal(second.id, 2);
  assert.equal(first.at, "2026-09-02 10:00:00");
  assert.equal(journal.notes.length, 2);
  updateNote(journal, 1, { text: "updated" });
  assert.equal(journal.notes[0].text, "updated");
  assert.equal(deleteNote(journal, 1), true);
  assert.equal(journal.notes.length, 1);
  assert.match(formatNotes(journal.notes), /Written: 2026-09-02 11:00:00/);
});

test("the log is a ring buffer and never stores more than the cap", () => {
  let journal = createJournal();
  for (let i = 0; i < JOURNAL_LOG_LIMIT + 5; i++) {
    appendLog(journal, { tool: "calc", action: "derive", detail: `n=${i}` }, new Date(2026, 0, 1, 0, 0, 0));
  }
  assert.equal(journal.log.length, JOURNAL_LOG_LIMIT);
  assert.match(journal.log[0].detail, /n=5/);
  assert.match(formatLog(journal.log), /calc\tderive/);
});

test("a public snapshot names fingerprints and omits secrets unless asked", () => {
  let publicText = snapshotSession({
    capturedAt: "2026-09-02 10:00:00",
    version: "v0.1.3",
    commit: "abc1234",
    includePrivate: false,
    keys: [{ name: "Key Station", derived: false, mode: "dice" }, { name: "a1b2c3d4", derived: true, fingerprint: "a1b2c3d4", sheet: "Master fingerprint: a1b2c3d4\nxpub: xpub123" }],
    msigs: [],
    bip85: [{ name: "child", fingerprint: "deadbeef", app: "BIP-39", secret: "abandon abandon abandon" }],
    sp: { derived: false },
    psbt: { loaded: false },
  });
  assert.match(publicText, /fingerprint a1b2c3d4/);
  assert.doesNotMatch(publicText, /abandon abandon abandon/);
  let privateText = snapshotSession({
    capturedAt: "2026-09-02 10:00:00",
    includePrivate: true,
    keys: [],
    msigs: [],
    bip85: [{ name: "child", fingerprint: "deadbeef", app: "BIP-39", secret: "abandon abandon abandon" }],
    sp: { derived: false },
    psbt: { loaded: false },
  });
  assert.match(privateText, /abandon abandon abandon/);
});

test("wipe drops notes, log, and snapshot text", () => {
  let journal = createJournal();
  addNote(journal, { text: "secret hint" });
  appendLog(journal, { tool: "calc", action: "derive", detail: "fp=aa" });
  journal.stateText = "xprv...";
  wipeJournal(journal);
  assert.equal(journal.notes.length, 0);
  assert.equal(journal.log.length, 0);
  assert.equal(journal.stateText, "");
});

test("the journal module never talks to the network, browser storage, or a CSPRNG", () => {
  const src = read("src/js/journal.js");
  assert.doesNotMatch(src, /\bfetch\s*\(|XMLHttpRequest|WebSocket|\blocalStorage\b|\bsessionStorage\b|indexedDB|Math\.random|crypto\.getRandomValues/);
});

// --- Encrypted entropy notebook (AES-GCM, password-derived, deterministic) ---

test("passwords need real length and a matching confirmation", () => {
  assert.throws(() => assertPassword(""), /missing/);
  assert.throws(() => assertPassword(42), /missing/);
  assert.throws(() => assertPassword("short"), /at least 12/);
  assert.throws(() => assertPassword(password, { confirm: otherPassword }), /do not match/);
  assert.equal(assertPassword(password, { confirm: password }), undefined);
  assert.equal(assertPassword("🐴".repeat(12)), undefined); // length counts characters, not bytes
});

test("the journal never invents entropy or talks to the network", () => {
  const code = read("src/js/journal.js").replace(/\/\/.*$/gm, "");
  assert.doesNotMatch(code, /Math\.random|crypto\.getRandomValues|fetch\b|XMLHttpRequest|WebSocket|localStorage|indexedDB/);
  assert.match(read("src/js/journal.js"), /never calls a CSPRNG/);
  assert.match(read("src/js/journal.js"), /PBKDF2-SHA-256/);
});

test("entries store the raw input, phrase, label, ISO time, and optional wallet link", () => {
  const doc = emptyDocument();
  const entry = addEntry(doc, {
    method: "dice",
    input: "1 2 3 4 5 6",
    phrase: "abandon ability able about above absent absorb abstract absurd abuse access accident",
    label: "Coldcard stash",
    notes: "garage",
    walletId: 3,
    walletName: "aabbccdd",
    fingerprint: "AABBCCDD",
  }, fixedNow);
  assert.equal(entry.id, 1);
  assert.equal(entry.input, "1 2 3 4 5 6");
  assert.equal(entry.created, "2026-09-01T15:04:05.000Z");
  assert.equal(entry.fingerprint, "aabbccdd");
  assert.equal(doc.nextId, 2);
  assert.equal(searchEntries(doc, "stash").length, 1);
  assert.equal(searchEntries(doc, "nope").length, 0);
  removeEntry(doc, 1);
  assert.equal(doc.entries.length, 0);
  assert.throws(() => addEntry(doc, { method: "dice", input: "1", phrase: "x" }, fixedNow), /label/);
  assert.throws(() => addEntry(doc, { method: "nostr", label: "x" }, fixedNow), /method/);
  assert.deepEqual(METHODS, ["dice", "coin", "hex", "brain", "seed", "cards"]);
});

test("a session key snapshot prefers the live dice / brain / seed transcript", () => {
  const dice = snapshotFromKeyState({
    id: 4,
    isLab: false,
    mode: "dice",
    diceMethod: "coldcard",
    name: "deadbeef",
    fields: { dice: "4 1 4 2 6 3" },
    result: { mnemonic: "legal winner thank year wave sausage worth useful legal winner thank yellow", masterFingerprint: "deadbeef" },
  });
  assert.equal(dice.method, "dice");
  assert.equal(dice.input, "4 1 4 2 6 3");
  assert.equal(dice.phrase.startsWith("legal winner"), true);
  assert.equal(dice.walletId, 4);
  const brain = snapshotFromKeyState({
    id: 5,
    isLab: false,
    mode: "key",
    name: "brain",
    fields: { keyKind: "brain", privateKeys: { brain: "correct horse" } },
    result: { mnemonic: "one two three" },
  });
  assert.equal(brain.method, "brain");
  assert.equal(brain.input, "correct horse");
  assert.equal(snapshotFromKeyState({ isLab: true, mode: "dice", fields: { dice: "123" } }), null);
});

test("AES-GCM round-trips with the password and fails on the wrong one", async () => {
  const created = await createDocument(password, password);
  assert.equal(created.doc.entries.length, 0);
  addEntry(created.doc, { method: "hex", input: "ab", phrase: "seed words here", label: "lab" }, fixedNow);
  const file = await sealDocument(created.doc, created.keys);
  assert.equal(file.entropylabJournal, JOURNAL_VERSION);
  assert.equal(file.kdf, "PBKDF2-SHA-256");
  assert.equal(file.iterations, JOURNAL_ITERATIONS);
  assert.equal(file.cipher, "AES-256-GCM");
  assert.equal(file.salt, undefined); // the salt is derived from the password, never stored
  assert.equal(file.iv.length, 24);
  assert.match(file.ciphertext, /^[0-9a-f]+$/);
  const packed = JSON.stringify(file);
  const opened = await openDocument(packed, password);
  assert.equal(opened.doc.entries[0].label, "lab");
  assert.equal(opened.doc.entries[0].input, "ab");
  assert.equal(opened.doc.entries[0].phrase, "seed words here");
  assert.equal(opened.keys.iterations, JOURNAL_ITERATIONS);
  await assert.rejects(() => openDocument(packed, otherPassword), /Wrong password/);
  wipeDocument(opened.doc);
  assert.equal(opened.doc.entries.length, 0);
});

test("encryption is deterministic: same password and entries, same file", async () => {
  const make = async () => {
    const created = await createDocument(password, password);
    addEntry(created.doc, { method: "dice", input: "1 2 3", phrase: "p", label: "same" }, fixedNow);
    return sealDocument(created.doc, created.keys);
  };
  const first = await make();
  const second = await make();
  assert.deepEqual(second, first); // byte-identical — nothing was generated
  // The synthetic IV covers the plaintext: a changed entry means a changed IV.
  const created = await createDocument(password, password);
  addEntry(created.doc, { method: "dice", input: "1 2 3", phrase: "p", label: "same" }, fixedNow);
  const before = await sealDocument(created.doc, created.keys);
  addEntry(created.doc, { method: "dice", input: "4 5 6", phrase: "q", label: "other" }, fixedNow);
  const after = await sealDocument(created.doc, created.keys);
  assert.notEqual(after.iv, before.iv);
  assert.deepEqual(before, first);
});

test("encodeFile stores the IV and iteration count next to the ciphertext", () => {
  const file = encodeFile({ iv: fill(12, 9), ciphertext: fill(32, 4) });
  const parsed = parseFile(JSON.stringify(file));
  assert.equal(parsed.iv.length, 12);
  assert.equal(parsed.ciphertext.length, 32);
  assert.equal(parsed.iterations, JOURNAL_ITERATIONS);
  assert.throws(() => parseFile("{}"), /not an EntropyLab journal/);
  assert.throws(() => parseFile("{"), /not valid JSON/);
  assert.throws(() => parseFile(JSON.stringify({ ...file, iterations: 7 })), /key-derivation cost/);
  assert.throws(() => parseFile(JSON.stringify({ ...file, iterations: 1e12 })), /key-derivation cost/);
  assert.throws(() => encodeFile({ iv: fill(16), ciphertext: fill(32) }), /IV must be 12 bytes/);
});
