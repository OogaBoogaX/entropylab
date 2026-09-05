// Backup drills for the Journal: every way a user backs up and restores —
// the encrypted journal file, the paged notepad, the Key Manager vault, the
// session snapshot, and the session log — plus the failure modes a backup
// must survive (wrong password, tampered bytes, cross-format confusion).
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  IV_BYTES,
  JOURNAL_CIPHER,
  JOURNAL_EXPORT_VERSION,
  JOURNAL_ITERATIONS,
  JOURNAL_KDF,
  JOURNAL_MAX_ITERATIONS,
  JOURNAL_MIN_ITERATIONS,
  JOURNAL_VERSION,
  NOTEBOOK_FORMAT,
  NOTEBOOK_MAX_PAGES,
  NOTEBOOK_MAX_TEXT_LENGTH,
  NOTEBOOK_VERSION,
  addEntry,
  appendLog,
  createDocument,
  createJournal,
  deriveJournalKeys,
  emptyDocument,
  encodeFile,
  formatLog,
  formatNotebook,
  formatNotebookPages,
  journalFromPlainText,
  journalKeyReferenceRanges,
  journalKeyReferenceToken,
  journalNotebookRuns,
  journalTextFromRuns,
  mergeNotebookImport,
  normalizeEntry,
  openDocument,
  openExport,
  parseFile,
  parseNotebook,
  removeEntry,
  replaceEntry,
  sealDocument,
  sealExport,
  searchEntries,
  serializeNotebook,
  snapshotFromKeyState,
  snapshotSession,
  wipeBytes,
  wipeDocument,
  wipeEntry,
} from "../src/js/journal.js";
import {
  KEY_VAULT_FORMAT,
  KEY_VAULT_MAX_KEYS,
  KEY_VAULT_VERSION,
  keyVaultIdentity,
  parseKeyVault,
  serializeKeyVault,
} from "../src/js/keymanager.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

const password = "correct horse battery staple";
const fixedNow = new Date("2026-09-01T15:04:05.000Z");
// Derived once for the whole file: PBKDF2 at JOURNAL_ITERATIONS is the slow
// part, and the backup drills below only need the keys, not fresh salt (the
// salt is a pure function of the password, so one derivation is every
// derivation).
const shared = await createDocument(password, password);
const keys = shared.keys;

const pack = (file) => JSON.stringify(file, null, 2) + "\n"; // mirrors hodlJournalSaveFile
const flip = (text, index) => text.slice(0, index) + (text[index] === "0" ? "1" : "0") + text.slice(index + 1);

function sampleEntry(overrides = {}) {
  return {
    method: "dice",
    input: "3 1 4 1 5 9",
    phrase: "legal winner thank year wave sausage worth useful legal winner thank yellow",
    label: "Cold storage",
    notes: "garage safe",
    created: "2026-09-01T15:04:05.000Z",
    walletId: 4,
    walletName: "cold",
    fingerprint: "DEADBEEF",
    ...overrides,
  };
}

// --- The encrypted journal file is the backup ------------------------------

test("a backup restores every entry method and keeps id allocation moving", async () => {
  const doc = emptyDocument();
  for (let [index, method] of ["dice", "coin", "hex", "brain", "seed", "cards"].entries()) {
    addEntry(doc, sampleEntry({ method, label: `Entry ${index} ☾`, walletId: index || null }));
  }
  const opened = await openDocument(pack(await sealDocument(doc, keys)), password);
  assert.deepEqual(opened.doc.entries, doc.entries);
  assert.equal(opened.doc.nextId, doc.nextId);
  // Restoring a backup must not collide new entries with restored ones.
  const next = addEntry(opened.doc, sampleEntry({ label: "after restore" }), fixedNow);
  assert.equal(next.id, doc.nextId);
  assert.equal(opened.doc.nextId, doc.nextId + 1);
});

test("an empty journal backs up and restores", async () => {
  const file = await sealDocument(emptyDocument(), keys);
  const opened = await openDocument(file, password); // an already-parsed object is accepted too
  assert.deepEqual(opened.doc, emptyDocument());
});

test("a restored backup re-seals to the identical file", async () => {
  const doc = emptyDocument();
  addEntry(doc, sampleEntry(), fixedNow);
  const file = await sealDocument(doc, keys);
  const opened = await openDocument(pack(file), password);
  // Save → load → save is a fixed point: backups never drift between cycles.
  assert.deepEqual(await sealDocument(opened.doc, opened.keys), file);
});

test("the backup file is opaque: fixed envelope, no salt, no plaintext secrets", async () => {
  const doc = emptyDocument();
  addEntry(doc, sampleEntry({ label: "Operation Moonshine", input: "6 6 6 1 1 1", phrase: "zoo zoo zoo" }), fixedNow);
  const file = await sealDocument(doc, keys);
  assert.deepEqual(Object.keys(file).sort(), ["cipher", "ciphertext", "entropylabJournal", "iterations", "iv", "kdf"]);
  assert.equal(file.entropylabJournal, JOURNAL_VERSION);
  assert.equal(file.kdf, JOURNAL_KDF);
  assert.equal(file.cipher, JOURNAL_CIPHER);
  assert.equal(file.iterations, JOURNAL_ITERATIONS);
  const packed = pack(file);
  for (let secret of ["Operation Moonshine", "6 6 6 1 1 1", "zoo zoo zoo", "deadbeef", "salt"]) {
    assert.ok(!packed.includes(secret), `the backup leaks "${secret}"`);
  }
  // AES-256-GCM appends a 16-byte tag: ciphertext = plaintext + tag.
  const plain = JSON.stringify({ version: JOURNAL_VERSION, nextId: doc.nextId, entries: doc.entries });
  assert.equal(file.ciphertext.length / 2 - plain.length, 16);
  assert.equal(file.iv.length, IV_BYTES * 2);
});

test("a tampered backup is detected at open, not silently restored", async () => {
  const doc = emptyDocument();
  addEntry(doc, sampleEntry(), fixedNow);
  const file = await sealDocument(doc, keys);
  const flippedCipher = { ...file, ciphertext: flip(file.ciphertext, 0) };
  await assert.rejects(() => openDocument(pack(flippedCipher), password), /Wrong password/);
  const flippedIv = { ...file, iv: flip(file.iv, 0) };
  await assert.rejects(() => openDocument(pack(flippedIv), password), /Wrong password/);
});

test("a backup that decrypts to invalid entries is rejected entry by entry", async () => {
  // sealDocument serializes whatever it is given, so a hand-built doc stands
  // in for a damaged or hostile plaintext.
  const badMethod = await sealDocument({ nextId: 1, entries: [{ method: "nostr", label: "x" }] }, keys);
  await assert.rejects(() => openDocument(pack(badMethod), password), /method must be/);
  const missingLabel = await sealDocument({ nextId: 1, entries: [{ method: "dice" }] }, keys);
  await assert.rejects(() => openDocument(pack(missingLabel), password), /needs a label/);
});

test("restoring drops unknown fields and repairs a broken nextId", async () => {
  const entry = { ...normalizeEntry(sampleEntry(), fixedNow), evil: "exfil" };
  const file = await sealDocument({ nextId: -5, entries: [entry] }, keys);
  const opened = await openDocument(pack(file), password);
  assert.equal("evil" in opened.doc.entries[0], false);
  assert.equal(opened.doc.nextId, 1); // non-positive nextId falls back to 1
});

test("an export file is not a journal backup and vice versa", async () => {
  const exportFile = await sealExport("notebook", "notes", keys);
  // The outer envelope parses as a journal file, so openDocument pays the
  // KDF and decrypts — then rejects the payload as a corrupt document.
  await assert.rejects(() => openDocument(pack(exportFile), password), /corrupt/);
  const docFile = await sealDocument(emptyDocument(), keys);
  await assert.rejects(() => openExport(pack(docFile), keys), /not an encrypted Journal export/);
  // Even with the export marker forged onto a journal file, the decrypted
  // payload is a document, not an export.
  const forged = { entropylabJournalExport: JOURNAL_EXPORT_VERSION, ...docFile };
  await assert.rejects(() => openExport(pack(forged), keys), /corrupt/);
});

test("parseFile enforces the backup envelope before any key work happens", () => {
  const file = encodeFile({ iv: Uint8Array.from({ length: IV_BYTES }, (_, i) => i), ciphertext: Uint8Array.from({ length: 32 }, () => 7) });
  assert.equal(parseFile(pack(file)).iterations, JOURNAL_ITERATIONS);
  assert.throws(() => parseFile(pack({ ...file, entropylabJournal: JOURNAL_VERSION + 1 })), /not an EntropyLab journal/);
  assert.throws(() => parseFile(pack({ ...file, kdf: "argon2" })), /unsupported cipher/);
  assert.throws(() => parseFile(pack({ ...file, cipher: "AES-128-GCM" })), /unsupported cipher/);
  assert.throws(() => parseFile(pack({ ...file, iterations: JOURNAL_MIN_ITERATIONS - 1 })), /key-derivation cost/);
  assert.throws(() => parseFile(pack({ ...file, iterations: JOURNAL_MAX_ITERATIONS + 1 })), /key-derivation cost/);
  assert.throws(() => parseFile(pack({ ...file, iterations: 600000.5 })), /key-derivation cost/);
  assert.throws(() => parseFile(pack({ ...file, iv: "zz" })), /missing its IV or ciphertext/);
  assert.throws(() => parseFile(pack({ ...file, iv: file.iv.slice(0, -2) })), /missing its IV or ciphertext/);
  assert.throws(() => parseFile(pack({ ...file, ciphertext: "" })), /missing its IV or ciphertext/);
  // The cost bounds themselves are legitimate.
  assert.equal(parseFile(pack({ ...file, iterations: JOURNAL_MIN_ITERATIONS })).iterations, JOURNAL_MIN_ITERATIONS);
  assert.equal(parseFile(pack({ ...file, iterations: JOURNAL_MAX_ITERATIONS })).iterations, JOURNAL_MAX_ITERATIONS);
});

test("encodeFile refuses to write a malformed envelope", () => {
  const iv = Uint8Array.from({ length: IV_BYTES }, (_, i) => i);
  const ciphertext = Uint8Array.from({ length: 32 }, () => 7);
  assert.throws(() => encodeFile({ iv: Uint8Array.from({ length: 16 }), ciphertext }), /IV must be 12 bytes/);
  assert.throws(() => encodeFile({ iv, ciphertext: new Uint8Array(0) }), /ciphertext is missing/);
  assert.throws(() => encodeFile({ iv, ciphertext, iterations: JOURNAL_MIN_ITERATIONS - 1 }), /out of range/);
  assert.throws(() => encodeFile({ iv, ciphertext, iterations: JOURNAL_MAX_ITERATIONS + 1 }), /out of range/);
  assert.throws(() => encodeFile({ iv, ciphertext, iterations: 600000.5 }), /out of range/);
});

// --- Key derivation ---------------------------------------------------------

test("key derivation is deterministic, bounded, and non-extractable", async () => {
  const again = await deriveJournalKeys(password);
  assert.deepEqual([...again.verify], [...keys.verify]); // same password, same verifier
  assert.equal(again.iterations, JOURNAL_ITERATIONS);
  assert.equal(again.encKey.extractable, false);
  assert.deepEqual([...again.encKey.usages].sort(), ["decrypt", "encrypt"]);
  assert.equal(again.ivKey.extractable, false);
  assert.deepEqual(again.ivKey.usages, ["sign"]);
  // The bounds throw before any PBKDF2 work, so a crafted file cannot hang
  // the page.
  await assert.rejects(() => deriveJournalKeys(password, JOURNAL_MIN_ITERATIONS - 1), /key-derivation cost/);
  await assert.rejects(() => deriveJournalKeys(password, JOURNAL_MAX_ITERATIONS + 1), /key-derivation cost/);
  await assert.rejects(() => deriveJournalKeys(password, 600000.5), /key-derivation cost/);
  await assert.rejects(() => deriveJournalKeys(""), /missing/);
});

// --- Entry bookkeeping behind the backup ------------------------------------

test("addEntry fills defaults, sequences ids, and ignores a supplied id", () => {
  const doc = emptyDocument();
  const bare = addEntry(doc, { method: "coin", label: "flips" }, fixedNow);
  assert.deepEqual(bare, {
    id: 1, method: "coin", input: "", phrase: "", label: "flips", notes: "",
    created: "2026-09-01T15:04:05.000Z", walletId: null, walletName: "", fingerprint: "",
  });
  const stamped = addEntry(doc, { ...sampleEntry({ id: 99, label: "second" }), created: "2020-01-02T03:04:05.000Z" }, fixedNow);
  assert.equal(stamped.id, 2); // the supplied id 99 is discarded
  assert.equal(stamped.created, "2020-01-02T03:04:05.000Z"); // a valid stamp is kept
  assert.equal(doc.nextId, 3);
  assert.throws(() => addEntry(null, sampleEntry()), /document is missing/);
  assert.throws(() => addEntry({}, sampleEntry()), /document is missing/);
});

test("entries validate their timestamp and wallet link", () => {
  assert.throws(() => normalizeEntry(sampleEntry({ created: "2026-09-01" })), /ISO-8601/);
  assert.throws(() => normalizeEntry(sampleEntry({ created: "yesterday" })), /ISO-8601/);
  assert.throws(() => normalizeEntry(sampleEntry({ walletId: 3.5 })), /whole number/);
  assert.throws(() => normalizeEntry(sampleEntry({ walletId: -1 })), /whole number/);
  assert.equal(normalizeEntry(sampleEntry({ walletId: "3" })).walletId, 3); // coerced like the UI select
  assert.equal(normalizeEntry(sampleEntry({ walletId: "" })).walletId, null);
  assert.equal(normalizeEntry(sampleEntry({ fingerprint: "AABBCCDD" })).fingerprint, "aabbccdd");
});

test("replaceEntry keeps identity, wipes the old object, and removeEntry wipes too", () => {
  const doc = emptyDocument();
  const original = addEntry(doc, sampleEntry(), fixedNow);
  const replaced = replaceEntry(doc, original.id, { label: "renamed", input: "1 1 1" });
  assert.equal(replaced.id, original.id);
  assert.equal(replaced.created, original.created);
  assert.equal(replaced.label, "renamed");
  // The replaced object was zeroed in place — no stale copy of the input.
  assert.equal(original.input, "");
  assert.equal(original.label, "");
  assert.equal(doc.entries[0], replaced);
  assert.throws(() => replaceEntry(doc, 99, { label: "x" }), /not in this file/);
  const doomed = addEntry(doc, sampleEntry({ label: "doomed" }), fixedNow);
  removeEntry(doc, doomed.id);
  assert.equal(doc.entries.length, 1);
  assert.equal(doomed.input, "");
  assert.equal(doomed.phrase, "");
  assert.throws(() => removeEntry(doc, doomed.id), /not in this file/);
  assert.throws(() => removeEntry(null, 1), /document is missing/);
});

test("search is case-insensitive, label-scoped, and hands back a copy", () => {
  const doc = emptyDocument();
  addEntry(doc, sampleEntry({ label: "Cold Storage", notes: "warm phrase" }), fixedNow);
  addEntry(doc, sampleEntry({ method: "hex", label: "attic" }), fixedNow);
  assert.equal(searchEntries(doc, "COLD").length, 1);
  assert.equal(searchEntries(doc, "warm").length, 0); // notes are not searched
  const all = searchEntries(doc, "  ");
  all.length = 0; // mutating the result must not touch the document
  assert.equal(doc.entries.length, 2);
  assert.deepEqual(searchEntries(null, "x"), []);
});

test("wipe helpers zero secrets in place and reset allocation", () => {
  const bytes = Uint8Array.from([1, 2, 3, 4]);
  assert.equal(wipeBytes(bytes), bytes);
  assert.deepEqual([...bytes], [0, 0, 0, 0]);
  assert.equal(wipeBytes(null), null);
  const entry = sampleEntry();
  wipeEntry(entry);
  for (let field of ["input", "phrase", "label", "notes", "walletName", "fingerprint"]) assert.equal(entry[field], "");
  const doc = emptyDocument();
  const kept = addEntry(doc, sampleEntry(), fixedNow);
  wipeDocument(doc);
  assert.equal(kept.input, ""); // wiped before the array was dropped
  assert.deepEqual(doc.entries, []);
  assert.equal(doc.nextId, 1);
  wipeDocument(null); // must not throw
});

// --- Session-key snapshots (what "Save to Journal" captures) ----------------

test("the snapshot captures each input method's live transcript", () => {
  const base = { id: 1, isLab: false, name: "", fields: {}, result: null };
  const dplus = snapshotFromKeyState({ ...base, mode: "dice", diceMethod: "dplus", fields: { dplusDice: "⚁⚂⚄", dice: "1 2 3" } });
  assert.equal(dplus.input, "⚁⚂⚄");
  const bitbox = snapshotFromKeyState({ ...base, mode: "dice", diceMethod: "bitbox", fields: { bitboxDice: "bb", dice: "1 2 3" } });
  assert.equal(bitbox.input, "bb");
  const direct = snapshotFromKeyState({ ...base, mode: "cards", cardMethod: "direct", fields: { directCards: "AS KD", cards: "hashed" } });
  assert.equal(direct.method, "cards");
  assert.equal(direct.input, "AS KD");
  const binary = snapshotFromKeyState({ ...base, mode: "hex", entropyFormat: "bin", fields: { bin: "0101", hex: "aa" } });
  assert.equal(binary.method, "hex");
  assert.equal(binary.input, "0101");
  const hexFallback = snapshotFromKeyState({ ...base, mode: "hex", entropyFormat: "base64", fields: { hex: "aa" } });
  assert.equal(hexFallback.input, "aa"); // an empty chosen format falls back to hex
  const numbers = snapshotFromKeyState({ ...base, mode: "seed", seedMethod: "numbers", fields: { seedNumbers: "1 2 3", seed: "words" } });
  assert.equal(numbers.input, "1 2 3");
});

test("the snapshot captures private-key modes and the passphrase warning", () => {
  const base = { id: 2, isLab: false, mode: "key", name: "", fields: {}, result: { mnemonic: "", masterFingerprint: "AABBCCDD" } };
  const brain = snapshotFromKeyState({ ...base, fields: { keyKind: "brain", privateKeys: { brain: "correct horse" } } });
  assert.equal(brain.method, "brain");
  assert.equal(brain.input, "correct horse");
  assert.equal(brain.label, "AABBCCDD"); // no name: the fingerprint names the entry
  assert.equal(brain.fingerprint, "aabbccdd"); // the fingerprint field is normalized
  const wif = snapshotFromKeyState({ ...base, fields: { keyKind: "minikey", privateKeys: { minikey: "", wif: "KwDi..." }, key: "fallback" } });
  assert.equal(wif.method, "seed");
  assert.equal(wif.input, "KwDi..."); // empty kind slot falls back to wif, then to the raw field
  const raw = snapshotFromKeyState({ ...base, fields: { keyKind: "hex-key", privateKeys: {}, key: "0011" } });
  assert.equal(raw.input, "0011");
  const withPass = snapshotFromKeyState({ ...base, fields: { keyKind: "brain", privateKeys: { brain: "x" }, pass: "secret pass" } });
  assert.match(withPass.notes, /passphrase was in effect/);
  assert.doesNotMatch(withPass.notes, /secret pass/); // the passphrase itself is never copied
  assert.equal(snapshotFromKeyState({ isLab: true, mode: "dice", fields: { dice: "1" } }), null);
  assert.equal(snapshotFromKeyState({ ...base, fields: {}, result: null }), null);
  assert.equal(snapshotFromKeyState(null), null);
});

// --- Notepad backups ---------------------------------------------------------

test("a notebook backup restores pages, order, and the active page", () => {
  const journal = createJournal();
  journal.pages[0].name = "  Field   notes  ";
  journal.pages[0].notesText = `first ${journalKeyReferenceToken("Key 1", "deadbeef")}`;
  journal.pages.push({ id: 2, number: 9, name: "Second", notesText: "two", style: { font: "sans", size: "small", spacing: "compact" } });
  journal.activePage = 1;
  const restored = parseNotebook(serializeNotebook(journal));
  assert.equal(restored.pages.length, 2);
  assert.equal(restored.pages[0].name, "Field notes"); // parse collapses the sloppy spacing
  assert.equal(restored.pages[0].notesText, journal.pages[0].notesText);
  assert.equal(restored.pages[1].number, 9);
  assert.equal(restored.activePage, 1);
  assert.equal(restored.nextPageNumber, 10);
  assert.equal(restored.nextPageId, 3);
  assert.equal(restored.notesText, "two"); // the active page drives the editor text
  assert.deepEqual(restored.log, []);
  assert.equal(restored.stateText, "");
});

test("notebook serialization clamps the active page and survives an empty journal", () => {
  const journal = createJournal();
  journal.pages.push({ id: 2, number: 2, name: "Page 2", notesText: "", style: journal.pages[0].style });
  journal.activePage = 99;
  assert.equal(JSON.parse(serializeNotebook(journal)).activePage, 1);
  journal.activePage = -3;
  assert.equal(JSON.parse(serializeNotebook(journal)).activePage, 0);
  const fallback = parseNotebook(serializeNotebook(undefined));
  assert.equal(fallback.pages.length, 1);
  assert.equal(fallback.pages[0].notesText, "");
});

test("notebook import repairs duplicate numbers, names, and styles", () => {
  const page = (overrides) => JSON.stringify({
    format: NOTEBOOK_FORMAT,
    version: NOTEBOOK_VERSION,
    activePage: 0,
    pages: [overrides],
  });
  const duplicates = parseNotebook(JSON.stringify({
    format: NOTEBOOK_FORMAT,
    version: NOTEBOOK_VERSION,
    activePage: 0,
    pages: [{ number: 5, content: [] }, { number: 5, content: [] }, { number: 5, content: [] }],
  }));
  assert.deepEqual(duplicates.pages.map((p) => p.number), [5, 6, 7]);
  assert.equal(duplicates.nextPageNumber, 8);
  const messy = parseNotebook(page({ number: 3, name: "  many\t\t spaces  ", style: { font: "gothic", size: "huge", spacing: "airy" }, content: [] }));
  assert.equal(messy.pages[0].name, "many spaces");
  assert.deepEqual(messy.pages[0].style, { font: "mono", size: "medium", spacing: "comfortable" });
  const unnamed = parseNotebook(page({ number: 4, content: [] }));
  assert.equal(unnamed.pages[0].name, "Page 4");
  const longName = parseNotebook(page({ number: 1, name: "n".repeat(200), content: [] }));
  assert.equal(longName.pages[0].name.length, 120);
  const clamped = parseNotebook(JSON.stringify({ format: NOTEBOOK_FORMAT, version: NOTEBOOK_VERSION, activePage: 42, pages: [{ content: [] }] }));
  assert.equal(clamped.activePage, 0);
});

test("notebook imports are bounded and content must be a run list", () => {
  assert.throws(() => parseNotebook(JSON.stringify({
    format: NOTEBOOK_FORMAT, version: NOTEBOOK_VERSION,
    pages: Array.from({ length: NOTEBOOK_MAX_PAGES + 1 }, () => ({ content: [] })),
  })), /between 1 and/);
  assert.equal(parseNotebook(JSON.stringify({
    format: NOTEBOOK_FORMAT, version: NOTEBOOK_VERSION,
    pages: Array.from({ length: NOTEBOOK_MAX_PAGES }, () => ({ content: [] })),
  })).pages.length, NOTEBOOK_MAX_PAGES);
  assert.throws(() => parseNotebook(JSON.stringify({ format: NOTEBOOK_FORMAT, version: NOTEBOOK_VERSION, pages: [{ content: "text" }] })), /content list/);
  assert.throws(() => journalTextFromRuns([{ type: "key", name: "k", fingerprint: "xyz" }]), /8-character hexadecimal/);
  assert.throws(() => journalTextFromRuns([{ type: "key", source: "bip85", application: "unknown", fingerprint: "deadbeef" }]), /supported application/);
  assert.throws(() => journalTextFromRuns([{ type: "text", text: "x".repeat(NOTEBOOK_MAX_TEXT_LENGTH + 1) }]), /too large/);
  assert.equal(journalTextFromRuns([{ type: "text", text: "x".repeat(NOTEBOOK_MAX_TEXT_LENGTH) }]).length, NOTEBOOK_MAX_TEXT_LENGTH);
  assert.throws(() => journalFromPlainText("x".repeat(NOTEBOOK_MAX_TEXT_LENGTH + 1)), /too large/);
  assert.equal(journalFromPlainText(null).pages[0].notesText, "");
});

test("key reference tokens survive careless names and reject bad fingerprints", () => {
  assert.equal(journalKeyReferenceToken("", "deadbeef"), "◆◆ Key [deadbeef]\u2063");
  assert.equal(journalKeyReferenceToken("  \n  ", "deadbeef"), "◆◆ Key [deadbeef]\u2063");
  assert.equal(journalKeyReferenceToken("a".repeat(200), "deadbeef"), `◆◆ ${"a".repeat(120)} [deadbeef]\u2063`);
  assert.equal(journalKeyReferenceToken("line\nbreak◆s", "DEADBEEF"), "◆◆ line break◇s [deadbeef]\u2063");
  assert.throws(() => journalKeyReferenceToken("Key", "1234567"), /8-character hexadecimal/);
  assert.throws(() => journalKeyReferenceToken("Key", "123456789"), /8-character hexadecimal/);
  assert.throws(() => journalKeyReferenceToken("Key", "abcdefgh"), /8-character hexadecimal/);
});

test("only well-formed tokens parse; lookalikes stay plain text", () => {
  assert.deepEqual(journalNotebookRuns("◆◆ [1234567] ◆"), [{ type: "text", text: "◆◆ [1234567] ◆" }]);
  assert.deepEqual(journalNotebookRuns("◆◆ [123456789] ◆"), [{ type: "text", text: "◆◆ [123456789] ◆" }]);
  // A token's trailing ◆ doubles as the next token's opener.
  const adjacent = journalNotebookRuns("◆◆ [aaaaaaaa] ◆◆◆ Key B [bbbbbbbb] ◆");
  assert.deepEqual(adjacent, [
    { type: "key", name: "aaaaaaaa", fingerprint: "aaaaaaaa" },
    { type: "key", name: "Key B", fingerprint: "bbbbbbbb" },
  ]);
  // Repeated calls see the same input (no hidden regex cursor state).
  const source = "x ◆◆ [aaaaaaaa] ◆ y";
  assert.deepEqual(journalNotebookRuns(source), journalNotebookRuns(source));
  assert.equal(journalFromPlainText(source).notesText, "x ◆◆ [aaaaaaaa]\u2063 y", "plain-text imports should upgrade the visible legacy boundary");
});

test("key reference ranges identify the complete atomic token", () => {
  const token = journalKeyReferenceToken("Key A", "deadbeef");
  assert.deepEqual(journalKeyReferenceRanges(`before ${token} after`), [{
    start: 7,
    end: 7 + token.length,
  }]);
  assert.deepEqual(journalKeyReferenceRanges("◆◆ [deadbeef]"), []);
});

test("the plain-text download strips only untouched hint lines", () => {
  assert.equal(formatNotebook("2026-09-02 10:00:00  real words"), "2026-09-02 10:00:00  real words");
  assert.equal(formatNotebook("2026-09-02 10:00:00 Add new note"), "2026-09-02 10:00:00 Add new note"); // single space: not a hint
  assert.equal(formatNotebook("2026-09-02 10:00:00  Add new notes"), "2026-09-02 10:00:00  Add new notes");
  assert.equal(formatNotebook("2026-09-02 10:00:00  \n"), "No notes.");
  assert.deepEqual(formatNotebookPages([]), "No notes.");
  assert.equal(formatNotebookPages(undefined), "No notes.");
});

// --- Session log and snapshot downloads --------------------------------------

test("log entries are stamped, coerced, and truncated to 300 characters", () => {
  const journal = createJournal();
  const entry = appendLog(journal, { tool: "calc", action: "derive", detail: "d".repeat(400) }, new Date(2026, 8, 2, 9, 5, 7));
  assert.equal(entry.at, "2026-09-02 09:05:07");
  assert.equal(entry.detail.length, 300);
  assert.equal(journal.log[journal.log.length - 1], entry); // returns the stored entry
  const stamped = appendLog(journal, { at: "2000-01-01 00:00:00", tool: 42, action: null, detail: undefined });
  assert.equal(stamped.at, "2000-01-01 00:00:00"); // an explicit stamp wins over the clock
  assert.equal(stamped.tool, "42");
  assert.equal(stamped.action, "");
  assert.equal(stamped.detail, "");
});

test("the log download is tab-separated with indented details", () => {
  assert.equal(formatLog([]), "No events yet.");
  const text = formatLog([
    { at: "2026-09-02 09:05:07", tool: "calc", action: "derive", detail: "fp=aa" },
    { at: "2026-09-02 09:06:00", tool: "app", action: "boot", detail: "" },
  ]);
  assert.equal(text, "2026-09-02 09:05:07\tcalc\tderive  fp=aa\n2026-09-02 09:06:00\tapp\tboot");
});

test("the session snapshot names every section and gates secrets on the toggle", () => {
  const text = snapshotSession({
    capturedAt: "2026-09-02 10:00:00",
    version: "v0.1.3",
    includePrivate: true,
    keys: [
      { name: "Station", derived: false, mode: "dice" },
      { name: "cold", derived: true, fingerprint: "deadbeef", sheet: "Master fingerprint: deadbeef" },
    ],
    msigs: [
      { name: "Vault", derived: false },
      { name: "Fund", derived: true, summary: "2-of-3", sheet: "descriptor text" },
    ],
    bip85: [{ name: "kid", fingerprint: "a1b2c3d4", app: "BIP-39", secret: "legal winner thank" }],
    sp: { derived: true, fingerprint: "cafef00d", address: "sp1q..." },
    psbt: { loaded: true },
  });
  assert.match(text, /^ENTROPYLAB SESSION STATE\n/);
  assert.match(text, /Build: v0\.1\.3$/m); // no commit fragment when none is known
  assert.match(text, /Private material: INCLUDED/);
  assert.match(text, /- Station · not derived · method dice/);
  assert.match(text, /- cold · fingerprint deadbeef\nMaster fingerprint: deadbeef/);
  assert.match(text, /- Vault · not derived/);
  assert.match(text, /- Fund · 2-of-3\ndescriptor text/);
  assert.match(text, /- kid · a1b2c3d4 · BIP-39\n  legal winner thank/);
  assert.match(text, /- fingerprint cafef00d\n  sp1q\.\.\./);
  assert.match(text, /- payload present in the inspector/);
  assert.match(text, /Closing the tab discards it\.$/);
  const bare = snapshotSession({ keys: [], msigs: [], bip85: [], sp: {}, psbt: {} });
  assert.match(bare, /Build: unknown/);
  assert.match(bare, /Private material: omitted/);
  assert.match(bare, /KEYS\n\(none\)/);
  assert.match(bare, /- not derived/); // silent payments
  assert.match(bare, /- inspector empty/);
  assert.doesNotMatch(bare, /legal winner/);
});

// --- Encrypted tab exports (notepad, keys, state, log) ------------------------

test("every export kind round-trips through the journal password", async () => {
  for (let [kind, content] of [
    ["notebook", serializeNotebook(createJournal())],
    ["key-manager", serializeKeyVault([])],
    ["session-state", snapshotSession({ keys: [], msigs: [], bip85: [], sp: {}, psbt: {} })],
    ["session-log", formatLog([{ at: "2026-09-02 09:05:07", tool: "app", action: "boot", detail: "" }])],
  ]) {
    const file = await sealExport(kind, content, keys);
    assert.equal(file.entropylabJournalExport, JOURNAL_EXPORT_VERSION);
    assert.deepEqual(await openExport(pack(file), keys), { kind, content });
  }
});

test("the export file is a fixed envelope plus the export marker", async () => {
  const file = await sealExport("session-log", "line", keys);
  assert.deepEqual(
    Object.keys(file).sort(),
    ["cipher", "ciphertext", "entropylabJournal", "entropylabJournalExport", "iterations", "iv", "kdf"],
  );
  assert.ok(!pack(file).includes("line")); // content is sealed, not embedded
});

test("an export sealed under another cost profile is refused before decrypting", async () => {
  const file = await sealExport("notebook", "notes", keys);
  // The iteration count is authenticated by context, not by the GCM tag: a
  // file claiming a different cost belongs to a different password.
  const doctored = { ...file, iterations: JOURNAL_MIN_ITERATIONS };
  await assert.rejects(() => openExport(pack(doctored), keys), /different journal password/);
});

test("tampered exports fail closed", async () => {
  const file = await sealExport("session-state", "state text", keys);
  const flippedCipher = { ...file, ciphertext: flip(file.ciphertext, file.ciphertext.length - 1) };
  await assert.rejects(() => openExport(pack(flippedCipher), keys), /different journal password, or the file is damaged/);
  const flippedIv = { ...file, iv: flip(file.iv, 0) };
  await assert.rejects(() => openExport(pack(flippedIv), keys), /different journal password, or the file is damaged/);
  // A truncated file is caught at the envelope (odd hex) or at the tag
  // (even hex that no longer carries the 16-byte GCM tag).
  const ragged = { ...file, ciphertext: file.ciphertext.slice(0, 41) };
  await assert.rejects(() => openExport(pack(ragged), keys), /missing its IV or ciphertext/);
  const truncated = { ...file, ciphertext: file.ciphertext.slice(0, 40) };
  await assert.rejects(() => openExport(pack(truncated), keys), /different journal password, or the file is damaged/);
  await assert.rejects(() => openExport("not json", keys), /not valid JSON/);
  await assert.rejects(() => openExport(pack({ ...file, entropylabJournalExport: 99 }), keys), /not an encrypted Journal export/);
});

// --- Key Manager vault backups ------------------------------------------------

function managedKey(overrides = {}) {
  return {
    id: 7,
    number: 2,
    name: "Cold storage",
    createdAt: "2026-09-03T12:00:00.000Z",
    fields: { derivationPath: "m/84'/0'/0'/0/0", seed: "user supplied words" },
    result: { masterFingerprint: "deadbeef", rootXpub: "xpub-example", rootXprv: "xprv-example" },
    reveal: true,
    error: "stale",
    ...overrides,
  };
}

test("a vault backup normalizes names and drops transient UI state", () => {
  const messy = managedKey({ name: "  too\t  many\n\n spaces  ", errorSpec: { field: "seed" }, extra: "kept" });
  const [restored] = parseKeyVault(serializeKeyVault([messy])).keys;
  assert.equal(restored.name, "too many spaces");
  assert.equal(restored.reveal, false);
  assert.equal(restored.error, "");
  assert.equal("errorSpec" in restored, false);
  assert.equal(restored.extra, "kept"); // unknown state is preserved for forward compatibility
  assert.equal(restored.fields.seed, "user supplied words");
  const [unnamed] = parseKeyVault(serializeKeyVault([managedKey({ name: "   " })])).keys;
  assert.equal(unnamed.name, "Imported key");
  const [longNamed] = parseKeyVault(serializeKeyVault([managedKey({ name: "k".repeat(200) })])).keys;
  assert.equal(longNamed.name.length, 120);
});

test("vault backups are bounded and schema-checked on both directions", () => {
  assert.throws(() => serializeKeyVault(Array.from({ length: KEY_VAULT_MAX_KEYS + 1 }, () => managedKey())), /too many keys/);
  assert.equal(JSON.parse(serializeKeyVault(Array.from({ length: KEY_VAULT_MAX_KEYS }, () => managedKey()))).keys.length, KEY_VAULT_MAX_KEYS);
  assert.throws(() => serializeKeyVault([], Array.from({ length: KEY_VAULT_MAX_KEYS + 1 }, () => managedKey())), /too many ignored keys/);
  assert.throws(() => serializeKeyVault([null]), /invalid key/);
  assert.throws(() => serializeKeyVault([{ name: "no state" }]), /invalid key/);
  assert.throws(() => serializeKeyVault([managedKey({ fields: null })]), /invalid key/);
  assert.throws(() => serializeKeyVault([managedKey({ result: null })]), /invalid key/);
  assert.throws(() => parseKeyVault(JSON.stringify({ format: KEY_VAULT_FORMAT, version: KEY_VAULT_VERSION })), /too many keys/);
  assert.throws(() => parseKeyVault(JSON.stringify({ format: KEY_VAULT_FORMAT, version: KEY_VAULT_VERSION + 1, keys: [] })), /not a supported/);
  const ignoredDefault = parseKeyVault(JSON.stringify({ format: KEY_VAULT_FORMAT, version: KEY_VAULT_VERSION, keys: [] }));
  assert.deepEqual(ignoredDefault, { keys: [], ignoredKeys: [] });
  assert.ok(serializeKeyVault([]).endsWith("}\n")); // stable on-disk shape
});

test("vault identity falls back through fingerprint, xpubs, then id", () => {
  assert.equal(keyVaultIdentity({ result: { masterFingerprint: "deadbeef", rootXpub: "xpub1", xpub: "xpub2" }, id: 7 }), "deadbeef");
  assert.equal(keyVaultIdentity({ result: { rootXpub: "xpub1", xpub: "xpub2" }, id: 7 }), "xpub1");
  assert.equal(keyVaultIdentity({ result: { xpub: "xpub2" }, id: 7 }), "xpub2");
  assert.equal(keyVaultIdentity({ result: {}, id: 7 }), "7");
  assert.equal(keyVaultIdentity({}), "");
  assert.equal(keyVaultIdentity(null), "");
});

test("an .elkeys backup is opaque until opened with the journal password", async () => {
  const content = serializeKeyVault([managedKey()], [managedKey({ id: 8, name: "Ignored" })]);
  const file = await sealExport("key-manager", content, keys);
  const packed = pack(file);
  for (let secret of ["user supplied words", "xprv-example", "xpub-example", "deadbeef"]) {
    assert.ok(!packed.includes(secret), `the key file leaks "${secret}"`);
  }
  const opened = await openExport(packed, keys);
  assert.equal(opened.kind, "key-manager");
  const vault = parseKeyVault(opened.content);
  assert.equal(vault.keys.length, 1);
  assert.equal(vault.ignoredKeys.length, 1);
  assert.equal(keyVaultIdentity(vault.keys[0]), "deadbeef");
});

// --- App wiring: the buttons actually route through these primitives ----------

test("the app routes every journal backup through the sealed primitives", () => {
  const app = read("src/js/app.js");
  // Downloads encrypt with the unlocked journal keys by default and mark the
  // file as encrypted.
  assert.match(app, /async function hodlJournalDownloadContent\(kind, filename, text[\s\S]*?hodlJournalSealExport\(kind, text, hodlJournalKeys\)/);
  assert.match(app, /filename\.replace\(\/\\\.\[\^\.\]\+\$\/, ""\) \+ "\.encrypted\.json"/);
  // The journal file itself downloads through sealDocument as JSON.
  assert.match(app, /hodlJournalSealDocument\(hodlJournalDoc, hodlJournalKeys\)/);
  assert.match(app, /link\.download = "entropylab-journal\.json"/);
  // Imports are size-bounded and sniff the export envelope before parsing.
  assert.match(app, /async function hodlJournalImportFile\(file\)[\s\S]*?file\.size > 2 \* 1024 \* 1024/);
  assert.match(app, /outer\?\.entropylabJournalExport[\s\S]*?hodlJournalOpenExport\(outer, hodlJournalKeys\)/);
  assert.match(app, /hodlJournalStoreNotesText\(field\)[\s\S]*?hodlMergeNotebookImport\(hodlJournal, imported\)/);
  assert.match(app, /async function hodlKeyManagerImportFile\(file\)[\s\S]*?file\.size > 2 \* 1024 \* 1024/);
  assert.match(app, /opened\.kind !== "key-manager"/);
  // Plain-text .txt uploads stay a legacy single-page import.
  assert.match(app, /\\\.txt\$\/i\.test\(file\.name\) \? hodlJournalFromPlainText\(text\) : hodlParseNotebook\(text\)/);
});

// --- The full backup drill ------------------------------------------------------

test("backup drill: seal everything, restore from a cold start", async () => {
  // Day one: derive keys, journal two entries, fill the notepad, manage a key.
  const doc = emptyDocument();
  addEntry(doc, sampleEntry({ label: "first" }), fixedNow);
  addEntry(doc, sampleEntry({ method: "cards", label: "second", input: "AS KD QH" }), fixedNow);
  const journalFile = pack(await sealDocument(doc, keys));
  const journal = createJournal();
  journal.pages[0].notesText = `rolls ${journalKeyReferenceToken("Cold storage", "deadbeef")}`;
  const notebookExport = pack(await sealExport("notebook", serializeNotebook(journal), keys));
  const vaultExport = pack(await sealExport("key-manager", serializeKeyVault([managedKey()]), keys));
  const stateExport = pack(await sealExport("session-state", snapshotSession({
    capturedAt: "2026-09-02 10:00:00", includePrivate: false,
    keys: [{ name: "cold", derived: true, fingerprint: "deadbeef" }],
    msigs: [], bip85: [], sp: {}, psbt: {},
  }), keys));
  const logExport = pack(await sealExport("session-log", formatLog([
    { at: "2026-09-02 10:00:00", tool: "calc", action: "derive", detail: "fp=deadbeef" },
  ]), keys));

  // Day two, cold start: open the journal file, then pull each tab back.
  const restored = await openDocument(journalFile, password);
  assert.deepEqual(restored.doc.entries, doc.entries);
  const notes = parseNotebook((await openExport(notebookExport, restored.keys)).content);
  assert.equal(notes.pages[0].notesText, journal.pages[0].notesText);
  const vault = parseKeyVault((await openExport(vaultExport, restored.keys)).content);
  assert.equal(keyVaultIdentity(vault.keys[0]), "deadbeef");
  const state = await openExport(stateExport, restored.keys);
  assert.match(state.content, /fingerprint deadbeef/);
  const log = await openExport(logExport, restored.keys);
  assert.match(log.content, /calc\tderive  fp=deadbeef/);

  // And the cycle continues: new entries seal on top of the restored file.
  addEntry(restored.doc, sampleEntry({ label: "third" }), fixedNow);
  const again = await openDocument(pack(await sealDocument(restored.doc, restored.keys)), password);
  assert.equal(again.doc.entries.length, 3);
  assert.equal(again.doc.entries[2].label, "third");
});
