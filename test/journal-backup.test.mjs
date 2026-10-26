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
import * as journalModule from "../src/js/journal.js";
import {
  IV_BYTES,
  JOURNAL_CIPHER,
  JOURNAL_EXPORT_VERSION,
  JOURNAL_ITERATIONS,
  JOURNAL_KDF,
  JOURNAL_LOG_LIMIT,
  JOURNAL_MAX_ITERATIONS,
  JOURNAL_MAX_TEXT_LENGTH,
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
  entryMethodLabel,
  encodeFile,
  formatLog,
  formatNotebook,
  formatNotebookPages,
  journalFromPlainText,
  journalKeyReferenceRanges,
  journalKeyReferenceToken,
  journalNotebookRuns,
  journalTextFromRuns,
  keySnapshotMatchesEntry,
  mergeNotebookImport,
  normalizeEntry,
  openDocument,
  openExport,
  parseFile,
  parseDocument,
  parseNotebook,
  removeEntry,
  replaceEntry,
  sealDocument,
  sealExport,
  searchEntries,
  serializeNotebook,
  snapshotFromKeyState,
  snapshotSession,
  syncKeySnapshots,
  wipeBytes,
  wipeDocument,
  wipeEntry,
  wipeJournal,
} from "../src/js/journal.js";
import {
  KEY_VAULT_FORMAT,
  KEY_VAULT_MAX_KEYS,
  KEY_VAULT_VERSION,
  keyVaultIdentity,
  parseKeyVault,
  serializeKeyVault,
  setKeyVaultModes,
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
  await assert.rejects(() => openDocument(pack(flippedCipher), password), /password is incorrect/);
  const flippedIv = { ...file, iv: flip(file.iv, 0) };
  await assert.rejects(() => openDocument(pack(flippedIv), password), /password is incorrect/);
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
  assert.equal(opened.doc.nextId, 2); // non-positive nextId falls back to 1, then clears the entry's repaired id 1
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
  // CryptoKeys are not comparable, so determinism is pinned behaviorally: a
  // fresh derivation of the same password decrypts what the first one sealed.
  const sealed = JSON.stringify(await sealDocument(emptyDocument(), again));
  const reopened = await openDocument(sealed, password);
  assert.equal(reopened.keys.iterations, JOURNAL_ITERATIONS);
  assert.equal(again.iterations, JOURNAL_ITERATIONS);
  assert.equal(again.passwordProtected, true);
  assert.equal(again.encKey.extractable, false);
  assert.deepEqual([...again.encKey.usages].sort(), ["decrypt", "encrypt"]);
  assert.equal(again.ivKey.extractable, false);
  assert.deepEqual(again.ivKey.usages, ["sign"]);
  // The bounds throw before any PBKDF2 work, so a crafted file cannot hang
  // the page.
  await assert.rejects(() => deriveJournalKeys(password, JOURNAL_MIN_ITERATIONS - 1), /key-derivation cost/);
  await assert.rejects(() => deriveJournalKeys(password, JOURNAL_MAX_ITERATIONS + 1), /key-derivation cost/);
  await assert.rejects(() => deriveJournalKeys(password, 600000.5), /key-derivation cost/);
  const passwordless = await deriveJournalKeys("");
  assert.equal(passwordless.passwordProtected, false);
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

// --- Session-key snapshots (what automatic Key Station capture stores) -------

test("the snapshot captures each input method's live transcript", () => {
  const base = { id: 1, isLab: false, name: "", fields: {}, result: null };
  const dplus = snapshotFromKeyState({ ...base, mode: "dice", diceMethod: "dplus", fields: { dplusDice: "⚁⚂⚄", dice: "1 2 3" } });
  assert.equal(dplus.input, "⚁⚂⚄");
  assert.equal(dplus.diceMethod, "dplus");
  assert.equal(entryMethodLabel(dplus), "Dice rolls · D++ direct word selection");
  const bitbox = snapshotFromKeyState({ ...base, mode: "dice", diceMethod: "bitbox", fields: { bitboxDice: "bb", dice: "1 2 3" } });
  assert.equal(bitbox.input, "bb");
  assert.equal(bitbox.diceMethod, "bitbox");
  const coleman = snapshotFromKeyState({ ...base, mode: "dice", diceMethod: "coleman", fields: { colemanDice: "654321", dice: "123456" } });
  assert.equal(coleman.input, "654321");
  const legacyColeman = snapshotFromKeyState({ ...base, mode: "dice", diceMethod: "coleman", fields: { dice: "123456" } });
  assert.equal(legacyColeman.input, "123456");
  const direct = snapshotFromKeyState({ ...base, mode: "cards", cardMethod: "direct", fields: { directCards: "AS KD", cards: "hashed" } });
  assert.equal(direct.method, "cards");
  assert.equal(direct.input, "AS KD");
  assert.equal(direct.cardMethod, "direct");
  assert.equal(entryMethodLabel(direct), "Playing cards · Direct word selection");
  const binary = snapshotFromKeyState({ ...base, mode: "hex", entropyFormat: "bin", fields: { bin: "0101", hex: "aa" } });
  assert.equal(binary.method, "hex");
  assert.equal(binary.input, "0101");
  assert.equal(binary.entropyFormat, "bin");
  assert.equal(entryMethodLabel(binary), "Number bases · Binary (Base 2)");
  const hexFallback = snapshotFromKeyState({ ...base, mode: "hex", entropyFormat: "base64", fields: { hex: "aa" } });
  assert.equal(hexFallback.input, "aa"); // an empty chosen format falls back to hex
  assert.equal(hexFallback.entropyFormat, "hex");
  const numbers = snapshotFromKeyState({ ...base, mode: "seed", seedMethod: "numbers", fields: { seedNumbers: "1 2 3", seed: "words" } });
  assert.equal(numbers.input, "1 2 3");
  assert.equal(numbers.seedMethod, "numbers");
  assert.equal(entryMethodLabel(numbers), "Manual seed · BIP39 word numbers");
});

test("journal entry variants survive encryption while old and unknown variants stay safe", async () => {
  const doc = emptyDocument();
  addEntry(doc, sampleEntry({ method: "dice", diceMethod: "coleman" }), fixedNow);
  const opened = await openDocument(pack(await sealDocument(doc, keys)), password);
  assert.equal(opened.doc.entries[0].diceMethod, "coleman");
  assert.equal(entryMethodLabel(opened.doc.entries[0]), "Dice rolls · Ian Coleman / Keystone");
  const oldEntry = normalizeEntry(sampleEntry({ method: "seed" }), fixedNow);
  assert.equal(entryMethodLabel(oldEntry), "Manual seed");
  const hostile = normalizeEntry(sampleEntry({ method: "cards", cardMethod: "exfil", entropyFormat: "javascript:" }), fixedNow);
  assert.equal(hostile.cardMethod, undefined);
  assert.equal(hostile.entropyFormat, undefined);
  assert.equal(entryMethodLabel(hostile), "Playing cards");
  // The hex method is labeled "Number bases" with or without a variant,
  // matching the method pickers in the rest of the app.
  assert.equal(entryMethodLabel(normalizeEntry(sampleEntry({ method: "hex" }), fixedNow)), "Number bases");
});

test("a variant that belongs to another method is dropped, even through an edit", () => {
  // replaceEntry merges the previous entry, so a stale diceMethod would
  // survive a method switch if normalizeEntry did not drop it.
  const doc = emptyDocument();
  const entry = addEntry(doc, sampleEntry({ method: "dice", diceMethod: "coldcard" }), fixedNow);
  const replaced = replaceEntry(doc, entry.id, sampleEntry({ method: "cards", cardMethod: "direct" }));
  assert.equal(replaced.method, "cards");
  assert.equal(replaced.diceMethod, undefined);
  assert.equal(replaced.cardMethod, "direct");
  assert.equal(entryMethodLabel(replaced), "Playing cards · Direct word selection");
  // Methods with no variant field (coin, brain) drop every variant.
  const coin = normalizeEntry(sampleEntry({ method: "coin", diceMethod: "coldcard", seedMethod: "numbers" }), fixedNow);
  assert.equal(coin.diceMethod, undefined);
  assert.equal(coin.seedMethod, undefined);
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

test("derived Key Station snapshots backfill a new journal and auto-add later keys", () => {
  const doc = emptyDocument(), associations = new Map();
  const beforeCreate = sampleEntry({ walletId: 11, label: "Before journal", input: "1 2 3", created: undefined });
  const afterCreate = sampleEntry({ walletId: 12, label: "After journal", input: "4 5 6", created: undefined });
  assert.deepEqual(syncKeySnapshots(doc, [beforeCreate], associations, fixedNow), { added: 1, updated: 0, matched: 0 });
  assert.equal(doc.entries.length, 1);
  assert.deepEqual(syncKeySnapshots(doc, [afterCreate], associations, fixedNow), { added: 1, updated: 0, matched: 0 });
  assert.deepEqual(doc.entries.map((entry) => entry.label), ["Before journal", "After journal"]);
  assert.equal(associations.get(11), doc.entries[0].id);
  assert.equal(associations.get(12), doc.entries[1].id);
});

test("re-deriving one Key Station state updates its associated entry", () => {
  const doc = emptyDocument(), associations = new Map();
  const first = sampleEntry({ walletId: 21, label: "Same tab", input: "first transcript", fingerprint: "11111111", created: undefined });
  syncKeySnapshots(doc, [first], associations, fixedNow);
  const entryId = doc.entries[0].id, created = doc.entries[0].created;
  const next = { ...first, input: "replacement transcript", phrase: "replacement mnemonic", fingerprint: "22222222" };
  assert.deepEqual(syncKeySnapshots(doc, [next], associations, new Date("2026-09-02T00:00:00Z")), { added: 0, updated: 1, matched: 0 });
  assert.equal(doc.entries.length, 1);
  assert.equal(doc.entries[0].id, entryId);
  assert.equal(doc.entries[0].created, created);
  assert.equal(doc.entries[0].input, "replacement transcript");
  assert.equal(doc.entries[0].fingerprint, "22222222");
});

test("opening a journal matches meaningful snapshots and backfills only missing keys", () => {
  const doc = emptyDocument();
  const matching = sampleEntry({ walletId: 31, label: "Existing", input: "same transcript", created: undefined });
  const existing = addEntry(doc, matching, fixedNow);
  const reusedSessionId = { ...matching, walletId: 31, input: "different transcript", phrase: "different mnemonic" };
  const missing = sampleEntry({ walletId: 32, label: "Missing", input: "new transcript", fingerprint: "cafebabe", created: undefined });
  const reopenedAssociations = new Map();
  assert(keySnapshotMatchesEntry(existing, { ...matching, walletId: 999 }), "session ids must not participate in meaningful matching");
  assert(!keySnapshotMatchesEntry(existing, reusedSessionId), "a fingerprint and reused session id must not hide changed key content");
  assert.deepEqual(syncKeySnapshots(doc, [{ ...matching, walletId: 999 }, reusedSessionId, missing], reopenedAssociations, fixedNow), { added: 2, updated: 0, matched: 1 });
  assert.equal(doc.entries.length, 3);
  assert.equal(reopenedAssociations.get(999), existing.id);
  assert.notEqual(reopenedAssociations.get(31), existing.id);
});

test("automatically captured Key Station entries survive journal download and reopen", async () => {
  const doc = emptyDocument(), associations = new Map();
  const snapshot = sampleEntry({ walletId: 41, label: "Automatic backup", input: "saved transcript", created: undefined });
  syncKeySnapshots(doc, [snapshot], associations, fixedNow);
  const opened = await openDocument(pack(await sealDocument(doc, keys)), password);
  assert.equal(opened.doc.entries.length, 1);
  assert(keySnapshotMatchesEntry(opened.doc.entries[0], snapshot));
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

test("notebook export accepts 100 pages and refuses an unreadable 101-page file", () => {
  const journal = createJournal();
  journal.pages = Array.from({ length: 100 }, (_, index) => ({
    id: index + 1, number: index + 1, name: `Page ${index + 1}`, notesText: `Note ${index + 1}`,
  }));
  const restored = parseNotebook(serializeNotebook(journal));
  assert.equal(restored.pages.length, 100);
  assert.equal(restored.pages[99].notesText, "Note 100");
  journal.pages.push({ id: 101, number: 101, name: "Page 101", notesText: "Keep this note in memory" });
  assert.throws(() => serializeNotebook(journal), /between 1 and/);
  assert.equal(journal.pages.length, 101, "refusing export must not delete the excess page");
  assert.equal(journal.pages[100].notesText, "Keep this note in memory");
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
  const adjacent = journalNotebookRuns(journalKeyReferenceToken("aaaaaaaa", "aaaaaaaa") + journalKeyReferenceToken("Key B", "bbbbbbbb"));
  assert.deepEqual(adjacent, [
    { type: "key", name: "aaaaaaaa", fingerprint: "aaaaaaaa" },
    { type: "key", name: "Key B", fingerprint: "bbbbbbbb" },
  ]);
  // Repeated calls see the same input (no hidden regex cursor state).
  const source = "x ◆◆ [aaaaaaaa] ◆ y";
  assert.deepEqual(journalNotebookRuns(source), journalNotebookRuns(source));
  assert.equal(journalFromPlainText(source).notesText, source, "plain-text imports must preserve visible legacy boundaries");
  const legacyAdjacent = "◆◆ [aaaaaaaa] ◆◆◆ Key B [bbbbbbbb] ◆";
  assert.deepEqual(journalNotebookRuns(legacyAdjacent), [{ type: "text", text: legacyAdjacent }]);
  assert.equal(parseNotebook(serializeNotebook(journalFromPlainText(legacyAdjacent))).notesText, legacyAdjacent);
});

test("key reference ranges identify the complete atomic token", () => {
  const token = journalKeyReferenceToken("Key A", "deadbeef");
  assert.deepEqual(journalKeyReferenceRanges(`before ${token} after`), [{
    start: 7,
    end: 7 + token.length,
  }]);
  assert.deepEqual(journalKeyReferenceRanges("◆◆ [deadbeef]"), []);
});

test("the plain-text download preserves saved timestamps and former hint text", () => {
  assert.equal(formatNotebook("2026-09-02 10:00:00  real words"), "2026-09-02 10:00:00  real words");
  assert.equal(formatNotebook("2026-09-02 10:00:00 Add new note"), "2026-09-02 10:00:00 Add new note");
  assert.equal(formatNotebook("2026-09-02 10:00:00  Add new notes"), "2026-09-02 10:00:00  Add new notes");
  assert.equal(formatNotebook("2026-09-02 10:00:00  \n"), "2026-09-02 10:00:00");
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
  assert.equal(restored.extra, undefined); // only input/settings fields cross the trust boundary
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
  assert.equal(parseKeyVault(serializeKeyVault([managedKey({ result: null })])).keys[0].needsDerivation, true);
  assert.throws(() => serializeKeyVault([managedKey({ fields: [] })]), /invalid key/);
  assert.throws(() => parseKeyVault(JSON.stringify({ format: KEY_VAULT_FORMAT, version: KEY_VAULT_VERSION })), /too many keys/);
  assert.throws(() => parseKeyVault(JSON.stringify({ format: KEY_VAULT_FORMAT, version: KEY_VAULT_VERSION + 1, keys: [] })), /not a supported/);
  const ignoredDefault = parseKeyVault(JSON.stringify({ format: KEY_VAULT_FORMAT, version: KEY_VAULT_VERSION, keys: [] }));
  assert.deepEqual(ignoredDefault, { keys: [], ignoredKeys: [] });
  assert.ok(serializeKeyVault([]).endsWith("}\n")); // stable on-disk shape
});

test("vault entry identity prefers the app-assigned ID without merging wallet configurations", () => {
  const result = { masterIdentity: "mi", masterFingerprint: "deadbeef", rootXpub: "xpub1", xpub: "xpub2" };
  assert.equal(keyVaultIdentity({ result, id: 7 }), "7");
  assert.equal(keyVaultIdentity({ result, id: 8 }), "8");
  assert.equal(keyVaultIdentity({ result: {}, id: 7 }), "7");
  // Legacy states without runtime IDs still prefer a complete wallet
  // identity over a potentially colliding four-byte fingerprint. File
  // parsing strips both IDs and cached identities before creating states.
  assert.equal(keyVaultIdentity({ result }), "mi");
  assert.equal(keyVaultIdentity({ result: { masterFingerprint: "deadbeef", rootXpub: "xpub1", xpub: "xpub2" } }), "xpub1");
  assert.equal(keyVaultIdentity({ result: { rootXpub: "xpub1", xpub: "xpub2" } }), "xpub1");
  assert.equal(keyVaultIdentity({ result: { xpub: "xpub2" } }), "xpub2");
  assert.equal(keyVaultIdentity({ result: { masterFingerprint: "deadbeef" } }), "deadbeef");
  for (const id of [0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, "7", {}, []]) {
    assert.equal(keyVaultIdentity({ result, id }), "mi", "an invalid runtime ID must not shadow the legacy identity");
  }
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
  assert.equal(keyVaultIdentity(vault.keys[0]), "");
  assert.equal(vault.keys[0].fields.seed, "user supplied words");
});

// --- App wiring: the buttons actually route through these primitives ----------

test("the app routes every journal backup through the sealed primitives", () => {
  const app = read("src/js/app.js");
  // Existing records remain editable without creating new duplicate
  // records from Key Station activity.
  assert.doesNotMatch(app, /hodlJournalSyncKeySnapshots|hodlJournalCaptureDerivedKey/);
  assert.equal((app.match(/hodlJournalEntryMethodLabel\(entry\)/g) || []).length, 2);
  // Downloads encrypt with the unlocked journal keys by default and mark the
  // file as encrypted.
  assert.match(app, /async function hodlJournalDownloadContent\(kind, filename, text[\s\S]*?hodlJournalSealExport\(kind, text, hodlJournalKeys\)/);
  assert.match(app, /filename\.replace\(\/\\\.\[\^\.\]\+\$\/, ""\) \+ "\.encrypted\.json"/);
  // The journal file includes all components in the complete sealed backup.
  assert.match(app, /hodlJournalSealBackup\(hodlJournalDoc, hodlJournalKeys, backup\)/);
  assert.match(app, /link\.download = "entropylab-journal\.json"/);
  // Imports are size-bounded and sniff the export envelope before parsing.
  assert.match(app, /async function hodlJournalImportFile\(file\)[\s\S]*?file\.size > hodlJournalMaxFileLength/);
  assert.match(app, /outer\?\.entropylabJournalExport[\s\S]*?hodlJournalOpenExport\(outer, hodlJournalKeys\)/);
  assert.match(app, /hodlJournalStoreNotesText\(field\)[\s\S]*?hodlMergeNotebookImport\(hodlJournal, imported\)/);
  assert.match(app, /async function hodlKeyManagerImportFile\(file[^)]*\)[\s\S]*?file\.size > hodlJournalMaxFileLength/);
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
  assert.equal(keyVaultIdentity(vault.keys[0]), "");
  assert.equal(vault.keys[0].fields.seed, "user supplied words");
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

// Complete backup contract: accept legacy v2 and complete v3 documents, refuse
// malformed/oversized or unauthenticated components before restoring anything,
// and keep restored key inputs unverified. Fixtures below are literal format
// examples, not expected output generated by the implementation under test.
function completeBackupFixture() {
  return {
    version: 3,
    nextId: 8,
    entries: [{ id: 7, method: "seed", input: "user seed input", phrase: "user seed phrase", label: "Savings", notes: "safe shelf", created: "2026-10-22T12:00:00.000Z", walletId: null, walletName: "", fingerprint: "deadbeef" }],
    backup: {
      notebook: JSON.stringify({ format: "entropylab-notebook", version: 1, activePage: 1, pages: [
        { number: 3, name: "Checklist", style: { font: "serif", size: "large", spacing: "spacious" }, content: [{ type: "text", text: "check the paper backup" }] },
        { number: 9, name: "Recovery", style: { font: "mono", size: "small", spacing: "compact" }, content: [{ type: "text", text: "second secret note" }] },
      ] }),
      keyManager: JSON.stringify({ format: "entropylab-key-manager", version: 2, keys: [
        { name: "Included", mode: "seed", fields: { seed: "managed seed input", pass: "typed passphrase", privateKeys: { wif: "private key input" } }, result: { masterIdentity: "forged identity", rootXprv: "forged private output" }, reveal: true, needsDerivation: false },
        { name: "Excluded", mode: "hex", fields: { hex: "001122" } },
      ], ignoredKeys: [{ name: "Ignored", mode: "dice", fields: { dice: "123456", pass: "ignored passphrase" } }] }),
      includedKeys: [0],
      activeKey: 1,
      snapshot: { text: "Historical session with private recovery text", includePrivate: true },
      log: [{ at: "2026-10-22 12:00:00", tool: "calc", action: "derive", detail: "deadbeef" }],
    },
  };
}

test("complete backup: literal v3 restores every component and strips key trust claims", () => {
  const doc = parseDocument(JSON.stringify(completeBackupFixture()));
  assert.equal(doc.version, 3);
  assert.equal(doc.nextId, 8);
  assert.deepEqual(doc.entries, [{ id: 7, method: "seed", input: "user seed input", phrase: "user seed phrase", label: "Savings", notes: "safe shelf", created: "2026-10-22T12:00:00.000Z", walletId: null, walletName: "", fingerprint: "deadbeef" }]);
  const backup = doc.backup;
  assert.deepEqual(backup.notebook.pages, [
    { id: 1, number: 3, name: "Checklist", notesText: "check the paper backup", style: { font: "serif", size: "large", spacing: "spacious" } },
    { id: 2, number: 9, name: "Recovery", notesText: "second secret note", style: { font: "mono", size: "small", spacing: "compact" } },
  ]);
  assert.equal(backup.notebook.activePage, 1);
  assert.equal(backup.notebook.notesText, "second secret note");
  assert.equal(backup.notebook.nextPageId, 3);
  assert.equal(backup.notebook.nextPageNumber, 10);
  assert.deepEqual(backup.keyManager.keys.map((key) => key.name), ["Included", "Excluded"]);
  assert.deepEqual(backup.keyManager.keys[0].fields, { seed: "managed seed input", pass: "typed passphrase", privateKeys: { wif: "private key input" } });
  assert.equal(backup.keyManager.ignoredKeys[0].fields.pass, "ignored passphrase");
  for (const key of [...backup.keyManager.keys, ...backup.keyManager.ignoredKeys]) {
    assert.equal(key.result, null);
    assert.equal(key.reveal, false);
    assert.equal(key.needsDerivation, true);
    assert.equal(keyVaultIdentity(key), "");
  }
  assert.deepEqual(backup.includedKeys, [0]);
  assert.equal(backup.activeKey, 1);
  assert.deepEqual(backup.snapshot, { text: "Historical session with private recovery text", includePrivate: true });
  assert.deepEqual(backup.log, [{ at: "2026-10-22 12:00:00", tool: "calc", action: "derive", detail: "deadbeef" }]);
});

test("complete backup: v2 remains entry-only and unknown document versions are refused", () => {
  assert.deepEqual(parseDocument('{"version":2,"nextId":1,"entries":[]}'), { version: 2, nextId: 1, entries: [] });
  for (const version of [0, 1, 4, "3"]) {
    assert.throws(() => parseDocument(JSON.stringify({ ...completeBackupFixture(), version })), /corrupt|unsupported/);
  }
});

// A legacy file accepted at its original limit must remain preservable when
// the default complete-backup sections are added, with no entry truncation.
test("complete backup: a maximum-size legacy document can be saved with the default sections", async () => {
  const legacy = { version: 2, nextId: 2, entries: [{
    id: 1, method: "seed", input: "", phrase: "", label: "Legacy notebook", notes: "",
    created: "2026-10-22T12:00:00.000Z", walletId: null, walletName: "", fingerprint: "",
  }] };
  legacy.entries[0].notes = "n".repeat(1024 * 1024 - JSON.stringify(legacy).length);
  const originalText = JSON.stringify(legacy);
  assert.equal(originalText.length, 1024 * 1024);
  assert.deepEqual(parseDocument(originalText), legacy);
  assert.throws(() => parseDocument(originalText + " "), /too large/);
  await assert.rejects(() => sealDocument({ ...legacy, entries: [{ ...legacy.entries[0], notes: legacy.entries[0].notes + "n" }] }, keys), /too large/);
  const originalFile = pack(await sealDocument(legacy, keys));
  const reopened = await openDocument(originalFile, password);
  const backup = {
    notebook: JSON.stringify({ format: "entropylab-notebook", version: 1, activePage: 0, pages: [
      { number: 1, name: "Page 1", style: { font: "mono", size: "medium", spacing: "comfortable" }, content: [] },
    ] }),
    keyManager: '{"format":"entropylab-key-manager","version":2,"keys":[],"ignoredKeys":[]}',
    includedKeys: [], activeKey: null, snapshot: { text: "", includePrivate: true }, log: [],
  };
  const completeFile = pack(await journalModule.sealBackup(reopened.doc, reopened.keys, backup));
  assert.ok(Buffer.byteLength(completeFile) <= 4 * 1024 * 1024);
  const restored = await openDocument(completeFile, password);
  assert.equal(restored.doc.version, 3);
  assert.deepEqual(restored.doc.entries, legacy.entries, "upgrading a valid legacy backup changed its record text");
  assert.equal(restored.doc.backup.notebook.pages[0].notesText, "");
  assert.deepEqual(restored.doc.backup.keyManager, { keys: [], ignoredKeys: [] });
  assert.deepEqual(restored.doc.backup.snapshot, { text: "", includePrivate: true });
});

test("complete backup: the separate two-MiB total limit does not relax component or legacy limits", async () => {
  const fixture = completeBackupFixture();
  fixture.entries[0].notes = "n".repeat(1024 * 1024);
  fixture.backup.snapshot.text = "";
  fixture.backup.snapshot.text = "s".repeat(2 * 1024 * 1024 - JSON.stringify(fixture).length);
  const text = JSON.stringify(fixture);
  assert.equal(text.length, 2 * 1024 * 1024);
  const opened = parseDocument(text);
  assert.equal(opened.entries[0].notes, fixture.entries[0].notes);
  assert.equal(opened.backup.snapshot.text, fixture.backup.snapshot.text);
  assert.throws(() => parseDocument(text + " "), /too large/);
  const oversized = { ...fixture, entries: [{ ...fixture.entries[0], input: fixture.entries[0].input + "n" }] };
  await assert.rejects(() => journalModule.sealBackup(oversized, keys, oversized.backup), /too large/);
  assert.throws(() => parseDocument(JSON.stringify({ ...fixture, version: 2 })), /too large/);
  assert.throws(() => parseDocument("x".repeat(1024 * 1024 + 1)), /too large/);
  const snapshotTooLarge = completeBackupFixture();
  snapshotTooLarge.backup.snapshot.text = "s".repeat(1024 * 1024 + 1);
  assert.throws(() => parseDocument(JSON.stringify(snapshotTooLarge)), /snapshot|too large/);
  const entryTooLarge = completeBackupFixture();
  entryTooLarge.entries[0].notes = "n".repeat(1024 * 1024 + 1);
  assert.throws(() => parseDocument(JSON.stringify(entryTooLarge)), /too large/);
});

test("complete backup: every component is required and schema checked", () => {
  for (const field of ["notebook", "keyManager", "includedKeys", "activeKey", "snapshot", "log"]) {
    const fixture = completeBackupFixture();
    delete fixture.backup[field];
    assert.throws(() => parseDocument(JSON.stringify(fixture)), /backup|notebook|key file|snapshot|log/i, `missing ${field}`);
  }
  for (const badBackup of [null, [], "text", {}]) {
    assert.throws(() => parseDocument(JSON.stringify({ ...completeBackupFixture(), backup: badBackup })), /backup/i);
  }
  const mutations = [
    (b) => { b.notebook = {}; },
    (b) => { b.notebook = '{"format":"wrong","version":1,"pages":[]}'; },
    (b) => { b.notebook = JSON.stringify({ format: NOTEBOOK_FORMAT, version: NOTEBOOK_VERSION, pages: [{ content: [{ type: "html", text: "<script>" }] }] }); },
    (b) => { b.keyManager = []; },
    (b) => { b.keyManager = '{"format":"entropylab-key-manager","version":3,"keys":[]}'; },
    (b) => { b.keyManager = '{"format":"entropylab-key-manager","version":2,"keys":[{"fields":null}]}'; },
    (b) => { b.snapshot = { text: "saved", includePrivate: "false" }; },
    (b) => { b.snapshot.text = { secret: "text" }; },
    (b) => { b.log = {}; },
    (b) => { b.log = [null]; },
    (b) => { b.log[0].detail = { secret: "text" }; },
    (b) => { delete b.log[0].at; },
    (b) => { b.log[0].detail = "x".repeat(301); },
  ];
  for (const mutate of mutations) {
    const fixture = completeBackupFixture();
    mutate(fixture.backup);
    assert.throws(() => parseDocument(JSON.stringify(fixture)), /backup|notebook|key file|content item|invalid key|snapshot|log/i);
  }
});

test("complete backup: key selections are unique in-range integer indexes", () => {
  for (const includedKeys of [[-1], [2], [0.5], ["0"], [0, 0], null, {}]) {
    const fixture = completeBackupFixture();
    fixture.backup.includedKeys = includedKeys;
    assert.throws(() => parseDocument(JSON.stringify(fixture)), /backup|key selection/i);
  }
  for (const activeKey of [-1, 2, 0.5, "0"]) {
    const fixture = completeBackupFixture();
    fixture.backup.activeKey = activeKey;
    assert.throws(() => parseDocument(JSON.stringify(fixture)), /backup|active key/i);
  }
  const fixture = completeBackupFixture();
  fixture.backup.keyManager = '{"format":"entropylab-key-manager","version":2,"keys":[],"ignoredKeys":[]}';
  fixture.backup.includedKeys = [];
  fixture.backup.activeKey = null;
  const backup = parseDocument(JSON.stringify(fixture)).backup;
  assert.deepEqual(backup.keyManager, { keys: [], ignoredKeys: [] });
  assert.deepEqual(backup.includedKeys, []);
  assert.equal(backup.activeKey, null);
});

// Serialized v3 passphrases must be absent or text. Other JSON values must
// never reach runtime conversion after the current journal has been replaced.
test("complete backup: non-text stored passphrases are rejected before restore", async () => {
  for (const collection of ["keys", "ignoredKeys"]) {
    for (const pass of [{ toString: null }, {}, [], 0, 42, false, true, null]) {
      const fixture = completeBackupFixture(), vault = JSON.parse(fixture.backup.keyManager);
      vault[collection][0].fields.pass = pass;
      fixture.backup.keyManager = JSON.stringify(vault);
      assert.throws(() => parseDocument(JSON.stringify(fixture)), /passphrase.*text/i, `${collection} accepted ${JSON.stringify(pass)}`);
      await assert.rejects(() => journalModule.sealBackup(fixture, keys, fixture.backup), /passphrase.*text/i);
    }
  }
});

test("complete backup: text or absent passphrases retain their exact value", () => {
  for (const collection of ["keys", "ignoredKeys"]) {
    for (const pass of [undefined, "", " ", "0", "TREZOR", "e\u0301"]) {
      const fixture = completeBackupFixture(), vault = JSON.parse(fixture.backup.keyManager);
      if (pass === undefined) delete vault[collection][0].fields.pass;
      else vault[collection][0].fields.pass = pass;
      fixture.backup.keyManager = JSON.stringify(vault);
      const opened = parseDocument(JSON.stringify(fixture));
      assert.equal(opened.backup.keyManager[collection][0].fields.pass, pass);
    }
  }
  // The shared portable-input boundary now rejects malformed passphrases in
  // standalone legacy vaults too, before any caller can coerce them to text.
  const legacy = '{"format":"entropylab-key-manager","version":1,"keys":[{"fields":{"pass":0}}]}';
  assert.throws(() => parseKeyVault(legacy), /passphrase.*text/i);
});

test("complete backup: malformed passphrase rejection wipes staged component objects", () => {
  const source = read("src/js/journal.js"), start = source.indexOf("function parseBackup("), end = source.indexOf("\nasync function sealPlainText(", start);
  assert.ok(start >= 0 && end > start);
  let notebook, vault;
  const parse = new Function("parseNotebook", "parseKeyVault", "JOURNAL_MAX_TEXT_LENGTH", "JOURNAL_LOG_LIMIT", "JOURNAL_LOG_MAX_BYTES", "logEventBytes", "wipeBackup", `${source.slice(start, end)}\nreturn parseBackup;`)(
    (text) => (notebook = parseNotebook(text)),
    (text) => {
      // Fault injection preserves the later complete-backup guard's wipe
      // coverage even though the real vault parser now rejects this sooner.
      const raw = JSON.parse(text), malformed = raw.ignoredKeys[0].fields.pass;
      raw.ignoredKeys[0].fields.pass = "";
      vault = parseKeyVault(JSON.stringify(raw));
      vault.ignoredKeys[0].fields.pass = malformed;
      return vault;
    },
    JOURNAL_MAX_TEXT_LENGTH, JOURNAL_LOG_LIMIT, journalModule.JOURNAL_LOG_MAX_BYTES, event => journalModule.logUsage({ log: [event] }).bytes - 2, journalModule.wipeBackup,
  );
  const fixture = completeBackupFixture(), rawVault = JSON.parse(fixture.backup.keyManager);
  rawVault.ignoredKeys[0].fields.pass = { toString: null, text: "temporary secret" };
  fixture.backup.keyManager = JSON.stringify(rawVault);
  assert.throws(() => parse(fixture.backup), /passphrase.*text/i);
  assert.equal(notebook.pages[0].notesText, "");
  assert.equal(vault.keys[0].fields.seed, "");
  assert.equal(vault.keys[0].fields.pass, "");
  assert.equal(vault.ignoredKeys[0].fields.pass.text, "");
});

test("complete backup: early vault passphrase rejection wipes the notebook before a vault is staged", () => {
  const source = read("src/js/journal.js"), start = source.indexOf("function parseBackup("), end = source.indexOf("\nasync function sealPlainText(", start);
  let notebook, vault;
  const parse = new Function("parseNotebook", "parseKeyVault", "JOURNAL_MAX_TEXT_LENGTH", "JOURNAL_LOG_LIMIT", "JOURNAL_LOG_MAX_BYTES", "logEventBytes", "wipeBackup", `${source.slice(start, end)}\nreturn parseBackup;`)(
    (text) => (notebook = parseNotebook(text)),
    (text) => (vault = parseKeyVault(text)),
    JOURNAL_MAX_TEXT_LENGTH, JOURNAL_LOG_LIMIT, journalModule.JOURNAL_LOG_MAX_BYTES, event => journalModule.logUsage({ log: [event] }).bytes - 2, journalModule.wipeBackup,
  );
  const fixture = completeBackupFixture(), rawVault = JSON.parse(fixture.backup.keyManager);
  rawVault.ignoredKeys[0].fields.pass = { value: "must not coerce" };
  fixture.backup.keyManager = JSON.stringify(rawVault);
  assert.throws(() => parse(fixture.backup), /passphrase.*text/i);
  assert.equal(notebook.pages[0].notesText, "");
  assert.equal(vault, undefined);
});

test("complete backup: component counts and individual snapshot text are bounded", () => {
  const mutations = [
    (b) => { b.notebook = JSON.stringify({ format: NOTEBOOK_FORMAT, version: NOTEBOOK_VERSION, pages: Array.from({ length: 101 }, () => ({ content: [] })) }); },
    (b) => { b.keyManager = JSON.stringify({ format: KEY_VAULT_FORMAT, version: KEY_VAULT_VERSION, keys: Array.from({ length: 101 }, () => ({ fields: {} })) }); },
    (b) => { b.keyManager = JSON.stringify({ format: KEY_VAULT_FORMAT, version: KEY_VAULT_VERSION, keys: [], ignoredKeys: Array.from({ length: 101 }, () => ({ fields: {} })) }); },
    (b) => { b.log = Array.from({ length: JOURNAL_LOG_LIMIT + 1 }, () => b.log[0]); },
    (b) => { b.snapshot.text = "s".repeat(JOURNAL_MAX_TEXT_LENGTH + 1); },
  ];
  for (const mutate of mutations) {
    const fixture = completeBackupFixture();
    mutate(fixture.backup);
    assert.throws(() => parseDocument(JSON.stringify(fixture)), /between 1 and|too many|too large|snapshot|log/i);
  }
  const fixture = completeBackupFixture();
  fixture.entries.push({ ...fixture.entries[0] });
  assert.throws(() => parseDocument(JSON.stringify(fixture)), /duplicate entry ids/);
});

test("complete backup: sealing is deterministic, opaque, and keeps envelope v2", async () => {
  const fixture = completeBackupFixture();
  const first = await journalModule.sealBackup(fixture, keys, fixture.backup);
  assert.deepEqual(await journalModule.sealBackup(fixture, keys, fixture.backup), first);
  assert.equal(first.entropylabJournal, 2);
  const opened = await openDocument(pack(first), password);
  assert.equal(opened.doc.version, 3);
  assert.equal(opened.doc.backup.notebook.pages[1].notesText, "second secret note");
  assert.equal(opened.doc.backup.keyManager.keys[0].fields.pass, "typed passphrase");
  for (const secret of ["user seed phrase", "second secret note", "typed passphrase", "Historical session", "ignored passphrase"]) assert.ok(!pack(first).includes(secret));
  const plain = new TextDecoder().decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: Buffer.from(first.iv, "hex") }, keys.encKey, Buffer.from(first.ciphertext, "hex")));
  assert.equal(JSON.parse(plain).version, 3, "old readers must reject the new payload instead of dropping its components");
  assert.ok(!plain.includes("forged private output"));
  assert.ok(!plain.includes("forged identity"));
});

test("complete backup: wrong password and modified ciphertext or IV never restore", async () => {
  const fixture = completeBackupFixture();
  const file = await journalModule.sealBackup(fixture, keys, fixture.backup);
  await assert.rejects(() => openDocument(pack(file), "wrong password"), /password is incorrect/);
  await assert.rejects(() => openDocument(pack({ ...file, ciphertext: flip(file.ciphertext, 0) }), password), /password is incorrect/);
  await assert.rejects(() => openDocument(pack({ ...file, iv: flip(file.iv, 0) }), password), /password is incorrect/);
  await assert.rejects(() => journalModule.sealBackup(fixture, null, fixture.backup), /Unlock/);
});

test("complete backup: passwordless files remain explicitly unprotected", async () => {
  const fixture = completeBackupFixture();
  const unprotected = await createDocument("", "");
  const file = await journalModule.sealBackup(fixture, unprotected.keys, fixture.backup);
  const opened = await openDocument(pack(file), "");
  assert.equal(opened.keys.passwordProtected, false);
  assert.equal(opened.doc.backup.snapshot.text, "Historical session with private recovery text");
});

test("complete backup: save validates components and refuses unreadable sizes", async () => {
  const fixture = completeBackupFixture();
  await assert.rejects(() => journalModule.sealBackup(fixture, keys, { ...fixture.backup, includedKeys: [9] }), /backup|key selection/i);
  await assert.rejects(() => journalModule.sealBackup(fixture, keys, { ...fixture.backup, snapshot: { text: "x".repeat(JOURNAL_MAX_TEXT_LENGTH + 1), includePrivate: false } }), /snapshot|too large/);
  // UTF-8 expansion followed by hex encoding can exceed the outer 4 MiB cap
  // even when every field and the complete plaintext are below their caps.
  await assert.rejects(() => journalModule.sealBackup(fixture, keys, { ...fixture.backup, snapshot: { text: "界".repeat(750000), includePrivate: false } }), /too large/);
});

test("complete backup: discard wipes nested source inputs and retained references", () => {
  // Built directly so this regression detects incomplete wiping independently
  // of whether the new parser has been implemented yet.
  for (const owner of ["document", "journal"]) {
    const page = { name: "secret title", notesText: "secret notes" };
    const fields = { seed: "secret seed", pass: "secret pass", privateKeys: { wif: "secret WIF" }, nested: [{ text: "nested secret" }], bytes: new Uint8Array([4, 5, 6]) };
    const ignoredFields = { pass: "ignored secret" };
    const snapshot = { text: "secret snapshot", includePrivate: true };
    const event = { at: "date", tool: "tool", action: "action", detail: "secret detail" };
    const backup = { notebook: { pages: [page], notesText: "secret notes" }, keyManager: { keys: [{ fields }], ignoredKeys: [{ fields: ignoredFields }] }, snapshot, log: [event], logDiscarded: 37, includedKeys: [0], activeKey: 0 };
    const holder = owner === "document" ? { entries: [], nextId: 1, backup } : { ...createJournal(), backup };
    (owner === "document" ? wipeDocument : wipeJournal)(holder);
    for (const value of [page.notesText, page.name, fields.seed, fields.pass, fields.privateKeys.wif, fields.nested[0].text, ignoredFields.pass, snapshot.text, event.detail]) assert.equal(value, "", `${owner} kept a backup secret`);
    assert.deepEqual([...fields.bytes], [0, 0, 0]);
    assert.equal(backup.logDiscarded, 0);
    assert.equal(holder.backup, null);
  }
});

// Retention metadata is data, not a trusted size claim. Old backups default to
// zero discarded events; new ones must fit the actual UTF-8 log budget.
test("complete backup: larger debug history and discarded count roundtrip without changing encryption", async () => {
  const fixture = completeBackupFixture();
  fixture.backup.log = Array.from({ length: 450 }, (_, index) => ({ at: "t", tool: "calc", action: "derive", detail: String(index) }));
  fixture.backup.logDiscarded = 37;
  const parsed = parseDocument(JSON.stringify(fixture));
  assert.equal(parsed.backup.log.length, 450);
  assert.equal(parsed.backup.logDiscarded, 37);
  const file = await journalModule.sealBackup(fixture, keys, fixture.backup);
  const opened = await openDocument(pack(file), password);
  assert.deepEqual(opened.doc.backup.log, fixture.backup.log);
  assert.equal(opened.doc.backup.logDiscarded, 37);
  const legacy = completeBackupFixture();
  legacy.backup.log = Array.from({ length: 400 }, (_, index) => ({ at: "t", tool: "calc", action: "derive", detail: String(index) }));
  const legacyBackup = parseDocument(JSON.stringify(legacy)).backup;
  assert.equal(legacyBackup.logDiscarded, 0);
  assert.deepEqual(legacyBackup.log, legacy.backup.log);
});

test("complete backup: exact serialized UTF-8 log byte boundary is accepted and one byte more is rejected", () => {
  const fixture = completeBackupFixture(), event = { at: "t", tool: "", action: "", detail: "界".repeat(300) };
  const budget = 512 * 1024, bytes = value => Buffer.byteLength(JSON.stringify(value), "utf8");
  const log = [];
  while (bytes(log) + bytes(event) + 1 <= budget - 400) log.push({ ...event });
  let remaining = budget - bytes(log) - bytes({ ...event, detail: "" }) - 1;
  while (remaining > 300) {
    log.push({ ...event, detail: "x".repeat(300) });
    remaining = budget - bytes(log) - bytes({ ...event, detail: "" }) - 1;
  }
  assert.ok(remaining >= 0 && remaining <= 300);
  log.push({ ...event, detail: "x".repeat(remaining) });
  assert.equal(bytes(log), budget);
  fixture.backup.log = log;
  fixture.backup.logDiscarded = 0;
  assert.equal(parseDocument(JSON.stringify(fixture)).backup.log.length, log.length);
  fixture.backup.log.at(-1).detail += "x";
  assert.equal(bytes(log), budget + 1);
  assert.throws(() => parseDocument(JSON.stringify(fixture)), /log|large/i);
});

test("complete backup: forged discarded metadata and oversized Unicode histories are rejected", () => {
  for (const value of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1, "1", null, {}, true]) {
    const fixture = completeBackupFixture();
    fixture.backup.logDiscarded = value;
    assert.throws(() => parseDocument(JSON.stringify(fixture)), /log|discarded/i);
  }
  const fixture = completeBackupFixture();
  fixture.backup.log = Array.from({ length: 200 }, () => ({ at: "界".repeat(300), tool: "界".repeat(300), action: "界".repeat(300), detail: "界".repeat(300) }));
  assert.ok(JSON.stringify(fixture).length < 2 * 1024 * 1024, "the test must reach the independent UTF-8 log cap");
  fixture.backup.logBytes = 2; // A supplied byte claim never overrides measurement.
  assert.throws(() => parseDocument(JSON.stringify(fixture)), /log|large/i);
});

test("complete backup: Unicode log bytes are checked even below the old event-count cap", () => {
  const fixture = completeBackupFixture();
  fixture.backup.log = Array.from({ length: 200 }, () => ({ at: "界".repeat(300), tool: "界".repeat(300), action: "界".repeat(300), detail: "界".repeat(300) }));
  assert.ok(Buffer.byteLength(JSON.stringify(fixture.backup.log), "utf8") > 512 * 1024);
  assert.ok(JSON.stringify(fixture).length < 2 * 1024 * 1024);
  assert.throws(() => parseDocument(JSON.stringify(fixture)), /log|large/i);
});

// Snapshot metadata selects an equality-comparison suffix only; it must never
// authorize truncating imported history or silently removing recovery text.
test("complete backup: snapshot latest offsets are optional validated integers preserved through encryption", async () => {
  for (const latestStart of [0, 2, 4]) {
    const fixture = completeBackupFixture();
    fixture.backup.snapshot = { text: "abcd", includePrivate: true, latestStart };
    assert.deepEqual(parseDocument(JSON.stringify(fixture)).backup.snapshot, fixture.backup.snapshot);
    const sealed = await journalModule.sealBackup(fixture, keys, fixture.backup);
    const opened = await openDocument(pack(sealed), password);
    assert.deepEqual(opened.doc.backup.snapshot, fixture.backup.snapshot);
  }
  const legacy = completeBackupFixture();
  assert.deepEqual(parseDocument(JSON.stringify(legacy)).backup.snapshot, legacy.backup.snapshot);
});

test("complete backup: malformed snapshot offsets are rejected instead of ignored", () => {
  for (const latestStart of [-1, 5, 0.5, "0", null, true, {}, [], Number.MAX_SAFE_INTEGER + 1]) {
    const fixture = completeBackupFixture();
    fixture.backup.snapshot = { text: "abcd", includePrivate: true, latestStart };
    assert.throws(() => parseDocument(JSON.stringify(fixture)), /snapshot/i);
  }
});

const snapshotReport = (body, stamp = "2026-10-23 12:00:00") => ({ text: `ENTROPYLAB SESSION STATE\nUpdated: ${stamp}\n${body}`, includePrivate: true });
test("snapshot combination retains historical secrets once across empty and identical restore-save cycles", () => {
  const original = { text: "Literal legacy private material <tag>\nUpdated: keep this line", includePrivate: true };
  const first = journalModule.combineSnapshots(original, snapshotReport("BIP-85\nchild-secret-one"));
  const expected = original.text + "\n\n" + snapshotReport("BIP-85\nchild-secret-one").text;
  assert.equal(first.text, expected);
  assert.equal(first.latestStart, original.text.length + 2);
  let saved = first;
  for (let cycle = 0; cycle < 20; cycle++) {
    const fixture = completeBackupFixture();
    fixture.backup.snapshot = saved;
    saved = parseDocument(JSON.stringify(fixture)).backup.snapshot;
    saved = journalModule.combineSnapshots(saved, snapshotReport("KEYS\n(none)", "later"), false);
    saved = journalModule.combineSnapshots(saved, snapshotReport("BIP-85\nchild-secret-one", `later ${cycle}`));
    assert.equal(saved.text, expected, "an empty restore or changed capture time must not add another report");
    assert.equal(saved.latestStart, first.latestStart);
  }
  assert.equal(original.text, "Literal legacy private material <tag>\nUpdated: keep this line");
});

test("snapshot combination preserves new private material from every changed derived session", () => {
  const first = snapshotReport("KEYS\noriginal-root"), second = snapshotReport("BIP-85\nchild-secret-two");
  const saved = journalModule.combineSnapshots(first, second);
  const third = snapshotReport("KEYS\nnew-root");
  const combined = journalModule.combineSnapshots(saved, third);
  assert.equal(combined.text, first.text + "\n\n" + second.text + "\n\n" + third.text);
  assert.equal(combined.latestStart, saved.text.length + 2);
  assert.deepEqual(journalModule.combineSnapshots(combined, snapshotReport("KEYS\n(none)"), false), combined);
  assert.deepEqual(journalModule.combineSnapshots(null, first), first);
});

test("snapshot combination ignores only capture time and never truncates history to fit", () => {
  const before = snapshotReport("BIP-85\nUpdated: secret-one"), after = snapshotReport("BIP-85\nUpdated: secret-two");
  assert.equal(journalModule.combineSnapshots(before, after).text, before.text + "\n\n" + after.text);
  const full = { text: "p".repeat(JOURNAL_MAX_TEXT_LENGTH), includePrivate: true };
  assert.deepEqual(journalModule.combineSnapshots(full, snapshotReport("empty"), false), full);
  assert.throws(() => journalModule.combineSnapshots(full, snapshotReport("new recovery")), /snapshot.*large.*export.*remove/i);
  assert.equal(full.text.length, JOURNAL_MAX_TEXT_LENGTH);
});

const RELEASE_MODES = ["dice", "cards", "hex", "seed", "key"];

test("a key file or journal backup naming a method this build does not offer is refused", () => {
  // A release build leaves the preview-only core-wallet method out; a key
  // exported from a preview build must not bring it back on import. Journal
  // backups carry their keys through the same parseKeyVault.
  setKeyVaultModes(RELEASE_MODES);
  try {
    const exported = serializeKeyVault([managedKey({ mode: "corewallet", coreMixSource: "cards" })]);
    assert.throws(() => parseKeyVault(exported), /invalid key/);
    assert.equal(parseKeyVault(serializeKeyVault([managedKey({ mode: "dice" })])).keys[0].mode, "dice");
    assert.equal(parseKeyVault(serializeKeyVault([managedKey()])).keys.length, 1, "a key with no mode stays the default dice method");
  } finally {
    setKeyVaultModes(null);
  }
});

test("a preview build imports its core-wallet keys with their dice/cards source", () => {
  setKeyVaultModes([...RELEASE_MODES, "corewallet"]);
  try {
    const [restored] = parseKeyVault(serializeKeyVault([managedKey({ mode: "corewallet", coreMixSource: "cards" })])).keys;
    assert.equal(restored.mode, "corewallet");
    assert.equal(restored.coreMixSource, "cards");
  } finally {
    setKeyVaultModes(null);
  }
});

test("app.js hands the import boundary the methods this build offers, after the preview gate", () => {
  const app = read("src/js/app.js");
  const gate = app.indexOf('hodlKeyModes.push("corewallet")');
  const set = app.indexOf("setKeyVaultModes(hodlKeyModes)");
  assert.ok(gate > 0 && set > gate, "setKeyVaultModes runs after the preview-only method is (or is not) added");
});

test("the release build's own method list refuses core-wallet keys, the preview list accepts them", () => {
  // Read the shipped list from app.js (not a hand-written copy), then apply
  // the preview gate both ways, exactly as app.js does before calling
  // setKeyVaultModes.
  const app = read("src/js/app.js");
  const literal = app.match(/^var hodlKeyModes = (\[[^\]]*\])/m);
  assert.ok(literal, "app.js declares hodlKeyModes as an array literal");
  const release = JSON.parse(literal[1]);
  assert.ok(!release.includes("corewallet"), "the release list does not offer the preview-only method");
  const exported = serializeKeyVault([managedKey({ mode: "corewallet", coreMixSource: "dice" })]);
  try {
    setKeyVaultModes(release);
    assert.throws(() => parseKeyVault(exported), /invalid key/);
    setKeyVaultModes([...release, "corewallet"]);
    assert.equal(parseKeyVault(exported).keys[0].mode, "corewallet");
  } finally {
    setKeyVaultModes(null);
  }
});

test("a core-wallet source other than dice or cards is refused at import", () => {
  for (const source of ["hex", "", 1, null, { toString: () => "dice" }]) {
    const exported = serializeKeyVault([managedKey({ mode: "corewallet", coreMixSource: source })]);
    assert.throws(() => parseKeyVault(exported), /invalid key/, `coreMixSource ${JSON.stringify(source)} must be refused`);
  }
  assert.equal(parseKeyVault(serializeKeyVault([managedKey({ mode: "corewallet", coreMixSource: "cards" })])).keys[0].coreMixSource, "cards");
});
