import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  IV_BYTES,
  JOURNAL_ITERATIONS,
  JOURNAL_EXPORT_VERSION,
  JOURNAL_LOG_LIMIT,
  JOURNAL_MAX_ENTRIES,
  JOURNAL_MAX_FILE_LENGTH,
  JOURNAL_MAX_TEXT_LENGTH,
  JOURNAL_VERSION,
  METHODS,
  addEntry,
  NOTEBOOK_FORMAT,
  NOTEBOOK_VERSION,
  NOTEBOOK_MAX_PAGES,
  NOTEBOOK_MAX_TEXT_LENGTH,
  appendLog,
  assertPassword,
  createDocument,
  createJournal,
  emptyDocument,
  encodeFile,
  defaultJournalPageStyle,
  formatLog,
  formatNotebook,
  formatNotebookPages,
  formatStamp,
  openDocument,
  openExport,
  parseDocument,
  parseFile,
  removeEntry,
  replaceEntry,
  searchEntries,
  sealDocument,
  sealExport,
  snapshotFromKeyState,
  wipeDocument,
  journalFromPlainText,
  journalBip85ReferenceToken,
  journalKeyReferenceRanges,
  journalKeyReferenceToken,
  journalNotebookRuns,
  journalTextFromRuns,
  mergeNotebookImport,
  notebookPageHasContent,
  parseNotebook,
  serializeNotebook,
  snapshotSession,
  wipeJournal,
  normalizeJournalPageStyle,
  keySnapshotMatchesEntry,
  syncKeySnapshots,
  wipeBytes,
  wipeEntry,
  entryMethodLabel,
  deriveJournalKeys,
  JOURNAL_KDF,
  JOURNAL_CIPHER,
  JOURNAL_SALT_PREFIX,
  JOURNAL_MIN_ITERATIONS,
  JOURNAL_MAX_ITERATIONS,
  METHOD_LABELS,
} from "../src/js/journal.js";
import {
  NONCE_HISTORY_FORMAT,
  compareNonceHistory,
  mergeNonceHistory,
  nonceHistoryRecord,
  parseNonceHistory,
  serializeNonceHistory,
} from "../src/js/nonce-history.js";

const nonceBytes = (hex) => Uint8Array.from(hex.match(/../g) || [], (pair) => parseInt(pair, 16));
const nonceKeyA = nonceBytes(`02${"11".repeat(32)}`);
const nonceKeyB = nonceBytes(`03${"22".repeat(32)}`);
const nonceR = nonceBytes("33".repeat(32));
const nonceDigestA = nonceBytes("44".repeat(32));
const nonceDigestB = nonceBytes("55".repeat(32));
const nonceContext = nonceBytes("66".repeat(36));
const nonceCheckedAt = "2026-09-10T20:15:30.000Z";

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

test("the notebook download preserves blank lines and removes untouched inline hints", () => {
  let text = "2026-09-02 10:00:00  first note\n\n2026-09-02 10:01:00  Add new note";
  assert.equal(formatNotebook(text), "2026-09-02 10:00:00  first note");
  assert.equal(formatNotebook("2026-09-02 10:00:00  first note\n2026-09-02 10:01:00  "), "2026-09-02 10:00:00  first note");
  assert.equal(formatNotebook(""), "No notes.");
});

test("a multi-page notebook download includes every named page", () => {
  assert.equal(formatNotebookPages([
    { number: 1, name: "Field notes", notesText: "2026-09-02 10:00:00  first note" },
    { number: 2, name: "Page 2", notesText: "2026-09-02 10:01:00  " },
  ]), "Field notes\n2026-09-02 10:00:00  first note\n\nPage 2\nNo notes.");
  assert.equal(formatNotebookPages([{ number: 1, name: "Page 1", notesText: "" }]), "No notes.");
});

test("key references round-trip as structured public runs and stay readable in text", () => {
  let token = journalKeyReferenceToken("Signing ◆ key\nbackup", "A1B2C3D4");
  assert.equal(token, "◆◆ Signing ◇ key backup [a1b2c3d4]\u2063");
  let source = `before ${token} after`;
  assert.deepEqual(journalNotebookRuns(source), [
    { type: "text", text: "before " },
    { type: "key", name: "Signing ◇ key backup", fingerprint: "a1b2c3d4" },
    { type: "text", text: " after" },
  ]);
  assert.equal(journalTextFromRuns(journalNotebookRuns(source)), source);
  assert.equal(formatNotebook(source), "before [Key: Signing ◇ key backup · a1b2c3d4] after");
  assert.throws(() => journalKeyReferenceToken("Key", "not-an-xfp"), /8-character hexadecimal/);
});

test("key references do not repeat a default fingerprint name", () => {
  let token = journalKeyReferenceToken("A1B2C3D4", "a1b2c3d4");
  assert.equal(token, "◆◆ [a1b2c3d4]\u2063");
  assert.deepEqual(journalNotebookRuns(token), [
    { type: "key", name: "a1b2c3d4", fingerprint: "a1b2c3d4" },
  ]);
  assert.equal(journalTextFromRuns(journalNotebookRuns(token)), token);
  assert.equal(formatNotebook(token), "[Key: a1b2c3d4]");
});

test("BIP-85 references round-trip with their application and remain visually distinct", () => {
  for (let [application, label] of [["bip39", "BIP-39"], ["wif", "WIF"], ["xprv", "XPRV"], ["hex", "HEX"], ["pwd-base64", "Base64 password"], ["pwd-base85", "Base85 password"]]) {
    let token = journalBip85ReferenceToken(application, "DEADBEEF");
    assert.equal(token, `◈◈ BIP-85 · ${label} [deadbeef]\u2063`);
    assert.deepEqual(journalNotebookRuns(token), [{
      type: "key",
      name: `BIP-85 · ${label}`,
      fingerprint: "deadbeef",
      source: "bip85",
      application,
    }]);
    assert.equal(journalTextFromRuns(journalNotebookRuns(token)), token);
    assert.equal(formatNotebook(token), `[BIP-85 ${label}: deadbeef]`);
    assert.deepEqual(journalKeyReferenceRanges(token), [{ start: 0, end: token.length }]);
  }
  let journal = createJournal(), token = journalBip85ReferenceToken("wif", "deadbeef");
  journal.pages[0].notesText = token;
  let encoded = serializeNotebook(journal), document = JSON.parse(encoded);
  assert.deepEqual(document.pages[0].content[0], {
    type: "key", name: "BIP-85 · WIF", fingerprint: "deadbeef", source: "bip85", application: "wif",
  });
  assert.equal(parseNotebook(encoded).pages[0].notesText, token);
  assert.throws(() => journalBip85ReferenceToken("unknown", "deadbeef"), /supported application/);
  assert.throws(() => journalBip85ReferenceToken("wif", "not-an-xfp"), /8-character hexadecimal/);
});

test("the versioned notebook preserves pages, styles, and key references", () => {
  let journal = createJournal();
  journal.pages[0].name = "Field notes";
  journal.pages[0].style = { font: "serif", size: "large", spacing: "spacious" };
  journal.pages[0].notesText = `2026-09-02 10:00:00  ${journalKeyReferenceToken("Key 1", "deadbeef")}`;
  journal.pages.push({ id: 2, number: 2, name: "Page 2", notesText: "second", style: { font: "sans", size: "small", spacing: "compact" } });
  journal.activePage = 1;
  let encoded = serializeNotebook(journal), document = JSON.parse(encoded);
  assert.equal(document.format, NOTEBOOK_FORMAT);
  assert.equal(document.version, NOTEBOOK_VERSION);
  assert.deepEqual(document.pages[0].content[1], { type: "key", name: "Key 1", fingerprint: "deadbeef" });
  assert.doesNotMatch(encoded, /data:image|<img|xprv|mnemonic/);
  let restored = parseNotebook(encoded);
  assert.equal(restored.pages.length, 2);
  assert.equal(restored.activePage, 1);
  assert.equal(restored.pages[0].notesText, journal.pages[0].notesText);
  assert.deepEqual(restored.pages[0].style, journal.pages[0].style);
  assert.deepEqual(restored.pages[1].style, journal.pages[1].style);
  assert.equal(restored.nextPageNumber, 3);
});

test("notebook imports validate their schema and legacy text becomes one page", () => {
  assert.throws(() => parseNotebook("not json"), /not valid notebook JSON/);
  assert.throws(() => parseNotebook('{"format":"something-else","version":1,"pages":[]}'), /not a supported/);
  assert.throws(() => journalTextFromRuns([{ type: "html", text: "<img>" }]), /unsupported content item/);
  let legacy = journalFromPlainText("old notes\nkept as text");
  assert.equal(legacy.pages.length, 1);
  assert.equal(legacy.pages[0].notesText, "old notes\nkept as text");
  assert.deepEqual(legacy.pages[0].style, defaultJournalPageStyle());
});

test("notebook uploads preserve a filled page and reuse an empty current page", () => {
  assert.equal(notebookPageHasContent("2026-09-04 13:17:24  "), false);
  assert.equal(notebookPageHasContent("\n  \n2026-09-04 13:17:24  Add new note"), false);
  assert.equal(notebookPageHasContent("2026-09-04 13:17:24  kept"), true);
  let imported = journalFromPlainText("uploaded notes");
  let journal = createJournal();
  journal.pages[0].notesText = "2026-09-04 13:17:24  existing notes";
  journal.notesText = journal.pages[0].notesText;
  let merged = mergeNotebookImport(journal, imported);
  assert.equal(merged.pages.length, 2);
  assert.equal(merged.pages[0].notesText, journal.pages[0].notesText);
  assert.equal(merged.pages[1].notesText, "uploaded notes");
  assert.equal(merged.pages[1].name, "Page 2");
  assert.equal(merged.activePage, 1);
  let empty = createJournal();
  empty.pages[0].notesText = "2026-09-04 13:17:24  ";
  merged = mergeNotebookImport(empty, imported);
  assert.equal(merged.pages.length, 1);
  assert.equal(merged.pages[0].id, 1);
  assert.equal(merged.pages[0].number, 1);
  assert.equal(merged.pages[0].notesText, "uploaded notes");
  assert.equal(merged.activePage, 0);
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
  assert.match(publicText, /Updated: 2026-09-02 10:00:00/);
  assert.match(publicText, /inspector empty/);
  assert.match(publicText, /nonce history: 0 records/);
  assert.doesNotMatch(publicText, /nonce verdict/);
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
  let reuseText = snapshotSession({
    capturedAt: "2026-09-02 10:00:00",
    includePrivate: false,
    keys: [],
    msigs: [],
    bip85: [],
    sp: { derived: false },
    psbt: { loaded: true, nonce: "reuse", nonceKind: "psbt", historyCount: 2, historyVerdict: "reuse" },
  });
  assert.match(reuseText, /payload present in the inspector/);
  assert.match(reuseText, /nonce verdict: reused ECDSA nonce in this PSBT/);
  assert.match(reuseText, /nonce history: 2 records/);
  assert.match(reuseText, /cross-session comparison: reused ECDSA nonce detected/);
  assert.doesNotMatch(reuseText, /\br=/);
});

test("wipe drops notes, log, and snapshot text", () => {
  let journal = createJournal();
  appendLog(journal, { tool: "calc", action: "derive", detail: "fp=aa" });
  journal.stateText = "xprv...";
  journal.notesText = "2026-09-02 10:00:00  secret hint";
  journal.pages.push({ id: 2, number: 2, name: "Field notes", notesText: journal.notesText });
  journal.activePage = 1;
  journal.nextPageId = 3;
  journal.nextPageNumber = 3;
  wipeJournal(journal);
  assert.equal(journal.log.length, 0);
  assert.equal(journal.stateText, "");
  assert.equal(journal.notesText, "");
  assert.deepEqual(journal.pages, [{ id: 1, number: 1, name: "Page 1", notesText: "", style: defaultJournalPageStyle() }]);
  assert.equal(journal.activePage, 0);
  assert.equal(journal.nextPageId, 2);
  assert.equal(journal.nextPageNumber, 2);
});

test("the journal module never talks to the network, browser storage, or a CSPRNG", () => {
  const src = read("src/js/journal.js");
  assert.doesNotMatch(src, /\bfetch\s*\(|XMLHttpRequest|WebSocket|\blocalStorage\b|\bsessionStorage\b|indexedDB|Math\.random|crypto\.getRandomValues/);
});

// --- Encrypted entropy notebook (AES-GCM, password-derived, deterministic) ---

test("passwords are optional and confirmation must match", () => {
  assert.equal(assertPassword("", { confirm: "" }), undefined);
  assert.throws(() => assertPassword(42), /must be text/);
  assert.equal(assertPassword("short", { confirm: "short" }), undefined);
  assert.throws(() => assertPassword(password, { confirm: otherPassword }), /do not match/);
  assert.equal(assertPassword(password, { confirm: password }), undefined);
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
  await assert.rejects(() => openDocument(packed, otherPassword), /password is incorrect/);
  wipeDocument(opened.doc);
  assert.equal(opened.doc.entries.length, 0);
});

test("a journal with no password downloads and reopens with a blank password", async () => {
  const created = await createDocument("", "");
  assert.equal(created.keys.passwordProtected, false);
  addEntry(created.doc, { method: "coin", input: "HTHT", phrase: "seed", label: "passwordless" }, fixedNow);
  const packed = JSON.stringify(await sealDocument(created.doc, created.keys));
  const opened = await openDocument(packed, "");
  assert.equal(opened.keys.passwordProtected, false);
  assert.equal(opened.doc.entries[0].label, "passwordless");
  await assert.rejects(() => openDocument(packed, "not blank"), /password is incorrect/);
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

test("tab exports reuse the unlocked journal password keys and remain deterministic", async () => {
  const created = await createDocument(password, password);
  const first = await sealExport("notebook", "reloadable notebook JSON", created.keys);
  const second = await sealExport("notebook", "reloadable notebook JSON", created.keys);
  assert.equal(first.entropylabJournalExport, JOURNAL_EXPORT_VERSION);
  assert.deepEqual(second, first);
  assert.deepEqual(await openExport(JSON.stringify(first), created.keys), {
    kind: "notebook",
    content: "reloadable notebook JSON",
  });
  const other = await createDocument(otherPassword, otherPassword);
  await assert.rejects(() => openExport(first, other.keys), /different journal password/);
  await assert.rejects(() => sealExport("unknown", "text", created.keys), /not supported/);
  await assert.rejects(() => openExport("{}", created.keys), /not an encrypted Journal export/);
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

test("nonce history exports the check time, master fingerprint, raw r, and exact-key identity", () => {
  const options = { checkedAt: nonceCheckedAt, masterFingerprint: "deadbeef", pubkey: nonceKeyA, r: nonceR, sighash: nonceDigestA, valid: true };
  const first = nonceHistoryRecord(options);
  const again = nonceHistoryRecord(options);
  assert.deepEqual(first, again);
  assert.equal(first.checkedAt, nonceCheckedAt);
  assert.equal(first.masterFingerprint, "deadbeef");
  assert.match(first.keyTag, /^[0-9a-f]{64}$/);
  assert.equal(first.r, Buffer.from(nonceR).toString("hex"));
  assert.match(first.messageTag, /^[0-9a-f]{64}$/);
  assert.equal(first.verified, true);
  const text = serializeNonceHistory([first]);
  assert.equal(JSON.parse(text).format, NONCE_HISTORY_FORMAT);
  assert.equal(text.includes(Buffer.from(nonceR).toString("hex")), true, "raw r was omitted from the history file");
  for (const raw of [Buffer.from(nonceKeyA).toString("hex"), Buffer.from(nonceDigestA).toString("hex")]) {
    assert.equal(text.includes(raw), false, "unneeded signature material leaked into the history file");
  }
  assert.deepEqual(parseNonceHistory(text), [first]);
});

test("nonce history uses context for unknown messages and upgrades verified evidence", () => {
  const contextRecord = nonceHistoryRecord({ checkedAt: nonceCheckedAt, masterFingerprint: null, pubkey: nonceKeyA, r: nonceR, context: nonceContext, valid: true });
  assert.match(contextRecord.messageTag, /^[0-9a-f]{64}$/);
  assert.equal(contextRecord.verified, false);
  const unverified = nonceHistoryRecord({ checkedAt: nonceCheckedAt, masterFingerprint: "deadbeef", pubkey: nonceKeyA, r: nonceR, sighash: nonceDigestA, valid: false });
  const verified = nonceHistoryRecord({ checkedAt: nonceCheckedAt, masterFingerprint: "deadbeef", pubkey: nonceKeyA, r: nonceR, sighash: nonceDigestA, valid: true });
  assert.deepEqual(mergeNonceHistory([unverified], [verified]), [verified]);
});

test("nonce history comparison separates confirmed, possible, cross-key, and duplicate matches", () => {
  const current = nonceHistoryRecord({ checkedAt: nonceCheckedAt, masterFingerprint: "deadbeef", pubkey: nonceKeyA, r: nonceR, sighash: nonceDigestA, valid: true });
  const reused = nonceHistoryRecord({ checkedAt: nonceCheckedAt, masterFingerprint: "deadbeef", pubkey: nonceKeyA, r: nonceR, sighash: nonceDigestB, valid: true });
  const incomplete = nonceHistoryRecord({ checkedAt: nonceCheckedAt, masterFingerprint: "deadbeef", pubkey: nonceKeyA, r: nonceR, context: nonceContext, valid: false });
  const otherKey = nonceHistoryRecord({ checkedAt: nonceCheckedAt, masterFingerprint: "deadbeef", pubkey: nonceKeyB, r: nonceR, sighash: nonceDigestB, valid: true });
  assert.equal(compareNonceHistory([current], [reused]).reused.length, 1);
  assert.equal(compareNonceHistory([current], [incomplete]).possible.length, 1);
  assert.equal(compareNonceHistory([current], [otherKey]).crossKey.length, 1);
  assert.deepEqual(compareNonceHistory([current], [current]), { reused: [], possible: [], crossKey: [] });
});

test("nonce history parser rejects malformed and expanded records", () => {
  assert.throws(() => parseNonceHistory(""), /empty/);
  assert.throws(() => parseNonceHistory("{"), /valid JSON/);
  assert.throws(() => parseNonceHistory(JSON.stringify({ format: NONCE_HISTORY_FORMAT, version: 2, records: [] })), /Unsupported/);
  assert.throws(() => parseNonceHistory(JSON.stringify({ format: NONCE_HISTORY_FORMAT, version: 1, records: [], payload: "psbt" })), /unsupported fields/);
  const valid = nonceHistoryRecord({ checkedAt: nonceCheckedAt, masterFingerprint: "deadbeef", pubkey: nonceKeyA, r: nonceR, sighash: nonceDigestA, valid: true });
  assert.throws(() => parseNonceHistory(JSON.stringify({ format: NONCE_HISTORY_FORMAT, version: 1, records: [{ ...valid, publicKey: "02" + "11".repeat(32) }] })), /unsupported fields/);
  assert.throws(() => parseNonceHistory(JSON.stringify({ format: NONCE_HISTORY_FORMAT, version: 1, records: [{ ...valid, checkedAt: "today" }] })), /ISO 8601/);
  assert.throws(() => parseNonceHistory(JSON.stringify({ format: NONCE_HISTORY_FORMAT, version: 1, records: [{ ...valid, masterFingerprint: "DEADBEEF" }] })), /master fingerprints/);
});

test("nonce findings stay out of the activity log and session state follows the inspected payload", () => {
  const app = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "src/js/app.js"), "utf8");
  assert.doesNotMatch(app, /hodlJournalLog\("inspect-nonce-/);
  assert.match(app, /loaded: hodlPsbtNonceInspected/);
  assert.match(app, /getElementById\("nonce-text"\)\.addEventListener\("input", hodlPsbtResetNonceInspection\)/);
  assert.match(app, /hodlPsbtClearNonceHistory\(true\)/);
});

test("the Journal does not render its KDF verifier", () => {
  const app = read("src/js/app.js");
  assert.doesNotMatch(app, /hodlJournalFillLifehash\([^;]*verify/, "a captured LifeHash must not verify password guesses");
});

// Audit L9 ledger (journal pass): a journal file's size was unbounded at
// every layer — the outer envelope, the entry count, and the per-entry
// strings. A crafted (or merely huge) file could make JSON.parse, the entry
// map, and the field strings allocate without bound on open. The caps mirror
// the notebook's existing discipline (NOTEBOOK_MAX_PAGES /
// NOTEBOOK_MAX_TEXT_LENGTH): generous for real journals, hard for hostile
// ones.
test("journal files and entries are size-bounded at every layer (audit L9)", () => {
  const oversizedField = "x".repeat(JOURNAL_MAX_TEXT_LENGTH + 1);
  assert.throws(
    () => addEntry(emptyDocument(), { method: "dice", label: "big notes", notes: oversizedField }),
    /too large/,
    "a single entry's text cannot exceed the cap",
  );
  const many = { version: JOURNAL_VERSION, nextId: JOURNAL_MAX_ENTRIES + 2, entries: [] };
  for (let i = 0; i < JOURNAL_MAX_ENTRIES + 1; i++) many.entries.push({ method: "dice", label: `entry ${i}`, input: "" });
  assert.throws(() => parseDocument(JSON.stringify(many)), /at most/, "a document cannot carry more than the entry cap");
  const full = emptyDocument();
  for (let i = 0; i < JOURNAL_MAX_ENTRIES; i++) addEntry(full, { method: "dice", label: `entry ${i}`, input: "" });
  assert.throws(() => addEntry(full, { method: "dice", label: "one more", input: "" }), /at most/, "in-session adds stop at the cap too");
  assert.throws(() => parseFile("[".repeat(JOURNAL_MAX_FILE_LENGTH + 1)), /large/, "the outer file cannot exceed the cap");
  // A real document still round-trips through the envelope (parseFile checks
  // structure, not authenticity — that is AES-GCM's job).
  const sealed = JSON.stringify(encodeFile({ iv: new Uint8Array(IV_BYTES), ciphertext: new Uint8Array(16), iterations: JOURNAL_ITERATIONS }));
  assert.deepEqual(parseFile(sealed), { iv: new Uint8Array(IV_BYTES), ciphertext: new Uint8Array(16), iterations: JOURNAL_ITERATIONS });
});

// AR-02: the plaintext cap alone let a save succeed while the serialized
// envelope (UTF-8 ciphertext, hex-coded, pretty-printed) exceeded the reader's
// file cap, so the file could not be reopened.
test("a save refuses an envelope the reader would reject (AR-02)", async () => {
  const rejected = async (notes) => {
    const created = await createDocument(password, password);
    addEntry(created.doc, { method: "dice", input: "1", phrase: "p", label: "big", notes }, fixedNow);
    await assert.rejects(() => sealDocument(created.doc, created.keys), /too large to save/);
  };
  // 750k CJK characters are 2.25 MB of UTF-8 that hex-encode past the cap.
  await rejected("界".repeat(750_000));
  // Astral characters expand the same way in a shorter string; at the entry
  // cap (1 Mi code units = 524,288 astral characters = 2 MiB of UTF-8) the
  // hex envelope alone reaches the reader's cap.
  await rejected("😀".repeat(524_288));

  // ASCII of the same character count still saves and reopens.
  const created = await createDocument(password, password);
  addEntry(created.doc, { method: "dice", input: "1", phrase: "p", label: "big", notes: "x".repeat(750_000) }, fixedNow);
  const file = await sealDocument(created.doc, created.keys);
  const text = JSON.stringify(file, null, 2) + "\n";
  assert.ok(text.length <= JOURNAL_MAX_FILE_LENGTH, "an accepted save must fit the reader's cap");
  assert.ok(parseFile(text));
});

// Journal ids key the entry list (`find((entry) => entry.id === id)` selects
// the first match) and `addEntry` trusts `nextId`. A hand-edited file that
// repeats an id makes one entry unreachable, and a stale `nextId` makes the
// next add collide with an existing entry.
test("a journal file rejects duplicate entry ids and repairs a stale nextId", () => {
  const entry = (id) => ({ id, method: "dice", label: `entry ${id}`, input: "", created: fixedNow.toISOString() });
  const duplicate = { version: JOURNAL_VERSION, nextId: 3, entries: [entry(1), entry(1)] };
  assert.throws(() => parseDocument(JSON.stringify(duplicate)), /duplicate/, "two entries cannot share an id");

  const stale = { version: JOURNAL_VERSION, nextId: 2, entries: [entry(5), entry(6)] };
  const repaired = parseDocument(JSON.stringify(stale));
  assert.equal(repaired.nextId, 7, "the counter must clear the highest existing id");
  assert.equal(addEntry(repaired, { method: "dice", label: "next" }).id, 7, "and the next add must not collide");

  const flat = parseDocument(JSON.stringify({ version: JOURNAL_VERSION, entries: [entry(1), entry(2)] }));
  assert.equal(flat.nextId, 3, "a missing counter is still derived from the entries");
});

test("addEntry does not reuse an id a document already carries", () => {
  const doc = parseDocument(JSON.stringify({ version: JOURNAL_VERSION, nextId: 1, entries: [{ id: 9, method: "dice", label: "nine" }] }));
  doc.nextId = 1;
  assert.equal(addEntry(doc, { method: "dice", label: "next" }).id, 10);
});

// Node's Number.isInteger accepts 2**53, but adding one to it does not
// advance, so an imported counter or entry id at that boundary collides on
// the next add and a save then fails to reopen.
test("an unsafe imported counter or entry id cannot produce a duplicate", () => {
  const unsafe = 2 ** 53;
  const doc = parseDocument(JSON.stringify({ version: JOURNAL_VERSION, nextId: unsafe, entries: [] }));
  assert.equal(doc.nextId, 1, "a counter above the safe range is repaired");
  assert.equal(addEntry(doc, { method: "hex", label: "first", input: "00" }).id, 1);
  assert.equal(addEntry(doc, { method: "hex", label: "second", input: "00" }).id, 2);

  const carried = parseDocument(JSON.stringify({
    version: JOURNAL_VERSION,
    nextId: 1,
    entries: [{ id: unsafe, method: "hex", label: "imported", input: "00" }],
  }));
  assert.deepEqual(carried.entries.map((entry) => entry.id), [1], "an unsafe entry id takes the lowest free one");
  assert.equal(addEntry(carried, { method: "hex", label: "next", input: "00" }).id, 2);
});

test("an entry with an unsafe imported id still edits in place and drops its old secret", () => {
  const doc = parseDocument(JSON.stringify({
    version: JOURNAL_VERSION,
    entries: [
      { id: 2 ** 53, method: "hex", label: "imported", input: "aa".repeat(32), notes: "old" },
      { id: 2 ** 53, method: "hex", label: "also imported", input: "bb".repeat(32) },
    ],
  }));
  assert.deepEqual(doc.entries.map((entry) => entry.id), [1, 2], "both unsafe ids get unique positive ids");
  const target = doc.entries[0].id;
  assert.ok(target, "the editor's add-or-replace fork sees a truthy id");
  replaceEntry(doc, target, { method: "dice", label: "edited", input: "1 2 3 4", notes: "" });
  assert.equal(doc.entries.length, 2, "an edit must replace, not append");
  assert.equal(doc.entries[0].label, "edited");
  assert.equal(doc.entries[0].input, "1 2 3 4");
  assert.equal(doc.entries[0].notes, "", "the old secret and note are gone");
});

test("allocation refuses at the safe-integer boundary before mutating the document", () => {
  const doc = parseDocument(JSON.stringify({
    version: JOURNAL_VERSION,
    nextId: Number.MAX_SAFE_INTEGER,
    entries: [{ id: Number.MAX_SAFE_INTEGER, method: "hex", label: "last", input: "00" }],
  }));
  const before = doc.entries.length;
  const nextId = doc.nextId;
  assert.throws(() => addEntry(doc, { method: "hex", label: "past the end", input: "00" }), /safe integer/);
  assert.equal(doc.entries.length, before, "a refused add leaves the list untouched");
  assert.equal(doc.nextId, nextId, "and the counter untouched");
});

// no observable effect: Regex at src/js/journal.js:48 /[\r\n]+/g -> /[\r\n]/g (collapsed by later /\s+/g)
// no observable effect: CallExpression at src/js/journal.js:467 wipeBytes(salt) in finally
// no observable effect: CallExpression at src/js/journal.js:470 wipeBytes(ikm) in finally
// no observable effect: CallExpression at src/js/journal.js:471 wipeBytes(saltInput) in finally
// no observable effect: CallExpression at src/js/journal.js:489 wipeBytes(master) in finally
// no observable effect: CallExpression at src/js/journal.js:793 wipeBytes(tag) in finally
// no observable effect: CallExpression at src/js/journal.js:796 wipeBytes(plain) in finally
// no observable effect: CallExpression at src/js/journal.js:852 wipeBytes(plainBytes) in finally
// no observable effect: CallExpression at src/js/journal.js:853 wipeBytes(parsed.iv) in finally
// no observable effect: CallExpression at src/js/journal.js:854 wipeBytes(parsed.ciphertext) in finally
// no observable effect: CallExpression at src/js/journal.js:871 wipeBytes(plainBytes) in finally
// no observable effect: CallExpression at src/js/journal.js:872 wipeBytes(parsed.iv) in finally
// no observable effect: CallExpression at src/js/journal.js:873 wipeBytes(parsed.ciphertext) in finally
// no observable effect: BlockStatement at src/js/journal.js:466 } finally {} -> {} (wipe only)
// no observable effect: BlockStatement at src/js/journal.js:469 } finally {} -> {} (wipe only)
// no observable effect: BlockStatement at src/js/journal.js:488 } finally {} -> {} (wipe only)
// no observable effect: BlockStatement at src/js/journal.js:792 } finally {} -> {} (wipe only)
// no observable effect: BlockStatement at src/js/journal.js:795 } finally {} -> {} (wipe only)
// no observable effect: BlockStatement at src/js/journal.js:851 } finally {} -> {} (wipe only)
// no observable effect: BlockStatement at src/js/journal.js:870 } finally {} -> {} (wipe only)

test("mutant kill: exported constants and labels", () => {
  assert.equal(NOTEBOOK_FORMAT, "entropylab-notebook");
  assert.equal(NOTEBOOK_VERSION, 1);
  assert.equal(JOURNAL_VERSION, 2);
  assert.equal(JOURNAL_EXPORT_VERSION, 1);
  assert.equal(JOURNAL_KDF, "PBKDF2-SHA-256");
  assert.equal(JOURNAL_CIPHER, "AES-256-GCM");
  assert.equal(JOURNAL_SALT_PREFIX, "entropylab-journal-salt-v1:");
  assert.equal(JOURNAL_ITERATIONS, 600_000);
  assert.equal(JOURNAL_MIN_ITERATIONS, 100_000);
  assert.equal(JOURNAL_MAX_ITERATIONS, 10_000_000);
  assert.equal(JOURNAL_MAX_ENTRIES, 1000);
  assert.equal(JOURNAL_MAX_FILE_LENGTH, 4 * 1024 * 1024);
  assert.equal(JOURNAL_MAX_TEXT_LENGTH, 1024 * 1024);
  assert.equal(NOTEBOOK_MAX_PAGES, 100);
  assert.equal(NOTEBOOK_MAX_TEXT_LENGTH, 1024 * 1024);
  assert.equal(IV_BYTES, 12);
  assert.deepEqual(METHODS, ["dice", "coin", "hex", "brain", "seed", "cards"]);
  assert.equal(METHOD_LABELS.dice, "Dice rolls");
  assert.equal(METHOD_LABELS.coin, "Coin flips");
  assert.equal(METHOD_LABELS.hex, "Number bases");
  assert.equal(METHOD_LABELS.brain, "Brain-wallet text");
  assert.equal(METHOD_LABELS.seed, "Manual seed");
  assert.equal(METHOD_LABELS.cards, "Playing cards");
  assert.equal(entryMethodLabel({ method: "dice", diceMethod: "coldcard" }), "Dice rolls · COLDCARD / SeedSigner");
  assert.equal(entryMethodLabel({ method: "hex", entropyFormat: "hex" }), "Number bases · Hexadecimal (Base 16)");
  assert.equal(entryMethodLabel({ method: "coin" }), "Coin flips");
});

test("mutant kill: formatStamp branches", () => {
  assert.equal(formatStamp(new Date(2026, 0, 2, 3, 4, 5)), "2026-01-02 03:04:05");
  assert.equal(formatStamp(new Date(2026, 8, 2, 9, 5, 7)), "2026-09-02 09:05:07");
  assert.equal(formatStamp(new Date("invalid")), "");
  assert.equal(formatStamp(new Date(NaN)), "");
  assert.equal(formatStamp("not a date"), "");
  assert.equal(formatStamp(null), "");
  assert.equal(formatStamp({}), "");
  assert.equal(formatStamp(new Date(2026, 0, 1)), "2026-01-01 00:00:00");
  // undefined triggers default param -> current wall-clock, not empty
  assert.match(formatStamp(), /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
  assert.match(formatStamp(undefined), /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
  // invalid Date must return empty, not current time (kills || -> &&)
  assert.equal(formatStamp(new Date("invalid")), "");
});

test("mutant kill: page style normalization", () => {
  assert.deepEqual(defaultJournalPageStyle(), { font: "mono", size: "medium", spacing: "comfortable" });
  assert.notEqual(defaultJournalPageStyle(), defaultJournalPageStyle());
  assert.deepEqual(normalizeJournalPageStyle({ font: "sans", size: "small", spacing: "compact" }), { font: "sans", size: "small", spacing: "compact" });
  assert.deepEqual(normalizeJournalPageStyle({ font: "serif", size: "large", spacing: "spacious" }), { font: "serif", size: "large", spacing: "spacious" });
  assert.deepEqual(normalizeJournalPageStyle({ font: "invalid", size: "invalid", spacing: "invalid" }), { font: "mono", size: "medium", spacing: "comfortable" });
  assert.deepEqual(normalizeJournalPageStyle({}), { font: "mono", size: "medium", spacing: "comfortable" });
  assert.deepEqual(normalizeJournalPageStyle(null), { font: "mono", size: "medium", spacing: "comfortable" });
  assert.deepEqual(normalizeJournalPageStyle(undefined), { font: "mono", size: "medium", spacing: "comfortable" });
});

test("mutant kill: journalKeyReferenceToken", () => {
  assert.equal(journalKeyReferenceToken("Test", "a1b2c3d4"), "◆◆ Test [a1b2c3d4]\u2063");
  assert.equal(journalKeyReferenceToken("A1B2C3D4", "a1b2c3d4"), "◆◆ [a1b2c3d4]\u2063");
  assert.equal(journalKeyReferenceToken("  Test  Name  ", "a1b2c3d4"), "◆◆ Test Name [a1b2c3d4]\u2063");
  assert.equal(journalKeyReferenceToken("Test\nName", "a1b2c3d4"), "◆◆ Test Name [a1b2c3d4]\u2063");
  assert.equal(journalKeyReferenceToken("Test◆Name", "a1b2c3d4"), "◆◆ Test◇Name [a1b2c3d4]\u2063");
  assert.equal(journalKeyReferenceToken("Test\u2063Name", "a1b2c3d4"), "◆◆ TestName [a1b2c3d4]\u2063");
  assert.equal(journalKeyReferenceToken("", "a1b2c3d4"), "◆◆ Key [a1b2c3d4]\u2063");
  assert.equal(journalKeyReferenceToken("Test", "A1B2C3D4"), "◆◆ Test [a1b2c3d4]\u2063");
  assert.equal(journalKeyReferenceToken("Test", " a1b2c3d4 "), "◆◆ Test [a1b2c3d4]\u2063");
  const longName = "a".repeat(200);
  const token = journalKeyReferenceToken(longName, "a1b2c3d4");
  assert.ok(token.includes("a".repeat(120)));
  assert.equal(token.includes("a".repeat(121)), false);
  assert.throws(() => journalKeyReferenceToken("Test", "not-hex"), /8-character hexadecimal/);
  assert.throws(() => journalKeyReferenceToken("Test", "a1b2c3d"), /8-character hexadecimal/);
  assert.throws(() => journalKeyReferenceToken("Test", "a1b2c3d45"), /8-character hexadecimal/);
  assert.throws(() => journalKeyReferenceToken("Test", ""), /8-character hexadecimal/);
  assert.throws(() => journalKeyReferenceToken("Test", "zzzzzzzz"), /8-character hexadecimal/);
});

test("mutant kill: journalBip85ReferenceToken", () => {
  assert.equal(journalBip85ReferenceToken("bip39", "deadbeef"), "◈◈ BIP-85 · BIP-39 [deadbeef]\u2063");
  assert.equal(journalBip85ReferenceToken("wif", "DEADBEEF"), "◈◈ BIP-85 · WIF [deadbeef]\u2063");
  assert.equal(journalBip85ReferenceToken("xprv", "deadbeef"), "◈◈ BIP-85 · XPRV [deadbeef]\u2063");
  assert.equal(journalBip85ReferenceToken("hex", "deadbeef"), "◈◈ BIP-85 · HEX [deadbeef]\u2063");
  assert.equal(journalBip85ReferenceToken("pwd-base64", "deadbeef"), "◈◈ BIP-85 · Base64 password [deadbeef]\u2063");
  assert.equal(journalBip85ReferenceToken("pwd-base85", "deadbeef"), "◈◈ BIP-85 · Base85 password [deadbeef]\u2063");
  assert.throws(() => journalBip85ReferenceToken("unknown", "deadbeef"), /supported application/);
  assert.throws(() => journalBip85ReferenceToken("", "deadbeef"), /supported application/);
  assert.throws(() => journalBip85ReferenceToken("bip39", "not-hex"), /8-character hexadecimal/);
  assert.throws(() => journalBip85ReferenceToken("bip39", "deadbee"), /8-character hexadecimal/);
  assert.equal(journalBip85ReferenceToken("bip39", " a1b2c3d4 "), "◈◈ BIP-85 · BIP-39 [a1b2c3d4]\u2063");
});

test("mutant kill: notebook runs and ranges", () => {
  const token = journalKeyReferenceToken("Key 1", "a1b2c3d4");
  const bipToken = journalBip85ReferenceToken("wif", "deadbeef");
  const source = `before ${token} middle ${bipToken} after`;
  const runs = journalNotebookRuns(source);
  assert.equal(runs.length, 5);
  assert.equal(runs[0].type, "text");
  assert.equal(runs[1].type, "key");
  assert.equal(runs[1].fingerprint, "a1b2c3d4");
  assert.equal(runs[3].type, "key");
  assert.equal(runs[3].application, "wif");
  assert.equal(journalTextFromRuns(runs), source);
  assert.deepEqual(journalKeyReferenceRanges(source), [{ start: 7, end: 7 + token.length }, { start: 7 + token.length + 8, end: 7 + token.length + 8 + bipToken.length }]);
  assert.deepEqual(journalKeyReferenceRanges("no refs"), []);
  assert.deepEqual(journalNotebookRuns(""), [{ type: "text", text: "" }]);
  assert.deepEqual(journalNotebookRuns(null), [{ type: "text", text: "" }]);
  const invalidBip = "◈◈ BIP-85 · Unknown [deadbeef]\u2063";
  assert.deepEqual(journalNotebookRuns(`a ${invalidBip} b`), [{ type: "text", text: `a ${invalidBip} b` }]);
  assert.deepEqual(journalKeyReferenceRanges(`a ${invalidBip} b`), []);
  assert.throws(() => journalTextFromRuns(null), /content list/);
  assert.throws(() => journalTextFromRuns([{ type: "text", text: 123 }]), /unsupported content item/);
  assert.throws(() => journalTextFromRuns([{ type: "key", name: "Test", fingerprint: "a1b2c3d4", source: "bip85", application: "unknown" }]), /supported application/);
  assert.throws(() => journalTextFromRuns([{ type: "key", name: "Test", fingerprint: "bad" }]), /8-character hexadecimal/);
  assert.throws(() => journalTextFromRuns([{ type: "invalid" }]), /unsupported content item/);
  const bigText = "a".repeat(NOTEBOOK_MAX_TEXT_LENGTH + 1);
  assert.throws(() => journalTextFromRuns([{ type: "text", text: bigText }]), /too large to import/);
});

test("mutant kill: journal basics and formatting", () => {
  const j = createJournal();
  assert.equal(j.notesText, "");
  assert.equal(j.pages.length, 1);
  assert.equal(j.pages[0].id, 1);
  assert.equal(j.pages[0].number, 1);
  assert.equal(j.pages[0].name, "Page 1");
  assert.equal(j.pages[0].notesText, "");
  assert.deepEqual(j.pages[0].style, { font: "mono", size: "medium", spacing: "comfortable" });
  assert.equal(j.activePage, 0);
  assert.equal(j.nextPageId, 2);
  assert.equal(j.nextPageNumber, 2);
  assert.deepEqual(j.log, []);
  assert.equal(j.stateText, "");
  const token = journalKeyReferenceToken("My Key", "a1b2c3d4");
  assert.equal(formatNotebook(`before ${token} after`), "before [Key: My Key · a1b2c3d4] after");
  assert.equal(formatNotebook(`before ${journalKeyReferenceToken("a1b2c3d4", "a1b2c3d4")} after`), "before [Key: a1b2c3d4] after");
  assert.equal(formatNotebook(`before ${journalBip85ReferenceToken("bip39", "deadbeef")} after`), "before [BIP-85 BIP-39: deadbeef] after");
  assert.equal(formatNotebook("2026-09-02 10:00:00  first note\n\n2026-09-02 10:01:00  Add new note"), "2026-09-02 10:00:00  first note");
  assert.equal(formatNotebook(""), "No notes.");
  assert.equal(formatNotebook(null), "No notes.");
  assert.equal(formatNotebookPages([{ number: 1, name: "Page 1", notesText: "" }]), "No notes.");
  assert.equal(formatNotebookPages([{ number: 1, name: "Field notes", notesText: "2026-09-02 10:00:00  first note" }, { number: 2, name: "Page 2", notesText: "2026-09-02 10:01:00  " }]), "Field notes\n2026-09-02 10:00:00  first note\n\nPage 2\nNo notes.");
  assert.equal(formatNotebookPages([]), "No notes.");
  assert.equal(formatNotebookPages(null), "No notes.");
});

test("mutant kill: notebook serialize/parse boundaries", () => {
  const journal = createJournal();
  journal.pages[0].name = "Field notes";
  journal.pages[0].style = { font: "serif", size: "large", spacing: "spacious" };
  journal.pages[0].notesText = `2026-09-02 10:00:00  ${journalKeyReferenceToken("Key 1", "deadbeef")}`;
  journal.pages.push({ id: 2, number: 2, name: "Page 2", notesText: "second", style: { font: "sans", size: "small", spacing: "compact" } });
  journal.activePage = 1;
  const encoded = serializeNotebook(journal);
  const doc = JSON.parse(encoded);
  assert.equal(doc.format, NOTEBOOK_FORMAT);
  assert.equal(doc.version, NOTEBOOK_VERSION);
  assert.equal(doc.activePage, 1);
  assert.equal(doc.pages.length, 2);
  assert.equal(doc.pages[0].name, "Field notes");
  assert.deepEqual(doc.pages[0].style, { font: "serif", size: "large", spacing: "spacious" });
  assert.deepEqual(doc.pages[0].content[1], { type: "key", name: "Key 1", fingerprint: "deadbeef" });
  assert.ok(encoded.endsWith("\n"));
  const j2 = createJournal();
  j2.pages[0].number = 0;
  assert.equal(JSON.parse(serializeNotebook(j2)).pages[0].number, 1);
  j2.pages[0].number = -5;
  assert.equal(JSON.parse(serializeNotebook(j2)).pages[0].number, 1);
  j2.pages[0].number = 1.5;
  assert.equal(JSON.parse(serializeNotebook(j2)).pages[0].number, 1);
  j2.pages[0].number = NaN;
  assert.equal(JSON.parse(serializeNotebook(j2)).pages[0].number, 1);
  j2.pages[0].name = "a".repeat(200);
  assert.equal(JSON.parse(serializeNotebook(j2)).pages[0].name.length, 120);
  j2.activePage = 5;
  assert.equal(JSON.parse(serializeNotebook(j2)).activePage, 0);
  j2.activePage = -1;
  assert.equal(JSON.parse(serializeNotebook(j2)).activePage, 0);
  j2.activePage = null;
  assert.equal(JSON.parse(serializeNotebook(j2)).activePage, 0);
  assert.equal(JSON.parse(serializeNotebook({})).pages.length, 1);
  assert.equal(JSON.parse(serializeNotebook({ pages: [] })).pages.length, 1);
  const bigJournal = createJournal();
  bigJournal.pages[0].notesText = "a".repeat(NOTEBOOK_MAX_TEXT_LENGTH + 1);
  assert.throws(() => serializeNotebook(bigJournal), /too large to save/);
  assert.throws(() => parseNotebook("not json"), /not valid notebook JSON/);
  assert.throws(() => parseNotebook('{"format":"something-else","version":1,"pages":[]}'), /not a supported/);
  assert.throws(() => parseNotebook(JSON.stringify({ format: NOTEBOOK_FORMAT, version: 999, pages: [{ number: 1, name: "Page 1", content: [{ type: "text", text: "hi" }] }] })), /not a supported/);
  assert.throws(() => parseNotebook(JSON.stringify({ format: NOTEBOOK_FORMAT, version: NOTEBOOK_VERSION, pages: [] })), /between 1 and/);
});

test("mutant kill: notebook import and page content", () => {
  assert.equal(notebookPageHasContent("2026-09-04 13:17:24  "), false);
  assert.equal(notebookPageHasContent("2026-09-04 13:17:24  kept"), true);
  assert.equal(notebookPageHasContent("hello"), true);
  assert.equal(notebookPageHasContent(""), false);
  const imported = journalFromPlainText("uploaded notes");
  const journal = createJournal();
  journal.pages[0].notesText = "2026-09-04 13:17:24  existing notes";
  journal.notesText = journal.pages[0].notesText;
  let merged = mergeNotebookImport(journal, imported);
  assert.equal(merged.pages.length, 2);
  assert.equal(merged.pages[0].notesText, journal.pages[0].notesText);
  assert.equal(merged.pages[1].notesText, "uploaded notes");
  assert.equal(merged.activePage, 1);
  const empty = createJournal();
  empty.pages[0].notesText = "2026-09-04 13:17:24  ";
  merged = mergeNotebookImport(empty, imported);
  assert.equal(merged.pages.length, 1);
  assert.equal(merged.pages[0].id, 1);
  assert.equal(merged.pages[0].notesText, "uploaded notes");
  assert.equal(merged.activePage, 0);
  assert.throws(() => journalFromPlainText("a".repeat(NOTEBOOK_MAX_TEXT_LENGTH + 1)), /too large to import/);
});

test("mutant kill: key snapshot matching and sync", () => {
  const entry = { method: "dice", diceMethod: "coldcard", input: "1 2 3", phrase: "abandon", label: "lab", notes: "", walletName: "w", fingerprint: "AABBCCDD" };
  const snapSame = { method: "dice", diceMethod: "coldcard", input: "1 2 3", phrase: "abandon", label: "lab", notes: "", walletName: "w", fingerprint: "aabbccdd" };
  const snapDiff = { method: "dice", diceMethod: "coldcard", input: "9 9 9", phrase: "abandon", label: "lab", notes: "", walletName: "w", fingerprint: "aabbccdd" };
  assert.equal(keySnapshotMatchesEntry(entry, snapSame), true);
  assert.equal(keySnapshotMatchesEntry(entry, snapDiff), false);
  assert.equal(keySnapshotMatchesEntry(null, snapSame), false);
  assert.equal(keySnapshotMatchesEntry(entry, null), false);
  // fingerprint case-insensitive
  assert.equal(keySnapshotMatchesEntry({ ...entry, fingerprint: "aabbccdd" }, { ...snapSame, fingerprint: "AABBCCDD" }), true);
  const doc = emptyDocument();
  const snap = { method: "dice", input: "1 2 3", phrase: "p", label: "s1", notes: "", walletId: 1, walletName: "w1", fingerprint: "aabbccdd" };
  const assoc = new Map();
  const res1 = syncKeySnapshots(doc, [snap], assoc, fixedNow);
  assert.equal(res1.added, 1);
  assert.equal(doc.entries.length, 1);
  const res2 = syncKeySnapshots(doc, [snap], assoc, fixedNow);
  assert.equal(res2.matched, 1);
  const snap2 = { ...snap, input: "9 9 9" };
  const res3 = syncKeySnapshots(doc, [snap2], assoc, fixedNow);
  assert.equal(res3.updated, 1);
  assert.equal(doc.entries[0].input, "9 9 9");
  assert.throws(() => syncKeySnapshots(null, [], assoc), /Journal document is missing/);
  assert.throws(() => syncKeySnapshots(doc, [], {}), /Journal key associations are missing/);
});

test("mutant kill: encodeFile and parseFile boundaries", () => {
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
  assert.throws(() => encodeFile({ iv: fill(12), ciphertext: new Uint8Array(0) }), /ciphertext is missing/);
  assert.throws(() => encodeFile({ iv: fill(12), ciphertext: fill(32), iterations: 1 }), /iteration count is out of range/);
  assert.throws(() => parseFile("[".repeat(JOURNAL_MAX_FILE_LENGTH + 1)), /large/);
});

test("mutant kill: parseDocument and entry validation", () => {
  assert.throws(() => parseDocument("not json"), /corrupt/);
  assert.throws(() => parseDocument(JSON.stringify({ version: 999, entries: [] })), /corrupt/);
  assert.throws(() => parseDocument("x".repeat(JOURNAL_MAX_TEXT_LENGTH + 1)), /too large to open/);
  const many = { version: JOURNAL_VERSION, nextId: 1, entries: [] };
  for (let i = 0; i < JOURNAL_MAX_ENTRIES + 1; i++) many.entries.push({ method: "dice", label: `e${i}`, input: "" });
  assert.throws(() => parseDocument(JSON.stringify(many)), /at most/);
  assert.throws(() => addEntry(emptyDocument(), { method: "dice", label: "", input: "" }), /label/);
  assert.throws(() => addEntry(emptyDocument(), { method: "bad", label: "x" }), /method/);
  const doc = emptyDocument();
  addEntry(doc, { method: "dice", label: "a", input: "1" });
  assert.throws(() => replaceEntry(doc, 999, { label: "b" }), /not in this file/);
  assert.throws(() => removeEntry(doc, 999), /not in this file/);
  assert.equal(searchEntries(doc, "").length, 1);
  assert.equal(searchEntries(doc, "A").length, 1);
  assert.equal(searchEntries(doc, "nope").length, 0);
  assert.throws(() => assertPassword(42), /must be text/);
  assert.throws(() => assertPassword("a", { confirm: "b" }), /do not match/);
  const b = new Uint8Array([1, 2, 3]);
  wipeBytes(b);
  assert.deepEqual(b, new Uint8Array([0, 0, 0]));
  const e = { input: "secret", phrase: "words", label: "l", notes: "n", walletName: "w", fingerprint: "fp" };
  wipeEntry(e);
  assert.equal(e.input, "");
  assert.equal(e.phrase, "");
});

test("mutant kill: snapshotFromKeyState variants", () => {
  const dice = snapshotFromKeyState({ id: 4, isLab: false, mode: "dice", diceMethod: "coldcard", name: "deadbeef", fields: { dice: "4 1 4 2" }, result: { mnemonic: "legal winner thank year", masterFingerprint: "deadbeef" } });
  assert.equal(dice.method, "dice");
  assert.equal(dice.input, "4 1 4 2");
  const dplus = snapshotFromKeyState({ id: 1, isLab: false, mode: "dice", diceMethod: "dplus", fields: { dplusDice: "1 2 3" }, result: { mnemonic: "abandon" } });
  assert.equal(dplus.input, "1 2 3");
  const bitbox = snapshotFromKeyState({ id: 1, isLab: false, mode: "dice", diceMethod: "bitbox", fields: { bitboxDice: "5 6" }, result: { mnemonic: "abandon" } });
  assert.equal(bitbox.input, "5 6");
  const cardsHashed = snapshotFromKeyState({ id: 1, isLab: false, mode: "cards", cardMethod: "hashed", fields: { cards: "AH KH" }, result: { mnemonic: "abandon" } });
  assert.equal(cardsHashed.method, "cards");
  assert.equal(cardsHashed.input, "AH KH");
  const cardsDirect = snapshotFromKeyState({ id: 1, isLab: false, mode: "cards", cardMethod: "direct", fields: { directCards: "AS KS" }, result: { mnemonic: "abandon" } });
  assert.equal(cardsDirect.input, "AS KS");
  const hex = snapshotFromKeyState({ id: 1, isLab: false, mode: "hex", entropyFormat: "hex", fields: { hex: "abcd" }, result: { mnemonic: "abandon" } });
  assert.equal(hex.method, "hex");
  assert.equal(hex.input, "abcd");
  const seedWords = snapshotFromKeyState({ id: 1, isLab: false, mode: "seed", seedMethod: "words", fields: { seed: "abandon abandon" }, result: { mnemonic: "abandon" } });
  assert.equal(seedWords.input, "abandon abandon");
  const seedNumbers = snapshotFromKeyState({ id: 1, isLab: false, mode: "seed", seedMethod: "numbers", fields: { seedNumbers: "1 2 3" }, result: { mnemonic: "abandon" } });
  assert.equal(seedNumbers.input, "1 2 3");
  const brain = snapshotFromKeyState({ id: 5, isLab: false, mode: "key", name: "brain", fields: { keyKind: "brain", privateKeys: { brain: "correct horse" } }, result: { mnemonic: "one two three" } });
  assert.equal(brain.method, "brain");
  assert.equal(brain.input, "correct horse");
  assert.equal(snapshotFromKeyState({ isLab: true, mode: "dice", fields: { dice: "123" } }), null);
  assert.equal(snapshotFromKeyState({ isLab: false, mode: "dice", fields: { dice: "" }, result: { mnemonic: "" } }), null);
});

test("mutant kill: appendLog and formatLog and wipeJournal", () => {
  const j = createJournal();
  appendLog(j, { tool: "calc", action: "derive", detail: "n=1" }, new Date(2026, 0, 1, 0, 0, 0));
  assert.equal(j.log.length, 1);
  assert.equal(j.log[0].tool, "calc");
  assert.equal(formatLog(j.log).includes("calc\tderive"), true);
  assert.equal(formatLog([]), "No events yet.");
  for (let i = 0; i < JOURNAL_LOG_LIMIT + 5; i++) appendLog(j, { tool: "t", action: "a", detail: `n=${i}` }, new Date(2026, 0, 1));
  assert.equal(j.log.length, JOURNAL_LOG_LIMIT);
  j.stateText = "xprv...";
  j.notesText = "secret";
  wipeJournal(j);
  assert.equal(j.log.length, 0);
  assert.equal(j.stateText, "");
  assert.equal(j.notesText, "");
  assert.equal(j.pages.length, 1);
});

test("mutant kill: deriveJournalKeys validation", async () => {
  await assert.rejects(() => deriveJournalKeys(42), /must be text/);
  await assert.rejects(() => deriveJournalKeys("pw", 1), /unsupported key-derivation cost/);
  await assert.rejects(() => deriveJournalKeys("pw", 1e12), /unsupported key-derivation cost/);
  // valid fast path with minimum iterations
  const keys = await deriveJournalKeys("test-password", JOURNAL_MIN_ITERATIONS);
  assert.ok(keys.encKey);
  assert.ok(keys.ivKey);
  assert.equal(keys.iterations, JOURNAL_MIN_ITERATIONS);
  assert.equal(keys.passwordProtected, true);
  const emptyKeys = await deriveJournalKeys("", JOURNAL_MIN_ITERATIONS);
  assert.equal(emptyKeys.passwordProtected, false);
});
