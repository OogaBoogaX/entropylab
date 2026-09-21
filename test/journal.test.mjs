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
  JOURNAL_VERSION,
  NOTEBOOK_FORMAT,
  NOTEBOOK_VERSION,
  appendLog,
  assertPassword,
  createAccess,
  createJournal,
  encodeFile,
  defaultJournalPageStyle,
  formatLog,
  formatNotebook,
  formatNotebookPages,
  formatStamp,
  openAccessFile,
  openExport,
  parseFile,
  sealAccessFile,
  sealExport,
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
const fill = (length, start = 1) => Uint8Array.from({ length }, (_, i) => (start + i) & 255);

async function sealLegacyJournalPayload(payload, keys) {
  const plain = new TextEncoder().encode(JSON.stringify(payload));
  const tag = new Uint8Array(await crypto.subtle.sign("HMAC", keys.ivKey, plain));
  const iv = tag.slice(0, IV_BYTES);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, keys.encKey, plain));
  return encodeFile({ iv, ciphertext, iterations: keys.iterations });
}

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

test("the Journal access file round-trips with the password and fails on the wrong one", async () => {
  const created = await createAccess(password, password);
  const file = await sealAccessFile(created.keys);
  assert.equal(file.entropylabJournal, JOURNAL_VERSION);
  assert.equal(file.kdf, "PBKDF2-SHA-256");
  assert.equal(file.iterations, JOURNAL_ITERATIONS);
  assert.equal(file.cipher, "AES-256-GCM");
  assert.equal(file.salt, undefined); // the salt is derived from the password, never stored
  assert.equal(file.iv.length, 24);
  assert.match(file.ciphertext, /^[0-9a-f]+$/);
  const packed = JSON.stringify(file);
  const opened = await openAccessFile(packed, password);
  assert.equal(opened.keys.iterations, JOURNAL_ITERATIONS);
  await assert.rejects(() => openAccessFile(packed, otherPassword), /password is incorrect/);
});

test("a Journal access file with no password reopens only with a blank password", async () => {
  const created = await createAccess("", "");
  assert.equal(created.keys.passwordProtected, false);
  const packed = JSON.stringify(await sealAccessFile(created.keys));
  const opened = await openAccessFile(packed, "");
  assert.equal(opened.keys.passwordProtected, false);
  await assert.rejects(() => openAccessFile(packed, "not blank"), /password is incorrect/);
});

test("the access file is deterministic for the same password", async () => {
  const make = async () => {
    const created = await createAccess(password, password);
    return sealAccessFile(created.keys);
  };
  const first = await make();
  const second = await make();
  assert.deepEqual(second, first); // byte-identical — nothing was generated
});

test("legacy files open only when the retired Entries collection is empty", async () => {
  const created = await createAccess(password, password);
  const emptyLegacy = await sealLegacyJournalPayload({ version: JOURNAL_VERSION, nextId: 1, entries: [] }, created.keys);
  const opened = await openAccessFile(emptyLegacy, password);
  assert.deepEqual([...opened.keys.verify], [...created.keys.verify]);

  const populatedLegacy = await sealLegacyJournalPayload({
    version: JOURNAL_VERSION,
    nextId: 2,
    entries: [{ id: 1, method: "seed", label: "Old entry" }],
  }, created.keys);
  await assert.rejects(() => openAccessFile(populatedLegacy, password), /retired Entries.*earlier EntropyLab release/);
});

test("tab exports reuse the unlocked journal password keys and remain deterministic", async () => {
  const created = await createAccess(password, password);
  const first = await sealExport("notebook", "reloadable notebook JSON", created.keys);
  const second = await sealExport("notebook", "reloadable notebook JSON", created.keys);
  assert.equal(first.entropylabJournalExport, JOURNAL_EXPORT_VERSION);
  assert.deepEqual(second, first);
  assert.deepEqual(await openExport(JSON.stringify(first), created.keys), {
    kind: "notebook",
    content: "reloadable notebook JSON",
  });
  const other = await createAccess(otherPassword, otherPassword);
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
  assert.match(app, /getElementById\("psbt-text"\)\.addEventListener\("input", hodlPsbtResetNonceInspection\)/);
  assert.match(app, /hodlPsbtClearNonceHistory\(true\)/);
});
