import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createCipheriv, createHash, createHmac, pbkdf2Sync } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  NONCE_HISTORY_ENCRYPTED_FORMAT,
  NONCE_HISTORY_ENCRYPTED_MAX_TEXT,
  NONCE_HISTORY_MAX_RECORDS,
  decryptNonceHistory,
  encryptNonceHistory,
  isEncryptedNonceHistory,
  nonceHistoryRecord,
  parseNonceHistory,
  serializeNonceHistory,
} from "../src/js/nonce-history.js";
import {
  JOURNAL_ITERATIONS,
  deriveJournalKeys,
  deriveNonceHistoryKeys,
  openBytesWithKeys,
  sealBytesWithKeys,
  sealExport,
} from "../src/js/journal.js";
import { loadAppFunctions } from "./app-slice-harness.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");
const bytes = (hex) => Uint8Array.from(hex.match(/../g) || [], (pair) => parseInt(pair, 16));
const passphrase = "a long unique nonce history passphrase";

function records() {
  return [
    nonceHistoryRecord({ checkedAt: "2026-09-10T20:15:30.000Z", masterFingerprint: "a1b2c3d4", pubkey: bytes(`02${"11".repeat(32)}`), r: bytes("33".repeat(32)), sighash: bytes("44".repeat(32)), valid: true }),
    nonceHistoryRecord({ checkedAt: "2026-09-11T08:00:00.000Z", masterFingerprint: "a1b2c3d4", pubkey: bytes(`03${"22".repeat(32)}`), r: bytes("55".repeat(32)), sighash: bytes("66".repeat(32)), valid: false }),
  ];
}

test("an encrypted nonce history round-trips to the same records", async () => {
  const source = records();
  const text = await encryptNonceHistory(source, passphrase);
  assert.equal(JSON.parse(text).format, NONCE_HISTORY_ENCRYPTED_FORMAT);
  assert.deepEqual(await decryptNonceHistory(text, passphrase), parseNonceHistory(serializeNonceHistory(source)));
});

test("a history at the record cap encrypts to a file the reader accepts (GLM)", async () => {
  const many = Array.from({ length: NONCE_HISTORY_MAX_RECORDS }, (_, i) => {
    const r = new Uint8Array(32), sighash = new Uint8Array(32);
    new DataView(r.buffer).setUint32(0, i + 1);
    new DataView(sighash.buffer).setUint32(4, i + 1);
    return nonceHistoryRecord({ checkedAt: "2026-09-10T20:15:30.000Z", masterFingerprint: "a1b2c3d4", pubkey: bytes(`02${"11".repeat(32)}`), r, sighash, valid: true });
  });
  const text = await encryptNonceHistory(many, passphrase);
  assert.ok(text.length <= NONCE_HISTORY_ENCRYPTED_MAX_TEXT);
  assert.equal(isEncryptedNonceHistory(text), true);
  assert.equal((await decryptNonceHistory(text, passphrase)).length, NONCE_HISTORY_MAX_RECORDS);
});

test("the encrypted file carries no r value, fingerprint or record field name", async () => {
  const source = records();
  const text = await encryptNonceHistory(source, passphrase);
  for (const record of source) {
    assert.equal(text.includes(record.r), false);
    assert.equal(text.includes(record.r.toUpperCase()), false);
    assert.equal(text.includes(record.masterFingerprint), false);
  }
  assert.equal(text.includes("masterFingerprint"), false);
});

test("a wrong passphrase, a flipped ciphertext byte and a bad outer field are refused", async () => {
  const text = await encryptNonceHistory(records(), passphrase);
  await assert.rejects(decryptNonceHistory(text, "another long unique passphrase"), (error) => error.code === "NONCE_HISTORY_WRONG_KEY");
  const parsed = JSON.parse(text);
  const damaged = { ...parsed, ciphertext: (parsed.ciphertext[0] === "0" ? "1" : "0") + parsed.ciphertext.slice(1) };
  await assert.rejects(decryptNonceHistory(JSON.stringify(damaged), passphrase), (error) => error.code === "NONCE_HISTORY_WRONG_KEY");
  for (const bad of [{ version: 2 }, { format: "other" }, { kdf: "scrypt" }, { cipher: "AES-128-GCM" }, { iv: "00" }, { ciphertext: "" }]) {
    await assert.rejects(decryptNonceHistory(JSON.stringify({ ...parsed, ...bad }), passphrase), (error) => error.code === "NONCE_HISTORY_BAD_FILE");
  }
});

test("the nonce history key is separate from the Journal key", async () => {
  const plaintext = serializeNonceHistory(records());
  const nonceKeys = await deriveNonceHistoryKeys(passphrase);
  const journalKeys = await deriveJournalKeys(passphrase);
  const nonce = await sealBytesWithKeys(plaintext, nonceKeys);
  const journal = await sealBytesWithKeys(plaintext, journalKeys);
  assert.notDeepEqual(nonce.ciphertext, journal.ciphertext);
  await assert.rejects(openBytesWithKeys(nonce, journalKeys), (error) => error.code === "NONCE_HISTORY_WRONG_KEY");
});

test("the same records and passphrase give byte-identical text; another passphrase does not", async () => {
  const first = await encryptNonceHistory(records(), passphrase);
  const second = await encryptNonceHistory(records(), passphrase);
  assert.equal(first, second);
  assert.notEqual(first, await encryptNonceHistory(records(), "another long unique passphrase"));
});

test("the nonce history and journal sources call no random-number generator", () => {
  for (const path of ["src/js/nonce-history.js", "src/js/nonce-history-confirm.js", "src/js/journal.js"]) {
    const source = read(path);
    assert.equal(source.includes("getRandomValues"), false, path);
    assert.equal(source.includes("Math.random"), false, path);
  }
});

test("an empty nonce history passphrase is refused", async () => {
  await assert.rejects(deriveNonceHistoryKeys(""), /passphrase/i);
  await assert.rejects(deriveNonceHistoryKeys(null), /passphrase/i);
});

test("an older plain nonce history still parses and is not mistaken for encrypted", () => {
  const text = serializeNonceHistory(records());
  assert.equal(isEncryptedNonceHistory(text), false);
  assert.deepEqual(parseNonceHistory(text), parseNonceHistory(serializeNonceHistory(records())));
});

// The Journal's sealed bytes are a pure function of the password and content:
// PBKDF2-SHA-256 (600,000 rounds) over a salt of SHA-256(prefix + password),
// split into an AES-256-GCM key and an HMAC-SHA-256 key, with the IV taken
// from the HMAC of the plaintext. This reference is written from that
// description with node:crypto, not from journal.js, so it pins the shared
// helper refactor to the same bytes the old sealPlainText produced.
function referenceSeal(plainText, password, iterations, prefix = "entropylab-journal-salt-v1:") {
  const salt = createHash("sha256").update(prefix + password, "utf8").digest();
  const master = pbkdf2Sync(Buffer.from(password, "utf8"), salt, iterations, 64, "sha256");
  const plain = Buffer.from(plainText, "utf8");
  const iv = createHmac("sha256", master.subarray(32)).update(plain).digest().subarray(0, 12);
  const cipher = createCipheriv("aes-256-gcm", master.subarray(0, 32), iv);
  const ciphertext = Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
  return { iv: iv.toString("hex"), ciphertext: ciphertext.toString("hex") };
}

test("the Journal seal is unchanged by the shared-helper refactor", async () => {
  const keys = await deriveJournalKeys(passphrase);
  const file = await sealExport("notebook", "hello", keys);
  const expected = referenceSeal(JSON.stringify({ entropylabJournalExport: 1, kind: "notebook", content: "hello" }), passphrase, JOURNAL_ITERATIONS);
  assert.equal(file.iv, expected.iv);
  assert.equal(file.ciphertext, expected.ciphertext);
});

test("the encrypted nonce history matches an independent node:crypto reference (GLM)", async () => {
  // The same construction under the nonce history's own salt prefix, so a
  // silent change to the format's bytes breaks this test, not saved files.
  const source = records();
  const file = JSON.parse(await encryptNonceHistory(source, passphrase));
  const expected = referenceSeal(serializeNonceHistory(source), passphrase, 600000, "entropylab-nonce-history-salt-v1:");
  assert.equal(file.iterations, 600000);
  assert.equal(file.iv, expected.iv);
  assert.equal(file.ciphertext, expected.ciphertext);
});

test("the encrypted file holds exactly its seven outer fields (red team N4)", async () => {
  const file = JSON.parse(await encryptNonceHistory(records(), passphrase));
  assert.deepEqual(Object.keys(file).sort(), ["cipher", "ciphertext", "format", "iterations", "iv", "kdf", "version"]);
});

test("a file that picks its own PBKDF2 cost is refused before any derivation (MiniMax)", async () => {
  const file = JSON.parse(await encryptNonceHistory(records(), passphrase));
  for (const iterations of [10000000, 600001, 599999, 1]) {
    await assert.rejects(decryptNonceHistory(JSON.stringify({ ...file, iterations }), passphrase), (error) => error.code === "NONCE_HISTORY_BAD_FILE");
  }
});

test("an import that finishes after Clear or End Session merges nothing (GLM)", () => {
  const app = read("src/js/app.js");
  const clear = app.slice(app.indexOf("function hodlPsbtClearNonceHistory("), app.indexOf("\n}", app.indexOf("function hodlPsbtClearNonceHistory(")));
  assert.match(clear, /hodlPsbtNonceHistoryGeneration \+= 1;/);
  const start = app.indexOf('historyFile.addEventListener("change"');
  const handler = app.slice(start, app.indexOf('document.getElementById("psbt-nonce-history-download")', start));
  assert.match(handler, /const generation = hodlPsbtNonceHistoryGeneration;\s*\(async/);
  const merges = [...handler.matchAll(/hodlPsbtNonceHistory = mergeNonceHistory\(/g)];
  assert.equal(merges.length, 2);
  for (const merge of merges) {
    assert.match(handler.slice(0, merge.index), /if \(generation !== hodlPsbtNonceHistoryGeneration\) return;\s*$/);
  }
  // No passphrase dialog for a file that finished reading after the wipe (Kimi).
  assert.match(handler, /const text = await chosen\.text\(\);\s*if \(generation !== hodlPsbtNonceHistoryGeneration\) return;/);
  // A download confirmed before the wipe is not saved after it (GLM).
  const downloadStart = app.indexOf('document.getElementById("psbt-nonce-history-download").onclick');
  const download = app.slice(downloadStart, app.indexOf('document.getElementById("psbt-nonce-history-clear")', downloadStart));
  assert.match(download, /if \(generation !== hodlPsbtNonceHistoryGeneration\) return;\s*hodlDownloadBytes\(/);
  assert.match(download, /\{ count: records\.length \}/);
});

test("End Session empties the nonce history", async () => {
  const stubs = {
    hodlPsbtWipeMem: () => {},
    hodlPsbtRetireAuditUploads: () => {},
    hodlPsbtRetireRbfUploads: () => {},
    hodlNote: () => "",
    hodlClearStationPassphrase: () => {},
    hodlSetPsbtError: () => {},
    hodlSetNonceError: () => {},
    hodlPaintPsbtSession: () => {},
    hodlRefreshStationKeyPickers: () => {},
    hodlSyncPsbtControls: () => {},
    hodlPsbtResetNonceInspection: () => {},
    hodlPsbtSyncNonceHistoryControls: () => {},
    hodlPsbtRenderNonceHistoryComparison: () => {},
  };
  const app = await loadAppFunctions(["hodlEndPsbtSession", "hodlPsbtNonceHistory"], { stubs, settable: ["hodlPsbtNonceHistory"] });
  const previous = globalThis.document;
  globalThis.document = { getElementById: () => null };
  try {
    app.__set.hodlPsbtNonceHistory([{ r: "aa" }, { r: "bb" }]);
    assert.equal(app.hodlPsbtNonceHistory.length, 2);
    app.hodlEndPsbtSession();
    assert.deepEqual(app.hodlPsbtNonceHistory, []);
  } finally {
    globalThis.document = previous;
  }
});
