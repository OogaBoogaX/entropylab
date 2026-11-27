import assert from "node:assert/strict";
import { createHash, pbkdf2Sync } from "node:crypto";
import { test } from "node:test";
import {
  JOURNAL_BACKUP_VERSION,
  JOURNAL_EXPORT_VERSION,
  JOURNAL_MIN_ITERATIONS,
  JOURNAL_SALT_PREFIX,
  JOURNAL_VERSION,
  NONCE_HISTORY_SALT_PREFIX,
  addEntry,
  createJournal,
  deriveJournalKeys,
  deriveNonceHistoryKeys,
  emptyDocument,
  encodeFile,
  logUsage,
  openBytesWithKeys,
  openDocument,
  openExport,
  parseDocument,
  sealBackup,
  sealBytesWithKeys,
  serializeNotebook,
} from "../src/js/journal.js";
import { serializeKeyVault } from "../src/js/keymanager.js";
import { fuzzEnv, mulberry32, replayLine, withReplay } from "./fuzz-kit.mjs";

const prefix = "JOURNAL_RESIDUE";
const file = "test/journal-residue-fuzz.test.mjs";
const { seed, iterations } = fuzzEnv(prefix, { defaultSeed: 750, defaultIterations: 32 });
const alphabet = ["A", "z", "9", "é", "́", "雪", "🔑"];
const thresholds = [1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256];
const password = "public residue test fixture";
const keys = await deriveJournalKeys(password, JOURNAL_MIN_ITERATIONS);

function fixture(random, i) {
  const size = thresholds[i % thresholds.length];
  // Alternate complete passes over exact ASCII byte lengths and mixed Unicode.
  const chars = Math.floor(i / thresholds.length) % 2 === 0 ? alphabet.slice(0, 3) : alphabet;
  let value = "";
  for (let j = 0; j < size; j++) value += chars[Math.floor(random() * chars.length)];
  return value;
}

function assertWiped(ref, size, label) {
  assert.ok(ref instanceof Uint8Array, `missing observer for ${label}`);
  assert.equal(ref.byteLength, size, `wrong size for ${label}`);
  assert.ok(ref.every(byte => byte === 0), `${label} was not fully wiped`);
}

for (const mode of ["round trip", "HMAC rejects", "encryption rejects", "decoder throws"]) {
  const name = `Journal temporary bytes are wiped when ${mode}`;
  test(name, async t => {
    const subtle = crypto.subtle;
    const sign = subtle.sign.bind(subtle);
    const decrypt = subtle.decrypt.bind(subtle);
    const decode = TextDecoder.prototype.decode;
    const random = mulberry32(seed);
    let plain, tag, opened, expected;

    t.mock.method(subtle, "sign", async (algorithm, key, data) => {
      assert.ok(Buffer.from(data).equals(expected), "the observed HMAC input must match the public fixture");
      plain = data; // Retain the original view, not a copy.
      const result = await sign(algorithm, key, data);
      tag = new Uint8Array(result); // Shares the buffer delivered to the application.
      assert.ok(tag.some(byte => byte !== 0), "empty HMAC control");
      return result;
    });
    t.mock.method(subtle, "decrypt", async (...args) => {
      const result = await decrypt(...args);
      opened = new Uint8Array(result);
      assert.ok(Buffer.from(opened).equals(expected), "decryption control");
      return result;
    });
    if (mode === "decoder throws") {
      t.mock.method(TextDecoder.prototype, "decode", function (bytes, ...args) {
        if (opened && bytes?.buffer === opened.buffer) throw new Error("fixture decoder failure");
        return decode.call(this, bytes, ...args);
      });
    }

    for (let i = 0; i < iterations; i++) {
      const text = fixture(random, i);
      expected = Buffer.from(text);
      plain = tag = opened = undefined;
      try {
        // Wrong key usage makes real Web Crypto reject at the selected await.
        let sealed;
        if (mode === "HMAC rejects" || mode === "encryption rejects") {
          const wrong = mode === "HMAC rejects" ? { ...keys, ivKey: keys.encKey } : { ...keys, encKey: keys.ivKey };
          await assert.rejects(sealBytesWithKeys(text, wrong), { name: "InvalidAccessError" });
        } else {
          sealed = await sealBytesWithKeys(text, keys);
        }
        assertWiped(plain, expected.length, "encoded plaintext");
        if (mode !== "HMAC rejects") assertWiped(tag, 32, "HMAC temporary");
        if (!sealed) continue;

        const iv = sealed.iv.slice();
        const ciphertext = sealed.ciphertext.slice();
        if (mode === "decoder throws") {
          await assert.rejects(openBytesWithKeys(sealed, keys), /fixture decoder failure/);
        } else {
          assert.equal(await openBytesWithKeys(sealed, keys), text);
        }
        assertWiped(opened, expected.length, "decrypted plaintext");
        assert.deepEqual(sealed.iv, iv, "caller-owned IV changed");
        assert.deepEqual(sealed.ciphertext, ciphertext, "caller-owned ciphertext changed");
      } catch (error) {
        error.message += ` (case ${i})`;
        throw withReplay(error, replayLine(prefix, seed, iterations, name, file));
      }
    }
  });
}

test("logUsage wipes every encoded event after measuring it", t => {
  const events = [
    { at: "2026-09-01 15:04:05", tool: "fixture", action: "measure", detail: "public 雪" },
    { at: "2026-09-01 15:04:06", tool: "fixture", action: "measure", detail: "second 🔑" },
  ];
  const expectedTexts = events.map(event => JSON.stringify({
    at: event.at, tool: event.tool, action: event.action, detail: event.detail,
  }));
  const expectedBytes = expectedTexts.map(text => Buffer.from(text, "utf8"));
  const observed = [];
  const encode = TextEncoder.prototype.encode;
  t.mock.method(TextEncoder.prototype, "encode", function (input, ...args) {
    const bytes = encode.call(this, input, ...args);
    const index = expectedTexts.indexOf(input);
    if (index !== -1) {
      assert.ok(Buffer.from(bytes).equals(expectedBytes[index]), "encoded event control");
      observed[index] = bytes;
    }
    return bytes;
  });

  const usage = logUsage({ log: events, logDiscarded: 0 });
  assert.equal(usage.count, events.length);
  assert.equal(usage.discarded, 0);
  assert.equal(usage.bytes, Buffer.byteLength(JSON.stringify(events), "utf8"));
  for (let i = 0; i < events.length; i++) assertWiped(observed[i], expectedBytes[i].length, `encoded event ${i}`);
});

// Node's independent SHA-256 and PBKDF2 implementations supply non-zero
// controls, including non-zero final bytes for shortened-wipe detection.
function derivationFixture(basePassword, saltPrefix) {
  for (let suffix = 0; suffix < 1024; suffix++) {
    const candidate = suffix ? `${basePassword}${suffix}` : basePassword;
    const ikm = Buffer.from(candidate, "utf8");
    const saltInputText = saltPrefix + candidate;
    const saltInput = Buffer.from(saltInputText, "utf8");
    const salt = createHash("sha256").update(saltInput).digest();
    const master = pbkdf2Sync(ikm, salt, JOURNAL_MIN_ITERATIONS, 64, "sha256");
    if (salt[salt.length - 1] !== 0 && master[master.length - 1] !== 0) {
      return { password: candidate, saltInputText, ikm, saltInput, salt, master };
    }
  }
  throw new Error("could not prepare a public derivation fixture");
}

async function checkDerivationWipes(t, derive, fixture, mode) {
  const subtle = crypto.subtle;
  const encode = TextEncoder.prototype.encode;
  const importKey = subtle.importKey.bind(subtle);
  const deriveBits = subtle.deriveBits.bind(subtle);
  let ikm, saltInput, salt, master;

  t.mock.method(TextEncoder.prototype, "encode", function (input, ...args) {
    const bytes = encode.call(this, input, ...args);
    if (input === fixture.password) {
      assert.ok(Buffer.from(bytes).equals(fixture.ikm), "IKM encoder control");
      ikm = bytes;
    } else if (input === fixture.saltInputText) {
      assert.ok(Buffer.from(bytes).equals(fixture.saltInput), "salt-input encoder control");
      saltInput = bytes;
    }
    return bytes;
  });
  t.mock.method(subtle, "importKey", async (...args) => {
    const [, keyData, algorithm] = args;
    if (algorithm === "PBKDF2") {
      assert.ok(Buffer.from(keyData).equals(fixture.ikm), "PBKDF2 key-material control");
      ikm = keyData;
    }
    if (mode === "key import rejects" && algorithm?.name === "HMAC") {
      await importKey(...args);
      throw new Error("fixture key import failure");
    }
    return importKey(...args);
  });
  t.mock.method(subtle, "deriveBits", async (...args) => {
    salt = args[0].salt;
    assert.ok(Buffer.from(salt).equals(fixture.salt), "derived-salt control");
    const result = await deriveBits(...args);
    if (mode !== "deriveBits rejects") {
      master = new Uint8Array(result);
      assert.ok(Buffer.from(master).equals(fixture.master), "master-key control");
    }
    if (mode === "deriveBits rejects") throw new Error("fixture deriveBits failure");
    return result;
  });

  if (mode === "success") {
    const derived = await derive(fixture.password, JOURNAL_MIN_ITERATIONS);
    assert.ok(derived.encKey);
    assert.ok(derived.ivKey);
  } else {
    const expected = mode === "deriveBits rejects" ? /fixture deriveBits failure/ : /fixture key import failure/;
    await assert.rejects(() => derive(fixture.password, JOURNAL_MIN_ITERATIONS), expected);
  }

  assertWiped(ikm, fixture.ikm.length, "PBKDF2 IKM");
  assertWiped(saltInput, fixture.saltInput.length, "PBKDF2 salt input");
  assertWiped(salt, fixture.salt.length, "derived salt");
  if (mode !== "deriveBits rejects") assertWiped(master, fixture.master.length, "derived master");
}

for (const [label, derive, fixture] of [
  ["Journal", deriveJournalKeys, derivationFixture("public journal derivation fixture", JOURNAL_SALT_PREFIX)],
  ["Nonce history", deriveNonceHistoryKeys, derivationFixture("public nonce derivation fixture", NONCE_HISTORY_SALT_PREFIX)],
]) {
  for (const mode of ["success", "deriveBits rejects", "key import rejects"]) {
    test(`${label} derivation wipes temporary bytes on ${mode}`, async t => {
      await checkDerivationWipes(t, derive, fixture, mode);
    });
  }
}

const fixedNow = new Date("2026-09-01T15:04:05.000Z");
const entryFields = Object.freeze({
  method: "hex",
  input: "aa55aa55",
  phrase: "public fixture phrase",
  label: "residue fixture",
  notes: "public fixture note",
  walletName: "public fixture wallet",
  fingerprint: "AABBCCDD",
});

function assertEntryControl(entry) {
  assert.equal(entry.input, entryFields.input);
  assert.equal(entry.phrase, entryFields.phrase);
  assert.equal(entry.label, entryFields.label);
  assert.equal(entry.notes, entryFields.notes);
  assert.equal(entry.walletName, entryFields.walletName);
  assert.equal(entry.fingerprint, entryFields.fingerprint.toLowerCase());
}

function assertEntryWiped(entry) {
  assert.ok(entry, "missing normalized-entry observer");
  for (const field of ["input", "phrase", "label", "notes", "walletName", "fingerprint"]) {
    assert.equal(entry[field], "", `${field} was not wiped`);
  }
}

function backupFixture() {
  return {
    notebook: serializeNotebook(createJournal()),
    keyManager: serializeKeyVault([], []),
    includedKeys: [],
    activeKey: null,
    snapshot: { text: "public snapshot fixture", includePrivate: true, latestStart: 3 },
    log: [{ at: "2026-09-01 15:04:05", tool: "fixture", action: "seal", detail: "public log fixture" }],
    logDiscarded: 2,
  };
}

function backupPlain(validBackup) {
  const backup = backupFixture();
  if (!validBackup) backup.notebook = "not notebook JSON";
  return JSON.stringify({
    version: JOURNAL_BACKUP_VERSION,
    nextId: 2,
    entries: [{ id: 1, ...entryFields, created: fixedNow.toISOString() }],
    backup,
  });
}

function observeParse(t, plain) {
  const parse = JSON.parse;
  const observed = {};
  t.mock.method(JSON, "parse", function (text, ...args) {
    const value = parse.call(this, text, ...args);
    if (text !== plain) return value;

    const backupBytes = Uint8Array.from([1, 3, 5, 7, 9, 11, 13, 15]);
    const nestedBytes = Uint8Array.from([2, 4, 6, 8, 10, 12]);
    assert.ok(backupBytes.every(byte => byte !== 0), "backup-byte control");
    assert.ok(nestedBytes.every(byte => byte !== 0), "nested backup-byte control");
    value.backup.observer = { bytes: backupBytes, nested: { bytes: nestedBytes } };
    observed.parsed = value;
    observed.backupBytes = backupBytes;
    observed.nestedBytes = nestedBytes;

    const entries = value.entries;
    const map = entries.map;
    entries.map = function (...mapArgs) {
      const normalized = map.apply(this, mapArgs);
      observed.normalizedEntries = normalized;
      assertEntryControl(normalized[0]);
      return normalized;
    };
    return value;
  });
  return observed;
}

test("parseDocument wipes the parsed backup input after a successful parse", t => {
  const plain = backupPlain(true);
  const observed = observeParse(t, plain);
  const doc = parseDocument(plain);
  assertEntryControl(doc.entries[0]);
  assertWiped(observed.backupBytes, 8, "parsed backup bytes");
  assertWiped(observed.nestedBytes, 6, "nested parsed backup bytes");
});

test("parseDocument wipes its partial document and backup input when the backup fails", t => {
  const plain = backupPlain(false);
  const observed = observeParse(t, plain);
  assert.throws(() => parseDocument(plain));
  assert.ok(observed.normalizedEntries, "missing partial-document observer");
  assertEntryWiped(observed.normalizedEntries[0]);
  assertWiped(observed.backupBytes, 8, "failed parsed backup bytes");
  assertWiped(observed.nestedBytes, 6, "nested failed parsed backup bytes");
});

function documentFixture() {
  const doc = emptyDocument();
  addEntry(doc, { ...entryFields }, fixedNow);
  return doc;
}

function observeSealBackup(t, doc, backup) {
  const stringify = JSON.stringify;
  const observed = {};
  t.mock.method(JSON, "stringify", function (value, ...args) {
    const text = stringify.call(this, value, ...args);
    // The second document serialization borrows normalized.entries and the
    // normalized backup's snapshot/log objects. Retain those exact objects.
    if (value?.version === JOURNAL_BACKUP_VERSION && value.entries !== doc.entries &&
        value.backup?.snapshot && value.backup.snapshot !== backup.snapshot) {
      observed.entries = value.entries;
      observed.snapshot = value.backup.snapshot;
      observed.log = value.backup.log;
      assertEntryControl(value.entries[0]);
      assert.equal(observed.snapshot.text, backup.snapshot.text);
      assert.equal(observed.snapshot.includePrivate, true);
      assert.equal(observed.snapshot.latestStart, backup.snapshot.latestStart);
      assert.equal(observed.log[0].detail, backup.log[0].detail);
    }
    return text;
  });
  return observed;
}

function assertNormalizedBackupWiped(observed) {
  assert.ok(observed.entries, "missing normalized backup observer");
  assertEntryWiped(observed.entries[0]);
  assert.equal(observed.snapshot.text, "");
  assert.equal(observed.snapshot.includePrivate, false);
  assert.equal(observed.snapshot.latestStart, 0);
  for (const field of ["at", "tool", "action", "detail"]) assert.equal(observed.log[0][field], "");
}

for (const mode of ["seals", "cannot seal"]) {
  test(`sealBackup wipes its normalized document when it ${mode}`, async t => {
    const doc = documentFixture();
    const backup = backupFixture();
    const observed = observeSealBackup(t, doc, backup);
    if (mode === "seals") {
      const sealed = await sealBackup(doc, keys, backup);
      assert.equal(sealed.iterations, JOURNAL_MIN_ITERATIONS);
    } else {
      // The normalized document and plaintext exist before this key check.
      await assert.rejects(() => sealBackup(doc, {}, backup));
    }
    assertNormalizedBackupWiped(observed);
  });
}

const exportContent = "public export fixture";

async function openFixture(basePlainText, exported) {
  // Trailing JSON whitespace changes the deterministic synthetic IV without
  // changing the payload. Select a fixture whose final IV/ciphertext bytes are
  // non-zero so a wipe shortened by one byte cannot pass vacuously.
  for (let attempt = 0; attempt < 1024; attempt++) {
    const plainText = basePlainText + "\n".repeat(attempt);
    const sealed = await sealBytesWithKeys(plainText, keys);
    const envelope = encodeFile({ ...sealed, iterations: JOURNAL_MIN_ITERATIONS });
    const iv = Buffer.from(envelope.iv, "hex");
    const ciphertext = Buffer.from(envelope.ciphertext, "hex");
    if (iv[iv.length - 1] !== 0 && ciphertext[ciphertext.length - 1] !== 0) {
      if (exported) envelope.entropylabJournalExport = JOURNAL_EXPORT_VERSION;
      return { file: envelope, plainText, plainBytes: Buffer.from(plainText, "utf8"), iv, ciphertext };
    }
  }
  throw new Error("could not prepare a public open fixture");
}

for (const [label, exported] of [["openExport", true], ["openDocument", false]]) {
  for (const failing of [false, true]) {
    test(`${label} wipes plaintext, IV, and ciphertext ${failing ? "after a post-decrypt failure" : "after return"}`, async t => {
      const validPlainText = exported
        ? JSON.stringify({ entropylabJournalExport: JOURNAL_EXPORT_VERSION, kind: "notebook", content: exportContent })
        : JSON.stringify({ version: JOURNAL_VERSION, nextId: 1, entries: [] });
      const fixture = await openFixture(failing ? "not JSON fixture" : validPlainText, exported);
      const subtle = crypto.subtle;
      const decrypt = subtle.decrypt.bind(subtle);
      let plainBytes, iv, ciphertext;

      t.mock.method(subtle, "decrypt", async (algorithm, key, data) => {
        iv = algorithm.iv;
        ciphertext = data;
        assert.ok(Buffer.from(iv).equals(fixture.iv), "parsed-IV control");
        assert.ok(Buffer.from(ciphertext).equals(fixture.ciphertext), "parsed-ciphertext control");
        const result = await decrypt(algorithm, key, data);
        plainBytes = new Uint8Array(result);
        assert.ok(Buffer.from(plainBytes).equals(fixture.plainBytes), "decrypted-open-plaintext control");
        return result;
      });

      const open = exported ? () => openExport(fixture.file, keys) : () => openDocument(fixture.file, password);
      if (failing) {
        await assert.rejects(open);
      } else {
        const opened = await open();
        if (exported) assert.deepEqual(opened, { kind: "notebook", content: exportContent });
        else assert.equal(opened.doc.entries.length, 0);
      }

      assertWiped(plainBytes, fixture.plainBytes.length, `${label} plaintext`);
      assertWiped(iv, fixture.iv.length, `${label} IV`);
      assertWiped(ciphertext, fixture.ciphertext.length, `${label} ciphertext`);
    });
  }
}
