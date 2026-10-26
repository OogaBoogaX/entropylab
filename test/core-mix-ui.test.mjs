// Tests for the Key Station's Core wallet.dat + dice/cards method (issue #552).
// Run with: node --test test/core-mix-ui.test.mjs
//
// The wallet fixtures are the same Bitcoin Core v28.3.0 ground truth the
// core-mix suite uses; every expected hash is computed here with node:crypto,
// never with the module under test.
import { test } from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { createHash } from "node:crypto";
import { coreMixEntropy, coreMixSecrets, wipeCoreMixSecrets } from "../src/js/core-mix.js";
import { GENERATED_ROWS, GENERATED_SEED } from "./core-generated-fixture.mjs";
import { REF_WATCH_ONLY_RECORDS } from "./wallet-export-reference.mjs";
import { bytesToHex, hdMasterFromSeed, hexToBytes, publicKeyForPrivate, read, sha256 } from "./wallet-export-harness.mjs";

const app = read("src/js/app.js");
const registry = read("test/secret-field-registry.test.mjs");

// The vm extraction pattern the core-importdescriptors suite uses.
const fnSource = (name) => {
  const match = app.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^}`, "m"));
  assert.ok(match, `${name} exists in app.js`);
  return match[0];
};

const fill = (text, params) => params ? text.replace(/\{(\w+)\}/g, (_, key) => String(params[key])) : text;

const utf8 = (text) => new TextEncoder().encode(text);
// The specification's preimage, written out here rather than called from the
// module: domain tag, 0x00, the sorted secrets, 0x00, the transcript.
const expectedEntropy = (secrets, transcript, size) =>
  new Uint8Array(createHash("sha256")
    .update(Buffer.concat([
      Buffer.from("entropylab-core-mix-v1", "utf8"),
      Buffer.from([0]),
      ...secrets.map((secret) => Buffer.from(secret)),
      Buffer.from([0]),
      Buffer.from(transcript, "utf8"),
    ]))
    .digest()
    .subarray(0, size));

// The fixture wallet's one master secret, taken from the seed it was
// generated from — not from coreMixSecrets.
const fixtureSecret = () => new Uint8Array(hdMasterFromSeed(GENERATED_SEED).secret);

const MAIN_SQL = "CREATE TABLE main(key BLOB PRIMARY KEY NOT NULL, value BLOB NOT NULL)";
const REGTEST_APP_ID = 0xfabfb5da;
let walletModule = null;
const wallet = () => walletModule || (walletModule = new Function(
  `${read("src/js/sqlite-writer.js")}\n${read("src/js/sqlite-reader.js")}\n${read("src/js/wallet-export.js")}\n${read("src/js/core-wallet.js")}\nreturn { writer: hodlSqliteWriter, core: hodlCoreWallet };`)());
const walletBytes = (records) => wallet().writer.createDatabase({
  applicationId: REGTEST_APP_ID,
  tables: [{ name: "main", sql: MAIN_SQL, primaryKey: 0, rows: records.map(([key, value]) => [hexToBytes(key), hexToBytes(value)]) }],
});

function loadContext({ parse, secrets } = {}) {
  const elements = {
    "core-mix-error": { textContent: "" },
    "core-mix-summary": { hidden: true, textContent: "" },
  };
  const context = vm.createContext({
    hodlCoreMix: null,
    hodlCoreMixGeneration: 0,
    hodlActiveKey: 0,
    hodlKeys: [{ id: "key-1" }],
    coreMixSecrets: secrets || coreMixSecrets,
    wipeCoreMixSecrets,
    hodlCoreWallet: parse ? { parseWalletDat: parse } : wallet().core,
    hodlSha256: sha256,
    hodlWalletDatDeps: () => ({ publicKeyForPrivate }),
    hodlTText: fill,
    document: { getElementById: (id) => elements[id] || null },
  });
  for (const name of ["hodlCoreMixReset", "hodlCoreMixShowError", "hodlCoreMixShowSummary", "hodlCoreMixLoadBytes"]) {
    vm.runInContext(fnSource(name), context);
  }
  // The document wipe is the fix under test: run it when it exists, so the
  // original source fails on the un-zeroed buffers, not on a missing name.
  const wipeDoc = app.match(/^function hodlCoreMixWipeDoc\([^]*?^}/m);
  if (wipeDoc) vm.runInContext(wipeDoc[0], context);
  return { context, elements };
}

function entropyContext({ loaded, source, transcript, dice, cards, split, activeKeyId = "key-1" }) {
  const context = vm.createContext({
    hodlCoreMix: loaded,
    hodlCoreMixSource: source,
    hodlTargetWordCount: 24,
    hodlActiveKey: 0,
    hodlKeys: [{ id: activeKeyId }],
    hodlNote: fill,
    hodlSeedConfig: (words) => ({ words, bytes: 32, bits: 256, hashRolls: 99, partialWords: 23, candidates: 8 }),
    hodlDiceEntropy: dice || (() => ({ ok: true, bytes: new Uint8Array(32), sourceBits: 24, warnings: [] })),
    hodlSplitDiceString: split || ((value) => ({ rolls: [...String(value)].filter((character) => "123456".includes(character)) })),
    hodlCardsEntropy: cards || (() => ({ ok: true, hashInput: transcript, sourceBits: 11, warnings: [] })),
    hodlSha256: sha256,
    hodlHex: { encode: (bytes) => Buffer.from(bytes).toString("hex") },
    coreMixEntropy,
    document: { getElementById: (id) => id === "core-mix-transcript" ? { value: transcript } : null },
  });
  vm.runInContext(fnSource("hodlCoreMixSelectedEntropy"), context);
  return context;
}

function warningContext({ source }) {
  const context = vm.createContext({
    hodlCoreMixSource: source,
    hodlNote: fill,
    hodlSeedConfig: (words) => ({ words, bytes: 32, bits: 256, hashRolls: 99, partialWords: 23, candidates: 8 }),
    hodlSplitDiceString: (value) => ({ rolls: [...String(value)].filter((character) => "123456".includes(character)) }),
    hodlDiceEntropyBits: (rolls) => rolls * Math.log2(6),
    hodlParseCards: (value) => ({ cards: [...String(value).matchAll(/[2-9TJQKA][SHDC]/gi)], needed: { first: 58, extra: 0 }, bits: 11 }),
    document: { getElementById: () => null },
  });
  vm.runInContext(fnSource("hodlLowEntropyWarningFor"), context);
  return context;
}

// The corewallet render branch, and the handlers inside it.
const coreWalletBranch = () => {
  const form = app.indexOf("function hodlRenderKeyForm(");
  const start = app.indexOf('if (hodlKeyMode === "corewallet") {', form);
  const end = app.indexOf('if (hodlKeyMode === "dice") {', start);
  assert.ok(form >= 0 && start > form && end > start, "the corewallet render branch exists");
  return app.slice(start, end);
};
const handlerSource = (name, next) => {
  const branch = coreWalletBranch();
  const start = branch.indexOf(`${name} = `);
  const end = branch.indexOf(next, start);
  assert.ok(start >= 0 && end > start, `${name} handler exists`);
  let text = branch.slice(start + `${name} = `.length, end).trim();
  if (text.endsWith(";")) text = text.slice(0, -1);
  return text;
};
const fileHandlerSource = () => handlerSource("file.onchange", "sourceSelect.onchange");
const sourceHandler = () => handlerSource("sourceSelect.onchange", "transcript.oninput");
const transcriptHandler = () => handlerSource("transcript.oninput", "hodlBindKeyFields();");

const ENCRYPTED_ROWS = [
  ...GENERATED_ROWS,
  ["1a77616c6c657464657363726970746f72637279707465646b6579" + "00".repeat(32) + "21" + "02".repeat(33), "f0" + "01".repeat(48)],
];
const TAMPERED_ROWS = (() => {
  const rows = GENERATED_ROWS.map(([key, value]) => [key, value]);
  const record = rows.find(([key]) => key.startsWith("1377616c6c657464657363726970746f726b6579"));
  const value = hexToBytes(record[1]);
  value[1 + 8] ^= 0x01;
  record[1] = bytesToHex(value);
  return rows;
})();

test("a loaded wallet shows its name, key count and fingerprint, and the file bytes are zeroed", () => {
  const { context, elements } = loadContext();
  const bytes = walletBytes(GENERATED_ROWS);
  assert.equal(context.hodlCoreMixLoadBytes(bytes, "core.dat"), true);
  assert.ok(bytes.every((byte) => byte === 0), "the file bytes are zeroed");
  assert.equal(context.hodlCoreMix.name, "core.dat");
  assert.equal(context.hodlCoreMix.count, 1);
  assert.equal(context.hodlCoreMix.keyId, "key-1", "the holder is tied to the tab that loaded it");
  assert.match(context.hodlCoreMix.fingerprint, /^[0-9a-f]{8}$/);
  assert.equal(elements["core-mix-summary"].hidden, false);
  assert.match(elements["core-mix-summary"].textContent, /core\.dat/);
  assert.match(elements["core-mix-summary"].textContent, /1 key/);
  assert.match(elements["core-mix-summary"].textContent, /fingerprint [0-9a-f]{8}/);
  assert.equal(elements["core-mix-error"].textContent, "");
  wipeCoreMixSecrets(context.hodlCoreMix.secrets);
});

test("an encrypted, watch-only or tampered wallet is refused without loading", () => {
  for (const [records, code] of [[ENCRYPTED_ROWS, /^encrypted:/], [REF_WATCH_ONLY_RECORDS, /^watch-only:/], [TAMPERED_ROWS, /^key-mismatch:/]]) {
    const { context, elements } = loadContext();
    const bytes = walletBytes(records);
    assert.equal(context.hodlCoreMixLoadBytes(bytes, "wallet.dat"), false);
    assert.equal(context.hodlCoreMix, null);
    assert.match(elements["core-mix-error"].textContent, code);
    assert.equal(elements["core-mix-summary"].hidden, true);
    assert.ok(bytes.every((byte) => byte === 0), "the file bytes are zeroed even on refusal");
  }
});

test("a file that is not a wallet is refused and zeroed", () => {
  const { context, elements } = loadContext();
  const bytes = new Uint8Array([1, 2, 3, 4]);
  assert.equal(context.hodlCoreMixLoadBytes(bytes, "bad.dat"), false);
  assert.equal(context.hodlCoreMix, null);
  assert.ok(elements["core-mix-error"].textContent.length > 0);
  assert.ok(bytes.every((byte) => byte === 0));
});

test("the parsed document's record buffers are zeroed after a load, success or failure", () => {
  const makeDoc = () => {
    const key = new Uint8Array([1, 2, 3]), value = new Uint8Array([4, 5, 6]);
    const otherKey = new Uint8Array([7, 8]), otherValue = new Uint8Array([9, 10]);
    const der = new Uint8Array([11, 12]), pubkey = new Uint8Array([13, 14]);
    // doc.rows is every raw database row as [key, value] (the DER key records
    // among them), and records can nest buffers inside sub-objects.
    const rowKey = new Uint8Array([15, 16]), rowValue = new Uint8Array([17, 18]), nested = new Uint8Array([19, 20]);
    return {
      records: [{ name: "walletdescriptorkey", key, value, parsed: { inner: [nested] } }],
      others: [{ name: "tx", key: otherKey, value: otherValue }],
      descriptors: [{ keys: [{ der, pubkey }] }],
      rows: [[rowKey, rowValue]],
      buffers: [key, value, otherKey, otherValue, der, pubkey, rowKey, rowValue, nested],
    };
  };
  for (const fail of [false, true]) {
    const doc = makeDoc();
    // A raw ArrayBuffer and a DataView in the document must be zeroed too;
    // they are checked through views kept outside the document.
    const raw = new ArrayBuffer(4), viewed = new ArrayBuffer(4);
    new Uint8Array(raw).fill(21);
    new Uint8Array(viewed).fill(22);
    doc.records[0].raw = raw;
    doc.records[0].dv = new DataView(viewed);
    const { context } = loadContext({
      parse: () => doc,
      secrets: fail ? () => { throw new Error("key-mismatch: nope"); } : () => ({ secrets: [new Uint8Array(32).fill(1)], count: 1, fingerprint: "aabbccdd" }),
    });
    const bytes = new Uint8Array([1, 2, 3]);
    context.hodlCoreMixLoadBytes(bytes, "wallet.dat");
    for (const buffer of doc.buffers) assert.ok(buffer.every((byte) => byte === 0), "the document's copy is zeroed");
    assert.ok(new Uint8Array(raw).every((byte) => byte === 0), "a raw ArrayBuffer is zeroed");
    assert.ok(new Uint8Array(viewed).every((byte) => byte === 0), "a DataView's bytes are zeroed");
    assert.ok(bytes.every((byte) => byte === 0), "the file bytes are zeroed");
  }
});

test("each wallet.dat pick makes an earlier read stale and retires the derived result", () => {
  const change = app.slice(app.indexOf("file.onchange = () => {"), app.indexOf("sourceSelect.onchange"));
  assert.match(change, /let generation = \+\+hodlCoreMixGeneration, keyId = hodlKeys\[hodlActiveKey\]\?\.id \?\? null;\s*(?:\/\/[^\n]*\n\s*)*if \(typeof hodlInvalidateDerivation === "function"\) hodlInvalidateDerivation\(\);/);
});

test("loading a new file wipes the previous wallet's secrets", () => {
  const { context } = loadContext();
  assert.equal(context.hodlCoreMixLoadBytes(walletBytes(GENERATED_ROWS), "first.dat"), true);
  const previous = context.hodlCoreMix.secrets;
  assert.ok(previous.every((secret) => secret.some((byte) => byte !== 0)));
  assert.equal(context.hodlCoreMixLoadBytes(walletBytes(GENERATED_ROWS), "second.dat"), true);
  for (const secret of previous) assert.ok(secret.every((byte) => byte === 0), "the old secrets are zeroed");
  wipeCoreMixSecrets(context.hodlCoreMix.secrets);
});

test("the held secrets survive the load's document wipe", () => {
  const { context } = loadContext();
  assert.equal(context.hodlCoreMixLoadBytes(walletBytes(GENERATED_ROWS), "wallet.dat"), true);
  const { secrets } = context.hodlCoreMix;
  assert.ok(secrets.length > 0);
  for (const secret of secrets) assert.ok(secret.length === 32 && secret.some((byte) => byte !== 0), "a held secret is not zeroed by the document wipe");
  wipeCoreMixSecrets(secrets);
});

test("the reset zeroes every secret, drops the holder and hides its summary", () => {
  const { context, elements } = loadContext();
  assert.equal(context.hodlCoreMixLoadBytes(walletBytes(GENERATED_ROWS), "wallet.dat"), true);
  assert.equal(elements["core-mix-summary"].hidden, false);
  const secrets = context.hodlCoreMix.secrets;
  context.hodlCoreMixReset();
  assert.equal(context.hodlCoreMix, null);
  for (const secret of secrets) assert.ok(secret.every((byte) => byte === 0));
  assert.equal(elements["core-mix-summary"].hidden, true, "the dropped wallet's summary is hidden");
  assert.equal(elements["core-mix-summary"].textContent, "");
});

test("the reset clears a refusal left by the dropped file", () => {
  const { context, elements } = loadContext();
  elements["core-mix-error"].textContent = "This wallet file is too large to inspect safely.";
  context.hodlCoreMixReset();
  assert.equal(elements["core-mix-error"].textContent, "", "no stale error after the holder is dropped");
});

test("the active key's wipe drops the wallet secrets", () => {
  const secrets = [new Uint8Array(32).fill(7)];
  const context = vm.createContext({
    hodlActiveKey: -1,
    hodlKeys: [],
    hodlCoreMix: { keyId: "key-1", name: "wallet.dat", count: 1, fingerprint: "aabbccdd", secrets },
    hodlCoreMixGeneration: 0,
    wipeCoreMixSecrets,
    hodlInvalidateDerivation: () => {},
    hodlLastWordCache: { clear: () => {} },
  });
  vm.runInContext(fnSource("hodlCoreMixReset"), context);
  vm.runInContext(fnSource("hodlWipeActiveKey"), context);
  context.hodlWipeActiveKey();
  assert.equal(context.hodlCoreMix, null);
  for (const secret of secrets) assert.ok(secret.every((byte) => byte === 0));
});

test("switching to another method drops the wallet secrets", () => {
  const secrets = [new Uint8Array(32).fill(7)];
  const context = vm.createContext({
    hodlActiveKey: -1,
    hodlKeys: [],
    hodlCoreMix: { keyId: "key-1", name: "wallet.dat", count: 1, fingerprint: "aabbccdd", secrets },
    hodlCoreMixGeneration: 0,
    wipeCoreMixSecrets,
    hodlCaptureKey: () => {},
    hodlNormalizeSeedMethod: () => "words",
    hodlNormalizeEntropyFormat: () => "bin",
    hodlSyncKeyModeSelect: () => {},
    hodlRenderKeyForm: () => {},
    hodlRestoreFormFields: () => {},
    hodlUpdateSeedLengthControl: () => {},
    hodlUpdateDerivationPathPreview: () => {},
    hodlQueueSegmentedControlSync: () => {},
  });
  vm.runInContext(fnSource("hodlCoreMixReset"), context);
  vm.runInContext(fnSource("hodlSetMode"), context);
  context.hodlSetMode("dice");
  assert.equal(context.hodlCoreMix, null);
  for (const secret of secrets) assert.ok(secret.every((byte) => byte === 0));
});

test("switching to the core wallet method keeps the loaded wallet", () => {
  const secrets = [new Uint8Array(32).fill(7)];
  const context = vm.createContext({
    hodlActiveKey: -1,
    hodlKeys: [],
    hodlCoreMix: { keyId: "key-1", name: "wallet.dat", count: 1, fingerprint: "aabbccdd", secrets },
    hodlCoreMixGeneration: 0,
    wipeCoreMixSecrets,
    hodlCaptureKey: () => {},
    hodlNormalizeSeedMethod: () => "words",
    hodlNormalizeEntropyFormat: () => "bin",
    hodlSyncKeyModeSelect: () => {},
    hodlRenderKeyForm: () => {},
    hodlRestoreFormFields: () => {},
    hodlUpdateSeedLengthControl: () => {},
    hodlUpdateDerivationPathPreview: () => {},
    hodlQueueSegmentedControlSync: () => {},
  });
  vm.runInContext(fnSource("hodlCoreMixReset"), context);
  vm.runInContext(fnSource("hodlSetMode"), context);
  context.hodlSetMode("corewallet");
  assert.notEqual(context.hodlCoreMix, null);
  wipeCoreMixSecrets(context.hodlCoreMix.secrets);
});

test("switching key tabs drops the wallet secrets", () => {
  const secrets = [new Uint8Array(32).fill(7)];
  const context = vm.createContext({
    hodlActiveKey: 0,
    hodlKeys: [{ id: "key-1" }, { id: "key-2" }],
    hodlCoreMix: { keyId: "key-1", name: "wallet.dat", count: 1, fingerprint: "aabbccdd", secrets },
    hodlCoreMixGeneration: 0,
    wipeCoreMixSecrets,
    hodlInvalidateDerivation: () => {},
    hodlCaptureKey: () => {},
    hodlRenderKeyTabs: () => {},
    hodlRestoreKey: () => {},
    hodlJournalLog: () => {},
  });
  vm.runInContext(fnSource("hodlCoreMixReset"), context);
  vm.runInContext(fnSource("hodlSelectKey"), context);
  context.hodlSelectKey(1);
  assert.equal(context.hodlCoreMix, null);
  for (const secret of secrets) assert.ok(secret.every((byte) => byte === 0));
});

test("the session-end sweep drops the wallet secrets and clears the transcript field", () => {
  const sweep = fnSource("hodlInitSecretFieldAutoClear");
  assert.match(sweep, /hodlCoreMixReset\(\)/, "the sweep must call the core-mix reset");
  assert.match(sweep, /"core-mix-transcript"/, "the sweep must clear the transcript field");
  const { context } = loadContext();
  assert.equal(context.hodlCoreMixLoadBytes(walletBytes(GENERATED_ROWS), "wallet.dat"), true);
  const secrets = context.hodlCoreMix.secrets;
  context.hodlCoreMixReset();
  assert.equal(context.hodlCoreMix, null);
  for (const secret of secrets) assert.ok(secret.every((byte) => byte === 0));
});

test("dice: the mixed entropy is SHA-256 of the domain tag, the secret and the COLDCARD transcript", () => {
  const secret = fixtureSecret();
  const loaded = { keyId: "key-1", name: "wallet.dat", count: 1, fingerprint: "aabbccdd", secrets: [secret] };
  const context = entropyContext({ loaded, source: "dice", transcript: "4 1 5 2 6 3" });
  const result = context.hodlCoreMixSelectedEntropy(24);
  assert.equal(result.ok, true);
  const expected = expectedEntropy([secret], "415263", 32);
  assert.deepEqual([...result.bytes], [...expected]);
  assert.equal(Buffer.from(result.bytes).toString("hex"), Buffer.from(expected).toString("hex"));
  assert.equal(result.bits, 256);
  assert.equal(result.method, "core-wallet-mix-v1");
  assert.equal(result.notes.length, 1);
  assert.match(result.notes[0], /wallet's spend secrets \(1\) and the dice transcript/);
  assert.match(result.notes[0], /of that hash become the seed/);
  const plain = sha256(utf8("415263")).slice(0, 32);
  assert.notDeepEqual([...result.bytes], [...plain], "not the plain dice method's bytes");
});

test("cards: the mixed entropy is SHA-256 over the card hashInput", () => {
  const secret = fixtureSecret();
  const loaded = { keyId: "key-1", name: "wallet.dat", count: 1, fingerprint: "aabbccdd", secrets: [secret] };
  const hashInput = "AS 2C TD";
  const context = entropyContext({ loaded, source: "cards", transcript: "AS 2C TD", cards: () => ({ ok: true, hashInput, sourceBits: 33, warnings: [] }) });
  const result = context.hodlCoreMixSelectedEntropy(24);
  assert.equal(result.ok, true);
  assert.deepEqual([...result.bytes], [...expectedEntropy([secret], hashInput, 32)]);
  assert.equal(result.sourceBits, 33);
});

test("no wallet loaded is refused before any transcript is read", () => {
  const context = entropyContext({ loaded: null, source: "dice", transcript: "415263" });
  const result = context.hodlCoreMixSelectedEntropy(24);
  assert.equal(result.ok, false);
  assert.match(result.error, /Choose a Bitcoin Core wallet\.dat first\./);
});

test("a holder from another key tab is refused", () => {
  const secret = fixtureSecret();
  const loaded = { keyId: "key-2", name: "wallet.dat", count: 1, fingerprint: "aabbccdd", secrets: [secret] };
  const context = entropyContext({ loaded, source: "dice", transcript: "415263", activeKeyId: "key-1" });
  const result = context.hodlCoreMixSelectedEntropy(24);
  assert.equal(result.ok, false);
  assert.match(result.error, /Choose a Bitcoin Core wallet\.dat first\./);
});

test("an invalid transcript returns the dice or card failure unchanged", () => {
  const secret = fixtureSecret();
  const loaded = { keyId: "key-1", name: "wallet.dat", count: 1, fingerprint: "aabbccdd", secrets: [secret] };
  const diceFailure = { ok: false, error: "Enter at least one dice roll (faces 1–6)." };
  assert.equal(entropyContext({ loaded, source: "dice", transcript: "", dice: () => diceFailure }).hodlCoreMixSelectedEntropy(24), diceFailure);
  const cardsFailure = { ok: false, error: "Deal at least one card from a shuffled deck." };
  assert.equal(entropyContext({ loaded, source: "cards", transcript: "", cards: () => cardsFailure }).hodlCoreMixSelectedEntropy(24), cardsFailure);
});

test("an empty transcript is refused by the mixer, not hashed", () => {
  const secret = fixtureSecret();
  const loaded = { keyId: "key-1", name: "wallet.dat", count: 1, fingerprint: "aabbccdd", secrets: [secret] };
  const context = entropyContext({ loaded, source: "dice", transcript: " ", split: () => ({ rolls: [] }) });
  const result = context.hodlCoreMixSelectedEntropy(24);
  assert.equal(result.ok, false);
  assert.match(result.error, /empty-transcript/);
});

test("a one-roll transcript gets the low-entropy warning", () => {
  const context = warningContext({ source: "dice" });
  const warning = context.hodlLowEntropyWarningFor("corewallet", "coldcard", "1", 24);
  assert.ok(warning, "a one-roll transcript warns");
  assert.equal(warning.recommended, 256);
  assert.match(warning.detail, /1 of 99 recommended rolls/);
});

test("a short card transcript gets the low-entropy warning", () => {
  const context = warningContext({ source: "cards" });
  const warning = context.hodlLowEntropyWarningFor("corewallet", "hashed", "AS 2C", 24);
  assert.ok(warning, "a two-card transcript warns");
  assert.match(warning.detail, /2 of 58 recommended cards/);
});

test("the Derive-time warning check reaches the core-mix transcript", () => {
  const context = warningContext({ source: "dice" });
  Object.assign(context, {
    hodlKeyMode: "corewallet",
    hodlTargetWordCount: 24,
    document: { getElementById: (id) => id === "core-mix-transcript" ? { value: "1" } : null },
  });
  vm.runInContext(fnSource("hodlLowEntropyWarning"), context);
  const warning = context.hodlLowEntropyWarning();
  assert.ok(warning, "a one-roll core-mix transcript warns through the dispatcher");
  assert.match(warning.detail, /1 of 99 recommended rolls/);
});

test("a full transcript gets no low-entropy warning", () => {
  const context = warningContext({ source: "dice" });
  assert.equal(context.hodlLowEntropyWarningFor("corewallet", "coldcard", "1".repeat(99), 24), null);
});

test("a transcript edit invalidates the derived result", () => {
  const calls = [];
  const context = vm.createContext({
    hodlInvalidateDerivation: () => calls.push("derivation"),
    hodlInvalidateLiveKeyResult: () => calls.push("result"),
    hodlSyncDeriveButton: () => calls.push("sync"),
  });
  vm.runInContext(`(${transcriptHandler()})()`, context);
  assert.ok(calls.includes("derivation"), "the running derivation is cancelled");
  assert.ok(calls.includes("result"), "the stale result is cleared");
});

test("a dice/cards source change invalidates the derived result", () => {
  const calls = [];
  const context = vm.createContext({
    sourceSelect: { value: "cards" },
    hodlCoreMixSource: "dice",
    state: null,
    document: { getElementById: () => null },
    hodlT: (text) => text,
    hodlInvalidateDerivation: () => calls.push("derivation"),
    hodlInvalidateLiveKeyResult: () => calls.push("result"),
    hodlSyncDeriveButton: () => calls.push("sync"),
  });
  vm.runInContext(`(${sourceHandler()})()`, context);
  assert.equal(context.hodlCoreMixSource, "cards");
  assert.ok(calls.includes("derivation"));
  assert.ok(calls.includes("result"));
});

test("a wallet.dat read that finishes after a reset is zeroed, not loaded", async () => {
  let loaded = false, released;
  const bytes = new Uint8Array([1, 2, 3]);
  const chosen = { size: 3, name: "wallet.dat", arrayBuffer: () => new Promise((resolve) => { released = () => resolve(bytes.buffer); }) };
  const file = { files: [chosen], value: "" };
  const context = vm.createContext({
    file,
    hodlCoreMixGeneration: 0,
    hodlActiveKey: 0,
    hodlKeys: [{ id: "key-1" }],
    hodlKeyMode: "corewallet",
    CORE_WALLET_MAX_BYTES: 64 * 1024 * 1024,
    hodlT: (text) => text,
    hodlCoreMixLoadBytes: () => { loaded = true; },
    hodlCoreMixReset: () => {},
    hodlCoreMixShowError: () => {},
    hodlSyncDeriveButton: () => {},
  });
  vm.runInContext(`file.onchange = ${fileHandlerSource()};`, context);
  context.file.onchange();
  // A reset (End Session, Clear, a tab switch, a method switch) lands while
  // the read is in flight.
  context.hodlCoreMixGeneration++;
  released();
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(loaded, false, "the late read is not loaded");
  assert.ok(bytes.every((byte) => byte === 0), "the late read's bytes are zeroed");
});

test("a stale wallet.dat read that fails keeps the newer wallet", async () => {
  let rejectA, loadedName = null, resets = 0, errors = 0;
  const first = { size: 3, name: "A.dat", arrayBuffer: () => new Promise((_, reject) => { rejectA = reject; }) };
  const second = { size: 3, name: "B.dat", arrayBuffer: async () => new Uint8Array([4, 5, 6]).buffer };
  const file = { files: [first], value: "" };
  const context = vm.createContext({
    file,
    hodlCoreMixGeneration: 0,
    hodlActiveKey: 0,
    hodlKeys: [{ id: "key-1" }],
    hodlKeyMode: "corewallet",
    CORE_WALLET_MAX_BYTES: 64 * 1024 * 1024,
    hodlT: (text) => text,
    hodlCoreMixLoadBytes: (_, name) => { loadedName = name; },
    hodlCoreMixReset: () => { resets++; },
    hodlCoreMixShowError: () => { errors++; },
    hodlSyncDeriveButton: () => {},
  });
  vm.runInContext(`file.onchange = ${fileHandlerSource()};`, context);
  context.file.onchange();
  file.files = [second];
  context.file.onchange();
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(loadedName, "B.dat", "the newer pick loads");
  const resetsAfterPicks = resets;
  rejectA(new Error("NotReadableError"));
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(resets, resetsAfterPicks, "the stale failure does not reset the newer wallet");
  assert.equal(errors, 0, "the stale failure shows no error");
});

test("a new wallet.dat pick drops the loaded wallet before its read finishes", async () => {
  let release, resets = 0;
  const pending = { size: 3, name: "B.dat", arrayBuffer: () => new Promise((resolve) => { release = () => resolve(new Uint8Array([4, 5, 6]).buffer); }) };
  const file = { files: [pending], value: "" };
  const context = vm.createContext({
    file,
    hodlCoreMixGeneration: 0,
    hodlActiveKey: 0,
    hodlKeys: [{ id: "key-1" }],
    hodlKeyMode: "corewallet",
    CORE_WALLET_MAX_BYTES: 64 * 1024 * 1024,
    hodlT: (text) => text,
    hodlCoreMixLoadBytes: () => {},
    hodlCoreMixReset: () => { resets++; },
    hodlCoreMixShowError: () => {},
    hodlSyncDeriveButton: () => {},
  });
  vm.runInContext(`file.onchange = ${fileHandlerSource()};`, context);
  context.file.onchange();
  // Wallet A is gone while B is still being read, so a Derive clicked now
  // finds no wallet instead of mixing A's secrets under B's name.
  assert.equal(resets, 1, "the pick resets the holder before the read resolves");
  release();
  await new Promise((resolve) => setTimeout(resolve, 0));
});

test("Clear stays available while a core-mix transcript is stored in the key", () => {
  const source = fnSource("hodlKeyStateNeedsClear");
  assert.match(source, /"coreMixTranscript"\]\.some\(hasText\)/, "the stored transcript counts as something to clear, whatever the method");
});

test("Derive follows the loaded wallet and the active tab", () => {
  const context = vm.createContext({
    hodlKeyMode: "corewallet",
    hodlCoreMix: { keyId: "key-1", secrets: [] },
    hodlActiveKey: 0,
    hodlKeys: [{ id: "key-1" }],
    hodlTargetWordCount: 24,
    hodlCoreMixSelectedEntropy: () => ({ ok: true }),
    hodlReadDerivationPlan: () => null,
    hodlReadBranchWindow: () => ({}),
    hodlReadAddressWindow: () => ({}),
    hodlPassphraseBip39Enabled: () => false,
    document: { getElementById: () => null },
  });
  vm.runInContext(fnSource("hodlCanDeriveCurrentKey"), context);
  assert.equal(context.hodlCanDeriveCurrentKey(), true, "a loaded wallet enables Derive");
  context.hodlCoreMix = null;
  assert.equal(context.hodlCanDeriveCurrentKey(), false, "a tab switch (reset) disables Derive");
});

test("the preview gate pushes corewallet before the picker is built", () => {
  const gate = app.indexOf('if (typeof __ENTROPYLAB_PREVIEW__ !== "undefined" && __ENTROPYLAB_PREVIEW__) hodlKeyModes.push("corewallet");');
  const picker = app.indexOf('var hodlKeyModeSelectEl = document.createElement("select");');
  assert.ok(gate >= 0, "the preview gate exists");
  assert.ok(picker >= 0, "the picker is built");
  assert.ok(gate < picker, "the gate runs before the picker");
  assert.doesNotMatch(app, /^\s*hodlKeyModes\.push\("corewallet"\);/m, "no unconditional push");
});

test("the method has a label and a summary sub-method label", () => {
  const labels = read("src/js/i18n-labels.js");
  assert.match(labels, /corewallet: "Core wallet\.dat \+ dice\/cards"/);
  assert.match(labels, /corewallet: Object\.freeze\(\{ dice: "Dice rolls \(D6\)", cards: "Cards" \}\)/);
});

test("the registry lists the core-mix transcript", () => {
  assert.match(registry, /"core-mix-transcript"/);
});

// The vm harness supplies the mixer functions itself, so it cannot notice a
// missing import; the page would throw on the first wallet.dat.
test("app.js imports the mixer and the size cap it calls", () => {
  assert.match(app, /^import \{ coreMixEntropy, coreMixSecrets, wipeCoreMixSecrets \} from "\.\/core-mix\.js";$/m);
  assert.match(app, /^import \{ CORE_WALLET_MAX_BYTES, initCoreWallet \} from "\.\/core-wallet-ui\.js";$/m);
});

test("the Derive-button check zeroes the seed entropy it computes", () => {
  const can = app.slice(app.indexOf("function hodlCanDeriveCurrentKey("), app.indexOf("\nfunction ", app.indexOf("function hodlCanDeriveCurrentKey(") + 1));
  assert.match(can, /let entropy = hodlCoreMixSelectedEntropy\(hodlTargetWordCount\);\s*if \(entropy\.ok && entropy\.bytes\) entropy\.bytes\.fill\(0\);\s*return entropy\.ok;/);
});
