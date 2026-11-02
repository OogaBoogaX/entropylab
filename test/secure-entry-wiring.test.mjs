// Secure entry P1b wiring: the session switch, its lifecycle hooks and the
// global-sync guards. The module itself is tested in secure-entry.test.mjs;
// this file pins the app-side plumbing.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadAppFunctions } from "./app-slice-harness.mjs";
import { createSecureSession, seedEntry, seedSet, seedIndices, keyEntry, sessionSet, sessionDeleteKey, sessionWipe, sessionGet, SUPPORTED_METHODS } from "../src/js/secure-entry.js";
import { seedFromIndices, entropyFromWordIndices } from "../src/js/bip39.js";
import { wordlist } from "../src/js/bip39-english.js";
import { createBase58check, hex } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";
import { base58checkDecode } from "../src/js/base58.js";
import { sha256 as wasmSha256 } from "../src/js/hashes.js";

const root = dirname(fileURLToPath(import.meta.url));
const app = readFileSync(join(root, "..", "src/js/app.js"), "utf8");

// app.js binds the secure-entry helpers in one import statement, and the slice
// harness emits that whole statement as soon as any one of its names is
// reached. Stub every name it binds, or the emitted import collides with the
// stub declaration of the same name.
const secureEntryStubs = {
  createSecureSession: () => ({ marker: "fresh" }),
  sessionWipe: () => {},
  sessionDeleteKey: () => {},
  keyEntry,
  hodlSecureSupported: {},
};

// The real session and seed-entry helpers, for the tests that drive the
// app-side plumbing against a live session. Every name app.js binds from
// secure-entry.js is here, so the harness never emits that import statement.
const realSecureEntryStubs = {
  createSecureSession,
  sessionWipe,
  sessionDeleteKey,
  sessionGet,
  sessionSet,
  seedEntry,
  seedIndices,
  keyEntry,
  hodlSecureSupported: {},
};

test("hodlSecureEntryAvailable is false without preview or a supported method", async () => {
  const off = await loadAppFunctions(["hodlSecureEntryAvailable"], {
    stubs: { ...secureEntryStubs, PREVIEW: false, hodlSecureSupported: { seed: false, key: false } },
  });
  assert.equal(off.hodlSecureEntryAvailable(), false);

  const noMethods = await loadAppFunctions(["hodlSecureEntryAvailable"], {
    stubs: { ...secureEntryStubs, PREVIEW: true, hodlSecureSupported: { seed: false, key: false } },
  });
  assert.equal(noMethods.hodlSecureEntryAvailable(), false);

  const oneMethod = await loadAppFunctions(["hodlSecureEntryAvailable"], {
    stubs: { ...secureEntryStubs, PREVIEW: true, hodlSecureSupported: { seed: true, key: false } },
  });
  assert.equal(oneMethod.hodlSecureEntryAvailable(), true);
});

test("hodlSecureEntryEnd turns the switch off and wipes the session", async () => {
  const wiped = [];
  const session = { marker: "session" };
  let hashedCalls = 0;
  const mod = await loadAppFunctions(["hodlSecureEntryEnd", "hodlGlobalSyncFromCurrentInput"], {
    stubs: {
      ...secureEntryStubs,
      sessionWipe: (s) => { wiped.push(s); },
      hodlRenderGlobalSyncControl: () => {},
      hodlRenderSecureEntryControl: () => {},
      hodlGlobalSyncIsHashedMode: () => { hashedCalls++; return true; },
      hodlGlobalSyncCurrentValue: () => "",
      hodlGlobalSyncCurrentBits: () => null,
      hodlApplyGlobalSync: () => { throw new Error("should not apply"); },
      hodlNewKeyState: () => ({}),
      hodlSecureEntryHasData: () => false,
      hodlSecureKeyOf: () => null,
    },
    settable: ["hodlSecureEntryOn", "hodlSecureSession", "hodlKeys", "hodlActiveKey"],
  });
  mod.__set.hodlSecureSession(session);
  mod.__set.hodlSecureEntryOn(true);
  mod.__set.hodlKeys([{ globalSync: true }]);
  mod.__set.hodlActiveKey(0);
  mod.hodlSecureEntryEnd();
  assert.equal(wiped.length, 1);
  assert.equal(wiped[0], session);
  // The switch is off: the sync path no longer short-circuits.
  mod.hodlGlobalSyncFromCurrentInput();
  assert.equal(hashedCalls, 1);
});

test("hodlSecureEntryEnd survives a throwing wipe", async () => {
  let hashedCalls = 0;
  const mod = await loadAppFunctions(["hodlSecureEntryEnd", "hodlGlobalSyncFromCurrentInput"], {
    stubs: {
      ...secureEntryStubs,
      sessionWipe: () => { throw new Error("wipe failed"); },
      hodlRenderGlobalSyncControl: () => {},
      hodlRenderSecureEntryControl: () => {},
      hodlGlobalSyncIsHashedMode: () => { hashedCalls++; return true; },
      hodlGlobalSyncCurrentValue: () => "",
      hodlGlobalSyncCurrentBits: () => null,
      hodlApplyGlobalSync: () => { throw new Error("should not apply"); },
      hodlNewKeyState: () => ({}),
      hodlSecureEntryHasData: () => false,
      hodlSecureKeyOf: () => null,
    },
    settable: ["hodlSecureEntryOn", "hodlSecureSession", "hodlKeys", "hodlActiveKey"],
  });
  mod.__set.hodlSecureSession({});
  mod.__set.hodlSecureEntryOn(true);
  mod.__set.hodlKeys([{ globalSync: true }]);
  mod.__set.hodlActiveKey(0);
  assert.doesNotThrow(() => mod.hodlSecureEntryEnd());
  mod.hodlGlobalSyncFromCurrentInput();
  assert.equal(hashedCalls, 1);
});

test("hodlSecureEntryDropKey deletes only a real key id", async () => {
  const calls = [];
  const session = { marker: "session" };
  const mod = await loadAppFunctions(["hodlSecureEntryDropKey"], {
    stubs: {
      ...secureEntryStubs,
      sessionDeleteKey: (s, id) => { calls.push([s, id]); },
    },
    settable: ["hodlSecureSession"],
  });
  mod.__set.hodlSecureSession(session);
  mod.hodlSecureEntryDropKey(7);
  assert.deepEqual(calls, [[session, 7]]);
  mod.hodlSecureEntryDropKey(null);
  mod.hodlSecureEntryDropKey(undefined);
  assert.equal(calls.length, 1);
});

test("hodlSecureEntryDropKey survives a throwing delete", async () => {
  const mod = await loadAppFunctions(["hodlSecureEntryDropKey"], {
    stubs: {
      ...secureEntryStubs,
      sessionDeleteKey: () => { throw new Error("delete failed"); },
    },
    settable: ["hodlSecureSession"],
  });
  mod.__set.hodlSecureSession({});
  assert.doesNotThrow(() => mod.hodlSecureEntryDropKey(7));
});

test("hodlApplyGlobalSync is off while secure entry is on", async () => {
  const mod = await loadAppFunctions(["hodlApplyGlobalSync"], {
    stubs: {
      ...secureEntryStubs,
      hodlGlobalSyncSourceId: () => "seed:words",
      hodlSeedConfig: () => ({ bits: 128, words: 12, partialWords: 11 }),
      hodlGlobalSyncCurrentValue: () => "",
      hodlPrivateKeyValues: () => ({}),
      hodlGlobalSyncMnemonic: () => null,
      hodlGlobalSyncWordIndices: () => [],
      hodlBip39Wordlist: [],
      hodlEntropyFormats: {},
      hodlGlobalSyncNumberValue: () => "",
      hodlBip39WordIndex: new Map(),
      hodlGlobalSyncDPlusValue: () => "",
      hodlGlobalSyncDirectCardsValue: () => "",
      hodlGlobalSyncBitBoxValue: () => "",
      hodlBytesFromBits: () => new Uint8Array(),
      hodlAssertPrivateKey: () => {},
      hodlParseDerivationIndexText: () => ({ value: 0 }),
      hodlNetworkFromCoinType: () => "mainnet",
      hodlEncodeWif: () => "",
      hodlGlobalSyncSourceBits: () => "",
      hodlNewKeyState: () => ({}),
    },
    settable: ["hodlSecureEntryOn", "hodlKeys", "hodlActiveKey"],
  });
  const fields = {};
  mod.__set.hodlSecureEntryOn(true);
  mod.__set.hodlKeys([{ fields }]);
  mod.__set.hodlActiveKey(0);
  assert.equal(mod.hodlApplyGlobalSync("1010"), false);
  assert.deepEqual(fields, {});
});

test("hodlGlobalSyncFromCurrentInput is off while secure entry is on", async () => {
  let renderCalls = 0, applyCalls = 0;
  // A real bit count, so the only thing that can stop the apply is the switch.
  const stubs = {
    ...secureEntryStubs,
    hodlRenderGlobalSyncControl: () => { renderCalls++; },
    hodlApplyGlobalSync: () => { applyCalls++; },
    hodlGlobalSyncIsHashedMode: () => false,
    hodlGlobalSyncCurrentValue: () => "",
    hodlGlobalSyncCurrentBits: () => 128,
    hodlNewKeyState: () => ({}),
  };
  const mod = await loadAppFunctions(["hodlGlobalSyncFromCurrentInput"], {
    stubs,
    settable: ["hodlSecureEntryOn", "hodlKeys", "hodlActiveKey"],
  });
  mod.__set.hodlSecureEntryOn(true);
  mod.__set.hodlKeys([{ globalSync: true }]);
  mod.__set.hodlActiveKey(0);
  assert.equal(mod.hodlGlobalSyncFromCurrentInput(), false);
  assert.equal(renderCalls, 1);
  assert.equal(applyCalls, 0);

  // Control: the same input with the switch off applies the sync once, so the
  // guard above is what stopped it.
  const control = await loadAppFunctions(["hodlGlobalSyncFromCurrentInput"], {
    stubs,
    settable: ["hodlSecureEntryOn", "hodlKeys", "hodlActiveKey"],
  });
  control.__set.hodlSecureEntryOn(false);
  control.__set.hodlKeys([{ globalSync: true }]);
  control.__set.hodlActiveKey(0);
  assert.equal(control.hodlGlobalSyncFromCurrentInput(), true);
  assert.equal(applyCalls, 1);
});

test("the real secure session deletes one key and wipes the rest", () => {
  const session = createSecureSession();
  const seed = seedEntry(12);
  seedSet(seed, 0, 42);
  seedSet(seed, 1, 7);
  const indices = seed.indices;
  sessionSet(session, "1", "seed", seed);

  const key = keyEntry();
  sessionSet(session, "2", "key", key);

  sessionDeleteKey(session, 1);
  assert.equal(sessionGet(session, "1", "seed"), null);
  assert.deepEqual([...indices], new Array(12).fill(0));
  assert.equal(sessionGet(session, "2", "key"), key);
  assert.equal(key.wiped, false);

  sessionWipe(session);
  assert.equal(sessionGet(session, "2", "key"), null);
  assert.equal(key.wiped, true);
});

test("the wiring hooks are in the right order", () => {
  const clearStart = app.indexOf("let clearSecretFields = () => {");
  assert.ok(clearStart >= 0);
  const clearEnd = app.indexOf("hodlSyncWorkspaceCounts();", clearStart);
  assert.ok(clearEnd >= 0);
  const endCall = app.indexOf("hodlSecureEntryEnd();", clearStart);
  assert.ok(endCall >= 0 && endCall < clearEnd);

  const detachStart = app.indexOf("function hodlKeyManagerDetachFromStation(state) {");
  assert.ok(detachStart >= 0);
  const detachRelease = app.indexOf("hodlReleaseKeyConsumers(state.id);", detachStart);
  const detachDrop = app.indexOf("hodlSecureEntryDropKey(hodlSecureKeyOf(state));", detachStart);
  assert.ok(detachRelease >= 0 && detachDrop > detachRelease);

  const deleteStart = app.indexOf("let deletedIndex = hodlActiveKey, deletedState = state;");
  assert.ok(deleteStart >= 0);
  const deleteRelease = app.indexOf("hodlReleaseKeyConsumers(deletedState.id);", deleteStart);
  const deleteDrop = app.indexOf("hodlSecureEntryDropKey(hodlSecureKeyOf(deletedState));", deleteStart);
  assert.ok(deleteRelease >= 0 && deleteDrop > deleteRelease);

  const wipeStart = app.indexOf("function hodlWipeActiveKey() {");
  assert.ok(wipeStart >= 0);
  const wipeRelease = app.indexOf("hodlReleaseKeyConsumers(state.id);", wipeStart);
  const wipeDrop = app.indexOf("hodlSecureEntryDropKey(hodlSecureKeyOf(state));", wipeStart);
  assert.ok(wipeRelease >= 0 && wipeDrop > wipeRelease);

  const calcStart = app.indexOf("async function hodlCalculateKey(progress, action = \"derive\", options = {}) {");
  assert.ok(calcStart >= 0);
  const seedBranch = app.indexOf("} else if (hodlKeyMode === \"seed\") {", calcStart);
  assert.ok(seedBranch >= 0);
  const secureActive = app.indexOf("hodlSecureSeedApplies()", seedBranch);
  const selectedSeed = app.indexOf("hodlSelectedSeedInput(", seedBranch);
  assert.ok(secureActive >= 0 && selectedSeed > secureActive);

  for (const name of ["async function hodlKeyManagerDownload() {", "function hodlJournalCollectBackup() {"]) {
    const start = app.indexOf(name);
    assert.ok(start >= 0, name);
    const refusal = app.indexOf("hodlSecureEntryBackupRefusal()", start);
    const serialize = app.indexOf("serializeKeyVault(", start);
    assert.ok(refusal > start && serialize > refusal, name);
  }

  for (const line of app.split("\n")) {
    if (line.includes("hodlSecureEntryOn")) assert.doesNotMatch(line, /setItem/);
  }
});

test("hodlMnemonicWalletWithProgress derives from secure indices", async () => {
  const recorded = {};
  let validateCalls = 0;
  const mod = await loadAppFunctions(["hodlMnemonicWalletWithProgress"], {
    stubs: {
      hodlRootWalletWithProgress: async (root, network, count, material) => {
        recorded.entropy = Uint8Array.from(material.entropy);
        recorded.seed = Uint8Array.from(material.seed);
        return { ok: true };
      },
      hodlHDKey: { fromMasterSeed: () => ({ wipePrivateData() {} }) },
      hodlActiveDerivation: null,
      hodlSeedFromIndices: seedFromIndices,
      hodlEntropyFromWordIndices: entropyFromWordIndices,
      hodlValidateMnemonic: () => { validateCalls++; throw new Error("text path used"); },
      hodlWordIndices: () => { throw new Error("text path used"); },
      hodlCoinTypeFromNetwork: () => 0,
      hodlDefaultHardening: () => ({}),
      hodlError: (key) => new Error(key),
    },
  });
  const abandon = wordlist.indexOf("abandon"), about = wordlist.indexOf("about");
  const indices = new Uint16Array([abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, about]);
  await mod.hodlMnemonicWalletWithProgress({ indices }, "TREZOR", "mainnet", 1, undefined, 0, 0, undefined, 84, 0, {}, 0, 2, null);
  assert.equal(Buffer.from(recorded.seed).toString("hex"), "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04");
  assert.deepEqual([...recorded.entropy], new Array(16).fill(0));
  assert.deepEqual([...indices], new Array(12).fill(0));
  assert.equal(validateCalls, 0);
});

test("hodlMnemonicWalletWithProgress rejects bad secure indices and zeroes them", async () => {
  let seedCalls = 0;
  const mod = await loadAppFunctions(["hodlMnemonicWalletWithProgress"], {
    stubs: {
      hodlRootWalletWithProgress: async () => { throw new Error("should not derive"); },
      hodlHDKey: { fromMasterSeed: () => ({ wipePrivateData() {} }) },
      hodlActiveDerivation: null,
      hodlSeedFromIndices: (...args) => { seedCalls++; return seedFromIndices(...args); },
      hodlEntropyFromWordIndices: entropyFromWordIndices,
      hodlValidateMnemonic: () => { throw new Error("text path used"); },
      hodlWordIndices: () => { throw new Error("text path used"); },
      hodlCoinTypeFromNetwork: () => 0,
      hodlDefaultHardening: () => ({}),
      hodlError: (key) => new Error(key),
    },
  });
  const bad = new Uint16Array(12).fill(wordlist.indexOf("ability"));
  assert.throws(() => entropyFromWordIndices(Uint16Array.from(bad)));
  await assert.rejects(
    () => mod.hodlMnemonicWalletWithProgress({ indices: bad }, "TREZOR", "mainnet", 1, undefined, 0, 0, undefined, 84, 0, {}, 0, 2, null),
    /Invalid seed phrase/,
  );
  assert.equal(seedCalls, 0);
  assert.deepEqual([...bad], new Array(12).fill(0));

  const short = new Uint16Array(11).fill(wordlist.indexOf("able"));
  await assert.rejects(
    () => mod.hodlMnemonicWalletWithProgress({ indices: short }, "TREZOR", "mainnet", 1, undefined, 0, 0, undefined, 84, 0, {}, 0, 2, null),
    /Invalid seed phrase/,
  );
  assert.equal(seedCalls, 0);
  assert.deepEqual([...short], new Array(11).fill(0));
});

test("hodlSecureSeedEntry applies only to seed words and creates on demand", async () => {
  const session = createSecureSession();
  const load = (overrides) => loadAppFunctions(["hodlSecureSeedEntry", "hodlSecureKeyOf"], {
    stubs: { ...realSecureEntryStubs, hodlKeyMode: "seed", hodlSeedMethod: "words", hodlTargetWordCount: 12, ...overrides },
    settable: ["hodlSecureEntryOn", "hodlKeys", "hodlActiveKey", "hodlSecureSession"],
  });
  const prepared = { key: null };
  const prepare = (mod) => {
    prepared.key = { id: 1 };
    mod.__set.hodlSecureSession(session);
    mod.__set.hodlKeys([prepared.key]);
    mod.__set.hodlActiveKey(0);
  };

  const off = await load({});
  prepare(off);
  off.__set.hodlSecureEntryOn(false);
  assert.equal(off.hodlSecureSeedEntry(), null);

  const dice = await load({ hodlKeyMode: "dice" });
  prepare(dice);
  dice.__set.hodlSecureEntryOn(true);
  assert.equal(dice.hodlSecureSeedEntry(), null);

  const numbers = await load({ hodlSeedMethod: "numbers" });
  prepare(numbers);
  numbers.__set.hodlSecureEntryOn(true);
  assert.equal(numbers.hodlSecureSeedEntry(), null);

  const on = await load({});
  prepare(on);
  on.__set.hodlSecureEntryOn(true);
  const entry = on.hodlSecureSeedEntry(true);
  assert.equal(entry.length, 12);
  assert.equal(entry.count, 0);
  const owner = on.hodlSecureKeyOf(prepared.key);
  assert.equal(typeof owner, "string");
  assert.equal(sessionGet(session, owner, "seed"), entry);

  // An empty entry of another length is replaced on create.
  const empty24 = seedEntry(24);
  sessionSet(session, owner, "seed", empty24);
  const replaced = on.hodlSecureSeedEntry(true);
  assert.notEqual(replaced, empty24);
  assert.equal(replaced.length, 12);
  assert.equal(sessionGet(session, owner, "seed"), replaced);

  // An entry that already holds a word is kept.
  const held = seedEntry(24);
  seedSet(held, 0, 0);
  sessionSet(session, owner, "seed", held);
  assert.equal(on.hodlSecureSeedEntry(true), held);
  assert.equal(sessionGet(session, owner, "seed"), held);

  // A copy of the key state (the Journal filling the editor) keeps the id but
  // never the words.
  const copy = { ...prepared.key };
  on.__set.hodlKeys([copy]);
  assert.equal(on.hodlSecureKeyOf(copy), null);
  assert.equal(on.hodlSecureSeedEntry(), null);
});

test("hodlSecureSeedIndices and hodlSecureSeedReady gate on a complete valid seed", async () => {
  const session = createSecureSession();
  const mod = await loadAppFunctions(["hodlSecureSeedEntry", "hodlSecureSeedIndices", "hodlSecureSeedReady"], {
    stubs: { ...realSecureEntryStubs, hodlKeyMode: "seed", hodlSeedMethod: "words", hodlTargetWordCount: 12 },
    settable: ["hodlSecureEntryOn", "hodlKeys", "hodlActiveKey", "hodlSecureSession"],
  });
  mod.__set.hodlSecureSession(session);
  mod.__set.hodlKeys([{ id: 1 }]);
  mod.__set.hodlActiveKey(0);
  mod.__set.hodlSecureEntryOn(true);

  assert.equal(mod.hodlSecureSeedIndices(), null);
  assert.equal(mod.hodlSecureSeedReady(), false);

  const entry = mod.hodlSecureSeedEntry(true);
  const abandon = wordlist.indexOf("abandon"), about = wordlist.indexOf("about");
  for (let i = 0; i < 11; i++) seedSet(entry, i, abandon);
  assert.equal(mod.hodlSecureSeedIndices(), null);
  assert.equal(mod.hodlSecureSeedReady(), false);

  seedSet(entry, 11, abandon);
  assert.equal(mod.hodlSecureSeedIndices(), null);
  assert.equal(mod.hodlSecureSeedReady(), false);

  seedSet(entry, 11, about);
  const indices = mod.hodlSecureSeedIndices();
  assert.ok(indices instanceof Uint16Array);
  assert.deepEqual([...indices], [...entry.indices]);
  indices.fill(0);
  assert.equal(entry.indices[0], abandon);
  assert.equal(entry.indices[11], about);
  assert.equal(mod.hodlSecureSeedReady(), true);
});

test("hodlFingerprintSource uses secure indices and never reads the text field", async () => {
  const session = createSecureSession();
  let selectedCalls = 0;
  const mod = await loadAppFunctions(["hodlSecureSeedEntry", "hodlFingerprintSource"], {
    stubs: {
      ...realSecureEntryStubs,
      hodlKeyMode: "seed",
      hodlSeedMethod: "words",
      hodlTargetWordCount: 12,
      hodlDiceMethod: "coldcard",
      hodlPickedLastWord: "",
      hodlDPlusRolls: () => { throw new Error("dice path used"); },
      hodlBitBoxRolls: () => { throw new Error("dice path used"); },
      hodlAnalyzeDiceInput: () => { throw new Error("dice path used"); },
      hodlDiceEntropy: () => { throw new Error("dice path used"); },
      hodlSelectedCardsEntropy: () => { throw new Error("cards path used"); },
      hodlSelectedEntropy: () => { throw new Error("hex path used"); },
      hodlSelectedSeedInput: () => { selectedCalls++; throw new Error("text path used"); },
      hodlValidateTargetMnemonic: () => { throw new Error("text path used"); },
      hodlLooksExtendedKey: () => { throw new Error("text path used"); },
      hodlWordIndices: () => { throw new Error("text path used"); },
      hodlEntropyFromWordIndices: entropyFromWordIndices,
    },
    settable: ["hodlSecureEntryOn", "hodlKeys", "hodlActiveKey", "hodlSecureSession"],
  });
  mod.__set.hodlSecureSession(session);
  mod.__set.hodlKeys([{ id: 1 }]);
  mod.__set.hodlActiveKey(0);
  mod.__set.hodlSecureEntryOn(true);

  const entry = mod.hodlSecureSeedEntry(true);
  const abandon = wordlist.indexOf("abandon"), about = wordlist.indexOf("about");
  for (let i = 0; i < 11; i++) seedSet(entry, i, abandon);
  assert.equal(mod.hodlFingerprintSource(), null);

  seedSet(entry, 11, about);
  const source = mod.hodlFingerprintSource();
  assert.deepEqual([...source.indices], [...entry.indices]);
  assert.equal(selectedCalls, 0);
});

test("hodlSecureSeedApplies keeps text that arrived while the switch was on", async () => {
  const session = createSecureSession();
  let seedField = null;
  const mod = await loadAppFunctions(["hodlSecureSeedApplies", "hodlSecureKeyOf"], {
    stubs: {
      ...realSecureEntryStubs,
      hodlKeyMode: "seed", hodlSeedMethod: "words", hodlTargetWordCount: 12,
      document: { getElementById: (id) => (id === "seed" ? seedField : null) },
    },
    settable: ["hodlSecureEntryOn", "hodlKeys", "hodlActiveKey", "hodlSecureSession"],
  });
  const key = { id: 1, fields: { seed: "" } };
  mod.__set.hodlSecureSession(session);
  mod.__set.hodlKeys([key]);
  mod.__set.hodlActiveKey(0);

  mod.__set.hodlSecureEntryOn(false);
  assert.equal(mod.hodlSecureSeedApplies(), false);
  mod.__set.hodlSecureEntryOn(true);
  // Nothing typed and no secure words: the picker's key.
  assert.equal(mod.hodlSecureSeedApplies(), true);
  // A seed that came in as text (an import) keeps the text path.
  key.fields.seed = "abandon ability";
  assert.equal(mod.hodlSecureSeedApplies(), false);
  key.fields.seed = "";
  seedField = { value: "abandon" };
  assert.equal(mod.hodlSecureSeedApplies(), false);
  // Secure words decide, whatever text is around.
  const entry = seedEntry(12);
  seedSet(entry, 0, 1);
  sessionSet(session, mod.hodlSecureKeyOf(key, true), "seed", entry);
  assert.equal(mod.hodlSecureSeedApplies(), true);
  // GLM/Kimi: the Journal fills the editor with a copy that keeps its id; the
  // copy's imported text is what derives, never the original's secure words.
  const filled = { ...key, fields: { seed: "zoo zoo" } };
  mod.__set.hodlKeys([filled]);
  seedField = { value: "zoo zoo" };
  assert.equal(mod.hodlSecureSeedApplies(), false);
  // The original (a parked draft) still owns its words.
  assert.equal(sessionGet(session, mod.hodlSecureKeyOf(key), "seed"), entry);
});

test("both Journal backups refuse while a key holds secure words", async () => {
  const session = createSecureSession();
  const mod = await loadAppFunctions(["hodlSecureEntryBackupRefusal", "hodlSecureKeyOf"], {
    stubs: { ...realSecureEntryStubs, hodlTText: (text) => text },
    settable: ["hodlKeys", "hodlSecureSession"],
  });
  const second = { id: 2 };
  mod.__set.hodlSecureSession(session);
  mod.__set.hodlKeys([{ id: 1 }, second]);
  assert.equal(mod.hodlSecureEntryBackupRefusal(), null);
  const entry = seedEntry(12);
  seedSet(entry, 0, 1);
  sessionSet(session, mod.hodlSecureKeyOf(second, true), "seed", entry);
  const refusal = mod.hodlSecureEntryBackupRefusal();
  assert.ok(refusal instanceof Error);
  assert.ok(refusal.message.length > 0);

  // A session read that fails counts as holding words.
  const failing = await loadAppFunctions(["hodlSecureEntryBackupRefusal", "hodlSecureKeyOf"], {
    stubs: { ...realSecureEntryStubs, hodlTText: (text) => text, sessionGet: () => { throw new Error("broken"); } },
    settable: ["hodlKeys"],
  });
  const broken = { id: 1 };
  failing.hodlSecureKeyOf(broken, true);
  failing.__set.hodlKeys([broken]);
  assert.ok(failing.hodlSecureEntryBackupRefusal() instanceof Error);
});

test("a cleared key refuses backup, and held words win", async () => {
  const session = createSecureSession();
  const tTextCalls = [];
  const mod = await loadAppFunctions(["hodlSecureEntryBackupRefusal", "hodlSecureKeyOf"], {
    stubs: { ...realSecureEntryStubs, hodlTText: (text) => { tTextCalls.push(text); return text; } },
    settable: ["hodlKeys", "hodlSecureSession"],
  });
  mod.__set.hodlSecureSession(session);
  const cleared = { id: 1, secureCleared: true };
  mod.__set.hodlKeys([cleared]);
  const refusal = mod.hodlSecureEntryBackupRefusal();
  assert.ok(refusal instanceof Error);
  const clearedText = tTextCalls.at(-1);
  // The cleared-key refusal must be localized, or the comparison below proves nothing (MiniMax).
  assert.equal(typeof clearedText, "string");

  const held = { id: 2 };
  const entry = seedEntry(12);
  seedSet(entry, 0, 1);
  sessionSet(session, mod.hodlSecureKeyOf(held, true), "seed", entry);
  mod.__set.hodlKeys([cleared, held]);
  tTextCalls.length = 0;
  const heldRefusal = mod.hodlSecureEntryBackupRefusal();
  assert.ok(heldRefusal instanceof Error);
  // Held words win: the refusal is the held-words one, not the cleared-key one
  // (compared by identity, never by wording: AGENTS.md).
  assert.equal(tTextCalls.length, 1);
  assert.notEqual(tTextCalls[0], clearedText);
  assert.equal(heldRefusal.message, tTextCalls[0]);
});

test("hodlSecureEntryHasData sees any securely entered word", async () => {
  const session = createSecureSession();
  const mod = await loadAppFunctions(["hodlSecureEntryHasData"], {
    stubs: realSecureEntryStubs,
    settable: ["hodlSecureSession"],
  });
  mod.__set.hodlSecureSession(session);
  assert.equal(mod.hodlSecureEntryHasData(null), false);
  assert.equal(mod.hodlSecureEntryHasData(1), false);

  const entry = seedEntry(12);
  sessionSet(session, 1, "seed", entry);
  assert.equal(mod.hodlSecureEntryHasData(1), false);

  seedSet(entry, 0, 0);
  assert.equal(mod.hodlSecureEntryHasData(1), true);

  sessionDeleteKey(session, 1);
  assert.equal(mod.hodlSecureEntryHasData(1), false);
});

test("hodlKeyStateNeedsClear sees securely entered words", async () => {
  const session = createSecureSession();
  const mod = await loadAppFunctions(["hodlKeyStateNeedsClear", "hodlSecureKeyOf"], {
    stubs: {
      ...realSecureEntryStubs,
      hodlPrivateKeyValues: () => ({ wif: "" }),
      hodlPrivateKeyKinds: ["wif"],
      hodlNormalizePrivateKeyKind: () => "wif",
    },
    settable: ["hodlSecureSession"],
  });
  mod.__set.hodlSecureSession(session);
  const state = { id: 1, fields: {} };
  assert.equal(mod.hodlKeyStateNeedsClear(state), false);

  const entry = seedEntry(12);
  seedSet(entry, 0, 0);
  sessionSet(session, mod.hodlSecureKeyOf(state, true), "seed", entry);
  assert.equal(mod.hodlKeyStateNeedsClear(state), true);
  // Another state with the same id holds nothing.
  assert.equal(mod.hodlKeyStateNeedsClear({ ...state }), false);
});

test("detach refuses a key with securely entered words", async () => {
  const session = createSecureSession();
  const state = { id: 1, number: 1, fields: {} };
  const keys = [state];
  const statusCalls = [];
  let captureCalls = 0, releaseCalls = 0;
  const mod = await loadAppFunctions(["hodlKeyManagerDetachFromStation", "hodlSecureKeyOf"], {
    stubs: {
      ...realSecureEntryStubs,
      keyVaultIdentity: () => "identity",
      hodlCaptureKey: () => { captureCalls++; },
      hodlKeyManagerHasInputs: () => false,
      hodlKeyManagerCapacityError: () => "",
      hodlKeyManagerStatus: (...args) => { statusCalls.push(args); },
      hodlReleaseKeyConsumers: () => { releaseCalls++; },
      hodlKeyManagerPending: [],
      hodlRenderKeyTabs: () => {},
      hodlRestoreKey: () => {},
      hodlJournalLog: () => {},
      hodlElement: () => ({ children: [], focus() {} }),
      hodlTText: (text) => text,
    },
    settable: ["hodlKeys", "hodlActiveKey", "hodlSecureSession"],
  });
  mod.__set.hodlSecureSession(session);
  mod.__set.hodlKeys(keys);
  mod.__set.hodlActiveKey(0);

  const entry = seedEntry(12);
  seedSet(entry, 0, 0);
  const owner = mod.hodlSecureKeyOf(state, true);
  sessionSet(session, owner, "seed", entry);

  mod.hodlKeyManagerDetachFromStation(state);
  assert.equal(statusCalls.length, 1);
  assert.equal(statusCalls[0][1], true);
  assert.equal(captureCalls, 0);
  assert.equal(releaseCalls, 0);
  assert.deepEqual(keys, [state]);
  assert.equal(sessionGet(session, owner, "seed"), entry);
  assert.equal(entry.count, 1);
});

test("detach refuses a key whose words were cleared", async () => {
  const session = createSecureSession();
  const state = { id: 1, number: 1, fields: {}, secureCleared: true };
  const keys = [state];
  const statusCalls = [];
  let captureCalls = 0, releaseCalls = 0;
  const mod = await loadAppFunctions(["hodlKeyManagerDetachFromStation", "hodlSecureKeyOf"], {
    stubs: {
      ...realSecureEntryStubs,
      keyVaultIdentity: () => "identity",
      hodlCaptureKey: () => { captureCalls++; },
      hodlKeyManagerHasInputs: () => false,
      hodlKeyManagerCapacityError: () => "",
      hodlKeyManagerStatus: (...args) => { statusCalls.push(args); },
      hodlReleaseKeyConsumers: () => { releaseCalls++; },
      hodlKeyManagerPending: [],
      hodlRenderKeyTabs: () => {},
      hodlRestoreKey: () => {},
      hodlJournalLog: () => {},
      hodlElement: () => ({ children: [], focus() {} }),
      hodlTText: (text) => text,
    },
    settable: ["hodlKeys", "hodlActiveKey", "hodlSecureSession"],
  });
  mod.__set.hodlSecureSession(session);
  mod.__set.hodlKeys(keys);
  mod.__set.hodlActiveKey(0);
  mod.hodlKeyManagerDetachFromStation(state);
  assert.equal(statusCalls.length, 1);
  assert.equal(statusCalls[0][1], true);
  assert.equal(captureCalls, 0);
  assert.equal(releaseCalls, 0);
  assert.deepEqual(keys, [state]);
});

test("a key derived from secure words is marked, and Journal refuses it", async () => {
  const session = createSecureSession();
  const mod = await loadAppFunctions(["hodlCloneDerivedKey", "hodlSecureEntryHeld", "hodlSecureEntryBackupRefusal", "hodlSecureKeyOf"], {
    stubs: { ...realSecureEntryStubs, hodlTText: (text) => text, hodlStoredPassphraseBytes: (value) => value, hodlNewKeyState: () => ({ id: 9, fields: {} }) },
    settable: ["hodlKeys", "hodlSecureSession"],
  });
  mod.__set.hodlSecureSession(session);
  const lab = { id: 0, isLab: true, mode: "seed", seedMethod: "words", fields: { seed: "" }, result: { masterFingerprint: "abcd1234" } };
  const entry = seedEntry(12);
  seedSet(entry, 0, 3);
  sessionSet(session, mod.hodlSecureKeyOf(lab, true), "seed", entry);

  const derived = mod.hodlCloneDerivedKey(lab);
  assert.equal(derived.secureSource, true);
  assert.equal(mod.hodlSecureKeyOf(derived), null, "the derived key holds no copy of the words");
  assert.equal(mod.hodlSecureEntryHeld(derived), true);
  // A plain editor's key is not marked.
  assert.equal(mod.hodlCloneDerivedKey({ id: 0, isLab: true, fields: { seed: "abandon" } }).secureSource, false);
  // The backups refuse while the derived key is in the station, even with the
  // editor's words gone.
  sessionDeleteKey(session, mod.hodlSecureKeyOf(lab));
  mod.__set.hodlKeys([{ id: 0, isLab: true, fields: {} }, derived]);
  assert.ok(mod.hodlSecureEntryBackupRefusal() instanceof Error);
  mod.__set.hodlKeys([{ id: 0, isLab: true, fields: {} }]);
  assert.equal(mod.hodlSecureEntryBackupRefusal(), null);
});

test("deleting a key with Journal open goes through the detach refusal", async () => {
  // With Journal open the delete is a detach, which refuses a key holding
  // secure words (the test above); the delete itself drops and splices nothing.
  const state = { id: 1, number: 1, fields: {} };
  const keys = [state];
  const detached = [];
  let dropCalls = 0;
  const mod = await loadAppFunctions(["hodlDeleteActiveKey"], {
    stubs: {
      ...realSecureEntryStubs,
      hodlSyncKeyDeleteButton: () => {},
      hodlSyncKeyAddButton: () => {},
      hodlInvalidateDerivation: () => {},
      hodlJournalUnlocked: () => true,
      hodlKeyManagerDetachFromStation: (target) => { detached.push(target); },
      hodlSecureEntryDropKey: () => { dropCalls++; },
      hodlZeroKeyPassphrase: () => { throw new Error("delete path used"); },
      hodlReleaseKeyConsumers: () => { throw new Error("delete path used"); },
      hodlRenderKeyTabs: () => {},
      hodlRestoreKey: () => {},
      hodlDisposeDroppedWallets: () => {},
      hodlJournalLog: () => {},
      hodlElement: () => null,
      hodlNewLabState: () => ({ isLab: true }),
      hodlNextKeyNumber: 1,
    },
    settable: ["hodlKeys", "hodlActiveKey"],
  });
  mod.__set.hodlKeys(keys);
  mod.__set.hodlActiveKey(0);
  mod.hodlDeleteActiveKey();
  assert.deepEqual(detached, [state]);
  assert.equal(dropCalls, 0);
  assert.deepEqual(keys, [state]);
});
test("discarding a key's inputs drops only that state's secure words", async () => {
  const session = createSecureSession();
  const mod = await loadAppFunctions(["hodlKeyManagerDiscardInputs", "hodlSecureKeyOf"], {
    stubs: { ...realSecureEntryStubs, hodlZeroKeyPassphrase: () => {}, hodlWipeUnsharedWalletRows: () => {} },
    settable: ["hodlSecureSession"],
  });
  mod.__set.hodlSecureSession(session);
  const draft = { id: 0, fields: { seed: "" } }, temporary = { ...draft };
  const entry = seedEntry(12);
  seedSet(entry, 0, 9);
  const owner = mod.hodlSecureKeyOf(draft, true);
  sessionSet(session, owner, "seed", entry);
  // The batch discards its temporary copy: the parked draft keeps its words.
  mod.hodlKeyManagerDiscardInputs(temporary);
  assert.equal(sessionGet(session, owner, "seed"), entry);
  assert.equal(entry.indices[0], 9);
  // Discarding the draft itself takes its words.
  mod.hodlKeyManagerDiscardInputs(draft);
  assert.equal(sessionGet(session, owner, "seed"), null);
  assert.equal(entry.indices[0], 0);
});

// Secure entry P3b-1: derive a private key from the key vault's bytes.
const b58 = createBase58check(sha256);
const wifOf = (key, network, compressed) => b58.encode(Uint8Array.from([network === "mainnet" ? 0x80 : 0xef, ...key, ...(compressed ? [1] : [])]));
const WIKI_KEY = hex.decode("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d");
const WIKI_WIF = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
const MINI = "S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy";
const changedWif = WIKI_WIF.slice(0, 10) + (WIKI_WIF[10] === "1" ? "2" : "1") + WIKI_WIF.slice(11);
const changedMini = MINI.slice(0, 10) + (MINI[10] === "1" ? "2" : "1") + MINI.slice(11);
const keyCorpus = [
  WIKI_WIF,
  wifOf(WIKI_KEY, "mainnet", true),
  wifOf(WIKI_KEY, "testnet", true),
  MINI,
  hex.encode(WIKI_KEY),
  hex.encode(WIKI_KEY).toUpperCase(),
  "0x" + hex.encode(WIKI_KEY),
  "  " + hex.encode(WIKI_KEY).slice(0, 32) + "\n" + hex.encode(WIKI_KEY).slice(32) + "  ",
  changedWif,
  WIKI_WIF.slice(0, -1),
  b58.encode(Uint8Array.from([0x81, ...WIKI_KEY])),
  b58.encode(Uint8Array.from([0x80, ...WIKI_KEY, 0x02])),
  changedMini,
  MINI.slice(0, 21),
];
const CURVE_ORDER_HEX = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
const CURVE_ORDER = BigInt("0x" + CURVE_ORDER_HEX);

// The curve is stubbed: the range check is the published secp256k1 order and
// the public keys are deterministic, so both paths feed the same bytes to the
// same code. The real curve is exercised by the wallet tests.
const secpStub = {
  utils: {
    isValidSecretKey: (key) => {
      if (!(key instanceof Uint8Array) || key.length !== 32) return false;
      let value = 0n;
      for (const byte of key) value = (value << 8n) | BigInt(byte);
      return value > 0n && value < CURVE_ORDER;
    },
  },
  getPublicKey: (key, compressed) => {
    const out = new Uint8Array(compressed ? 33 : 65);
    out[0] = compressed ? 0x02 : 0x04;
    out.set(key, 1);
    if (!compressed) out.set(key, 33);
    return out;
  },
};

const hodlErrorStub = (key, vars) => Object.assign(new Error(key), { spec: vars === undefined ? { key } : { key, vars } });

const keyDocument = () => {
  const state = { kind: "wif", keyValue: null };
  return {
    state,
    querySelector: (selector) => (selector === 'input[name="kk"]:checked' ? { value: state.kind } : null),
    getElementById: (id) => (id === "key" ? (state.keyValue === null ? null : { value: state.keyValue }) : null),
  };
};

const loadKeyApp = async (overrides = {}) => {
  const doc = keyDocument();
  const mod = await loadAppFunctions(
    [
      "hodlSecureKeyKind", "hodlSecureKeyActive", "hodlSecureKeyEntry", "hodlSecureKeyApplies",
      "hodlSecureKeyFormApplies", "hodlSecureKeyTyped",
      "hodlSecureKeyParsed", "hodlSecureKeyReady", "hodlSecureKeyWallet",
      "hodlSecureEntryHasData", "hodlSecureKeyOf",
      "hodlSingleKeyWallet", "hodlAssertPrivateKeyKind",
    ],
    {
      stubs: {
        ...realSecureEntryStubs,
        hodlSecureSupported: { ...SUPPORTED_METHODS, key: true },
        hodlKeyMode: "key",
        document: doc,
        hodlBase58Check: { decode: base58checkDecode },
        hodlSha256: wasmSha256,
        hodlHex: hex,
        hodlSecp256k1: secpStub,
        addressFor: (type, pubkey, network) => `${type}:${hex.encode(pubkey)}:${network}`,
        hodlError: hodlErrorStub,
        hodlActiveDerivation: null,
        hodlBrainWalletPassphrase: (text) => text,
        hodlBrainWalletPrivateKey: () => { throw new Error("brain path used"); },
        ...overrides.stubs,
      },
      settable: ["hodlSecureEntryOn", "hodlKeys", "hodlActiveKey", "hodlSecureSession", ...(overrides.settable ?? [])],
    }
  );
  return { mod, doc };
};

const prepareKey = (mod, state = { id: 1, fields: {} }) => {
  const session = createSecureSession();
  mod.__set.hodlSecureSession(session);
  mod.__set.hodlKeys([state]);
  mod.__set.hodlActiveKey(0);
  mod.__set.hodlSecureEntryOn(true);
  const owner = mod.hodlSecureKeyOf(state, true);
  const entry = keyEntry();
  sessionSet(session, owner, "key", entry);
  return { session, state, owner, entry };
};

test("hodlSecureKeyWallet matches the text path for every accepted corpus input", async () => {
  const { mod, doc } = await loadKeyApp();
  const { session, owner } = prepareKey(mod);
  let compared = 0;
  for (const text of keyCorpus) {
    for (const kind of ["wif", "hex-key", "minikey"]) {
      doc.state.kind = kind;
      for (const network of ["mainnet", "testnet"]) {
        let textWallet;
        try {
          mod.hodlAssertPrivateKeyKind(text, network, kind);
          textWallet = mod.hodlSingleKeyWallet(text, network, kind);
        } catch {
          continue;
        }
        const entry = keyEntry();
        entry.vault.setText(text);
        sessionSet(session, owner, "key", entry);
        const vaultWallet = mod.hodlSecureKeyWallet(network);
        const label = `${JSON.stringify(text)} (${kind}, ${network})`;
        assert.deepEqual(vaultWallet.privateKey, textWallet.privateKey, label);
        assert.deepEqual(vaultWallet.minikey, textWallet.minikey, label);
        assert.equal(vaultWallet.pubkeyCompressed, textWallet.pubkeyCompressed, label);
        assert.equal(vaultWallet.pubkeyUncompressed, textWallet.pubkeyUncompressed, label);
        assert.equal(vaultWallet.p2pkhUncompressed, textWallet.p2pkhUncompressed, label);
        assert.equal(vaultWallet.p2pkhCompressed, textWallet.p2pkhCompressed, label);
        assert.equal(vaultWallet.p2shP2wpkh, textWallet.p2shP2wpkh, label);
        assert.equal(vaultWallet.p2wpkh, textWallet.p2wpkh, label);
        assert.equal(vaultWallet.p2tr, textWallet.p2tr, label);
        assert.equal(vaultWallet.network, textWallet.network, label);
        assert.equal(vaultWallet.source, textWallet.source, label);
        assert.equal(vaultWallet.compressed, textWallet.compressed, label);
        assert.deepEqual(vaultWallet.notes, textWallet.notes, label);
        assert.deepEqual(vaultWallet.warnings, textWallet.warnings, label);
        compared++;
      }
    }
  }
  assert.ok(compared > 0, "the corpus must exercise the accepted path");
});

test("hodlSecureKeyWallet refuses with the text path's message", async () => {
  const { mod, doc } = await loadKeyApp();
  const { session, owner } = prepareKey(mod);
  const cases = [];
  for (const text of keyCorpus) for (const kind of ["wif", "hex-key", "minikey"]) for (const network of ["mainnet", "testnet"]) cases.push({ text, kind, network });
  cases.push(
    { text: "", kind: "wif", network: "mainnet" },
    { text: "   ", kind: "wif", network: "mainnet" },
    { text: WIKI_WIF, kind: "hex-key", network: "mainnet" },
    { text: MINI, kind: "wif", network: "mainnet" },
    { text: wifOf(WIKI_KEY, "testnet", true), kind: "wif", network: "mainnet" },
    { text: "0".repeat(64), kind: "hex-key", network: "mainnet" },
    { text: CURVE_ORDER_HEX, kind: "hex-key", network: "mainnet" },
  );
  let compared = 0;
  for (const { text, kind, network } of cases) {
    doc.state.kind = kind;
    let textError;
    try {
      mod.hodlAssertPrivateKeyKind(text, network, kind);
      mod.hodlSingleKeyWallet(text, network, kind);
    } catch (error) {
      textError = error;
    }
    if (!textError) continue;
    const entry = keyEntry();
    entry.vault.setText(text);
    sessionSet(session, owner, "key", entry);
    let vaultError;
    try {
      mod.hodlSecureKeyWallet(network);
    } catch (error) {
      vaultError = error;
    }
    const label = `${JSON.stringify(text)} (${kind}, ${network})`;
    assert.ok(vaultError, `the vault path must refuse ${label}`);
    assert.equal(vaultError.message, textError.message, label);
    assert.deepEqual(vaultError.spec, textError.spec, label);
    compared++;
  }
  assert.ok(compared > 0, "the corpus must exercise the refused path");
});

test("hodlSecureKeyWallet zeroes every vault copy and keeps its own key", async () => {
  const { mod, doc } = await loadKeyApp();
  const { entry } = prepareKey(mod);
  const recorded = [];
  const original = entry.vault.bytes.bind(entry.vault);
  entry.vault.bytes = () => { const bytes = original(); recorded.push(bytes); return bytes; };

  doc.state.kind = "wif";
  entry.vault.setText(WIKI_WIF);
  const vaultLength = entry.vault.length;
  assert.equal(vaultLength, WIKI_WIF.length);
  const wallet = mod.hodlSecureKeyWallet("mainnet");
  assert.equal(entry.vault.length, vaultLength, "the vault still holds the key");
  assert.ok(recorded.length > 0);
  for (const bytes of recorded) assert.deepEqual([...bytes], new Array(bytes.length).fill(0));
  // The parsed key was zeroed by the wallet builder, so a non-zero key here is
  // the wallet's own copy, not the parser's array.
  assert.ok(wallet.privateKey.some((byte) => byte !== 0), "the wallet keeps its own copy");
  assert.deepEqual([...wallet.privateKey], [...WIKI_KEY]);

  recorded.length = 0;
  entry.vault.setText(wifOf(WIKI_KEY, "testnet", true));
  assert.throws(() => mod.hodlSecureKeyWallet("mainnet"));
  assert.ok(recorded.length > 0);
  for (const bytes of recorded) assert.deepEqual([...bytes], new Array(bytes.length).fill(0));
});

test("hodlSecureKeyActive needs the switch, the supported method and a non-brain kind", async () => {
  const off = await loadKeyApp({ stubs: { hodlSecureSupported: { ...SUPPORTED_METHODS, key: false } } });
  const session = createSecureSession();
  off.mod.__set.hodlSecureSession(session);
  off.mod.__set.hodlKeys([{ id: 1, fields: {} }]);
  off.mod.__set.hodlActiveKey(0);
  off.mod.__set.hodlSecureEntryOn(true);
  off.doc.state.kind = "wif";
  assert.equal(off.mod.hodlSecureKeyActive(), false, "the key method is not supported");
  assert.equal(off.mod.hodlSecureKeyEntry(true), null);
  assert.equal(session.entries.size, 0);

  const real = await loadKeyApp({ stubs: { hodlSecureSupported: SUPPORTED_METHODS } });
  real.mod.__set.hodlSecureSession(createSecureSession());
  real.mod.__set.hodlKeys([{ id: 1, fields: {} }]);
  real.mod.__set.hodlActiveKey(0);
  real.mod.__set.hodlSecureEntryOn(true);
  real.doc.state.kind = "wif";
  assert.equal(real.mod.hodlSecureKeyActive(), true, "SUPPORTED_METHODS.key is true");

  const on = await loadKeyApp();
  on.mod.__set.hodlSecureSession(createSecureSession());
  on.mod.__set.hodlKeys([{ id: 1, fields: {} }]);
  on.mod.__set.hodlActiveKey(0);
  on.mod.__set.hodlSecureEntryOn(true);
  on.doc.state.kind = "brain";
  assert.equal(on.mod.hodlSecureKeyActive(), false, "brain wallets stay text");
  on.doc.state.kind = "wif";
  assert.equal(on.mod.hodlSecureKeyActive(), true);
  on.mod.__set.hodlSecureEntryOn(false);
  assert.equal(on.mod.hodlSecureKeyActive(), false, "the switch is off");
});

test("hodlSecureKeyApplies keeps text that arrived while the switch was on", async () => {
  const session = createSecureSession();
  const { mod, doc } = await loadKeyApp();
  const key = { id: 1, fields: {} };
  mod.__set.hodlSecureSession(session);
  mod.__set.hodlKeys([key]);
  mod.__set.hodlActiveKey(0);
  mod.__set.hodlSecureEntryOn(true);
  doc.state.kind = "wif";

  // Nothing typed anywhere: the picker's key.
  assert.equal(mod.hodlSecureKeyApplies(), true);

  // Text stored for the selected kind keeps the text path.
  key.fields.privateKeys = { wif: WIKI_WIF };
  assert.equal(mod.hodlSecureKeyApplies(), false);

  // The standard text field keeps it too.
  key.fields.privateKeys = { wif: "" };
  doc.state.keyValue = WIKI_WIF;
  assert.equal(mod.hodlSecureKeyApplies(), false);
  doc.state.keyValue = null;

  // A character in the vault decides, whatever text is around.
  const entry = keyEntry();
  entry.vault.setText("5");
  sessionSet(session, mod.hodlSecureKeyOf(key, true), "key", entry);
  key.fields.privateKeys = { wif: WIKI_WIF };
  assert.equal(mod.hodlSecureKeyApplies(), true);
});

test("hodlSecureEntryHasData sees a key vault with anything in it", async () => {
  const session = createSecureSession();
  const mod = await loadAppFunctions(["hodlSecureEntryHasData"], {
    stubs: realSecureEntryStubs,
    settable: ["hodlSecureSession"],
  });
  mod.__set.hodlSecureSession(session);
  assert.equal(mod.hodlSecureEntryHasData(1), false);

  const entry = keyEntry();
  sessionSet(session, 1, "key", entry);
  assert.equal(mod.hodlSecureEntryHasData(1), false);

  entry.vault.setText("5");
  assert.equal(mod.hodlSecureEntryHasData(1), true);

  entry.vault.clear();
  assert.equal(mod.hodlSecureEntryHasData(1), false);

  const seed = seedEntry(12);
  seedSet(seed, 0, 0);
  sessionSet(session, 2, "seed", seed);
  assert.equal(mod.hodlSecureEntryHasData(2), true);
});

test("a key vault does not make the seed method apply (Kimi K3.1)", async () => {
  const session = createSecureSession();
  const phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident";
  const key = { id: 1, seedMethod: "words", targetWords: 12, fields: { seed: phrase } };
  const mod = await loadAppFunctions(
    ["hodlSecureSeedApplies", "hodlSecureSeedPickerShown", "hodlSecureEntryHasData", "hodlSecureEntryHeld", "hodlSecureKeyOf"],
    {
      stubs: {
        ...realSecureEntryStubs,
        hodlSecureSupported: { ...SUPPORTED_METHODS, seed: true },
        hodlKeyMode: "seed",
        hodlSeedMethod: "words",
        hodlTargetWordCount: 12,
        document: { getElementById: () => null },
      },
      settable: ["hodlSecureEntryOn", "hodlKeys", "hodlActiveKey", "hodlSecureSession"],
    }
  );
  mod.__set.hodlSecureSession(session);
  mod.__set.hodlKeys([key]);
  mod.__set.hodlActiveKey(0);
  mod.__set.hodlSecureEntryOn(true);
  const owner = mod.hodlSecureKeyOf(key, true);
  const entry = keyEntry();
  entry.vault.setText("5");
  sessionSet(session, owner, "key", entry);

  assert.equal(mod.hodlSecureSeedApplies(), false, "a key vault is not seed words");
  assert.equal(mod.hodlSecureSeedPickerShown(key), false, "the text phrase keeps the text field");
  assert.equal(mod.hodlSecureEntryHasData(owner), true, "the protective check still sees the vault");
  assert.equal(mod.hodlSecureEntryHeld(key), true);
});

test("secure seed words do not make the key method apply (Kimi K3.1)", async () => {
  const { mod, doc } = await loadKeyApp();
  const session = createSecureSession();
  const key = { id: 1, fields: {} };
  mod.__set.hodlSecureSession(session);
  mod.__set.hodlKeys([key]);
  mod.__set.hodlActiveKey(0);
  mod.__set.hodlSecureEntryOn(true);
  doc.state.kind = "wif";
  doc.state.keyValue = WIKI_WIF;
  const seed = seedEntry(12);
  seedSet(seed, 0, 0);
  sessionSet(session, mod.hodlSecureKeyOf(key, true), "seed", seed);
  assert.equal(mod.hodlSecureKeyApplies(), false, "seed words are not a key vault");
});

test("the method-specific checks see only their own method (Kimi K3)", async () => {
  const session = createSecureSession();
  const mod = await loadAppFunctions(["hodlSecureSeedHasWords", "hodlSecureKeyHasData"], {
    stubs: realSecureEntryStubs,
    settable: ["hodlSecureSession"],
  });
  mod.__set.hodlSecureSession(session);
  assert.equal(mod.hodlSecureSeedHasWords(null), false);
  assert.equal(mod.hodlSecureKeyHasData(null), false);

  const seed = seedEntry(12);
  const key = keyEntry();
  sessionSet(session, 1, "seed", seed);
  sessionSet(session, 2, "key", key);
  assert.equal(mod.hodlSecureSeedHasWords(1), false, "an empty seed entry holds no words");
  assert.equal(mod.hodlSecureKeyHasData(2), false, "an empty vault holds no bytes");
  assert.equal(mod.hodlSecureKeyHasData(1), false, "a seed entry is not key data");
  assert.equal(mod.hodlSecureSeedHasWords(2), false, "a key entry is not seed words");

  seedSet(seed, 0, 0);
  key.vault.setText("5");
  assert.equal(mod.hodlSecureSeedHasWords(1), true);
  assert.equal(mod.hodlSecureKeyHasData(2), true);
  assert.equal(mod.hodlSecureKeyHasData(1), false);
  assert.equal(mod.hodlSecureSeedHasWords(2), false);

  const failing = await loadAppFunctions(["hodlSecureSeedHasWords", "hodlSecureKeyHasData"], {
    stubs: { ...realSecureEntryStubs, sessionGet: () => { throw new Error("broken"); } },
    settable: ["hodlSecureSession"],
  });
  failing.__set.hodlSecureSession({});
  assert.equal(failing.hodlSecureSeedHasWords(1), true, "a failed read counts as holding words");
  assert.equal(failing.hodlSecureKeyHasData(1), true, "a failed read counts as holding bytes");
});

test("the length lock ignores key-vault data and holds for seed words (MiniMax)", async () => {
  const session = createSecureSession();
  const state = { id: 1, fields: {} };
  let captured = 0;
  const mod = await loadAppFunctions(["hodlSetSeedLength", "hodlSecureKeyOf"], {
    stubs: {
      ...realSecureEntryStubs,
      hodlSeedLengths: { 12: { words: 12 }, 24: { words: 24 } },
      hodlDiceMethod: "coldcard",
      hodlUpdateSeedLengthControl: () => {},
      hodlCaptureKey: () => { captured++; },
      hodlInvalidateActiveKeyOutput: () => {},
      hodlRenderKeyForm: () => {},
      hodlRestoreFormFields: () => {},
      hodlQueueMasterFingerprintPreview: () => {},
    },
    settable: ["hodlSecureEntryOn", "hodlKeys", "hodlActiveKey", "hodlSecureSession", "hodlTargetWordCount"],
  });
  mod.__set.hodlSecureSession(session);
  mod.__set.hodlKeys([state]);
  mod.__set.hodlActiveKey(0);
  mod.__set.hodlSecureEntryOn(true);
  mod.__set.hodlTargetWordCount(24);
  const owner = mod.hodlSecureKeyOf(state, true);

  // Only key-vault data: the length may change.
  const key = keyEntry();
  key.vault.setText("5");
  sessionSet(session, owner, "key", key);
  mod.hodlSetSeedLength(12);
  assert.equal(captured, 1, "a key vault does not lock the length");
  assert.equal(state.targetWords, 12);

  // Secure seed words: the length is refused.
  const seed = seedEntry(12);
  seedSet(seed, 0, 0);
  sessionSet(session, owner, "seed", seed);
  mod.hodlSetSeedLength(24);
  assert.equal(captured, 1, "secure words lock the length");
  assert.equal(state.targetWords, 12);
});

test("the key vault path never builds a string", async () => {
  const { mod } = await loadKeyApp();
  for (const name of ["hodlSecureKeyParsed", "hodlSecureKeyReady", "hodlSecureKeyWallet"]) {
    const source = mod[name].toString();
    for (const forbidden of ["vault.text(", "TextDecoder", "fromCharCode", "String("]) {
      assert.equal(source.includes(forbidden), false, `${name} must not contain ${forbidden}`);
    }
  }
});

test("hodlSecureKeyTyped reads only the key's own kind", async () => {
  const { mod } = await loadKeyApp();
  const hexKey = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";
  assert.equal(mod.hodlSecureKeyTyped({ fields: { keyKind: "brain", privateKeys: { wif: WIKI_WIF, brain: "correct horse" } } }), null);
  assert.equal(mod.hodlSecureKeyTyped({ fields: { keyKind: "wif", privateKeys: { wif: "   ", "hex-key": hexKey } } }), null);
  assert.deepEqual(
    mod.hodlSecureKeyTyped({ fields: { keyKind: "hex-key", privateKeys: { wif: WIKI_WIF, "hex-key": hexKey } } }),
    { text: hexKey, kind: "hex-key" },
  );
});

test("hodlSecureKeyFormApplies follows the key's kind, typed text and vault", async () => {
  const { mod } = await loadKeyApp();
  const use = (state, vault = "") => {
    const session = createSecureSession();
    mod.__set.hodlSecureSession(session);
    mod.__set.hodlKeys([state]);
    mod.__set.hodlActiveKey(0);
    mod.__set.hodlSecureEntryOn(true);
    if (vault) {
      const entry = keyEntry();
      entry.vault.setText(vault);
      sessionSet(session, mod.hodlSecureKeyOf(state, true), "key", entry);
    }
    return state;
  };
  assert.equal(mod.hodlSecureKeyFormApplies(use({ id: 1, fields: { keyKind: "brain", privateKeys: { wif: "", brain: "" } } })), false);
  assert.equal(mod.hodlSecureKeyFormApplies(use({ id: 2, fields: { keyKind: "wif", privateKeys: { wif: WIKI_WIF } } })), false);
  assert.equal(mod.hodlSecureKeyFormApplies(use({ id: 3, fields: { keyKind: "wif", privateKeys: { wif: "" } } })), true);
  assert.equal(mod.hodlSecureKeyFormApplies(use({ id: 4, fields: { keyKind: "wif", privateKeys: { wif: WIKI_WIF } } }, "5")), true);
});

test("hodlCaptureKey ignores a masked field that is not #key", async () => {
  const before = { wif: WIKI_WIF, "hex-key": "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d" };
  const privateKeys = { ...before };
  const state = { id: 1, fields: { keyKind: "wif", privateKeys } };
  const secureKey = { id: "secure-key", value: "••••••", dataset: {} };
  const mod = await loadAppFunctions(["hodlCaptureKey"], {
    stubs: {
      document: {
        getElementById: (id) => id === "secure-key" ? secureKey : null,
        querySelector: () => null,
      },
      hodlKeyMode: "key",
      hodlDiceMethod: "coldcard",
      hodlCardMethod: "direct",
      hodlSeedMethod: "words",
      hodlSeedZeroIndexed: false,
      hodlCardColemanSymbols: false,
      hodlEntropyFormat: "hex",
      hodlTargetWordCount: 12,
      hodlDiceCoinPositions: [],
      hodlPickedLastWord: "",
      hodlWalletResult: null,
      hodlRevealPrivate: false,
      hodlKeyErrorSpec: null,
      hodlSelectedScriptType: () => "p2wpkh",
      hodlFormatErrorSpec: () => "",
      hodlStorePassphrase: () => {},
      hodlBrainWalletOutput: () => "scalar",
      hodlReadHardening: () => ({ purpose: true, coinType: true, account: true, branch: false, address: false }),
      hodlSelectedNetwork: () => "mainnet",
      hodlDiceFieldName: () => "dice",
      hodlPrivateKeyValues: (fields) => fields.privateKeys,
      hodlNormalizePrivateKeyKind: (kind) => kind || "wif",
    },
    settable: ["hodlKeys", "hodlActiveKey"],
  });
  mod.__set.hodlKeys([state]);
  mod.__set.hodlActiveKey(0);
  mod.hodlCaptureKey();
  assert.deepEqual(state.fields.privateKeys, before);
  assert.equal(state.fields.wif, undefined);
  assert.equal(secureKey.value, "••••••");
});
