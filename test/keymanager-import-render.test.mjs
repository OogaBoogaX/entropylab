// Issue #389 requires defensive rendering even for crafted result values.
// Issue #425 additionally requires authenticity: imported caches are not
// derivation evidence. Exercise the real parser and controllers, and retain
// the renderer's escaping checks as an independent boundary.
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { KEY_VAULT_MAX_KEYS, keyVaultIdentity, keyResultSetup, parseKeyVault, serializeKeyVault } from "../src/js/keymanager.js";
import { JOURNAL_MAX_FILE_LENGTH } from "../src/js/journal.js";
import { runInNewContext } from "node:vm";
import { mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { HDKey } from "@scure/bip32";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { p2wpkh } from "@scure/btc-signer";
import { loadAppFunctions } from "./app-slice-harness.mjs";
import { addressQrButtonHtml } from "../src/js/address-qr.js";
import { t, tAttr } from "../src/js/i18n.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");

function loadSlice(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let depth = 0;
  let end = -1;
  for (let i = app.indexOf(") {", start) + 2; i < app.length; i++) {
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
  return (app.slice(start - 6, start) === "async " ? "async " : "") + app.slice(start, end);
}

const WORDS = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const legacyEntry = () => ({
  id: 1, number: 1, name: "Imported", mode: "seed", targetWords: 12,
  fields: { seed: WORDS, pass: "", derivationPath: "m/84'/0'/0'/0/0" },
  needsDerivation: false, verified: true, importedKeyId: 1,
  result: { kind: "hd", masterFingerprint: "deadbeef", mnemonic: "forged cached mnemonic",
    rootXprv: "forged cached xprv", accounts: [{ primaryPrivate: "forged WIF", address: "forged address" }] },
});
const legacyFile = (keys, ignoredKeys = []) => JSON.stringify({ format: "entropylab-key-manager", version: 1, keys, ignoredKeys });

// Existing Bitcoin wiki WIF vector (also pinned by single-private-key.test).
// Public identity is checked against noble's independent secp256k1 engine;
// private scalar 1 additionally pins the SEC 2 generator, without any RNG.
const WIKI_HEX = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";
const WIKI_WIF = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
const GENERATOR = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
async function singleWalletApi() {
  const inert = new Proxy(function () {}, { get: (_target, key) => key === Symbol.toPrimitive ? () => "" : key === "then" ? undefined : inert, apply: () => inert });
  const previous = { document: globalThis.document, window: globalThis.window };
  Object.assign(globalThis, { document: inert, window: inert });
  try { return await loadAppFunctions(["hodlSingleKeyWallet", "hodlKeyWalletIdentity"]); }
  finally { Object.assign(globalThis, previous); }
}

test("Journal single-key matching uses a fresh public identity without changing ordinary manual matching", async () => {
  const api = await singleWalletApi();
  const one = api.hodlSingleKeyWallet("00".repeat(31) + "01", "mainnet", "hex-key");
  assert.equal(one.pubkeyCompressed, GENERATOR);
  assert.equal(api.hodlKeyWalletIdentity(one, true), `single:${GENERATOR}`);
  const expected = Buffer.from(secp256k1.getPublicKey(Buffer.from(WIKI_HEX, "hex"), true)).toString("hex");
  for (const result of [api.hodlSingleKeyWallet(WIKI_WIF, "mainnet", "wif"), api.hodlSingleKeyWallet(WIKI_HEX, "mainnet", "hex-key"), api.hodlSingleKeyWallet(WIKI_HEX, "regtest", "hex-key")]) {
    assert.equal(result.pubkeyCompressed, expected);
    assert.equal(api.hodlKeyWalletIdentity(result, true), `single:${expected}`);
    assert.equal(api.hodlKeyWalletIdentity(result), null, "default manual derivation must retain its existing append behavior");
  }
  for (const pubkeyCompressed of [undefined, null, "", "02" + "1".repeat(63), "04" + "1".repeat(64), "02" + "z".repeat(64), { key: GENERATOR }]) {
    assert.equal(api.hodlKeyWalletIdentity({ kind: "single", pubkeyCompressed }, true), null);
  }
  assert.equal(api.hodlKeyWalletIdentity({ kind: "hd", masterIdentity: "root-identity" }, true), "root-identity");
  const imported = parseKeyVault(legacyFile([{ ...legacyEntry(), result: { kind: "single", pubkeyCompressed: expected } }])).keys[0];
  assert.equal(api.hodlKeyWalletIdentity(imported.result, true), null, "file-supplied caches must not become wallet identity");
});

test("fresh single-key imports reuse exact setups and ask before different network or compression", async () => {
  const api = await singleWalletApi(), { context: c } = importHarness();
  const existing = c.hodlNewKeyState("Existing single key");
  existing.result = api.hodlSingleKeyWallet(WIKI_WIF, "mainnet", "wif");
  c.hodlKeys.push(existing);
  c.hodlKeyResultSetup = keyResultSetup;
  c.hodlResultHasSeed = () => false;
  c.hodlResultHasRoot = () => false;
  c.hodlResultHasImportedPrivate = () => false;
  c.hodlResultHasSingleKey = (result) => Boolean(result.privateKey);
  let prompted = 0, choice = "keep", comparison;
  c.hodlKeyManagerDecision = async (options) => { prompted++; comparison = options; return choice; };
  const exact = await c.hodlKeyManagerDecideCommit(null, { name: "Imported" }, api.hodlSingleKeyWallet(WIKI_WIF, "mainnet", "wif"), "bip84");
  assert.equal(exact.kind, "reuse");
  assert.equal(exact.state, existing);
  assert.equal(prompted, 0);
  const before = JSON.stringify(existing);
  for (const result of [api.hodlSingleKeyWallet(WIKI_HEX, "regtest", "hex-key"), api.hodlSingleKeyWallet(WIKI_HEX, "mainnet", "hex-key")]) {
    assert.equal((await c.hodlKeyManagerDecideCommit(null, { name: "Imported" }, result, "bip84")).kind, "skip");
  }
  assert.equal(prompted, 2);
  assert.ok(comparison.existingEncoding && comparison.importedEncoding);
  assert.notEqual(comparison.existingEncoding, comparison.importedEncoding, "the setup choice must explain the different input encoding");
  assert.equal(JSON.stringify(existing), before);
  choice = "append";
  assert.equal((await c.hodlKeyManagerDecideCommit(null, { name: "Imported" }, api.hodlSingleKeyWallet(WIKI_HEX, "regtest", "hex-key"), "bip84")).kind, "append");
  assert.equal(JSON.stringify(existing), before);
  const different = api.hodlSingleKeyWallet("00".repeat(31) + "01", "mainnet", "hex-key");
  assert.equal((await c.hodlKeyManagerDecideCommit(null, { name: "Other" }, different, "bip84")).kind, "append");
  assert.equal(prompted, 3, "another private key must not prompt as the same wallet");
  // Single-key recovery must use the same private-recovery category as an
  // HD private root. Compare the categories without pinning their wording.
  c.hodlResultHasRoot = () => true;
  await c.hodlKeyManagerDecideCommit(null, { name: "Imported" }, api.hodlSingleKeyWallet(WIKI_HEX, "regtest", "hex-key"), "bip84");
  const privateRecovery = comparison.importedRecovery;
  c.hodlResultHasRoot = () => false;
  await c.hodlKeyManagerDecideCommit(null, { name: "Imported" }, api.hodlSingleKeyWallet(WIKI_HEX, "regtest", "hex-key"), "bip84");
  assert.equal(comparison.importedRecovery, privateRecovery);
  assert.equal(comparison.existingRecovery, privateRecovery);
  const imported = c.hodlKeyManagerImportedState({ name: "Imported source", mode: "key", fields: { keyKind: "wif", privateKeys: { wif: WIKI_WIF } } });
  c.hodlKeyManagerPending.push(imported);
  c.hodlKeyManagerIds.add(keyVaultIdentity(imported));
  c.hodlKeys[0].result = api.hodlSingleKeyWallet(WIKI_WIF, "mainnet", "wif");
  c.hodlKeys[0].importedKeyId = imported.id;
  c.hodlCommitDerivedKey("derive", exact);
  assert.equal(c.hodlKeys.length, 2);
  assert.equal(c.hodlKeys[1], existing);
  assert.equal(c.hodlKeyManagerPending.length, 0);
  assert.equal(c.hodlKeyManagerIgnored[0].fields.privateKeys.wif, WIKI_WIF);
  c.hodlActiveKey = 0;
  c.hodlKeys[0].result = api.hodlSingleKeyWallet(WIKI_WIF, "mainnet", "wif");
  c.hodlCommitDerivedKey();
  assert.equal(c.hodlKeys.length, 3, "ordinary manual derivation must still append");
  assert.equal(JSON.stringify(existing), before);
});

function importHarness() {
  const calls = [], context = {
    keyVaultIdentity, parseKeyVault, hodlKeyVaultMaxKeys: KEY_VAULT_MAX_KEYS,
    hodlPrivateKeyKinds: ["wif", "hex-key", "minikey", "brain"],
    hodlNextKeyId: 1, hodlNextKeyNumber: 1, hodlActiveKey: 0,
    hodlWorkspace: "journal",
    hodlKeyManagerFileRequest: 0,
    hodlPassphraseVaultField: null, TextEncoder, TextDecoder,
    hodlKeys: [], hodlKeyManagerPending: [], hodlKeyManagerIgnored: [],
    hodlKeyManagerIds: new Set(), hodlKeyManagerActiveId: "", hodlActiveDerivation: null, hodlJournalKeyDerivation: null,
    document: { getElementById: () => null, querySelectorAll: () => [] },
    hodlWalletResult: null, hodlOutEl: { innerHTML: "" },
    hodlDefaultCoinType: () => 0, hodlNetworkDefault: "mainnet", hodlKeyColor: id => String(id),
    hodlDefaultKeyName: id => `Key ${id}`,
    hodlScriptDefinition: id => ({ label: id }),
    hodlKeyResultSetup: (result, script) => result ? { network: result.network, script } : null,
    hodlKeyManagerDecision: async () => "append",
    hodlKeyManagerDeriveInputs: async () => {},
    hodlKeyManagerCancelDerivation() {}, hodlWipeUnsharedWalletRows() {},
    hodlJournalUnlocked: () => true, hodlJournalKeys: {}, hodlJournalGeneration: 0,
    hodlJournalMaxFileLength: JOURNAL_MAX_FILE_LENGTH,
    hodlJournalOpenExport: async content => ({ kind: "key-manager", content }),
    hodlTText: (text, vars) => text.replace("{n}", String(vars?.n ?? "")),
    hodlJournalLog: (...args) => calls.push(args),
    hodlKeyManagerStatus: text => calls.push(["status", text]),
    hodlRenderKeyTabs() {}, hodlKeyManagerRender() {},
    hodlElement: () => ({ children: [] }),
    hodlCaptureKey: () => { context.hodlKeys[context.hodlActiveKey].result = context.hodlWalletResult; },
    hodlShowWorkspace: () => { context.hodlWalletResult = context.hodlKeys[context.hodlActiveKey].result; },
    hodlRestoreKey: () => { context.hodlWalletResult = context.hodlKeys[context.hodlActiveKey].result; },
    // Zeroing dropped wallets and releasing their cloned sessions are covered
    // in secret-clear.test.mjs.
    hodlCommittedResults: new Set(), hodlDisposeDroppedWallets() {},
    hodlReleaseKeyConsumers() {}, hodlZeroKeyPassphrase() {},
  };
  for (const name of ["hodlNewKeyState", "hodlNewLabState", "hodlKeyManagerImportedState",
    "hodlKeyManagerStates", "hodlKeyManagerUseInStation", "hodlKeyManagerDetachFromStation", "hodlKeyManagerSyncReviewedContext",
    "hodlCloneDerivedKey", "hodlFillLabFromKey", "hodlKeyWalletIdentity", "hodlCommitDerivedKey", "hodlKeyManagerImportFile", "hodlNormalizeKeyName", "hodlKeyNameTaken",
    "hodlKeyManagerIgnore", "hodlKeyManagerEntry", "hodlKeyManagerHasInputs", "hodlPrivateKeyValues", "hodlNormalizePrivateKeyKind", "hodlDetectPrivateKeyKind", "hodlKeyManagerArchiveEntry", "hodlKeyLogLabel",
    "hodlKeyManagerRestoreIgnored", "hodlStoredPassphraseBytes", "hodlPassphraseText",
    "hodlKeyManagerDecideCommit", "hodlKeyManagerResultPaths", "hodlKeyManagerDiscardInputs", "hodlKeyManagerCapacityError"])
    runInNewContext(loadSlice(name), context);
  context.hodlKeys.push(context.hodlNewLabState());
  return { context, calls, importFile: text => context.hodlKeyManagerImportFile({ size: text.length, text: async () => text }) };
}

test("both vault versions ignore forged caches, identity, flags, and unrelated properties", () => {
  for (const version of [1, 2]) {
    const entry = legacyEntry();
    const parsed = parseKeyVault(JSON.stringify({ format: "entropylab-key-manager", version, keys: [entry], ignoredKeys: [entry] }));
    for (const item of [...parsed.keys, ...parsed.ignoredKeys]) {
      assert.equal(item.result, null);
      assert.equal(item.needsDerivation, true);
      assert.equal(item.id, undefined);
      assert.equal(item.verified, undefined);
      assert.equal(item.importedKeyId, undefined);
      assert.equal(item.fields.seed, WORDS);
      assert.ok(!JSON.stringify(item).includes("forged"));
    }
  }
});

test("forged fingerprint/ID cannot alias an existing key; ignored imports stay unverified", async () => {
  const { context: c, importFile } = importHarness();
  const trusted = c.hodlNewKeyState();
  trusted.result = { masterFingerprint: "deadbeef", rootXprv: "existing secret" };
  c.hodlKeys.push(trusted);
  await importFile(legacyFile([legacyEntry(), legacyEntry()], [legacyEntry()]));
  assert.equal(c.hodlKeys[1], trusted);
  assert.equal(trusted.result.rootXprv, "existing secret");
  assert.equal(c.hodlKeyManagerPending.length, 2);
  assert.equal(c.hodlKeyManagerIgnored.length, 1);
  const pending = c.hodlKeyManagerPending[0];
  assert.notEqual(pending.id, trusted.id);
  assert.equal(pending.result, null);
  await c.hodlKeyManagerRestoreIgnored(c.hodlKeyManagerIgnored[0]);
  assert.equal(c.hodlKeyManagerPending.length, 3);
  assert.equal(c.hodlKeyManagerPending[2].needsDerivation, true);
  assert.equal(c.hodlKeyManagerPending[2].result, null);
  c.hodlKeyManagerUseInStation(pending);
  assert.equal(c.hodlKeys.length, 2, "loading inputs cannot install an unverified wallet");
  const lab = c.hodlKeys[c.hodlActiveKey];
  assert.equal(lab.isLab, true);
  assert.equal(lab.result, null);
  assert.equal(c.hodlWalletResult, null);
  assert.equal(lab.fields.seed, WORDS);
  assert.equal(c.hodlKeyManagerPending.length, 3, "loading alone does not verify or remove the input");
});

test("a successful key import selects its first added input without changing the active station key", async () => {
  const { context: c, importFile } = importHarness();
  const trusted = c.hodlNewKeyState("Existing station key");
  trusted.result = { masterIdentity: "existing-root", masterFingerprint: "deadbeef" };
  c.hodlKeys.push(trusted);
  c.hodlActiveKey = 1;
  c.hodlKeyManagerActiveId = keyVaultIdentity(trusted);
  await importFile(legacyFile([legacyEntry(), legacyEntry()]));
  assert.equal(c.hodlKeyManagerActiveId, keyVaultIdentity(c.hodlKeyManagerPending[0]));
  assert.equal(c.hodlKeys[c.hodlActiveKey], trusted);
  const selected = c.hodlKeyManagerActiveId;
  await importFile(legacyFile([], [legacyEntry()]));
  assert.equal(c.hodlKeyManagerActiveId, selected, "an archive-only import does not change the selected input");
});

function enableDerivation(c) {
  Object.assign(c, {
    hodlKeyMode: "seed", hodlSeedMethod: "words", hodlTargetWordCount: 12, hodlNetworkChoice: "mainnet",
    document: { getElementById: id => id === "journal-keymanager-panel" ? null : ({ value: c.hodlKeys[c.hodlActiveKey].fields[id] || "", children: [], focus() {} }), querySelectorAll: () => [] },
    hodlReadDerivationPlan: () => ({ network: "mainnet", coinType: 0 }),
    hodlNetworkFamily: value => value, hodlReadAddressWindow: () => ({ start: 0, range: 1 }),
    hodlReadBranchWindow: () => ({ start: 0, range: 1 }), hodlSelectedScriptType: () => "bip84",
    hodlDefaultHardening: () => ({}), hodlPassphraseBip39Enabled: () => false,
    hodlSelectedSeedInput: () => ({ value: c.hodlKeys[c.hodlActiveKey].fields.seed }),
    hodlValidateTargetMnemonic: value => {
      assert.ok(validateMnemonic(value, wordlist), "invalid source mnemonic");
      return { words: value.split(" ") };
    },
    hodlThrowIfFailed() {}, hodlError: text => new Error(text), hodlSetWorkspaceError() {}, hodlSetSelectedScriptType() {},
    hodlSnapshotKeySummary() {}, hodlFocusWalletResult() {},
    // The shared-fingerprint confirmation is a modal; the browser suite
    // drives it. Here the user proceeds, so the commit logic runs.
    hodlConfirmKeyFingerprint: () => Promise.resolve(true),
    hodlErrorSpecFrom: error => error.message,
    // The real controller drives an independent BIP39/BIP32 implementation.
    // Its existing wallet-engine vector tests separately cover production crypto.
    hodlMnemonicWalletWithProgress: async (words, passphrase, network) => {
      const master = HDKey.fromMasterSeed(mnemonicToSeedSync(words, passphrase));
      const leaf = master.derive("m/84'/0'/0'/0/0");
      return { network, mnemonic: words, masterFingerprint: master.fingerprint.toString(16).padStart(8, "0"),
        masterIdentity: Buffer.from(master.chainCode).toString("hex") + ":" + Buffer.from(master.publicKey).toString("hex"),
        rootXpub: master.publicExtendedKey,
        rootXprv: master.privateExtendedKey, address: p2wpkh(leaf.publicKey).address };
    },
  });
  // Keep the real cancellation control declarations with the controller,
  // including the generation fence supplied by the separate lifecycle fix.
  // No passphrase vault is bound here: the derivation reads the field's text.
  Object.assign(c, { hodlPassphraseVaultField: null, TextEncoder, TextDecoder });
  runInNewContext(app.slice(app.indexOf("class HodlDerivationCancelledError"), app.indexOf("function hodlDerivationButton")), c);
  for (const name of ["hodlResultHasSeed", "hodlResultHasRoot", "hodlResultHasSingleKey", "hodlResultHasImportedPrivate", "hodlCalculateKey", "hodlPassphraseFieldBytes"])
    runInNewContext(loadSlice(name), c);
}

// The queue uses the production calculator/commit controllers above. The
// independent BIP39 implementation remains the oracle for the resulting key.
function enableBatch(c) {
  enableDerivation(c);
  Object.assign(c, {
    hodlJournalKeyDerivation: null, hodlJournalKeyImportConfirm: null,
    hodlWorkspace: "journal",
    hodlLowEntropyConfirm: null, hodlFingerprintCollisionConfirm: null,
    hodlLowEntropyWarning: () => null,
    hodlWipeUnsharedWalletRows() {}, hodlWipeWalletKeys() {}, hodlSettleDerivationKeys() {},
    hodlKeyResultSetup: (result, script) => result ? { network: result.network, script } : null,
    hodlKeyManagerDecision: async () => null,
    hodlDeriveWithProgress: async (_kind, derive) => {
      const control = { cancelled: false, rowKeys: [], nodes: [] };
      c.hodlActiveDerivation = control;
      try { await derive({}); } finally { c.hodlActiveDerivation = null; }
    },
  });
  for (const name of ["hodlKeyManagerDiscardInputs", "hodlKeyManagerSyncDerivationUI", "hodlKeyManagerFinishDerivation",
    "hodlKeyManagerCancelDerivation", "hodlKeyManagerDeriveInputs", "hodlKeyManagerDecideCommit", "hodlZeroKeyPassphrase"])
    runInNewContext(loadSlice(name), c);
}

test("Journal batch derives fresh inputs while preserving the unfinished station draft", async () => {
  const { context: c, importFile, calls } = importHarness();
  await importFile(legacyFile([legacyEntry()]));
  const source = c.hodlKeyManagerPending[0], draft = c.hodlKeys[0];
  draft.fields.dice = "123456";
  draft.fields.pass = new Uint8Array([19, 23]);
  const pass = draft.fields.pass;
  enableBatch(c);
  await c.hodlKeyManagerDeriveInputs([source]);
  assert.equal(c.hodlKeys[0], draft);
  assert.equal(c.hodlKeys[c.hodlActiveKey], draft);
  assert.equal(draft.fields.dice, "123456");
  assert.deepEqual([...pass], [19, 23]);
  const key = c.hodlKeys.find(state => !state.isLab);
  assert.equal(key.result.address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
  assert.equal(key.name, "Imported");
  assert.equal(c.hodlKeyManagerPending.length, 0);
  assert.equal(c.hodlJournalKeyDerivation, null);
  assert.deepEqual(calls.filter(([action]) => action === "key-import-summary"), [
    ["key-import-summary", "added=1 reused=0 failed=0 kept=0 pending=0 cancelled=false", "journal"],
  ]);
  assert.equal(calls.find(([action]) => action === "derive")?.[2], "journal");
});

test("Journal batch does not recapture a hidden station over its stored active key", async () => {
  const { context: c, importFile } = importHarness();
  const existing = c.hodlNewKeyState("Existing wallet");
  existing.result = { masterIdentity: "unrelated-wallet", masterFingerprint: "deadbeef" };
  c.hodlKeys.push(existing); c.hodlActiveKey = 1;
  const before = JSON.stringify(existing);
  await importFile(legacyFile([legacyEntry()]));
  enableBatch(c);
  c.hodlWalletResult = null; // leaving Key Station conceals its displayed result
  await c.hodlKeyManagerDeriveInputs(c.hodlKeyManagerPending.slice());
  assert.equal(JSON.stringify(existing), before);
  assert.equal(c.hodlKeys[c.hodlActiveKey], existing);
});

test("Journal batch retains rejected inputs and continues with valid inputs", async () => {
  const { context: c, importFile } = importHarness();
  const rejected = legacyEntry(); rejected.fields.seed = "bad words";
  await importFile(legacyFile([rejected, legacyEntry()]));
  const bad = c.hodlKeyManagerPending[0], draft = c.hodlKeys[0];
  enableBatch(c);
  await c.hodlKeyManagerDeriveInputs(c.hodlKeyManagerPending.slice());
  assert.equal(c.hodlKeyManagerPending.length, 1);
  assert.equal(c.hodlKeyManagerPending[0], bad);
  assert.ok(bad.error);
  assert.equal(bad.result, null);
  assert.equal(c.hodlKeys[0], draft);
  assert.equal(c.hodlKeys.filter(state => !state.isLab).length, 1);
});

test("Journal batch exact reuse preserves the existing object and archives imported recovery inputs", async () => {
  const { context: c, importFile } = importHarness();
  await importFile(legacyFile([legacyEntry()]));
  enableBatch(c);
  await c.hodlKeyManagerDeriveInputs(c.hodlKeyManagerPending.slice());
  const existing = c.hodlKeys.find(state => !state.isLab), result = existing.result;
  existing.name = "Existing label";
  await importFile(legacyFile([legacyEntry()]));
  const imported = c.hodlKeyManagerPending[0], before = JSON.stringify(existing);
  await c.hodlKeyManagerDeriveInputs([imported]);
  assert.equal(c.hodlKeys.filter(state => !state.isLab).length, 1);
  assert.equal(c.hodlKeys.find(state => !state.isLab), existing);
  assert.equal(existing.result, result);
  assert.equal(JSON.stringify(existing), before);
  assert.equal(c.hodlKeyManagerPending.length, 0);
  assert.equal(c.hodlKeyManagerIgnored.length, 1);
  assert.equal(c.hodlKeyManagerIgnored[0].fields.seed, WORDS);
});

test("Journal batch waits on differing setups without changing the existing key", async () => {
  const { context: c, importFile } = importHarness();
  await importFile(legacyFile([legacyEntry()]));
  enableBatch(c);
  await c.hodlKeyManagerDeriveInputs(c.hodlKeyManagerPending.slice());
  const existing = c.hodlKeys.find(state => !state.isLab);
  existing.result.network = "testnet";
  const before = JSON.stringify(existing);
  await importFile(legacyFile([legacyEntry()]));
  const imported = c.hodlKeyManagerPending[0];
  let choose, shown;
  const opened = new Promise(resolve => { shown = resolve; });
  c.hodlKeyManagerDecision = () => { shown(); return new Promise(resolve => { choose = resolve; }); };
  const pending = c.hodlKeyManagerDeriveInputs([imported]);
  await opened;
  assert.equal(JSON.stringify(existing), before);
  assert.equal(c.hodlKeyManagerPending[0], imported);
  choose("keep"); await pending;
  assert.equal(JSON.stringify(existing), before);
  assert.equal(c.hodlKeyManagerPending[0], imported);
  c.hodlKeyManagerDecision = async () => "append";
  await c.hodlKeyManagerDeriveInputs([imported]);
  assert.equal(c.hodlKeys.filter(state => !state.isLab).length, 2);
  assert.equal(JSON.stringify(existing), before);
});

test("manually deriving reviewed Journal inputs also asks before changing an existing setup", async () => {
  const { context: c, importFile } = importHarness();
  await importFile(legacyFile([legacyEntry()]));
  enableBatch(c);
  await c.hodlKeyManagerDeriveInputs(c.hodlKeyManagerPending.slice());
  const existing = c.hodlKeys.find(state => !state.isLab), before = JSON.stringify(existing);
  await importFile(legacyFile([legacyEntry()]));
  const input = c.hodlKeyManagerPending[0];
  c.hodlKeyManagerUseInStation(input);
  c.hodlKeyResultSetup = () => null; // incomplete setups require a decision
  let asked = false;
  c.hodlKeyManagerDecision = async () => { asked = true; return "keep"; };
  assert.equal(await c.hodlCalculateKey({}), false);
  assert.equal(asked, true);
  assert.equal(c.hodlKeyManagerPending[0], input);
  assert.equal(c.hodlKeys.find(state => !state.isLab), existing);
  assert.equal(JSON.stringify(existing), before);
});

test("clearing Journal during a reviewed derivation prevents late prompts and commits", async () => {
  for (const pauseAt of ["derive", "fingerprint"]) {
    const { context: c, importFile } = importHarness();
    await importFile(legacyFile([legacyEntry()]));
    enableDerivation(c);
    c.hodlKeyManagerUseInStation(c.hodlKeyManagerPending[0]);
    let finish, entered, fingerprints = 0, decisions = 0;
    const waiting = new Promise(resolve => { entered = resolve; });
    const pause = () => { entered(); return new Promise(resolve => { finish = resolve; }); };
    const derive = c.hodlMnemonicWalletWithProgress;
    c.hodlMnemonicWalletWithProgress = async (...args) => {
      const result = await derive(...args);
      if (pauseAt === "derive") await pause();
      return result;
    };
    c.hodlConfirmKeyFingerprint = async () => {
      fingerprints++;
      if (pauseAt === "fingerprint") await pause();
      return true;
    };
    c.hodlKeyManagerDecideCommit = async () => { decisions++; return { kind: "append" }; };
    const pending = c.hodlCalculateKey({});
    await waiting;
    c.hodlJournalGeneration++;
    c.hodlKeyManagerPending = [];
    finish();
    await assert.rejects(pending, error => error.name === "HodlDerivationCancelledError");
    assert.equal(fingerprints, pauseAt === "derive" ? 0 : 1);
    assert.equal(decisions, 0);
    assert.equal(c.hodlKeys.filter(state => !state.isLab).length, 0);
  }
});

test("Review inputs then ordinary Derive preserves the saved chain", async () => {
  for (const network of ["signet", "regtest"]) {
    const { context: c, importFile } = importHarness();
    const entry = legacyEntry();
    Object.assign(entry.fields, { network, coinType: "1'", derivationPath: "m/84'/1'/0'/0/0" });
    await importFile(legacyFile([entry]));
    enableDerivation(c);
    c.hodlNetworkChoice = "mainnet";
    c.hodlNetworkFamily = value => value === "mainnet" ? "mainnet" : "testnet";
    c.hodlReadDerivationPlan = () => ({ network: "testnet", coinType: 1 });
    c.hodlKeyManagerUseInStation(c.hodlKeyManagerPending[0]);
    assert.equal(await c.hodlCalculateKey({}), true);
    assert.equal(c.hodlKeys[c.hodlActiveKey].result.network, network);
  }
});

test("an explicit Network choice replaces the reviewed input's saved chain", async () => {
  const { context: c, importFile } = importHarness();
  const entry = legacyEntry();
  Object.assign(entry.fields, { network: "signet", coinType: "1'", derivationPath: "m/84'/1'/0'/0/0" });
  await importFile(legacyFile([entry]));
  enableDerivation(c);
  c.hodlKeyManagerUseInStation(c.hodlKeyManagerPending[0]);
  Object.assign(c, { Event: class {}, CustomEvent: class {}, hodlNetworkDefault: "mainnet" });
  c.document = { getElementById: () => null, dispatchEvent() {} };
  runInNewContext(loadSlice("hodlApplyNetworkDefault"), c);
  c.hodlApplyNetworkDefault("regtest");
  c.document.getElementById = id => ({ value: c.hodlKeys[c.hodlActiveKey].fields[id] || "" });
  c.hodlNetworkFamily = value => value === "mainnet" ? "mainnet" : "testnet";
  c.hodlReadDerivationPlan = () => ({ network: "testnet", coinType: 1 });
  assert.equal(await c.hodlCalculateKey({}), true);
  assert.equal(c.hodlKeys[c.hodlActiveKey].result.network, "regtest");
});

test("Journal batch cancellation restores the draft and refuses a late derived result", async () => {
  const { context: c, importFile } = importHarness();
  await importFile(legacyFile([legacyEntry(), legacyEntry()]));
  const inputs = c.hodlKeyManagerPending.slice(), draft = c.hodlKeys[0];
  enableBatch(c);
  let finish, entered;
  const waiting = new Promise(resolve => { entered = resolve; });
  const derive = c.hodlMnemonicWalletWithProgress;
  c.hodlMnemonicWalletWithProgress = async (...args) => {
    const result = await derive(...args);
    entered();
    await new Promise(resolve => { finish = resolve; });
    return result;
  };
  const pending = c.hodlKeyManagerDeriveInputs(inputs);
  await waiting;
  c.hodlKeyManagerCancelDerivation();
  assert.equal(c.hodlKeys[0], draft);
  finish(); await pending;
  assert.equal(c.hodlKeys.filter(state => !state.isLab).length, 0);
  assert.equal(c.hodlKeyManagerPending.length, 2);
  assert.equal(c.hodlKeys[0], draft);
});

test("Journal batch cancellation of a warning preserves all remaining inputs", async () => {
  const { context: c, importFile } = importHarness();
  await importFile(legacyFile([legacyEntry(), legacyEntry()]));
  enableBatch(c);
  c.hodlLowEntropyWarning = () => ({ bits: 1, recommended: 128, words: 12 });
  c.hodlLowEntropyConfirm = { isAcknowledged: () => false, open: async () => false, close() {} };
  await c.hodlKeyManagerDeriveInputs(c.hodlKeyManagerPending.slice());
  assert.equal(c.hodlKeyManagerPending.length, 2);
  assert.equal(c.hodlKeys.filter(state => !state.isLab).length, 0);
});

test("Journal batch summary counts pending inputs outside the current import", async () => {
  const { context: c, importFile } = importHarness();
  await importFile(legacyFile([legacyEntry(), legacyEntry()]));
  const [older, current] = c.hodlKeyManagerPending;
  enableBatch(c);
  let summary;
  c.hodlTText = (text, vars) => { if (vars && "pending" in vars) summary = vars; return text; };
  await c.hodlKeyManagerDeriveInputs([current]);
  assert.equal(c.hodlKeyManagerPending[0], older);
  assert.equal(summary.added, 1);
  assert.equal(summary.pending, 1);
});

test("Journal batch teardown wipes its parked draft and cannot restore it later", async () => {
  const { context: c, importFile } = importHarness();
  await importFile(legacyFile([legacyEntry()]));
  const draft = c.hodlKeys[0];
  draft.fields.seed = WORDS;
  draft.fields.pass = new Uint8Array([19, 23]);
  const bytes = draft.fields.pass;
  enableBatch(c);
  let finish, entered;
  const waiting = new Promise(resolve => { entered = resolve; });
  c.hodlLowEntropyWarning = () => ({});
  c.hodlLowEntropyConfirm = { isAcknowledged: () => false, open: () => { entered(); return new Promise(resolve => { finish = resolve; }); }, close: () => finish(false) };
  const pending = c.hodlKeyManagerDeriveInputs(c.hodlKeyManagerPending.slice());
  await waiting;
  c.hodlKeyManagerCancelDerivation({ wipeDraft: true });
  await pending;
  assert.deepEqual([...bytes], [0, 0]);
  assert.equal(draft.fields.seed, "");
  assert.notEqual(c.hodlKeys[0], draft);
  assert.equal(c.hodlKeys[0].fields.seed, "");
  assert.equal(c.hodlJournalKeyDerivation, null);
});

test("Journal batch teardown still erases its parked draft when a warning or wallet wipe throws", async () => {
  const { context: c, importFile } = importHarness();
  await importFile(legacyFile([legacyEntry()]));
  const draft = c.hodlKeys[0];
  draft.fields.seed = WORDS; draft.fields.pass = new Uint8Array([7, 11]);
  const bytes = draft.fields.pass;
  enableBatch(c);
  let resolveWarning, entered;
  const waiting = new Promise(resolve => { entered = resolve; });
  c.hodlLowEntropyWarning = () => ({});
  c.hodlLowEntropyConfirm = {
    isAcknowledged: () => false,
    open: () => { entered(); return new Promise(resolve => { resolveWarning = resolve; }); },
    close: () => { resolveWarning(false); throw new Error("callback failure"); },
  };
  c.hodlWipeWalletKeys = () => { throw new Error("node wipe failure"); };
  const pending = c.hodlKeyManagerDeriveInputs(c.hodlKeyManagerPending.slice());
  await waiting;
  assert.doesNotThrow(() => c.hodlKeyManagerCancelDerivation({ wipeDraft: true }));
  await pending;
  assert.deepEqual([...bytes], [0, 0]);
  assert.equal(draft.fields.seed, "");
  assert.equal(c.hodlJournalKeyDerivation, null);
});

test("Journal reset clears source strings held by an interrupted import queue", async () => {
  const { context: c, importFile } = importHarness();
  await importFile(legacyFile([legacyEntry()]));
  const captured = c.hodlKeyManagerPending[0];
  Object.assign(c, { document: { getElementById: () => null }, hodlLiveWalletResults: () => new Set(), hodlWipeUnsharedWalletRows() {} });
  for (const name of ["hodlKeyManagerReset", "hodlKeyManagerWipeValue", "hodlKeyManagerDiscardInputs"])
    runInNewContext(loadSlice(name), c);
  c.hodlKeyManagerReset();
  assert.equal(captured.fields.seed, "");
  assert.equal(c.hodlKeyManagerPending.length, 0);
});

test("saved key derivation uses its explicit chain rather than an unrelated global picker", async () => {
  const { context: c, importFile } = importHarness();
  await importFile(legacyFile([legacyEntry()]));
  c.hodlKeyManagerUseInStation(c.hodlKeyManagerPending[0]);
  enableDerivation(c);
  c.hodlNetworkChoice = "regtest";
  c.hodlNetworkFamily = value => value === "mainnet" ? "mainnet" : "testnet";
  c.hodlReadDerivationPlan = () => ({ network: "testnet", coinType: 1 });
  assert.equal(await c.hodlCalculateKey({}, "derive", { networkChoice: "signet" }), true);
  assert.equal(c.hodlKeys[c.hodlActiveKey].result.network, "signet");
});

test("saved key derivation rejects unknown chains and chain/path family conflicts", async () => {
  for (const networkChoice of ["unknown-chain", "testnet"]) {
    const { context: c, importFile } = importHarness();
    await importFile(legacyFile([legacyEntry()]));
    c.hodlKeyManagerUseInStation(c.hodlKeyManagerPending[0]);
    enableDerivation(c);
    assert.equal(await c.hodlCalculateKey({}, "derive", { networkChoice }), false);
    assert.equal(c.hodlKeyManagerPending.length, 1);
    assert.equal(c.hodlKeys.some(state => !state.isLab), false);
  }
});

test("combined import previews before mutating and derives only the accepted new inputs", async () => {
  const { context: c } = importHarness();
  let decision = null, queued = null;
  c.hodlKeyManagerDecision = async () => decision;
  c.hodlKeyManagerDeriveInputs = async inputs => { queued = inputs; };
  c.hodlKeyManagerSyncDerivationUI = () => {};
  const text = legacyFile([legacyEntry()]);
  const file = { size: text.length, text: async () => text };
  await c.hodlKeyManagerImportFile(file, true);
  assert.equal(c.hodlKeyManagerPending.length, 0, "Cancel must leave the Journal unchanged");
  assert.equal(queued, null);
  decision = "derive";
  await c.hodlKeyManagerImportFile(file, true);
  assert.equal(c.hodlKeyManagerPending.length, 1);
  assert.equal(queued.length, 1);
  assert.equal(queued[0], c.hodlKeyManagerPending[0]);
});

test("invalid portable passphrases reject the entire import before preview or mutation", async () => {
  for (const archived of [false, true]) {
    const { context: c } = importHarness();
    let previews = 0, derivations = 0;
    c.hodlKeyManagerDecision = async () => { previews++; return "derive"; };
    c.hodlKeyManagerDeriveInputs = async () => { derivations++; };
    const invalid = legacyEntry(); invalid.fields.pass = { value: "must not coerce" };
    const text = archived ? legacyFile([legacyEntry()], [invalid]) : legacyFile([legacyEntry(), invalid]);
    await c.hodlKeyManagerImportFile({ size: text.length, text: async () => text }, true);
    assert.equal(previews, 0);
    assert.equal(derivations, 0);
    assert.equal(c.hodlKeyManagerPending.length, 0);
    assert.equal(c.hodlKeyManagerIgnored.length, 0);
    assert.equal(c.hodlKeys.length, 1);
  }
});

test("known capacity refusal happens before preview and is rechecked after an accepted preview", async () => {
  for (const fillBefore of [true, false]) {
    const { context: c } = importHarness();
    const fill = () => {
      while (c.hodlKeyManagerPending.length < KEY_VAULT_MAX_KEYS) c.hodlKeyManagerPending.push(c.hodlKeyManagerImportedState(legacyEntry()));
    };
    if (fillBefore) fill();
    let previews = 0;
    c.hodlKeyManagerDecision = async () => { previews++; fill(); return "derive"; };
    c.hodlKeyManagerDeriveInputs = async () => assert.fail("over-capacity import started derivation");
    const text = legacyFile([legacyEntry()]);
    await c.hodlKeyManagerImportFile({ size: text.length, text: async () => text }, true);
    assert.equal(previews, fillBefore ? 0 : 1);
    assert.equal(c.hodlKeyManagerPending.length, KEY_VAULT_MAX_KEYS);
  }
});

test("imports refuse busy derivation before reading and after every asynchronous boundary", async () => {
  for (const busyField of ["hodlActiveDerivation", "hodlJournalKeyDerivation"]) for (const stage of ["initial", "read", "decrypt", "preview"]) {
    const { context: c } = importHarness();
    const pending = c.hodlKeyManagerImportedState(legacyEntry()), archived = c.hodlKeyManagerImportedState(legacyEntry());
    c.hodlKeyManagerPending.push(pending);
    c.hodlKeyManagerIgnored.push(archived);
    c.hodlKeyManagerIds.add(keyVaultIdentity(pending));
    c.hodlKeyManagerActiveId = keyVaultIdentity(pending);
    const inventory = () => JSON.stringify([c.hodlKeys, c.hodlKeyManagerPending, c.hodlKeyManagerIgnored, [...c.hodlKeyManagerIds], c.hodlKeyManagerActiveId, c.hodlNextKeyId]);
    const before = inventory(), busy = {}, text = legacyFile([legacyEntry()], [legacyEntry()]);
    let reads = 0, opens = 0, previews = 0, derives = 0, status;
    if (stage === "initial") c[busyField] = busy;
    c.hodlJournalOpenExport = async content => { opens++; if (stage === "decrypt") c[busyField] = busy; return { kind: "key-manager", content }; };
    c.hodlKeyManagerDecision = async () => { previews++; if (stage === "preview") c[busyField] = busy; return "derive"; };
    c.hodlKeyManagerDeriveInputs = async () => { derives++; };
    c.hodlKeyManagerStatus = (text, error) => { status = { text, error }; };
    await c.hodlKeyManagerImportFile({ size: text.length, text: async () => { reads++; if (stage === "read") c[busyField] = busy; return text; } }, true);
    assert.equal(inventory(), before, `${busyField} at ${stage} must not install inputs`);
    assert.equal(c[busyField], busy, "the existing derivation must remain owned by its controller");
    assert.equal(reads, stage === "initial" ? 0 : 1);
    assert.equal(opens, ["initial", "read"].includes(stage) ? 0 : 1);
    assert.equal(previews, stage === "preview" ? 1 : 0);
    assert.equal(derives, 0);
    assert.equal(status?.error, true);
    assert.ok(status.text, "the refused import needs a visible explanation");
  }
});

test("archive-only import reports archived inputs and never starts derivation", async () => {
  const { context: c } = importHarness();
  let summary;
  c.hodlTText = (text, vars) => { if (vars && "archived" in vars) summary = vars; return text; };
  c.hodlKeyManagerDecision = async () => "import";
  c.hodlKeyManagerDeriveInputs = async () => assert.fail("archive-only import started derivation");
  const text = legacyFile([], [legacyEntry(), legacyEntry()]);
  await c.hodlKeyManagerImportFile({ size: text.length, text: async () => text }, true);
  assert.equal(c.hodlKeyManagerIgnored.length, 2);
  assert.equal(c.hodlKeyManagerPending.length, 0);
  assert.deepEqual(JSON.parse(JSON.stringify(summary)), { n: 0, archived: 2 });
});

test("combined import cannot install inputs after its Journal was cleared during preview", async () => {
  const { context: c } = importHarness();
  c.hodlKeyManagerDecision = async () => { c.hodlJournalGeneration++; return "derive"; };
  c.hodlKeyManagerDeriveInputs = async () => assert.fail("a stale preview derived keys");
  const text = legacyFile([legacyEntry()]);
  await c.hodlKeyManagerImportFile({ size: text.length, text: async () => text }, true);
  assert.equal(c.hodlKeyManagerPending.length, 0);
});

test("combined import ignores a slower file after a newer file was selected", async () => {
  const { context: c } = importHarness();
  let release;
  c.hodlKeyManagerDecision = async () => "derive";
  c.hodlKeyManagerDeriveInputs = async () => {};
  const older = legacyEntry(), newer = legacyEntry();
  older.name = "Older"; newer.name = "Newer";
  const first = c.hodlKeyManagerImportFile({ size: 10, text: () => new Promise(resolve => { release = resolve; }) }, true);
  await c.hodlKeyManagerImportFile({ size: 10, text: async () => legacyFile([newer]) }, true);
  release(legacyFile([older])); await first;
  assert.deepEqual(Array.from(c.hodlKeyManagerPending, input => input.name), ["Newer"]);
});

test("reviewing imported inputs asks before replacing a nonempty draft", async () => {
  const { context: c, importFile } = importHarness();
  await importFile(legacyFile([legacyEntry()]));
  const input = c.hodlKeyManagerPending[0], draft = c.hodlKeys[0];
  draft.fields.dice = "123456";
  c.hodlKeyManagerDecision = async () => null;
  c.hodlKeyManagerDiscardInputs = () => {};
  runInNewContext(loadSlice("hodlKeyManagerReviewInputs"), c);
  await c.hodlKeyManagerReviewInputs(input);
  assert.equal(c.hodlKeys[0], draft);
  assert.equal(draft.fields.dice, "123456");
  c.hodlKeyManagerDecision = async () => "load";
  await c.hodlKeyManagerReviewInputs(input);
  assert.equal(c.hodlKeys[0].fields.seed, WORDS);
  assert.equal(c.hodlKeyManagerPending[0], input);
});

test("only a successful fresh derivation retires an imported input and publishes the genuine wallet", async () => {
  const { context: c, importFile } = importHarness();
  await importFile(legacyFile([legacyEntry()]));
  const imported = c.hodlKeyManagerPending[0], oldIdentity = keyVaultIdentity(imported);
  c.hodlKeyManagerUseInStation(imported);
  enableDerivation(c);
  assert.equal(await c.hodlCalculateKey({}), true);
  const derived = c.hodlKeys[c.hodlActiveKey];
  assert.equal(derived.isLab, false);
  assert.equal(derived.name, imported.name, "deriving imported inputs retains their user-assigned label");
  assert.equal(derived.result.address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
  assert.equal(derived.result.mnemonic, WORDS);
  assert.ok(!JSON.stringify(derived.result).includes("forged"));
  assert.equal(c.hodlKeyManagerPending.length, 0);
  assert.equal(c.hodlKeyManagerIds.has(oldIdentity), false);
  assert.equal(c.hodlKeyManagerIds.has(keyVaultIdentity(derived)), true);
  assert.equal(parseKeyVault(serializeKeyVault([derived])).keys[0].result, null, "even a genuine export must be rederived next time");
});

test("two wallets sharing a master fingerprint stay two keys in the station and the Key Manager (GHSA-6rr2-5r82-grwc sibling)", async () => {
  // Both seeds are valid BIP39 with master fingerprint 5c86104e (found by
  // brute force, 127,677 trials); their wallets differ. Fingerprint-keyed
  // dedup collapsed them into one tab and one vault identity: the second
  // wallet never reached a downloaded key file.
  const seedA = "abandon arm moon abandon abandon abandon abandon abandon abandon abandon abandon ability";
  const seedB = "abandon auto pyramid abandon abandon abandon abandon abandon abandon abandon abandon abstract";
  const { context: c, importFile } = importHarness();
  const deriveThrough = async (seed, id) => {
    const entry = legacyEntry();
    entry.id = id;
    entry.importedKeyId = id;
    entry.fields.seed = seed;
    await importFile(legacyFile([entry]));
    c.hodlKeyManagerUseInStation(c.hodlKeyManagerPending[c.hodlKeyManagerPending.length - 1]);
    assert.equal(await c.hodlCalculateKey({}), true, "derivation for " + seed.split(" ")[1]);
  };
  enableDerivation(c);
  await deriveThrough(seedA, 1);
  await deriveThrough(seedB, 2);
  const tabs = c.hodlKeys.filter((state) => !state.isLab && state.result);
  assert.equal(tabs.length, 2, "the second wallet did not get its own tab");
  assert.equal(tabs[0].name, "Imported");
  assert.equal(tabs[1].name, "Imported (1)", "different imported wallets retain distinguishable labels");
  assert.equal(tabs[0].result.masterFingerprint, "5c86104e");
  assert.equal(tabs[1].result.masterFingerprint, "5c86104e", "the fixture no longer collides");
  assert.notEqual(tabs[0].result.masterIdentity, tabs[1].result.masterIdentity);
  assert.notEqual(keyVaultIdentity(tabs[0]), keyVaultIdentity(tabs[1]), "the vault merges the two wallets");
  const states = c.hodlKeyManagerStates();
  assert.equal(states.length, 2, "the Key Manager (and its Download) collapses the colliding wallets into one");
  // Same-wallet re-derivation still updates in place.
  await deriveThrough(seedA, 3);
  assert.equal(c.hodlKeys.filter((state) => !state.isLab && state.result).length, 2, "re-deriving an existing wallet added a duplicate tab");
  assert.equal(c.hodlKeys[c.hodlActiveKey].name, "Imported", "a repeated import preserves the existing station label");
});

test("key-manager journal events never log the wallet identity (#534 review)", async () => {
  // The journal persists, so a keyVaultIdentity detail would write the root
  // xpub's contents (chain code + pubkey) into it — a permanent, linkable
  // identifier. Every key-manager event must log the journal-safe label.
  const { context: c, calls, importFile } = importHarness();
  const entry = legacyEntry();
  entry.fields.seed = "abandon arm moon abandon abandon abandon abandon abandon abandon abandon abandon ability";
  await importFile(legacyFile([entry]));
  c.hodlKeyManagerUseInStation(c.hodlKeyManagerPending[0]);
  enableDerivation(c);
  assert.equal(await c.hodlCalculateKey({}), true);
  const state = c.hodlKeys.find((item) => !item.isLab && item.result);
  assert.ok(state?.result?.masterIdentity, "the fixture derives a master identity");
  calls.length = 0;
  c.hodlKeyManagerUseInStation(state);
  c.hodlKeyManagerDetachFromStation(state);
  c.hodlKeyManagerIgnore(state);
  await c.hodlKeyManagerRestoreIgnored(c.hodlKeyManagerIgnored[0]);
  const events = calls.filter((call) => call[0]?.startsWith?.("key-manager-"));
  assert.deepEqual(events.map(([kind]) => kind), ["key-manager-use", "key-manager-ignore", "key-manager-restore"]);
  for (const call of events) {
    const detail = String(call[1]);
    assert.ok(!detail.includes(state.result.masterIdentity) && !detail.includes(state.result.rootXpub),
      `${call[0]} logged the wallet identity: ${detail.slice(0, 40)}…`);
    assert.ok(detail === "5c86104e" || detail.startsWith("key-"), `${call[0]} logged an unexpected detail: ${detail}`);
  }
});

test("selecting, detaching, archiving and restoring a wallet setup preserves its sibling", async () => {
  const { context: c } = importHarness();
  c.hodlInvalidateDerivation = () => {};
  const first = c.hodlNewKeyState("First account"), second = c.hodlNewKeyState("Second account");
  first.result = { masterIdentity: "shared-wallet", masterFingerprint: "deadbeef" };
  second.result = { masterIdentity: "shared-wallet", masterFingerprint: "deadbeef" };
  first.fields.derivationPath = "m/84'/0'/0'/0/0";
  second.fields.derivationPath = "m/84'/0'/1'/0/0";
  c.hodlKeys.push(first, second);
  const before = JSON.stringify(first);
  c.hodlKeyManagerUseInStation(second);
  assert.equal(c.hodlKeys[c.hodlActiveKey], second, "opening an alternate setup selected its sibling");
  c.hodlKeyManagerDetachFromStation(second);
  assert.equal(c.hodlKeyManagerPending[0], second);
  assert.equal(c.hodlKeys.includes(first), true);
  c.hodlKeyManagerIgnore(second);
  assert.equal(c.hodlKeyManagerPending.length, 0);
  assert.equal(c.hodlKeyManagerIgnored.length, 1);
  assert.equal(c.hodlKeyManagerIgnored[0].fields.derivationPath, "m/84'/0'/1'/0/0");
  await c.hodlKeyManagerRestoreIgnored(c.hodlKeyManagerIgnored[0]);
  assert.equal(c.hodlKeyManagerIgnored.length, 0);
  assert.equal(c.hodlKeyManagerPending.length, 1, "restoring an archived setup incorrectly reused its live sibling");
  const restored = c.hodlKeyManagerPending[0];
  assert.equal(restored.fields.derivationPath, "m/84'/0'/1'/0/0");
  assert.equal(restored.result, null);
  assert.equal(restored.needsDerivation, true);
  assert.equal(c.hodlKeyManagerActiveId, keyVaultIdentity(restored));
  assert.equal(JSON.stringify(first), before, "the other setup was changed");
  assert.deepEqual(Array.from(c.hodlKeyManagerStates(), (state) => state.fields.derivationPath),
    ["m/84'/0'/0'/0/0", "m/84'/0'/1'/0/0"]);
});

test("invalid source inputs cannot fall back to the imported cached wallet", async () => {
  const { context: c, importFile } = importHarness();
  const entry = legacyEntry();
  entry.fields.seed = "invalid source words";
  await importFile(legacyFile([entry]));
  c.hodlKeyManagerUseInStation(c.hodlKeyManagerPending[0]);
  enableDerivation(c);
  assert.equal(await c.hodlCalculateKey({}), false);
  assert.equal(c.hodlWalletResult, null);
  assert.equal(c.hodlKeyManagerPending.length, 1);
  assert.equal(c.hodlKeys.every(state => !state.result), true);
});

// The real table renderer and its shared escaping and copy helpers, without
// the unrelated page state initialized alongside the app's reveal flag.
const readouts = await loadAppFunctions(["hodlPublicInlineHtml", "hodlPrivateCopyButton"]);
const source = [
  loadSlice("hodlEscapeHtml"),
  loadSlice("hodlDisplayDerivationPath"),
  loadSlice("hodlAddressIndexHtml"),
  loadSlice("hodlPrivateValue"),
  loadSlice("hodlAddressTableRows"),
].join("\n");
const loadRows = (revealPrivate = false) =>
  new Function("hodlRevealPrivate", "hodlT", "hodlTText", "hodlTAttr", "hodlAddressQrButton", "hodlPublicInlineHtml", "hodlPrivateCopyButton", `${source}; return hodlAddressTableRows;`)(
    revealPrivate, t, t, tAttr, addressQrButtonHtml, readouts.hodlPublicInlineHtml, readouts.hodlPrivateCopyButton,
  );

const ATTACK_INDEX = '<svg onload="alert(document.domain)">';
const craftedRow = { index: ATTACK_INDEX, path: "m/84'/0'/0'/0/0", address: "bc1qexampleaddress000000000000000000000000" };

test("legacy vault caches are discarded before rendering or identity matching (#425)", () => {
  const entry = {
    id: 7,
    number: 2,
    name: "Imported key",
    createdAt: "2026-09-03T12:00:00.000Z",
    fields: { seed: "user supplied words" },
    result: { masterFingerprint: "deadbeef", kind: "hd", accounts: [{ rows: [craftedRow] }] },
  };
  const [parsed] = parseKeyVault(JSON.stringify({ format: "entropylab-key-manager", version: 1, keys: [entry] })).keys;
  assert.equal(parsed.result, null);
  assert.equal(parsed.needsDerivation, true);
  assert.equal(parsed.id, undefined);
  assert.equal(parsed.fields.seed, entry.fields.seed);
});

test("the address table renders a crafted index as inert text (issue #389)", () => {
  const html = loadRows()([craftedRow]);
  assert.ok(!html.includes("<svg"), "no element markup from the import");
  assert.ok(!html.includes('onload="'), "no live event-handler attribute");
  assert.ok(html.includes("&lt;svg onload=&quot;alert(document.domain)&quot;&gt;"), "the payload shows as escaped text");
  // Same guarantee with the private-sheet column enabled.
  const wifHtml = loadRows(true)([{ ...craftedRow, wif: "L1xWifExample" }]);
  assert.ok(!wifHtml.includes("<svg"));
});

test("legitimate numeric indexes render unchanged", () => {
  const html = loadRows()([
    { index: 0, path: "m/84'/0'/0'/0/0", address: "bc1qzero" },
    { index: 2147483647, path: "m/84'/0'/0'/1", address: "bc1qmax" },
  ]);
  assert.ok(html.includes('<th scope="row">0</th>'));
  assert.ok(html.includes('<th scope="row">2147483647</th>'));
  // Other non-integer shapes degrade to escaped text, never to markup.
  for (const index of [-1, 1.5, "3", null, undefined, '3<img src=x onerror=alert(1)>']) {
    const cell = loadRows()([{ index, path: "m/0/0", address: "bc1qx" }]);
    assert.ok(!cell.includes("<img"), `index ${String(index)} stays inert`);
    assert.ok(!/<th scope="row"><\/th>/.test(cell) || index == null, "only nullish indexes render empty");
  }
});

test("multisig address indexes route through the index guard", () => {
  // The lead-address block is gone; the branch tables are where a multisig
  // index still reaches markup, and they must keep using the guard.
  const rows = loadSlice("hodlAddressTableRows");
  assert.ok(rows.includes("hodlAddressIndexHtml("), "address rows use the index guard");
});
