import { test } from "node:test";
import assert from "node:assert/strict";
import { runInNewContext } from "node:vm";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  KEY_VAULT_FORMAT,
  KEY_VAULT_MAX_KEYS,
  KEY_VAULT_VERSION,
  keyVaultIdentity,
  parseKeyVault,
  serializeKeyVault,
} from "../src/js/keymanager.js";
import { createDocument, openExport, sealExport } from "../src/js/journal.js";
import * as keyManager from "../src/js/keymanager.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");
const password = "correct horse battery staple";

function stationHarness(keys, pending, ignored = []) {
  const source = read("src/js/app.js");
  const slice = (name, next) => source.slice(source.indexOf(`function ${name}(`), source.indexOf(`function ${next}(`));
  const calls = [];
  const context = {
    hodlKeys: keys, hodlKeyManagerPending: pending, hodlKeyManagerIgnored: ignored,
    hodlActiveKey: 0, hodlActiveDerivation: null, hodlJournalKeyDerivation: null, keyVaultIdentity,
    document: { getElementById: () => null },
    hodlJournalLog: (...args) => calls.push(args),
    hodlInvalidateDerivation: () => calls.push(["invalidate"]),
    hodlRenderKeyTabs: () => calls.push(["tabs"]),
    hodlKeyManagerRender: () => calls.push(["manager"]),
    hodlShowWorkspace: (id) => calls.push(["workspace", id]),
  };
  runInNewContext(slice("hodlKeyManagerStates", "hodlKeyManagerEntry") +
    slice("hodlKeyLogLabel", "hodlKeyManagerImportedState") +
    slice("hodlKeyManagerUseInStation", "hodlKeyManagerIgnore"), context);
  return { context, calls };
}

test("using a key transfers only that pending input, preserving existing and archived keys", () => {
  const existing = key(), first = key({ id: 8, result: { masterFingerprint: "11111111" } }),
    second = key({ id: 9, result: { masterFingerprint: "22222222" } }), ignored = key({ id: 10, name: "Ignored" });
  const lab = { isLab: true, fields: { seed: "unfinished input" } };
  const keys = [lab, existing], pending = [first, second], ignoredKeys = [ignored];
  const before = JSON.stringify([first, second, lab, ignored]);
  const { context, calls } = stationHarness(keys, pending, ignoredKeys);
  context.hodlKeyManagerUseInStation(first);
  assert.deepEqual(keys, [lab, existing, first]);
  assert.deepEqual(pending, [second]);
  assert.equal(context.hodlActiveKey, 2);
  assert.equal(JSON.stringify([first, second, lab, ignored]), before);
  assert.deepEqual(ignoredKeys, [ignored]);
  assert.deepEqual(calls, [
    ["invalidate"],
    ["tabs"], ["key-manager-use", "11111111", "journal"], ["workspace", "calc"],
  ]);
  calls.length = 0;
  context.hodlKeyManagerUseInStation(second);
  assert.deepEqual(keys, [lab, existing, first, second]);
  assert.equal(pending.length, 0);
  assert.equal(context.hodlActiveKey, 3);
  assert.deepEqual(calls, [["invalidate"], ["tabs"], ["key-manager-use", "22222222", "journal"], ["workspace", "calc"]]);
  context.hodlKeyManagerUseInStation(second);
  assert.equal(keys.length, 4);
  assert.equal(context.hodlActiveKey, 3, "repeated activation focuses the same key");
  assert.equal(JSON.stringify([first, second, lab, ignored]), before);
});

test("using the same entry identity focuses the existing key after invalidating derivation", () => {
  const existing = key(), duplicate = key({ name: "Duplicate" });
  const { context, calls } = stationHarness([existing], [duplicate]);
  context.hodlKeyManagerUseInStation(duplicate);
  assert.equal(context.hodlKeys.length, 1);
  assert.equal(context.hodlKeys[0], existing);
  assert.equal(context.hodlActiveKey, 0);
  assert.deepEqual(context.hodlKeyManagerPending, [duplicate]);
  assert.deepEqual(calls, [["invalidate"], ["tabs"], ["key-manager-use", "deadbeef", "journal"], ["workspace", "calc"]]);
});

test("Journal keeps distinct configurations of one wallet and deduplicates only the same entry", () => {
  const mainnet = key({ id: 7, result: { masterIdentity: "same-wallet", network: "mainnet" } });
  const testnet = key({ id: 8, fields: { ...mainnet.fields, network: "testnet", derivationPath: "m/84'/1'/0'/0/0" },
    result: { masterIdentity: "same-wallet", network: "testnet" } });
  const { context } = stationHarness([mainnet], [mainnet, testnet]);
  const states = context.hodlKeyManagerStates();
  assert.equal(states.length, 2, "a distinct network/path setup was omitted from Journal");
  assert.equal(states[0], mainnet);
  assert.equal(states[1], testnet);
  context.hodlKeyManagerUseInStation(testnet);
  assert.deepEqual(context.hodlKeys, [mainnet, testnet], "activation focused another setup of the wallet");
  assert.equal(context.hodlKeys[context.hodlActiveKey], testnet);
  assert.deepEqual(context.hodlKeyManagerPending, [mainnet]);
  assert.deepEqual(parseKeyVault(serializeKeyVault(context.hodlKeyManagerStates())).keys.map((entry) => entry.fields.derivationPath),
    ["m/84'/0'/0'/0/0", "m/84'/1'/0'/0/0"]);
});

test("using a key outside the pending collection cannot install it", () => {
  const { context, calls } = stationHarness([], []);
  context.hodlKeyManagerUseInStation(key());
  assert.deepEqual(context.hodlKeys, []);
  assert.deepEqual(context.hodlKeyManagerPending, []);
  assert.ok(!calls.some(([kind]) => kind === "workspace" || kind === "key-manager-use"));
});

test("bulk reopening moves verified detached keys once without deriving or changing their sources", () => {
  const existing = key({ result: { masterIdentity: "same-wallet", masterFingerprint: "11111111" } });
  const first = key({ id: 8, name: "Other setup", result: { masterIdentity: "same-wallet", masterFingerprint: "11111111" }, fields: { seed: "saved source", derivationPath: "m/84'/0'/1'/0/0" } });
  const second = key({ id: 9, name: "Another wallet", result: { masterIdentity: "another-wallet", masterFingerprint: "22222222" } });
  const unverified = key({ id: 10, needsDerivation: true, result: { masterIdentity: "file-supplied-cache" } });
  const missing = key({ id: 11, result: null }), archived = key({ id: 12 });
  const lab = { id: 0, isLab: true, fields: { seed: "unfinished draft", pass: Uint8Array.of(13, 17) } };
  const keys = [lab, existing], pending = [unverified, first, missing, second], ignored = [archived];
  const before = JSON.stringify([lab, existing, first, second, unverified, missing, archived]);
  const { context, calls } = stationHarness(keys, pending, ignored);
  context.hodlCalculateKey = context.hodlKeyManagerDeriveInputs = () => assert.fail("reopening verified keys must not derive them again");
  context.hodlKeyManagerUseAllInStation();
  assert.deepEqual(keys, [lab, existing, first, second]);
  assert.deepEqual(pending, [unverified, missing]);
  assert.deepEqual(ignored, [archived]);
  assert.equal(keys[context.hodlActiveKey], first);
  assert.equal(JSON.stringify([lab, existing, first, second, unverified, missing, archived]), before);
  assert.deepEqual(calls.filter(([kind]) => kind === "key-manager-use").map(([, fingerprint]) => fingerprint), ["11111111", "22222222"]);
  assert.deepEqual(calls.filter(([kind]) => kind === "workspace"), [["workspace", "calc"]]);
  assert.equal(calls.filter(([kind]) => kind === "tabs").length, 1, "bulk reopening should render its destination once");
  calls.length = 0;
  context.hodlKeyManagerUseAllInStation();
  assert.deepEqual(calls, [], "repeated activation cannot reinstall or derive keys");
  assert.deepEqual(keys, [lab, existing, first, second]);
});

test("bulk reopening excludes an entry already in Station and refuses either busy controller", () => {
  const existing = key(), duplicate = key({ name: "Same entry" });
  const idle = stationHarness([existing], [duplicate]);
  idle.context.hodlKeyManagerUseAllInStation();
  assert.deepEqual(idle.context.hodlKeys, [existing]);
  assert.deepEqual(idle.context.hodlKeyManagerPending, [duplicate]);
  assert.deepEqual(idle.calls, []);
  for (const busy of ["hodlActiveDerivation", "hodlJournalKeyDerivation"]) {
    const first = key({ id: 8 }), second = key({ id: 9 });
    const { context, calls } = stationHarness([existing], [first, second]);
    const control = context[busy] = {};
    context.hodlKeyManagerUseAllInStation();
    assert.deepEqual(context.hodlKeys, [existing]);
    assert.deepEqual(context.hodlKeyManagerPending, [first, second]);
    assert.equal(context[busy], control);
    assert.deepEqual(calls, []);
  }
});

function key(overrides = {}) {
  return {
    id: 7,
    number: 2,
    name: "Cold storage",
    createdAt: "2026-09-03T12:00:00.000Z",
    fields: { derivationPath: "m/84'/0'/0'/0/0", seed: "user supplied words" },
    result: { masterFingerprint: "deadbeef", rootXpub: "xpub-example", rootXprv: "xprv-example" },
    reveal: true,
    error: "stale error",
    ...overrides,
  };
}

test("Key Manager payloads round-trip and clear transient UI state", () => {
  const text = serializeKeyVault([key()], [key({ id: 8, name: "Ignored", result: { masterFingerprint: "a1b2c3d4" } })]);
  const raw = JSON.parse(text);
  assert.equal(raw.format, KEY_VAULT_FORMAT);
  assert.equal(raw.version, KEY_VAULT_VERSION);
  assert.equal(raw.keys[0].reveal, false);
  assert.equal(raw.keys[0].error, "");
  assert.equal(raw.keys[0].errorSpec, undefined);
  assert.equal(raw.ignoredKeys[0].name, "Ignored");
  assert.deepEqual(parseKeyVault(text), { keys: raw.keys, ignoredKeys: raw.ignoredKeys });
  assert.equal(raw.keys[0].result, null);
  assert.equal(raw.keys[0].needsDerivation, true);
  assert.equal(keyVaultIdentity(raw.keys[0]), "", "file claims cannot supply a trusted identity");
});

test("Key Manager payload validation rejects malformed or oversized files", () => {
  assert.throws(() => parseKeyVault("not json"), /not valid Key Manager JSON/);
  assert.throws(() => parseKeyVault('{"format":"other","version":1,"keys":[]}'), /not a supported/);
  assert.throws(() => serializeKeyVault([{ name: "missing state" }]), /invalid key/);
  assert.throws(() => serializeKeyVault(Array.from({ length: KEY_VAULT_MAX_KEYS + 1 }, () => key())), /too many keys/);
  assert.throws(() => serializeKeyVault([key({ isLab: true })]), /invalid key/);
});

// Portable source inputs must never invent a passphrase through coercion.
// A missing passphrase and any exact string are accepted; present non-text
// values are refused in both active and archived inputs before restoration.
test("portable passphrases preserve exact text and reject every non-text JSON type", () => {
  for (const version of [1, KEY_VAULT_VERSION]) {
    for (const pass of ["", " words ", "\uFEFFleading BOM", "e\u0301", "line\nnext"]) {
      const state = key({ fields: { seed: "source words", pass } });
      const parsed = parseKeyVault(JSON.stringify({ format: KEY_VAULT_FORMAT, version, keys: [state], ignoredKeys: [state] }));
      assert.equal(parsed.keys[0].fields.pass, pass);
      assert.equal(parsed.ignoredKeys[0].fields.pass, pass);
      assert.equal(parseKeyVault(serializeKeyVault([state])).keys[0].fields.pass, pass);
    }
    for (const pass of [null, false, true, 0, 1, [], ["words"], {}, { value: "words" }]) {
      for (const archived of [false, true]) {
        const state = key({ fields: { seed: "source words", pass } });
        const file = JSON.stringify({ format: KEY_VAULT_FORMAT, version, keys: archived ? [] : [state], ignoredKeys: archived ? [state] : [] });
        assert.throws(() => parseKeyVault(file), { name: "Error" }, `accepted ${JSON.stringify(pass)} in ${archived ? "archived" : "active"} inputs`);
      }
    }
    assert.equal(parseKeyVault(JSON.stringify({ format: KEY_VAULT_FORMAT, version, keys: [key()] })).keys[0].fields.pass, undefined);
  }
});

test("key exports preserve the freshly derived chain without trusting imported result caches", () => {
  for (const network of ["mainnet", "testnet", "signet", "regtest"]) {
    const state = key({ fields: { network: "mainnet", seed: "input words" }, result: { network } });
    const opened = parseKeyVault(serializeKeyVault([state], [state]));
    assert.equal(opened.keys[0].fields.network, network);
    assert.equal(opened.ignoredKeys[0].fields.network, network);
    assert.equal(state.fields.network, "mainnet", "export changed the live input settings");
    const imported = parseKeyVault(JSON.stringify({ format: KEY_VAULT_FORMAT, version: KEY_VAULT_VERSION, keys: [state] }));
    assert.equal(imported.keys[0].fields.network, "mainnet", "a cached result overrode the file's input settings");
    assert.equal(imported.keys[0].result, null);
    assert.equal(parseKeyVault(serializeKeyVault(imported.keys)).keys[0].fields.network, "mainnet");
  }
  for (const overrides of [{ id: undefined }, { id: "7" }, { needsDerivation: true }, { result: { network: "invalid" } }]) {
    const state = key({ fields: { network: "mainnet" }, result: { network: "regtest" }, ...overrides });
    assert.equal(parseKeyVault(serializeKeyVault([state])).keys[0].fields.network, "mainnet");
  }
});

test("key exports preserve supported source entropy assessments and omit malformed assessments", () => {
  for (const globalSyncSourceBits of [null, "unknown", 0, 2.584962500721156, 256]) {
    const state = key({ globalSync: true, globalSyncSource: "dice:coldcard", globalSyncBitCount: 256, globalSyncSourceBits });
    const exported = JSON.parse(serializeKeyVault([state], [state]));
    for (const entry of [exported.keys[0], exported.ignoredKeys[0]]) {
      assert.equal(entry.globalSyncSourceBits, globalSyncSourceBits);
      assert.equal(entry.globalSyncBitCount, 256);
    }
  }
  for (const globalSyncSourceBits of [-1, NaN, Infinity, "256", true, [], {}]) {
    const state = key({ globalSyncSourceBits });
    assert.equal(JSON.parse(serializeKeyVault([state])).keys[0].globalSyncSourceBits, undefined);
    if (Number.isNaN(globalSyncSourceBits) || globalSyncSourceBits === Infinity) continue;
    const file = JSON.stringify({ format: KEY_VAULT_FORMAT, version: KEY_VAULT_VERSION, keys: [state] });
    assert.equal(parseKeyVault(file).keys[0].globalSyncSourceBits, undefined);
  }
});

test("synced key imports never trust file-supplied entropy assessments", () => {
  // A digest can have 256 bits while its source was a single die roll.
  // Neither a claimed assessment nor its absence proves source entropy.
  const fields = { ...key().fields, dice: "1", hex: "00".repeat(32) };
  for (const version of [1, KEY_VAULT_VERSION]) {
    for (const globalSyncSourceBits of [256, undefined, null, "unknown", 0, 2.584962500721156, -1, "256", true, [], {}]) {
      const state = key({ fields, globalSync: true, globalSyncSource: "dice:coldcard", globalSyncBitCount: 256, globalSyncSourceBits });
      const file = JSON.stringify({ format: KEY_VAULT_FORMAT, version, keys: [state], ignoredKeys: [state] });
      const opened = parseKeyVault(file);
      for (const entry of [opened.keys[0], opened.ignoredKeys[0]]) {
        assert.equal(entry.globalSyncSourceBits, "unknown", "imported metadata was accepted as evidence of source entropy");
        assert.equal(entry.globalSyncSource, "dice:coldcard");
        assert.equal(entry.globalSyncBitCount, 256);
        assert.deepEqual(entry.fields, fields, "normalizing an assessment changed the source inputs");
      }
      const restored = parseKeyVault(serializeKeyVault([state], [state]));
      assert.equal(restored.keys[0].globalSyncSourceBits, "unknown");
      assert.equal(restored.ignoredKeys[0].globalSyncSourceBits, "unknown");
      assert.equal(state.globalSyncSourceBits, globalSyncSourceBits, "import changed the live state");
    }
  }
});

function freshResult() {
  const privateNode = { get privateExtendedKey() { throw new Error("projection read private material"); } };
  return {
    kind: "hd", network: "mainnet", coinType: 0, imported: false,
    purposeMatch: true, originalPurpose: { index: 84, hardened: true },
    entropy: new Uint8Array([1, 2]), seed: new Uint8Array([3, 4]), rootNode: privateNode,
    accounts: [{ def: { id: "bip84", script: "p2wpkh" }, network: "mainnet", accountPath: "m/84'/0'/0'",
      importedFamily: null, branchHardened: false, addressHardened: false,
      branchStart: 0, branchRange: 1, privateNode,
      addressBranches: [{ branch: 0, rows: [{ index: 0, path: "m/84'/0'/0'/0/0" }] }],
    }],
  };
}

test("fresh key setup projection is deterministic and contains no private values", () => {
  const result = freshResult();
  const expected = {
    kind: "hd", network: "mainnet", selectedScript: "bip84", coinType: 0,
    purposeMatch: true, originalPurpose: { index: 84, hardened: true }, brainWalletOutput: null,
    capabilities: { mnemonic: true, seed: true, rootPrivate: true, singlePrivate: false, minikey: false },
    accounts: [{ script: "p2wpkh", accountPath: "m/84'/0'/0'", importedFamily: null,
      branchHardened: false, addressHardened: false, privateAvailable: true,
      branches: [{ branch: 0, rows: [{ index: 0, path: "m/84'/0'/0'/0/0" }] }],
    }],
  };
  const setup = keyManager.keyResultSetup(result, "bip84");
  assert.deepEqual(setup, expected);
  assert.equal(JSON.stringify(keyManager.keyResultSetup(result, "bip84")), JSON.stringify(expected));
  assert.deepEqual([...result.entropy], [1, 2]);
  assert.deepEqual([...result.seed], [3, 4]);
  result.accounts[0].addressBranches[0].rows[0].path = "changed afterwards";
  assert.deepEqual(setup, expected, "the projection retained mutable result objects");
});

test("fresh setup differences cover chains, paths, ranges, scripts, hardening and recovery capabilities", () => {
  const baseline = JSON.stringify(keyManager.keyResultSetup(freshResult(), "bip84"));
  const mutations = [
    (r) => { r.network = r.accounts[0].network = "testnet"; },
    (r) => { r.network = r.accounts[0].network = "signet"; },
    (r) => { r.network = r.accounts[0].network = "regtest"; },
    (r) => { r.coinType = 1; },
    (r) => { r.accounts[0].accountPath = "m/84'/0'/1'"; r.accounts[0].addressBranches[0].rows[0].path = "m/84'/0'/1'/0/0"; },
    (r) => { r.accounts[0].addressBranches[0].rows.push({ index: 1, path: "m/84'/0'/0'/0/1" }); },
    (r) => { r.accounts[0].addressBranches[0].rows = [{ index: 5, path: "m/84'/0'/0'/0/5" }]; },
    (r) => { r.accounts[0].branchRange = 2; r.accounts[0].addressBranches.push({ branch: 1, rows: [{ index: 0, path: "m/84'/0'/0'/1/0" }] }); },
    (r) => { r.accounts[0].branchHardened = true; r.accounts[0].addressBranches[0].rows[0].path = "m/84'/0'/0'/0'/0"; },
    (r) => { r.accounts[0].addressHardened = true; r.accounts[0].addressBranches[0].rows[0].path = "m/84'/0'/0'/0/0'"; },
    (r) => { r.accounts[0].def.script = "p2tr"; },
    (r) => { r.purposeMatch = false; },
    (r) => { r.originalPurpose = { index: 49, hardened: true }; },
    (r) => { r.entropy = null; }, (r) => { r.seed = null; },
    (r) => { r.rootNode = null; }, (r) => { r.accounts[0].privateNode = null; },
    (r) => { r.brainWalletOutput = "hd"; },
  ];
  for (const mutate of mutations) {
    const result = freshResult();
    mutate(result);
    const setup = keyManager.keyResultSetup(result, "bip84");
    assert.ok(setup, mutate.toString());
    assert.notEqual(JSON.stringify(setup), baseline, mutate.toString());
  }
  assert.notEqual(JSON.stringify(keyManager.keyResultSetup(freshResult(), "bip49")), baseline);
});

test("fresh setup rejects incomplete or inconsistent results instead of equating missing data", () => {
  const mutations = [
    (r) => { r.kind = "unknown"; }, (r) => { r.network = "unknown"; },
    (r) => { delete r.coinType; }, (r) => { r.coinType = -1; },
    (r) => { r.purposeMatch = "yes"; }, (r) => { delete r.originalPurpose; },
    (r) => { r.originalPurpose.hardened = "yes"; }, (r) => { r.originalPurpose.index = -1; },
    (r) => { r.accounts = []; }, (r) => { r.accounts = [null]; },
    (r) => { delete r.accounts[0].def; }, (r) => { r.accounts[0].network = "regtest"; },
    (r) => { r.accounts[0].accountPath = ""; }, (r) => { r.accounts[0].branchHardened = "false"; },
    (r) => { delete r.accounts[0].addressHardened; }, (r) => { r.accounts[0].branchRange = 2; },
    (r) => { r.accounts[0].branchStart = 1; }, (r) => { r.accounts[0].addressBranches = []; },
    (r) => { r.accounts[0].addressBranches[0].rows = []; },
    (r) => { r.accounts[0].addressBranches[0].rows[0].index = -1; },
    (r) => { r.accounts[0].addressBranches[0].rows[0].path = ""; },
    (r) => { r.accounts[0].addressBranches[0].rows.push({ index: 0, path: "duplicate index" }); },
  ];
  for (const mutate of mutations) {
    const result = freshResult();
    mutate(result);
    assert.equal(keyManager.keyResultSetup(result, "bip84"), null, mutate.toString());
  }
  for (const result of [null, undefined, {}, []]) assert.equal(keyManager.keyResultSetup(result, "bip84"), null);
  assert.equal(keyManager.keyResultSetup(freshResult(), "unknown"), null);
});

test("single and imported-account setup projections retain their distinct capabilities", () => {
  const single = { kind: "single", network: "regtest", compressed: false, privateKey: new Uint8Array(32), minikey: new Uint8Array([1]) };
  const setup = keyManager.keyResultSetup(single, "bip44");
  assert.equal(setup.kind, "single");
  assert.equal(setup.network, "regtest");
  assert.equal(setup.compressed, false);
  assert.deepEqual(setup.capabilities, { mnemonic: false, seed: false, rootPrivate: false, singlePrivate: true, minikey: true });
  assert.notDeepEqual(keyManager.keyResultSetup({ ...single, compressed: true }, "bip44"), setup);
  assert.equal(keyManager.keyResultSetup({ ...single, compressed: "false" }, "bip44"), null);
  const account = freshResult();
  Object.assign(account, { imported: true, coinType: undefined, purposeMatch: false, originalPurpose: undefined, rootNode: null, entropy: null, seed: null });
  Object.assign(account.accounts[0], { importedFamily: "z", accountPath: "Imported account key" });
  account.accounts[0].addressBranches[0].rows[0].path = "Imported account key/0/0";
  const imported = keyManager.keyResultSetup(account, "bip84");
  assert.equal(imported.coinType, null);
  assert.equal(imported.accounts[0].importedFamily, "z");
  assert.equal(imported.accounts[0].privateAvailable, true);
  assert.equal(imported.capabilities.rootPrivate, false);
});

test(".elkeys reuse deterministic Journal encryption and the Journal password", async () => {
  const journal = await createDocument(password, password);
  const content = serializeKeyVault([key()]);
  const first = await sealExport("key-manager", content, journal.keys);
  const second = await sealExport("key-manager", content, journal.keys);
  assert.deepEqual(second, first);
  const opened = await openExport(JSON.stringify(first), journal.keys);
  assert.equal(opened.kind, "key-manager");
  assert.equal(parseKeyVault(opened.content).keys[0].fields.seed, "user supplied words");
  assert.equal(parseKeyVault(opened.content).keys[0].result, null);
});

test("Key Manager has no entropy, network, or browser-storage primitive", () => {
  const source = read("src/js/keymanager.js").replace(/\/\/.*$/gm, "");
  assert.doesNotMatch(source, /Math\.random|crypto\.getRandomValues|fetch\b|XMLHttpRequest|WebSocket|localStorage|sessionStorage|indexedDB/);
});

test("the Journal integration keeps imported keys pending until explicit use", () => {
  const source = read("src/js/app.js");
  assert.match(source, /hodlKeyManagerPending\.push\(state\)/);
  assert.match(source, /function hodlKeyManagerUseInStation\(state, show = true\)[\s\S]*hodlKeyManagerPending\.splice\(pending, 1\);[\s\S]*hodlKeys\.push\(state\)/);
  assert.match(source, /function hodlDeleteActiveKey\(\)[\s\S]*hodlJournalUnlocked\(\)[\s\S]*hodlKeyManagerDetachFromStation\(state\)/);
  assert.match(source, /hodlJournalSealExport\("key-manager", content, hodlJournalKeys\)/);
  const importer = source.slice(source.indexOf("async function hodlKeyManagerImportFile("), source.indexOf("function hodlInitJournalToolTabs("));
  assert.match(importer, /let isCurrent = \(\) => generation === hodlJournalGeneration && request === hodlKeyManagerFileRequest/);
  assert.match(importer, /let text = await file\.text\(\);\s*if \(!isCurrent\(\)\) return;\s*assertAvailable\(\);\s*let opened = await hodlJournalOpenExport\(text, hodlJournalKeys\)/);
});
