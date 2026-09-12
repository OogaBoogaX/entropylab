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
import { keyVaultIdentity, parseKeyVault, serializeKeyVault } from "../src/js/keymanager.js";
import { runInNewContext } from "node:vm";
import { mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { HDKey } from "@scure/bip32";
import { p2wpkh } from "@scure/btc-signer";
import { addressQrButtonHtml } from "../src/js/address-qr.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");

function loadSlice(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let depth = 0;
  let end = -1;
  for (let i = app.indexOf("{", start); i < app.length; i++) {
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

function importHarness() {
  const calls = [], context = {
    keyVaultIdentity, parseKeyVault,
    hodlNextKeyId: 1, hodlNextKeyNumber: 1, hodlActiveKey: 0,
    hodlKeys: [], hodlKeyManagerPending: [], hodlKeyManagerIgnored: [],
    hodlKeyManagerIds: new Set(), hodlKeyManagerActiveId: "", hodlActiveDerivation: null,
    hodlWalletResult: null, hodlOutEl: { innerHTML: "" },
    hodlDefaultCoinType: () => 0, hodlNetworkDefault: "mainnet", hodlKeyColor: id => String(id),
    hodlDefaultKeyName: id => `Key ${id}`,
    hodlJournalUnlocked: () => true, hodlJournalKeys: {}, hodlJournalGeneration: 0,
    hodlJournalOpenExport: async content => ({ kind: "key-manager", content }),
    hodlTText: (text, vars) => text.replace("{n}", String(vars?.n ?? "")),
    hodlJournalLog: (...args) => calls.push(args),
    hodlKeyManagerStatus: text => calls.push(["status", text]),
    hodlRenderKeyTabs() {}, hodlKeyManagerRender() {},
    hodlCaptureKey: () => { context.hodlKeys[context.hodlActiveKey].result = context.hodlWalletResult; },
    hodlShowWorkspace: () => { context.hodlWalletResult = context.hodlKeys[context.hodlActiveKey].result; },
    hodlRestoreKey: () => { context.hodlWalletResult = context.hodlKeys[context.hodlActiveKey].result; },
  };
  for (const name of ["hodlNewKeyState", "hodlNewLabState", "hodlKeyManagerImportedState",
    "hodlKeyManagerStates", "hodlKeyManagerUseInStation", "hodlKeyManagerUseAllInStation",
    "hodlCloneDerivedKey", "hodlFillLabFromKey", "hodlCommitDerivedKey", "hodlKeyManagerImportFile",
    "hodlKeyManagerRestoreIgnored"])
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
  c.hodlKeyManagerUseAllInStation();
  assert.equal(c.hodlKeys.length, 2, "bulk add cannot install an unverified wallet");
  c.hodlKeyManagerRestoreIgnored(c.hodlKeyManagerIgnored[0]);
  assert.equal(c.hodlKeyManagerPending.length, 3);
  assert.equal(c.hodlKeyManagerPending[2].needsDerivation, true);
  assert.equal(c.hodlKeyManagerPending[2].result, null);
  c.hodlKeyManagerUseInStation(pending);
  const lab = c.hodlKeys[c.hodlActiveKey];
  assert.equal(lab.isLab, true);
  assert.equal(lab.result, null);
  assert.equal(c.hodlWalletResult, null);
  assert.equal(lab.fields.seed, WORDS);
  assert.equal(c.hodlKeyManagerPending.length, 3, "loading alone does not verify or remove the input");
});

function enableDerivation(c) {
  Object.assign(c, {
    hodlKeyMode: "seed", hodlSeedMethod: "words", hodlTargetWordCount: 12, hodlNetworkChoice: "mainnet",
    document: { getElementById: id => ({ value: c.hodlKeys[c.hodlActiveKey].fields[id] || "" }) },
    hodlReadDerivationPlan: () => ({ network: "mainnet", coinType: 0 }),
    hodlNetworkFamily: value => value, hodlReadAddressWindow: () => ({ start: 0, range: 1 }),
    hodlReadBranchWindow: () => ({ start: 0, range: 1 }), hodlSelectedScriptType: () => "bip84",
    hodlDefaultHardening: () => ({}), hodlPassphraseBip39Enabled: () => false,
    hodlSelectedSeedInput: () => ({ value: c.hodlKeys[c.hodlActiveKey].fields.seed }),
    hodlValidateTargetMnemonic: value => {
      assert.ok(validateMnemonic(value, wordlist), "invalid source mnemonic");
      return { words: value.split(" ") };
    },
    hodlThrowIfFailed() {}, hodlSetWorkspaceError() {}, hodlSetSelectedScriptType() {},
    hodlSnapshotKeySummary() {}, hodlJournalCaptureDerivedKey() {}, hodlFocusWalletResult() {},
    hodlErrorSpecFrom: error => error.message,
    // The real controller drives an independent BIP39/BIP32 implementation.
    // Its existing wallet-engine vector tests separately cover production crypto.
    hodlMnemonicWalletWithProgress: async (words, passphrase, network) => {
      const master = HDKey.fromMasterSeed(mnemonicToSeedSync(words, passphrase));
      const leaf = master.derive("m/84'/0'/0'/0/0");
      return { network, mnemonic: words, masterFingerprint: master.fingerprint.toString(16).padStart(8, "0"),
        rootXprv: master.privateExtendedKey, address: p2wpkh(leaf.publicKey).address };
    },
  });
  // Keep the real cancellation control declarations with the controller,
  // including the generation fence supplied by the separate lifecycle fix.
  runInNewContext(app.slice(app.indexOf("class HodlDerivationCancelledError"), app.indexOf("function hodlDerivationButton")), c);
  runInNewContext(loadSlice("hodlCalculateKey"), c);
}

test("only a successful fresh derivation retires an imported input and publishes the genuine wallet", async () => {
  const { context: c, importFile } = importHarness();
  await importFile(legacyFile([legacyEntry()]));
  const imported = c.hodlKeyManagerPending[0], oldIdentity = keyVaultIdentity(imported);
  c.hodlKeyManagerUseInStation(imported);
  enableDerivation(c);
  assert.equal(await c.hodlCalculateKey({}), true);
  const derived = c.hodlKeys[c.hodlActiveKey];
  assert.equal(derived.isLab, false);
  assert.equal(derived.result.address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
  assert.equal(derived.result.mnemonic, WORDS);
  assert.ok(!JSON.stringify(derived.result).includes("forged"));
  assert.equal(c.hodlKeyManagerPending.length, 0);
  assert.equal(c.hodlKeyManagerIds.has(oldIdentity), false);
  assert.equal(c.hodlKeyManagerIds.has(keyVaultIdentity(derived)), true);
  assert.equal(parseKeyVault(serializeKeyVault([derived])).keys[0].result, null, "even a genuine export must be rederived next time");
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

// The real escaping helpers and table renderer from app.js; hodlPrivateValue
// (the WIF cell) is sliced too, with its two globals stubbed.
const source = [
  loadSlice("hodlEscapeHtml"),
  loadSlice("hodlDisplayDerivationPath"),
  loadSlice("hodlAddressIndexHtml"),
  loadSlice("hodlPrivateValue"),
  loadSlice("hodlAddressTableRows"),
].join("\n");
const loadRows = (revealPrivate = false) =>
  new Function("hodlRevealPrivate", "hodlT", "hodlAddressQrButton", `${source}; return hodlAddressTableRows;`)(
    revealPrivate,
    (text, vars) => text.replace("{n}", String(vars?.n ?? "{n}")),
    addressQrButtonHtml,
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

test("the first-address lead and the multisig lead route the index through the same guard", () => {
  const show = loadSlice("hodlShowAccount");
  assert.ok(show.includes("address #${hodlAddressIndexHtml(firstIndex)}"), "HD account heading");
  assert.ok(show.includes('address ${hodlAddressIndexHtml(firstIndex)} QR code'), "HD account QR label");
  const msig = loadSlice("hodlShowMsig");
  assert.ok(msig.includes("address #${hodlAddressIndexHtml(firstIndex)}"), "multisig heading");
  assert.ok(msig.includes('address ${hodlAddressIndexHtml(firstIndex)} QR code'), "multisig QR label");
});
