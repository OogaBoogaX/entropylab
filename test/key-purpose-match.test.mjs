// Security contract: only an HD wallet retaining its root private key may
// replace its first derivation component with the selected script's hardened
// standard purpose, or restore its original component; every suffix and
// derived output must remain consistent, and unsupported sources are refused.
// Published BIP84/BIP86 addresses and BIP49's testnet address pin the standard
// mappings. Custom paths, account keys and addresses are compared against
// the independently implemented, already-pinned @scure libraries; descriptor
// checksums use the BIP380 reference in wallet-export-harness.mjs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { HDKey as ReferenceHDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";
import { NETWORK, TEST_NETWORK, p2pkh, p2sh, p2wpkh, p2tr } from "@scure/btc-signer";
import { HDKey } from "../src/js/hdkey.js";
import { loadAppFunctions } from "./app-slice-harness.mjs";
import { descriptorChecksum } from "./wallet-export-harness.mjs";

const WORDS = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PURPOSES = { bip44: 44, bip49: 49, bip84: 84, bip86: 86 };
const HARDENING = { purpose: true, coinType: true, account: true, script: true, branch: false, address: false };
const tracker = { setTotal() {}, step() { return null; } };
const inert = new Proxy(function () {}, { get: (_, key) => key === Symbol.toPrimitive ? () => "" : key === "then" ? undefined : inert, apply: () => inert, construct: () => inert });
async function load(names, options = {}) {
  Object.assign(globalThis, { __ENTROPYLAB_TEST_HOOKS__: false, document: inert, window: inert });
  try {
    return await loadAppFunctions(names, { ...options, stubs: { hodlSelectedScriptType: () => "bip84", ...options.stubs } });
  } finally {
    delete globalThis.document;
    delete globalThis.window;
  }
}
// Load the new API inside each test so a missing capability reports its own
// failure, while all of the independently specified assertions remain present.
const names = ["hodlCanMatchPurpose", "hodlWalletWithPurposeMatch", "hodlMnemonicWalletWithProgress", "hodlImportedWalletWithProgress", "hodlWipeWalletKeys", "hodlAccountPrivateKey", "hodlBranchPrivateDescriptor", "hodlWalletExportView"];
const wallet = (api, { purpose = 100, hardened = true, network = "mainnet", count = 2, start = 0, branch = 0, range = 2, passphrase = "", account = 0, plan = null, hardening = HARDENING } = {}) => api.hodlMnemonicWalletWithProgress(WORDS, passphrase, network, count, { notes: ["purpose fixture"], warnings: [] }, account, start, tracker, purpose, network === "mainnet" ? 0 : 1, { ...hardening, purpose: hardened }, branch, range, plan);
const referenceRoot = (passphrase = "") => ReferenceHDKey.fromMasterSeed(mnemonicToSeedSync(WORDS, passphrase));
const origin = (path) => path.slice(2).replaceAll("'", "h");
const descriptor = (script, token) => {
  const body = { bip44: () => `pkh(${token})`, bip49: () => `sh(wpkh(${token}))`, bip84: () => `wpkh(${token})`, bip86: () => `tr(${token})` }[script]();
  return `${body}#${descriptorChecksum(body)}`;
};
const address = (script, publicKey, network) => {
  const net = network === "mainnet" ? NETWORK : TEST_NETWORK;
  return { bip44: () => p2pkh(publicKey, net), bip49: () => p2sh(p2wpkh(publicKey, net), net), bip84: () => p2wpkh(publicKey, net), bip86: () => p2tr(publicKey.slice(1), undefined, net) }[script]().address;
};
function assertDerived(api, result, root, accountPaths) {
  const exported = api.hodlWalletExportView(result);
  for (const account of result.accounts) {
    const path = accountPaths[account.def.id], expected = root.derive(path);
    assert.equal(account.accountPath, path);
    assert.equal(account.originPath, origin(path));
    assert.equal(account.genericPublic, expected.publicExtendedKey);
    assert.equal(api.hodlAccountPrivateKey(account), expected.privateExtendedKey);
    const accountExport = exported.accounts.find((item) => item.def.id === account.def.id);
    for (const branch of account.addressBranches) {
      const branchStep = `${branch.branch}${account.branchHardened ? "'" : ""}`;
      const suffix = `${branchStep}/${account.addressHardened ? "*'" : "*"}`;
      const token = `[73c5da0a/${origin(path)}]`;
      if (!account.branchHardened && !account.addressHardened) {
        assert.equal(branch.publicDescriptor, descriptor(account.def.id, `${token}${expected.publicExtendedKey}/${suffix}`));
      }
      assert.equal(api.hodlBranchPrivateDescriptor(account, branch.branch), descriptor(account.def.id, `${token}${expected.privateExtendedKey}/${suffix}`));
      if (branch.branch === 0) assert.equal(accountExport.receiveDescriptorPriv, api.hodlBranchPrivateDescriptor(account, 0));
      if (branch.branch === 1) assert.equal(accountExport.changeDescriptorPriv, api.hodlBranchPrivateDescriptor(account, 1));
      for (const row of branch.rows) {
        const rowPath = `${path}/${branchStep}/${row.index}${account.addressHardened ? "'" : ""}`, child = root.derive(rowPath);
        assert.equal(row.path, rowPath);
        assert.equal(row.address, address(account.def.id, child.publicKey, result.network));
        assert.deepEqual(row.privateKey, child.privateKey);
      }
    }
  }
}

test("unchecked derivation keeps one explicit purpose for every script type", async () => {
  const api = await load(names);
  for (const [purpose, hardened] of [[84, true], [100, true], [100, false]]) {
    const result = await wallet(api, { purpose, hardened });
    const path = `m/${purpose}${hardened ? "'" : ""}/0'/0'`;
    assert.equal(Boolean(result.purposeMatch), false);
    assert.equal(result.originalPurpose, undefined);
    assertDerived(api, result, referenceRoot(), Object.fromEntries(Object.keys(PURPOSES).map(id => [id, path])));
    for (const account of result.accounts) {
      assert.equal(account.def.purpose, purpose);
      assert.equal(account.def.purposeHardened, hardened);
    }
  }
});

test("a fresh purpose-matched derivation remembers the entered standard and preserves custom suffixes", async () => {
  const api = await load(names), root = referenceRoot();
  for (const purpose of Object.values(PURPOSES)) {
    const accountPath = `m/${purpose}'/0'/3/777'`, plan = { accountPath, originPath: origin(accountPath), matchPurpose: true };
    const result = await wallet(api, { purpose, account: 3, start: 7, count: 2, branch: 2, range: 2, plan });
    assert.equal(result.purposeMatch, true);
    assert.deepEqual(result.originalPurpose, { index: purpose, hardened: true });
    assertDerived(api, result, root, Object.fromEntries(Object.entries(PURPOSES).map(([id, standard]) => [id, `m/${standard}'/0'/3/777'`])));
    const restored = await api.hodlWalletWithPurposeMatch(result, false, { index: 44, hardened: true }, tracker);
    assert.equal(restored.purposeMatch, false);
    assert.deepEqual(restored.originalPurpose, { index: purpose, hardened: true });
    assertDerived(api, restored, root, Object.fromEntries(Object.keys(PURPOSES).map(id => [id, accountPath])));
  }
});

test("initial purpose matching is available for private roots but never public roots or account imports", async () => {
  const api = await load(names), root = referenceRoot();
  const plan = { accountPath: "m/84'/0'/0'", originPath: "84h/0h/0h", hasHardenedPrefix: true, matchPurpose: true };
  const privateRoot = await api.hodlImportedWalletWithProgress(root.privateExtendedKey, "mainnet", 1, 0, 0, tracker, 84, 0, HARDENING, 0, 2, plan);
  assert.equal(privateRoot.purposeMatch, true);
  assert.deepEqual(privateRoot.originalPurpose, { index: 84, hardened: true });
  assertDerived(api, privateRoot, root, Object.fromEntries(Object.entries(PURPOSES).map(([id, purpose]) => [id, `m/${purpose}'/0'/0'`])));
  const publicPlan = { accountPath: "m/84/0/0", originPath: "84/0/0", hasHardenedPrefix: false, matchPurpose: true };
  const publicRoot = await api.hodlImportedWalletWithProgress(root.publicExtendedKey, "mainnet", 1, 0, 0, tracker, 84, 0, Object.fromEntries(Object.keys(HARDENING).map(key => [key, false])), 0, 2, publicPlan);
  assert.equal(Boolean(publicRoot.purposeMatch), false);
  assert.equal(publicRoot.originalPurpose, undefined);
  assert.ok(publicRoot.accounts.every(account => account.accountPath === "m/84/0/0"));
  for (const key of [root.derive("m/84'/0'/0'").publicExtendedKey, root.derive("m/84'/0'/0'").privateExtendedKey]) {
    const imported = await api.hodlImportedWalletWithProgress(key, "mainnet", 1, 0, 0, tracker, 84, 0, HARDENING, 0, 2, plan);
    assert.equal(Boolean(imported.purposeMatch), false);
    assert.equal(imported.originalPurpose, undefined);
  }
});

test("purpose matching derives all four standards and agrees with published BIP84/BIP86 vectors", async () => {
  const api = await load(names), initial = await wallet(api), matched = await api.hodlWalletWithPurposeMatch(initial, true, { index: 100, hardened: true }, tracker);
  assert.notEqual(matched, initial);
  assert.equal(Boolean(initial.purposeMatch), false);
  assert.equal(matched.purposeMatch, true);
  assert.deepEqual(matched.originalPurpose, { index: 100, hardened: true });
  assert.equal(api.hodlCanMatchPurpose(initial), true);
  assert.equal(matched.accounts.length, 4);
  assertDerived(api, matched, referenceRoot(), Object.fromEntries(Object.entries(PURPOSES).map(([id, purpose]) => [id, `m/${purpose}'/0'/0'`])));
  for (const account of matched.accounts) {
    assert.equal(account.def.purpose, PURPOSES[account.def.id]);
    assert.equal(account.def.purposeHardened, true);
    assert.equal(account.primaryFamily, { bip44: "x", bip49: "y", bip84: "z", bip86: "x" }[account.def.id]);
  }
  assert.equal(api.hodlAccountPrivateKey(matched.accounts.find((a) => a.def.id === "bip84"), "z"), "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE");
  assert.equal(matched.accounts.find((a) => a.def.id === "bip84").receive[0].address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
  assert.equal(matched.accounts.find((a) => a.def.id === "bip86").receive[0].address, "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr");
  assert.equal(matched.masterIdentity, initial.masterIdentity);
  assert.equal(matched.masterFingerprint, initial.masterFingerprint);
  assert.deepEqual(matched.multisigCosignerExports, initial.multisigCosignerExports);
  assert.deepEqual(initial.accounts.map((a) => a.accountPath), Array(4).fill("m/100'/0'/0'"));
});

test("purpose matching agrees with the published BIP49 testnet address", async () => {
  const api = await load(names), initial = await wallet(api, { network: "testnet", count: 1 }), matched = await api.hodlWalletWithPurposeMatch(initial, true, { index: 100, hardened: true }, tracker);
  const account = matched.accounts.find((a) => a.def.id === "bip49");
  assert.equal(account.accountPath, "m/49'/1'/0'");
  assert.equal(account.receive[0].address, "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2");
});

for (const hardened of [false, true]) test(`unchecking restores the exact original ${hardened ? "hardened" : "unhardened"} purpose`, async () => {
  const api = await load(names), initial = await wallet(api, { hardened, start: 7, account: 3 }), original = { index: 100, hardened };
  let current = initial;
  for (let round = 0; round < 2; round++) {
    current = await api.hodlWalletWithPurposeMatch(current, true, original, tracker);
    current = await api.hodlWalletWithPurposeMatch(current, false, original, tracker);
    assert.equal(current.purposeMatch, false);
    assert.deepEqual(current.originalPurpose, original);
    assert.ok(current.accounts.every((account) => account.primaryFamily === "x"));
    assertDerived(api, current, referenceRoot(), Object.fromEntries(Object.keys(PURPOSES).map((id) => [id, `m/100${hardened ? "'" : ""}/0'/3'`])));
    assert.deepEqual(current.accounts.map((a) => a.receive.map((r) => r.address)), initial.accounts.map((a) => a.receive.map((r) => r.address)));
    assert.deepEqual(original, { index: 100, hardened });
  }
});

test("automatic purpose values cannot overwrite the original component remembered by the wallet", async () => {
  const api = await load(names), initial = await wallet(api, { hardened: false });
  const matched = await api.hodlWalletWithPurposeMatch(initial, true, { index: 100, hardened: false }, tracker);
  const rematched = await api.hodlWalletWithPurposeMatch(matched, true, { index: 84, hardened: true }, tracker);
  assert.deepEqual(rematched.originalPurpose, { index: 100, hardened: false });
  const restored = await api.hodlWalletWithPurposeMatch(rematched, false, { index: 44, hardened: true }, tracker);
  assert.deepEqual(restored.accounts.map((account) => account.accountPath), Array(4).fill("m/100/0'/0'"));
});

test("custom path depth, suffix hardening, branch selection and address window survive matching and restoration", async () => {
  const api = await load(names), original = { index: 100, hardened: false };
  for (const accountPath of ["m/100", "m/100/0'/3/9'/2"]) {
    const plan = { accountPath, originPath: origin(accountPath) }, hardening = { ...HARDENING, branch: true, address: true };
    const initial = await wallet(api, { hardened: false, account: 3, start: 7, count: 3, branch: 4, range: 2, plan, hardening });
    const matched = await api.hodlWalletWithPurposeMatch(initial, true, original, tracker);
    assertDerived(api, matched, referenceRoot(), Object.fromEntries(Object.entries(PURPOSES).map(([id, purpose]) => [id, accountPath.replace("m/100", `m/${purpose}'`)])));
    for (const account of matched.accounts) {
      assert.equal(account.branchStart, 4);
      assert.equal(account.branchRange, 2);
      assert.equal(account.branchHardened, true);
      assert.equal(account.addressHardened, true);
      assert.deepEqual(account.addressBranches.map((b) => [b.branch, b.rows.map((r) => r.index)]), [[4, [7, 8, 9]], [5, [7, 8, 9]]]);
    }
    const restored = await api.hodlWalletWithPurposeMatch(matched, false, original, tracker);
    assertDerived(api, restored, referenceRoot(), Object.fromEntries(Object.keys(PURPOSES).map((id) => [id, accountPath])));
  }
});

test("unsupported key sources and invalid original purposes are refused", async () => {
  const api = await load(names), initial = await wallet(api), root = referenceRoot();
  const importedRoot = await api.hodlImportedWalletWithProgress(root.privateExtendedKey, "mainnet", 1, 0, 0, tracker, 100, 0);
  assert.equal(api.hodlCanMatchPurpose(importedRoot), true);
  const rootPublic = await api.hodlImportedWalletWithProgress(root.publicExtendedKey, "mainnet", 1, 0, 0, tracker, 100, 0, Object.fromEntries(Object.keys(HARDENING).map((key) => [key, false])));
  const accountNode = root.derive("m/84'/0'/0'");
  for (const source of [rootPublic, { kind: "single", privateKey: new Uint8Array(32).fill(1) }, { ...initial, rootNode: HDKey.fromExtendedKey(accountNode.privateExtendedKey) }, { ...initial, accounts: [] }, null]) {
    assert.equal(api.hodlCanMatchPurpose(source), false);
    await assert.rejects(api.hodlWalletWithPurposeMatch(source, true, { index: 100, hardened: true }, tracker));
  }
  for (const key of [accountNode.publicExtendedKey, accountNode.privateExtendedKey]) {
    const imported = await api.hodlImportedWalletWithProgress(key, "mainnet", 1, 0, 0, tracker, 100, 0);
    assert.equal(api.hodlCanMatchPurpose(imported), false);
    await assert.rejects(api.hodlWalletWithPurposeMatch(imported, true, { index: 100, hardened: true }, tracker));
  }
  for (const original of [null, {}, { index: -1, hardened: true }, { index: 2147483648, hardened: true }, { index: 1.5, hardened: true }, { index: 100, hardened: "false" }]) {
    await assert.rejects(api.hodlWalletWithPurposeMatch(initial, false, original, tracker));
  }
});

test("replacement secrets are independently owned and one key's matching leaves another unchanged", async () => {
  const api = await load(names), initial = await wallet(api, { passphrase: "TREZOR" }), other = await wallet(api, { purpose: 13 });
  const beforeOther = other.accounts.map((a) => a.genericPublic), matched = await api.hodlWalletWithPurposeMatch(initial, true, { index: 100, hardened: true }, tracker);
  for (const field of ["entropy", "seed", "passphrase"]) {
    assert.notEqual(matched[field], initial[field]);
    assert.notEqual(matched[field].buffer, initial[field].buffer);
    assert.deepEqual(matched[field], initial[field]);
  }
  assert.notEqual(matched.rootNode, initial.rootNode);
  const seed = Uint8Array.from(matched.seed), passphrase = Uint8Array.from(matched.passphrase);
  api.hodlWipeWalletKeys(initial);
  assert.deepEqual(matched.seed, seed);
  assert.deepEqual(matched.passphrase, passphrase);
  assert.equal(matched.rootNode.privateExtendedKey, referenceRoot("TREZOR").privateExtendedKey);
  for (const account of matched.accounts) assert.equal(api.hodlAccountPrivateKey(account), referenceRoot("TREZOR").derive(`m/${PURPOSES[account.def.id]}'/0'/0'`).privateExtendedKey);
  assert.deepEqual(other.accounts.map((a) => a.genericPublic), beforeOther);
});

for (const failAt of [1, 5]) test(`interrupted purpose derivation at row ${failAt} wipes new secrets and keeps the source usable`, async () => {
  const api = await load([...names, "hodlSettleDerivationKeys"], { settable: ["hodlActiveDerivation"], stubs: { hodlLiveWalletResults: () => new Set(), hodlKeyManagerPending: [] } });
  const initial = await wallet(api, { passphrase: "TREZOR" }), control = { rowKeys: [], nodes: [] }, originalKey = initial.rootNode.privateExtendedKey;
  api.__set.hodlActiveDerivation(control);
  let steps = 0;
  const stopping = { setTotal() {}, step() { if (++steps === failAt) throw new Error("stopped purpose derivation"); } };
  try {
    await assert.rejects(api.hodlWalletWithPurposeMatch(initial, true, { index: 100, hardened: true }, stopping), /stopped purpose derivation/);
  } finally {
    api.hodlSettleDerivationKeys(control);
    api.__set.hodlActiveDerivation(null);
  }
  assert.ok(control.rowKeys.length >= failAt + 3, "source entropy, seed and passphrase copies must join the cleanup lifecycle");
  assert.ok(control.rowKeys.every((bytes) => bytes.every((byte) => byte === 0)));
  assert.ok(control.nodes.every((node) => !node.hasPrivateKey));
  assert.equal(initial.rootNode.privateExtendedKey, originalKey);
  assert.deepEqual(initial.seed, mnemonicToSeedSync(WORDS, "TREZOR"));
});
