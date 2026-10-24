// #546 B2 step 2b: a derived wallet's extended private keys (the root xprv,
// each account's xprv and SLIP-132 yprv/zprv, and the private descriptors
// that embed them) are held as wipeable key material, not text, and are
// turned into text only where one is shown, copied or exported. Strings
// cannot be erased, so text held for the whole session defeats Wipe.
//
// Expected keys come from @scure/bip32 and the published BIP84 vector,
// versions from SLIP-0132, and descriptor checksums from the independent
// BIP-380 reference in wallet-export-harness.mjs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { HDKey as ScureHDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";
import { createBase58check } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";
import { descriptorChecksum } from "./wallet-export-harness.mjs";
import { loadAppFunctions } from "./app-slice-harness.mjs";
import { HDKey } from "../src/js/hdkey.js";


const MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
// BIP84's published vector for this mnemonic: the root and m/84'/0'/0'.
const BIP84_ROOT_ZPRV = "zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5";
const BIP84_ACCOUNT_ZPRV = "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE";
const FINGERPRINT = "73c5da0a";
// SLIP-0132 private and public versions.
const VERSIONS = {
  mainnet: { x: [0x0488ade4, 0x0488b21e], y: [0x049d7878, 0x049d7cb2], z: [0x04b2430c, 0x04b24746] },
  testnet: { x: [0x04358394, 0x043587cf], y: [0x044a4e28, 0x044a5262], z: [0x045f18bc, 0x045f1cf6] },
};
const b58 = createBase58check(sha256);
const reversion = (text, version) => {
  const raw = Uint8Array.from(b58.decode(text));
  new DataView(raw.buffer).setUint32(0, version);
  return b58.encode(raw);
};
const scureRoot = ScureHDKey.fromMasterSeed(mnemonicToSeedSync(MNEMONIC));
const coinOf = (network) => network === "testnet" ? 1 : 0;
const expected = (network) => {
  const account = scureRoot.derive(`m/84'/${coinOf(network)}'/0'`);
  const family = (name, key) => reversion(key.privateExtendedKey, VERSIONS[network][name][0]);
  return {
    root: family("x", scureRoot),
    account: { x: family("x", account), y: family("y", account), z: family("z", account) },
    accountPublic: reversion(account.publicExtendedKey, VERSIONS[network].x[1]),
  };
};

test("the oracle agrees with the published BIP84 vector", () => {
  assert.equal(reversion(scureRoot.privateExtendedKey, VERSIONS.mainnet.z[0]), BIP84_ROOT_ZPRV);
  assert.equal(expected("mainnet").account.z, BIP84_ACCOUNT_ZPRV);
  assert.equal(scureRoot.fingerprint.toString(16).padStart(8, "0"), FINGERPRINT);
});

test("every standard extended key serializes to 111 characters, so a hidden one masks at that length", () => {
  const lengths = new Set();
  for (const network of Object.values(VERSIONS)) for (const [prv, pub] of Object.values(network)) for (const version of [prv, pub]) for (const fill of [0x00, 0xff]) {
    const raw = new Uint8Array(78).fill(fill);
    new DataView(raw.buffer).setUint32(0, version);
    lengths.add(b58.encode(raw).length);
  }
  assert.deepEqual([...lengths], [111]);
});

// The slices these functions need carry page-boot statements (the build flag,
// element lookups) that run once at load; give them inert stand-ins there.
const inert = new Proxy(function () {}, { get: (target, key) => key === Symbol.toPrimitive ? () => "" : key === "then" ? undefined : inert, apply: () => inert, construct: () => inert });
const load = async (names, stubs = {}, settable = []) => {
  Object.assign(globalThis, { __ENTROPYLAB_TEST_HOOKS__: false, document: inert, window: inert });
  try {
    return await loadAppFunctions(names, { stubs: { hodlSelectedScriptType: () => "bip84", ...stubs }, settable });
  } finally {
    delete globalThis.document;
    delete globalThis.window;
  }
};
const tracker = { setTotal() {}, step() { return null; } };
const builders = await load(["hodlMnemonicWalletWithProgress", "hodlImportedWalletWithProgress"]);
const mnemonicWallet = (network) => builders.hodlMnemonicWalletWithProgress(MNEMONIC, "", network, 2, undefined, 0, 0, tracker, 84, coinOf(network));
const importedWallet = (value, network = "mainnet") => builders.hodlImportedWalletWithProgress(value, network, 2, 0, 0, tracker, 84, coinOf(network));
const stringsIn = (value, seen = new Set(), out = []) => {
  if (typeof value === "string") out.push(value);
  else if (value && typeof value === "object" && !ArrayBuffer.isView(value) && !seen.has(value)) {
    seen.add(value);
    for (const key of Object.keys(value)) stringsIn(value[key], seen, out);
  }
  return out;
};
const secretTexts = (network) => { const keys = expected(network); return [keys.root, ...Object.values(keys.account)]; };
const bip84 = (result) => result.accounts.find((account) => account.def.id === "bip84");

test("a derived wallet holds no extended private key as text", async () => {
  const cases = [
    ["seed phrase, mainnet", await mnemonicWallet("mainnet"), secretTexts("mainnet"), []],
    ["seed phrase, testnet", await mnemonicWallet("testnet"), secretTexts("testnet"), []],
    ["imported root xprv", await importedWallet(expected("mainnet").root), secretTexts("mainnet"), []],
    // Nor is the pasted account key itself (#546 B2 step 2c-3): the account's
    // key node rebuilds it as pasted.
    ["imported account zprv", await importedWallet(BIP84_ACCOUNT_ZPRV), Object.values(expected("mainnet").account), []],
  ];
  for (const [label, result, secrets, pasted] of cases) {
    const leaks = stringsIn(result).filter((text) => !pasted.includes(text) && secrets.some((secret) => text.includes(secret)));
    assert.deepEqual(leaks.map((text) => text.slice(0, 16) + "…"), [], `${label}: the result holds extended private keys as text`);
  }
});

// The spending descriptor is the watch-only one with the account xprv in
// place of its xpub (both 111 characters), under a recomputed checksum.
const spendingDescriptor = (account, branch, network) => {
  const watch = account.addressBranches.find((entry) => entry.branch === branch).publicDescriptor, keys = expected(network);
  assert.ok(watch.includes(keys.accountPublic), "the template is not this account's watch-only descriptor");
  const body = watch.slice(0, watch.lastIndexOf("#")).replace(keys.accountPublic, keys.account.x);
  return `${body}#${descriptorChecksum(body)}`;
};

test("each extended private key is produced on request and matches an independent encoder", async () => {
  const api = await load(["hodlResultRootXprv", "hodlAccountPrivateKey", "hodlBranchPrivateDescriptor"]);
  for (const network of ["mainnet", "testnet"]) {
    const result = await mnemonicWallet(network), keys = expected(network);
    assert.equal(api.hodlResultRootXprv(result), keys.root, `${network}: root`);
    for (const account of result.accounts) {
      assert.equal(api.hodlAccountPrivateKey(account, "x"), keys.account.x, `${network} ${account.def.id}: account xprv`);
      assert.equal(api.hodlAccountPrivateKey(account, account.primaryFamily), keys.account[account.primaryFamily], `${network} ${account.def.id}: SLIP-132 export`);
      for (const branch of [0, 1]) assert.equal(api.hodlBranchPrivateDescriptor(account, branch), spendingDescriptor(account, branch, network), `${network} ${account.def.id}: branch ${branch} spending descriptor`);
    }
  }
  assert.equal(api.hodlAccountPrivateKey(bip84(await mnemonicWallet("mainnet")), "z"), BIP84_ACCOUNT_ZPRV);
  // Watch-only sources have none, and a BIP-85 XPRV child's session key keeps
  // its root as a node, like a Key Station wallet (#546 B3).
  const watch = await importedWallet(reversion(scureRoot.derive("m/84'/0'/0'").publicExtendedKey, VERSIONS.mainnet.z[1]));
  assert.equal(api.hodlAccountPrivateKey(watch.accounts[0], "x"), null);
  assert.equal(api.hodlBranchPrivateDescriptor(watch.accounts[0], 0), null);
  assert.equal(api.hodlResultRootXprv(watch), null);
  assert.equal(api.hodlResultRootXprv({ network: "mainnet", rootNode: HDKey.fromExtendedKey(expected("mainnet").root) }), expected("mainnet").root);
});

// The hidden view is a mask as long as the value, and the revealed view is
// the value: both rendered with the unchanged private-field primitive around
// the independently computed key. (The wallet card's root field is covered by
// the rendered page comparison against rock, which the PR records.)
const renderers = async (revealed) => {
  const view = await load(["hodlSlip132Fields", "hodlAddressBranchDescriptorFields", "hodlPrivateFieldHtml"], {}, ["hodlRevealPrivate"]);
  view.__set.hodlRevealPrivate(revealed);
  return view;
};

test("the account exports render the same, hidden and revealed", async () => {
  const keys = expected("mainnet"), wallet = await mnemonicWallet("mainnet"), zprvWallet = await importedWallet(BIP84_ACCOUNT_ZPRV), xprvWallet = await importedWallet(keys.account.x);
  for (const revealed of [false, true]) {
    const view = await renderers(revealed), field = (label, value, vars) => view.hodlPrivateFieldHtml(label, value, vars, "label"), state = revealed ? "revealed" : "hidden";
    const account = bip84(wallet);
    const checkSecrets = (html, values, context) => {
      for (const value of values) assert.equal(html.includes(value), revealed, `${state}: ${context}`);
    };
    checkSecrets(view.hodlSlip132Fields(account, wallet, true), [keys.account.x, keys.account.z], "derived account keys");
    const legacy = wallet.accounts.find((candidate) => candidate.def.id === "bip44");
    checkSecrets(view.hodlSlip132Fields(legacy, wallet, true), [keys.account.x], "legacy account key");
    checkSecrets(view.hodlSlip132Fields(zprvWallet.accounts[0], zprvWallet, true), [BIP84_ACCOUNT_ZPRV, keys.account.x], "pasted zprv account keys");
    checkSecrets(view.hodlSlip132Fields(xprvWallet.accounts[0], xprvWallet, true), [keys.account.x], "pasted xprv account key");
    assert.equal(view.hodlAddressBranchDescriptorFields(account.addressBranches, true, "label", account),
      [0, 1].map((branch) => field(`Spending ${branch ? "change" : "receive"} descriptor`, spendingDescriptor(account, branch, "mainnet"))).join(""), `${state}: spending descriptors`);
  }
});

test("the recovery sheet prints the extended private keys only when private material is saved", async () => {
  const { hodlRecoverySheetText } = await load(["hodlRecoverySheetText"]);
  const keys = expected("mainnet"), wallet = await mnemonicWallet("mainnet"), account = bip84(wallet);
  const sheet = hodlRecoverySheetText(wallet, true);
  for (const value of [keys.root, keys.account.z, keys.account.x,
    spendingDescriptor(account, 0, "mainnet"), spendingDescriptor(account, 1, "mainnet")])
    assert.ok(sheet.split("\n").some((line) => line.endsWith(value)), "the private sheet lacks an expected account or spending key");
  const watchSheet = hodlRecoverySheetText(wallet, false);
  assert.ok(![keys.root, ...Object.values(keys.account)].some((secret) => watchSheet.includes(secret)), "the watch-only sheet carries an extended private key");
});

test("the wallet.dat export view carries the spending descriptors the result no longer holds", async () => {
  const { hodlWalletExportView } = await load(["hodlWalletExportView"]);
  for (const network of ["mainnet", "testnet"]) {
    const wallet = await mnemonicWallet(network), view = hodlWalletExportView(wallet);
    for (const [index, account] of view.accounts.entries()) {
      assert.equal(account.receiveDescriptorPriv, spendingDescriptor(wallet.accounts[index], 0, network));
      assert.equal(account.changeDescriptorPriv, spendingDescriptor(wallet.accounts[index], 1, network));
      assert.equal(account.receiveDescriptor, wallet.accounts[index].receiveDescriptor);
      // Every exported branch carries its own private descriptor, so a window
      // starting at 1 or 2 still reaches wallet-export's key records (AR-03).
      for (const entry of account.addressBranches ?? []) {
        assert.equal(entry.privateDescriptor, spendingDescriptor(wallet.accounts[index], entry.branch, network), `${network} ${account.def.id}: branch ${entry.branch} private descriptor`);
      }
    }
    assert.ok(!stringsIn(wallet).some((text) => text.includes(expected(network).account.x)), "building the view left text on the result");
  }
  const watch = await importedWallet(reversion(scureRoot.derive("m/84'/0'/0'").publicExtendedKey, VERSIONS.mainnet.z[1]));
  assert.equal(hodlWalletExportView(watch).accounts[0].receiveDescriptorPriv ?? null, null);
  for (const entry of hodlWalletExportView(watch).accounts[0].addressBranches ?? []) assert.equal(entry.privateDescriptor ?? null, null);
});

// The page's download and its button hand the wallet.dat builder (stood in
// for here; its records are tested in wallet-export.test.mjs) the export view
// while private material is shown, and the result itself otherwise.
test("the wallet.dat download carries the spending descriptors only while private material is shown", async () => {
  const calls = [];
  const walletExport = {
    hasDescriptors: () => true,
    walletDatSupported: () => true,
    hasPrivateDescriptors: (wallet) => wallet.accounts.some((account) => account.receiveDescriptorPriv || account.changeDescriptorPriv),
    buildWalletDat: (wallet, withSecrets) => { calls.push({ wallet, withSecrets }); return new Uint8Array(1); },
    walletDatFilename: () => "wallet.dat",
    walletDatButtonLabel: (withSecrets) => { calls.push({ label: withSecrets }); return ""; },
  };
  const page = { document: inert, Blob: class {}, URL: { createObjectURL: () => "", revokeObjectURL() {} }, setTimeout: () => 0 };
  const api = await load(["hodlDownloadWalletDat", "hodlWalletDatControl"], { hodlWalletExport: walletExport, hodlWalletDatDeps: () => ({}), hodlSetWorkspaceError() {}, hodlErrorSpecFrom: (error) => error, ...page }, ["hodlWalletResult", "hodlRevealPrivate"]);
  for (const network of ["mainnet", "testnet"]) {
    const wallet = await mnemonicWallet(network);
    api.__set.hodlWalletResult(wallet);
    for (const revealed of [true, false]) {
      calls.length = 0;
      api.__set.hodlRevealPrivate(revealed);
      api.hodlDownloadWalletDat();
      api.hodlWalletDatControl(revealed);
      const [built, label] = calls, state = `${network}, ${revealed ? "revealed" : "hidden"}`;
      assert.equal(built.withSecrets, revealed, `${state}: secrets flag`);
      assert.equal(label.label, revealed, `${state}: button label`);
      for (const [index, account] of built.wallet.accounts.entries()) {
        const expectedDescriptor = (branch) => revealed ? spendingDescriptor(wallet.accounts[index], branch, network) : undefined;
        assert.equal(account.receiveDescriptorPriv, expectedDescriptor(0), `${state} ${account.def.id}: receive`);
        assert.equal(account.changeDescriptorPriv, expectedDescriptor(1), `${state} ${account.def.id}: change`);
      }
    }
    assert.ok(!stringsIn(wallet).some((text) => text.includes(expected(network).account.x)), `${network}: the download left text on the result`);
  }
});

test("a station session gets its own copy of the root, which it can wipe alone", async () => {
  const api = await load(["hodlResultRootNode", "hodlResultRootXprv"]);
  for (const network of ["mainnet", "testnet"]) {
    const wallet = await mnemonicWallet(network), copy = api.hodlResultRootNode(wallet);
    assert.equal(copy.privateExtendedKey, scureRoot.privateExtendedKey, `${network}: the session root`);
    copy.wipePrivateData();
    assert.equal(api.hodlResultRootXprv(wallet), expected(network).root, `${network}: wiping the session copy wiped the wallet's root`);
    const second = api.hodlResultRootNode(wallet);
    assert.equal(second.privateExtendedKey, scureRoot.privateExtendedKey);
    second.wipePrivateData();
  }
  const child = api.hodlResultRootNode({ kind: "hd", rootNode: HDKey.fromExtendedKey(expected("mainnet").root) });
  assert.equal(child.privateExtendedKey, scureRoot.privateExtendedKey, "a BIP-85 child's root node");
  assert.equal(api.hodlResultRootNode({ kind: "hd", rootNode: null }), null);
});

// Every copy is built from the key and chain code the source node hands out,
// and those arrays are the getters' own copies: none may outlive the copy.
test("copying a key node leaves no copy of its private key or chain code behind", async () => {
  const { hodlCopyPrivateNode } = await load(["hodlCopyPrivateNode"]);
  const source = HDKey.fromMasterSeed(mnemonicToSeedSync(MNEMONIC)).derive("m/84'/0'/0'"), handed = [];
  const node = {
    versions: source.versions, depth: source.depth, index: source.index, parentFingerprint: source.parentFingerprint,
    get privateKey() { const key = source.privateKey; if (key) handed.push(key); return key; },
    get chainCode() { const code = source.chainCode; handed.push(code); return code; },
  };
  const copy = hodlCopyPrivateNode(node);
  assert.equal(copy.privateExtendedKey, scureRoot.derive("m/84'/0'/0'").privateExtendedKey);
  assert.equal(handed.length, 2);
  assert.ok(handed.every((bytes) => bytes.every((byte) => byte === 0)), "the source's key or chain code outlived the copy");
  copy.wipePrivateData();
  assert.equal(source.privateExtendedKey, scureRoot.derive("m/84'/0'/0'").privateExtendedKey, "wiping the copy wiped its source");
  // A public node has no private key to copy.
  handed.length = 0;
  source.wipePrivateData();
  assert.equal(hodlCopyPrivateNode(node), null);
  assert.equal(hodlCopyPrivateNode(null), null);
});

test("the multisig co-signer exports wipe every account node they derive", async () => {
  const { hodlBuildMultisigCosignerExports } = await load(["hodlBuildMultisigCosignerExports"]);
  const root = HDKey.fromMasterSeed(mnemonicToSeedSync(MNEMONIC)), derive = root.derive.bind(root), nodes = [];
  root.derive = (path) => { const node = derive(path); nodes.push(node); return node; };
  const exports = hodlBuildMultisigCosignerExports(root, "mainnet", 0, FINGERPRINT, 0);
  assert.equal(nodes.length, exports.length);
  for (const item of exports) {
    const path = item.accountPath.replace(/^m\//, "").split("/").map((step) => step.replace("'", "h")).join("/");
    const xpub = reversion(scureRoot.derive(item.accountPath).publicExtendedKey, VERSIONS.mainnet.x[1]);
    assert.equal(item.value, `[${FINGERPRINT}/${path}]${xpub}`, item.label);
  }
  assert.ok(nodes.every((node) => node.privateKey === null), "a co-signer account node kept its private key");
  root.wipePrivateData();
});

// The wallet.dat builder's private-child dep builds its own HDKey parent and
// child from the account xprv text; like the co-signer exports and the
// address search above, both nodes must be wiped before it returns.
test("the wallet.dat private-child derivation wipes the parent and child nodes it builds", async () => {
  const created = [];
  const api = await load(["hodlWalletDatDeps"], {
    hodlHDKey: {
      fromExtendedKey: (text) => {
        const parent = HDKey.fromExtendedKey(text), deriveChild = parent.deriveChild.bind(parent);
        created.push(parent);
        parent.deriveChild = (index) => {
          // One rejected index stands in for a derivation that fails after
          // the parent exists, so the wipe-on-throw path has a live parent.
          if (index === 0x80000001) throw new Error("derived child is invalid");
          const child = deriveChild(index);
          created.push(child);
          return child;
        };
        return parent;
      },
    },
    hodlSecp256k1: { getPublicKey: () => { throw new Error("not under test"); } },
    canonicalizeWatchDescriptor: () => { throw new Error("not under test"); },
  });
  const derive = api.hodlWalletDatDeps().deriveExtendedPrivateChild;
  // Hardened branch 0 below the BIP84 account key: m/84'/0'/0'/0'.
  assert.equal(derive(expected("mainnet").account.x, 0x80000000), scureRoot.derive("m/84'/0'/0'/0'").privateExtendedKey);
  assert.equal(created.length, 2);
  assert.ok(created.every((node) => node.privateKey === null), "the export left a derived private node unwiped");
  created.length = 0;
  assert.throws(() => derive(expected("mainnet").account.x, 0x80000001), /derived child is invalid/);
  assert.equal(created.length, 1);
  assert.ok(created.every((node) => node.privateKey === null), "a failed derivation left the parent's private key live");
});

test("an address search on hardened branches derives from a wiped copy of the account key", async () => {
  const created = [];
  class TrackedHDKey extends HDKey {
    constructor(options) { super(options); created.push(this); }
    derive(path) { const child = super.derive(path); if (child !== this) created.push(child); return child; }
  }
  for (const name of ["fromMasterSeed", "fromExtendedKey"]) TrackedHDKey[name] = (...args) => HDKey[name](...args);
  // hodlAddressesEqual is a compact one-liner the slice loader cannot cut
  // out; a bech32-only stand-in serves this test's address.
  const api = await load(["hodlMnemonicWalletWithProgress", "hodlMatchHdAddressBeyond"], { hodlHDKey: TrackedHDKey, hodlAddressesEqual: (left, right) => left.toLowerCase() === right.toLowerCase() });
  const hardening = { purpose: true, coinType: true, account: true, script: true, branch: true, address: false };
  const wallet = await api.hodlMnemonicWalletWithProgress(MNEMONIC, "", "mainnet", 2, undefined, 0, 0, tracker, 84, 0, hardening);
  const account = bip84(wallet);
  assert.equal(account.branchHardened, true);
  // Address 5 on the hardened change branch, beyond the two in the table.
  const child = scureRoot.derive("m/84'/0'/0'/1'/5");
  const { p2wpkh } = await import("@scure/btc-signer");
  const expectedPath = account.addressBranches.find((entry) => entry.branch === 1).rows[0].path.replace(/\/0$/, "/5");
  // Twice: the first search must leave the wallet's own key usable.
  for (const round of [1, 2]) {
    created.length = 0;
    const match = api.hodlMatchHdAddressBeyond(p2wpkh(child.publicKey).address, account, 2);
    assert.deepEqual([match.state, match.path], ["match", expectedPath], `search ${round}`);
    assert.ok(created.length > 0, `search ${round}: the search did not work from a copy of the account key`);
    assert.ok(created.every((node) => node.privateKey === null), `search ${round}: the search left a private node unwiped`);
  }
});
