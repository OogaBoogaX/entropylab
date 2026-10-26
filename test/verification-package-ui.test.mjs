// Tests for the preview-gated verification package UI in src/js/app.js.
// Run with: node --test test/verification-package-ui.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "url";
import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";
import { NETWORK, TEST_NETWORK, p2pkh, p2sh, p2tr, p2wpkh } from "@scure/btc-signer";
import {
  buildDeriveAddressesCommands,
  buildImportDescriptorsJson,
  descriptorChecksum,
} from "../src/js/core-importdescriptors.js";
import { b58checkDecode, b58checkEncode, descriptorChecksum as harnessChecksum, loadModule } from "./wallet-export-harness.mjs";
import { buildVerificationPackage, verificationPackageFilename } from "../src/js/verification-package.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");
const codec = { decode: b58checkDecode, encode: b58checkEncode };

const seed = mnemonicToSeedSync(
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
);
const master = HDKey.fromMasterSeed(seed);
const fingerprint = master.fingerprint.toString(16).padStart(8, "0");
const nodeA = master.derive("m/48'/0'/0'/2'");
const nodeB = master.derive("m/48'/0'/1'/2'");
const nodeC = master.derive("m/48'/0'/2'/2'");
const keyA = `[${fingerprint}/48h/0h/0h/2h]${nodeA.publicExtendedKey}`;
const keyB = `[${fingerprint}/48h/0h/1h/2h]${nodeB.publicExtendedKey}`;
const keyC = `[${fingerprint}/48h/0h/2h/2h]${nodeC.publicExtendedKey}`;
const receiveBody = `wsh(sortedmulti(2,${keyA}/0/*,${keyB}/0/*,${keyC}/0/*))`;
const changeBody = `wsh(sortedmulti(2,${keyA}/1/*,${keyB}/1/*,${keyC}/1/*))`;
const receive = `${receiveBody}#${descriptorChecksum(receiveBody)}`;
const change = `${changeBody}#${descriptorChecksum(changeBody)}`;

const bip84 = master.derive("m/84'/0'/0'");

const parse = (json) => JSON.parse(json);

// Exercise the application adapter with independently derived public fixtures.
function keyExportHarness() {
  const source = read("src/js/app.js");
  const context = vm.createContext({
    buildImportDescriptorsJson,
    buildDeriveAddressesCommands,
    buildVerificationPackage,
    verificationPackageFilename,
    hodlBase58Check: codec,
    hodlWalletExport: loadModule(),
    hodlDescriptorChecksum: descriptorChecksum,
    hodlT: text => text,
    hodlTText: text => text,
    hodlWalletDatBirthday: "genesis",
    hodlAccountId: "bip84",
    hodlWalletResult: null,
  });
  for (const name of [
    "hodlError",
    "hodlFormatErrorSpec",
    "hodlMsigCoreImportCodec",
    "hodlCoreImportDescriptorsWallet",
    "hodlCoreDescriptorUnits",
    "hodlCoreImportDescriptorsJson",
    "hodlCoreDeriveAddressesText",
    "hodlCoreImportDescriptorsPublicWallet",
    "hodlCoreImportDescriptorsError",
    "hodlCopyCoreImportDescriptors",
    "hodlCopyCoreDeriveAddresses",
    "hodlCopyCoreText",
    "hodlDownloadCoreImportDescriptors",
    "hodlKeyCoreImportDescriptorsMarkup",
    "hodlMsigCoreImportDescriptorsMarkup",
    "hodlCoreImportDescriptorsNote",
    "hodlCoreImportDescriptorsButtons",
    "hodlCoreDeriveAddressesNote",
    "hodlVerificationPackageNote",
    "hodlVerificationPackageJson",
    "hodlDownloadVerificationPackage",
  ]) {
    const match = source.match(new RegExp(`^function ${name}\\([^]*?^}`, "m"));
    assert.ok(match, `application export adapter ${name} exists`);
    vm.runInContext(match[0], context);
  }
  return context;
}

function customAccount(purpose, network, start, count, hardened = false) {
  const mainnet = network === "mainnet";
  const node = HDKey.fromMasterSeed(seed, mainnet ? undefined : { public: 0x043587cf, private: 0x04358394 })
    .derive(`m/${purpose}'/${mainnet ? 0 : 1}'/0'`);
  const wrap = key => purpose === 49 ? `sh(wpkh(${key}))` : `${purpose === 44 ? "pkh" : purpose === 86 ? "tr" : "wpkh"}(${key})`;
  const addressBranches = Array.from({ length: count }, (_, offset) => {
    const branch = start + offset;
    const key = hardened ? `${node.deriveChild(branch + 0x80000000).publicExtendedKey}/*` : `${node.publicExtendedKey}/${branch}/*`;
    const body = wrap(key);
    return { branch, publicDescriptor: `${body}#${harnessChecksum(body)}`, rows: [{ index: branch + 2,
      get privateKey() { throw new Error("row private key read"); } }],
      get privateDescriptor() { throw new Error("branch private descriptor read"); } };
  });
  const account = { def: { id: `bip${purpose}` }, branchStart: start, branchHardened: hardened, addressBranches,
    receiveDescriptor: addressBranches.find(entry => entry.branch === 0)?.publicDescriptor ?? null,
    changeDescriptor: addressBranches.find(entry => entry.branch === 1)?.publicDescriptor ?? null,
    get privateNode() { throw new Error("private node read"); },
    get receiveDescriptorPriv() { throw new Error("private descriptor read"); },
    get changeDescriptorPriv() { throw new Error("private descriptor read"); } };
  const net = mainnet ? NETWORK : { ...TEST_NETWORK, bech32: network === "regtest" ? "bcrt" : "tb" };
  const expectedAddress = (branch, index) => {
    const key = node.deriveChild(branch + (hardened ? 0x80000000 : 0)).deriveChild(index).publicKey;
    return (purpose === 44 ? p2pkh(key, net) : purpose === 49 ? p2sh(p2wpkh(key, net), net) : purpose === 86 ? p2tr(key.slice(1), undefined, net) : p2wpkh(key, net)).address;
  };
  return { account, expectedAddress };
}

function withAddresses(account, expectedAddress) {
  for (const branch of account.addressBranches) {
    for (const row of branch.rows) {
      row.address = expectedAddress(branch.branch, row.index);
    }
  }
  return account;
}

function keyStation() {
  const { account, expectedAddress } = customAccount(84, "mainnet", 0, 2);
  withAddresses(account, expectedAddress);
  account.network = "mainnet";
  account.masterFingerprint = fingerprint;
  account.xpub = bip84.publicExtendedKey;
  return account;
}

function msigResult() {
  return {
    kind: "msig",
    script: "p2wsh",
    network: "mainnet",
    xpubs: [nodeA.publicExtendedKey, nodeB.publicExtendedKey, nodeC.publicExtendedKey],
    receiveDescriptor: receive,
    changeDescriptor: change,
  };
}

function downloadHarness(ui) {
  let link = null;
  ui.document = {
    getElementById: () => null,
    createElement: () => {
      link = { click() {} };
      return link;
    },
  };
  ui.URL = { createObjectURL: () => "blob:test", revokeObjectURL: () => {} };
  ui.Blob = class { constructor() {} };
  ui.setTimeout = () => 0;
  ui.hodlErrorSpecFrom = error => ({ raw: error.message });
  ui.hodlSetWorkspaceError = () => {};
  return () => link;
}

test("Key Station verification package carries public data only", () => {
  const ui = keyExportHarness();
  const account = keyStation();
  ui.hodlWalletResult = { kind: "hd", accounts: [account] };
  const pkg = parse(ui.hodlVerificationPackageJson("calc"));
  assert.equal(pkg.network, "main");
  assert.equal(pkg.masterFingerprint, fingerprint);
  assert.deepEqual(pkg.xpubs, [bip84.publicExtendedKey]);
  assert.deepEqual(pkg.descriptors, [account.receiveDescriptor, account.changeDescriptor]);
  assert.deepEqual(pkg.receiveAddresses, account.addressBranches[0].rows.map(row => ({ index: row.index, address: row.address })));
  assert.deepEqual(pkg.changeAddresses, account.addressBranches[1].rows.map(row => ({ index: row.index, address: row.address })));
});

test("multisig verification package has no master fingerprint and carries its xpubs", () => {
  const ui = keyExportHarness();
  const msig = msigResult();
  ui.hodlWalletResult = msig;
  const pkg = parse(ui.hodlVerificationPackageJson("msig"));
  assert.equal(pkg.masterFingerprint, null);
  assert.deepEqual(pkg.xpubs, msig.xpubs);
  assert.deepEqual(pkg.descriptors, [receive, change]);
});

test("download handler names the verification package file", () => {
  const ui = keyExportHarness();
  ui.hodlWalletResult = { kind: "hd", accounts: [keyStation()] };
  const link = downloadHarness(ui);
  ui.hodlDownloadVerificationPackage("calc");
  assert.equal(link().download, `entropylab-verification-main-${fingerprint}.json`);
});

test("multisig download handler names the verification package file without a fingerprint", () => {
  const ui = keyExportHarness();
  ui.hodlWalletResult = msigResult();
  const link = downloadHarness(ui);
  ui.hodlDownloadVerificationPackage("msig");
  assert.equal(link().download, "entropylab-verification-main.json");
});

test("a refusal reaches the error slot and creates no Blob", () => {
  const ui = keyExportHarness();
  const error = { textContent: "" };
  ui.document = { getElementById: id => id === "key-core-importdescriptors-error" ? error : null };
  ui.hodlErrorSpecFrom = error => ({ raw: error.message });
  let blobs = 0;
  ui.Blob = class { constructor() { blobs++; } };
  const account = keyStation();
  account.receiveDescriptor = "invalid";
  account.addressBranches[0].publicDescriptor = "invalid";
  ui.hodlWalletResult = { kind: "hd", accounts: [account] };
  ui.hodlDownloadVerificationPackage("calc");
  assert.ok(error.textContent, "the refusal reaches the error slot");
  assert.equal(blobs, 0, "no Blob is created");
});

test("the verification package button and note show only in a preview build", () => {
  const ui = keyExportHarness();
  const account = keyStation();
  ui.__ENTROPYLAB_TEST_HOOKS__ = true;
  ui.__ENTROPYLAB_PREVIEW__ = false;
  assert.doesNotMatch(ui.hodlKeyCoreImportDescriptorsMarkup(account), /verification-package/);
  ui.hodlWalletResult = { ...msigResult(), receive: [{ index: 0 }], change: [{ index: 0 }] };
  assert.doesNotMatch(ui.hodlMsigCoreImportDescriptorsMarkup(), /verification-package/);
  ui.__ENTROPYLAB_PREVIEW__ = true;
  for (const [prefix, markup] of [["key", ui.hodlKeyCoreImportDescriptorsMarkup(account)], ["msig", ui.hodlMsigCoreImportDescriptorsMarkup()]]) {
    assert.match(markup, new RegExp(`id="${prefix}-save-verification-package"`));
    assert.ok(markup.includes(`<p class="edge-note is-public" id="${prefix}-verification-package-help">Public data only (descriptors, xpubs, addresses) for checking this wallet with an independent Bitcoin Core tool.</p>`), `${prefix}: the approved note`);
    const saveIndex = markup.indexOf(`id="${prefix}-save-importdescriptors"`);
    const verificationIndex = markup.indexOf(`id="${prefix}-save-verification-package"`);
    assert.ok(saveIndex >= 0 && verificationIndex > saveIndex, `${prefix}: the button follows the Save button`);
  }
});

test("the source binds the verification package download", () => {
  const app = read("src/js/app.js");
  assert.match(app, /\["save-verification-package", hodlDownloadVerificationPackage\]/);
});
