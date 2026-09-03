// SLIP-132 single-signature recovery exports and script-type warnings.
// Run with: node --test test/slip132-import.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { HDKey } from "@scure/bip32";
import { base58check } from "@scure/base";
import { p2wpkh } from "@scure/btc-signer";
import { sha256 } from "@noble/hashes/sha2.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");

function loadFunction(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, `missing ${name}`);
  const bodyStart = app.indexOf(") {", start) + 2;
  assert.ok(bodyStart > start + 1, `missing body for ${name}`);
  let depth = 0;
  for (let i = bodyStart; i < app.length; i++) {
    if (app[i] === "{") depth++;
    else if (app[i] === "}" && --depth === 0) return app.slice(start, i + 1);
  }
  throw new Error(`unterminated ${name}`);
}

function extract(startNeedle, endNeedle) {
  const start = app.indexOf(startNeedle);
  const end = app.indexOf(endNeedle, start);
  assert.ok(start >= 0 && end > start, `missing ${startNeedle}`);
  return app.slice(start, end);
}

const INPUT_CHARSET =
  "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`JKLMNOPQRSTUVWXYZ";
const CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN = [0xf5dee51989n, 0xa9fdca3312n, 0x1bab10e32dn, 0x3706b1677an, 0x644d626ffdn];
function descriptorChecksum(body) {
  let checksum = 1n;
  const groups = [];
  const symbols = [];
  for (const character of body) {
    const index = INPUT_CHARSET.indexOf(character);
    assert.ok(index >= 0, `descriptor character ${character}`);
    symbols.push(index & 31);
    groups.push(index >> 5);
    if (groups.length === 3) symbols.push(groups.shift() * 9 + groups.shift() * 3 + groups.shift());
  }
  if (groups.length === 1) symbols.push(groups[0]);
  else if (groups.length === 2) symbols.push(groups[0] * 3 + groups[1]);
  for (const value of [...symbols, 0, 0, 0, 0, 0, 0, 0, 0]) {
    const top = checksum >> 35n;
    checksum = ((checksum & 0x7ffffffffn) << 5n) ^ BigInt(value);
    for (let i = 0; i < 5; i++) if ((top >> BigInt(i)) & 1n) checksum ^= GEN[i];
  }
  checksum ^= 1n;
  let result = "";
  for (let i = 0; i < 8; i++) result += CHECKSUM_CHARSET[Number((checksum >> BigInt(5 * (7 - i))) & 31n)];
  return result;
}
const hodlDescriptorWithChecksum = (body) => `${body}#${descriptorChecksum(body)}`;
const hodlScriptDescriptor = (script, key) => script === "p2wpkh" ? `wpkh(${key})` : script === "p2sh-p2wpkh" ? `sh(wpkh(${key}))` : `pkh(${key})`;

const codec = base58check(sha256);
const hodlBase58Check = { decode: codec.decode, encode: codec.encode };
const hodlExtendedKeyVersions = {
  mainnet: {
    x: { pub: 0x0488b21e, prv: 0x0488ade4, pubName: "xpub", prvName: "xprv" },
    y: { pub: 0x049d7cb2, prv: 0x049d7878, pubName: "ypub", prvName: "yprv" },
    z: { pub: 0x04b24746, prv: 0x04b2430c, pubName: "zpub", prvName: "zprv" },
  },
  testnet: {
    x: { pub: 0x043587cf, prv: 0x04358394, pubName: "tpub", prvName: "tprv" },
    y: { pub: 0x044a5262, prv: 0x044a4e28, pubName: "upub", prvName: "uprv" },
    z: { pub: 0x045f1cf6, prv: 0x045f18bc, pubName: "vpub", prvName: "vprv" },
  },
};
const hodlExtendedKeyPrefixTable = [];
for (const [network, families] of Object.entries(hodlExtendedKeyVersions)) for (const [family, entry] of Object.entries(families)) {
  hodlExtendedKeyPrefixTable.push({ network, family, scope: "singlesig", private: false, ver: entry.pub, name: entry.pubName });
  hodlExtendedKeyPrefixTable.push({ network, family, scope: "singlesig", private: true, ver: entry.prv, name: entry.prvName });
}
const en = JSON.parse(readFileSync(join(root, "src/locales/en.json"), "utf8"));
const hodlT = (key, vars) => {
  let text = en[key] || key;
  if (vars) text = text.replace(/\{(\w+)\}/g, (_, n) => (vars[n] == null ? `{${n}}` : String(vars[n])));
  return text;
};
const hodlNote = (key, vars) => (vars == null ? { key } : { key, vars });
const hodlError = (key, vars) => {
  const err = new Error(hodlT(key, vars));
  err.hodlSpec = vars == null ? { key } : { key, vars };
  return err;
};
const hodlFormatNote = (message) => (message && typeof message === "object" && typeof message.key === "string" ? hodlT(message.key, message.vars) : String(message ?? ""));
const hodlReversionExtendedKey = new Function("hodlBase58Check", `${loadFunction("hodlReversionExtendedKey")}; return hodlReversionExtendedKey;`)(hodlBase58Check);
const hodlReadExtendedKeyVersion = new Function("hodlBase58Check", `${loadFunction("hodlReadExtendedKeyVersion")}; return hodlReadExtendedKeyVersion;`)(hodlBase58Check);
const hodlParseExtendedKey = new Function("hodlBase58Check", "hodlReadExtendedKeyVersion", "hodlReversionExtendedKey", "hodlExtendedKeyPrefixTable", "hodlHDKey", "hodlExtendedKeyVersions", "hodlError", `let hodlParseExtendedKey; ${extract("hodlParseExtendedKey = function(value)", "function hodlAccountExportFamily")}; return hodlParseExtendedKey;`)(hodlBase58Check, hodlReadExtendedKeyVersion, hodlReversionExtendedKey, hodlExtendedKeyPrefixTable, HDKey, hodlExtendedKeyVersions, hodlError);

const hodlAccountExportFamily = new Function(`${loadFunction("hodlAccountExportFamily")}; return hodlAccountExportFamily;`)();
const hodlSerializeExtendedKey = new Function("hodlReversionExtendedKey", "hodlExtendedKeyVersions", `${loadFunction("hodlSerializeExtendedKey")}; return hodlSerializeExtendedKey;`)(hodlReversionExtendedKey, hodlExtendedKeyVersions);
const hodlStripDescriptorChecksum = new Function(`${loadFunction("hodlStripDescriptorChecksum")}; return hodlStripDescriptorChecksum;`)();
const hodlWatchOnlyMultipathDescriptor = new Function("hodlStripDescriptorChecksum", "hodlDescriptorWithChecksum", `${loadFunction("hodlWatchOnlyMultipathDescriptor")}; return hodlWatchOnlyMultipathDescriptor;`)(hodlStripDescriptorChecksum, hodlDescriptorWithChecksum);
const hodlPathComponent = new Function(`${loadFunction("hodlPathComponent")}; return hodlPathComponent;`)();
const hodlOriginPathComponent = new Function(`${loadFunction("hodlOriginPathComponent")}; return hodlOriginPathComponent;`)();
const hodlAddressBranchRole = new Function(`${loadFunction("hodlAddressBranchRole")}; return hodlAddressBranchRole;`)();
const hodlAddressBranchLabel = new Function(`${loadFunction("hodlAddressBranchLabel")}; return hodlAddressBranchLabel;`)();
const hodlAccountResult = new Function(
  "hodlAccountExportFamily", "hodlSerializeExtendedKey", "hodlExtendedKeyVersions", "hodlDescriptorWithChecksum", "hodlScriptDescriptor", "hodlWatchOnlyMultipathDescriptor", "hodlPathComponent", "hodlOriginPathComponent", "hodlAddressBranchRole", "hodlAddressBranchLabel", "hodlDeriveAddressRows",
  `${loadFunction("hodlAccountResult")}; return hodlAccountResult;`,
)(hodlAccountExportFamily, hodlSerializeExtendedKey, hodlExtendedKeyVersions, hodlDescriptorWithChecksum, hodlScriptDescriptor, hodlWatchOnlyMultipathDescriptor, hodlPathComponent, hodlOriginPathComponent, hodlAddressBranchRole, hodlAddressBranchLabel, () => { throw new Error("unexpected address derivation"); });
const hodlScriptTypes = [
  { id: "bip44", label: "Legacy", bip: "BIP44", script: "p2pkh" },
  { id: "bip49", label: "Nested SegWit", bip: "BIP49", script: "p2sh-p2wpkh" },
  { id: "bip84", label: "Native SegWit", bip: "BIP84", script: "p2wpkh" },
];
const hodlScriptUiLabel = new Function("hodlTText", `${loadFunction("hodlScriptUiLabel")}; return hodlScriptUiLabel;`)(hodlT);
const hodlSinglesigScriptMismatch = new Function("hodlScriptTypes", "hodlNote", "hodlScriptUiLabel", `${loadFunction("hodlSinglesigScriptMismatch")}; return hodlSinglesigScriptMismatch;`)(hodlScriptTypes, hodlNote, hodlScriptUiLabel);
const hodlImportedCoreRecoveryData = new Function("hodlDescriptorWithChecksum", "hodlScriptDescriptor", `${loadFunction("hodlImportedCoreRecoveryData")}; return hodlImportedCoreRecoveryData;`)(hodlDescriptorWithChecksum, hodlScriptDescriptor);

// Official BIP84 test vector ("abandon" x11 + "about", account m/84'/0'/0').
// https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki#test-vectors
const ZPUB = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
const XPUB = "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V";
const CORE_DESCRIPTOR = `wpkh(${XPUB}/<0;1>/*)#3r0wrtd9`;

test("published BIP84 zpub vector exposes the same Core xpub and descriptor", () => {
  const parsed = hodlParseExtendedKey(ZPUB);
  assert.equal(parsed.family, "z");
  assert.equal(parsed.scope, "singlesig");
  assert.equal(parsed.network, "mainnet");
  assert.equal(parsed.xkey, XPUB);
  assert.equal(p2wpkh(parsed.node.derive("m/0/0").publicKey).address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
  const account = hodlAccountResult(parsed.node, hodlScriptTypes[2], "mainnet", 1, {
    imported: true,
    importedFamily: parsed.family,
    accountPath: "Imported account key",
    addressBranches: [{ branch: 0, rows: [] }, { branch: 1, rows: [] }],
  });
  assert.equal(account.genericPublic, XPUB);
  assert.equal(account.walletDescriptor, CORE_DESCRIPTOR);
  assert.doesNotMatch(account.walletDescriptor, /\[/);
  const data = hodlImportedCoreRecoveryData({ importedPublicKey: ZPUB, importedPublicLabel: "zpub" }, account);
  assert.deepEqual(data, {
    importedLabel: "Imported zpub",
    importedKey: ZPUB,
    coreLabel: "Core xpub",
    coreKey: XPUB,
    descriptorLabel: "Bitcoin Core descriptor",
    descriptor: CORE_DESCRIPTOR,
  });
});

test("all single-signature SLIP-132 public prefixes preserve payload and expose Core keys", () => {
  for (const [network, family, scriptId] of [
    ["mainnet", "y", "bip49"],
    ["mainnet", "z", "bip84"],
    ["testnet", "y", "bip49"],
    ["testnet", "z", "bip84"],
  ]) {
    const importedKey = hodlReversionExtendedKey(XPUB, hodlExtendedKeyVersions[network][family].pub);
    const parsed = hodlParseExtendedKey(importedKey);
    assert.equal(parsed.network, network);
    assert.equal(parsed.family, family);
    assert.deepEqual([...codec.decode(importedKey).slice(4)], [...codec.decode(parsed.xkey).slice(4)]);
    const definition = hodlScriptTypes.find((candidate) => candidate.id === scriptId);
    const account = hodlAccountResult(parsed.node, definition, network, 1, { imported: true, importedFamily: family, addressBranches: [{ branch: 0, rows: [] }, { branch: 1, rows: [] }] });
    assert.ok(account.genericPublic.startsWith(network === "mainnet" ? "xpub" : "tpub"));
    const data = hodlImportedCoreRecoveryData({ importedPublicKey: importedKey, importedPublicLabel: parsed.prefix }, account);
    assert.equal(data.importedKey, importedKey);
    assert.equal(data.coreKey, account.genericPublic);
    assert.equal(data.coreLabel, `Core ${network === "mainnet" ? "xpub" : "tpub"}`);
    assert.match(data.descriptor, family === "y" ? /^sh\(wpkh\(/ : /^wpkh\(/);
    assert.equal(data.descriptor.slice(-8), descriptorChecksum(data.descriptor.slice(0, data.descriptor.lastIndexOf("#"))));
    assert.equal(hodlSinglesigScriptMismatch(parsed, scriptId), "");
    assert.match(hodlFormatNote(hodlSinglesigScriptMismatch(parsed, scriptId === "bip49" ? "bip84" : "bip44")), /indicates.*selected.*derive/i);
  }
});

test("Core recovery descriptor stays on conventional receive/change branches", () => {
  const parsed = hodlParseExtendedKey(ZPUB);
  const account = hodlAccountResult(parsed.node, hodlScriptTypes[2], "mainnet", 1, {
    imported: true,
    importedFamily: parsed.family,
    branchStart: 7,
    branchRange: 1,
    addressBranches: [{ branch: 7, rows: [] }],
  });
  assert.match(account.walletDescriptor, /\/7\/\*/);
  const data = hodlImportedCoreRecoveryData({ importedPublicKey: ZPUB, importedPublicLabel: "zpub" }, account);
  assert.equal(data.descriptor, CORE_DESCRIPTOR);
});

test("SLIP-132 script mismatch warning is explicit but matching settings are quiet", () => {
  const parsed = hodlParseExtendedKey(ZPUB);
  assert.equal(hodlSinglesigScriptMismatch(parsed, "bip84"), "");
  assert.match(hodlFormatNote(hodlSinglesigScriptMismatch(parsed, "bip44")), /zpub indicates Native SegWit.*selected Legacy.*derive Native SegWit/i);
});

test("generic xpub imports do not claim a script type or duplicate a Core export", () => {
  assert.equal(hodlSinglesigScriptMismatch({ family: "x", prefix: "xpub" }, "bip84"), "");
  assert.equal(hodlImportedCoreRecoveryData({ importedPublicKey: XPUB, importedPublicLabel: "xpub" }, {
    imported: true,
    primaryFamily: "x",
    genericPublic: XPUB,
    genericPublicLabel: "xpub",
    walletDescriptor: `wpkh(${XPUB}/<0;1>/*)`,
  }), null);
});

test("result rendering shows the prefix-swap fields and groups the Core descriptor in one safe block", () => {
  assert.match(app, /function hodlImportedCoreRecoveryExport\(wallet, account\)/);
  assert.match(app, /Bitcoin Core recovery export/);
  assert.match(app, /hodlSlip132WatchFields\(account, hodlWalletResult\)/);
  assert.match(app, /hodlImportedCoreRecoveryExport\(hodlWalletResult, account\)/);
  assert.match(app, /status\.warning \? "err" : "ok"/);
  // The prefix-swap fields above the block already show the pasted key and its
  // Core equivalent; the recovery block adds only the conventional descriptor.
  assert.doesNotMatch(app, /hodlPublicFieldHtml\(data\.importedLabel/);
  assert.doesNotMatch(app, /hodlPublicFieldHtml\(data\.coreLabel/);
  assert.doesNotMatch(app, /innerHTML\s*=\s*wallet\.importedPublicKey/);
});
