// Reusing one Key Station key for more than one co-signer is only valid with
// a derivation path appended after the extended key (xpub…/1): the descriptor
// derives each co-signer's public keys through that path, so the same account
// key stays one co-signer per distinct path and identical paths still clash.
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";
import { hex as hodlHex } from "@scure/base";
import { createBase58check } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");

function loadFunction(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, `missing ${name}`);
  let depth = 0;
  for (let i = app.indexOf("{", start); i < app.length; i++) {
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

const codec = createBase58check(sha256);
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
const hodlReversionExtendedKey = new Function("hodlBase58Check", `${loadFunction("hodlReversionExtendedKey")}; return hodlReversionExtendedKey;`)(hodlBase58Check);
const hodlReadExtendedKeyVersion = new Function("hodlBase58Check", `${loadFunction("hodlReadExtendedKeyVersion")}; return hodlReadExtendedKeyVersion;`)(hodlBase58Check);
const hodlParseExtendedKey = new Function("hodlBase58Check", "hodlReadExtendedKeyVersion", "hodlReversionExtendedKey", "hodlExtendedKeyPrefixTable", "hodlHDKey", "hodlExtendedKeyVersions", `let hodlParseExtendedKey; ${extract("hodlParseExtendedKey = function(value)", "function hodlAccountExportFamily")}; return hodlParseExtendedKey;`)(hodlBase58Check, hodlReadExtendedKeyVersion, hodlReversionExtendedKey, hodlExtendedKeyPrefixTable, HDKey, hodlExtendedKeyVersions);
const hodlNormalizeOriginPath = new Function(`${loadFunction("hodlNormalizeOriginPath")}; return hodlNormalizeOriginPath;`)();
const hodlParseKeyOrigin = new Function("hodlNormalizeOriginPath", `${loadFunction("hodlParseKeyOrigin")}; return hodlParseKeyOrigin;`)(hodlNormalizeOriginPath);
const hodlStripDescriptorChecksum = new Function(`${loadFunction("hodlStripDescriptorChecksum")}; return hodlStripDescriptorChecksum;`)();
const hodlDescriptorKeyExpressions = new Function("hodlStripDescriptorChecksum", `${loadFunction("hodlDescriptorKeyExpressions")}; return hodlDescriptorKeyExpressions;`)(hodlStripDescriptorChecksum);
const hodlParseMultisigCosigner = new Function("hodlParseKeyOrigin", "hodlParseExtendedKey", "hodlDescriptorKeyExpressions", `${loadFunction("hodlParseMultisigCosigner")}; return hodlParseMultisigCosigner;`)(hodlParseKeyOrigin, hodlParseExtendedKey, hodlDescriptorKeyExpressions);
const hodlNetworkFamily = new Function(`${loadFunction("hodlNetworkFamily")}; return hodlNetworkFamily;`)();
const hodlSerializeExtendedKey = new Function("hodlReversionExtendedKey", "hodlExtendedKeyVersions", "hodlNetworkFamily", `${loadFunction("hodlSerializeExtendedKey")}; return hodlSerializeExtendedKey;`)(hodlReversionExtendedKey, hodlExtendedKeyVersions, hodlNetworkFamily);
const hodlMultisigKeyToken = new Function("hodlSerializeExtendedKey", `${loadFunction("hodlMultisigKeyToken")}; return hodlMultisigKeyToken;`)(hodlSerializeExtendedKey);
const hodlMsigDerivedNode = new Function(`${loadFunction("hodlMsigDerivedNode")}; return hodlMsigDerivedNode;`)();
const hodlStripMsigKeyPath = new Function(`${loadFunction("hodlStripMsigKeyPath")}; return hodlStripMsigKeyPath;`)();

// BIP39 "abandon" x11 + "about"; master fingerprint 73c5da0a.
const seed = mnemonicToSeedSync("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
const node = HDKey.fromMasterSeed(seed).derive("m/48'/0'/0'/2'");
const EXPORT = `[73c5da0a/48h/0h/0h/2h]${node.publicExtendedKey}`;

test("a plain co-signer export carries no derivation path", () => {
  const parsed = hodlParseMultisigCosigner(EXPORT);
  assert.equal(parsed.derivationPath, "");
  assert.equal(hodlMultisigKeyToken(parsed, "mainnet"), EXPORT);
});

test("a path after the extended key parses and lands in the descriptor token", () => {
  const parsed = hodlParseMultisigCosigner(`${EXPORT}/1`);
  assert.equal(parsed.derivationPath, "1");
  assert.equal(parsed.origin.fingerprint, "73c5da0a");
  assert.equal(parsed.origin.path, "48h/0h/0h/2h");
  assert.equal(hodlMultisigKeyToken(parsed, "mainnet"), `${EXPORT}/1`);
  const deeper = hodlParseMultisigCosigner(`${EXPORT}/0/2`);
  assert.equal(deeper.derivationPath, "0/2");
  assert.equal(hodlMultisigKeyToken(deeper, "mainnet"), `${EXPORT}/0/2`);
});

test("a pasted descriptor key tail is a branch wildcard, not a co-signer path", () => {
  assert.equal(hodlParseMultisigCosigner(`${EXPORT}/0/*`).derivationPath, "");
  assert.equal(hodlParseMultisigCosigner(`${EXPORT}/<0;1>/*`).derivationPath, "");
  // Two or more steps ahead of the wildcard are the signer's fixed path and
  // are preserved in full — only a sole branch step (/0/* above) drops.
  assert.equal(hodlParseMultisigCosigner(`${EXPORT}/1/0/*`).derivationPath, "1/0");
  assert.equal(hodlParseMultisigCosigner(`${EXPORT}/0/0/20/*`).derivationPath, "0/0/20");
});

test("hardened or out-of-range path steps are rejected with a clear error", () => {
  assert.throws(() => hodlParseMultisigCosigner(`${EXPORT}/1'`), /must be unhardened/);
  assert.throws(() => hodlParseMultisigCosigner(`${EXPORT}/1h`), /must be unhardened/);
  assert.throws(() => hodlParseMultisigCosigner(`${EXPORT}/2147483648`), /out of range/);
});

test("the derived co-signer node follows the appended path", () => {
  const parsed = hodlParseMultisigCosigner(`${EXPORT}/1`);
  assert.equal(hodlHex.encode(hodlMsigDerivedNode(parsed).publicKey), hodlHex.encode(node.derive("m/1").publicKey));
  assert.equal(hodlHex.encode(hodlMsigDerivedNode(hodlParseMultisigCosigner(EXPORT)).publicKey), hodlHex.encode(node.publicKey));
});

test("stripping the path returns the export a session key picked", () => {
  assert.equal(hodlStripMsigKeyPath(`${EXPORT}/1`), EXPORT);
  assert.equal(hodlStripMsigKeyPath(`${EXPORT}/0/2`), EXPORT);
  assert.equal(hodlStripMsigKeyPath(`${EXPORT}/1/0/*`), EXPORT);
  assert.equal(hodlStripMsigKeyPath(EXPORT), EXPORT);
});
