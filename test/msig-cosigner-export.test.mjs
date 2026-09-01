// Multisig co-signer exports default to plain xpub/tpub with a key-origin
// bracket; SLIP-132 multisig prefixes (Ypub/Zpub/Upub/Vpub) remain accepted
// on paste but are never what the app hands out.
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";
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

function loadObjectLiteral(name) {
  const start = app.indexOf(`${name} = {`);
  assert.ok(start >= 0, `missing ${name}`);
  const braceStart = app.indexOf("{", start);
  let depth = 0;
  for (let i = braceStart; i < app.length; i++) {
    if (app[i] === "{") depth++;
    else if (app[i] === "}" && --depth === 0) return app.slice(braceStart, i + 1);
  }
  throw new Error(`unterminated ${name}`);
}

const hodlBase58Check = createBase58check(sha256);
const hodlExtendedKeyVersions = new Function(`return ${loadObjectLiteral("hodlExtendedKeyVersions")};`)();
const hodlReversionExtendedKey = new Function("hodlBase58Check", `${loadFunction("hodlReversionExtendedKey")}; return hodlReversionExtendedKey;`)(hodlBase58Check);
const hodlSerializeExtendedKey = new Function("hodlReversionExtendedKey", "hodlExtendedKeyVersions", `${loadFunction("hodlSerializeExtendedKey")}; return hodlSerializeExtendedKey;`)(hodlReversionExtendedKey, hodlExtendedKeyVersions);
const hodlCoinTypeFromNetwork = new Function(`${loadFunction("hodlCoinTypeFromNetwork")}; return hodlCoinTypeFromNetwork;`)();
const hodlBuildMultisigCosignerExports = new Function(
  "hodlSerializeExtendedKey", "hodlExtendedKeyVersions", "hodlCoinTypeFromNetwork",
  `${loadFunction("hodlBuildMultisigCosignerExports")}; return hodlBuildMultisigCosignerExports;`,
)(hodlSerializeExtendedKey, hodlExtendedKeyVersions, hodlCoinTypeFromNetwork);
const hodlMultisigPrefixCompatible = new Function(`${loadFunction("hodlMultisigPrefixCompatible")}; return hodlMultisigPrefixCompatible;`)();

// BIP39 "abandon" x11 + "about"; master fingerprint 73c5da0a.
const seed = mnemonicToSeedSync("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
const FINGERPRINT = "73c5da0a";

test("default multisig co-signer exports are plain xpub/tpub, never SLIP-132", () => {
  for (const [network, pub, banned] of [
    ["mainnet", "xpub", /(?:ypub|zpub|Ypub|Zpub)/],
    ["testnet", "tpub", /(?:upub|vpub|Upub|Vpub)/],
  ]) {
    const exports = hodlBuildMultisigCosignerExports(HDKey.fromMasterSeed(seed), network, 0, FINGERPRINT);
    assert.equal(exports.length, 5);
    for (const item of exports) {
      assert.equal(item.prefix, pub, `${network} ${item.label}`);
      assert.match(item.value, new RegExp(`^\\[${FINGERPRINT}\\/[\\dh/]+\\]${pub}`), `${network} ${item.label}`);
      assert.doesNotMatch(item.value, banned, `${network} ${item.label}`);
    }
  }
});

test("the xpub-default export carries the same account key as before", () => {
  const node = HDKey.fromMasterSeed(seed).derive("m/48'/0'/0'/2'");
  const exports = hodlBuildMultisigCosignerExports(HDKey.fromMasterSeed(seed), "mainnet", 0, FINGERPRINT);
  const native = exports.find((item) => item.kind === "p2wsh");
  assert.equal(native.value, `[${FINGERPRINT}/48h/0h/0h/2h]${node.publicExtendedKey}`);
});

test("pasted SLIP-132 multisig keys still pass the prefix gate", () => {
  // scope/family pairs as produced by hodlParseExtendedKey for pasted keys.
  const zpubMsig = { scope: "multisig", family: "z" };
  const ypubMsig = { scope: "multisig", family: "y" };
  const xpubGeneric = { scope: "singlesig", family: "x" };
  const zpubSinglesig = { scope: "singlesig", family: "z" };
  assert.equal(hodlMultisigPrefixCompatible(zpubMsig, "p2wsh", 48), true);
  assert.equal(hodlMultisigPrefixCompatible(ypubMsig, "p2sh-p2wsh", 48), true);
  assert.equal(hodlMultisigPrefixCompatible(zpubMsig, "p2sh-p2wsh", 48), false);
  for (const kind of ["p2sh", "p2sh-p2wsh", "p2wsh", "p2tr"]) {
    assert.equal(hodlMultisigPrefixCompatible(xpubGeneric, kind, 48), true, `xpub for ${kind}`);
  }
  assert.equal(hodlMultisigPrefixCompatible(zpubSinglesig, "p2wsh", 48), false);
});
