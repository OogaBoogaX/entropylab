// Multisig co-signer fields accept a pasted output descriptor (issue #175).
// A descriptor holding exactly one co-signer key is reduced to that key
// origin plus extended public key; a full multisig descriptor lists every
// co-signer and must fail with directions instead of silently picking a
// position.
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
  return app.slice(start, end);
}

const source = [
  loadSlice("hodlStripDescriptorChecksum"),
  loadSlice("hodlNormalizeOriginPath"),
  loadSlice("hodlParseKeyOrigin"),
  loadSlice("hodlDescriptorKeyExpressions"),
  loadSlice("hodlParseMultisigCosigner"),
].join("\n");
// Stub the extended-key decoder: these tests assert which key text the parser
// hands to it, and how the origin metadata survives, not base58check itself.
const hodlParseExtendedKey = (key) => ({ receivedKey: key });
const hodlParseMultisigCosigner = new Function("hodlParseExtendedKey", `${source}; return hodlParseMultisigCosigner;`)(hodlParseExtendedKey);
const hodlDescriptorKeyExpressions = new Function(`${source}; return hodlDescriptorKeyExpressions;`)();

const base58check = createBase58check(sha256);
const seed = mnemonicToSeedSync(
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
);
const master = HDKey.fromMasterSeed(seed);
const fingerprint = master.fingerprint.toString(16).padStart(8, "0");

// Re-encode an extended key with different version bytes (xpub -> Zpub etc.).
const reversion = (xkey, version) => {
  const payload = base58check.decode(xkey);
  payload.set([(version >>> 24) & 0xff, (version >>> 16) & 0xff, (version >>> 8) & 0xff, version & 0xff], 0);
  return base58check.encode(payload);
};
const ZPUB = 0x02aa7ed3;

const nodeA = master.derive("m/48'/0'/0'/2'");
const nodeB = master.derive("m/48'/0'/1'/2'");
const nodeC = master.derive("m/48'/0'/2'/2'");
const zpubA = reversion(nodeA.publicExtendedKey, ZPUB);
const zpubB = reversion(nodeB.publicExtendedKey, ZPUB);
const zpubC = reversion(nodeC.publicExtendedKey, ZPUB);
const originA = `[${fingerprint}/48'/0'/0'/2h]`;
const originB = `[${fingerprint}/48'/0'/1'/2h]`;
const originC = `[${fingerprint}/48'/0'/2'/2h]`;

test("plain xpub and origin-plus-xpub inputs are untouched", () => {
  assert.equal(hodlDescriptorKeyExpressions(zpubA), null);
  assert.equal(hodlDescriptorKeyExpressions(`${originA}${zpubA}`), null);
  assert.equal(hodlDescriptorKeyExpressions(`  ${originA}${zpubA}/0/*  `), null);
  const parsed = hodlParseMultisigCosigner(`${originA}${zpubA}`);
  assert.equal(parsed.receivedKey, zpubA);
  assert.equal(parsed.origin.fingerprint, fingerprint);
  assert.equal(parsed.origin.path, "48h/0h/0h/2h");
});

test("a single-sig descriptor yields its one key with origin intact", () => {
  const descriptor = `wpkh(${originA}${zpubA}/0/*)`;
  const parsed = hodlParseMultisigCosigner(descriptor);
  assert.equal(parsed.receivedKey, zpubA, "the decoder must receive the bare extended key, suffix stripped");
  assert.equal(parsed.origin.fingerprint, fingerprint);
  assert.equal(parsed.origin.path, "48h/0h/0h/2h");
});

test("a one-key multisig wrapper and multipath suffixes are accepted", () => {
  for (const descriptor of [
    `wsh(sortedmulti(2,${originA}${zpubA}/<0;1>/*))`,
    `sh(wsh(multi(1,${zpubA}/0/*)))`,
    `wsh(sortedmulti(1,${originA}${zpubA}/0/*))#abcdef12`,
  ]) {
    const parsed = hodlParseMultisigCosigner(descriptor);
    assert.equal(parsed.receivedKey, zpubA, descriptor);
  }
  const bare = hodlParseMultisigCosigner(`sh(wsh(multi(1,${zpubA}/0/*)))`);
  assert.equal(bare.origin, null, "no origin brackets means no origin metadata");
});

test("a full multisig descriptor fails instead of picking a position", () => {
  const descriptor = `wsh(sortedmulti(2,${originA}${zpubA}/0/*,${originB}${zpubB}/0/*,${originC}${zpubC}/0/*))`;
  assert.throws(
    () => hodlParseMultisigCosigner(descriptor),
    /lists 3 co-signer keys/,
  );
  const expressions = hodlDescriptorKeyExpressions(descriptor);
  assert.equal(expressions.length, 3);
  assert.deepEqual(
    expressions.map((entry) => entry.key),
    [zpubA, zpubB, zpubC],
  );
  assert.equal(expressions[1].origin, originB);
});

test("a descriptor without an extended public key fails with directions", () => {
  assert.throws(
    () => hodlParseMultisigCosigner("wsh(pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798))"),
    /does not contain an extended public key/,
  );
  assert.throws(() => hodlParseMultisigCosigner("wsh(sortedmulti(2,))"), /does not contain an extended public key/);
});

test("extended private keys are never extracted from a descriptor", () => {
  const xprv = nodeA.privateExtendedKey;
  assert.ok(xprv.startsWith("xprv"));
  assert.throws(
    () => hodlParseMultisigCosigner(`wpkh(${originA}${xprv}/0/*)`),
    /does not contain an extended public key/,
  );
  const zprv = reversion(nodeA.privateExtendedKey, 0x02aa7a99);
  assert.ok(zprv.startsWith("Zprv"));
  assert.throws(
    () => hodlParseMultisigCosigner(`wsh(sortedmulti(2,${originA}${zprv}/0/*))`),
    /does not contain an extended public key/,
  );
});
