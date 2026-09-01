// Regression guard for #194: hodlDeclaredOutput() used to return after the
// first PSBT_OUT_BIP32_DERIVATION record in an output map. A PSBT creator
// controls the record order, so a foreign-fingerprint record placed first hid
// a later false claim naming the session wallet: the output was labeled
// "other-wallet" and the "PSBT lies ... Do not sign" warning never appeared.
// The verdict must depend on the set of derivation records, not their order.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { HDKey } from "../src/js/hdkey.js";
import { mnemonicToSeedSync } from "../src/js/bip39.js";
import { indexHdKey } from "../src/js/ownership.js";
import { multisigScript, p2wpkhScript, p2wshScript } from "../src/js/addresses.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");

function slice(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let depth = 0;
  for (let index = app.indexOf("{", start); index < app.length; index++) {
    if (app[index] === "{") depth++;
    else if (app[index] === "}" && --depth === 0) return app.slice(start, index + 1);
  }
  throw new Error(`Could not extract ${name}`);
}

const source = [
  `import { hex as hodlHex } from "../src/js/coders.js";`,
  `import { matchOwnership, pathLabel } from "../src/js/ownership.js";`,
  `import { addressFor, addressFromScript } from "../src/js/addresses.js";`,
  "let hodlPsbtHd = null;",
  "export function hodlSetSession(key) { hodlPsbtHd = key; }",
  slice("hodlFingerprintHex"),
  slice("hodlEq"),
  slice("hodlFind"),
  slice("hodlAddr"),
  slice("hodlAddressOrThrow"),
  slice("hodlAddressesEqual"),
  slice("hodlDeclaredOutput"),
  slice("hodlOwnershipWarning"),
  "export { hodlDeclaredOutput, hodlOwnershipWarning };",
].join("\n");

const modulePath = join(root, "test", `.psbt-output-derivation-${process.pid}.mjs`);
writeFileSync(modulePath, source);
let hodlDeclaredOutput, hodlOwnershipWarning, hodlSetSession;
try {
  ({ hodlDeclaredOutput, hodlOwnershipWarning, hodlSetSession } = await import(pathToFileURL(modulePath).href));
} finally {
  unlinkSync(modulePath);
}

const H = 0x80000000;
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
};
const u32le = (n) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, true);
  return b;
};
// BIP174 record values: the master fingerprint as its raw 4 bytes (big-endian
// display order, what hodlHex.encode reproduces) then little-endian path indices.
const u32be = (n) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, false);
  return b;
};
const derivation = (key, fingerprint, path) => ({
  type: 2, // PSBT_OUT_BIP32_DERIVATION
  keydata: key.publicKey,
  val: concat(u32be(fingerprint), ...path.map(u32le)),
});

function permutations(items) {
  if (items.length <= 1) return [items];
  return items.flatMap((item, index) =>
    permutations([...items.slice(0, index), ...items.slice(index + 1)]).map((rest) => [item, ...rest]));
}

const seed = mnemonicToSeedSync("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "");
const hd = HDKey.fromMasterSeed(seed);
const foreign = HDKey.fromMasterSeed(new Uint8Array(32).fill(7));
const cosigner = HDKey.fromMasterSeed(new Uint8Array(32).fill(9));

const changePath = [84 | H, 0 | H, 0 | H, 1, 5];
const receivePath = [84 | H, 0 | H, 0 | H, 0, 0];
const changeNode = hd.derive("m/84'/0'/0'/1/5");
const receiveNode = hd.derive("m/84'/0'/0'/0/0");
const foreignNode = foreign.derive("m/84'/0'/0'/0/0");
const cosignerNode = cosigner.derive("m/48'/0'/0'/2'/0/0");

const changeScript = p2wpkhScript(changeNode.publicKey);
const foreignScript = p2wpkhScript(foreignNode.publicKey);

// An honest record from another wallet.
const foreignRecord = derivation(foreignNode, foreign.fingerprint, receivePath);
// A record naming the session wallet whose keydata the claimed path does not
// produce: the pubkey belongs to the foreign wallet.
const falseKeyRecord = derivation(foreignNode, hd.fingerprint, receivePath);
// A record naming the session wallet with the correct pubkey for the claimed
// path, but the output script pays someone else.
const falseScriptRecord = { type: 2, keydata: receiveNode.publicKey, val: concat(u32be(hd.fingerprint), ...receivePath.map(u32le)) };
// An honest record from the session wallet for the genuine change output.
const validChangeRecord = derivation(changeNode, hd.fingerprint, changePath);

hodlSetSession(hd);

test("a false claim hiding behind a foreign record is still a lie (the #194 attack)", () => {
  assert.equal(hodlDeclaredOutput([foreignRecord, falseKeyRecord], foreignScript, "mainnet").state, "lie");
  assert.equal(hodlDeclaredOutput([falseKeyRecord, foreignRecord], foreignScript, "mainnet").state, "lie");
});

test("a claim whose pubkey matches but whose output script does not is a lie in every order", () => {
  for (const records of permutations([foreignRecord, falseScriptRecord])) {
    assert.equal(hodlDeclaredOutput(records, foreignScript, "mainnet").state, "lie");
  }
});

test("a valid claim hiding behind a foreign record still verifies as ours", () => {
  for (const records of permutations([foreignRecord, validChangeRecord])) {
    const declared = hodlDeclaredOutput(records, changeScript, "mainnet");
    assert.equal(declared.state, "ours");
    assert.equal(declared.role, "change");
    assert.equal(declared.path, "m/84h/0h/0h/1/5");
  }
});

test("every matching-fingerprint claim is validated, even after one verifies", () => {
  for (const records of permutations([validChangeRecord, falseKeyRecord])) {
    assert.equal(hodlDeclaredOutput(records, changeScript, "mainnet").state, "lie");
  }
});

test("multisig cosigner records give the same verdict in every permutation", () => {
  const multisig = p2wshScript(multisigScript(2, [foreignNode.publicKey, cosignerNode.publicKey]));
  const records = [
    derivation(foreignNode, foreign.fingerprint, receivePath),
    derivation(cosignerNode, cosigner.fingerprint, [48 | H, 0 | H, 0 | H, 2 | H, 0, 0]),
  ];
  for (const order of permutations(records)) {
    assert.equal(hodlDeclaredOutput(order, multisig, "mainnet").state, "other-wallet");
  }
  // A cosigner session key alone never produces the multisig script, so its
  // claim cannot verify; crucially the verdict is the same in every order.
  const withSessionKey = [...records, derivation(changeNode, hd.fingerprint, changePath)];
  const verdicts = new Set(permutations(withSessionKey).map((order) => hodlDeclaredOutput(order, multisig, "mainnet").state));
  assert.deepEqual([...verdicts], ["lie"]);
});

test("genuine change does not mask a false claim on another output", () => {
  const outputs = [{ script: changeScript }, { script: foreignScript }];
  const map = indexHdKey(hd, "mainnet", { gap: 10, accounts: 1 });
  // The global ownership warning stays quiet because one output is ours...
  const warning = hodlOwnershipWarning(outputs, "mainnet", map);
  assert.match(warning, /outputs compared against/);
  assert.doesNotMatch(warning, /No output belongs to this session wallet/);
  // ...so only the per-output verdict can catch the false claim, and it must.
  assert.equal(hodlDeclaredOutput([validChangeRecord], changeScript, "mainnet").state, "ours");
  assert.equal(hodlDeclaredOutput([foreignRecord, falseKeyRecord], foreignScript, "mainnet").state, "lie");
});

test("only foreign records report other-wallet only when no record claims the wallet", () => {
  const declared = hodlDeclaredOutput([foreignRecord], foreignScript, "mainnet");
  assert.equal(declared.state, "other-wallet");
  assert.match(declared.fingerprint, /^[0-9a-f]{8}$/);
  assert.equal(hodlDeclaredOutput([], foreignScript, "mainnet"), null);
});

test("malformed derivation records are skipped, not an order-dependent verdict", () => {
  const truncated = { type: 2, keydata: foreignNode.publicKey, val: new Uint8Array(3) };
  const ragged = { type: 2, keydata: foreignNode.publicKey, val: new Uint8Array(9) };
  assert.equal(hodlDeclaredOutput([truncated, ragged], foreignScript, "mainnet"), null);
  for (const records of permutations([truncated, validChangeRecord])) {
    assert.equal(hodlDeclaredOutput(records, changeScript, "mainnet").state, "ours");
  }
});

test("no session key declares nothing", () => {
  hodlSetSession(null);
  try {
    assert.equal(hodlDeclaredOutput([falseKeyRecord], foreignScript, "mainnet"), null);
  } finally {
    hodlSetSession(hd);
  }
});
