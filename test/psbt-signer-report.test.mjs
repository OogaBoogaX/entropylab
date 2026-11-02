// The signer availability report module, alone: real HDKey roots, scripts and
// entries built by hand. Expected values come from the BIPs and from the
// fixture generator's published keys, never from the code under test.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { HDKey } from "../src/js/hdkey.js";
import { hash160, sha256 } from "../src/js/hashes.js";
import { mnemonicToSeedSync } from "../src/js/bip39.js";
import { psbtSignerReport, signerReportPolicy, signerReportFallbackPaths, SIGNER_REPORT_GAP } from "../src/js/psbt-signer-report.js";

const bytes = (...values) => Uint8Array.from(values);
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};
const hex = (text) => Uint8Array.from(text.match(/../g).map((pair) => Number.parseInt(pair, 16)));
const toHex = (value) => Buffer.from(value).toString("hex");
const entry = (type, keydata = new Uint8Array(), val = new Uint8Array()) => ({ type, keydata, val });
const push = (key) => concat(bytes(0x21), key);
const multisig = (m, keys) => concat(bytes(0x50 + m), ...keys.map(push), bytes(0x50 + keys.length, 0xae));
const p2wsh = (script) => concat(bytes(0x00, 0x20), sha256(script));
const p2sh = (script) => concat(bytes(0xa9, 0x14), hash160(script), bytes(0x87));
const p2wpkh = (pubkey) => concat(bytes(0x00, 0x14), hash160(pubkey));
const p2pkh = (pubkey) => concat(bytes(0x76, 0xa9, 0x14), hash160(pubkey), bytes(0x88, 0xac));
const bip32 = (fingerprint, path) => {
  const val = new Uint8Array(4 + 4 * path.length);
  new DataView(val.buffer).setUint32(0, fingerprint >>> 0);
  path.forEach((step, i) => new DataView(val.buffer).setUint32(4 + 4 * i, step >>> 0, true));
  return val;
};
const HARD = 0x80000000;

const rootA = HDKey.fromMasterSeed(new Uint8Array(32).fill(1));
const rootB = HDKey.fromMasterSeed(new Uint8Array(32).fill(2));
const rootC = HDKey.fromMasterSeed(new Uint8Array(32).fill(3));
const cosigner = (root) => {
  const node = root.derive("m/48'/0'/0'/2'/0/0");
  const pubkey = node.publicKey;
  node.wipePrivateData();
  return pubkey;
};
const pkA = cosigner(rootA), pkB = cosigner(rootB), pkC = cosigner(rootC);
const COSIGNER_PATH = [48 + HARD, HARD, HARD, 2 + HARD, 0, 0];
const source = (id, root, label = id) => ({ id, label, private: true, node: root });

const witnessScript = multisig(2, [pkA, pkB, pkC]);
const p2wshPrevout = { script: p2wsh(witnessScript), amount: 100000n };
const declared = (pubkey, fingerprint, path) => entry(6, pubkey, bip32(fingerprint, path));
const multiInput = (extra = []) => ({ entries: [entry(5, new Uint8Array(), witnessScript), ...extra], prevout: p2wshPrevout, prevoutConflict: false });

test("2-of-3 P2WSH with declared paths: one, two and three signers", () => {
  const input = multiInput([declared(pkA, rootA.fingerprint, COSIGNER_PATH), declared(pkB, rootB.fingerprint, COSIGNER_PATH), declared(pkC, rootC.fingerprint, COSIGNER_PATH)]);
  const one = psbtSignerReport({ inputs: [input], sources: [source("a", rootA)], network: "mainnet" });
  assert.equal(one.inputs[0].state, "short");
  assert.equal(one.inputs[0].signed + one.inputs[0].canAdd, 1);
  const two = psbtSignerReport({ inputs: [input], sources: [source("a", rootA), source("b", rootB)], network: "mainnet" });
  assert.equal(two.inputs[0].state, "ready");
  assert.equal(two.inputs[0].all, false);
  const three = psbtSignerReport({ inputs: [input], sources: [source("a", rootA), source("b", rootB), source("c", rootC)], network: "mainnet" });
  assert.equal(three.inputs[0].state, "ready");
  assert.equal(three.inputs[0].all, true);
  // The same key loaded twice never adds a signer.
  const twice = psbtSignerReport({ inputs: [input], sources: [source("a", rootA), source("a2", rootA)], network: "mainnet" });
  assert.equal(twice.inputs[0].state, "short");
  assert.equal(twice.inputs[0].signed + twice.inputs[0].canAdd, 1);
  assert.deepEqual(twice.inputs[0].signers.map((signer) => signer.id).sort(), ["a", "a2"]);
});

test("wrong fingerprints in the file fall back to the searched paths", () => {
  const input = multiInput([declared(pkA, 0xdeadbeef, COSIGNER_PATH), declared(pkB, 0xdeadbeef, COSIGNER_PATH)]);
  const report = psbtSignerReport({ inputs: [input], sources: [source("a", rootA), source("b", rootB)], network: "mainnet" });
  assert.equal(report.inputs[0].state, "ready");
  assert.deepEqual(report.inputs[0].signers.map((signer) => signer.path).sort(), ["m/48h/0h/0h/2h/0/0", "m/48h/0h/0h/2h/0/0"]);
  // Index 25 is past the gap: not found, and the budget is not exhausted.
  const deep = rootA.derive("m/48'/0'/0'/2'/0/25");
  const deepPubkey = deep.publicKey;
  deep.wipePrivateData();
  const beyond = psbtSignerReport({ inputs: [{ entries: [entry(5, new Uint8Array(), multisig(1, [deepPubkey]))], prevout: { script: p2wsh(multisig(1, [deepPubkey])), amount: 1000n }, prevoutConflict: false }], sources: [source("a", rootA)], network: "mainnet" });
  assert.equal(beyond.inputs[0].state, "short");
  assert.equal(beyond.exhausted, false);
});

test("purpose is never tied to script type: a 44 key signs a P2WPKH input", () => {
  const node = rootA.derive("m/44'/0'/0'/0/3");
  const pubkey = node.publicKey;
  node.wipePrivateData();
  const report = psbtSignerReport({ inputs: [{ entries: [], prevout: { script: p2wpkh(pubkey), amount: 1000n }, prevoutConflict: false }], sources: [source("a", rootA)], network: "mainnet" });
  assert.equal(report.inputs[0].state, "ready");
  assert.equal(report.inputs[0].signers[0].path, "m/44h/0h/0h/0/3");
});

test("the published BIP39 anchor signs its BIP-84 P2WPKH input", () => {
  const seed = mnemonicToSeedSync("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "");
  const root = HDKey.fromMasterSeed(seed);
  assert.equal(root.fingerprint, 0x73c5da0a);
  const node = root.derive("m/84'/0'/0'/0/0");
  assert.equal(toHex(node.publicKey), "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c");
  const pubkey = node.publicKey;
  node.wipePrivateData();
  const report = psbtSignerReport({ inputs: [{ entries: [], prevout: { script: p2wpkh(pubkey), amount: 1000n }, prevoutConflict: false }], sources: [source("a", root)], network: "mainnet" });
  assert.equal(report.inputs[0].state, "ready");
  assert.equal(report.inputs[0].signers[0].path, "m/84h/0h/0h/0/0");
  root.wipePrivateData();
});

test("policy edge cases: uncompressed keys, and the P2SH shapes", async () => {
  const uncompressed = rootA.derive("m/44'/0'/0'/0/0");
  const uncompressedPubkey = uncompressed.publicKey.toBytes ? uncompressed.publicKey : null;
  uncompressed.wipePrivateData();
  // A single-key source carrying both encodings signs a P2PKH input.
  const priv = new Uint8Array(32).fill(7);
  const { secp256k1 } = await import("../src/js/secp256k1.js");
  const compressedKey = secp256k1.getPublicKey(priv, true), uncompressedKey = secp256k1.getPublicKey(priv, false);
  const single = { id: "s", label: "s", private: true, pubkeys: [compressedKey, uncompressedKey] };
  const p2pkhReport = psbtSignerReport({ inputs: [{ entries: [], prevout: { script: p2pkh(uncompressedKey), amount: 1000n }, prevoutConflict: false }], sources: [single], network: "mainnet" });
  assert.equal(p2pkhReport.inputs[0].state, "ready");
  // A P2WPKH input takes compressed keys only.
  const witnessReport = psbtSignerReport({ inputs: [{ entries: [], prevout: { script: p2wpkh(uncompressedKey), amount: 1000n }, prevoutConflict: false }], sources: [single], network: "mainnet" });
  assert.equal(witnessReport.inputs[0].state, "short");
  // The three P2SH shapes classify with the right script, m and n.
  const redeem = p2wpkh(compressedKey);
  assert.equal(signerReportPolicy({ entries: [entry(4, new Uint8Array(), redeem)], prevout: { script: p2sh(redeem), amount: 1n } }).script, "p2sh-p2wpkh");
  const bare = multisig(2, [pkA, pkB, pkC]);
  const barePolicy = signerReportPolicy({ entries: [entry(4, new Uint8Array(), bare)], prevout: { script: p2sh(bare), amount: 1n } });
  assert.deepEqual([barePolicy.script, barePolicy.m, barePolicy.n], ["p2sh", 2, 3]);
  const nested = signerReportPolicy({ entries: [entry(4, new Uint8Array(), p2wsh(bare)), entry(5, new Uint8Array(), bare)], prevout: { script: p2sh(p2wsh(bare)), amount: 1n } });
  assert.deepEqual([nested.script, nested.m, nested.n], ["p2sh-p2wsh", 2, 3]);
});

test("policy errors are refused, never guessed", () => {
  const bare = multisig(2, [pkA, pkB, pkC]);
  assert.deepEqual(signerReportPolicy({ entries: [], prevout: { script: p2wsh(bare), amount: 1n } }), { kind: "unknown", reason: "no-script" });
  assert.deepEqual(signerReportPolicy({ entries: [entry(5, new Uint8Array(), multisig(2, [pkA, pkB]))], prevout: { script: p2wsh(bare), amount: 1n } }), { kind: "unknown", reason: "script-mismatch" });
  const repeated = multisig(2, [pkA, pkA, pkB]);
  assert.deepEqual(signerReportPolicy({ entries: [entry(5, new Uint8Array(), repeated)], prevout: { script: p2wsh(repeated), amount: 1n } }), { kind: "unsupported", reason: "repeated-keys" });
  assert.deepEqual(signerReportPolicy({ entries: [], prevout: { script: concat(bytes(0x51, 0x20), new Uint8Array(32)), amount: 1n } }), { kind: "unsupported", reason: "taproot" });
  assert.deepEqual(signerReportPolicy({ entries: [], prevout: { script: bytes(0x6a, 0x01, 0x00), amount: 1n } }), { kind: "unsupported", reason: "script-type" });
  assert.deepEqual(signerReportPolicy({ entries: [], prevout: null, prevoutConflict: false }), { kind: "unknown", reason: "no-prevout" });
  assert.deepEqual(signerReportPolicy({ entries: [], prevout: null, prevoutConflict: true }), { kind: "unknown", reason: "prevout-conflict" });
  assert.deepEqual(signerReportPolicy({ entries: [entry(8)], prevout: p2wshPrevout, prevoutConflict: false }), { kind: "finalized" });
});

test("partial signatures are counted once, from the verifier's own answer", () => {
  const input = multiInput([entry(2, pkA, bytes(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01))]);
  const calls = [];
  const verify = (index, pubkey, signature) => { calls.push(toHex(pubkey)); return true; };
  const report = psbtSignerReport({ inputs: [input], sources: [source("b", rootB)], network: "mainnet", verify });
  assert.equal(report.inputs[0].signed, 1);
  assert.equal(report.inputs[0].state, "ready");
  assert.equal(calls.length, 1, "one check per (input, policy key)");
  // A false answer is invalid and counts nowhere.
  const invalid = psbtSignerReport({ inputs: [input], sources: [], network: "mainnet", verify: () => false });
  assert.equal(invalid.inputs[0].invalid, 1);
  assert.equal(invalid.inputs[0].state, "short");
  // An unchecked answer with no private key for that slot is unknown.
  const unchecked = psbtSignerReport({ inputs: [input], sources: [source("b", rootB)], network: "mainnet", verify: () => null });
  assert.equal(unchecked.inputs[0].state, "unknown");
  assert.equal(unchecked.inputs[0].reason, "unchecked-signatures");
});

test("watch-only matches are kept apart from usable private keys", () => {
  const account = rootA.derive("m/84'/0'/0'");
  const watch = account.neutered();
  account.wipePrivateData();
  const node = rootA.derive("m/84'/0'/0'/0/1");
  const pubkey = node.publicKey;
  node.wipePrivateData();
  const input = { entries: [], prevout: { script: p2wpkh(pubkey), amount: 1000n }, prevoutConflict: false };
  const publicSource = { id: "w", label: "watch", private: false, node: watch };
  const short = psbtSignerReport({ inputs: [input], sources: [publicSource], network: "mainnet" });
  assert.equal(short.inputs[0].state, "short");
  assert.equal(short.inputs[0].watchOnly, 1);
  assert.deepEqual(short.inputs[0].watchers.map((watcher) => watcher.label), ["watch"]);
  const ready = psbtSignerReport({ inputs: [input], sources: [publicSource, source("a", rootA)], network: "mainnet" });
  assert.equal(ready.inputs[0].state, "ready");
  // A public root with a hardened declared path matches nothing and throws nothing.
  const hardened = psbtSignerReport({ inputs: [{ entries: [declared(pubkey, rootA.fingerprint, [84 + HARD, HARD, HARD, 0, 1])], prevout: input.prevout, prevoutConflict: false }], sources: [{ id: "w", label: "watch", private: false, node: rootA.neutered() }], network: "mainnet" });
  assert.equal(hardened.inputs[0].state, "short");
});

test("the derivation budget bounds the report and says so", () => {
  const node = rootA.derive("m/84'/0'/0'/0/0");
  const pubkey = node.publicKey;
  node.wipePrivateData();
  const report = psbtSignerReport({ inputs: [{ entries: [], prevout: { script: p2wpkh(pubkey), amount: 1000n }, prevoutConflict: false }], sources: [source("a", rootA)], network: "mainnet", budget: 5 });
  assert.equal(report.inputs[0].state, "unknown");
  assert.equal(report.inputs[0].reason, "budget");
  assert.equal(report.exhausted, true);
});

test("the summary counts every input and adds up to the total", () => {
  const finalized = { entries: [entry(8)], prevout: null, prevoutConflict: false };
  const taproot = { entries: [], prevout: { script: concat(bytes(0x51, 0x20), new Uint8Array(32)), amount: 1n }, prevoutConflict: false };
  const report = psbtSignerReport({ inputs: [multiInput(), finalized, taproot], sources: [source("a", rootA), source("b", rootB), source("c", rootC)], network: "mainnet" });
  assert.equal(report.summary.total, 3);
  assert.equal(report.summary.ready, 1);
  assert.equal(report.summary.done, 1);
  assert.equal(report.summary.unknown, 1);
  assert.equal(report.summary.ready + report.summary.done + report.summary.short + report.summary.unknown, report.summary.total);
});

test("signerReportFallbackPaths names the accounts in order, with the coin type", () => {
  assert.deepEqual(signerReportFallbackPaths("mainnet").map((entry) => entry.label), [
    "m/44h/0h/0h", "m/49h/0h/0h", "m/84h/0h/0h", "m/48h/0h/0h/1h", "m/48h/0h/0h/2h", "m/87h/0h/0h", "m/45h",
  ]);
  assert.deepEqual(signerReportFallbackPaths("testnet").map((entry) => entry.label), [
    "m/44h/1h/0h", "m/49h/1h/0h", "m/84h/1h/0h", "m/48h/1h/0h/1h", "m/48h/1h/0h/2h", "m/87h/1h/0h", "m/45h",
  ]);
  assert.deepEqual(signerReportFallbackPaths("mainnet")[0].path, [44 + HARD, HARD, HARD]);
  assert.equal(SIGNER_REPORT_GAP, 20);
});

test("every node the report derives is wiped, and the source roots are not", () => {
  const created = [];
  const deriveChild = HDKey.prototype.deriveChild;
  const wipe = HDKey.prototype.wipePrivateData;
  HDKey.prototype.deriveChild = function (index) {
    const node = deriveChild.call(this, index);
    created.push(node);
    return node;
  };
  HDKey.prototype.wipePrivateData = function () {
    return wipe.call(this);
  };
  try {
    psbtSignerReport({ inputs: [multiInput([declared(pkA, rootA.fingerprint, COSIGNER_PATH)])], sources: [source("a", rootA)], network: "mainnet" });
  } finally {
    HDKey.prototype.deriveChild = deriveChild;
    HDKey.prototype.wipePrivateData = wipe;
  }
  assert.ok(created.length > 0, "the report derived nodes");
  for (const [i, node] of created.entries()) assert.equal(node.hasPrivateKey, false, `derived node ${i} still holds its private key`);
  assert.equal(rootA.hasPrivateKey, true, "the caller's root is not the report's to wipe");
});

test("the report never reads the privateKey getter", () => {
  const copies = [];
  const original = Object.getOwnPropertyDescriptor(HDKey.prototype, "privateKey");
  Object.defineProperty(HDKey.prototype, "privateKey", {
    configurable: true,
    get() {
      const copy = original.get.call(this);
      if (copy) copies.push(copy);
      return copy;
    },
  });
  try {
    psbtSignerReport({ inputs: [multiInput([declared(pkA, rootA.fingerprint, COSIGNER_PATH)])], sources: [source("a", rootA)], network: "mainnet" });
  } finally {
    Object.defineProperty(HDKey.prototype, "privateKey", original);
  }
  assert.equal(copies.length, 0, "the report must never read privateKey");
});

test("the module is pure: no private fields, no network, no dynamic import", () => {
  const text = readFileSync(new URL("../src/js/psbt-signer-report.js", import.meta.url), "utf8");
  for (const forbidden of ["privateKey", "privateExtendedKey", "fetch(", "XMLHttpRequest", "WebSocket", "import("]) {
    assert.ok(!text.includes(forbidden), `the module must not contain ${forbidden}`);
  }
});
