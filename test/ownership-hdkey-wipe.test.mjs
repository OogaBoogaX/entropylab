// Audit finding C2-A (security.md): the ownership scan behind PSBT Inspect
// (hodlSessionOwnership) and the Silent-Payments send resolver derives the
// four script types across accounts, chains, and a 50-index gap — 1,200 leaf
// HDKey nodes plus 12 hardened account nodes per default build — and every
// returned node held a live private key that nothing wiped (hodlPsbtWipeMem
// zeroes only the session root). SECURITY.md promises the layer "clears …
// per-address child keys", so indexHdKey must wipe every node it derives
// before returning, while leaving the caller's root untouched and the
// recorded map (public strings only) fully built.
//
// The spy counts nodes through HDKey.prototype.deriveChild (derive() funnels
// through it) and every wipePrivateData() call. Fixture: the published BIP39
// "abandon … about" test wallet; expected node counts follow from the path
// grammar, not from the implementation — each account path is 3 hardened
// steps, each leaf path 2 steps (chain, index).
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { HDKey } from "../src/js/hdkey.js";
import { mnemonicToSeedSync } from "../src/js/bip39.js";
import { indexHdKey, OWNERSHIP_GAP, OWNERSHIP_ACCOUNTS } from "../src/js/ownership.js";

const SEED = mnemonicToSeedSync("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "");

// Root scan: per (script type, account) derive m/purpose'/coin'/account'
// (3 steps) plus chains × gap leaves (2 steps each).
const ROOT_SCAN_NODES = (gap, accounts) => 4 * accounts * (3 + 2 * gap * 2);
// Account-node scan: each leaf is re-derived once per script type.
const ACCOUNT_SCAN_NODES = (gap) => 4 * 2 * gap * 2;

function spyOnNodes(fn) {
  const created = [];
  let wipes = 0;
  const deriveChild = HDKey.prototype.deriveChild;
  const wipe = HDKey.prototype.wipePrivateData;
  HDKey.prototype.deriveChild = function (index) {
    const node = deriveChild.call(this, index);
    created.push(node);
    return node;
  };
  HDKey.prototype.wipePrivateData = function () {
    wipes++;
    return wipe.call(this);
  };
  try {
    return { value: fn(), created, wipes };
  } finally {
    HDKey.prototype.deriveChild = deriveChild;
    HDKey.prototype.wipePrivateData = wipe;
  }
}

function assertAllChildrenWiped({ created, wipes }, expected, label) {
  assert.equal(created.length, expected, `${label}: the scan derives ${expected} nodes`);
  for (const [i, node] of created.entries()) {
    assert.equal(node.hasPrivateKey, false, `${label}: derived node ${i} still holds its private key`);
  }
  // derive() wipes its own dead intermediates; indexHdKey must account for
  // every node it keeps to the end — together exactly one wipe per node.
  assert.equal(wipes, created.length, `${label}: every derived node is wiped exactly once`);
}

test("C2-A: a default root scan wipes all 1,212 returned account and leaf nodes", () => {
  const root = HDKey.fromMasterSeed(SEED);
  const spy = spyOnNodes(() => indexHdKey(root, "mainnet"));
  assert.ok(spy.value.size > 0, "the ownership index is still built");
  assertAllChildrenWiped(spy, ROOT_SCAN_NODES(OWNERSHIP_GAP, OWNERSHIP_ACCOUNTS), "indexHdKey(root)");
  assert.equal(root.hasPrivateKey, true, "the caller's root is not indexHdKey's to wipe");
  root.wipePrivateData();
});

test("C2-A: an account-level private node scan wipes every derived leaf", () => {
  const master = HDKey.fromMasterSeed(SEED);
  const account = master.derive("m/84'/0'/0'");
  master.wipePrivateData();
  const spy = spyOnNodes(() => indexHdKey(account, "mainnet", { gap: 2, accounts: 1 }));
  assert.ok(spy.value.size > 0);
  assertAllChildrenWiped(spy, ACCOUNT_SCAN_NODES(2), "indexHdKey(account node)");
  assert.equal(account.hasPrivateKey, true, "the caller's node is not indexHdKey's to wipe");
  account.wipePrivateData();
});

test("C2-A: a watch-only scan still records the map and nothing private survives", () => {
  const master = HDKey.fromMasterSeed(SEED);
  const watch = master.derive("m/84'/0'/0'").neutered();
  master.wipePrivateData();
  const spy = spyOnNodes(() => indexHdKey(watch, "mainnet", { gap: 2, accounts: 1 }));
  assert.ok(spy.value.size > 0, "a watch-only index still records the public data");
  assertAllChildrenWiped(spy, ACCOUNT_SCAN_NODES(2), "indexHdKey(watch-only)");
});
