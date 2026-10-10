// HDKey.privateKey returns a fresh copy on every read (src/js/hdkey.js). A
// truthiness check such as Boolean(node.privateKey) or !node.privateKey
// throws that copy away unzeroed, and a call that reads the getter several
// times (scanNode.privateKey.slice(), getPublicKey(node.privateKey, …))
// leaves every read but the kept one in freed heap slots. The residue audit
// measured exactly this shape of leak in freed PartitionAlloc slots after
// Wipe (issue #546).
//
// Contract: a truthiness check on an HDKey must not copy the private key,
// and every getter copy a function takes is all zero once that function
// returns, on success and on refusal. What the functions accept, refuse and
// derive is unchanged.
//
// Expected values come from published vectors, not from the code under
// test: BIP32 test vector 1 (bitcoin/bips BIP-0032) and the BIP-85
// HMAC-SHA512 test cases (bip-0085.mediawiki). Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { HDKey as ScureHDKey } from "@scure/bip32";
import { HDKey } from "../src/js/hdkey.js";
import { deriveSilentPaymentKeys } from "../src/js/bip352.js";
import { deriveBip85Entropy } from "../src/js/bip85.js";
import { loadAppFunctions } from "./app-slice-harness.mjs";

const hexToBytes = (hex) => new Uint8Array(hex.match(/.{2}/g).map((b) => parseInt(b, 16)));
const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

// BIP32 test vector 1's seed and master keys (bitcoin/bips BIP-0032).
const SEED = hexToBytes("000102030405060708090a0b0c0d0e0f");
const XPRV = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
const XPUB = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
// BIP-85's own master root key and HMAC-SHA512 test case 1
// (bip-0085.mediawiki).
const BIP85_MASTER = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";
const BIP85_CASE1 = "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7";

// Runs fn() with a recording wrapper on the app HDKey's privateKey getter,
// and returns fn()'s value plus every copy the getter handed out.
function recordGetterCopies(fn) {
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
    return { value: fn(), copies };
  } finally {
    Object.defineProperty(HDKey.prototype, "privateKey", original);
  }
}
function assertAllZero(copies, label, { kept = [] } = {}) {
  for (const [i, copy] of copies.entries()) {
    if (kept.includes(copy)) continue;
    assert.ok(copy.every((b) => b === 0), `${label}: getter copy ${i + 1} of ${copies.length} still holds the private key`);
  }
}

test("BIP-352 session derivation takes one getter copy per key, and hands both to the caller", () => {
  // The all-zero smoke seed and the derived path shape are pinned by the
  // existing BIP-352 suite; the recorded copies are the new assertion.
  const seed = hexToBytes("00".repeat(64));
  const { value: keys, copies } = recordGetterCopies(() => deriveSilentPaymentKeys(seed, { coinType: 0, account: 0 }));
  // The session owns scanPriv/spendPriv; every other read must be zero.
  assertAllZero(copies, "deriveSilentPaymentKeys", { kept: [keys.scanPriv, keys.spendPriv] });
  assert.equal(copies.length, 2, "exactly one getter copy per session key, no duplicates");
  assert.equal(keys.scanPath, "m/352'/0'/0'/1'/0");
  assert.equal(keys.spendPath, "m/352'/0'/0'/0'/0");
  assert.equal(keys.scanPriv.length, 32);
  assert.equal(keys.spendPriv.length, 32);
});

test("BIP-85 entropy derivation zeroes every getter copy, and the watch-only refusal takes none", () => {
  // The BIP-85 spec's master root, so the published HMAC test case applies.
  const root = HDKey.fromExtendedKey(BIP85_MASTER);
  const { value: entropy, copies } = recordGetterCopies(() => deriveBip85Entropy(root, "m/83696968'/0'/0'"));
  // The kept copy (the derived child's key) is wiped by the function; the
  // watch-only truthiness check must not add an unzeroed one.
  assertAllZero(copies, "deriveBip85Entropy");
  assert.ok(copies.length > 0, "the derived child's key is read once and wiped");
  assert.equal(bytesToHex(entropy), BIP85_CASE1);
  // A watch-only root is refused, and the refusal leaves no copy behind.
  // With no preflight, the fully-hardened path refuses inside derive()
  // ("Could not derive hardened child key") before any private key exists.
  const watch = HDKey.fromExtendedKey(XPUB);
  const { copies: refuseCopies } = recordGetterCopies(() => {
    assert.throws(() => deriveBip85Entropy(watch, "m/83696968'/0'/0'"));
  });
  assert.equal(refuseCopies.length, 0, "a watch-only refusal must not read the privateKey getter at all");
});

test("@scure/bip32 roots derive the published BIP-85 vector, and the compatibility path takes no discarded getter copy", () => {
  // The existing suites hand @scure/bip32 HDKeys to deriveBip85Entropy. The
  // pinned scure 2.4.0 getter returns a FRESH copy (Uint8Array.from), not an
  // alias of the node — so a truthiness fallback like Boolean(root.privateKey)
  // would create and discard an unzeroed copy. Record every copy scure's
  // getter hands out and prove the only ones taken are wiped, never dropped.
  const scureRoot = ScureHDKey.fromExtendedKey(BIP85_MASTER);
  const copies = [];
  const original = Object.getOwnPropertyDescriptor(ScureHDKey.prototype, "privateKey");
  Object.defineProperty(ScureHDKey.prototype, "privateKey", {
    configurable: true,
    get() {
      const copy = original.get.call(this);
      if (copy) copies.push(copy);
      return copy;
    },
  });
  let entropy;
  try {
    entropy = deriveBip85Entropy(scureRoot, "m/83696968'/0'/0'");
  } finally {
    Object.defineProperty(ScureHDKey.prototype, "privateKey", original);
  }
  assert.equal(bytesToHex(entropy), BIP85_CASE1);
  assertAllZero(copies, "deriveBip85Entropy on a scure root");
  // The node's own key material must survive untouched as well.
  const after = original.get.call(scureRoot);
  assert.notEqual(after.every((b) => b === 0), true, "the scure root must still hold its key");
  after.fill(0);
});

// ---- app.js sites, loaded through the slice harness ----

// The prefix table rows the parsed keys need stand in for the page-boot
// statements the harness does not run.
const XPRV_VERSION = 0x0488ade4, XPUB_VERSION = 0x0488b21e;
const hodlExtendedKeyPrefixTable = [
  { network: "mainnet", family: "x", scope: "singlesig", private: true, ver: XPRV_VERSION, name: "xprv" },
  { network: "mainnet", family: "x", scope: "singlesig", private: false, ver: XPUB_VERSION, name: "xpub" },
];

test("hodlParseExtendedKey's prefix check reads no private-key copy at all", async () => {
  const app = await loadAppFunctions(["hodlParseExtendedKey"], { stubs: { hodlExtendedKeyPrefixTable } });
  const { copies } = recordGetterCopies(() => {
    const parsed = app.hodlParseExtendedKey(XPRV);
    assert.equal(parsed.isPrivate, true);
    assert.equal(parsed.xkey, XPRV);
    parsed.node.wipePrivateData();
    const watch = app.hodlParseExtendedKey(XPUB);
    assert.equal(watch.isPrivate, false);
  });
  assert.equal(copies.length, 0, "the prefix check answers from hasPrivateKey, never the copying getter");
});

test("hodlRootWalletResult's multisig branch takes no unzeroed root-key copy", async () => {
  const app = await loadAppFunctions(["hodlRootWalletResult"], { stubs: {} });
  const root = HDKey.fromMasterSeed(SEED);
  const source = { entropy: null, passphraseUsed: false, notes: [], warnings: [] };
  const { value: result, copies } = recordGetterCopies(() => app.hodlRootWalletResult(root, "mainnet", source, 0, "73c5da0a", []));
  assert.equal(result.kind, "hd");
  assert.equal(result.rootXpub, XPUB);
  assert.ok(result.multisigCosignerExports.length > 0, "a private root produces multisig cosigner exports");
  result.rootNode?.wipePrivateData();
  assertAllZero(copies, "hodlRootWalletResult");
});
