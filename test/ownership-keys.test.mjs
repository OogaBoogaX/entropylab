// Ownership indexing for single (non-HD) session keys and the small
// normalize/label helpers in ownership.js. indexSingleKey is what lets the
// transaction inspectors recognize a wallet derived from a pasted private
// key; a regression there mislabels owned outputs as external (or worse,
// external as ours). Expected addresses are published values for the
// private key 1 (BIP173's own example among them).
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { indexSingleKey, matchOwnership, normalizeAddress, pathLabel } from "../src/js/ownership.js";
import { secp256k1 } from "../src/js/secp256k1.js";

// Fixed public material: the private key 1. Nothing here is secret.
const KEY1 = new Uint8Array(32);
KEY1[31] = 1;

const KEY1_MAINNET = {
  p2pkh: "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
  "p2sh-p2wpkh": "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN",
  p2wpkh: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
  p2tr: "bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9",
  p2pkhUncompressed: "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm",
};
const KEY1_TESTNET_P2WPKH = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
// hash160 of the compressed generator point, from BIP143's own example.
const KEY1_P2WPKH_SCRIPT = "0014751e76e8199196d454941c45d1b3a323f1433bd6";

test("indexSingleKey covers every script type plus the uncompressed legacy form", () => {
  const map = indexSingleKey(KEY1, "mainnet", secp256k1.getPublicKey);
  // Four compressed-key records plus the uncompressed p2pkh record, each
  // remembered under both its address and its raw script hex.
  assert.equal(map.size, 10);
  for (const [script, address] of Object.entries(KEY1_MAINNET)) {
    const hit = matchOwnership(map, address);
    assert.equal(hit.state, "ours", `${script} address must be recognized`);
    assert.equal(hit.scriptType, script === "p2pkhUncompressed" ? "p2pkh" : script);
    assert.equal(hit.role, "key");
    assert.equal(hit.index, null);
    assert.equal(hit.path, script === "p2pkhUncompressed" ? "session key (uncompressed)" : "session key");
  }
  const segwit = matchOwnership(map, KEY1_MAINNET.p2wpkh);
  assert.equal(segwit.bip, "bip84");
  assert.equal(segwit.scriptHex, KEY1_P2WPKH_SCRIPT);
});

test("indexSingleKey indexes testnet scripts under testnet addresses", () => {
  const map = indexSingleKey(KEY1, "testnet", secp256k1.getPublicKey);
  assert.equal(matchOwnership(map, KEY1_TESTNET_P2WPKH).state, "ours");
  assert.equal(matchOwnership(map, KEY1_MAINNET.p2wpkh).state, "external", "mainnet form is not in a testnet index");
});

test("indexSingleKey refuses to index nothing", () => {
  assert.equal(indexSingleKey(null, "mainnet", secp256k1.getPublicKey).size, 0);
  assert.equal(indexSingleKey(KEY1, "mainnet", undefined).size, 0);
});

test("matchOwnership recognizes outputs by raw script, not just address strings", () => {
  const map = indexSingleKey(KEY1, "mainnet", secp256k1.getPublicKey);
  const byBytes = matchOwnership(map, Buffer.from(KEY1_P2WPKH_SCRIPT, "hex"));
  assert.equal(byBytes.state, "ours");
  assert.equal(byBytes.scriptType, "p2wpkh");
  const byText = matchOwnership(map, `  script ${KEY1_P2WPKH_SCRIPT.slice(0, 8)} ${KEY1_P2WPKH_SCRIPT.slice(8)}  `);
  assert.equal(byText.state, "ours", "the script form tolerates whitespace");
  const upper = matchOwnership(map, KEY1_MAINNET.p2wpkh.toUpperCase());
  assert.equal(upper.state, "ours", "bech32 case is normalized");
});

test("matchOwnership reports the empty, no-session, and external states", () => {
  assert.equal(matchOwnership(new Map(), KEY1_MAINNET.p2wpkh).state, "no-session");
  assert.equal(matchOwnership(null, KEY1_MAINNET.p2wpkh).state, "no-session");
  const map = indexSingleKey(KEY1, "mainnet", secp256k1.getPublicKey);
  assert.equal(matchOwnership(map, "   ").state, "empty");
  const miss = matchOwnership(map, "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh");
  assert.equal(miss.state, "external");
  assert.equal(miss.searched, map.size);
});

test("normalizeAddress lowercases bech32 but never base58", () => {
  assert.equal(normalizeAddress("  BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4 "), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
  assert.equal(normalizeAddress(KEY1_MAINNET.p2pkh), KEY1_MAINNET.p2pkh, "base58 is case-sensitive");
  // Mixed-case bech32 is invalid; it is returned as-is so it simply never matches.
  assert.equal(normalizeAddress("bC1Qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"), "bC1Qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
  assert.equal(normalizeAddress(""), "");
  assert.equal(normalizeAddress(null), "");
});

test("pathLabel renders hardened suffixes and rejects non-arrays", () => {
  assert.equal(pathLabel([0x8000002c, 0x80000000, 0x80000005, 1, 7]), "44h/0h/5h/1/7");
  assert.equal(pathLabel([0]), "0");
  assert.equal(pathLabel([]), "");
  assert.equal(pathLabel("m/44'/0'/0'"), "");
  assert.equal(pathLabel(null), "");
});
