// Tests for the script/address WASM facade (src/js/addresses.js) and the
// bech32m facade (src/js/bech32.js), backed by rust-bitcoin's Address/
// ScriptBuf and bech32 crates (entropylab-wasm/). Run with `npm test`.
//
// Three layers of assurance:
//  1. Fixed, independently published constants (the generator-point legacy
//     address, the BIP173/BIP350 reference address, the BIP86 first address,
//     and the BIP433 P2A address).
//  2. Differential checks against @scure/btc-signer and @scure/base (pinned,
//     previously the implementation).
//  3. Round-trips through the existing PSBT/descriptors suites exercise these
//     paths end to end (psbt-*, descriptor, msig-*, bip352 tests).
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { NETWORK, TEST_NETWORK, p2pkh, p2sh, p2tr, p2wpkh } from "@scure/btc-signer";
import { bech32m } from "@scure/base";
import { base58checkEncode, base58checkDecode } from "../src/js/base58.js";
import { bech32mDecode, bech32mEncode, fromWords, toWords } from "../src/js/bech32.js";
import { addressFor, addressFromScript, descriptorDerive, multisigScript, multisigTrScript, p2pkhScript, p2shP2wpkhScript, p2shScript, p2trKeyScript, p2trLeafScript, p2wpkhScript, p2wshScript } from "../src/js/addresses.js";
import { hex, base64 } from "../src/js/coders.js";
import { hash160 } from "../src/js/hashes.js";

const hexToBytes = (h) => hex.decode(h);
const bytesToHex = (b) => hex.encode(b);
const sha256Sync = (bytes) => new Uint8Array(createHash("sha256").update(bytes).digest());
const G_COMPRESSED = hexToBytes("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
const G_UNCOMPRESSED = hexToBytes("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
const NUMS = hexToBytes("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0");

test("generator point renders its published legacy and SegWit addresses", () => {
  // Well-known: secret key 1.
  assert.equal(addressFor("p2pkh", G_COMPRESSED, "mainnet"), "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
  // BIP173/BIP350 reference P2WPKH address for the generator's hash160.
  assert.equal(addressFor("p2wpkh", G_COMPRESSED, "mainnet"), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
  assert.equal(addressFor("p2wpkh", G_COMPRESSED, "testnet"), "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx");
});

test("BIP86 first address matches the published vector", async () => {
  // BIP86 test vector: mnemonic "abandon ... about", m/86'/0'/0'/0/0.
  const { HDKey } = await import("../src/js/hdkey.js");
  const { mnemonicToSeedSync } = await import("../src/js/bip39.js");
  const seed = mnemonicToSeedSync("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "");
  const node = HDKey.fromMasterSeed(seed).derive("m/86'/0'/0'/0/0");
  assert.equal(
    addressFor("p2tr", node.publicKey, "mainnet"),
    "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
  );
});

test("differential: addresses match @scure/btc-signer for every template", () => {
  for (const [network, net] of [["mainnet", NETWORK], ["testnet", TEST_NETWORK]]) {
    for (const key of [G_COMPRESSED, G_UNCOMPRESSED]) {
      assert.equal(addressFor("p2pkh", key, network), p2pkh(key, net).address, `p2pkh ${network}`);
      if (key.length === 33) {
        assert.equal(addressFor("p2wpkh", key, network), p2wpkh(key, net).address, `p2wpkh ${network}`);
        assert.equal(addressFor("p2sh-p2wpkh", key, network), p2sh(p2wpkh(key, net), net).address, `p2sh-p2wpkh ${network}`);
        assert.equal(addressFor("p2tr", key, network), p2tr(key.slice(1), undefined, net).address, `p2tr ${network}`);
      } else {
        assert.throws(() => p2wpkhScript(key), /compressed/);
        assert.throws(() => p2shP2wpkhScript(key), /compressed/);
      }
    }
  }
});

test("differential: script bytes match scure for every template", () => {
  assert.equal(bytesToHex(p2pkhScript(G_COMPRESSED)), bytesToHex(p2pkh(G_COMPRESSED, NETWORK).script));
  assert.equal(bytesToHex(p2wpkhScript(G_COMPRESSED)), bytesToHex(p2wpkh(G_COMPRESSED, NETWORK).script));
  assert.equal(bytesToHex(p2shP2wpkhScript(G_COMPRESSED)), bytesToHex(p2sh(p2wpkh(G_COMPRESSED, NETWORK), NETWORK).script));
  assert.equal(bytesToHex(p2trKeyScript(G_COMPRESSED.slice(1))), bytesToHex(p2tr(G_COMPRESSED.slice(1), undefined, NETWORK).script));
});

test("P2SH/P2WSH wrapping matches scure", () => {
  const redeem = p2wpkhScript(G_COMPRESSED);
  assert.equal(bytesToHex(p2shScript(redeem)), bytesToHex(p2sh({ script: redeem }, NETWORK).script));
  assert.equal(bytesToHex(p2wshScript(redeem)), "0020" + bytesToHex(sha256Sync(redeem)));
});

test("multisig scripts match scure's ms and tr_ms encodings", () => {
  const keys = [G_COMPRESSED, hexToBytes("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")];
  const ours = multisigScript(2, keys);
  // scure reference shape: OP_2 <pk1> <pk2> OP_2 OP_CHECKMULTISIG
  assert.equal(bytesToHex(ours), "5221" + bytesToHex(keys[0]) + "21" + bytesToHex(keys[1]) + "52ae");
  const xonly = keys.map((k) => k.slice(1));
  const tr = multisigTrScript(1, xonly);
  assert.equal(bytesToHex(tr), "20" + bytesToHex(xonly[0]) + "ac" + "20" + bytesToHex(xonly[1]) + "ba" + "519c");
  // and the leaf tweaks to the same address scure's p2tr with that leaf makes
  const scureTr = p2tr(NUMS, { script: tr }, NETWORK);
  assert.equal(addressFromScript(p2trLeafScript(NUMS, tr), "mainnet"), scureTr.address);
});

test("P2A (BIP433) renders the fixed address", () => {
  const p2a = hexToBytes("51024e73");
  assert.equal(addressFromScript(p2a, "mainnet"), "bc1pfeessrawgf");
});

test("unknown scripts return null (caller shows script hex)", () => {
  assert.equal(addressFromScript(hexToBytes("6a0b68656c6c6f20776f726c64"), "mainnet"), null); // OP_RETURN
  assert.equal(addressFromScript(hexToBytes("00" + "14".padStart(2, "0")), "mainnet"), null); // truncated
});

test("bech32m word-level encode/decode matches @scure/base including >90 chars", () => {
  const payload = new Uint8Array(66).map((_, i) => (i * 41 + 7) & 0xff); // BIP352-sized
  const words = [0, ...toWords(payload)];
  const ours = bech32mEncode("sp", words);
  const theirs = bech32m.encode("sp", words, 1023);
  assert.equal(ours, theirs);
  assert.ok(ours.length > 90, "silent payment addresses exceed the BIP173 limit");
  const decoded = bech32mDecode(ours);
  assert.equal(decoded.prefix, "sp");
  assert.deepEqual(decoded.words, words);
  assert.deepEqual(Array.from(fromWords(decoded.words.slice(1))), Array.from(payload));
  // scure decodes the same string identically
  const scureDecoded = bech32m.decodeUnsafe(ours, 1023);
  assert.equal(scureDecoded.prefix, decoded.prefix);
  assert.deepEqual(scureDecoded.words, decoded.words);
  // bad checksum -> null (decodeUnsafe-style), not a throw
  const tampered = ours.slice(0, -2) + (ours.endsWith("q") ? "p" : "q");
  assert.equal(bech32mDecode(tampered), null);
});

// ── descriptorDerive: rust-miniscript through the WASM boundary ──────────────

test("descriptorDerive derives the app taproot multisig (sortedmulti_a)", () => {
  // Same keys and NUMS internal key as the msig-address-kinds vectors.
  const keys = [G_COMPRESSED, hexToBytes("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"), hexToBytes("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")];
  const inner = (list) => list.map((k) => bytesToHex(k.slice(1))).join(",");
  const sorted = descriptorDerive(`tr(${bytesToHex(NUMS)},sortedmulti_a(2,${inner(keys)}))`, 0, "mainnet");
  assert.equal(sorted.address, "bc1pm5jn9xnjz3v9xm7jjw2yheajy92pps5fdazdpfnmvzfymu787hhs2vktyy");
  // sortedmulti_a ignores the written order; multi_a is defined by it.
  const reversed = [...keys].reverse();
  assert.equal(descriptorDerive(`tr(${bytesToHex(NUMS)},sortedmulti_a(2,${inner(reversed)}))`, 0, "mainnet").scriptHex, sorted.scriptHex);
  assert.notEqual(descriptorDerive(`tr(${bytesToHex(NUMS)},multi_a(2,${inner(reversed)}))`, 0, "mainnet").scriptHex, sorted.scriptHex);
});

test("descriptorDerive: xpub descriptors and raw-key descriptors agree", async () => {
  // The two paths to a multisig address must never drift: deriving the
  // branch descriptor's xpubs in the crate equals deriving the child keys
  // (hdkey.js, BIP32-vector-tested) and evaluating the raw-key descriptor.
  const { HDKey } = await import("../src/js/hdkey.js");
  const cosigners = [
    "[73c5da0a/48h/1h/0h/2h]tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ",
    "[b8688df1/48h/1h/0h/2h]tpubDEfobrrtptRTbKf4gysDhoabneABDTAcdj3Vbn4XwPsLE2pmqpizSPRG6zHsbAMuiSgWmWPsYCLHTKTPpyrGJ5rAoTpKoQNZcxodiPf2tSJ",
    "[3f635a63/48h/1h/0h/2h]tpubDFPtPArj4GzBEFHohegg1Xatrc1Fi9oSox5LzuSRX91miwQxuUrEpBxpvDRsmZYJKYFhgdK3UStsjC8JKXfUbMinjFqiEM4uNwzVaCaHpys",
  ];
  const branchDescriptor = `wsh(sortedmulti(2,${cosigners.map((c) => `${c}/0/*`).join(",")}))`;
  for (const index of [0, 1, 7]) {
    const fromXpubs = descriptorDerive(branchDescriptor, index, "testnet");
    const rawKeys = cosigners.map((c) => HDKey.fromExtendedKey(c.slice(c.indexOf("]") + 1), { private: 0x04358394, public: 0x043587cf }).derive(`m/0/${index}`).publicKey);
    const fromRawKeys = descriptorDerive(`wsh(sortedmulti(2,${rawKeys.map((k) => bytesToHex(k)).join(",")}))`, 0, "testnet");
    assert.equal(fromXpubs.address, fromRawKeys.address, `index ${index}`);
    assert.equal(fromXpubs.scriptHex, fromRawKeys.scriptHex, `index ${index}`);
    assert.deepEqual(fromXpubs.pubkeys, fromRawKeys.pubkeys, `index ${index}`);
    assert.match(fromXpubs.address, /^tb1q/);
  }
  // The Taproot flow (BIP87-style origins, x-only keys under the NUMS
  // internal key) agrees the same way, with sortedmulti_a doing the sort.
  const taprootDescriptor = `tr(${bytesToHex(NUMS)},sortedmulti_a(2,${cosigners.map((c) => `${c}/1/*`).join(",")}))`;
  for (const index of [0, 3]) {
    const fromXpubs = descriptorDerive(taprootDescriptor, index, "testnet");
    const rawKeys = cosigners.map((c) => HDKey.fromExtendedKey(c.slice(c.indexOf("]") + 1), { private: 0x04358394, public: 0x043587cf }).derive(`m/1/${index}`).publicKey);
    const fromRawKeys = descriptorDerive(`tr(${bytesToHex(NUMS)},sortedmulti_a(2,${rawKeys.map((k) => bytesToHex(k.slice(1))).join(",")}))`, 0, "testnet");
    assert.equal(fromXpubs.address, fromRawKeys.address, `taproot index ${index}`);
    assert.equal(fromXpubs.scriptHex, fromRawKeys.scriptHex, `taproot index ${index}`);
    assert.match(fromXpubs.address, /^tb1p/);
  }
});

test("descriptorDerive verifies a supplied #checksum and refuses multipath", () => {
  const body = `tr(${bytesToHex(NUMS)},sortedmulti_a(2,${bytesToHex(G_COMPRESSED.slice(1))},${bytesToHex(hexToBytes("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5").slice(1))}))`;
  const good = descriptorDerive(body, 0, "mainnet");
  // rfjlk7yv is the BIP380 checksum of this exact body (the app's Le agrees).
  const checksummed = descriptorDerive(`${body}#rfjlk7yv`, 0, "mainnet");
  assert.equal(checksummed.scriptHex, good.scriptHex);
  assert.throws(() => descriptorDerive(`${body}#qqqqqqqq`, 0, "mainnet"), /Invalid output descriptor/);
  assert.throws(() => descriptorDerive("wpkh(xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/<0;1>/*)", 0, "mainnet"), /Invalid output descriptor/);
  assert.throws(() => descriptorDerive(body, 0, "regtest"), /Unknown Bitcoin network/);
});

test("base58check and coders match @scure/base", async () => {
  const { createBase58check, hex: scureHex, base64: scureBase64 } = await import("@scure/base");
  const { sha256 } = await import("../src/js/hashes.js");
  const scure58 = createBase58check(sha256);
  for (let i = 0; i < 8; i++) {
    const payload = new Uint8Array(21 + (i % 3) * 13).map((_, j) => (i * 91 + j * 7) & 0xff);
    const encoded = base58checkEncode(payload);
    assert.equal(encoded, scure58.encode(payload));
    assert.deepEqual(Array.from(base58checkDecode(encoded)), Array.from(payload));
    assert.equal(hex.encode(payload), scureHex.encode(payload));
    assert.deepEqual(Array.from(hex.decode(hex.encode(payload))), Array.from(payload));
    assert.equal(base64.encode(payload), scureBase64.encode(payload));
  }
  assert.throws(() => base58checkDecode("0OIl"));
  assert.throws(() => hex.decode("xyz"));
});
