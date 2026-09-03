import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyScript, compareAddressAndScript, inspectAddress, inspectScriptPubKey } from "../src/js/scriptpubkey-inspector.js";

const WPKH_ADDRESS = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const WPKH_SCRIPT = "0014751e76e8199196d454941c45d1b3a323f1433bd6";
const P2SH_SCRIPT = "a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba87";
const P2SH_ADDRESS = "3EExK1K1TF3v7zsFtQHt14XqexCwgmXM1y";
const P2A_SCRIPT = "51024e73";
const P2A_ADDRESS = "bc1pfeessrawgf";
const BARE_MS =
  "5221030000000000000000000000000000000000000000000000000000000000000001210300000000000000000000000000000000000000000000000000000000000000022103000000000000000000000000000000000000000000000000000000000000000353ae";
const P2PK = "210300000000000000000000000000000000000000000000000000000000000001ac";

test("BIP350 v0 address resolves to its scriptPubKey", () => {
  const result = inspectAddress(WPKH_ADDRESS, "mainnet");
  assert.equal(result.state, "recognized");
  assert.equal(result.type, "p2wpkh");
  assert.equal(result.scriptHex, WPKH_SCRIPT);
});

test("scriptPubKey resolves back to the supported address", () => {
  const result = inspectScriptPubKey(WPKH_SCRIPT, "mainnet");
  assert.equal(result.type, "p2wpkh");
  assert.equal(result.address, WPKH_ADDRESS);
});

test("address and script comparison matches by bytes, not spelling", () => {
  const result = compareAddressAndScript(`  ${WPKH_ADDRESS.toUpperCase()}  `, `00\n14 751e76e8199196d454941c45d1b3a323f1433bd6`, "mainnet");
  assert.equal(result.state, "match");
});

test("non-matching address and script are reported", () => {
  const result = compareAddressAndScript(WPKH_ADDRESS, "0014" + "00".repeat(20), "mainnet");
  assert.equal(result.state, "mismatch");
});

test("malformed address and checksum failure are invalid", () => {
  assert.equal(inspectAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", "mainnet").state, "invalid");
  assert.equal(inspectAddress("not-an-address", "mainnet").state, "invalid");
});

test("malformed script hex becomes an invalid inspection result while whitespace is accepted", () => {
  const malformed = inspectScriptPubKey("0014xz", "mainnet");
  assert.equal(malformed.type, "invalid");
  assert.match(malformed.label, /hexadecimal/);
  assert.equal(inspectScriptPubKey("  00\n14\t751e76e8199196d454941c45d1b3a323f1433bd6  ", "mainnet").scriptHex, WPKH_SCRIPT);
  assert.equal(inspectScriptPubKey("0", "mainnet").type, "invalid");
});

test("P2SH classification does not infer an unavailable redeem script", () => {
  const result = inspectScriptPubKey(P2SH_SCRIPT, "mainnet");
  assert.equal(result.type, "p2sh");
  assert.equal(result.label, "P2SH");
  assert.equal(result.address, P2SH_ADDRESS);
  assert.equal(inspectAddress(P2SH_ADDRESS, "mainnet").scriptHex, P2SH_SCRIPT);
});

test("valid non-addressable scripts remain distinct from invalid hex", () => {
  assert.deepEqual(classifyScript(Uint8Array.from(Buffer.from("6a02abcd", "hex"))), {
    type: "op_return",
    label: "OP_RETURN",
    addressable: false,
  });
  assert.equal(classifyScript(Uint8Array.from(Buffer.from(P2PK, "hex"))).type, "p2pk");
  assert.equal(classifyScript(Uint8Array.from(Buffer.from(BARE_MS, "hex"))).type, "multisig");
  assert.equal(inspectScriptPubKey("51ae", "mainnet").type, "unknown");
});

test("P2A is recognized and keeps its address representation", () => {
  const result = inspectScriptPubKey(P2A_SCRIPT, "mainnet");
  assert.equal(result.type, "p2a");
  assert.equal(result.address, P2A_ADDRESS);
  assert.equal(inspectAddress(P2A_ADDRESS, "mainnet").scriptHex, P2A_SCRIPT);
});

test("malformed witness programs are never presented as recognized addresses", () => {
  const result = inspectScriptPubKey("0015" + "00".repeat(21), "mainnet");
  assert.equal(result.type, "witness_invalid");
  assert.equal(result.address, null);
});

test("testnet address encoding stays distinct from mainnet", () => {
  const result = inspectScriptPubKey(WPKH_SCRIPT, "testnet");
  assert.equal(result.address, "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kmf7cjg");
  assert.notEqual(result.address, WPKH_ADDRESS);
});

test("Silent Payment addresses take a distinct path", () => {
  const malformed = inspectAddress("sp1qnot-a-valid-silent-payment-address", "mainnet");
  assert.equal(malformed.state, "invalid-silent-payment");
  const comparison = compareAddressAndScript("sp1qnot-a-valid-silent-payment-address", WPKH_SCRIPT, "mainnet");
  assert.equal(comparison.state, "invalid-silent-payment");
});
