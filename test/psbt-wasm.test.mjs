// Tests for the rust-bitcoin PSBT WASM facade (src/js/psbt-wasm.js) and the
// editor document plumbing (src/js/psbt-editor.js).
// Run with `npm test` (part of the default and CI suites).
//
// Vectors are the published BIP-174 ones, mirrored by rust-bitcoin's own test
// suite (psbt::tests::valid_vector_2 and the invalid_vector_2 should-panic
// case): a two-input PSBT with a finalized P2PKH scriptSig and a nested
// P2WPKH input, and a malformed file missing its output maps.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { psbtInspectDoc, psbtBuildBytes, psbtWasmReady } from "../src/js/psbt-wasm.js";
import { psbtBytesFromText, psbtEditorBuildDoc, satsToBtc } from "../src/js/psbt-editor.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));

const unhex = (hex) => new Uint8Array(hex.match(/.{2}/g).map((b) => parseInt(b, 16)));

// BIP-174 valid vector 2 (hex form, as in rust-bitcoin's valid_vector_2).
const VALID_HEX =
  "70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffff" +
  "ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40" +
  "bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac00000000" +
  "0001076a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf133" +
  "6f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa882920001012000e1" +
  "f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000";
const VALID = unhex(VALID_HEX);
const VALID_B64 = Buffer.from(VALID).toString("base64");

// BIP-174 invalid vector 2: its non-witness utxo does not cover the unsigned
// transaction's input (and the file is missing its output maps).
const INVALID_B64 =
  "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA" +
  "4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y" +
  "0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLr" +
  "CwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf" +
  "3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuF" +
  "LYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgH" +
  "NEZPhPKrMAAAAAAA==";

const inspectValid = () => psbtInspectDoc(VALID);
const rebuild = (doc) => psbtBuildBytes(psbtEditorBuildDoc(doc));

// Minimal raw-transaction builder for the regression tests below: version 2,
// one dummy input spending 00..00:0xffffffff with an empty scriptSig, the
// given [sats, scriptBytes] outputs, locktime 0. Returns { hex, txid } with
// the txid in display order (as the unsigned transaction references it).
const prevTx = (...outputs) => {
  const le32 = (n) => [n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255];
  const le64 = (value) => {
    let n = BigInt(value);
    const bytes = [];
    for (let i = 0; i < 8; i++) { bytes.push(Number(n & 255n)); n >>= 8n; }
    return bytes;
  };
  const bytes = new Uint8Array([
    ...le32(2), 1, ...new Uint8Array(32), ...le32(0xffffffff), 0, ...le32(0xffffffff),
    outputs.length,
    ...outputs.flatMap(([value, script]) => [...le64(value), script.length, ...script]),
    ...le32(0),
  ]);
  const hash = createHash("sha256").update(createHash("sha256").update(bytes).digest()).digest();
  return { hex: Buffer.from(bytes).toString("hex"), txid: Buffer.from(hash).reverse().toString("hex") };
};

test("psbtWasmReady resolves (WASM initialized synchronously under Node)", async () => {
  await psbtWasmReady;
});

test("committed WASM artifact is intact (sha256 in module header matches payload)", () => {
  const source = readFileSync(join(root, "src/js/psbt-wasm-b64.js"), "utf8");
  const declared = source.match(/wasm sha256: ([0-9a-f]{64})/);
  assert.ok(declared, "module header carries the wasm sha256");
  const b64 = source.match(/export const PSBT_WASM_B64 =\s*"([A-Za-z0-9+/=]+)";/);
  assert.ok(b64, "module exports the base64 payload");
  const actual = createHash("sha256").update(Buffer.from(b64[1], "base64")).digest("hex");
  assert.equal(actual, declared[1]);
});

test("committed WASM carries no build-host paths (remapped at build time)", () => {
  const source = readFileSync(join(root, "src/js/psbt-wasm-b64.js"), "utf8");
  const payload = Buffer.from(source.match(/"([A-Za-z0-9+/=]+)"/)[1], "base64").toString("latin1");
  for (const banned of ["/home/", "/Users/", ".cargo/", ".rustup/"]) {
    assert.equal(payload.includes(banned), false, `build fingerprints the build host: ${banned}`);
  }
});

test("inspect decodes the transaction, every map pair, and the parse verdict", () => {
  const doc = inspectValid();
  assert.equal(doc.psbtVersion, 0);
  assert.equal(doc.rustBitcoinError, null, "rust-bitcoin accepts the valid vector");
  assert.equal(doc.tx.version, 2);
  assert.equal(doc.tx.locktime, 0);
  assert.equal(doc.tx.inputs.length, 2);
  assert.equal(doc.tx.outputs.length, 2);
  assert.equal(doc.tx.inputs[0].txid, "e47b5b7a879f13a8213815cf3dc3f5b35af1e217f412829bc4f75a8ca04909ab");
  assert.equal(doc.tx.inputs[0].vout, 0);
  assert.equal(doc.tx.inputs[0].sequence, 4294967294);
  assert.equal(doc.tx.outputs[0].value, 199900000);
  assert.equal(doc.tx.outputs[0].scriptPubKey, "76a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac");
  assert.match(doc.tx.outputs[0].asm, /OP_DUP OP_HASH160/);

  assert.deepEqual(doc.globals.map((p) => p.name), ["PSBT_GLOBAL_UNSIGNED_TX"]);
  assert.deepEqual(doc.inputs[0].map((p) => p.name), ["PSBT_IN_FINAL_SCRIPTSIG"]);
  assert.deepEqual(doc.inputs[1].map((p) => p.name), ["PSBT_IN_WITNESS_UTXO", "PSBT_IN_REDEEM_SCRIPT"]);
  assert.deepEqual(doc.outputs[0], []);
  assert.deepEqual(doc.outputs[1], []);

  const witnessUtxo = doc.inputs[1][0].decoded;
  assert.equal(witnessUtxo.value, 100000000);
  assert.equal(witnessUtxo.scriptPubKey, "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787");
  assert.match(witnessUtxo.asm, /OP_HASH160/);
  const redeem = doc.inputs[1][1].decoded;
  assert.equal(redeem.hex, "001485d13537f2e265405a34dbafa9e3dda01fb82308");
  const finalScriptSig = doc.inputs[0][0].decoded;
  assert.match(finalScriptSig.asm, /OP_PUSHBYTES_71 3044/);

  // Only one input carries a claimed amount, so the fee stays unknown.
  assert.equal(doc.fee.known, false);
  assert.equal(doc.totalIn, null);
  assert.equal(doc.totalOut, 199909358);
});

test("an unedited document rebuilds byte-identically", () => {
  const rebuilt = rebuild(inspectValid());
  assert.equal(Buffer.from(rebuilt).toString("hex"), VALID_HEX);
});

test("transaction field edits re-serialize and re-inspect", () => {
  const doc = inspectValid();
  doc.tx.version = 1;
  doc.tx.locktime = 850000;
  doc.tx.inputs[0].sequence = 4294967293;
  doc.tx.outputs[0].value = doc.tx.outputs[0].value + 1000;
  doc.tx.outputs[1].scriptPubKey = "00144d1b7e3b0d6a1f0a3f3a4c5f6b7c8d9e0f1a2b3c";
  const fresh = psbtInspectDoc(rebuild(doc));
  assert.equal(fresh.tx.version, 1);
  assert.equal(fresh.tx.locktime, 850000);
  assert.equal(fresh.tx.inputs[0].sequence, 4294967293);
  assert.equal(fresh.tx.outputs[0].value, 199901000);
  assert.equal(fresh.tx.outputs[1].scriptPubKey, "00144d1b7e3b0d6a1f0a3f3a4c5f6b7c8d9e0f1a2b3c");
  assert.equal(fresh.rustBitcoinError, null);
});

test("numeric fields accept string values (JSON-safe for large u64s)", () => {
  const doc = inspectValid();
  doc.tx.outputs[0].value = "2100000000000000"; // 21M BTC in sats
  const fresh = psbtInspectDoc(rebuild(doc));
  assert.equal(fresh.tx.outputs[0].value, 2100000000000000);
  assert.ok(Number.isSafeInteger(fresh.tx.outputs[0].value));
});

test("fee computes once every input carries a claimed amount", () => {
  const doc = inspectValid();
  // Claim input 0 spends a 5000-sat P2PKH prevout: witness utxo = amount +
  // compact-size script, hex (here deliberately smaller than the outputs so
  // the inconsistent-amounts path is exercised too).
  doc.inputs[0].push({ key: "01", value: "88130000000000001976a914" + "00".repeat(20) + "88ac" });
  const fresh = psbtInspectDoc(rebuild(doc));
  assert.equal(fresh.fee.known, true);
  assert.equal(fresh.fee.sats, null);
  assert.equal(fresh.fee.error, "outputs exceed claimed inputs");

  doc.inputs[0].at(-1).value = "00a3e111000000001976a914" + "00".repeat(20) + "88ac"; // 300,000,000 sats
  const richer = psbtInspectDoc(rebuild(doc));
  assert.equal(richer.fee.known, true);
  assert.equal(richer.totalIn, 400000000);
  assert.equal(richer.fee.sats, 400000000 - 199909358);
});

test("inputs spending different outputs of one transaction resolve by index, not txid", () => {
  // Regression test: both inputs reference the same previous txid, so a
  // transaction-wide txid search resolves every non-witness utxo to the first
  // input's vout. The inspector must match each input map to its own
  // unsigned-transaction input and use that outpoint's vout.
  const prev = prevTx([1000, [0x51]], [9000, [0x52]]); // vout 0 = OP_TRUE, vout 1 = OP_2
  const doc = {
    tx: {
      version: 2,
      locktime: 0,
      inputs: [
        { txid: prev.txid, vout: 0, scriptSig: "", sequence: 0xffffffff },
        { txid: prev.txid, vout: 1, scriptSig: "", sequence: 0xffffffff },
      ],
      outputs: [{ value: 1500, scriptPubKey: "51" }],
    },
    globals: [],
    inputs: [
      [{ key: "00", value: prev.hex }],
      [{ key: "00", value: prev.hex }],
    ],
    outputs: [[]],
  };
  const inspected = psbtInspectDoc(psbtBuildBytes(doc));
  assert.equal(inspected.rustBitcoinError, null);
  // Each input map decodes its own prevout: distinct vout, amount, and script.
  assert.deepEqual(inspected.inputs[0][0].decoded.prevout, { vout: 0, value: 1000, scriptPubKey: "51" });
  assert.deepEqual(inspected.inputs[1][0].decoded.prevout, { vout: 1, value: 9000, scriptPubKey: "52" });
  // Totals and fee use the two distinct outputs, not the first output twice.
  assert.equal(inspected.totalIn, 10000);
  assert.deepEqual(inspected.fee, { known: true, sats: 8500 });
});

test("a non-witness utxo that does not match its input's outpoint is not claimed", () => {
  // Two inputs spending two different previous transactions. With the maps in
  // the right order each decodes its prevout; reversed, neither map's utxo
  // matches its own input's outpoint, so it must not be re-associated with
  // the other input by txid — the prevout and amount are omitted instead.
  const a = prevTx([1000, [0x51]]);
  const b = prevTx([9000, [0x52]]);
  const build = (first, second) => psbtInspectDoc(psbtBuildBytes({
    tx: {
      version: 2,
      locktime: 0,
      inputs: [
        { txid: a.txid, vout: 0, scriptSig: "", sequence: 0xffffffff },
        { txid: b.txid, vout: 0, scriptSig: "", sequence: 0xffffffff },
      ],
      outputs: [{ value: 1500, scriptPubKey: "51" }],
    },
    globals: [],
    inputs: [
      [{ key: "00", value: first }],
      [{ key: "00", value: second }],
    ],
    outputs: [[]],
  }));

  const correct = build(a.hex, b.hex);
  assert.equal(correct.inputs[0][0].decoded.prevout.value, 1000);
  assert.equal(correct.inputs[1][0].decoded.prevout.value, 9000);
  assert.equal(correct.totalIn, 10000);
  assert.deepEqual(correct.fee, { known: true, sats: 8500 });

  // Reversing the maps must not silently associate either utxo with the wrong
  // input: the txid no longer matches, so the prevout and amount are omitted.
  const reversed = build(b.hex, a.hex);
  assert.equal(reversed.inputs[0][0].decoded.prevout, undefined);
  assert.equal(reversed.inputs[1][0].decoded.prevout, undefined);
  assert.equal(reversed.totalIn, null);
  assert.deepEqual(reversed.fee, { known: false });
});

test("unknown and proprietary pairs round-trip with decodes", () => {
  const doc = inspectValid();
  doc.globals.push({ key: "fc026d7900", value: "deadbeef" });
  doc.inputs[0].push({ key: "ee0102", value: "" });
  doc.outputs[0].push({ key: "2a", value: "ff" });
  const fresh = psbtInspectDoc(rebuild(doc));
  const proprietary = fresh.globals.at(-1);
  assert.equal(proprietary.name, "PSBT_GLOBAL_PROPRIETARY");
  assert.equal(proprietary.decoded.prefixText, "my");
  assert.equal(proprietary.decoded.subtype, 0);
  assert.equal(proprietary.decoded.keydata, "");
  assert.equal(proprietary.value, "deadbeef");
  assert.equal(fresh.inputs[0].at(-1).name, "PSBT_IN_UNKNOWN");
  assert.equal(fresh.inputs[0].at(-1).decoded, null);
  assert.equal(fresh.outputs[0].at(-1).name, "PSBT_OUT_UNKNOWN");
  assert.equal(fresh.outputs[0].at(-1).key, "2a");
});

test("output 0x07 is named and decoded as PSBT_OUT_TAP_BIP32_DERIVATION (BIP-371)", () => {
  const doc = inspectValid();
  const xonly = "22".repeat(32);
  const leafHash = "11".repeat(32);
  const value = "01" + leafHash + "aabbccdd" + "00000080"; // 1 leaf hash, fingerprint, one hardened path element
  doc.outputs[0].push({ key: "07" + xonly, value });
  const fresh = psbtInspectDoc(rebuild(doc));
  const pair = fresh.outputs[0].at(-1);
  assert.equal(pair.name, "PSBT_OUT_TAP_BIP32_DERIVATION");
  assert.equal(pair.decoded.xonly, xonly);
  assert.deepEqual(pair.decoded.leafHashes, [leafHash]);
  assert.equal(pair.decoded.fingerprint, "aabbccdd");
  assert.equal(pair.decoded.path, "m/0'");
});

test("the unsigned transaction pair is regenerated, not passed through", () => {
  const doc = inspectValid();
  doc.globals[0].value = "ff".repeat(32); // corrupt the passed-through pair
  const fresh = psbtInspectDoc(rebuild(doc));
  // The transaction section wins; the file still parses.
  assert.equal(fresh.rustBitcoinError, null);
  assert.equal(fresh.tx.inputs.length, 2);
});

test("build rejects duplicate keys, count mismatches, and bad hex", () => {
  const dup = inspectValid();
  dup.inputs[1].push({ key: dup.inputs[1][0].key, value: dup.inputs[1][0].value });
  assert.throws(() => rebuild(dup), /duplicate key 01/);

  const short = inspectValid();
  short.inputs.pop();
  assert.throws(() => rebuild(short), /1 input maps but the transaction has 2 inputs/);

  const badHex = inspectValid();
  badHex.inputs[1][0].value = "zz";
  assert.throws(() => rebuild(badHex), /hex value contains a non-hex character/);

  const badScript = inspectValid();
  badScript.tx.inputs[0].scriptSig = "51";
  assert.throws(() => rebuild(badScript), /empty scriptSigs/);
});

test("build rejects values rust-bitcoin cannot parse into typed fields", () => {
  const doc = inspectValid();
  doc.inputs[1][0].value = "0102"; // truncated witness utxo
  assert.throws(() => rebuild(doc), /rebuilt PSBT does not parse/);
});

test("inspect rejects garbage, the invalid BIP-174 vector, and v2 files", () => {
  assert.throws(() => psbtInspectDoc(new Uint8Array([1, 2, 3])), /not a PSBT/);
  assert.throws(
    () => psbtInspectDoc(new Uint8Array(Buffer.from(INVALID_B64, "base64"))),
    /missing an output map/
  );
  // A PSBT_GLOBAL_VERSION of 2 must be refused until v2 support exists.
  const doc = inspectValid();
  doc.globals.push({ key: "fb", value: "02000000" });
  assert.throws(() => psbtBuildBytes(psbtEditorBuildDoc(doc)), /only PSBT v0 is supported/);
});

test("psbtBytesFromText accepts base64 and hex with whitespace", () => {
  assert.deepEqual(psbtBytesFromText(VALID_B64), VALID);
  assert.deepEqual(psbtBytesFromText(VALID_HEX.toUpperCase()), VALID);
  const spaced = VALID_B64.slice(0, 40) + "\n  " + VALID_B64.slice(40);
  assert.deepEqual(psbtBytesFromText(spaced), VALID);
  assert.throws(() => psbtBytesFromText(""), /Paste a PSBT/);
  assert.throws(() => psbtBytesFromText("not a psbt at all !!!"), /base64 or hex/);
});

test("satsToBtc formats like the inspector", () => {
  assert.equal(satsToBtc(0), "0.00000000");
  assert.equal(satsToBtc(199900000), "1.99900000");
  assert.equal(satsToBtc("2100000000000000"), "21000000.00000000");
  assert.equal(satsToBtc(1), "0.00000001");
});
