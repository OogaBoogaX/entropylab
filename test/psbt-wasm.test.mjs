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
  assert.equal(doc.tx.outputs[0].value, "199900000");
  assert.equal(doc.tx.outputs[0].scriptPubKey, "76a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac");
  assert.match(doc.tx.outputs[0].asm, /OP_DUP OP_HASH160/);

  assert.deepEqual(doc.globals.map((p) => p.name), ["PSBT_GLOBAL_UNSIGNED_TX"]);
  assert.deepEqual(doc.inputs[0].map((p) => p.name), ["PSBT_IN_FINAL_SCRIPTSIG"]);
  assert.deepEqual(doc.inputs[1].map((p) => p.name), ["PSBT_IN_WITNESS_UTXO", "PSBT_IN_REDEEM_SCRIPT"]);
  assert.deepEqual(doc.outputs[0], []);
  assert.deepEqual(doc.outputs[1], []);

  const witnessUtxo = doc.inputs[1][0].decoded;
  assert.equal(witnessUtxo.value, "100000000");
  assert.equal(witnessUtxo.scriptPubKey, "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787");
  assert.match(witnessUtxo.asm, /OP_HASH160/);
  const redeem = doc.inputs[1][1].decoded;
  assert.equal(redeem.hex, "001485d13537f2e265405a34dbafa9e3dda01fb82308");
  const finalScriptSig = doc.inputs[0][0].decoded;
  assert.match(finalScriptSig.asm, /OP_PUSHBYTES_71 3044/);

  // Only one input carries a claimed amount, so the fee stays unknown.
  assert.equal(doc.fee.known, false);
  assert.equal(doc.totalIn, null);
  assert.equal(doc.totalOut, "199909358");
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
  doc.tx.outputs[0].value = String(BigInt(doc.tx.outputs[0].value) + 1000n);
  doc.tx.outputs[1].scriptPubKey = "00144d1b7e3b0d6a1f0a3f3a4c5f6b7c8d9e0f1a2b3c";
  const fresh = psbtInspectDoc(rebuild(doc));
  assert.equal(fresh.tx.version, 1);
  assert.equal(fresh.tx.locktime, 850000);
  assert.equal(fresh.tx.inputs[0].sequence, 4294967293);
  assert.equal(fresh.tx.outputs[0].value, "199901000");
  assert.equal(fresh.tx.outputs[1].scriptPubKey, "00144d1b7e3b0d6a1f0a3f3a4c5f6b7c8d9e0f1a2b3c");
  assert.equal(fresh.rustBitcoinError, null);
});

test("amounts at and above 2^53 survive the JSON boundary exactly, as strings (issue #351)", () => {
  // 2^53 + 1 rounds to 2^53 as an f64: transported as a JSON number it would
  // come back corrupted from an inspect → edit → rebuild round trip. (Such an
  // output is past MAX_MONEY, so the build gate refuses it — the lossless
  // check runs through inspection of raw bytes, which is where the rounding
  // used to happen.)
  const spliceOutput0 = (leHex) => unhex(VALID_HEX.replace("603bea0b00000000", leHex));
  assert.equal(psbtInspectDoc(spliceOutput0("0100000000002000")).tx.outputs[0].value, "9007199254740993"); // 2^53 + 1
  assert.equal(psbtInspectDoc(spliceOutput0("ffffffffffffffff")).tx.outputs[0].value, "18446744073709551615"); // u64::MAX
  // The largest consensus-valid amount, 21M BTC in sats (2.1e15, f64-safe),
  // rides the same string path through a full inspect → rebuild round trip.
  const doc = inspectValid();
  doc.tx.outputs[0].value = "2100000000000000";
  doc.tx.outputs[1].value = "0"; // keep the aggregate within MAX_MONEY
  assert.equal(psbtInspectDoc(rebuild(doc)).tx.outputs[0].value, "2100000000000000");
});

test("build rejects consensus-invalid transactions with Core's reasons; inspect reports them (issues #322, #361)", () => {
  const sane = { version: 2, locktime: 0, inputs: [{ txid: "22".repeat(32), vout: 0, scriptSig: "", sequence: 0xffffffff }], outputs: [{ value: 1000, scriptPubKey: "51" }] };
  const buildTx = (tx) => psbtBuildBytes({ tx, globals: [], inputs: [[]], outputs: tx.outputs.map(() => []) });
  const MAX_MONEY = "2100000000000000";

  // The sane control builds and inspects clean.
  const ok = psbtInspectDoc(buildTx(sane));
  assert.equal(ok.txSanityError, null);
  assert.equal(ok.rustBitcoinError, null);

  // No outputs / no inputs.
  assert.throws(() => buildTx({ ...sane, outputs: [] }), /consensus-invalid: bad-txns-vout-empty/);
  assert.throws(() => psbtBuildBytes({ tx: { ...sane, inputs: [] }, globals: [], inputs: [], outputs: [[]] }), /bad-txns-vin-empty/);

  // Duplicate prevouts.
  const dup = { ...sane, inputs: [sane.inputs[0], sane.inputs[0]] };
  assert.throws(() => psbtBuildBytes({ tx: dup, globals: [], inputs: [[], []], outputs: [[]] }), /bad-txns-inputs-duplicate/);

  // Null prevout (txid 0, vout u32::MAX): a hand edit away in the editor.
  // Core rejects it as bad-cb-length when it is the only input (coinbase
  // shape, empty scriptSig) and as bad-txns-prevout-null otherwise; the gate
  // reports the latter either way.
  const nullPrevout = { txid: "0".repeat(64), vout: "4294967295", scriptSig: "", sequence: "4294967295" };
  assert.throws(() => buildTx({ ...sane, inputs: [nullPrevout] }), /bad-txns-prevout-null/);
  assert.throws(() => psbtBuildBytes({ tx: { ...sane, inputs: [sane.inputs[0], nullPrevout] }, globals: [], inputs: [[], []], outputs: [[]] }), /bad-txns-prevout-null/);

  // One output past MAX_MONEY (u64::MAX included) and an over-cap total.
  assert.throws(() => buildTx({ ...sane, outputs: [{ value: "18446744073709551615", scriptPubKey: "51" }] }), /bad-txns-vout-toolarge/);
  assert.throws(() => buildTx({ ...sane, outputs: [{ value: "2100000000000001", scriptPubKey: "51" }] }), /bad-txns-vout-toolarge/);
  assert.throws(() => buildTx({ ...sane, outputs: [{ value: MAX_MONEY, scriptPubKey: "51" }, { value: "1", scriptPubKey: "52" }] }), /bad-txns-txouttotal-toolarge/);

  // Inspection separates the facts: structurally valid, consensus-invalid.
  const insane = psbtInspectDoc(unhex(VALID_HEX.replace("603bea0b00000000", "ffffffffffffffff")));
  assert.equal(insane.rustBitcoinError, null); // rust-bitcoin parses the PSBT fine
  assert.equal(insane.txSanityError, "bad-txns-vout-toolarge");
  assert.equal(insane.tx.outputs[0].value, "18446744073709551615");

  // Same separation for a null prevout spliced into the first input: the PSBT
  // parses, the transaction is flagged with Core's reason.
  const nullHex = VALID_HEX.replace(
    "ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000",
    "00".repeat(32) + "ffffffff00",
  );
  const nullDoc = psbtInspectDoc(unhex(nullHex));
  assert.equal(nullDoc.tx.inputs[0].txid, "0".repeat(64));
  assert.equal(nullDoc.tx.inputs[0].vout, 4294967295);
  assert.equal(nullDoc.rustBitcoinError, null);
  assert.equal(nullDoc.txSanityError, "bad-txns-prevout-null");
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
  assert.equal(richer.totalIn, "400000000");
  assert.equal(richer.fee.sats, String(400000000 - 199909358));
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
  assert.deepEqual(inspected.inputs[0][0].decoded.prevout, { vout: 0, value: "1000", scriptPubKey: "51" });
  assert.deepEqual(inspected.inputs[1][0].decoded.prevout, { vout: 1, value: "9000", scriptPubKey: "52" });
  // Totals and fee use the two distinct outputs, not the first output twice.
  assert.equal(inspected.totalIn, "10000");
  assert.deepEqual(inspected.fee, { known: true, sats: "8500" });
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
  assert.equal(correct.inputs[0][0].decoded.prevout.value, "1000");
  assert.equal(correct.inputs[1][0].decoded.prevout.value, "9000");
  assert.equal(correct.totalIn, "10000");
  assert.deepEqual(correct.fee, { known: true, sats: "8500" });

  // Reversing the maps must not silently associate either utxo with the wrong
  // input: the txid no longer matches, so the prevout and amount are omitted.
  const reversed = build(b.hex, a.hex);
  assert.equal(reversed.inputs[0][0].decoded.prevout, undefined);
  assert.equal(reversed.inputs[1][0].decoded.prevout, undefined);
  assert.equal(reversed.totalIn, null);
  assert.deepEqual(reversed.fee, { known: false });
});

test("conflicting witness and non-witness UTXO claims mark amount and fee unknown, in both map orders (issue #324)", () => {
  // The real prevout pays 1,000 sats; a conflicting witness UTXO claims
  // 5,000. Whichever pair serializes first must not win.
  const le64hex = (value) => {
    let n = BigInt(value);
    const bytes = [];
    for (let i = 0; i < 8; i++) { bytes.push(Number(n & 255n)); n >>= 8n; }
    return Buffer.from(bytes).toString("hex");
  };
  const prev = prevTx([1000, [0x51]]);
  const witness = (sats) => ({ key: "01", value: le64hex(sats) + "0151" }); // 5,000-sat claim, same script
  const nonWitness = { key: "00", value: prev.hex };
  const build = (pairs) => psbtInspectDoc(psbtBuildBytes({
    tx: {
      version: 2,
      locktime: 0,
      inputs: [{ txid: prev.txid, vout: 0, scriptSig: "", sequence: 0xffffffff }],
      outputs: [{ value: 900, scriptPubKey: "51" }],
    },
    globals: [],
    inputs: [pairs],
    outputs: [[]],
  }));
  for (const ordered of [[witness(5000), nonWitness], [nonWitness, witness(5000)]]) {
    const doc = build(ordered);
    assert.deepEqual(doc.inputConflicts, [0]);
    assert.equal(doc.totalIn, null);
    assert.equal(doc.fee.known, false);
    assert.match(doc.fee.error, /conflicting witness and non-witness UTXO amounts/);
  }
  // Agreement between the two declarations resolves normally to the amount.
  const agreed = build([witness(1000), nonWitness]);
  assert.deepEqual(agreed.inputConflicts, []);
  assert.equal(agreed.totalIn, "1000");
  assert.deepEqual(agreed.fee, { known: true, sats: "100" });
  // A malformed witness declaration (amount only, no script) claims nothing —
  // it neither resolves nor conflicts, the input simply has no claim. The
  // build gate would reject such a value, so splice it into valid bytes.
  const validBytes = Buffer.from(psbtBuildBytes({
    tx: {
      version: 2,
      locktime: 0,
      inputs: [{ txid: prev.txid, vout: 0, scriptSig: "", sequence: 0xffffffff }],
      outputs: [{ value: 900, scriptPubKey: "51" }],
    },
    globals: [],
    inputs: [[witness(5000), nonWitness]],
    outputs: [[]],
  })).toString("hex");
  const malformedHex = validBytes.replace(
    "01" + "01" + "0a" + le64hex(5000) + "0151",
    "01" + "01" + "08" + le64hex(5000)
  );
  assert.notEqual(malformedHex, validBytes); // the splice must have happened
  const malformed = psbtInspectDoc(unhex(malformedHex));
  assert.match(malformed.inputs[0][0].decodeError, /witness utxo is truncated/);
  assert.deepEqual(malformed.inputConflicts, []);
  // The malformed declaration claims nothing, so the verified non-witness
  // claim resolves alone: no conflict, amount known.
  assert.equal(malformed.totalIn, "1000");
  assert.deepEqual(malformed.fee, { known: true, sats: "100" });
});

test("hostile amount totals mark totals and fee invalid instead of wrapping (issue #367)", () => {
  // A structurally valid PSBT can claim amounts whose u64 total overflows; a
  // wrapped sum would display as a plausible total or fee. The inspector must
  // accumulate with checked arithmetic, report the totals as unknown and the
  // fee as invalid, and separately refuse fees derived from amounts past
  // Bitcoin's MAX_MONEY supply cap.
  const le64hex = (value) => {
    let n = BigInt(value);
    const bytes = [];
    for (let i = 0; i < 8; i++) { bytes.push(Number(n & 255n)); n >>= 8n; }
    return Buffer.from(bytes).toString("hex");
  };
  // Each input claims `sats` via a witness utxo with an empty scriptPubKey.
  const hostile = ({ claims, outputs }) => psbtInspectDoc(psbtBuildBytes({
    tx: {
      version: 2,
      locktime: 0,
      inputs: claims.map((_, vout) => ({ txid: "22".repeat(32), vout, scriptSig: "", sequence: 0xffffffff })),
      outputs: outputs.map((value) => ({ value: String(value), scriptPubKey: "51" })),
    },
    globals: [],
    inputs: claims.map((sats) => [{ key: "01", value: le64hex(sats) + "00" }]),
    outputs: outputs.map(() => []),
  }));
  const U64_MAX = 18446744073709551615n;
  const MAX_MONEY = 2100000000000000n;

  // Multiple u64::MAX claims: the input total overflows; without checked
  // arithmetic the fee would wrap to a small plausible number.
  const claims = hostile({ claims: [U64_MAX, U64_MAX], outputs: [0n] });
  assert.equal(claims.totalIn, null);
  assert.equal(claims.fee.known, true);
  assert.equal(claims.fee.sats, null);
  assert.equal(claims.fee.error, "amounts overflow u64");

  // Overflow boundary: u64::MAX + 1 wraps to exactly 0, which a wrapping
  // build would show as fee 0. Checked arithmetic marks it invalid.
  const boundary = hostile({ claims: [U64_MAX, 1n], outputs: [0n] });
  assert.equal(boundary.totalIn, null);
  assert.equal(boundary.fee.sats, null);
  assert.equal(boundary.fee.error, "amounts overflow u64");

  // Multiple u64::MAX outputs overflow the output total the same way, even
  // though the input claim is honest. The build gate refuses outputs past
  // MAX_MONEY (issue #322), so splice the wire bytes directly instead.
  const zeroed = psbtBuildBytes({
    tx: {
      version: 2,
      locktime: 0,
      inputs: [{ txid: "22".repeat(32), vout: 0, scriptSig: "", sequence: 0xffffffff }],
      outputs: [{ value: 0, scriptPubKey: "51" }, { value: 0, scriptPubKey: "51" }],
    },
    globals: [],
    inputs: [[{ key: "01", value: le64hex(1000n) + "00" }]],
    outputs: [[], []],
  });
  const overOut = Buffer.from(zeroed).toString("hex").replaceAll("0000000000000000" + "0151", "ffffffffffffffff" + "0151");
  const outs = psbtInspectDoc(unhex(overOut));
  assert.equal(outs.txSanityError, "bad-txns-vout-toolarge"); // per-output rule fires first, as in Core
  assert.equal(outs.totalOut, null);
  assert.equal(outs.fee.known, true);
  assert.equal(outs.fee.sats, null);
  assert.equal(outs.fee.error, "amounts overflow u64");

  // u64::MAX exactly is representable but past the 21M BTC supply cap: the
  // totals still render (they are the PSBT's own claims) but the fee must be
  // invalid rather than a monetary-impossible number.
  const capped = hostile({ claims: [U64_MAX], outputs: [0n] });
  assert.equal(capped.fee.known, true);
  assert.equal(capped.fee.sats, null);
  assert.equal(capped.fee.error, "amounts exceed Bitcoin's MAX_MONEY");

  // One sat over the cap invalidates the fee too.
  const overCap = hostile({ claims: [MAX_MONEY + 1n], outputs: [0n] });
  assert.equal(overCap.fee.sats, null);
  assert.equal(overCap.fee.error, "amounts exceed Bitcoin's MAX_MONEY");

  // Exactly MAX_MONEY stays valid: 21M BTC in, nothing out, all of it fee.
  const exact = hostile({ claims: [MAX_MONEY], outputs: [0n] });
  assert.deepEqual(exact.fee, { known: true, sats: "2100000000000000" });
  assert.equal(exact.totalIn, "2100000000000000");
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

test("inspect rejects garbage and the invalid BIP-174 vector", () => {
  assert.throws(() => psbtInspectDoc(new Uint8Array([1, 2, 3])), /not a PSBT/);
  assert.throws(
    () => psbtInspectDoc(new Uint8Array(Buffer.from(INVALID_B64, "base64"))),
    /missing an output map/
  );
});

// ── PSBT v2 (BIP-370) — issues #337, #340, #358 ─────────────────────────────

// BIP-370's own vectors (the BIP's hex/base64 test cases, verbatim).
const V2_MINIMAL_B64 =
  "cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==";
const V2_MINIMAL_HEX = Buffer.from(V2_MINIMAL_B64, "base64").toString("hex");
const inspectB64 = (b64) => psbtInspectDoc(new Uint8Array(Buffer.from(b64, "base64")));

// Splice exactly one occurrence of `from` out of/into the vector hex.
const spliceOnce = (hex, from, to) => {
  assert.equal(hex.split(from).length - 1, 1, `expected one occurrence of ${from}`);
  return hex.replace(from, to);
};

test("PSBT v2: the BIP-370 minimal vector inspects and rebuilds byte-identically (issue #358)", () => {
  const doc = inspectB64(V2_MINIMAL_B64);
  assert.equal(doc.psbtVersion, 2);
  assert.equal(doc.tx.version, 2);
  assert.equal(doc.tx.locktime, 0);
  assert.equal(doc.tx.inputs.length, 1);
  assert.equal(doc.tx.inputs[0].txid, "c85f81844094f9f0eec1e41f8d63e0a99e9f73dc725d7319871c9c4121d90a0b");
  assert.equal(doc.tx.inputs[0].vout, 0);
  assert.equal(doc.tx.inputs[0].sequence, 4294967295); // omitted = final
  assert.deepEqual(doc.tx.outputs.map((o) => o.value), ["800000000", "199998859"]);
  // rust-bitcoin is v0-only; the v2 parse is this crate's own BIP-370 reader.
  assert.equal(doc.rustBitcoinError, null);
  assert.equal(doc.txSanityError, null);
  // Typed field names render for the pair tables.
  assert.deepEqual(doc.globals.map((p) => p.name), [
    "PSBT_GLOBAL_TX_VERSION",
    "PSBT_GLOBAL_INPUT_COUNT",
    "PSBT_GLOBAL_OUTPUT_COUNT",
    "PSBT_GLOBAL_VERSION",
  ]);
  assert.deepEqual(doc.inputs[0].map((p) => p.name), ["PSBT_IN_PREVIOUS_TXID", "PSBT_IN_OUTPUT_INDEX"]);
  assert.deepEqual(doc.outputs[0].map((p) => p.name), ["PSBT_OUT_AMOUNT", "PSBT_OUT_SCRIPT"]);
  // An unedited document rebuilds byte-identically.
  assert.equal(Buffer.from(rebuild(doc)).toString("base64"), V2_MINIMAL_B64);
});

test("PSBT v2: BIP-370 locktime determination vectors (issue #337)", () => {
  const cases = [
    ["cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==", 0], // none specified
    ["cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAAAAQ4gOhs7PIN9ZInqejHY5sfdUDwAG+8+BpWOdXSAjWjKeKUBDwQAAAAAAAEDCE+TNXcAAAAAAQQWABQLE1LKzQPPaqG388jWOIZxs0peEQA=", 0], // fallback 0
    ["cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAABEgQQJwAAAAEOIDobOzyDfWSJ6nox2ObH3VA8ABvvPgaVjnV0gI1oynilAQ8EAAAAAAABAwhPkzV3AAAAAAEEFgAUCxNSys0Dz2qht/PI1jiGcbNKXhEA", 10000], // height 10000, none
    ["cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAABEgQQJwAAAAEOIDobOzyDfWSJ6nox2ObH3VA8ABvvPgaVjnV0gI1oynilAQ8EAAAAAAESBCgjAAAAAQMIT5M1dwAAAAABBBYAFAsTUsrNA89qobfzyNY4hnGzSl4RAA==", 10000], // height 10000, height 9000
    ["cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAABEQSLjcRiARIEECcAAAABDiA6Gzs8g31kiep6Mdjmx91QPAAb7z4GlY51dICNaMp4pQEPBAAAAAABEQSMjcRiARIEKCMAAAABAwhPkzV3AAAAAAEEFgAUCxNSys0Dz2qht/PI1jiGcbNKXhEA", 10000], // both/both → height
    ["cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAABEQSLjcRiAAEOIDobOzyDfWSJ6nox2ObH3VA8ABvvPgaVjnV0gI1oynilAQ8EAAAAAAERBIyNxGIBEgQoIwAAAAEDCE+TNXcAAAAAAQQWABQLE1LKzQPPaqG388jWOIZxs0peEQA=", 1657048460], // time-only + both → time
    ["cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAABEQSLjcRiARIEECcAAAABDiA6Gzs8g31kiep6Mdjmx91QPAAb7z4GlY51dICNaMp4pQEPBAAAAAABEQSMjcRiAAEDCE+TNXcAAAAAAQQWABQLE1LKzQPPaqG388jWOIZxs0peEQA=", 1657048460], // both + time-only → time
    ["cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAAAAQ4gOhs7PIN9ZInqejHY5sfdUDwAG+8+BpWOdXSAjWjKeKUBDwQAAAAAAREEjI3EYgABAwhPkzV3AAAAAAEEFgAUCxNSys0Dz2qht/PI1jiGcbNKXhEA", 1657048460], // time-only + none → time
  ];
  for (const [b64, locktime] of cases) {
    assert.equal(inspectB64(b64).tx.locktime, locktime, `locktime for ${b64.slice(20, 36)}…`);
  }
  // Height-only on input 1, time-only on input 2: incompatible.
  assert.throws(
    () => inspectB64("cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAABEgQQJwAAAAEOIDobOzyDfWSJ6nox2ObH3VA8ABvvPgaVjnV0gI1oynilAQ8EAAAAAAERBIyNxGIAAQMIT5M1dwAAAAABBBYAFAsTUsrNA89qobfzyNY4hnGzSl4RAA=="),
    /incompatible time and height locktimes/
  );
});

test("PSBT v2: BIP-370's invalid cases are refused (issue #358)", () => {
  // v2 carrying PSBT_GLOBAL_UNSIGNED_TX.
  assert.throws(
    () => inspectB64("cHNidP8BAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQIEAgAAAAEDBAAAAAABBAEBAQUBAgEGAQcB+wQCAAAAAAEAUgIAAAABwaolbiFLlqGCL5PeQr/ztfP/jQUZMG41FddRWl6AWxIAAAAAAP////8BGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgAAAAABAR8Yxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAQ4gCwrZIUGcHIcZc11y3HOfnqngY40f5MHu8PmUQISBX8gBDwQAAAAAARAE/v///wERBIyNxGIBEgQQJwAAACICAtYB+EhGpnVfd2vgDj2d6PsQrMk1+4PEX7AWLUytWreSGPadhz5UAACAAQAAgAAAAIAAAAAAKgAAAAEDCAAIry8AAAAAAQQWABTEMPZMR1baMQ29GghVcu8pmSYnLAAiAgLjb7/1PdU0Bwz4/TlmFGgPNXqbhdtzQL8c+nRdKtezQBj2nYc+VAAAgAEAAIAAAACAAQAAAGQAAAABAwiLvesLAAAAAAEEFgAUTdGTrJZKVqwbnhzKhFT+L0dPhRMA"),
    /must not carry PSBT_GLOBAL_UNSIGNED_TX/
  );
  // Missing PSBT_GLOBAL_INPUT_COUNT (BIP case).
  assert.throws(
    () => inspectB64("cHNidP8BAgQCAAAAAQMEAAAAAAEFAQIB+wQCAAAAAAEAUgIAAAABwaolbiFLlqGCL5PeQr/ztfP/jQUZMG41FddRWl6AWxIAAAAAAP////8BGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgAAAAABAR8Yxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAQ4gCwrZIUGcHIcZc11y3HOfnqngY40f5MHu8PmUQISBX8gBDwQAAAAAARAE/v///wAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA=="),
    /missing PSBT_GLOBAL_INPUT_COUNT/
  );
  // Required time locktime below 500,000,000 (BIP case).
  assert.throws(
    () => inspectB64("cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEAUgIAAAABwaolbiFLlqGCL5PeQr/ztfP/jQUZMG41FddRWl6AWxIAAAAAAP////8BGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgAAAAABAR8Yxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAQ4gCwrZIUGcHIcZc11y3HOfnqngY40f5MHu8PmUQISBX8gBDwQAAAAAAREE/2TNHQAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA=="),
    /at least 500000000/
  );
  // Required height locktime at 500,000,000 (BIP case).
  assert.throws(
    () => inspectB64("cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEAUgIAAAABwaolbiFLlqGCL5PeQr/ztfP/jQUZMG41FddRWl6AWxIAAAAAAP////8BGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgAAAAABAR8Yxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAQ4gCwrZIUGcHIcZc11y3HOfnqngY40f5MHu8PmUQISBX8gBDwQAAAAAARIEAGXNHQAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA=="),
    /height locktime must be 1 to 499999999/
  );
  // Splice-based strictness on the minimal vector (issue #340 counts exact).
  const noVersion = spliceOnce(V2_MINIMAL_HEX, "01020402000000", "");
  assert.throws(() => psbtInspectDoc(unhex(noVersion)), /missing PSBT_GLOBAL_TX_VERSION/);
  const trailingCount = spliceOnce(V2_MINIMAL_HEX, "01040101", "0104020100");
  assert.throws(() => psbtInspectDoc(unhex(trailingCount)), /trailing bytes after the count/);
  const negativeAmount = spliceOnce(V2_MINIMAL_HEX, "0008af2f00000000", "ffffffffffffffff");
  assert.throws(() => psbtInspectDoc(unhex(negativeAmount)), /amount is negative/);
  const dupPrevoutIndex = spliceOnce(V2_MINIMAL_HEX, "010f0400000000", "010f0400000000010f0400000000");
  assert.throws(() => psbtInspectDoc(unhex(dupPrevoutIndex)), /appears more than once/);
  // An unknown version is still refused.
  const v3 = spliceOnce(V2_MINIMAL_HEX, "01fb0402000000", "01fb0403000000");
  assert.throws(() => psbtInspectDoc(unhex(v3)), /only PSBT v0 and v2/);
});

test("PSBT v2: builds from the tx section, and a locktime edit must go through the requirement fields (issue #337)", () => {
  // An amount edit regenerates the PSBT_OUT_AMOUNT pair and stays parseable.
  const doc = inspectB64(V2_MINIMAL_B64);
  doc.tx.outputs[0].value = "799999999";
  const edited = psbtInspectDoc(rebuild(doc));
  assert.equal(edited.tx.outputs[0].value, "799999999");
  assert.equal(edited.rustBitcoinError, null);
  // A locktime-bearing v2 document: requirement fields drive the tx locktime.
  const locked = inspectB64("cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAABEgQQJwAAAAEOIDobOzyDfWSJ6nox2ObH3VA8ABvvPgaVjnV0gI1oynilAQ8EAAAAAAABAwhPkzV3AAAAAAEEFgAUCxNSys0Dz2qht/PI1jiGcbNKXhEA");
  assert.equal(locked.tx.locktime, 10000);
  assert.equal(Buffer.from(rebuild(locked)).toString("base64"), "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAABEgQQJwAAAAEOIDobOzyDfWSJ6nox2ObH3VA8ABvvPgaVjnV0gI1oynilAQ8EAAAAAAABAwhPkzV3AAAAAAEEFgAUCxNSys0Dz2qht/PI1jiGcbNKXhEA");
  locked.tx.locktime = 9999; // an edit that fights the requirement field
  assert.throws(() => rebuild(locked), /edit PSBT_IN_REQUIRED_\*_LOCKTIME or PSBT_GLOBAL_FALLBACK_LOCKTIME/);
});

test("oversized compact-size lengths fail as parse errors, never as WASM traps (issue #323)", () => {
  // On wasm32 `usize` is 32 bits: a u64 length truncated by `as usize` and an
  // unchecked offset addition could wrap the bounds check and panic, reaching
  // JavaScript as `RuntimeError: unreachable`. Every oversized length must
  // instead surface as a controlled parse Error whose message matches.
  const controlled = (hex, pattern) => {
    let caught = null;
    try {
      psbtInspectDoc(unhex(hex));
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "expected a thrown parse error");
    assert.ok(!(caught instanceof WebAssembly.RuntimeError), `trapped instead of erroring: ${caught}`);
    assert.match(caught.message, pattern);
  };
  // magic + key length u64::MAX (the 14-byte input from the issue).
  controlled("70736274ffffffffffffffffffff", /ended inside a key/);
  // key length u32::MAX: fits a truncated usize but the offset addition wraps.
  controlled("70736274ff" + "feffffffff", /ended inside a key/);
  // key length u32::MAX + 1: loses its high bit under a truncating cast.
  controlled("70736274ff" + "ff0000000001000000", /ended inside a key/);
  // same three as value lengths: magic, key `00`, then the length.
  controlled("70736274ff" + "0100" + "ffffffffffffffffff", /ended inside a value/);
  controlled("70736274ff" + "0100" + "feffffffff", /ended inside a value/);
  controlled("70736274ff" + "0100" + "ff0000000001000000", /ended inside a value/);
});

test("a taproot derivation pair with a huge leaf count decodes to an error, not a trap (issue #323)", () => {
  // count * 32 must be a checked multiplication: u64::MAX leaves wraps it.
  const tx =
    "02000000" + "01" + "00".repeat(32) + "00000000" + "00" + "ffffffff" +
    "01" + "0000000000000000" + "00" + "00000000";
  const psbt =
    "70736274ff" +
    "0100" + (tx.length / 2).toString(16).padStart(2, "0") + tx + "00" +
    "21" + "16" + "11".repeat(32) + "09" + "ffffffffffffffffff" + "00" +
    "00";
  const doc = psbtInspectDoc(unhex(psbt));
  const pair = doc.inputs[0].find((p) => p.name === "PSBT_IN_TAP_BIP32_DERIVATION");
  assert.match(pair.decodeError, /tap bip32 derivation is truncated/);
});

test("build and inspect limits agree: exactly 10,000 pairs per map round-trips (issue #355)", () => {
  // The inspector counted the terminator slot against the cap while the
  // builder did not, so exactly 10,000 pairs built fine but refused to
  // re-inspect. Both sides now accept up to 10,000 real pairs.
  const doc = inspectValid();
  const existing = doc.globals.length;
  for (let i = 0; i < 10_000 - existing; i++) {
    doc.globals.push({ key: "70" + i.toString(16).padStart(8, "0"), value: "00" });
  }
  const bytes = rebuild(doc);
  const fresh = psbtInspectDoc(bytes);
  assert.equal(fresh.globals.length, 10_000);
  doc.globals.push({ key: "70ffffffff", value: "00" }); // pair 10,001
  assert.throws(() => rebuild(doc), /too many pairs/);
});

test("the builder enforces the same 5 MB cap as the inspector (issue #355)", () => {
  // Just under the cap: builds and re-inspects. Split across the two output
  // maps because rust-bitcoin also bounds each map to 4,000,000 bytes.
  const under = inspectValid();
  under.outputs[0].push({ key: "71" + "22".repeat(32), value: "ab".repeat(2_400_000) });
  under.outputs[1].push({ key: "71" + "33".repeat(32), value: "cd".repeat(2_400_000) });
  const bytes = rebuild(under);
  assert.ok(bytes.length < 5_000_000);
  assert.equal(psbtInspectDoc(bytes).rustBitcoinError, null);
  // Just over: the builder refuses instead of emitting an uninspectable file.
  const over = inspectValid();
  over.outputs[0].push({ key: "71" + "22".repeat(32), value: "ab".repeat(2_900_000) });
  over.outputs[1].push({ key: "71" + "33".repeat(32), value: "cd".repeat(2_900_000) });
  assert.throws(() => rebuild(over), /rebuilt PSBT is too large/);
});

test("malformed signing fields keep their names but carry decode errors, never a decode (issue #328)", () => {
  // One input map with an empty partial signature, a 63-byte taproot key
  // signature, a truncated final witness, and a decodable final scriptSig.
  const tx =
    "02000000" + "01" + "00".repeat(32) + "00000000" + "00" + "ffffffff" +
    "01" + "0000000000000000" + "0151" + "00000000";
  const psbt =
    "70736274ff" + "0100" + "3d" + tx + "00" +
    "22" + "02" + "02".repeat(33) + "00" + // partial sig, empty value
    "01" + "13" + "3f" + "5a".repeat(63) + // taproot key sig, 63 bytes
    "01" + "08" + "01" + "03" + // final witness: count 3, then nothing
    "01" + "07" + "01" + "51" + // final scriptSig: OP_TRUE, decodes
    "00" + "00";
  const doc = psbtInspectDoc(unhex(psbt));
  const byName = (name) => doc.inputs[0].find((p) => p.name === name);
  for (const [name, error] of [
    ["PSBT_IN_PARTIAL_SIG", /partial signature is empty/],
    ["PSBT_IN_TAP_KEY_SIG", /taproot signature must be 64 or 65 bytes/],
    ["PSBT_IN_FINAL_SCRIPTWITNESS", /final witness does not decode/],
  ]) {
    assert.equal(byName(name).decoded, null, `${name} must not decode`);
    assert.match(byName(name).decodeError, error, `${name} must name its decode failure`);
  }
  // Any byte string is a script, so a final scriptSig "decodes" — presence
  // plus parseability is all the diagram claims for it.
  assert.ok(byName("PSBT_IN_FINAL_SCRIPTSIG").decoded);
  assert.ok(!byName("PSBT_IN_FINAL_SCRIPTSIG").decodeError);
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
