// Issue #87: finalized PSBT inputs carry ECDSA signatures in
// PSBT_IN_FINAL_SCRIPTSIG (0x07) / PSBT_IN_FINAL_SCRIPTWITNESS (0x08), not in
// partial-signature records. These tests run the app's real decoders against
// synthetic finalized inputs, including a same-key/same-nonce pair that must
// trigger the same reused-nonce warning as partial signatures.
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Transaction, p2pk, p2sh, p2wpkh, p2wsh } from "@scure/btc-signer";
import { loadAppFunctions } from "./app-slice-harness.mjs";
import { psbtWasmReady } from "../src/js/psbt-wasm.js";

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

// Execute the app's own decoders in a module scope whose curve, hash, and
// script/address helpers are the app's real WASM facades (never a
// reimplementation). hodlBip143 itself now calls rust-bitcoin's SighashCache
// through the WASM boundary. The curve is bound under app.js's own name: under
// a stale one, hodlFinalSigs' verify throws inside its try, and every
// signature falls back to the single-candidate rule unnoticed.
const harnessSource = `
import { secp256k1 as hodlSecp256k1 } from "../src/js/secp256k1.js";
import { hex as hodlHex } from "../src/js/coders.js";
import { p2shScript, p2wshScript } from "../src/js/addresses.js";
import { wasmExports as hodlWasm, withInput as hodlWasmIn, withOutput as hodlWasmOut } from "../src/js/entropylab-wasm.js";
import { serializeTx } from "../src/js/tx.js";
import { isP2tr } from "../src/js/bip352.js";
import { hodlTapWitnessShape } from "../src/js/psbt-schnorr.js";
${[
  "hodlPsbtNeed",
  "hodlR32",
  "hodlR64",
  "hodlVarInt",
  "hodlEq",
  "hodlConcatBytes",
  "hodlBip143",
  "hodlInputScriptCode",
  "hodlScriptHasCodeSeparator",
  "hodlScriptPushes",
  "hodlWitnessStackItems",
  "hodlLooksPubkey",
  "hodlLooksSignature",
  "hodlFinalSigs",
  "hodlCompareNonces",
]
  .map((name) => app.slice(app.indexOf(`function ${name}(`), (() => { let d = 0, s = app.indexOf("{", app.indexOf(`function ${name}(`)); for (let i = s; i < app.length; i++) { if (app[i] === "{") d++; else if (app[i] === "}" && !--d) return i + 1; } })()))
  .join("\n")}
const hodlFind = (entries, type) => entries.filter((entry) => entry.type === type);
export { hodlScriptPushes, hodlWitnessStackItems, hodlFinalSigs, hodlCompareNonces, hodlBip143, hodlInputScriptCode };
`;
// Kept inside test/ only for the import instant so bare vendor imports
// resolve; unlinked immediately after (same pattern as descriptor.test.mjs).
const harnessPath = join(root, "test", `.psbt-final-nonce-${Math.random().toString(16).slice(2)}.mjs`);
writeFileSync(harnessPath, harnessSource);
const harness = await import(pathToFileURL(harnessPath).href);
unlinkSync(harnessPath);

// --- synthetic key, fixed-nonce ECDSA, and P2WPKH fixtures -----------------

const FIELD_P = BigInt("0x" + "f".repeat(55) + "efffffc2f");
const ORDER_N = BigInt("0x" + "f".repeat(31) + "ebaaedce6af48a03bbfd25e8cd0364141");
const BASE_G = [
  BigInt("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
  BigInt("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
];
const modPow = (base, exp, mod) => {
  let result = 1n;
  base %= mod;
  while (exp) {
    if (exp & 1n) result = (result * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return result;
};
const pointAdd = (p, q) => {
  if (p === null) return q;
  if (q === null) return p;
  if (p[0] === q[0] && (p[1] + q[1]) % FIELD_P === 0n) return null;
  const inv = (a) => modPow(((a % FIELD_P) + FIELD_P) % FIELD_P, FIELD_P - 2n, FIELD_P);
  const l = p[0] === q[0]
    ? (3n * p[0] * p[0] * inv(2n * p[1])) % FIELD_P
    : ((q[1] - p[1]) * inv(q[0] - p[0])) % FIELD_P;
  const x = ((l * l - p[0] - q[0]) % FIELD_P + FIELD_P) % FIELD_P;
  return [x, ((l * (p[0] - x) - p[1]) % FIELD_P + FIELD_P) % FIELD_P];
};
const pointMul = (scalar) => {
  let k = ((scalar % ORDER_N) + ORDER_N) % ORDER_N;
  let result = null;
  let point = BASE_G;
  while (k) {
    if (k & 1n) result = pointAdd(result, point);
    point = pointAdd(point, point);
    k >>= 1n;
  }
  return result;
};
const bytes32 = (value) => Uint8Array.from(Buffer.from(value.toString(16).padStart(64, "0"), "hex"));

// Private key 7, fixed nonce k — the classic repeated-nonce laboratory.
const PRIV = 7n;
const NONCE = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefn;
const PUB_POINT = pointMul(PRIV);
const PUBKEY = Uint8Array.of(PUB_POINT[1] & 1n ? 3 : 2, ...bytes32(PUB_POINT[0]));

const derEncode = (r, s) => {
  const enc = (v) => {
    let raw = bytes32(v);
    while (raw.length > 1 && raw[0] === 0 && raw[1] < 0x80) raw = raw.slice(1);
    if (raw[0] >= 0x80) raw = Uint8Array.of(0, ...raw);
    return Uint8Array.of(2, raw.length, ...raw);
  };
  const body = Uint8Array.of(...enc(r), ...enc(s));
  return Uint8Array.of(0x30, body.length, ...body);
};

// Sign a 32-byte digest with an explicit nonce (test-only; the app never
// generates or fixes nonces itself).
const signWithNonce = (digest, k) => {
  const z = BigInt("0x" + Buffer.from(digest).toString("hex"));
  const r = pointMul(k)[0] % ORDER_N;
  const s = (modPow(k, ORDER_N - 2n, ORDER_N) * ((z + r * PRIV) % ORDER_N)) % ORDER_N;
  return { der: derEncode(r, s), r: bytes32(r) };
};

const P2WPKH_SCRIPT = (() => {
  const sha = createHash("sha256").update(Buffer.from(PUBKEY)).digest();
  const h160 = createHash("ripemd160").update(sha).digest();
  return Uint8Array.of(0x00, 0x14, ...h160);
})();

const witnessUtxoEntry = (amount, script) => ({
  type: 1,
  keydata: new Uint8Array(),
  val: Uint8Array.of(
    ...[...Array(8)].map((_, i) => Number((BigInt(amount) >> BigInt(8 * i)) & 0xffn)),
    script.length,
    ...script,
  ),
});

const finalWitnessEntry = (items) => ({
  type: 8,
  keydata: new Uint8Array(),
  val: Uint8Array.of(items.length, ...items.flatMap((item) => [item.length, ...item])),
});

const makeTx = (vout) => ({
  version: 2,
  inputs: [{ txid: new Uint8Array(32).fill(0x11), vout, sequence: 0xfffffffd }],
  outputs: [{ amount: 900n, script: P2WPKH_SCRIPT }],
  locktime: 0,
});

test("final scriptWitness fields decode into analyzed ECDSA signatures", () => {
  const tx = makeTx(0);
  const entries = [witnessUtxoEntry(1000, P2WPKH_SCRIPT)];
  const witnessUtxo = { amount: 1000n, script: P2WPKH_SCRIPT };
  const scriptCode = harness.hodlInputScriptCode(entries, witnessUtxo);
  assert.ok(scriptCode, "scriptCode");
  const digest = harness.hodlBip143(tx, 0, scriptCode, witnessUtxo.amount, 1);
  const { der } = signWithNonce(digest, NONCE);
  const signed = Uint8Array.of(...der, 1);
  entries.push(finalWitnessEntry([signed, PUBKEY]));

  const result = harness.hodlFinalSigs(entries, witnessUtxo, tx, 0);
  assert.equal(result.uninspected, 0);
  assert.equal(result.malformed, false);
  assert.equal(result.signatures.length, 1);
  // Ownership came from cryptographic verification, not stack position.
  assert.deepEqual([...result.signatures[0].pubkey], [...PUBKEY]);
  assert.deepEqual([...result.signatures[0].der], [...der]);
  assert.equal(result.signatures[0].sighash, 1);
});

test("a finalized same-key/same-r pair is flagged exactly like partial signatures", () => {
  const witnessUtxo = { amount: 1000n, script: P2WPKH_SCRIPT };
  const rValues = [];
  for (const vout of [0, 1]) {
    const tx = makeTx(vout);
    const entries = [witnessUtxoEntry(1000, P2WPKH_SCRIPT)];
    const scriptCode = harness.hodlInputScriptCode(entries, witnessUtxo);
    const digest = harness.hodlBip143(tx, 0, scriptCode, witnessUtxo.amount, 1);
    const { der, r } = signWithNonce(digest, NONCE);
    entries.push(finalWitnessEntry([Uint8Array.of(...der, 1), PUBKEY]));
    const result = harness.hodlFinalSigs(entries, witnessUtxo, tx, 0);
    assert.equal(result.signatures.length, 1);
    rValues.push({ input: vout, r, pubkey: result.signatures[0].pubkey, sighash: digest, valid: true });
  }
  assert.deepEqual([...rValues[0].r], [...rValues[1].r], "fixture must reuse r");
  const scan = harness.hodlCompareNonces(rValues);
  assert.equal(scan.reused.length, 1);
  assert.equal(scan.possible.length, 0);
});

test("final scriptSig pushes decode with a single unambiguous candidate key", () => {
  // No witness UTXO: the digest cannot be reconstructed, but a lone pubkey
  // candidate still claims the signature so r comparison stays possible.
  const sig = Uint8Array.of(...derEncode(1n, 2n), 1);
  const entries = [{
    type: 7,
    keydata: new Uint8Array(),
    val: Uint8Array.of(sig.length, ...sig, 33, ...PUBKEY),
  }];
  const result = harness.hodlFinalSigs(entries, null, makeTx(0), 0);
  assert.equal(result.signatures.length, 1);
  assert.deepEqual([...result.signatures[0].pubkey], [...PUBKEY]);
  assert.equal(result.uninspected, 0);
});

test("multiple candidate keys without a verifiable digest stay uninspected", () => {
  // A multisig-sized stack where ownership cannot be established
  // cryptographically must never produce a clean verdict.
  const other = Uint8Array.of(3, ...bytes32(42n));
  const sig = Uint8Array.of(...derEncode(1n, 2n), 1);
  const entries = [{
    type: 7,
    keydata: new Uint8Array(),
    val: Uint8Array.of(sig.length, ...sig, 33, ...PUBKEY, 33, ...other),
  }];
  const result = harness.hodlFinalSigs(entries, null, makeTx(0), 0);
  assert.equal(result.signatures.length, 0);
  assert.equal(result.uninspected, 1);
});

test("malformed final fields fail safely under explicit bounds", () => {
  const truncated = harness.hodlFinalSigs(
    [{ type: 8, keydata: new Uint8Array(), val: Uint8Array.of(1, 72, 0x30, 1) }],
    null,
    makeTx(0),
    0,
  );
  assert.equal(truncated.malformed, true);
  assert.equal(truncated.signatures.length, 0);
  const overstuffed = harness.hodlFinalSigs(
    [{ type: 8, keydata: new Uint8Array(), val: Uint8Array.of(101) }],
    null,
    makeTx(0),
    0,
  );
  assert.equal(overstuffed.malformed, true);
  const trailing = harness.hodlFinalSigs(
    [{ type: 8, keydata: new Uint8Array(), val: Uint8Array.of(0, 0) }],
    null,
    makeTx(0),
    0,
  );
  assert.equal(trailing.malformed, true);
});

test("a Taproot-only final witness yields no ECDSA material", () => {
  const schnorr = new Uint8Array(64).fill(7);
  const result = harness.hodlFinalSigs([finalWitnessEntry([schnorr])], null, makeTx(0), 0);
  assert.equal(result.signatures.length, 0);
  assert.equal(result.uninspected, 0);
  // With no previous output the witness is recognized as Taproot by its
  // shape and skipped, not swallowed as an error (Kimi K3 review of #1051).
  assert.equal(result.malformed, false);
});

test("the render loop merges final fields and never issues a clean verdict for unanalyzed final signatures", () => {
  const render = loadSlice("hodlRenderPsbt");
  // The fifth argument is the render's shared digest-reconstruction budget
  // (audit C3-3); the wiring being guarded is that final fields merge in.
  assert.match(render, /hodlFinalSigs\(entries, witnessUtxo, tx, index, signatureChecks\)/);
  assert.match(render, /uninspected \+= finalMaterial\.uninspected/);
  assert.match(render, /finalMaterial\.malformed/);
  // An unsupported finalized input forces the incomplete-coverage warning.
  assert.match(render, /!signatures\.length && !finalMaterial\.signatures\.length && !finalMaterial\.uninspected/);
  assert.match(app, /signatures carried by finalized scriptSig\/witness fields/);
});

// --- finalized inputs whose script survives only in the final fields --------
//
// A finalizer removes the redeem (0x04) and witness (0x05) script fields
// (BIP-174). The spend still carries both: the final scriptSig's last push and
// the final witness's last item. Until they were read from there, a finalized
// wrapped or P2WSH input had no digest, so its RFC 6979 check was skipped and a
// reused nonce read as "possible" or "incomplete", never as reuse.

const hash160 = (bytes) => createHash("ripemd160").update(createHash("sha256").update(Buffer.from(bytes)).digest()).digest();
const p2shOf = (redeem) => Uint8Array.of(0xa9, 0x14, ...hash160(redeem), 0x87);
const p2wshOf = (script) => Uint8Array.of(0x00, 0x20, ...createHash("sha256").update(Buffer.from(script)).digest());
const push = (bytes) => Uint8Array.of(bytes.length, ...bytes);
const unkeyed = (type, val) => ({ type, keydata: new Uint8Array(), val });
// The P2WPKH program's BIP-143 scriptCode, built here, not by the app.
const P2WPKH_SCRIPT_CODE = Uint8Array.of(0x76, 0xa9, 0x14, ...P2WPKH_SCRIPT.slice(2), 0x88, 0xac);
const compressed = (priv) => {
  const point = pointMul(priv);
  return Uint8Array.of(point[1] & 1n ? 3 : 2, ...bytes32(point[0]));
};
// signWithNonce for any key, returned with its SIGHASH_ALL byte.
const signAs = (priv, digest, k) => {
  const z = BigInt("0x" + Buffer.from(digest).toString("hex"));
  const r = pointMul(k)[0] % ORDER_N;
  const s = (modPow(k, ORDER_N - 2n, ORDER_N) * ((z + r * priv) % ORDER_N)) % ORDER_N;
  return Uint8Array.of(...derEncode(r, s), 1);
};

test("a finalized 2-of-2 P2WSH input's keys come from its final witness script", () => {
  const otherPriv = 11n, other = compressed(otherPriv);
  const witnessScript = Uint8Array.of(0x52, 33, ...PUBKEY, 33, ...other, 0x52, 0xae);
  const redeem = p2wshOf(witnessScript);
  for (const [label, outputScript, scriptSig] of [["P2WSH", redeem, []], ["P2SH-P2WSH", p2shOf(redeem), [unkeyed(7, push(redeem))]]]) {
    const witnessUtxo = { amount: 1000n, script: outputScript };
    const tx = makeTx(0);
    const digest = harness.hodlBip143(tx, 0, witnessScript, witnessUtxo.amount, 1);
    const stack = [new Uint8Array(), signAs(PRIV, digest, NONCE), signAs(otherPriv, digest, NONCE + 1n), witnessScript];
    const entries = [witnessUtxoEntry(1000, outputScript), ...scriptSig, finalWitnessEntry(stack)];
    assert.deepEqual(harness.hodlInputScriptCode(entries, witnessUtxo), witnessScript, label);
    // Two keys, so only verification can say which one made each signature.
    const result = harness.hodlFinalSigs(entries, witnessUtxo, tx, 0);
    assert.equal(result.uninspected, 0, label);
    assert.deepEqual(result.signatures.map((signature) => [...signature.pubkey]), [[...PUBKEY], [...other]], label);
  }
});

test("a final-field script that does not hash to the previous output is not used", () => {
  const otherPriv = 11n;
  const committed = Uint8Array.of(33, ...PUBKEY, 0xac), carried = Uint8Array.of(33, ...compressed(otherPriv), 0xac);
  const tx = makeTx(0);
  const wshUtxo = { amount: 1000n, script: p2wshOf(committed) };
  const signature = signAs(otherPriv, harness.hodlBip143(tx, 0, carried, wshUtxo.amount, 1), NONCE);
  const wsh = [witnessUtxoEntry(1000, wshUtxo.script), finalWitnessEntry([signature, carried])];
  assert.equal(harness.hodlInputScriptCode(wsh, wshUtxo), null);
  const result = harness.hodlFinalSigs(wsh, wshUtxo, tx, 0);
  assert.equal(result.signatures.length, 0);
  assert.equal(result.uninspected, 1);
  const shUtxo = { amount: 1000n, script: p2shOf(P2WPKH_SCRIPT) };
  const otherProgram = Uint8Array.of(0x00, 0x14, ...hash160(compressed(otherPriv)));
  assert.equal(harness.hodlInputScriptCode([witnessUtxoEntry(1000, shUtxo.script), unkeyed(7, push(otherProgram))], shUtxo), null);
});

// The whole inspector, as the PSBT tab runs it.
const view = await loadAppFunctions(["hodlParsePsbt", "hodlRenderPsbt"], {
  stubs: { document: { getElementById: () => null }, hodlPsbtRecordNonceInspection: () => {} },
  settable: ["hodlPsbtPriv"],
});
await psbtWasmReady;
const renderPsbt = (bytes) => view.hodlRenderPsbt(view.hodlParsePsbt(bytes), new Uint8Array(), new Date().toISOString(), "all");
const compactSize = (n) => (n < 0xfd ? [n] : [0xfd, n & 0xff, n >> 8]);
const varBytes = (bytes) => [...compactSize(bytes.length), ...bytes];
const psbtOf = (unsignedTx, inputs, outputCount) => Uint8Array.from([
  0x70, 0x73, 0x62, 0x74, 0xff, ...varBytes([0x00]), ...varBytes(unsignedTx), 0x00,
  ...inputs.flatMap((entries) => [...entries.flatMap((entry) => [...varBytes([entry.type, ...entry.keydata]), ...varBytes(entry.val)]), 0x00]),
  ...Array(outputCount).fill(0x00),
]);
const twoInputSpend = (payment) => {
  const tx = new Transaction();
  for (const index of [0, 1]) tx.addInput({ txid: "11".repeat(32), index, witnessUtxo: { script: payment.script, amount: 50_000n }, redeemScript: payment.redeemScript, witnessScript: payment.witnessScript });
  tx.addOutputAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 90_000n);
  return tx;
};

test("a finalized wrapped or P2WSH spend keeps its RFC 6979 verdicts", () => {
  const payments = [p2sh(p2wpkh(PUBKEY)), p2wsh(p2pk(PUBKEY)), p2sh(p2wsh(p2pk(PUBKEY)))];
  const tx = new Transaction();
  payments.forEach((payment, index) => tx.addInput({ txid: "11".repeat(32), index, witnessUtxo: { script: payment.script, amount: 50_000n }, redeemScript: payment.redeemScript, witnessScript: payment.witnessScript }));
  tx.addOutputAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 140_000n);
  tx.sign(bytes32(PRIV));
  tx.finalize();
  // @scure/btc-signer, the independent finalizer, cleared both script fields.
  payments.forEach((_, index) => {
    assert.equal(tx.getInput(index).redeemScript, undefined);
    assert.equal(tx.getInput(index).witnessScript, undefined);
  });
  view.__set.hodlPsbtPriv(bytes32(PRIV));
  const html = renderPsbt(tx.toPSBT());
  assert.equal((html.match(/Matches RFC 6979/g) || []).length, payments.length);
  assert.match(html, /Nonce analysis<\/span> — <span class='psbt-ok'>Completed<\/span>/);
});

test("a finalized wrapped or P2WSH pair that reuses a nonce is reported as reuse", () => {
  view.__set.hodlPsbtPriv(null);
  const wrapped = p2sh(p2wpkh(PUBKEY)), native = p2wsh(p2pk(PUBKEY));
  for (const [label, payment, scriptCode, finalFields] of [
    ["P2SH-P2WPKH", wrapped, P2WPKH_SCRIPT_CODE, (signature) => [unkeyed(7, push(wrapped.redeemScript)), finalWitnessEntry([signature, PUBKEY])]],
    ["P2WSH", native, native.witnessScript, (signature) => [finalWitnessEntry([signature, native.witnessScript])]],
  ]) {
    const unsigned = twoInputSpend(payment).unsignedTx;
    const inputs = [0, 1].map((index) => [
      witnessUtxoEntry(50_000, payment.script),
      ...finalFields(signAs(PRIV, harness.hodlBip143({ raw: unsigned }, index, scriptCode, 50_000n, 1), NONCE)),
    ]);
    const html = renderPsbt(psbtOf(unsigned, inputs, 1));
    assert.match(html, /Reused nonce detected for the same public key/, label);
    assert.doesNotMatch(html, /Possible repeated nonce|Incomplete nonce coverage/, label);
  }
});
