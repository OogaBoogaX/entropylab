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
// through the WASM boundary.
const harnessSource = `
import { secp256k1 as xe } from "../src/js/secp256k1.js";
import { p2shScript, p2wshScript } from "../src/js/addresses.js";
import { wasmExports as hodlWasm, withInput as hodlWasmIn, withOutput as hodlWasmOut } from "../src/js/entropylab-wasm.js";
import { serializeTx } from "../src/js/tx.js";
${[
  "hodlPsbtNeed",
  "hodlR32",
  "hodlR64",
  "hodlVarInt",
  "hodlEq",
  "hodlConcatBytes",
  "hodlBip143",
  "hodlInputScriptCode",
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
});

test("the render loop merges final fields and never issues a clean verdict for unanalyzed final signatures", () => {
  const render = loadSlice("hodlRenderPsbt");
  assert.match(render, /hodlFinalSigs\(entries, witnessUtxo, tx, index\)/);
  assert.match(render, /uninspected \+= finalMaterial\.uninspected/);
  assert.match(render, /finalMaterial\.malformed/);
  // An unsupported finalized input forces the incomplete-coverage warning.
  assert.match(render, /!signatures\.length && !finalMaterial\.signatures\.length && !finalMaterial\.uninspected/);
  assert.match(app, /signatures carried by finalized scriptSig\/witness fields/);
});
