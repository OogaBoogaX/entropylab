// Audit C2-D: the JS inspector reconstructs each BIP-143 sighash over the
// FULL witness script, but consensus hashes from just past the last executed
// OP_CODESEPARATOR (psbt-wasm's scriptcode.rs enumerates those starts). For a
// P2WSH script containing OP_CODESEPARATOR the per-signature verdict could
// therefore be wrong in both directions: a green "Matches RFC 6979" on a
// signature the network rejects, and a false "does not verify" on an honest
// codeseparated signature. The render must skip the digest verdict and the
// RFC-6979 recompute for such a signature with an explicit incomplete row,
// and a script without a separator opcode must keep the existing verdicts.
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { secp256k1 } from "../src/js/secp256k1.js";
import { p2wshScript } from "../src/js/addresses.js";
import { psbtWasmReady } from "../src/js/psbt-wasm.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");

// Extract one function's full source. The parameter list is matched first
// (defaults like `options = {}` contain braces), then the body's braces —
// the same slice the other PSBT harnesses take, hardened for that one case.
function loadSlice(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let parens = 0;
  let index = app.indexOf("(", start);
  for (; index < app.length; index++) {
    if (app[index] === "(") parens++;
    else if (app[index] === ")" && !--parens) break;
  }
  let depth = 0;
  for (let cursor = app.indexOf("{", index); cursor < app.length; cursor++) {
    if (app[cursor] === "{") depth++;
    else if (app[cursor] === "}" && !--depth) return app.slice(start, cursor + 1);
  }
  throw new Error(`Could not extract ${name}`);
}

// The render path is exercised against the shipped source: the harness
// slices the transitive closure of whatever hodlParsePsbt / hodlRenderPsbt
// call, so statements added to either travel into this suite without the
// slice list drifting. Every referenced hodl* identifier must resolve to an
// app.js function (sliced below) or to a name the prelude declares; anything
// else fails the load loudly instead of rendering with a silent stand-in.
const DECLARED = new Set([
  // Real imports (same modules app.js imports from).
  "hodlSha256", "hodlHash160", "hodlSecp256k1", "hodlHex", "p2shScript", "p2wshScript", "addressFromScript",
  "parseRawTx", "serializeTx", "hodlWasm", "hodlWasmIn", "hodlWasmOut", "psbtInspectDoc",
  "hodlT", "hodlTText", "hodlTAttr", "matchOwnership", "indexHdKey", "indexSingleKey", "pathLabel",
  "hodlTapKeySigs", "hodlTapScriptSigs", "hodlTapSighashProblems",
  "inspectPsbtInscriptions", "describeEnvelope", "parseOpReturn", "describeOpReturn",
  "hodlPublicValueHtml",
  // Harness seams from the prelude below (no browser chrome; controllable session).
  "document", "hodlNetworkDefault", "hodlNetworkChoice", "hodlPsbtPriv", "hodlPsbtHd", "hodlPsbtRecordNonceInspection",
]);
// Top-level variables of app.js the render closure reads or writes through
// the reset/refresh functions it reaches (session state, nonce-history
// bookkeeping, the journal snapshot globals). None may name an app.js
// function — the module-scope check below fails the load if app.js ever
// turns one of them into a function the slice should have taken.
const DECLARED_VARS = [
  "hodlPsbtSource", "hodlPsbtSessionSpec",
  "hodlPsbtCurrentNonceRecords", "hodlPsbtNonceVerdict", "hodlPsbtNonceVerdictKind",
  "hodlPsbtNonceHistoryVerdict", "hodlPsbtNonceInspected",
  "hodlJournalStateRefreshQueued", "hodlJournalKeys", "hodlJournalDoc", "hodlKeys",
  "hodlRecoverySheetText", "hodlMsigs", "hodlBip85Children", "hodlSpKeys",
  "hodlPsbtNonceHistory", "hodlJournalSnapshot", "hodlJournalStamp", "hodlJournal",
  "hodlPsbtLast", "hodlNonceLast",
];
DECLARED_VARS.forEach((name) => {
  assert.ok(!app.includes(`function ${name}(`), `${name} is an app.js function now — the closure must slice it, not redeclare it`);
  DECLARED.add(name);
});
// Render rows build their copy buttons through this module-scope seam, not a
// `function hodl...` declaration, so the closure walk cannot find it.
DECLARED.add("hodlPrivateCopyButtonHtml");

function closure(names) {
  const seen = new Set(DECLARED);
  const queue = [...names];
  const bodies = [];
  while (queue.length) {
    const name = queue.shift();
    if (seen.has(name)) continue;
    seen.add(name);
    const body = loadSlice(name);
    bodies.push(body);
    for (const match of body.matchAll(/\bhodl[A-Za-z0-9_]*\b/g)) {
      const id = match[0];
      if (seen.has(id)) continue;
      assert.ok(app.includes(`function ${id}(`), `${id} is neither an app.js function nor a declared harness seam`);
      queue.push(id);
    }
  }
  return bodies.join("\n");
}

// Execute the app's own parser and inspector with its real curve, hash,
// script/address, i18n, and WASM facades (never a reimplementation), the
// same pattern as psbt-final-nonce.test.mjs. The nonce-history side effect
// is stubbed; the Anti-exfil transcript field reads as absent (no document).
const harnessSource = `
import { sha256 as hodlSha256, hash160 as hodlHash160 } from "../src/js/hashes.js";
import { secp256k1 as hodlSecp256k1 } from "../src/js/secp256k1.js";
import { hex as hodlHex } from "../src/js/coders.js";
import { p2shScript, p2wshScript, addressFromScript } from "../src/js/addresses.js";
import { parseRawTx, serializeTx } from "../src/js/tx.js";
import { wasmExports as hodlWasm, withInput as hodlWasmIn, withOutput as hodlWasmOut } from "../src/js/entropylab-wasm.js";
import { psbtInspectDoc } from "../src/js/psbt-wasm.js";
import { tHtml as hodlT, t as hodlTText, tAttr as hodlTAttr } from "../src/js/i18n.js";
import { matchOwnership, indexHdKey, indexSingleKey, pathLabel } from "../src/js/ownership.js";
import { hodlTapKeySigs, hodlTapScriptSigs, hodlTapSighashProblems } from "../src/js/psbt-schnorr.js";
import { inspectPsbtInscriptions, describeEnvelope } from "../src/js/inscription.js";
import { parseOpReturn, describeOpReturn } from "../src/js/opreturn.js";
import { publicValueHtml as hodlPublicValueHtml } from "../src/js/public-data.js";
const document = { getElementById: () => null };
const hodlNetworkDefault = "mainnet";
const hodlNetworkChoice = "mainnet";
var hodlPsbtPriv = null, hodlPsbtHd = null;
const hodlPsbtRecordNonceInspection = () => {};
const hodlPrivateCopyButtonHtml = () => "";
${DECLARED_VARS.map((name) => `var ${name};`).join("\n")}
export function hodlTestSetPriv(key) { hodlPsbtPriv = key; }
${closure(["hodlParsePsbt", "hodlRenderPsbt"])}
export { hodlParsePsbt, hodlRenderPsbt, hodlInputScriptCode, hodlBip143, hodlFinalSigs };
`;
// Kept inside test/ only for the import instant so bare vendor imports
// resolve; unlinked immediately after (same pattern as psbt-final-nonce).
const harnessPath = join(root, "test", `.psbt-codeseparator-${Math.random().toString(16).slice(2)}.mjs`);
writeFileSync(harnessPath, harnessSource);
const harness = await import(pathToFileURL(harnessPath).href);
unlinkSync(harnessPath);
await psbtWasmReady;

// --- fixtures ---------------------------------------------------------------
// A fixed key pair signs every fixture; the RFC-6979 recompute path needs the
// session key, so the harness session slot holds it during renders.

const SECRET = new Uint8Array(32).fill(7);
const PUBKEY = secp256k1.getPublicKey(SECRET, true);
const PUSH_KEY = Uint8Array.of(0x21, ...PUBKEY);
const OP_CHECKSIG = 0xac;
const OP_CODESEPARATOR = 0xab;

// <pk> CHECKSIG has no separator: the control. Prefixing one OP_CODESEPARATOR
// makes the separated variant; the script a signature there commits to is the
// bytes past the separator (BIP-143), i.e. the control script itself.
const CONTROL_SCRIPT = Uint8Array.of(...PUSH_KEY, OP_CHECKSIG);
const SEPARATED_SCRIPT = Uint8Array.of(OP_CODESEPARATOR, ...PUSH_KEY, OP_CHECKSIG);
const CODE_START_SCRIPT = CONTROL_SCRIPT;
// A separator byte carried as PUSHDATA1 payload is data, not an opcode: the
// walker must skip it, so this script keeps the control verdicts.
const PUSHDATA_SCRIPT = Uint8Array.of(...PUSH_KEY, OP_CHECKSIG, 0x4c, 0x02, OP_CODESEPARATOR, OP_CODESEPARATOR);

const le32 = (n) => [n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255];
const le64 = (n) => [...Array(8)].map((_, i) => Number((n >> BigInt(8 * i)) & 255n));
const compactSize = (n) => (n < 0xfd ? [n] : n <= 0xffff ? [0xfd, n & 255, n >>> 8] : [0xfe, ...le32(n)]);
const varBytes = (bytes) => [...compactSize(bytes.length), ...bytes];
const kv = (key, value) => [...varBytes(key), ...varBytes(value)];

const INPUTS = 2; // two signatures, so rValues.length < 2 cannot cloud the summary state
const AMOUNT = 100000n;
const OUTPUT_SCRIPT = Uint8Array.of(0x00, 0x14, ...new Uint8Array(20).fill(0x42));

// Two-input transaction spending fabricated prevouts to one output. The
// reference layer cannot check prevouts against a chain; no input claims a
// sighash policy, so each signature's SIGHASH_ALL byte is in-policy.
function unsignedTxBytes() {
  return Uint8Array.from([
    ...le32(2),
    INPUTS,
    ...[...Array(INPUTS)].flatMap((_, i) => [
      ...new Uint8Array(32).fill(0x10 + i), // fabricated previous txid
      ...le32(0), // vout 0
      0, // empty scriptSig, as a PSBT v0 unsigned transaction requires
      ...le32(0xfffffffd),
    ]),
    1, // one output
    ...le64(90000n),
    ...varBytes(OUTPUT_SCRIPT),
    ...le32(0),
  ]);
}

const derEncode = (compact) => {
  const integer = (bytes) => {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0 && bytes[start + 1] < 0x80) start++;
    let raw = bytes.slice(start);
    if (raw[0] >= 0x80) raw = Uint8Array.of(0, ...raw);
    return Uint8Array.of(0x02, raw.length, ...raw);
  };
  const body = Uint8Array.of(...integer(compact.slice(0, 32)), ...integer(compact.slice(32)));
  return Uint8Array.of(0x30, body.length, ...body);
};

// One PSBT per scenario: two P2WSH inputs committing to witnessScript, each
// carrying an RFC-6979 partial signature over the BIP-143 digest of
// digestScript. For the control the two scripts coincide; for the crafted
// case digestScript is the full separated script (what the JS reconstruction
// computed before the fix); for the honest case it is the post-separator
// bytes, exactly what a network consensus check hashes.
function buildPsbt(witnessScript, digestScript) {
  const tx = unsignedTxBytes();
  const out = [0x70, 0x73, 0x62, 0x74, 0xff, ...kv([0x00], tx), 0x00];
  for (let i = 0; i < INPUTS; i++) {
    out.push(...kv([0x01], [...le64(AMOUNT), ...varBytes(p2wshScript(witnessScript))]));
    const digest = harness.hodlBip143({ raw: tx }, i, digestScript, AMOUNT, 1);
    assert.ok(digest, "fixture digest");
    const sig = Uint8Array.of(...derEncode(secp256k1.sign(digest, SECRET, { prehash: false, extraEntropy: false })), 0x01);
    out.push(...kv([0x02, ...PUBKEY], sig));
    out.push(...kv([0x05], witnessScript));
    out.push(0x00);
  }
  out.push(0x00);
  return Uint8Array.from(out);
}

function render(bytes) {
  return harness.hodlRenderPsbt(harness.hodlParsePsbt(bytes), new Uint8Array(), new Date().toISOString(), "all");
}

function assertCodeseparatorIncomplete(html) {
  const rows = html.match(/<span class='psbt-warn'>[^<]*OP_CODESEPARATOR[^<]*<\/span>/g) || [];
  assert.equal(rows.length, INPUTS, "every signature on the separated script gets the incomplete row");
  assert.doesNotMatch(html, /Matches RFC 6979/);
  assert.doesNotMatch(html, /does not verify against the reconstructed input digest/);
  assert.match(html, /Nonce analysis<\/span> — <span class='psbt-warn'>Incomplete<\/span>/);
}

function assertControlUnchanged(html) {
  assert.match(html, /Matches RFC 6979/);
  assert.doesNotMatch(html, /<span class='psbt-warn'>[^<]*OP_CODESEPARATOR/);
  assert.match(html, /Nonce analysis<\/span> — <span class='psbt-ok'>Completed<\/span>/);
}

test("codeseparated P2WSH: a signature only the full-script digest accepts is reported incomplete, not a green verdict (audit C2-D)", () => {
  harness.hodlTestSetPriv(SECRET);
  // Before the fix this file rendered "Matches RFC 6979" for both inputs,
  // while the crate reported the signatures invalid for their prevouts.
  assertCodeseparatorIncomplete(render(buildPsbt(SEPARATED_SCRIPT, SEPARATED_SCRIPT)));
});

test("codeseparated P2WSH: an honest post-separator signature is reported incomplete, never 'does not verify' (audit C2-D)", () => {
  harness.hodlTestSetPriv(SECRET);
  // Before the fix this file rendered "does not verify against the
  // reconstructed input digest" for both signatures.
  assertCodeseparatorIncomplete(render(buildPsbt(SEPARATED_SCRIPT, CODE_START_SCRIPT)));
});

test("control: a P2WSH script without separators keeps the existing verdicts", () => {
  harness.hodlTestSetPriv(SECRET);
  assertControlUnchanged(render(buildPsbt(CONTROL_SCRIPT, CONTROL_SCRIPT)));
});

test("control: a separator byte inside pushed data is not an opcode", () => {
  harness.hodlTestSetPriv(SECRET);
  // PUSHDATA1 carries 0xab bytes as payload; the digest correctly covers the
  // full script, so the RFC-6979 verdict must remain exactly as before.
  assertControlUnchanged(render(buildPsbt(PUSHDATA_SCRIPT, PUSHDATA_SCRIPT)));
});

// --- finalized inputs (hodlFinalSigs) ----------------------------------------
// A finalized input's signatures sit in its final witness, and hodlFinalSigs
// attributes each to a key so the repeated-nonce pass can use it. Contract:
// in a script containing OP_CODESEPARATOR, the full-script digest never
// attributes a signature to a key; with more than one candidate key such a
// signature stays unattributed and counts as uninspected. A script without a
// separator still attributes by verification. Two candidate keys rule out
// the single-candidate fallback, so only the digest could pin the signature.
// The witness script stays in 0x05, which is what lets the inspector
// reconstruct a digest at all.
const OTHER_PUBKEY = secp256k1.getPublicKey(new Uint8Array(32).fill(9), true);
const OP_DROP = 0x75;
const TWO_KEY_CONTROL = Uint8Array.of(0x21, ...OTHER_PUBKEY, OP_DROP, ...PUSH_KEY, OP_CHECKSIG);
const TWO_KEY_SEPARATED = Uint8Array.of(0x21, ...OTHER_PUBKEY, OP_DROP, OP_CODESEPARATOR, ...PUSH_KEY, OP_CHECKSIG);

// Input 0's map entries for a finalized P2WSH spend of witnessScript whose
// one signature, by SECRET, is over the BIP-143 digest of digestScript.
function finalizedEntries(witnessScript, digestScript) {
  const tx = { raw: unsignedTxBytes() };
  const witnessUtxo = { amount: AMOUNT, script: p2wshScript(witnessScript) };
  const digest = harness.hodlBip143(tx, 0, digestScript, AMOUNT, 1);
  assert.ok(digest, "fixture digest");
  const sig = Uint8Array.of(...derEncode(secp256k1.sign(digest, SECRET, { prehash: false, extraEntropy: false })), 0x01);
  const entry = (type, val) => ({ type, keydata: new Uint8Array(), val: Uint8Array.from(val) });
  const entries = [
    entry(0x01, [...le64(AMOUNT), ...varBytes(witnessUtxo.script)]),
    entry(0x05, witnessScript),
    entry(0x08, [2, ...varBytes(sig), ...varBytes(witnessScript)]),
  ];
  return { entries, witnessUtxo, tx };
}
const finalSigs = ({ entries, witnessUtxo, tx }) => harness.hodlFinalSigs(entries, witnessUtxo, tx, 0, null);

test("finalized codeseparated P2WSH: the full-script digest never attributes a signature to a key (#857 follow-up)", () => {
  // Crafted: signed over the full separated script, so only the digest this
  // inspector would reconstruct accepts it.
  const crafted = finalSigs(finalizedEntries(TWO_KEY_SEPARATED, TWO_KEY_SEPARATED));
  assert.equal(crafted.signatures.length, 0, "no key is pinned by a full-script digest");
  assert.equal(crafted.uninspected, 1);
  assert.equal(crafted.malformed, false);
  // Honest: signed over the post-separator code, which consensus hashes.
  const honest = finalSigs(finalizedEntries(TWO_KEY_SEPARATED, CONTROL_SCRIPT));
  assert.equal(honest.signatures.length, 0);
  assert.equal(honest.uninspected, 1);
});

test("control: a finalized two-key P2WSH script without separators attributes by verification", () => {
  const control = finalSigs(finalizedEntries(TWO_KEY_CONTROL, TWO_KEY_CONTROL));
  assert.equal(control.uninspected, 0);
  assert.equal(control.signatures.length, 1);
  assert.deepEqual([...control.signatures[0].pubkey], [...PUBKEY], "the verifying key, not the other candidate");
});
