// Per-signature verification for the PSBT Signer Audit (engine:
// psbt-signer-audit.js; wiring: hodlPsbtPrependSignerAudit in app.js).
//
// Why this module exists (approved plan, option b): the psbt-wasm verify
// layer (psbt-wasm/src/verify.rs) already verifies every partial and
// taproot signature, but the inspect document carries only its problems —
// a signature that verified and one that was never checked (a missing UTXO
// claim skips the input silently; an exhausted budget skips the signature
// silently) leave the same absence, so "no problem" cannot soundly be read
// as "valid" across the WASM boundary, and exposing per-signature outcomes
// would be a Rust change plus a rebuilt artifact. The soundest source
// available to JS is recomputation: every digest is rebuilt here and every
// signature is verified with the app's own secp256k1 (src/js/secp256k1.js).
//
// The contract is fail closed. `valid` is true only when the signature
// verified against the exact consensus digest for that input and sighash
// type; false only when verification ran and failed (a malformed DER blob
// or key fails the same way consensus would, mirroring verify.rs); null
// whenever the digest cannot be computed soundly — a missing or
// conflicting UTXO claim, an OP_CODESEPARATOR, an unsupported sighash or
// script type, the exhausted check budget, or a secp256k1 facade that is
// not ready. Never true on a guess.
//
// Every entry names the exact PSBT key it verified — the pair's keydata
// with its type byte ("02"+pubkey for a partial signature, "13" for a
// key-path signature, "14"+xonly+leafHash for a script-path one). The
// engine's Phase F matches an entry only on index + name + that exact key,
// so an entry without one never counts.
//
// Digests: segwit v0 SIGHASH_ALL comes from the same crypto-WASM export
// the Inspector's BIP-143 path uses; legacy SIGHASH_ALL and BIP-341 (key
// path, and script path with no OP_CODESEPARATOR, sighash DEFAULT/ALL)
// preimages are hashed here from the BIP specs and pinned against
// @scure/btc-signer in test/psbt-signer-audit-verify.test.mjs. Weak
// sighash types are not reconstructed: the engine's sighash-policy phase
// already fails the audit on them, so an unverified report loses nothing.
//
// BIP-340 verification runs only through the libsecp256k1 WASM facade
// (src/js/secp256k1.js, secp256k1.schnorr.verify). The page never does
// curve math in JavaScript.
import { sha256 as hodlSha256, hash160 as hodlHash160 } from "./hashes.js";
import { secp256k1 as hodlSecp256k1 } from "./secp256k1.js";
import { hex as hodlHex } from "./coders.js";
import { wasmExports as hodlWasm, withInput as hodlWasmIn, withOutput as hodlWasmOut } from "./entropylab-wasm.js";

// One budget per audit run, mirroring the consensus layer's
// MAX_SIGNATURE_CHECKS (psbt-wasm/src/verify.rs) and the Inspector's
// per-file check budget: past it, signatures are unverified, never valid.
export const SIGNER_AUDIT_MAX_SIGNATURE_CHECKS = 256;

const SIG_NAMES = new Set(["PSBT_IN_PARTIAL_SIG", "PSBT_IN_TAP_KEY_SIG", "PSBT_IN_TAP_SCRIPT_SIG"]);
// BIP-341's defined appended sighash bytes; SIGHASH_DEFAULT exists only as
// the 64-byte implicit form (mirrors psbt-schnorr.js).
const TAPROOT_SIGHASH_BYTES = new Set([0x01, 0x02, 0x03, 0x81, 0x82, 0x83]);

const lower = (value) => String(value ?? "").toLowerCase();
const hexBytes = (value) => {
  const text = lower(value);
  if (text.length % 2 || !/^[0-9a-f]*$/.test(text)) return null;
  try {
    return hodlHex.decode(text);
  } catch {
    return null;
  }
};
const eqBytes = (a, b) => a.length === b.length && a.every((byte, index) => byte === b[index]);
// Concatenate a list of byte arrays without spreading them into one call:
// a PSBT with very many inputs produces tens of thousands of parts, and
// `f(...parts)` throws RangeError past the engine's argument limit, which
// would downgrade the whole audit to unverified.
const concatBytes = (parts) => {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
};
const containsBytes = (haystack, needle) => {
  if (!needle.length) return false;
  for (let i = 0; i + needle.length <= haystack.length; i++) {
    let match = true;
    for (let j = 0; j < needle.length; j++) if (haystack[i + j] !== needle[j]) { match = false; break; }
    if (match) return true;
  }
  return false;
};
const u32le = (n) => { const out = new Uint8Array(4); new DataView(out.buffer).setUint32(0, n >>> 0, true); return out; };
const i32le = (n) => { const out = new Uint8Array(4); new DataView(out.buffer).setInt32(0, n, true); return out; };
const u64le = (v) => { const out = new Uint8Array(8); new DataView(out.buffer).setBigUint64(0, v, true); return out; };
const varintBytes = (n) => {
  if (n < 0xfd) return Uint8Array.of(n);
  if (n <= 0xffff) return Uint8Array.of(0xfd, n & 0xff, (n >> 8) & 0xff);
  if (n <= 0xffffffff) {
    const out = new Uint8Array(5);
    out[0] = 0xfe;
    new DataView(out.buffer).setUint32(1, n, true);
    return out;
  }
  const out = new Uint8Array(9);
  out[0] = 0xff;
  new DataView(out.buffer).setBigUint64(1, BigInt(n), true);
  return out;
};
// The inspect document serializes u64 amounts as decimal strings (issue
// #351); anything that is not a non-negative integer is not an amount.
const satsOf = (value) => {
  if (typeof value === "string" && /^\d+$/.test(value)) return BigInt(value);
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  if (typeof value === "bigint" && value >= 0n) return value;
  return null;
};
const mapPairs = (doc, index) => {
  const map = doc?.inputs?.[index];
  return Array.isArray(map) ? map : [];
};

// The unsigned transaction as consensus bytes, rebuilt from the inspect
// document (display-order txids reverse to wire order; amounts are the
// document's decimal strings). Null when any field is not soundly
// serializable — every digest then reports unverified. `scriptAt`
// overrides each input's scriptSig (the legacy digest empties all but one).
const serializeDocTx = (tx, scriptAt) => {
  if (!tx || !Array.isArray(tx.inputs) || !Array.isArray(tx.outputs)) return null;
  const version = Number(tx.version), locktime = Number(tx.locktime);
  if (!Number.isInteger(version) || !Number.isInteger(locktime) || locktime < 0 || locktime > 0xffffffff) return null;
  const parts = [i32le(version), varintBytes(tx.inputs.length)];
  for (let index = 0; index < tx.inputs.length; index++) {
    const input = tx.inputs[index];
    const txid = hexBytes(input?.txid);
    if (!txid || txid.length !== 32) return null;
    txid.reverse();
    const vout = Number(input.vout), sequence = Number(input.sequence);
    if (!Number.isInteger(vout) || vout < 0 || vout > 0xffffffff) return null;
    if (!Number.isInteger(sequence) || sequence < 0 || sequence > 0xffffffff) return null;
    const script = scriptAt ? scriptAt(index) : hexBytes(input.scriptSig);
    if (!script) return null;
    parts.push(txid, u32le(vout), varintBytes(script.length), script, u32le(sequence));
  }
  parts.push(varintBytes(tx.outputs.length));
  for (const output of tx.outputs) {
    const value = satsOf(output?.value), script = hexBytes(output?.scriptPubKey);
    if (value === null || !script || value > 0xffffffffffffffffn) return null;
    parts.push(u64le(value), varintBytes(script.length), script);
  }
  parts.push(u32le(locktime));
  return concatBytes(parts);
};

// One input's UTXO claim, from the witness declaration or the non-witness
// one (the inspect document only fills `prevout` when the embedded
// transaction's txid matches the input's prevout). A conflict between the
// two is itself a consensus problem (verify.rs utxo_claim_conflict): no
// verdict may rest on a disputed output, so the claim is nothing.
const inputClaim = (doc, index) => {
  let witness = null, nonWitness = null;
  for (const pair of mapPairs(doc, index)) {
    if (!pair || pair.decodeError || !pair.decoded) continue;
    if (pair.name === "PSBT_IN_WITNESS_UTXO") {
      const value = satsOf(pair.decoded.value), scriptPubKey = hexBytes(pair.decoded.scriptPubKey);
      if (value !== null && scriptPubKey) witness = { value, scriptPubKey };
    } else if (pair.name === "PSBT_IN_NON_WITNESS_UTXO") {
      const value = satsOf(pair.decoded.prevout?.value), scriptPubKey = hexBytes(pair.decoded.prevout?.scriptPubKey);
      if (value !== null && scriptPubKey) nonWitness = { value, scriptPubKey };
    }
  }
  if (witness && nonWitness && (witness.value !== nonWitness.value || !eqBytes(witness.scriptPubKey, nonWitness.scriptPubKey))) return null;
  return witness ?? nonWitness;
};

// Whether a script carries an OP_CODESEPARATOR (0xab) opcode. BIP-143 and
// BIP-342 commit from just past the last executed separator, which this
// module does not reconstruct, so such a signature is never verified here
// (the Inspector's hodlScriptHasCodeSeparator walk, mirrored).
const hasCodeSeparator = (script) => {
  let pc = 0;
  while (pc < script.length) {
    let op = script[pc], left = script.length - pc - 1, header = 0, data = 0;
    if (op >= 1 && op <= 75) data = op;
    else if (op === 0x4c) { if (left < 1) break; header = 1; data = script[pc + 1]; }
    else if (op === 0x4d) { if (left < 2) break; header = 2; data = script[pc + 1] + script[pc + 2] * 256; }
    else if (op === 0x4e) { if (left < 4) break; header = 4; data = script[pc + 1] + script[pc + 2] * 256 + script[pc + 3] * 65536 + script[pc + 4] * 16777216; }
    else if (op === 0xab) return true;
    if (data > left - header) break;
    pc += 1 + header + data;
  }
  return false;
};

const isP2wpkh = (s) => s.length === 22 && s[0] === 0x00 && s[1] === 0x14;
const isP2wsh = (s) => s.length === 34 && s[0] === 0x00 && s[1] === 0x20;
const isP2tr = (s) => s.length === 34 && s[0] === 0x51 && s[1] === 0x20;
const isP2sh = (s) => s.length === 23 && s[0] === 0xa9 && s[1] === 0x14 && s[22] === 0x87;
const p2pkhScriptCode = (keyHash) => concatBytes([Uint8Array.of(0x76, 0xa9, 0x14), keyHash, Uint8Array.of(0x88, 0xac)]);

const decodedField = (doc, index, name) => {
  for (const pair of mapPairs(doc, index)) {
    if (pair && pair.name === name && !pair.decodeError && pair.decoded) {
      const bytes = hexBytes(pair.decoded.hex);
      if (bytes) return bytes;
    }
  }
  return null;
};
// The witness script, only when it hashes to the program it must match
// (the BIP-174 signer check; verify.rs witness_script_mismatch).
const witnessScriptFor = (doc, index, program) => {
  const script = decodedField(doc, index, "PSBT_IN_WITNESS_SCRIPT");
  return script && eqBytes(hodlSha256(script), program) ? script : null;
};

// The scriptCode an ECDSA partial signature on this input can be checked
// against, and the digest kind. Null when nothing sound remains (a taproot
// claim, a missing or hash-mismatched script).
const ecdsaScriptCode = (doc, index, claim) => {
  const spk = claim.scriptPubKey;
  if (isP2wpkh(spk)) return { kind: "bip143", scriptCode: p2pkhScriptCode(spk.slice(2)), amount: claim.value };
  if (isP2wsh(spk)) {
    const script = witnessScriptFor(doc, index, spk.slice(2));
    return script ? { kind: "bip143", scriptCode: script, amount: claim.value } : null;
  }
  if (isP2tr(spk)) return null; // taproot signs with Schnorr; an ECDSA partial here has no digest
  if (isP2sh(spk)) {
    const redeem = decodedField(doc, index, "PSBT_IN_REDEEM_SCRIPT");
    if (!redeem || !eqBytes(hodlHash160(redeem), spk.slice(2, 22))) return null;
    if (isP2wpkh(redeem)) return { kind: "bip143", scriptCode: p2pkhScriptCode(redeem.slice(2)), amount: claim.value };
    if (isP2wsh(redeem)) {
      const script = witnessScriptFor(doc, index, redeem.slice(2));
      return script ? { kind: "bip143", scriptCode: script, amount: claim.value } : null;
    }
    return { kind: "legacy", scriptCode: redeem };
  }
  return { kind: "legacy", scriptCode: spk };
};

// BIP-143 segwit v0 SIGHASH_ALL digest from the crypto WASM module — the
// same export the Inspector's hodlBip143 uses.
const bip143AllDigest = (rawTx, index, scriptCode, amount) => {
  try {
    return hodlWasmIn(rawTx, (txPtr) =>
      hodlWasmIn(scriptCode, (scriptPtr) =>
        hodlWasmOut(32, (out) =>
          hodlWasm().el_sighash_segwit_v0(txPtr, rawTx.length, index, scriptPtr, scriptCode.length, amount, out)))) ?? null;
  } catch {
    return null;
  }
};

// Legacy SIGHASH_ALL digest (Bitcoin Core's SignatureHash): every
// scriptSig emptied but this input's scriptCode, the four-byte hash type
// appended, double SHA-256. Core also FindAndDelete's the signature itself
// from the scriptCode; a script that embeds it is refused instead.
const legacyAllDigest = (tx, index, scriptCode, signature) => {
  if (containsBytes(scriptCode, signature)) return null;
  const raw = serializeDocTx(tx, (at) => (at === index ? scriptCode : new Uint8Array()));
  return raw ? hodlSha256(hodlSha256(concatBytes([raw, u32le(1)]))) : null;
};

const taggedHash = (tag, ...messages) => {
  const tagHash = hodlSha256(new TextEncoder().encode(tag));
  return hodlSha256(concatBytes([tagHash, tagHash, ...messages]));
};

// BIP-341 SigMsg digest for SIGHASH_DEFAULT/ALL (the only full-commitment
// taproot types; anything else is refused and the engine's sighash-policy
// phase names it). Key path (ext null) and BIP-342 script path with no
// executed OP_CODESEPARATOR (codesep_pos 0xffffffff). Every input needs a
// resolved claim — the message commits to all of them.
const bip341Digest = (tx, claims, index, sighashType, ext) => {
  if (sighashType !== 0 && sighashType !== 1) return null;
  if (!claims.every(Boolean)) return null;
  const prevouts = [], amounts = [], scriptPubKeys = [], sequences = [], outputs = [];
  for (let i = 0; i < tx.inputs.length; i++) {
    const txid = hexBytes(tx.inputs[i]?.txid);
    if (!txid || txid.length !== 32) return null;
    prevouts.push(txid.reverse(), u32le(Number(tx.inputs[i].vout)));
    amounts.push(u64le(claims[i].value));
    scriptPubKeys.push(varintBytes(claims[i].scriptPubKey.length), claims[i].scriptPubKey);
    sequences.push(u32le(Number(tx.inputs[i].sequence)));
  }
  for (const output of tx.outputs) {
    const value = satsOf(output?.value), script = hexBytes(output?.scriptPubKey);
    if (value === null || !script) return null;
    outputs.push(u64le(value), varintBytes(script.length), script);
  }
  const message = concatBytes([
    Uint8Array.of(sighashType),
    i32le(Number(tx.version)),
    u32le(Number(tx.locktime)),
    hodlSha256(concatBytes(prevouts)),
    hodlSha256(concatBytes(amounts)),
    hodlSha256(concatBytes(scriptPubKeys)),
    hodlSha256(concatBytes(sequences)),
    hodlSha256(concatBytes(outputs)),
    Uint8Array.of(ext ? 2 : 0), // spend_type: ext_flag << 1, no annex
    u32le(index),
  ]);
  const extension = ext ? concatBytes([ext.leafHash, Uint8Array.of(0), u32le(0xffffffff)]) : new Uint8Array();
  return taggedHash("TapSighash", Uint8Array.of(0), message, extension);
};

// The declared tapscript leaf whose hash is the signature's leaf-hash
// keydata, or null. The BIP-342 message commits to the leaf hash and the
// position of the last executed OP_CODESEPARATOR; only a declared leaf
// pins that position (the caller refuses separators), so an undeclared or
// mismatched leaf is never verified here.
const tapLeafFor = (doc, index, leafHash) => {
  for (const pair of mapPairs(doc, index)) {
    if (!pair || pair.name !== "PSBT_IN_TAP_LEAF_SCRIPT" || pair.decodeError || !pair.decoded) continue;
    const script = hexBytes(pair.decoded.script), version = hexBytes(pair.decoded.leafVersion);
    if (!script || !version || version.length !== 1) continue;
    if (eqBytes(taggedHash("TapLeaf", version, varintBytes(script.length), script), leafHash)) return script;
  }
  return null;
};

// Verification ran and failed is false. A verifier that cannot parse its
// inputs returns null — unverified, which the engine treats as critical —
// never true: a facade that is not ready cannot verify at all, and a throw
// is not evidence that the signature is invalid.
const verifyEcdsa = (der, digest, pubkey) => {
  try {
    return hodlSecp256k1.verify(der, digest, pubkey, { prehash: false, format: "der", lowS: false }) === true;
  } catch {
    return null;
  }
};

// BIP-340 verification runs only through the libsecp256k1 WASM facade
// (src/js/secp256k1.js). The page never does curve math in JavaScript.
// A facade that is not ready cannot verify: the entry is unverified
// (null), never valid. A verifier that parses its inputs and rejects the
// signature returns false, as consensus would.
const schnorrVerify = (signature, digest, xonly) => {
  try {
    return hodlSecp256k1.schnorr.verify(signature, digest, xonly) === true;
  } catch {
    return null;
  }
};

const verifyPartialSig = (ctx, index, pair) => {
  const value = hexBytes(pair.value);
  if (!value || value.length < 9) return null; // malformed; the engine names it
  const sighash = value[value.length - 1];
  if (sighash !== 1) return null; // only SIGHASH_ALL is reconstructed; weak types are the engine's finding
  const claim = ctx.claims[index];
  if (!claim) return null;
  const resolved = ecdsaScriptCode(ctx.afterDoc, index, claim);
  if (!resolved || hasCodeSeparator(resolved.scriptCode)) return null;
  if (!ctx.takeBudget()) return null;
  const digest = resolved.kind === "bip143"
    ? bip143AllDigest(ctx.rawTx, index, resolved.scriptCode, resolved.amount)
    : legacyAllDigest(ctx.tx, index, resolved.scriptCode, value);
  if (!digest) return null;
  const pubkey = hexBytes(pair.decoded?.pubkey ?? lower(pair.key).slice(2));
  if (!pubkey) return null;
  return verifyEcdsa(value.slice(0, -1), digest, pubkey);
};

const tapSigBytes = (pair) => {
  const value = hexBytes(pair.value);
  if (!value || (value.length !== 64 && value.length !== 65)) return null;
  const sighash = value.length === 65 ? value[64] : 0;
  if (value.length === 65 && !TAPROOT_SIGHASH_BYTES.has(sighash)) return null; // malformed; the engine names it
  return { signature: value.slice(0, 64), sighash };
};

const verifyTapKeySig = (ctx, index, pair) => {
  const parsed = tapSigBytes(pair);
  if (!parsed) return null;
  if (parsed.sighash !== 0 && parsed.sighash !== 1) return null; // weak types are the engine's finding
  // The spent output is the SENT document's claim, the same source the
  // engine uses for Taproot-ness. A missing claim is unverified; a claim
  // that is not P2TR makes a Taproot signature invalid, never unverified.
  const claim = ctx.beforeClaims[index];
  if (!claim) return null;
  if (!isP2tr(claim.scriptPubKey)) return false;
  if (!ctx.takeBudget()) return null;
  const digest = bip341Digest(ctx.tx, ctx.beforeClaims, index, parsed.sighash, null);
  if (!digest) return null;
  return schnorrVerify(parsed.signature, digest, claim.scriptPubKey.slice(2));
};

const verifyTapScriptSig = (ctx, index, pair) => {
  const parsed = tapSigBytes(pair);
  if (!parsed) return null;
  if (parsed.sighash !== 0 && parsed.sighash !== 1) return null;
  const claim = ctx.beforeClaims[index];
  if (!claim) return null;
  if (!isP2tr(claim.scriptPubKey)) return false;
  const xonly = hexBytes(pair.decoded?.xonly ?? lower(pair.key).slice(2, 66));
  const leafHash = hexBytes(pair.decoded?.leafHash ?? lower(pair.key).slice(66, 130));
  if (!xonly || xonly.length !== 32 || !leafHash || leafHash.length !== 32) return null;
  const leaf = tapLeafFor(ctx.afterDoc, index, leafHash);
  if (!leaf || hasCodeSeparator(leaf)) return null;
  if (!ctx.takeBudget()) return null;
  const digest = bip341Digest(ctx.tx, ctx.beforeClaims, index, parsed.sighash, { leafHash });
  if (!digest) return null;
  return schnorrVerify(parsed.signature, digest, xonly);
};

// The pubkey the engine's Phase F reports: the partial signature's keydata,
// the script-path signature's x-only key, and null for a key-path signature
// (the engine's own pubkeyForEvent does the same).
const entryPubkey = (pair) => {
  if (pair.name === "PSBT_IN_TAP_KEY_SIG") return null;
  if (pair.name === "PSBT_IN_TAP_SCRIPT_SIG") return lower(pair.decoded?.xonly ?? lower(pair.key).slice(2, 66));
  return lower(pair.decoded?.pubkey ?? lower(pair.key).slice(2));
};

// The signatures the returned PSBT adds, each verified against the returned
// document's own transaction and UTXO claims (Taproot-ness and the BIP-341
// prevouts come from the sent document, as in the engine). "Added" is a key
// the same input map did not carry before — the engine's diff keys on the
// same pair identity, and on a reordered transaction (already a critical
// finding) an entry that matches no engine event is simply never read, so
// the per-index comparison can never turn a fail into a pass.
export function psbtSignerAuditVerification(beforeDoc, afterDoc) {
  const signatures = [];
  let complete = true;
  const tx = afterDoc?.tx;
  const rawTx = serializeDocTx(tx);
  const inputCount = Array.isArray(tx?.inputs) ? tx.inputs.length : 0;
  const claims = [], beforeClaims = [];
  for (let index = 0; index < inputCount; index++) {
    claims.push(inputClaim(afterDoc, index));
    beforeClaims.push(inputClaim(beforeDoc, index));
  }
  let budgetLeft = SIGNER_AUDIT_MAX_SIGNATURE_CHECKS;
  const ctx = { afterDoc, tx, rawTx, claims, beforeClaims, budgetExhausted: false };
  ctx.takeBudget = () => {
    if (budgetLeft > 0) {
      budgetLeft -= 1;
      return true;
    }
    ctx.budgetExhausted = true;
    return false;
  };
  for (let index = 0; index < inputCount; index++) {
    const beforeKeys = new Set(mapPairs(beforeDoc, index).map((pair) => lower(pair?.key)));
    for (const pair of mapPairs(afterDoc, index)) {
      if (!pair || !SIG_NAMES.has(pair.name) || beforeKeys.has(lower(pair.key))) continue;
      const valid = !rawTx ? null
        : pair.name === "PSBT_IN_PARTIAL_SIG" ? verifyPartialSig(ctx, index, pair)
        : pair.name === "PSBT_IN_TAP_KEY_SIG" ? verifyTapKeySig(ctx, index, pair)
        : verifyTapScriptSig(ctx, index, pair);
      if (ctx.budgetExhausted) complete = false;
      signatures.push({ index, name: pair.name, key: lower(pair.key), pubkey: entryPubkey(pair), valid });
    }
  }
  return { complete, signatures };
}
