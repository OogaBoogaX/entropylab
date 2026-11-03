// MuSig2 (BIP-327) key aggregation and Taproot (BIP-341) output-key
// verification for EntropyLab, from public data only.
//
// SECURITY CONTRACT: this module accepts MuSig2 participant public keys,
// aggregate keys, tweaks and the BIP-373 PSBT fields, and reports "verified"
// only when the listed participants really aggregate to the stated key under
// BIP-327 (cross-checked against an independent implementation) and, where a
// Taproot scriptPubKey is present, when that key really commits to it under
// BIP-341; everything else is reported as mismatch, malformed, not-checked or
// missing. Every participant field gets its own record, so a second or
// repeated entry is never skipped. It does not check nonces, partial
// signatures, BIP-328 derivation, script leaves or script trees (an output
// committing to a tree it cannot hash is "not-checked", never "mismatch"), or
// whether the participants are the people the user expects, and a "verified"
// key aggregation says nothing about who holds the keys. Two known divergences,
// both fail-closed: an intermediate KeyAgg sum at infinity (the facade cannot
// hold the point) errors where BIP-327 fails only on the final sum, and KeyAgg
// skips a zero coefficient (it contributes nothing) where BIP-327 would
// multiply by it; both give the same final Q and need a hash collision to
// reach. The commitmentReason codes are "witness-utxo", "internal-key",
// "merkle-root", "duplicate-field", "script-conflict", "not-taproot",
// "script-tree" and "indirect", alongside the key-aggregation reasons.
//
// Curve arithmetic goes through the libsecp256k1 WASM facade
// (./secp256k1.js), hashes through ./bip352.js's taggedHash, and the
// independent cross-check through @scure/btc-signer's MuSig2 module.
import { keyAggregate } from "@scure/btc-signer/musig2.js";
import { taggedHash } from "./bip352.js";
import { secp256k1 } from "./secp256k1.js";

const ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const Point = secp256k1.Point;
const HEX = /^(?:[0-9a-fA-F]{2})*$/;

const hexToBytes = (hex) => {
  if (typeof hex !== "string" || !HEX.test(hex)) throw new Error("Invalid hexadecimal input.");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
};

const bytesToHex = (bytes) => [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const bytesToBig = (bytes) => {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
};

const equalBytes = (a, b) => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
};

const compareBytes = (a, b) => {
  for (let i = 0; i < a.length && i < b.length; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
};

const negate = (point) => {
  const bytes = point.toBytes(true);
  bytes[0] = bytes[0] === 0x02 ? 0x03 : 0x02;
  return Point.fromBytes(bytes);
};

const liftX = (xonly32) => {
  const compressed = new Uint8Array(33);
  compressed[0] = 0x02;
  compressed.set(xonly32, 1);
  try {
    return Point.fromBytes(compressed);
  } catch {
    throw new Error("Taproot internal key is not a valid x-only public key.");
  }
};

// Errors carry a field name and an index only; never the offending bytes.
const contributionError = (signer, contrib) => {
  const error = new Error(`Invalid MuSig2 contribution from signer ${signer}: ${contrib}.`);
  error.type = "invalid_contribution";
  error.signer = signer;
  error.contrib = contrib;
  return error;
};

const parsePubkey = (pubkey, signer) => {
  if (!(pubkey instanceof Uint8Array) || pubkey.length !== 33 || (pubkey[0] !== 0x02 && pubkey[0] !== 0x03)) {
    throw contributionError(signer, "pubkey");
  }
  try {
    return Point.fromBytes(pubkey);
  } catch {
    throw contributionError(signer, "pubkey");
  }
};

// BIP-327 GetSecondKey: the first key different from pk1, else 33 zero bytes.
const secondKey = (pubkeys) => {
  for (let i = 1; i < pubkeys.length; i++) if (!equalBytes(pubkeys[i], pubkeys[0])) return pubkeys[i];
  return new Uint8Array(33);
};

// BIP-327 KeySort: lexicographic order, on copies (the input is not reordered).
export function keySort(pubkeys) {
  if (!Array.isArray(pubkeys)) throw new Error("MuSig2 key sorting needs an array of public keys.");
  const copies = pubkeys.map((pubkey) => {
    if (!(pubkey instanceof Uint8Array) || pubkey.length !== 33) throw new Error("A MuSig2 public key must be 33 bytes.");
    return pubkey.slice();
  });
  return copies.sort(compareBytes);
}

// BIP-327 KeyAgg.
export function keyAgg(pubkeys) {
  if (!Array.isArray(pubkeys) || !pubkeys.length) throw new Error("MuSig2 key aggregation needs at least one public key.");
  const points = pubkeys.map((pubkey, signer) => parsePubkey(pubkey, signer));
  const list = taggedHash("KeyAgg list", ...pubkeys.map((pubkey) => pubkey.slice()));
  const second = secondKey(pubkeys);
  let Q = null;
  for (let i = 0; i < pubkeys.length; i++) {
    const coefficient = equalBytes(pubkeys[i], second)
      ? 1n
      : bytesToBig(taggedHash("KeyAgg coefficient", list, pubkeys[i].slice())) % ORDER;
    // A zero coefficient contributes nothing; multiplying by it would throw.
    if (coefficient === 0n) continue;
    const term = coefficient === 1n ? points[i] : points[i].multiply(coefficient);
    if (!Q) {
      Q = term;
    } else {
      try {
        Q = Q.add(term);
      } catch {
        // BIP-327 KeyAgg: an infinite aggregate is an error, not a key.
        throw new Error("MuSig2 key aggregation produced the point at infinity.");
      }
    }
  }
  if (!Q) throw new Error("MuSig2 key aggregation produced the point at infinity.");
  return { Q, gacc: 1n, tacc: 0n };
}

// BIP-327 ApplyTweak.
export function applyTweak(ctx, tweak32, isXonly) {
  if (!ctx || !(ctx.Q instanceof Point)) throw new Error("A MuSig2 key aggregation context is required.");
  if (!(tweak32 instanceof Uint8Array) || tweak32.length !== 32) throw new Error("A MuSig2 tweak must be 32 bytes.");
  const t = bytesToBig(tweak32);
  if (t >= ORDER) throw new Error("MuSig2 tweak is not below the secp256k1 group order.");
  const g = isXonly && ctx.Q.toBytes(true)[0] === 0x03 ? ORDER - 1n : 1n;
  let Q = g === 1n ? ctx.Q : negate(ctx.Q);
  if (t !== 0n) {
    try {
      Q = Q.add(Point.BASE.multiply(t));
    } catch {
      // BIP-327 ApplyTweak: "fail if is_infinite(Q')". The facade throws on
      // the point at infinity; name the tweak so the caller can tell it apart
      // from an invalid key contribution.
      throw new Error("MuSig2 tweak gives the point at infinity.");
    }
  }
  return { Q, gacc: (g * ctx.gacc) % ORDER, tacc: (t + g * ctx.tacc) % ORDER };
}

export const xonly = (ctx) => ctx.Q.toBytes(true).slice(1);
export const plain = (ctx) => ctx.Q.toBytes(true);

// BIP-341 TapTweak: lift_x(P), add int(taggedHash("TapTweak", P || root))·G.
export function taprootOutputKey(internalXonly32, merkleRoot32 = null) {
  if (!(internalXonly32 instanceof Uint8Array) || internalXonly32.length !== 32) throw new Error("A Taproot internal key must be 32 bytes.");
  if (merkleRoot32 !== null && (!(merkleRoot32 instanceof Uint8Array) || merkleRoot32.length !== 32)) throw new Error("A Taproot merkle root must be 32 bytes.");
  const P = liftX(internalXonly32);
  const tweak = merkleRoot32
    ? taggedHash("TapTweak", internalXonly32.slice(), merkleRoot32.slice())
    : taggedHash("TapTweak", internalXonly32.slice());
  const t = bytesToBig(tweak);
  if (t >= ORDER) throw new Error("Taproot tweak is not below the secp256k1 group order.");
  const Q = t === 0n ? P : P.add(Point.BASE.multiply(t));
  return Q.toBytes(true).slice(1);
}

// The same aggregation through an independent implementation; the 33-byte
// result is returned only when both agree on the whole key, its parity
// included (an x-only comparison would let a sign error through).
export function crossCheckKeyAgg(pubkeys, tweaks = [], isXonlyFlags = []) {
  let ctx = keyAgg(pubkeys);
  for (let i = 0; i < tweaks.length; i++) ctx = applyTweak(ctx, tweaks[i], !!isXonlyFlags[i]);
  const mine = plain(ctx);
  const theirs = keyAggregate(
    pubkeys.map((pubkey) => pubkey.slice()),
    tweaks.map((tweak) => tweak.slice()),
    isXonlyFlags.map((flag) => !!flag),
  ).aggPublicKey.toBytes(true);
  if (!(theirs instanceof Uint8Array) || theirs.length !== 33 || !equalBytes(mine, theirs)) throw new Error("MuSig2 implementations disagree");
  return mine;
}

// ── BIP-373 PSBT fields ────────────────────────────────────────────────────
const PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS = "1a";
const PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS = "08";
const PSBT_IN_WITNESS_UTXO = "01";
const PSBT_IN_TAP_INTERNAL_KEY = "17";
const PSBT_IN_TAP_MERKLE_ROOT = "18";
const PSBT_OUT_TAP_INTERNAL_KEY = "05";
const PSBT_OUT_SCRIPT = "04";
const PSBT_IN_TAP_LEAF_SCRIPT = "15";
const PSBT_OUT_TAP_TREE = "06";

const pairValue = (item) => {
  if (typeof item.value === "string") return item.value;
  if (item.value && typeof item.value === "object" && typeof item.value.hex === "string") return item.value.hex;
  return null;
};

// The key-value pairs of one PSBT map, in whichever shape the inspect
// document carries them (a list of { key, value } records, or a map keyed by
// key hex). Anything else yields no pairs rather than a guess.
const pairKey = (item) => {
  if (typeof item.key === "string") return item.key;
  if (item.key && typeof item.key === "object" && typeof item.key.hex === "string") return item.key.hex;
  return null;
};

const isPairRecord = (item) => item && typeof item === "object" && pairKey(item) !== null;

const mapPairs = (map, depth = 0) => {
  if (!map || typeof map !== "object" || depth > 3) return [];
  const pairs = [];
  const collect = (item) => {
    pairs.push({ key: pairKey(item), value: pairValue(item), decoded: item.decoded ?? null });
  };
  if (Array.isArray(map)) {
    for (const item of map) {
      if (isPairRecord(item)) collect(item);
      else pairs.push(...mapPairs(item, depth + 1));
    }
    return pairs;
  }
  for (const value of Object.values(map)) {
    if (Array.isArray(value)) {
      for (const item of value) {
        if (isPairRecord(item)) collect(item);
        else pairs.push(...mapPairs(item, depth + 1));
      }
    } else if (value && typeof value === "object") {
      pairs.push(...mapPairs(value, depth + 1));
    }
  }
  if (!pairs.length) {
    for (const [name, value] of Object.entries(map)) {
      if (/^[0-9a-f]+$/i.test(name) && typeof value === "string" && HEX.test(value)) pairs.push({ key: name, value });
    }
  }
  return pairs;
};

const findPairs = (pairs, type, keyHexLength) => pairs.filter((pair) => {
  const key = pair.key.toLowerCase();
  return key.startsWith(type) && (keyHexLength === undefined || key.length === keyHexLength);
});

const findPair = (pairs, type, keyHexLength) => findPairs(pairs, type, keyHexLength)[0] ?? null;

// A single-instance 32-byte field: `present` tells a malformed value apart
// from an absent one, so a present-but-unparseable field is never read as
// absent.
const optionalKey = (pairs, type) => {
  const pair = findPair(pairs, type, 2);
  if (!pair) return { present: false, value: null };
  try {
    const bytes = hexToBytes(pair.value);
    return { present: true, value: bytes.length === 32 ? bytes : null };
  } catch {
    return { present: true, value: null };
  }
};

// A serialized TxOut: 8-byte little-endian value, compact-size script length,
// script. Strict: a length that does not match the bytes is refused.
const txOutScript = (hex) => {
  const bytes = hexToBytes(hex);
  if (bytes.length < 9) throw new Error("A witness UTXO is too short.");
  let offset = 8;
  const first = bytes[offset];
  let length;
  if (first < 0xfd) {
    length = first;
    offset += 1;
  } else if (first === 0xfd) {
    if (offset + 3 > bytes.length) throw new Error("A witness UTXO script length is truncated.");
    length = bytes[offset + 1] | (bytes[offset + 2] << 8);
    offset += 3;
  } else if (first === 0xfe) {
    if (offset + 5 > bytes.length) throw new Error("A witness UTXO script length is truncated.");
    length = (bytes[offset + 1] | (bytes[offset + 2] << 8) | (bytes[offset + 3] << 16) | (bytes[offset + 4] << 24)) >>> 0;
    offset += 5;
  } else {
    throw new Error("A witness UTXO script length is too large.");
  }
  if (offset + length !== bytes.length) throw new Error("A witness UTXO script length does not match its bytes.");
  return bytes.slice(offset, offset + length);
};

const txOutputs = (doc) => {
  const tx = doc && doc.tx;
  if (!tx || typeof tx !== "object") return [];
  if (Array.isArray(tx.outputs)) return tx.outputs;
  // rust-bitcoin's Transaction serializes its outputs as `output` (singular).
  if (Array.isArray(tx.output)) return tx.output;
  if (Array.isArray(tx.vout)) return tx.vout;
  return [];
};

const scriptHexOf = (output) => {
  if (!output || typeof output !== "object") return null;
  for (const name of ["scriptPubKey", "script", "script_pubkey"]) {
    const value = output[name];
    if (typeof value === "string") return value;
    if (value && typeof value === "object" && typeof value.hex === "string") return value.hex;
  }
  return null;
};

// treeUnknown: the output commits to a script tree this stage cannot hash (an
// output's TAP_TREE, or an input's leaf scripts with no merkle-root field), so
// an internal-key match is "not-checked" rather than a false "mismatch".
const evidenceRecord = (where, aggregateHex, participantsHex, scriptPubKey, internalKey, merkleRoot, treeUnknown = false, commitmentIssue = null) => {
  const record = {
    where,
    aggregate: String(aggregateHex).toLowerCase(),
    participants: String(participantsHex).toLowerCase(),
    sorted: false,
    keyAgg: "malformed",
    commitment: "missing",
  };
  let reason = null;
  let aggregate = null;
  try {
    aggregate = hexToBytes(aggregateHex);
  } catch {
    reason = "aggregate-hex";
  }
  if (aggregate && aggregate.length !== 33) {
    reason = "aggregate-length";
    aggregate = null;
  }
  let participants = null;
  try {
    participants = hexToBytes(participantsHex);
  } catch {
    reason = reason ?? "participants-hex";
  }
  let keys = null;
  if (participants) {
    if (!participants.length) reason = reason ?? "participants-empty";
    else if (participants.length % 33) reason = reason ?? "participants-length";
    else {
      keys = [];
      for (let i = 0; i < participants.length; i += 33) keys.push(participants.slice(i, i + 33));
    }
  }
  if (keys) {
    const ordered = keySort(keys);
    record.sorted = keys.every((key, i) => equalBytes(key, ordered[i]));
    if (aggregate) {
      try {
        const computed = crossCheckKeyAgg(keys);
        if (equalBytes(computed, aggregate)) {
          record.keyAgg = "verified";
          reason = null;
        } else {
          record.keyAgg = "mismatch";
          reason = "aggregate-mismatch";
        }
      } catch (error) {
        record.keyAgg = "malformed";
        reason = error && error.type === "invalid_contribution" ? "participant-pubkey" : "aggregate-failed";
      }
    }
  }
  if (reason) record.reason = reason;

  const taproot = scriptPubKey && scriptPubKey.length === 34 && scriptPubKey[0] === 0x51 && scriptPubKey[1] === 0x20
    ? scriptPubKey
    : null;
  if (commitmentIssue) {
    record.commitment = commitmentIssue.state;
    record.commitmentReason = commitmentIssue.reason;
  } else if (!taproot) {
    record.commitment = "missing";
    if (scriptPubKey) record.commitmentReason = "not-taproot";
  } else if (!aggregate) {
    record.commitment = "not-checked";
  } else {
    const aggregateXonly = aggregate.slice(1);
    const outputKey = taproot.slice(2);
    if (internalKey && equalBytes(internalKey, aggregateXonly) && treeUnknown) {
      record.commitment = "not-checked";
      record.commitmentReason = "script-tree";
    } else if (internalKey && equalBytes(internalKey, aggregateXonly)) {
      let computed = null;
      try {
        computed = taprootOutputKey(internalKey, merkleRoot);
      } catch {
        computed = null;
      }
      record.commitment = computed && equalBytes(computed, outputKey) ? "verified-internal" : "mismatch";
    } else if (equalBytes(aggregateXonly, outputKey)) {
      record.commitment = "verified-output";
    } else {
      record.commitment = "not-checked";
      record.commitmentReason = "indirect";
    }
  }
  return record;
};

// One record per MuSig2 participant field: BIP-373 allows one per aggregate
// key, and a second (or a repeated) entry must never be skipped silently.
// The commitment inputs of one input map, with a malformed singleton field
// reported as such rather than read as absent.
const inputCommitment = (pairs) => {
  const result = { scriptPubKey: null, internalKey: null, merkleRoot: null, treeUnknown: false, commitmentIssue: null };
  // BIP-174 forbids duplicate keys; a repeated singleton field is malformed.
  if ([PSBT_IN_WITNESS_UTXO, PSBT_IN_TAP_INTERNAL_KEY, PSBT_IN_TAP_MERKLE_ROOT]
    .some((type) => findPairs(pairs, type, 2).length > 1)) {
    result.commitmentIssue = { state: "malformed", reason: "duplicate-field" };
    return result;
  }
  const witnessUtxo = findPair(pairs, PSBT_IN_WITNESS_UTXO, 2);
  if (witnessUtxo) {
    if (typeof witnessUtxo.value === "string") {
      try {
        result.scriptPubKey = txOutScript(witnessUtxo.value);
      } catch {
        result.scriptPubKey = null;
      }
    }
    // Some inspect documents carry the decoded TxOut instead of its raw
    // serialization; read the scriptPubKey from it rather than guessing.
    const decoded = witnessUtxo.decoded && witnessUtxo.decoded.scriptPubKey;
    const decodedHex = typeof decoded === "string" ? decoded : decoded && typeof decoded.hex === "string" ? decoded.hex : null;
    if (!result.scriptPubKey && decodedHex !== null) {
      try {
        result.scriptPubKey = hexToBytes(decodedHex);
      } catch {
        result.scriptPubKey = null;
      }
    }
    if (!result.scriptPubKey) result.commitmentIssue = { state: "malformed", reason: "witness-utxo" };
  }
  const internal = optionalKey(pairs, PSBT_IN_TAP_INTERNAL_KEY);
  result.internalKey = internal.value;
  if (internal.present && !internal.value && !result.commitmentIssue) {
    result.commitmentIssue = { state: "malformed", reason: "internal-key" };
  }
  const merkle = optionalKey(pairs, PSBT_IN_TAP_MERKLE_ROOT);
  result.merkleRoot = merkle.value;
  if (merkle.present && !merkle.value && !result.commitmentIssue) {
    result.commitmentIssue = { state: "malformed", reason: "merkle-root" };
  }
  result.treeUnknown = !result.merkleRoot && findPairs(pairs, PSBT_IN_TAP_LEAF_SCRIPT).length > 0;
  return result;
};

const inputEvidence = (index, input) => {
  const pairs = mapPairs(input);
  const fields = findPairs(pairs, PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS);
  if (!fields.length) return [];
  const commitment = inputCommitment(pairs);
  return fields.map((pair) => evidenceRecord(
    { scope: "input", index },
    pair.key.slice(2),
    pair.value,
    commitment.scriptPubKey,
    commitment.internalKey,
    commitment.merkleRoot,
    commitment.treeUnknown,
    commitment.commitmentIssue,
  ));
};

const outputCommitment = (pairs, index, doc) => {
  const result = { scriptPubKey: null, internalKey: null, merkleRoot: null, treeUnknown: false, commitmentIssue: null };
  if ([PSBT_OUT_SCRIPT, PSBT_OUT_TAP_INTERNAL_KEY].some((type) => findPairs(pairs, type, 2).length > 1)) {
    result.commitmentIssue = { state: "malformed", reason: "duplicate-field" };
    return result;
  }
  const txOutput = txOutputs(doc)[index];
  const fromTx = txOutput ? scriptHexOf(txOutput) : null;
  const fromPair = findPair(pairs, PSBT_OUT_SCRIPT, 2);
  // Two present scripts that disagree are a mismatch, not a choice of one.
  if (fromTx !== null && fromPair && typeof fromPair.value === "string"
    && fromTx.toLowerCase() !== fromPair.value.toLowerCase()) {
    result.commitmentIssue = { state: "mismatch", reason: "script-conflict" };
    return result;
  }
  const hex = fromTx ?? (fromPair ? fromPair.value : null);
  if (hex !== null) {
    try {
      result.scriptPubKey = hexToBytes(hex);
    } catch {
      result.scriptPubKey = null;
    }
  }
  const internal = optionalKey(pairs, PSBT_OUT_TAP_INTERNAL_KEY);
  result.internalKey = internal.value;
  if (internal.present && !internal.value && !result.commitmentIssue) {
    result.commitmentIssue = { state: "malformed", reason: "internal-key" };
  }
  // An output's script tree is not hashed at this stage (no merkle root).
  result.treeUnknown = findPairs(pairs, PSBT_OUT_TAP_TREE, 2).length > 0;
  return result;
};

const outputEvidence = (index, output, doc) => {
  const pairs = mapPairs(output);
  const fields = findPairs(pairs, PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS);
  if (!fields.length) return [];
  const commitment = outputCommitment(pairs, index, doc);
  return fields.map((pair) => evidenceRecord(
    { scope: "output", index },
    pair.key.slice(2),
    pair.value,
    commitment.scriptPubKey,
    commitment.internalKey,
    null,
    commitment.treeUnknown,
    commitment.commitmentIssue,
  ));
};

// One record per BIP-373 MuSig2 participant field, on every input and output.
export function musig2PsbtEvidence(doc) {
  if (!doc || typeof doc !== "object") throw new Error("A PSBT inspect document is required.");
  const records = [];
  const inputs = Array.isArray(doc.inputs) ? doc.inputs : [];
  const outputs = Array.isArray(doc.outputs) ? doc.outputs : [];
  for (const [index, input] of inputs.entries()) records.push(...inputEvidence(index, input));
  for (const [index, output] of outputs.entries()) records.push(...outputEvidence(index, output, doc));
  return records;
}
