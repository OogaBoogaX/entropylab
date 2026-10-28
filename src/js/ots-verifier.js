// OpenTimestamps verifier — issue #315, phase 2.
//
// Walks every DAG path of a parsed .ots proof, classifies each leaf, and
// applies the result-precedence rules from the issue (#315) to produce an
// overall verdict.
//
// All hash primitives are existing, reviewed primitives called as black
// boxes — none are implemented in this file:
//   - sha256          : src/js/hashes.js (WASM `el_sha256`)
//   - ripemd160       : src/js/hashes.js (WASM `el_ripemd160`)
//
// SHA-1 is NOT supported: a sha1 op on a path marks that path unsupported-op
// and its siblings still evaluate. keccak256 / reverse / hexlify are likewise
// unsupported. Their paths are marked unsupported-op, never silently skipped,
// and never poison sibling branches per the issue's rule.

import { parseDetachedTimestamp, OtsParseError, OtsBudgetError, OTS_LIMITS } from "./ots-parser.js";
import { sha256, ripemd160 } from "./hashes.js";

// Hash function dispatch table for v1-supported crypt ops.
const SUPPORTED_HASH_OPS = {
  0x08: { name: "sha256", hash: sha256 },
  0x03: { name: "ripemd160", hash: ripemd160 },
};

// Bitcoin block header layout (per issue #315 "Bitcoin header layout").
const HEADER_LENGTH = 80;
const HEADER_MERKLE_ROOT_OFFSET = 36;
const HEADER_MERKLE_ROOT_LENGTH = 32;
const HEADER_TIME_OFFSET = 68;

// Reference op length limits (python-opentimestamps op.py:
// Op.MAX_RESULT_LENGTH = Op.MAX_MSG_LENGTH = 4096).
const MAX_RESULT_LENGTH = 4096;

const bytesToHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

const bytesEqual = (a, b) => {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
};

// nTime of a Bitcoin block header: uint32 little-endian at byte 68.
const readUint32LE = (bytes, offset) =>
  (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;

// Apply a single op to the running digest along a path. Returns a structured
// sentinel (never throws) so the walker can record the path detail and
// continue with siblings.
function applyOp(op, msg, ctx) {
  if (msg.length > MAX_RESULT_LENGTH) {
    return { kind: "too-long", length: msg.length, limit: MAX_RESULT_LENGTH };
  }

  if (op.tag === 0x08 || op.tag === 0x03) {
    ctx.hashedBytes += msg.length;
    if (ctx.hashedBytes > OTS_LIMITS.MAX_HASHED_BYTES) return { kind: "budget" };
    return { kind: "ok", bytes: SUPPORTED_HASH_OPS[op.tag].hash(msg) };
  }

  if (op.tag === 0xf0 || op.tag === 0xf1) {
    const out = new Uint8Array(msg.length + op.arg.length);
    if (op.tag === 0xf0) {
      out.set(msg, 0);
      out.set(op.arg, msg.length);
    } else {
      out.set(op.arg, 0);
      out.set(msg, op.arg.length);
    }
    if (out.length > MAX_RESULT_LENGTH) {
      return { kind: "too-long", length: out.length, limit: MAX_RESULT_LENGTH };
    }
    return { kind: "ok", bytes: out };
  }

  // sha1 (0x02), keccak256 (0x67), reverse (0xf2), hexlify (0xf3):
  // never silently skipped, never poison siblings.
  return { kind: "unsupported", name: op.name };
}

// Walk every leaf of the timestamp DAG. At each leaf, record the attestation
// and the running digest. At each op failure, record the path detail and stop
// descending that branch (siblings continue). `opNames` is one shared array,
// pushed/popped per step and copied only when a leaf record is created, so a
// deep path never allocates a fresh array per step.
function walkPaths(node, msg, opNames, ctx) {
  if (ctx.budgetExceeded) return;
  for (const att of node.attestations) {
    ctx.leaves.push({ attestation: att, msg, opNames: opNames.slice() });
  }
  for (const { op, child } of node.ops) {
    if (ctx.budgetExceeded) return;
    const step = applyOp(op, msg, ctx);
    if (step.kind === "budget") {
      ctx.budgetExceeded = true;
      return;
    }
    opNames.push(op.name);
    if (step.kind === "too-long") {
      ctx.opTooLong = true;
      ctx.leaves.push({ tooLong: true, opNames: opNames.slice(), length: step.length, limit: step.limit });
    } else if (step.kind === "unsupported") {
      ctx.leaves.push({ unsupportedOp: true, opNames: opNames.slice(), opName: step.name });
    } else {
      walkPaths(child, step.bytes, opNames, ctx);
    }
    opNames.pop();
  }
}

// The original-file check uses exactly the proof's declared file hash op and
// never substitutes another hash. A sha1 / keccak256 file hash op cannot be
// checked here, so it reports unsupported-hash and leaves the verdict alone.
function evaluateOriginal(originalFileBytes, fileHashOp, fileDigest) {
  if (originalFileBytes === null) return { status: "not-supplied" };
  if (originalFileBytes.length > OTS_LIMITS.MAX_ORIGINAL_BYTES) return { status: "too-large" };
  let digest;
  if (fileHashOp === "sha256") digest = sha256(originalFileBytes);
  else if (fileHashOp === "ripemd160") digest = ripemd160(originalFileBytes);
  else return { status: "unsupported-hash" };
  return bytesEqual(digest, fileDigest) ? { status: "matches" } : { status: "mismatch" };
}

// When the proof itself did not parse there is no declared file hash op, so
// the original file cannot be checked against anything.
function unparsedOriginal(originalFileBytes) {
  if (originalFileBytes === null) return { status: "not-supplied" };
  if (originalFileBytes.length > OTS_LIMITS.MAX_ORIGINAL_BYTES) return { status: "too-large" };
  return { status: "unsupported-hash" };
}

/**
 * Verify an OpenTimestamps proof against the user-supplied Bitcoin header.
 * Applies the result-precedence rules from issue #315.
 *
 * @param {object} args
 * @param {Uint8Array} args.proofBytes                Raw .ots file contents.
 * @param {Uint8Array|null} [args.header]             80-byte Bitcoin block header (user-supplied; untrusted).
 * @param {Uint8Array|null} [args.expectedDigest]     Expected initial digest (e.g. derived BIP-322/PACT commitment).
 * @param {Uint8Array|null} [args.originalFileBytes]  The file the proof is supposed to commit to.
 * @returns {Promise<{
 *   result: "MATCHES_SUPPLIED_HEADER"|"INVALID"|"PENDING"|"UNSUPPORTED"|"HEADER_REQUIRED"|"INCOMPLETE",
 *   reason: null|string,
 *   fileHashOp: string|null,
 *   fileDigest: Uint8Array|null,
 *   original: { status: "not-supplied"|"matches"|"mismatch"|"unsupported-hash"|"too-large" },
 *   claimedHeights: number[],
 *   headerTime: number|null,
 *   paths: Array<{
 *     outcome: "matches"|"mismatch"|"pending"|"no-header"|"unsupported-op"|"op-too-long"|"unsupported-attestation",
 *     opNames: string[],
 *     attestation?: object,
 *     finalDigest?: Uint8Array,
 *     detail?: string,
 *     length?: number,
 *     limit?: number,
 *   }>,
 *   summary: { matches: number, mismatch: number, pending: number, other: number },
 * }>}
 */
export async function verifyOts({ proofBytes, header = null, expectedDigest = null, originalFileBytes = null } = {}) {
  if (!(proofBytes instanceof Uint8Array)) {
    throw new TypeError("proofBytes must be a Uint8Array");
  }
  if (header !== null && !(header instanceof Uint8Array)) {
    throw new TypeError("header must be a Uint8Array or null");
  }
  if (expectedDigest !== null && !(expectedDigest instanceof Uint8Array)) {
    throw new TypeError("expectedDigest must be a Uint8Array or null");
  }
  if (originalFileBytes !== null && !(originalFileBytes instanceof Uint8Array)) {
    throw new TypeError("originalFileBytes must be a Uint8Array or null");
  }
  if (header !== null && header.length !== HEADER_LENGTH) {
    throw new TypeError(`header must be exactly ${HEADER_LENGTH} bytes, got ${header.length}`);
  }

  const headerTime = header === null ? null : readUint32LE(header, HEADER_TIME_OFFSET);

  let parsed;
  try {
    parsed = parseDetachedTimestamp(proofBytes);
  } catch (err) {
    if (err instanceof OtsBudgetError) {
      return {
        result: "INCOMPLETE",
        reason: err.code,
        fileHashOp: null,
        fileDigest: null,
        original: unparsedOriginal(originalFileBytes),
        claimedHeights: [],
        headerTime,
        paths: [],
        summary: { matches: 0, mismatch: 0, pending: 0, other: 0 },
      };
    }
    if (err instanceof OtsParseError) {
      return {
        result: "INVALID",
        reason: `parse:${err.code}`,
        fileHashOp: null,
        fileDigest: null,
        original: unparsedOriginal(originalFileBytes),
        claimedHeights: [],
        headerTime,
        paths: [],
        summary: { matches: 0, mismatch: 0, pending: 0, other: 0 },
      };
    }
    throw err;
  }

  const fileHashOp = parsed.fileHashOp.name;
  const fileDigest = parsed.fileDigest;
  const original = evaluateOriginal(originalFileBytes, fileHashOp, fileDigest);

  const headerMerkleRoot =
    header === null
      ? null
      : header.slice(HEADER_MERKLE_ROOT_OFFSET, HEADER_MERKLE_ROOT_OFFSET + HEADER_MERKLE_ROOT_LENGTH);

  const ctx = { leaves: [], hashedBytes: 0, budgetExceeded: false, opTooLong: false };
  walkPaths(parsed.timestamp, fileDigest, [], ctx);

  const paths = [];
  const heights = new Set();
  let bitcoinLeaves = 0;
  let bitcoinMatches = 0;
  let pendingLeaves = 0;

  for (const leaf of ctx.leaves) {
    if (leaf.tooLong) {
      paths.push({ outcome: "op-too-long", opNames: leaf.opNames, length: leaf.length, limit: leaf.limit });
      continue;
    }
    if (leaf.unsupportedOp) {
      paths.push({ outcome: "unsupported-op", opNames: leaf.opNames, detail: leaf.opName });
      continue;
    }
    const att = leaf.attestation;
    if (att.type === "bitcoin") {
      bitcoinLeaves += 1;
      heights.add(att.height);
      if (headerMerkleRoot === null) {
        paths.push({
          outcome: "no-header",
          opNames: leaf.opNames,
          attestation: att,
          finalDigest: leaf.msg,
          detail: "bitcoin attestation reached but no header was supplied",
        });
      } else if (bytesEqual(leaf.msg, headerMerkleRoot)) {
        bitcoinMatches += 1;
        paths.push({ outcome: "matches", opNames: leaf.opNames, attestation: att, finalDigest: leaf.msg });
      } else {
        paths.push({
          outcome: "mismatch",
          opNames: leaf.opNames,
          attestation: att,
          finalDigest: leaf.msg,
          detail: `attested digest ${bytesToHex(leaf.msg)} != merkle_root ${bytesToHex(headerMerkleRoot)}`,
        });
      }
    } else if (att.type === "pending") {
      pendingLeaves += 1;
      paths.push({ outcome: "pending", opNames: leaf.opNames, attestation: att, finalDigest: leaf.msg });
    } else {
      paths.push({
        outcome: "unsupported-attestation",
        opNames: leaf.opNames,
        attestation: att,
        finalDigest: leaf.msg,
        detail: `${att.type} attestation (URI ${att.uriHex}) is outside v1 scope`,
      });
    }
  }

  const summary = {
    matches: paths.filter((p) => p.outcome === "matches").length,
    mismatch: paths.filter((p) => p.outcome === "mismatch").length,
    pending: paths.filter((p) => p.outcome === "pending").length,
    other: paths.filter((p) => !["matches", "mismatch", "pending"].includes(p.outcome)).length,
  };

  const claimedHeights = [...heights].sort((a, b) => a - b);

  // Verdict, first rule that applies (issue #315 / #460).
  let result;
  let reason = null;
  if (expectedDigest !== null && !bytesEqual(fileDigest, expectedDigest)) {
    result = "INVALID";
    reason = "expected-digest";
  } else if (original.status === "mismatch") {
    result = "INVALID";
    reason = "original-file";
  } else if (ctx.budgetExceeded) {
    result = "INCOMPLETE";
    reason = "hash-budget";
  } else if (ctx.opTooLong) {
    result = "INVALID";
    reason = "op-too-long";
  } else if (bitcoinMatches > 0) {
    result = "MATCHES_SUPPLIED_HEADER";
  } else if (header !== null && bitcoinLeaves > 0) {
    result = "INVALID";
    reason = "header-mismatch";
  } else if (header === null && bitcoinLeaves > 0) {
    result = "HEADER_REQUIRED";
  } else if (pendingLeaves > 0) {
    result = "PENDING";
  } else {
    result = "UNSUPPORTED";
  }

  return { result, reason, fileHashOp, fileDigest, original, claimedHeights, headerTime, paths, summary };
}
