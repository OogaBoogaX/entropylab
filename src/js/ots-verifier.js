// OpenTimestamps verifier — issue #315, phase 2.
//
// Walks every DAG path of a parsed .ots proof, classifies each as
// MATCHES / MISMATCH / PENDING / UNSUPPORTED-op / UNSUPPORTED-attestation /
// NO-HEADER / MESSAGE-TOO-LONG, and applies the result-precedence rules
// from the issue (#315) to produce an overall verdict.
//
// All hash primitives are existing, reviewed primitives called as black
// boxes — none are implemented in this file:
//   - sha256          : src/js/hashes.js (WASM `el_sha256`)
//   - ripemd160       : src/js/hashes.js (WASM `el_ripemd160`)
//   - sha1            : platform WebCrypto (`crypto.subtle.digest('SHA-1')`,
//                        available in browsers and Node 19+). This brings
//                        SHA-1 into v1 scope without writing fresh crypto.
//
// Crypto operations land on a single, plainly-named dispatch table
// (`SUPPORTED_HASH_OPS`); adding an SHA-1 primitive to hashes.js later
// changes exactly one line in this file. Reusing a well-known platform
// primitive is the same trust model as the repo's existing WASM
// primitives, which call reviewed code under the hood.
//
// Unscalable operations (keccak256 / reverse / hexlify) stay marked
// UNSUPPORTED in v1 — only SHA-1 is added at this step. Their paths are
// marked UNSUPPORTED-op, never silently skipped, and never poison
// sibling branches per the issue's rule.

import { parseDetachedTimestamp } from "./ots-parser.js";
import { sha256, ripemd160 } from "./hashes.js";

// SHA-1 via WebCrypto. Async because `crypto.subtle.digest` returns a
// Promise. Available in browsers (file:// counts as a secure context per
// the W3C SecureContext spec) and Node 19+ via `globalThis.crypto`.
async function sha1(bytes) {
  const buf = await crypto.subtle.digest("SHA-1", bytes);
  return new Uint8Array(buf);
}

// Hash function dispatch table for v1-supported crypt ops.
const SUPPORTED_HASH_OPS = {
  0x08: { name: "sha256", hash: sha256 },
  0x03: { name: "ripemd160", hash: ripemd160 },
  0x02: { name: "sha1", hash: sha1 },
};

// Bitcoin block header layout (per issue #315 "Bitcoin header layout").
const HEADER_LENGTH = 80;
const HEADER_MERKLE_ROOT_OFFSET = 36;
const HEADER_MERKLE_ROOT_LENGTH = 32;

// Reference op length limits (python-opentimestamps op.py:
// Op.MAX_RESULT_LENGTH = Op.MAX_MSG_LENGTH = 4096).
const MAX_RESULT_LENGTH = 4096;

const bytesToHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

const bytesEqual = (a, b) => {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
};

// Apply a single op to the running digest along a path. Returns either
// a Uint8Array (success), or a structured sentinel for an
// unsupproted / too-long branch. The sentinel is kept (not thrown) so the
// walker can record the path detail and continue with siblings.
async function applyOp(op, msg) {
  if (msg.length > MAX_RESULT_LENGTH) {
    return { tooLong: true, length: msg.length, limit: MAX_RESULT_LENGTH };
  }

  if (op.tag === 0x08 || op.tag === 0x03 || op.tag === 0x02) {
    return await SUPPORTED_HASH_OPS[op.tag].hash(msg);
  }

  if (op.tag === 0xf0) {
    const out = new Uint8Array(msg.length + op.arg.length);
    out.set(msg, 0);
    out.set(op.arg, msg.length);
    return out.length > MAX_RESULT_LENGTH ? { tooLong: true, length: out.length, limit: MAX_RESULT_LENGTH } : out;
  }
  if (op.tag === 0xf1) {
    const out = new Uint8Array(op.arg.length + msg.length);
    out.set(op.arg, 0);
    out.set(msg, op.arg.length);
    return out.length > MAX_RESULT_LENGTH ? { tooLong: true, length: out.length, limit: MAX_RESULT_LENGTH } : out;
  }

  // keccak256 (0x67), reverse (0xf2), hexlify (0xf3), unknown tags:
  // never silently skipped, never poison siblings.
  return { unsupported: op.name };
}

// Walk every leaf of the timestamp DAG. At each leaf, record the
// attestation + the running digest. At each op failure, record the path
// detail and stop descending that branch (siblings continue).
async function walkPaths(node, msg, opPath) {
  const out = [];
  for (const att of node.attestations) {
    out.push({ kind: "leaf", attestation: att, msg, opPath });
  }
  for (const { op, child } of node.ops) {
    const step = await applyOp(op, msg);
    if (step instanceof Uint8Array) {
      out.push(...(await walkPaths(child, step, [...opPath, op.name])));
    } else if (step.tooLong) {
      out.push({ kind: "tooLong", opPath: [...opPath, op.name], length: step.length, limit: step.limit });
    } else {
      out.push({ kind: "unsupportedOp", opPath: [...opPath, op.name], opName: step.unsupported });
    }
  }
  return out;
}

function evaluateAttestation(att, msg, headerMerkleRoot) {
  if (att.type === "pending") {
    return { outcome: "pending", finalDigest: msg };
  }
  if (att.type === "bitcoin") {
    if (!headerMerkleRoot) {
      return { outcome: "no-header", detail: "bitcoin attestation reached but no header was supplied" };
    }
    if (msg.length !== headerMerkleRoot.length) {
      return {
        outcome: "mismatch",
        detail: `attested digest is ${msg.length} bytes, header merkle_root is ${headerMerkleRoot.length} bytes`,
      };
    }
    if (bytesEqual(msg, headerMerkleRoot)) {
      return { outcome: "matches", finalDigest: msg };
    }
    return {
      outcome: "mismatch",
      detail: `attested digest ${bytesToHex(msg)} != merkle_root ${bytesToHex(headerMerkleRoot)}`,
    };
  }
  return {
    outcome: "unsupported-attestation",
    detail: `${att.type} attestation (URI ${att.uriHex}) is outside v1 scope`,
  };
}

function extractMerkleRoot(header) {
  if (!(header instanceof Uint8Array)) {
    throw new TypeError("header must be a Uint8Array");
  }
  if (header.length !== HEADER_LENGTH) {
    throw new RangeError(`bitcoin header must be ${HEADER_LENGTH} bytes, got ${header.length}`);
  }
  return header.slice(HEADER_MERKLE_ROOT_OFFSET, HEADER_MERKLE_ROOT_OFFSET + HEADER_MERKLE_ROOT_LENGTH);
}

// Existence scan: collect every attestation in the parsed DAG, ignoring op
// reachability. Issue #315 rule 3 reads "a pending attestation exists" —
// "exists" here means structurally present in the proof, not necessarily
// evaluatable through supported ops. A pending att behind a keccak/reverse/
// hexlify barrier still counts. Used by the precedence check only.
function collectAttestations(node) {
  const out = [];
  for (const att of node.attestations) out.push(att);
  for (const { child } of node.ops) out.push(...collectAttestations(child));
  return out;
}

const existsPending = (atts) => atts.some((a) => a.type === "pending");

/**
 * Verify an OpenTimestamps proof against the user-supplied Bitcoin header.
 * Applies the result-precedence rules from issue #315.
 *
 * @param {object} args
 * @param {Uint8Array} args.proofBytes                Raw .ots file contents.
 * @param {Uint8Array} [args.header]                  80-byte Bitcoin block header (user-supplied; untrusted).
 * @param {Uint8Array} [args.expectedDigest]          Expected initial digest (e.g. derived BIP-322/PACT commitment).
 *                                                   Mismatch is an overall INVALID (issue #315, INVALID description).
 * @returns {Promise<{
 *   result: "MATCHES_SUPPLIED_HEADER"|"INVALID"|"PENDING"|"UNSUPPORTED",
 *   fileHashOp: string,
 *   fileDigest: Uint8Array,
 *   paths: Array<{
 *     outcome: "matches"|"mismatch"|"pending"|"no-header"|"unsupported-op"|"message-too-long"|"unsupported-attestation"|"expected-digest-mismatch",
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
export async function verifyOts({ proofBytes, header, expectedDigest } = {}) {
  if (!(proofBytes instanceof Uint8Array)) {
    throw new TypeError("proofBytes must be a Uint8Array");
  }
  const parsed = parseDetachedTimestamp(proofBytes);

  if (expectedDigest && !(expectedDigest instanceof Uint8Array)) {
    throw new TypeError("expectedDigest must be a Uint8Array if provided");
  }
  if (expectedDigest && !bytesEqual(parsed.fileDigest, expectedDigest)) {
    return {
      result: "INVALID",
      fileHashOp: parsed.fileHashOp.name,
      fileDigest: parsed.fileDigest,
      paths: [
        {
          outcome: "expected-digest-mismatch",
          opNames: [],
          detail: `expected ${bytesToHex(expectedDigest)}, proof carries ${bytesToHex(parsed.fileDigest)}`,
        },
      ],
      summary: { matches: 0, mismatch: 0, pending: 0, other: 1 },
    };
  }

  const headerMerkleRoot = header ? extractMerkleRoot(header) : null;
  const allAtts = collectAttestations(parsed.timestamp);

  const raw = await walkPaths(parsed.timestamp, parsed.fileDigest, []);

  // Classify each raw record into one of the issue's six path outcomes.
  const paths = raw.map((r) => {
    if (r.kind === "tooLong") {
      return { outcome: "message-too-long", opNames: r.opPath, length: r.length, limit: r.limit };
    }
    if (r.kind === "unsupportedOp") {
      return { outcome: "unsupported-op", opNames: r.opPath, detail: r.opName };
    }
    const evalR = evaluateAttestation(r.attestation, r.msg, headerMerkleRoot);
    return {
      outcome: evalR.outcome,
      opNames: r.opPath,
      attestation: r.attestation,
      finalDigest: evalR.finalDigest ?? null,
      detail: evalR.detail,
    };
  });

  const summary = {
    matches: paths.filter((p) => p.outcome === "matches").length,
    mismatch: paths.filter((p) => p.outcome === "mismatch").length,
    pending: paths.filter((p) => p.outcome === "pending").length,
    other: paths.filter((p) => !["matches", "mismatch", "pending"].includes(p.outcome)).length,
  };

  // Precedence rules from issue #315, "Overall result precedence":
  //   1. any supported completed Bitcoin matches the supplied merkle root → MATCHES
  //   2. else if any completed supported Bitcoin was evaluated and none matched → INVALID
  //   3. else if no completed supported Bitcoin was evaluated and a pending attestation exists → PENDING
  //   4. otherwise → UNSUPPORTED
  // Rule 3's "pending attestation exists" is read as structurally present in
  // the proof (`existsPending`), independent of op reachability. So a pending
  // att behind an unsupported-op barrier still fires PENDING.
  let result;
  if (summary.matches > 0) result = "MATCHES_SUPPLIED_HEADER";
  else if (summary.mismatch > 0) result = "INVALID";
  else if (summary.pending > 0 || existsPending(allAtts)) result = "PENDING";
  else result = "UNSUPPORTED";

  return {
    result,
    fileHashOp: parsed.fileHashOp.name,
    fileDigest: parsed.fileDigest,
    paths,
    summary,
  };
}
