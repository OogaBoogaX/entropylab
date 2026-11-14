// OpenTimestamps (.ots) DetachedTimestampFile parser — issue #315, phase 1.
//
// Parses a serialized .ots proof into a structural tree. This module ONLY
// parses: it never applies operations, never hashes, never compares against
// a Bitcoin header. That is phase 2 (the verifier), which walks the tree
// this parser returns. Keeping parse and verify as separate, separately
// tested layers follows the issue's own decomposition ("The parser must
// validate the OTS serialization and fail closed on malformed or truncated
// data ... before applying operations").
//
// The wire format is pinned byte-for-byte against the python-opentimestamps
// reference implementation (the format's canonical definition):
//   opentimestamps/core/serialize.py  — LEB128 varuint, varbytes, truncation
//                                       and trailing-garbage rules
//   opentimestamps/core/op.py         — operation tags and argument limits
//   opentimestamps/core/timestamp.py  — DetachedTimestampFile header, magic,
//                                       version, Timestamp DAG structure,
//                                       recursion limit
//   opentimestamps/core/notary.py     — TimeAttestation layout (8-byte URI
//                                       tag + varbytes payload), per-type
//                                       payloads, payload size limits
//
// Fail-closed policy (mirrors the reference's DeserializationError family):
// every structural violation throws OtsParseError with a machine-readable
// .code. Nothing is ever silently skipped or defaulted.
//
// Scope notes:
// - Known-but-unsupported op tags (keccak256 0x67, reverse 0xf2,
//   hexlify 0xf3) PARSE fine — representing them is the parser's job.
//   Marking paths that use them UNSUPPORTED is the verifier's job (#315
//   result rules), because an unsupported op on one DAG branch must not
//   poison a supported sibling branch.
// - Unknown/future attestation URIs likewise parse into { type: "unknown" }
//   nodes for the verifier to mark. Unknown op TAGS remain a parse error,
//   matching the reference ("Unknown operation tag").
// - Proof files are non-secret public data; no zeroization is applied.
//
// Run tests: node --test test/ots-parser.test.mjs

export class OtsParseError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.name = "OtsParseError";
    this.code = code;
  }
}

// Resource limits are EntropyLab application policy, not part of the OTS
// format. Real proofs fit easily (the v1.0.0 release proof: 249 ops, paths
// up to 88 ops, fork nesting 3). Exceeding one is a budget failure, distinct
// from a malformed proof, so the verifier can report INCOMPLETE rather than
// INVALID.
export class OtsBudgetError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.name = "OtsBudgetError";
    this.code = code;
  }
}

export const OTS_LIMITS = {
  MAX_PROOF_BYTES: 1048576,
  MAX_OPS: 1024,
  MAX_PATH_OPS: 256,
  MAX_FORK_NESTING: 32,
  MAX_ATTESTATIONS: 64,
  MAX_HASHED_BYTES: 4194304,
  MAX_ORIGINAL_BYTES: 67108864,
};

// DetachedTimestampFile.HEADER_MAGIC (timestamp.py): a leading NUL so `file`
// classifies it as data, a human-readable banner, then 8 random-looking
// bytes to make accidental collisions implausible. 31 bytes total.
const HEADER_MAGIC = Uint8Array.from([
  0x00,
  0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, // "OpenTimestamps"
  0x00, 0x00,
  0x50, 0x72, 0x6f, 0x6f, 0x66, // "Proof"
  0x00,
  0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
]);

const MAJOR_VERSION = 1; // DetachedTimestampFile.MAJOR_VERSION

// Operation tags (op.py). Binary ops carry a varbytes argument; unary and
// crypt ops carry none. DIGEST_LENGTH is the CryptOp output size, used for
// the file digest that follows the file_hash_op tag in the header.
const OPS = {
  0x02: { name: "sha1", kind: "crypt", digestLength: 20 },
  0x03: { name: "ripemd160", kind: "crypt", digestLength: 20 },
  0x08: { name: "sha256", kind: "crypt", digestLength: 32 },
  0x67: { name: "keccak256", kind: "crypt", digestLength: 32 },
  0xf0: { name: "append", kind: "binary" },
  0xf1: { name: "prepend", kind: "binary" },
  0xf2: { name: "reverse", kind: "unary" },
  0xf3: { name: "hexlify", kind: "unary" },
};

// Attestation URI tags (notary.py), as 8-byte big-hex strings.
const ATTESTATION_URIS = {
  "83dfe30d2ef90c8e": "pending",
  "0588960d73d71901": "bitcoin",
  "06869a0d73d71b45": "litecoin",
};

// Reference limits (op.py / notary.py / timestamp.py). These are consensus
// for interop: a proof the reference accepts must parse identically here.
const MAX_OP_ARG_LENGTH = 4096; // Op.MAX_RESULT_LENGTH; binary op args read with min_len=1
const MAX_ATTESTATION_PAYLOAD = 8192; // TimeAttestation.MAX_PAYLOAD_SIZE
const MAX_URI_LENGTH = 1000; // PendingAttestation.MAX_URI_LENGTH
const MAX_VARUINT_BYTES = 8; // stricter than the reference (which loops
// unbounded); every legitimate length field is <= 8192 and every block height
// < 2^32, so >8 LEB128 bytes can only be hostile or corrupt. Fail closed.

// PendingAttestation.ALLOWED_URI_CHARS (notary.py) — enforced at parse time
// like the reference does, so a "pending" result can never smuggle an
// untypeable/ambiguous URI through the verifier's display layer.
const ALLOWED_URI_CHARS = new Set(
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/:".split(""),
);

class Reader {
  constructor(bytes) {
    this.bytes = bytes;
    this.pos = 0;
  }

  readByte() {
    if (this.pos >= this.bytes.length) {
      throw new OtsParseError("TRUNCATED", `tried to read 1 byte at offset ${this.pos}, input is ${this.bytes.length} bytes`);
    }
    return this.bytes[this.pos++];
  }

  readBytes(n) {
    if (this.pos + n > this.bytes.length) {
      throw new OtsParseError("TRUNCATED", `tried to read ${n} bytes at offset ${this.pos}, only ${this.bytes.length - this.pos} remain`);
    }
    const out = this.bytes.slice(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  // Unsigned LEB128 (serialize.py read_varuint). Like the reference, accepts
  // non-minimal encodings — canonical-form strictness would reject proofs the
  // reference accepts, breaking interop. Decoded with BigInt so a value above
  // 2^53 is never silently rounded before its field limit is checked.
  readVaruint() {
    let value = 0n;
    let shift = 0n;
    for (let i = 0; i < MAX_VARUINT_BYTES; i++) {
      const b = this.readByte();
      value |= BigInt(b & 0x7f) << shift;
      if ((b & 0x80) === 0) return value;
      shift += 7n;
    }
    throw new OtsParseError("VARUINT_TOO_LONG", `varuint exceeded ${MAX_VARUINT_BYTES} bytes`);
  }

  readVarbytes(maxLen, minLen = 0) {
    const len = this.readVaruint();
    if (len > BigInt(maxLen)) {
      throw new OtsParseError("LENGTH_LIMIT", `varbytes length ${len} exceeds limit ${maxLen}`);
    }
    if (len < BigInt(minLen)) {
      throw new OtsParseError("LENGTH_LIMIT", `varbytes length ${len} below minimum ${minLen}`);
    }
    return this.readBytes(Number(len));
  }

  assertEof(what) {
    if (this.pos !== this.bytes.length) {
      throw new OtsParseError("TRAILING_GARBAGE", `${this.bytes.length - this.pos} excess byte(s) after ${what}`);
    }
  }
}

const bytesToHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

function parseOp(reader, tag) {
  const def = OPS[tag];
  if (!def) {
    throw new OtsParseError("UNKNOWN_OP_TAG", `unknown operation tag 0x${tag.toString(16).padStart(2, "0")}`);
  }
  if (def.kind === "binary") {
    // BinaryOp.deserialize_from_tag: read_varbytes(MAX_RESULT_LENGTH, min_len=1)
    const arg = reader.readVarbytes(MAX_OP_ARG_LENGTH, 1);
    return { tag, name: def.name, kind: def.kind, arg };
  }
  return { tag, name: def.name, kind: def.kind };
}

function parseAttestation(reader, state) {
  const uriBytes = reader.readBytes(8); // TimeAttestation.TAG_SIZE
  const uriHex = bytesToHex(uriBytes);
  const payload = reader.readVarbytes(MAX_ATTESTATION_PAYLOAD);
  const type = ATTESTATION_URIS[uriHex] ?? "unknown";

  state.attestations += 1;
  if (state.attestations > OTS_LIMITS.MAX_ATTESTATIONS) {
    throw new OtsBudgetError("too-many-attestations", `more than ${OTS_LIMITS.MAX_ATTESTATIONS} attestations`);
  }

  if (type === "pending") {
    // PendingAttestation payload: varbytes(utf8 URI), then EOF.
    const inner = new Reader(payload);
    const uriRaw = inner.readVarbytes(MAX_URI_LENGTH);
    inner.assertEof("pending attestation URI");
    const uri = new TextDecoder().decode(uriRaw);
    for (const ch of uri) {
      if (!ALLOWED_URI_CHARS.has(ch)) {
        throw new OtsParseError("INVALID_URI", `pending attestation URI contains disallowed character ${JSON.stringify(ch)}`);
      }
    }
    return { type, uriHex, uri };
  }

  if (type === "bitcoin" || type === "litecoin") {
    // BitcoinBlockHeaderAttestation / LitecoinBlockHeaderAttestation payload:
    // varuint height, then EOF. The height is attestation metadata ONLY — it
    // is never independently authenticated (#315). A height above 2^32-1 is
    // not a parse error: it becomes a per-path unsupported outcome so a
    // sibling branch can still be evaluated.
    const inner = new Reader(payload);
    const height = inner.readVaruint();
    inner.assertEof(`${type} attestation payload`);
    if (height > 0xffffffffn) {
      return { type: "unsupported", uriHex, detail: "height out of range" };
    }
    return { type, uriHex, height: Number(height) };
  }

  // Unknown/future attestation: preserve tag and payload verbatim so the
  // verifier can mark the path UNSUPPORTED without the parser guessing.
  return { type, uriHex, payload };
}

// Timestamp.deserialize (timestamp.py): siblings are separated by 0xff; a
// path ends either at an attestation (0x00 tag) or by returning to a parent
// level. Resource limits are enforced here, while parsing, so a hostile proof
// is rejected before it can exhaust memory or the stack. Recursion depth is
// bounded by MAX_PATH_OPS, so no separate recursion limit is needed.
function parseTimestamp(reader, state, opDepth, forkDepth) {
  if (opDepth > OTS_LIMITS.MAX_PATH_OPS) {
    throw new OtsBudgetError("path-too-long", `more than ${OTS_LIMITS.MAX_PATH_OPS} ops on a path`);
  }
  const node = { attestations: [], ops: [] };
  let isFork = false;

  const processTag = (tag) => {
    if (tag === 0x00) {
      node.attestations.push(parseAttestation(reader, state));
    } else {
      const op = parseOp(reader, tag);
      state.ops += 1;
      if (state.ops > OTS_LIMITS.MAX_OPS) {
        throw new OtsBudgetError("too-many-ops", `more than ${OTS_LIMITS.MAX_OPS} op nodes`);
      }
      // NOTE: the reference EAGERLY applies the op to validate message length
      // limits during deserialization. This parser deliberately does not —
      // applying ops is the verifier's job, and length limits are re-enforced
      // there. Structural shape is identical either way.
      const child = parseTimestamp(reader, state, opDepth + 1, forkDepth + (isFork ? 1 : 0));
      node.ops.push({ op, child });
    }
  };

  let tag = reader.readByte();
  while (tag === 0xff) {
    isFork = true;
    if (forkDepth + 1 > OTS_LIMITS.MAX_FORK_NESTING) {
      throw new OtsBudgetError("fork-nesting", `fork nesting exceeds ${OTS_LIMITS.MAX_FORK_NESTING}`);
    }
    processTag(reader.readByte());
    tag = reader.readByte();
  }
  processTag(tag);
  return node;
}

/**
 * Parse a serialized .ots DetachedTimestampFile.
 *
 * @param {Uint8Array} bytes the raw .ots file contents
 * @returns {{
 *   majorVersion: number,
 *   fileHashOp: { tag: number, name: string, digestLength: number },
 *   fileDigest: Uint8Array,
 *   timestamp: { attestations: object[], ops: { op: object, child: object }[] },
 * }} the parsed proof tree (operations NOT applied)
 * @throws {OtsParseError} on any structural violation (fail closed)
 */
export function parseDetachedTimestamp(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError("proof bytes must be a Uint8Array");
  }
  if (bytes.length > OTS_LIMITS.MAX_PROOF_BYTES) {
    throw new OtsBudgetError("proof-too-large", `proof is ${bytes.length} bytes, limit ${OTS_LIMITS.MAX_PROOF_BYTES}`);
  }
  const reader = new Reader(bytes);

  const magic = reader.readBytes(HEADER_MAGIC.length); // TRUNCATED if short
  if (bytesToHex(magic) !== bytesToHex(HEADER_MAGIC)) {
    throw new OtsParseError("BAD_MAGIC", "input is not an OpenTimestamps detached timestamp file");
  }

  // DetachedTimestampFile.MAJOR_VERSION is a varuint in the reference.
  const majorVersionBig = reader.readVaruint();
  if (majorVersionBig !== BigInt(MAJOR_VERSION)) {
    throw new OtsParseError("UNSUPPORTED_VERSION", `detached timestamp major version ${majorVersionBig} is not supported`);
  }
  const majorVersion = Number(majorVersionBig);

  // CryptOp.deserialize: the file-hash op must be a cryptographic op tag.
  const hashTag = reader.readByte();
  const hashDef = OPS[hashTag];
  if (!hashDef || hashDef.kind !== "crypt") {
    throw new OtsParseError("UNKNOWN_OP_TAG", `file hash op tag 0x${hashTag.toString(16).padStart(2, "0")} is not a cryptographic op`);
  }
  const fileDigest = reader.readBytes(hashDef.digestLength);

  const state = { ops: 0, attestations: 0 };
  const timestamp = parseTimestamp(reader, state, 0, 0);
  reader.assertEof("detached timestamp file");

  return {
    majorVersion,
    fileHashOp: { tag: hashTag, name: hashDef.name, digestLength: hashDef.digestLength },
    fileDigest,
    timestamp,
  };
}
