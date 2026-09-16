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
const MAX_RECURSION_DEPTH = 256; // Timestamp.deserialize(_recursion_limit=256)
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
  // reference accepts, breaking interop.
  readVaruint() {
    let value = 0;
    let shift = 0;
    for (let i = 0; i < MAX_VARUINT_BYTES; i++) {
      const b = this.readByte();
      value += (b & 0x7f) * 2 ** shift; // +=, not |=: bitwise ops coerce to int32 and would corrupt varuints > 2^31
      if ((b & 0x80) === 0) return value;
      shift += 7;
    }
    throw new OtsParseError("VARUINT_TOO_LONG", `varuint exceeded ${MAX_VARUINT_BYTES} bytes`);
  }

  readVarbytes(maxLen, minLen = 0) {
    const len = this.readVaruint();
    if (len > maxLen) {
      throw new OtsParseError("LENGTH_LIMIT", `varbytes length ${len} exceeds limit ${maxLen}`);
    }
    if (len < minLen) {
      throw new OtsParseError("LENGTH_LIMIT", `varbytes length ${len} below minimum ${minLen}`);
    }
    return this.readBytes(len);
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

function parseAttestation(reader) {
  const uriBytes = reader.readBytes(8); // TimeAttestation.TAG_SIZE
  const uriHex = bytesToHex(uriBytes);
  const payload = reader.readVarbytes(MAX_ATTESTATION_PAYLOAD);
  const type = ATTESTATION_URIS[uriHex] ?? "unknown";

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
    // is never independently authenticated (#315).
    const inner = new Reader(payload);
    const height = inner.readVaruint();
    inner.assertEof(`${type} attestation payload`);
    return { type, uriHex, height };
  }

  // Unknown/future attestation: preserve tag and payload verbatim so the
  // verifier can mark the path UNSUPPORTED without the parser guessing.
  return { type, uriHex, payload };
}

// Timestamp.deserialize (timestamp.py): siblings are separated by 0xff; a
// path ends either at an attestation (0x00 tag) or by returning to a parent
// level. Like the reference, parsing is depth-limited to keep hostile proofs
// from smashing the stack.
function parseTimestamp(reader, depth) {
  if (depth >= MAX_RECURSION_DEPTH) {
    throw new OtsParseError("RECURSION_LIMIT", `timestamp DAG exceeded recursion depth ${MAX_RECURSION_DEPTH}`);
  }
  const node = { attestations: [], ops: [] };

  const processTag = (tag) => {
    if (tag === 0x00) {
      node.attestations.push(parseAttestation(reader));
    } else {
      const op = parseOp(reader, tag);
      // NOTE: the reference EAGERLY applies the op to validate message length
      // limits during deserialization. This parser deliberately does not —
      // applying ops is the verifier's job, and length limits are re-enforced
      // there. Structural shape is identical either way.
      node.ops.push({ op, child: parseTimestamp(reader, depth + 1) });
    }
  };

  let tag = reader.readByte();
  while (tag === 0xff) {
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
  const reader = new Reader(bytes);

  const magic = reader.readBytes(HEADER_MAGIC.length); // TRUNCATED if short
  if (bytesToHex(magic) !== bytesToHex(HEADER_MAGIC)) {
    throw new OtsParseError("BAD_MAGIC", "input is not an OpenTimestamps detached timestamp file");
  }

  const majorVersion = reader.readByte();
  if (majorVersion !== MAJOR_VERSION) {
    throw new OtsParseError("UNSUPPORTED_VERSION", `detached timestamp major version ${majorVersion} is not supported`);
  }

  // CryptOp.deserialize: the file-hash op must be a cryptographic op tag.
  const hashTag = reader.readByte();
  const hashDef = OPS[hashTag];
  if (!hashDef || hashDef.kind !== "crypt") {
    throw new OtsParseError("UNKNOWN_OP_TAG", `file hash op tag 0x${hashTag.toString(16).padStart(2, "0")} is not a cryptographic op`);
  }
  const fileDigest = reader.readBytes(hashDef.digestLength);

  const timestamp = parseTimestamp(reader, 0);
  reader.assertEof("detached timestamp file");

  return {
    majorVersion,
    fileHashOp: { tag: hashTag, name: hashDef.name, digestLength: hashDef.digestLength },
    fileDigest,
    timestamp,
  };
}
