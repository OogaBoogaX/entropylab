// BOLT12 (offers) decoder for EntropyLab: parses `lno1…` offers, `lnr1…`
// invoice requests, and `lni1…` invoices into structured, displayable fields.
//
// The envelope is bech32 WITHOUT a checksum (BOLT12 §Encoding: "We currently
// omit the six-character trailing checksum"), so the bech32m facade in
// bech32.js does not apply; only its pure-JS fromWords (5→8 bit reshaping)
// is reused. The local envelope decode below rejects mixed case, strips the
// spec's `+` continuation markers (`+` followed by optional whitespace,
// joining two bech32 characters), lowercases, splits HRP from data at the
// last "1", and maps data characters through the bech32 charset — with no
// polymod and no length cap, so long invoices with many blinded paths fit.
// The payload is a BOLT12 TLV stream — (bigsize type, bigsize length, value)
// records in strictly ascending type order — decoded per the field tables in
// BOLT12 (12-offer-encoding.md): offer fields in types 0-79, invoice_request
// fields in 80-159, invoice fields in 160-239, with 240 the signature
// record. Unknown even types are required fields the decoder cannot
// understand and hard-reject; unknown odd types are skipped and reported in
// `unknownOddTypes`.
//
// Blinded paths (offer_paths, invreq_paths, invoice_paths) are walked only
// far enough to count them and measure their total length — they are NEVER
// resolved, followed, or contacted. offer_issuer_id / invoice_node_id are
// signing keys, not a recoverable payee: a BOLT12 offer that omits paths
// publishes the issuer pubkey in the clear (a half-assed offer). Signatures
// are not verified either; the result merely reports `signaturePresent` and
// the UI renders the signature state as "not checked".
//
// Deterministic, offline, decode-only: no network, no entropy, no DOM. The
// module imports cleanly in Node for the unit tests. Failures throw keyed
// plain objects ({ key, vars }) for the DOM layer to translate with t().
import { fromWords } from "./bech32.js";
import { hex } from "./coders.js";

const utf8 = new TextDecoder("utf-8", { fatal: true });

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// ── bigsize (BOLT1's compact uint: <0xfd itself, else 0xfd/0xfe/0xff + BE) ──

const readBigsize = (bytes, offset) => {
  if (offset >= bytes.length) throw { key: "Truncated BOLT12 TLV record." };
  const first = bytes[offset];
  if (first < 0xfd) return { value: BigInt(first), size: 1 };
  const width = first === 0xfd ? 2 : first === 0xfe ? 4 : 8;
  if (offset + 1 + width > bytes.length) throw { key: "Truncated BOLT12 TLV record." };
  let value = 0n;
  for (let i = 0; i < width; i++) value = (value << 8n) | BigInt(bytes[offset + 1 + i]);
  const minimum = width === 2 ? 0xfdn : width === 4 ? 0x10000n : 0x100000000n;
  if (value < minimum) throw { key: "BOLT12 bigsize value is not minimally encoded." };
  return { value, size: 1 + width };
};

// ── field decoders (value bytes -> displayable JS value) ────────────────────

// Truncated u64/u32, big-endian, zero bytes meaning zero. Returned as a
// decimal string: a tu64 can exceed 2^53, so a Number would lie.
const tuField = (bytes) => {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value.toString();
};

const hexField = (bytes) => hex.encode(bytes);

const utf8Field = (name) => (bytes) => {
  try {
    return utf8.decode(bytes);
  } catch {
    throw { key: "The {name} field is not valid UTF-8.", vars: { name } };
  }
};

const lengthField = (name, length) => (bytes) => {
  if (bytes.length !== length) throw { key: "The {name} field has an invalid length.", vars: { name } };
  return hex.encode(bytes);
};

// offer_chains: a run of 32-byte chain hashes.
const chainsField = (bytes) => {
  if (bytes.length === 0 || bytes.length % 32 !== 0) throw { key: "The {name} field has an invalid length.", vars: { name: "offer_chains" } };
  const chains = [];
  for (let i = 0; i < bytes.length; i += 32) chains.push(hex.encode(bytes.slice(i, i + 32)));
  return chains;
};

// Blinded paths are counted and measured, never opened. One blinded_path is
// sciddir_or_pubkey (9 bytes when the first byte is 0x00/0x01 — direction +
// short channel id — otherwise a 33-byte pubkey), a 33-byte blinding key, a
// hop count, and that many (33-byte id + u16 length + encrypted data) hops.
const pathsField = (bytes) => {
  let offset = 0;
  let count = 0;
  while (offset < bytes.length) {
    offset += bytes[offset] <= 0x01 ? 9 : 33;
    offset += 33; // blinding key
    if (offset >= bytes.length) throw { key: "Truncated blinded path data." };
    const hops = bytes[offset];
    offset += 1;
    for (let hop = 0; hop < hops; hop++) {
      if (offset + 35 > bytes.length) throw { key: "Truncated blinded path data." };
      const enclen = (bytes[offset + 33] << 8) | bytes[offset + 34];
      offset += 35 + enclen;
    }
    if (offset > bytes.length) throw { key: "Truncated blinded path data." };
    count += 1;
  }
  return { count, totalBytes: bytes.length };
};

// invoice_blindedpay: one blinded_payinfo per path, each u32 + u32 + u16 +
// u64 + u64 + u16 flen + flen feature bytes (28 fixed + flen). Counted,
// never priced out.
const payinfoField = (bytes) => {
  let offset = 0;
  let count = 0;
  while (offset < bytes.length) {
    if (offset + 28 > bytes.length) throw { key: "Truncated blinded payinfo data." };
    const flen = (bytes[offset + 26] << 8) | bytes[offset + 27];
    offset += 28 + flen;
    if (offset > bytes.length) throw { key: "Truncated blinded payinfo data." };
    count += 1;
  }
  return count;
};

// ── TLV field tables (BOLT12, 12-offer-encoding.md) ─────────────────────────
// [type, camelCase name, decoder]. The signature record (240) is handled
// separately: its presence is reported, its bytes are not kept.

const OFFER_FIELDS = [
  [2n, "chains", chainsField],
  [4n, "metadata", hexField],
  [6n, "currency", utf8Field("offer_currency")],
  [8n, "amount", tuField],
  [10n, "description", utf8Field("offer_description")],
  [12n, "features", hexField],
  [14n, "absoluteExpiry", tuField],
  [16n, "paths", pathsField],
  [18n, "issuer", utf8Field("offer_issuer")],
  [20n, "quantityMax", tuField],
  [22n, "issuerId", lengthField("offer_issuer_id", 33)],
];

const INVREQ_FIELDS = [
  ...OFFER_FIELDS,
  [0n, "invreqMetadata", hexField],
  [80n, "chain", lengthField("invreq_chain", 32)],
  [82n, "amountMsat", tuField],
  [84n, "invreqFeatures", hexField],
  [86n, "quantity", tuField],
  [88n, "payerId", lengthField("invreq_payer_id", 33)],
  [89n, "payerNote", utf8Field("invreq_payer_note")],
  [90n, "invreqPaths", pathsField],
];

const INVOICE_FIELDS = [
  ...INVREQ_FIELDS,
  [160n, "invoicePaths", pathsField],
  [162n, "payinfoCount", payinfoField],
  [164n, "createdAt", tuField],
  [166n, "relativeExpiry", tuField],
  [168n, "paymentHash", lengthField("invoice_payment_hash", 32)],
  [170n, "invoiceAmount", tuField],
  [172n, "fallbacks", hexField],
  [174n, "invoiceFeatures", hexField],
  [176n, "nodeId", lengthField("invoice_node_id", 33)],
];

const SIGNATURE_TYPE = 240n;

const KINDS = {
  lno: OFFER_FIELDS,
  lnr: INVREQ_FIELDS,
  lni: INVOICE_FIELDS,
};

// ── envelope: checksum-free bech32 with `+` continuations (BOLT12 §Encoding) ─

const decodeEnvelope = (raw) => {
  if (raw !== raw.toLowerCase() && raw !== raw.toUpperCase()) {
    throw { key: "BOLT12 strings must be all lowercase or all uppercase, not mixed case." };
  }
  // A `+` (with optional whitespace) continues a long string; it is only
  // valid between two bech32 characters — never leading, trailing, or
  // doubled (bolt12/format-string-test.json).
  if (/^\+|\+\s*$|\+\s*\+/.test(raw)) {
    throw { key: "Not a valid BOLT12 string: “+” must join two bech32 characters." };
  }
  const joined = raw.replace(/\+\s*/g, "").toLowerCase();
  const separator = joined.lastIndexOf("1");
  if (separator < 1) throw { key: "Not a valid BOLT12 string: the “1” separator is missing." };
  const words = [];
  for (const c of joined.slice(separator + 1)) {
    const word = BECH32_CHARSET.indexOf(c);
    if (word < 0) throw { key: "Not a valid BOLT12 string: “{c}” is not a bech32 character.", vars: { c } };
    words.push(word);
  }
  return { hrp: joined.slice(0, separator), words };
};

// ── decoder ─────────────────────────────────────────────────────────────────

export const bolt12Decode = (text) => {
  if (typeof text !== "string" || text.trim() === "") {
    throw { key: "Paste a BOLT12 string (lno1…, lnr1…, or lni1…)." };
  }
  const { hrp, words } = decodeEnvelope(text.trim());
  const table = KINDS[hrp];
  if (!table) {
    throw { key: "Not a BOLT12 string: the prefix “{hrp}” is not lno, lnr, or lni.", vars: { hrp } };
  }
  let payload;
  try {
    payload = fromWords(words);
  } catch {
    throw { key: "Invalid padding in the BOLT12 data." };
  }
  if (payload.length === 0) throw { key: "The BOLT12 payload is empty." };

  const known = new Map(table.map(([type, name, decode]) => [type, { name, decode }]));
  const fields = {};
  const unknownOddTypes = [];
  let signaturePresent = false;
  let offset = 0;
  let lastType = -1n;
  while (offset < payload.length) {
    const type = readBigsize(payload, offset);
    offset += type.size;
    const length = readBigsize(payload, offset);
    offset += length.size;
    if (length.value > BigInt(payload.length - offset)) throw { key: "Truncated BOLT12 TLV record." };
    const value = payload.slice(offset, offset + Number(length.value));
    offset += Number(length.value);
    if (type.value === lastType) throw { key: "Duplicate TLV field type {t}.", vars: { t: type.value.toString() } };
    if (type.value < lastType) throw { key: "TLV field type {t} is out of order.", vars: { t: type.value.toString() } };
    lastType = type.value;
    if (type.value === SIGNATURE_TYPE) {
      signaturePresent = true;
      continue;
    }
    const field = known.get(type.value);
    if (!field) {
      if (type.value % 2n === 0n) throw { key: "Unknown required TLV field type {t}.", vars: { t: type.value.toString() } };
      unknownOddTypes.push(Number(type.value));
      continue;
    }
    fields[field.name] = field.decode(value);
  }
  return { kind: "bolt12", hrp, fields, unknownOddTypes, signaturePresent };
};

// Count blinded paths across the three TLV slots. Never opens a hop.
export const bolt12PathCount = (fields = {}) => {
  const n = (path) => (path && typeof path.count === "number" ? path.count : 0);
  return n(fields.paths) + n(fields.invreqPaths) + n(fields.invoicePaths);
};

// Honesty for the UI: a good offer hides the recipient. issuer_id / node_id
// are signing keys. "published" means the string put a pubkey in the clear
// with no blinded path — half-assed BOLT12, still decode it, never call it
// the destination.
export const bolt12RecipientVisibility = (fields = {}) => {
  const pathCount = bolt12PathCount(fields);
  if (pathCount > 0) return { kind: "blinded", pathCount };
  if (fields.issuerId || fields.nodeId) return { kind: "published", pathCount: 0 };
  return { kind: "none", pathCount: 0 };
};

