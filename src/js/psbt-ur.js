// UR crypto-psbt (BCR-2020-005 / tag 310, multipart per BCR-2024-001 "MUR").
// Detector and display only. Decode Coldcard / SeedSigner / Sparrow paste;
// encode single-part or fixed-rate MUR fragments for an animated QR.
// Not a signer.

const WORDS = "able acid also apex aqua arch atom aunt away axis back bald barn belt beta bias blue body brag brew bulb buzz calm cash cats chef city claw code cola cook cost crux curl cusp cyan dark data days deli dice diet door down draw drop drum dull duty each easy echo edge epic even exam exit eyes fact fair fern figs film fish fizz flap flew flux foxy free frog fuel fund gala game gear gems gift girl glow good gray grim guru gush gyro half hang hard hawk heat help high hill holy hope horn huts iced idea idle inch inky into iris iron item jade jazz join jolt jowl judo jugs jump junk jury keep keno kept keys kick kiln king kite kiwi knob lamb lava lazy leaf legs liar limp lion list logo loud love luau luck lung main many math maze memo menu meow mild mint miss monk nail navy need news next noon note numb obey oboe omit onyx open oval owls paid part peck play plus poem pool pose puff puma purr quad quiz race ramp real redo rich road rock roof ruby ruin runs rust safe saga scar sets silk skew slot soap solo song stub surf swan taco task taxi tent tied time tiny toil tomb toys trip tuna twin ugly undo unit urge user vast very veto vial vibe view visa void vows wall wand warm wasp wave waxy webs what when whiz wolf work yank yawn yell yoga yurt zaps zero zest zinc zone zoom".split(" ");

const WORD_AT = new Map(WORDS.map((word, index) => [word, index]));
const MINIMAL_AT = new Map(WORDS.map((word, index) => [word[0] + word[3], index]));

export function hodlCrc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let i = 0; i < 8; i++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
  }
  crc = (crc ^ 0xffffffff) >>> 0;
  return Uint8Array.of(crc >>> 24, (crc >>> 16) & 255, (crc >>> 8) & 255, crc & 255);
}

function concatBytes(...parts) {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function eq(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let different = 0;
  for (let i = 0; i < a.length; i++) different |= a[i] ^ b[i];
  return different === 0;
}

export function hodlBytewordsEncode(bytes, style = "minimal") {
  const payload = concatBytes(bytes, hodlCrc32(bytes));
  if (style === "standard") return Array.from(payload, (byte) => WORDS[byte]).join(" ");
  return Array.from(payload, (byte) => WORDS[byte][0] + WORDS[byte][3]).join("");
}

export function hodlBytewordsDecode(text) {
  const raw = String(text).trim().toLowerCase();
  if (!raw) throw new Error("Empty Bytewords.");
  let bytes;
  if (/^[a-z]{4}(?:[\s-]+[a-z]{4})+$/.test(raw) || /^[a-z]{4}$/.test(raw)) {
    const words = raw.split(/[\s-]+/).filter(Boolean);
    bytes = Uint8Array.from(words, (word) => {
      if (!WORD_AT.has(word)) throw new Error("Unknown Byteword: " + word);
      return WORD_AT.get(word);
    });
  } else if (/^[a-z]+$/.test(raw) && raw.length % 2 === 0) {
    bytes = new Uint8Array(raw.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      const pair = raw.slice(i * 2, i * 2 + 2);
      if (!MINIMAL_AT.has(pair)) throw new Error("Unknown minimal Byteword: " + pair);
      bytes[i] = MINIMAL_AT.get(pair);
    }
  } else {
    throw new Error("That is not Bytewords (standard or minimal).");
  }
  if (bytes.length < 5) throw new Error("Bytewords payload is too short.");
  const body = bytes.slice(0, -4);
  const crc = bytes.slice(-4);
  if (!eq(crc, hodlCrc32(body))) throw new Error("Bytewords checksum failed.");
  return body;
}

export function hodlCborBstr(bytes) {
  let header;
  if (bytes.length < 24) header = Uint8Array.of(0x40 + bytes.length);
  else if (bytes.length < 256) header = Uint8Array.of(0x58, bytes.length);
  else if (bytes.length < 65536) header = Uint8Array.of(0x59, bytes.length >> 8, bytes.length & 255);
  else header = Uint8Array.of(0x5a, bytes.length >>> 24, (bytes.length >>> 16) & 255, (bytes.length >>> 8) & 255, bytes.length & 255);
  return concatBytes(header, bytes);
}

export function hodlCborBstrRead(bytes, offset) {
  if (offset >= bytes.length) throw new Error("CBOR byte string ended early.");
  const first = bytes[offset];
  let length, start;
  if (first >= 0x40 && first <= 0x57) {
    length = first - 0x40;
    start = offset + 1;
  } else if (first === 0x58) {
    if (offset + 2 > bytes.length) throw new Error("CBOR byte string ended early.");
    length = bytes[offset + 1];
    start = offset + 2;
  } else if (first === 0x59) {
    if (offset + 3 > bytes.length) throw new Error("CBOR byte string ended early.");
    length = (bytes[offset + 1] << 8) | bytes[offset + 2];
    start = offset + 3;
  } else if (first === 0x5a) {
    if (offset + 5 > bytes.length) throw new Error("CBOR byte string ended early.");
    length = ((bytes[offset + 1] << 24) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 8) | bytes[offset + 4]) >>> 0;
    start = offset + 5;
  } else {
    throw new Error("CBOR value is not a byte string.");
  }
  if (start + length > bytes.length) throw new Error("CBOR byte string is truncated.");
  return [bytes.slice(start, start + length), start + length];
}

export function hodlCborUnwrapPsbt(bytes) {
  if (bytes.length >= 3 && bytes[0] === 0xd9 && bytes[1] === 0x01 && bytes[2] === 0x36) {
    const [psbt, end] = hodlCborBstrRead(bytes, 3);
    if (end !== bytes.length) throw new Error("crypto-psbt CBOR has trailing bytes.");
    return psbt;
  }
  if (bytes.length >= 3 && bytes[0] === 0xd9 && bytes[1] === 0x9d && bytes[2] === 0x76) {
    const [psbt, end] = hodlCborBstrRead(bytes, 3);
    if (end !== bytes.length) throw new Error("psbt CBOR has trailing bytes.");
    return psbt;
  }
  const [psbt, end] = hodlCborBstrRead(bytes, 0);
  if (end !== bytes.length) throw new Error("UR CBOR has trailing bytes.");
  return psbt;
}

// A dCBOR unsigned integer, minimal width.
function cborUint(value) {
  if (value < 0x18) return Uint8Array.of(value);
  if (value < 0x100) return Uint8Array.of(0x18, value);
  if (value < 0x10000) return Uint8Array.of(0x19, value >> 8, value & 255);
  return Uint8Array.of(0x1a, value >>> 24, (value >>> 16) & 255, (value >>> 8) & 255, value & 255);
}

// BCR-2024-001 part: [seqNum, seqLen, messageLen, checksum, data]. The
// checksum is the CRC-32 of the whole message, serialized as a fixed-width
// uint32; the other numbers use minimal-width dCBOR. Matches the published
// testEncoderCBOR vectors.
export function hodlUrPartCbor(seqNum, seqLen, messageLen, checksum, data) {
  return concatBytes(
    Uint8Array.of(0x85),
    cborUint(seqNum),
    cborUint(seqLen),
    cborUint(messageLen),
    Uint8Array.of(0x1a, checksum >>> 24, (checksum >>> 16) & 255, (checksum >>> 8) & 255, checksum & 255),
    hodlCborBstr(data),
  );
}

// The inverse: strict parse of the part structure, or null when the payload
// is anything else (a legacy raw-fragment chunk, garbage).
function hodlUrPartParse(bytes) {
  try {
    if (!bytes.length || bytes[0] !== 0x85) return null;
    let offset = 1;
    const readUint = () => {
      const first = bytes[offset++];
      if (first < 0x18) return first;
      if (first === 0x18) return bytes[offset++];
      if (first === 0x19) {
        const value = (bytes[offset] << 8) | bytes[offset + 1];
        offset += 2;
        return value;
      }
      if (first === 0x1a) {
        const value = ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
        offset += 4;
        return value;
      }
      throw new Error("not a uint");
    };
    const seqNum = readUint(), seqLen = readUint(), messageLen = readUint(), checksum = readUint();
    if ([seqNum, seqLen, messageLen, checksum].some((value) => !Number.isInteger(value))) return null;
    const [data, end] = hodlCborBstrRead(bytes, offset);
    if (end !== bytes.length) return null;
    return { seqNum, seqLen, messageLen, checksum, data };
  } catch {
    return null;
  }
}

const crc32Number = (bytes) => {
  const crc = hodlCrc32(bytes);
  return ((crc[0] << 24) | (crc[1] << 16) | (crc[2] << 8) | crc[3]) >>> 0;
};

export function hodlUrParsePart(raw) {
  const text = String(raw).trim().toLowerCase().replace(/^ur:\/\//, "ur:");
  const match = text.match(/^ur:([a-z0-9-]+)(?:\/(\d+)-(\d+))?\/([a-z][a-z0-9-]*)$/);
  if (!match) throw new Error("That is not a UR (ur:type/...bytewords).");
  const type = match[1];
  const seq = match[2] ? Number(match[2]) : 1;
  const count = match[3] ? Number(match[3]) : 1;
  const payload = hodlBytewordsDecode(match[4].replace(/-/g, ""));
  // A sequence number past the part count marks a multi-part fountain code.
  const fountain = Boolean(match[2] && seq > count);
  // A BCR-2024-001 part is only believed when its metadata agrees with the
  // URI's own sequencing; anything else is a legacy raw-fragment payload.
  let part = null;
  if (!fountain) {
    const candidate = hodlUrPartParse(payload);
    if (candidate && candidate.seqNum === seq && candidate.seqLen === count) part = candidate;
  }
  return { type, seq, count, payload, fountain, part };
}

function hodlUrEncodeMessage(type, message, options = {}) {
  if (!/^[a-z0-9-]+$/.test(type)) throw new Error("Bad UR type.");
  if (!(message instanceof Uint8Array) || !message.length) throw new Error("Need UR message bytes.");
  const maxBytes = Number.isFinite(options.maxBytes) ? options.maxBytes : 200;
  if (message.length <= maxBytes) return ["ur:" + type + "/" + hodlBytewordsEncode(message, "minimal")];
  // Same BCR-2024-001 fixed-rate parts crypto-psbt already uses. Not a new
  // dialect and not a fountain code: equal-length fragments, the last one
  // zero-padded, each carrying the whole message's length and CRC-32.
  const count = Math.ceil(message.length / maxBytes);
  const checksum = crc32Number(message);
  const parts = [];
  for (let i = 0; i < count; i++) {
    let fragment = message.slice(i * maxBytes, (i + 1) * maxBytes);
    if (fragment.length < maxBytes) fragment = concatBytes(fragment, new Uint8Array(maxBytes - fragment.length));
    parts.push("ur:" + type + "/" + (i + 1) + "-" + count + "/" + hodlBytewordsEncode(hodlUrPartCbor(i + 1, count, message.length, checksum, fragment), "minimal"));
  }
  return parts;
}

export function hodlUrEncodePsbt(psbt, options = {}) {
  if (!(psbt instanceof Uint8Array) || !psbt.length) throw new Error("Need PSBT bytes to encode a UR.");
  // The UR payload is the untagged CBOR byte string: the type component
  // already carries tag 310's information (BCR-2020-005).
  return hodlUrEncodeMessage("crypto-psbt", hodlCborBstr(psbt), options);
}

function hodlUrReassemble(raw, emptyMessage, acceptType) {
  const pieces = Array.isArray(raw) ? raw : String(raw).split(/[\s,]+/).filter(Boolean);
  if (!pieces.length) throw new Error(emptyMessage);
  const parsed = pieces.map(hodlUrParsePart);
  const type = parsed[0].type;
  acceptType(type);
  if (parsed.some((part) => part.type !== type)) throw new Error("Mixed UR types.");
  if (parsed.some((part) => part.fountain)) {
    throw new Error("Fountain UR fragments (seq > count) are not assembled yet. Display only: scan sequential 1-N parts.");
  }
  const count = parsed[0].count;
  if (parsed.some((part) => part.count !== count)) throw new Error("UR fragment counts do not match.");
  if (count === 1) {
    if (parsed.length !== 1) throw new Error("A single-part UR should be pasted once.");
    return { type, message: parsed[0].payload, parts: 1 };
  }
  const slots = Array.from({ length: count }, () => null);
  for (const part of parsed) {
    if (part.seq < 1 || part.seq > count) throw new Error("UR fragment index is out of range.");
    // A second fragment for an already-filled sequence number would silently
    // overwrite it — with fragments spliced from two different messages the
    // reassembly would decode to bytes neither sender produced.
    // Exact repeats (the same fragment pasted twice) are idempotent;
    // conflicting ones are rejected (issue #364).
    const existing = slots[part.seq - 1];
    if (existing) {
      if (eq(existing, part.payload)) continue;
      throw new Error("Duplicate UR fragment " + part.seq + " with different content.");
    }
    slots[part.seq - 1] = part.payload;
  }
  if (slots.some((slot) => !slot)) {
    const have = slots.reduce((n, slot) => n + (slot ? 1 : 0), 0);
    throw new Error("Need all " + count + " sequential UR fragments (have " + have + "). Fountain recovery is not implemented.");
  }
  const ordered = parsed.slice().sort((a, b) => a.seq - b.seq);
  const standard = ordered[0].part;
  if (standard) {
    // BCR-2024-001 fixed-rate reassembly: every part must carry the same
    // message metadata, and the reassembled message must match the CRC-32
    // they all commit to — fragments spliced from another message fail here
    // even when they land in different slots (audit C3-5).
    if (ordered.some((part) => !part.part)) throw new Error("Mixed UR fragment formats: some parts carry MUR metadata and some do not.");
    for (const part of ordered) {
      const p = part.part;
      if (p.seqLen !== standard.seqLen || p.messageLen !== standard.messageLen || p.checksum !== standard.checksum || p.data.length !== standard.data.length) {
        throw new Error("UR fragment metadata do not match.");
      }
    }
    const message = concatBytes(...ordered.map((part) => part.part.data)).slice(0, standard.messageLen);
    if (crc32Number(message) !== standard.checksum) {
      throw new Error("UR message checksum failed: the reassembled message is not the one the fragments belong to.");
    }
    return { type, message, parts: count };
  }
  if (ordered.some((part) => part.part)) throw new Error("Mixed UR fragment formats: some parts carry MUR metadata and some do not.");
  // Legacy pre-MUR fragments: raw chunks tied only by per-chunk checksums.
  return { type, message: concatBytes(...ordered.map((part) => part.payload)), parts: count };
}

export function hodlUrDecodePsbt(raw) {
  const assembled = hodlUrReassemble(raw, "Paste a UR crypto-psbt.", (type) => {
    if (type !== "crypto-psbt" && type !== "psbt") throw new Error("This UR is " + type + ", not crypto-psbt.");
  });
  return { type: assembled.type, psbt: hodlCborUnwrapPsbt(assembled.message), parts: assembled.parts };
}

// Watch-only descriptor and BIP-388 policy text. Same UR family as
// crypto-psbt: ur:bytes is the untagged CBOR byte string in BCR-2020-005,
// and a payload past one QR uses the same fixed-rate MUR parts. Not a
// signing protocol. An extended private key is refused.
const WATCH_ONLY_PRIVATE_KEY = /\b(?:[xyztuv]prv|[YZUV]prv)[1-9A-HJ-NP-Za-km-z]{90,}/;
export const WATCH_ONLY_QR_STATIC_MAX_CHARS = 1000;

function assertWatchOnlyText(value) {
  if (WATCH_ONLY_PRIVATE_KEY.test(value)) throw new Error("Watch-only QR refused an extended private key.");
}

export function watchOnlyQrPlan(text) {
  const value = String(text ?? "");
  assertWatchOnlyText(value);
  if (value.length <= WATCH_ONLY_QR_STATIC_MAX_CHARS) return { mode: "static", text: value };
  const message = hodlCborBstr(new TextEncoder().encode(value));
  const parts = hodlUrEncodeMessage("bytes", message, { maxBytes: 200 }).map((part) => part.toUpperCase());
  if (parts.length < 2) throw new Error("A payload past one QR must split into UR parts.");
  return { mode: "ur", parts };
}

export function hodlUrDecodeWatchOnly(raw) {
  const assembled = hodlUrReassemble(raw, "Paste a UR bytes payload.", (type) => {
    if (type !== "bytes") throw new Error("This UR is " + type + ", not bytes.");
  });
  const bytes = hodlCborUnwrapPsbt(assembled.message);
  const value = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  assertWatchOnlyText(value);
  return value;
}

export { WORDS };
