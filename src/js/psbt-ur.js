// UR crypto-psbt (BCR-2020-005 / tag 310). Detector and display only.
// Decode Coldcard / SeedSigner / Sparrow paste; encode single-part or
// sequential seq-len fragments for an animated QR. Not a signer.

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

export function hodlCborCryptoPsbt(psbt) {
  return concatBytes(Uint8Array.of(0xd9, 0x01, 0x36), hodlCborBstr(psbt));
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

export function hodlUrParsePart(raw) {
  const text = String(raw).trim().toLowerCase().replace(/^ur:\/\//, "ur:");
  const match = text.match(/^ur:([a-z0-9-]+)(?:\/(\d+)-(\d+))?\/([a-z][a-z0-9-]*)$/);
  if (!match) throw new Error("That is not a UR (ur:type/...bytewords).");
  const type = match[1];
  const seq = match[2] ? Number(match[2]) : 1;
  const count = match[3] ? Number(match[3]) : 1;
  const payload = hodlBytewordsDecode(match[4].replace(/-/g, ""));
  // A sequence number past the part count marks a multi-part fountain code.
  return { type, seq, count, payload, fountain: Boolean(match[2] && seq > count) };
}

export function hodlUrEncodePsbt(psbt, options = {}) {
  if (!(psbt instanceof Uint8Array) || !psbt.length) throw new Error("Need PSBT bytes to encode a UR.");
  const cbor = hodlCborCryptoPsbt(psbt);
  const maxBytes = Number.isFinite(options.maxBytes) ? options.maxBytes : 200;
  const parts = [];
  if (cbor.length <= maxBytes) {
    parts.push("ur:crypto-psbt/" + hodlBytewordsEncode(cbor, "minimal"));
    return parts;
  }
  const count = Math.ceil(cbor.length / maxBytes);
  for (let i = 0; i < count; i++) {
    const chunk = cbor.slice(i * maxBytes, (i + 1) * maxBytes);
    parts.push("ur:crypto-psbt/" + (i + 1) + "-" + count + "/" + hodlBytewordsEncode(chunk, "minimal"));
  }
  return parts;
}

export function hodlUrDecodePsbt(raw) {
  const pieces = Array.isArray(raw) ? raw : String(raw).split(/[\s,]+/).filter(Boolean);
  if (!pieces.length) throw new Error("Paste a UR crypto-psbt.");
  const parsed = pieces.map(hodlUrParsePart);
  const type = parsed[0].type;
  if (type !== "crypto-psbt" && type !== "psbt") throw new Error("This UR is " + type + ", not crypto-psbt.");
  if (parsed.some((part) => part.type !== type)) throw new Error("Mixed UR types.");
  if (parsed.some((part) => part.fountain)) {
    throw new Error("Fountain UR fragments (seq > count) are not assembled yet. Display only: scan sequential 1-N parts.");
  }
  const count = parsed[0].count;
  if (parsed.some((part) => part.count !== count)) throw new Error("UR fragment counts do not match.");
  if (count === 1) {
    if (parsed.length !== 1) throw new Error("A single-part UR should be pasted once.");
    return { type, psbt: hodlCborUnwrapPsbt(parsed[0].payload), parts: 1 };
  }
  const slots = Array.from({ length: count }, () => null);
  for (const part of parsed) {
    if (part.seq < 1 || part.seq > count) throw new Error("UR fragment index is out of range.");
    slots[part.seq - 1] = part.payload;
  }
  if (slots.some((slot) => !slot)) {
    const have = slots.reduce((n, slot) => n + (slot ? 1 : 0), 0);
    throw new Error("Need all " + count + " sequential UR fragments (have " + have + "). Fountain recovery is not implemented.");
  }
  return { type, psbt: hodlCborUnwrapPsbt(concatBytes(...slots)), parts: count };
}

export { WORDS };
