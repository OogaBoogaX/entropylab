// BBQr PSBT transport, https://github.com/coinkite/BBQr/blob/master/BBQr.md.
// No checksum or transfer ID exists in BBQr: consistent headers and duplicate
// checks cannot detect every mixture of two transfers with identical headers.
import { inflateRawBounded } from "./qr-deflate.js";

const MAX_PARTS = 1000;
const MAX_FRAME_CHARS = 4296; // QR version 40, alphanumeric, ECC L.
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const decode = (text, encoding) => {
  if (encoding === "H") {
    if (!/^(?:[0-9A-F]{2})+$/.test(text)) return null;
    const bytes = new Uint8Array(text.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
    return bytes;
  }
  // RFC 4648: no padding, only complete bytes, zero unused tail bits.
  if (!/^[A-Z2-7]+$/.test(text) || ![0, 2, 4, 5, 7].includes(text.length % 8)) return null;
  const bytes = new Uint8Array(Math.floor(text.length * 5 / 8));
  let value = 0, bits = 0, offset = 0;
  for (const char of text) {
    value = (value << 5) | BASE32.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes[offset++] = value >>> bits;
      value &= (1 << bits) - 1;
    }
  }
  if (value !== 0) { bytes.fill(0); return null; }
  return bytes;
};

export function createBbqrCollector({ maxBytes = 1048576 } = {}) {
  const parts = new Map();
  let header = null, total = 0, normalSize = null, retained = 0;
  let terminal = null, done = false;
  const wipe = () => {
    for (const bytes of parts.values()) bytes.fill(0);
    parts.clear();
    header = null;
    total = 0;
    normalSize = null;
    retained = 0;
  };
  const reset = () => { wipe(); terminal = null; done = false; };
  const fail = (status) => { wipe(); terminal = status; return { status }; };
  const progress = () => header == null ? null : { received: parts.size, total };

  const receive = (text) => {
    if (terminal) return { status: terminal };
    if (done) return { status: "done" };
    if (typeof text !== "string") return fail("bad-part");
    if (text.length > MAX_FRAME_CHARS) return fail("too-large");
    const match = /^B\$([0-9A-Z])([A-Z])([0-9A-Z]{2})([0-9A-Z]{2})/.exec(text);
    if (!match) return fail("bad-part");
    const [, encoding, type, countText, indexText] = match;
    if (header !== null && header !== text.slice(0, 6)) return fail("mismatch");
    if (type !== "P") return { status: "wrong-type" };
    if (!["H", "2", "Z"].includes(encoding)) return fail("bad-part");
    const count = parseInt(countText, 36), index = parseInt(indexText, 36);
    if (count === 0 || index >= count) return fail("bad-part");
    if (count > MAX_PARTS) return fail("too-large");
    const payload = text.slice(8);
    const length = encoding === "H" ? payload.length / 2 : Math.floor(payload.length * 5 / 8);
    const previous = parts.get(index);
    if (!previous && retained + length > maxBytes) return fail("too-large");
    const bytes = decode(payload, encoding);
    if (!bytes) return fail("bad-part");
    let keep = false;
    try {
      if (previous) {
        if (previous.length !== bytes.length || previous.some((byte, i) => byte !== bytes[i])) return fail("mismatch");
        return { status: "partial" };
      }
      const last = index === count - 1;
      if (!last && encoding !== "H" && payload.length % 8 !== 0) return fail("bad-part");
      if (!last && normalSize !== null && bytes.length !== normalSize) return fail("bad-part");
      const size = last ? normalSize : bytes.length;
      const lastSize = last ? bytes.length : parts.get(count - 1)?.length;
      if (size !== null && lastSize !== undefined && lastSize > size) return fail("bad-part");
      // The last part is nonempty and no longer than any other part. Check
      // the minimum possible total before retaining or allocating a transfer.
      const minimum = last && normalSize === null
        ? bytes.length * count
        : size * (count - 1) + (lastSize ?? 1);
      if (minimum > maxBytes) return fail("too-large");
      if (header === null) { header = text.slice(0, 6); total = count; }
      if (!last) normalSize = bytes.length;
      parts.set(index, bytes);
      retained += bytes.length;
      keep = true;
      if (parts.size !== total) return { status: "partial" };

      const message = new Uint8Array(retained);
      let offset = 0;
      for (let i = 0; i < total; i++) {
        const part = parts.get(i);
        message.set(part, offset);
        offset += part.length;
      }
      wipe();
      if (encoding !== "Z") { done = true; return { status: "complete", bytes: message }; }
      try {
        const output = inflateRawBounded(message, maxBytes);
        done = true;
        return { status: "complete", bytes: output };
      } catch (error) {
        return fail(error?.code === "too-large" ? "too-large" : "bad-part");
      } finally {
        message.fill(0);
      }
    } finally {
      if (!keep) bytes.fill(0);
    }
  };
  return { receive, progress, reset };
}
