// Byte coders for EntropyLab: strict hexadecimal and RFC 4648 base64.
//
// These are byte shufflings, not cryptography — they carry no keys and make
// no decisions. They replace the @scure/base hex/base64 coders the app used
// (Base58Check and bech32m, which do carry checksums, live in the WASM:
// base58.js and bech32.js). The API shape matches the @scure/base coders the
// app used (note base64 only needs `encode` here, so no `decode` is defined).

const HEX_ALPHABET = "0123456789abcdef";

export const hex = {
  encode(bytes) {
    if (!(bytes instanceof Uint8Array)) throw new Error("hex encode expects a Uint8Array");
    let out = "";
    for (let i = 0; i < bytes.length; i++) out += HEX_ALPHABET[bytes[i] >>> 4] + HEX_ALPHABET[bytes[i] & 15];
    return out;
  },
  decode(text) {
    if (typeof text !== "string" || text.length % 2 || /[^0-9a-f]/i.test(text)) throw new Error("Invalid hexadecimal string");
    const out = new Uint8Array(text.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
    return out;
  },
};

const B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export const base64 = {
  encode(bytes) {
    if (!(bytes instanceof Uint8Array)) throw new Error("base64 encode expects a Uint8Array");
    let out = "";
    for (let i = 0; i < bytes.length; i += 3) {
      const a = bytes[i], b = bytes[i + 1], c = bytes[i + 2];
      out += B64_ALPHABET[a >> 2];
      out += B64_ALPHABET[((a & 3) << 4) | (b >> 4)];
      out += i + 1 < bytes.length ? B64_ALPHABET[((b & 15) << 2) | (c >> 6)] : "=";
      out += i + 2 < bytes.length ? B64_ALPHABET[c & 63] : "=";
    }
    return out;
  },
};
