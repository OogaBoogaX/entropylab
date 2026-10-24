// BIP 77 (Async Payjoin) URI decoder for EntropyLab.
//
// Pure parsing: no DOM, no network, no randomness, and no clock read except
// the caller-supplied `now`. The page never contacts the directory, relay or
// receiver; this module only reports what a `bitcoin:` URI with a `pj`
// parameter points to so the user can inspect it before scanning it into a
// wallet.
//
// `parseBitcoinUri` in bip321.js does not expose the raw query parameters and
// rewrites `+` to a space, which would corrupt BIP 77's legacy `+` fragment
// separator. The URI is therefore parsed the same way here, keeping the raw
// `pj` value.

import { Address as BtcAddress, NETWORK, TEST_NETWORK } from "@scure/btc-signer";
import { parseBitcoinUri } from "./bip321.js";
import { secp256k1, secp256k1Ready } from "./secp256k1.js";

// Callers must await secp256k1Ready before calling decodePayjoinUri; the WASM
// facade validates public keys.

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_UPPER = "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L";
const BTC_REGTEST = { ...TEST_NETWORK, bech32: "bcrt" };

function assertValidCompressedPubkey(bytes, what) {
  try {
    secp256k1.Point.fromBytes(bytes);
  } catch (error) {
    const message = String(error && error.message ? error.message : error);
    if (/not ready|loading|WASM/i.test(message)) {
      throw new Error("Key checks are still loading; try again.");
    }
    throw new Error(`The ${what} is not a valid secp256k1 point.`);
  }
}

function bytesToHex(bytes) {
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

function decodeAddress(address) {
  if (!address) return { address: null, network: null };
  const networks = [
    ["mainnet", NETWORK],
    ["testnet", TEST_NETWORK],
    ["regtest", BTC_REGTEST],
  ];
  for (const [network, params] of networks) {
    try {
      BtcAddress(params).decode(address);
      return { address, network };
    } catch {}
  }
  throw new Error("The URI's address is not a valid Bitcoin address.");
}

// BIP 77's fragment parameters are bech32 strings without a checksum: the HRP
// is the parameter key, the separator is the right-most '1', and the data is
// the bech32 character set. rust-payjoin's nochecksum::decode splits at the
// right-most separator, so "EX1010" has HRP "EX10", not "EX1".
function decodeBech32NoChecksum(param) {
  const separator = param.lastIndexOf("1");
  if (separator < 1) throw new Error(`The pj fragment parameter is missing its 1 separator: ${param}`);
  const hrp = param.slice(0, separator);
  const data = param.slice(separator + 1);
  if (!data) throw new Error(`The pj fragment parameter has no value: ${param}`);
  const words = [];
  for (const char of data) {
    const index = BECH32_CHARSET.indexOf(char.toLowerCase());
    if (index === -1) throw new Error(`The pj fragment parameter contains a non-bech32 character: ${char}`);
    words.push(index);
  }
  let acc = 0, bits = 0;
  const bytes = [];
  for (const word of words) {
    acc = (acc << 5) | word;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((acc >>> bits) & 0xff);
    }
  }
  if (bits >= 5 || ((acc << (8 - bits)) & 0xff)) {
    throw new Error(`The pj fragment parameter has invalid bech32 padding: ${param}`);
  }
  return { hrp, bytes: Uint8Array.from(bytes) };
}

function decodeComponent(raw, what) {
  try {
    return decodeURIComponent(String(raw));
  } catch {
    throw new Error(`Malformed percent-encoding in the ${what}.`);
  }
}

function parseQuery(query) {
  if (!query) return [];
  return String(query).split("&").filter(Boolean).map((part) => {
    const eq = part.indexOf("=");
    const key = decodeComponent(eq === -1 ? part : part.slice(0, eq), "URI parameter name");
    const value = decodeComponent(eq === -1 ? "" : part.slice(eq + 1), "URI parameter");
    return { key: key.toLowerCase(), value };
  });
}

function parseV1Endpoint(pjValue) {
  let url;
  try {
    url = new URL(pjValue);
  } catch {
    throw new Error("The pj parameter is not a valid URL.");
  }
  if (url.username || url.password) {
    throw new Error("The pj endpoint must not carry userinfo.");
  }
  const scheme = url.protocol.replace(/:$/, "").toLowerCase();
  const host = url.hostname.toLowerCase();
  if (!host) throw new Error("The pj endpoint is missing a host.");
  if (scheme === "https") return { endpoint: url.href, origin: url.origin, host };
  if (scheme === "http" && host.endsWith(".onion")) return { endpoint: url.href, origin: url.origin, host };
  throw new Error("A BIP 78 payjoin endpoint must be https, or http on a .onion host.");
}

function parseV2(pjValue, now) {
  const hashIndex = pjValue.indexOf("#");
  if (hashIndex === -1) throw new Error("The pj parameter has no fragment.");
  const urlPart = pjValue.slice(0, hashIndex);
  const fragment = pjValue.slice(hashIndex + 1);
  if (fragment.includes("#")) throw new Error("The pj parameter carries more than one # fragment separator.");
  if (!fragment) throw new Error("The pj parameter has an empty fragment.");
  if (/[a-z]/.test(fragment)) throw new Error("The pj fragment must be uppercase.");
  const hasDash = fragment.includes("-");
  const hasPlus = fragment.includes("+");
  if (hasDash && hasPlus) throw new Error("The pj fragment mixes - and + separators.");
  const delimiter = hasPlus ? "+" : "-";
  const legacyPlus = hasPlus;
  for (const char of fragment) {
    if (!/[0-9A-Z+\-]/.test(char)) throw new Error(`The pj fragment contains an invalid character: ${char}`);
  }
  const parts = fragment.split(delimiter);
  const seen = new Set();
  const params = new Map();
  for (const part of parts) {
    if (!part) throw new Error("The pj fragment contains an empty parameter.");
    const separator = part.lastIndexOf("1");
    if (separator < 1) throw new Error(`The pj fragment parameter is missing its 1 separator: ${part}`);
    const hrp = part.slice(0, separator);
    if (hrp !== "EX" && hrp !== "OH" && hrp !== "RK") throw new Error(`Unknown pj fragment parameter: ${hrp}`);
    if (seen.has(hrp)) throw new Error(`Duplicate pj fragment parameter: ${hrp}`);
    seen.add(hrp);
    params.set(hrp, part);
  }
  for (const key of ["EX", "OH", "RK"]) {
    if (!params.has(key)) throw new Error(`The pj fragment is missing the ${key} parameter.`);
  }
  if (!legacyPlus) {
    const order = parts.map((part) => part.slice(0, part.lastIndexOf("1")));
    for (let i = 1; i < order.length; i++) {
      if (order[i - 1] >= order[i]) {
        throw new Error("The pj fragment parameters must be in lexicographical order (EX, OH, RK).");
      }
    }
  }
  const ex = decodeBech32NoChecksum(params.get("EX"));
  if (ex.hrp !== "EX") throw new Error("The EX parameter has the wrong key.");
  if (ex.bytes.length !== 4) throw new Error("The EX parameter must encode a 4-byte unix time.");
  // EX is a bitcoin consensus encoded u32 (little-endian); WKV8CEC = 0x677C9875 = 1736218741.
  const expiresAt = (ex.bytes[0] | (ex.bytes[1] << 8) | (ex.bytes[2] << 16) | (ex.bytes[3] << 24)) >>> 0;
  const oh = decodeBech32NoChecksum(params.get("OH"));
  if (oh.hrp !== "OH") throw new Error("The OH parameter has the wrong key.");
  if (oh.bytes.length !== 34) throw new Error("The OH parameter must encode a 1-byte key id and a 33-byte compressed public key.");
  const keyId = oh.bytes[0];
  const ohttpPublicKey = oh.bytes.slice(1);
  assertValidCompressedPubkey(ohttpPublicKey, "OH parameter's public key");
  const rk = decodeBech32NoChecksum(params.get("RK"));
  if (rk.hrp !== "RK") throw new Error("The RK parameter has the wrong key.");
  if (rk.bytes.length !== 33) throw new Error("The RK parameter must encode a 33-byte compressed public key.");
  assertValidCompressedPubkey(rk.bytes, "RK parameter");
  let url;
  try {
    url = new URL(urlPart);
  } catch {
    throw new Error("The pj parameter's mailbox URL is not a valid URL.");
  }
  if (url.search) throw new Error("The mailbox URL must not carry a query string.");
  if (url.username || url.password) throw new Error("The mailbox URL must not carry userinfo.");
  if (url.hash) throw new Error("The mailbox URL must not carry a fragment.");
  const scheme = url.protocol.replace(/:$/, "").toLowerCase();
  const host = url.hostname.toLowerCase();
  if (!host) throw new Error("The mailbox URL is missing a host.");
  if (scheme !== "https" && !(scheme === "http" && host.endsWith(".onion"))) {
    throw new Error("The mailbox URL must be https, or http on a .onion host.");
  }
  const segments = url.pathname.split("/").filter(Boolean);
  if (segments.length !== 1) throw new Error("The mailbox URL must have exactly one path segment (the Short ID).");
  const shortId = segments[0];
  if (shortId.length !== 13) throw new Error("The Short ID must be 13 bech32 characters.");
  for (const char of shortId) {
    if (!BECH32_UPPER.includes(char)) throw new Error("The Short ID must be uppercase bech32 characters.");
  }
  const lastWord = BECH32_UPPER.indexOf(shortId[12]);
  if (lastWord & 1) throw new Error("The Short ID has a nonzero padding bit.");
  const warnings = [];
  if (legacyPlus) warnings.push("plus-separator-legacy");
  if (expiresAt < now) warnings.push("expired");
  return {
    directory: { origin: url.origin, host },
    shortId,
    expiresAt,
    ohttp: { keyId, publicKeyHex: bytesToHex(ohttpPublicKey) },
    receiverKeyHex: bytesToHex(rk.bytes),
    warnings,
  };
}

export function decodePayjoinUri(text, now = Math.floor(Date.now() / 1000)) {
  const raw = String(text || "").trim().replace(/^['"]|['"]$/g, "");
  const match = raw.match(/^bitcoin:(?:\/\/)?([^?#]*)(?:\?([^#]*))?(?:#(.*))?$/i);
  if (!match) throw new Error("Not a bitcoin: URI.");
  const address = match[1] || "";
  const query = match[2] || "";
  const literalFragment = match[3];
  const params = parseQuery(query);
  const pjs = params.filter((param) => param.key === "pj");
  if (pjs.length > 1) throw new Error("A bitcoin: URI carries at most one pj parameter.");
  const pj = pjs[0]?.value;
  if (pj === undefined) return { kind: "none" };
  if (literalFragment !== undefined) {
    throw new Error("A payjoin URI must percent-encode # as %23; a literal fragment is not part of the pj value.");
  }
  const { address: checkedAddress, network } = decodeAddress(address);
  const pjoss = params.filter((param) => param.key === "pjos");
  if (pjoss.length > 1) throw new Error("A bitcoin: URI carries at most one pjos parameter.");
  const pjosRaw = pjoss[0]?.value;
  if (pjosRaw !== undefined && pjosRaw !== "0" && pjosRaw !== "1") {
    throw new Error('The pjos parameter must be "0" or "1".');
  }
  const pjos = pjosRaw ?? null;
  const amounts = params.filter((param) => param.key === "amount");
  if (amounts.length > 1) throw new Error("A bitcoin: URI carries at most one amount.");
  const amount = amounts.length
    ? parseBitcoinUri(`bitcoin:?amount=${encodeURIComponent(amounts[0].value)}`).amountSats
    : null;
  if (pj.includes("#")) {
    const v2 = parseV2(pj, now);
    return { kind: "v2", address: checkedAddress, network, amount, pjos, ...v2 };
  }
  const v1 = parseV1Endpoint(pj);
  return {
    kind: "v1",
    address: checkedAddress,
    network,
    amount,
    pjos,
    endpoint: v1.endpoint,
    directory: { origin: v1.origin, host: v1.host },
    warnings: ["v1-direct-endpoint"],
  };
}
