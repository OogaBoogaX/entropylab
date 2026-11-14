// Unified anti-exfil transcript reader.
// Pure module: no DOM, no shared state, no curve math.

import * as jade from "./anti-exfil-adapters/jade.js";
import * as bitbox02 from "./anti-exfil-adapters/bitbox02.js";
import * as aexb from "./anti-exfil-adapters/aexb.js";
import { s2cSignatureMatches } from "./s2c.js";

const JADE_BITBOX_WARNING =
  "This reads as a Jade host nonce \u03C1 or a BitBox02 host nonce. Both are checked the same way. From a BitBox02, paste the host nonce, not its SHA-256 commitment.";

function tokenize(input) {
  const text = String(input).replace(/0x/gi, "");
  return text.split(/[^0-9a-fA-F]+/).filter((token) => token.length);
}

function isHexText(input) {
  const text = String(input).replace(/0x/gi, "").trim();
  if (!text) return false;
  return /^[0-9a-fA-F\s\-_,;:.]+$/.test(text);
}

function aexbMessageList(input) {
  const text = String(input).trim();
  if (!text) return null;
  const withoutPrefix = text.startsWith("0x") || text.startsWith("0X") ? text.slice(2) : text;
  const magic = /^(41455842|41455854)/i;
  if (!magic.test(withoutPrefix)) return null;
  const messages = [];
  for (const token of text.split(/\s+/)) {
    if (!token) continue;
    const clean = token.startsWith("0x") || token.startsWith("0X") ? token.slice(2) : token;
    if (magic.test(clean)) messages.push(clean);
    else if (messages.length) messages[messages.length - 1] += clean;
    else return null;
  }
  return messages.length ? messages : null;
}

// True when the input, or its hex-decoded bytes, starts with the AEXB or AEXT
// magic. Mirrors aexb.js's toBytes() so a truncated AEXB/AEXT message is
// reported with its own decode error instead of the Jade parser's.
function aexbMagic(input) {
  const text = String(input).trim();
  if (!text) return false;
  const compact = text.replace(/\s+/g, "");
  const hex = compact.startsWith("0x") || compact.startsWith("0X") ? compact.slice(2) : compact;
  let bytes;
  if (hex.length > 0 && hex.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(hex)) {
    bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  } else {
    bytes = new TextEncoder().encode(text);
  }
  if (bytes.length < 4) return false;
  const magic = String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3]);
  return magic === "AEXB" || magic === "AEXT";
}

function bitboxTranscript(normalized) {
  return {
    host: normalized.host,
    openings: normalized.openings,
    commitment: normalized.commitment,
    commitmentMatches: normalized.commitmentMatches,
  };
}

export function readAntiExfil(input) {
  if (!input || !String(input).trim()) return null;

  // Input that starts with the AEXB/AEXT magic is read as the messages of one
  // session. When they do not decode, the other adapters still get their
  // turn: a Jade or BitBox02 host nonce can start with the same four bytes.
  let aexbListError = null;
  const messages = aexbMessageList(input);
  if (messages) {
    const decoded = [];
    for (let index = 0; index < messages.length && !aexbListError; index++) {
      try {
        decoded.push(aexb.normalize(messages[index]).decoded);
      } catch (error) {
        const message = error.message || String(error);
        aexbListError = messages.length === 1 ? message : `Message ${index + 1}: ${message}`;
      }
    }
    if (!aexbListError) return {
      kind: "aexb",
      transcript: { kind: "aexb", decoded: decoded[0], messages: decoded },
      candidates: ["aexb"],
      warning: null,
      warningCode: null,
    };
  }

  const errors = {};
  const detected = {};
  for (const [name, adapter] of [["jade", jade], ["bitbox02", bitbox02], ["aexb", aexb]]) {
    try {
      detected[name] = adapter.detect(input) === true;
    } catch {
      detected[name] = false;
    }
  }

  if (detected.aexb) {
    try {
      const normalized = aexb.normalize(input);
      return {
        kind: "aexb",
        transcript: { kind: "aexb", decoded: normalized.decoded },
        candidates: ["aexb"],
        warning: null,
        warningCode: null,
      };
    } catch (error) {
      errors.aexb = error.message || String(error);
    }
  }

  const tokens = tokenize(input);
  const thirtyTwo = tokens.filter((token) => token.length === 64).length;
  const openings = tokens.filter((token) => token.length === 66).length;
  const combined = tokens.some((token) => token.length === 130);

  if (!combined && thirtyTwo === 2 && openings === 1 && detected.bitbox02) {
    try {
      const normalized = bitbox02.normalize(input);
      return {
        kind: "bitbox02",
        transcript: bitboxTranscript(normalized),
        candidates: ["bitbox02"],
        warning: null,
        warningCode: null,
      };
    } catch (error) {
      errors.bitbox02 = error.message || String(error);
    }
  }

  if (detected.jade) {
    try {
      const normalized = jade.normalize(input);
      return {
        kind: "jade",
        transcript: { host: normalized.host, openings: normalized.openings },
        candidates: ["jade", "bitbox02"],
        warning: JADE_BITBOX_WARNING,
        warningCode: "jade-or-bitbox02",
      };
    } catch (error) {
      errors.jade = error.message || String(error);
    }
  }

  if (detected.bitbox02) {
    try {
      const normalized = bitbox02.normalize(input);
      return {
        kind: "bitbox02",
        transcript: bitboxTranscript(normalized),
        candidates: ["bitbox02"],
        warning: null,
        warningCode: null,
      };
    } catch (error) {
      errors.bitbox02 = error.message || String(error);
    }
  }

  for (const [name, adapter] of [["jade", jade], ["bitbox02", bitbox02], ["aexb", aexb]]) {
    if (errors[name]) continue;
    try {
      adapter.normalize(input);
    } catch (error) {
      errors[name] = error.message || String(error);
    }
  }

  // An AEXB/AEXT message that failed to decode is reported with its own
  // adapter's error: the Jade parser's message names the wrong format and
  // hides the real decode failure.
  const error = aexbListError
    ? aexbListError
    : aexbMagic(input) && errors.aexb
    ? errors.aexb
    : isHexText(input) && errors.jade
      ? errors.jade
      : errors.jade || errors.bitbox02 || errors.aexb || "Unrecognized anti-exfil transcript.";

  return { kind: null, transcript: null, candidates: [], warning: null, warningCode: null, error };
}

export function checkAntiExfilSignature(r32, transcript) {
  if (transcript && (transcript.kind === "aexb" || transcript.decoded)) {
    throw new Error("AEXB transcripts are verified with aexbVerify");
  }
  if (!transcript || !Array.isArray(transcript.openings)) return false;
  for (const opening of transcript.openings) {
    if (s2cSignatureMatches(r32, opening, transcript.host)) return true;
  }
  return false;
}
