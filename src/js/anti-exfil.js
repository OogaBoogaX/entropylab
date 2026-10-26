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

  const error = isHexText(input) && errors.jade
    ? errors.jade
    : errors.jade || errors.bitbox02 || errors.aexb || "Unrecognized anti-exfil transcript.";

  return { kind: null, transcript: null, candidates: [], warning: null, error };
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
