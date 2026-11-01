// The PSBT QR payload reader (preview builds only). Pure: no DOM, no camera,
// no user-facing strings (status codes only). It accepts either one static QR
// holding the whole PSBT (base64 or hex) or an animated UR (crypto-psbt or
// psbt) whose CBOR byte string wraps the PSBT.
//
// Security contract: only bytes that start with the PSBT magic are ever
// returned as complete; every other text is refused with a status code, and
// the collector's message copy is zeroed as soon as it has been unwrapped.

import { createUrCollector } from "./ur-fountain.js";
import { hodlCborUnwrapPsbt } from "./psbt-ur.js";
import { isPsbtMagic } from "./tx.js";

const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const HEX = /^[0-9a-fA-F]+$/;
const PSBT_HEX_MAGIC = /^70736274ff/i;
const DEFAULT_MAX_BYTES = 1048576;

const decodeBase64 = (text) => {
  if (!BASE64.test(text) || text.length % 4 === 1) return null;
  try {
    const binary = atob(text);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
};

const decodeHex = (text) => {
  if (text.length % 2 !== 0 || !HEX.test(text) || !PSBT_HEX_MAGIC.test(text)) return null;
  const bytes = new Uint8Array(text.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return bytes;
};

// The same unwrap as the paste path: tag 310 (crypto-psbt), tag 40310 (psbt)
// or a bare byte string, with no trailing bytes. Anything else is refused.
const unwrapCborBytes = (message) => {
  if (!(message instanceof Uint8Array) || message.length < 1) return null;
  try {
    return hodlCborUnwrapPsbt(message);
  } catch {
    return null;
  }
};

export function createPsbtQrReader({ maxBytes = DEFAULT_MAX_BYTES } = {}) {
  const limit = Number.isInteger(maxBytes) && maxBytes > 0 ? maxBytes : DEFAULT_MAX_BYTES;
  const collector = createUrCollector({ types: ["crypto-psbt", "psbt"], maxMessageLen: limit });
  let done = false;
  let terminal = null;

  const reset = () => {
    collector.reset();
    done = false;
    terminal = null;
  };

  const accept = (bytes) => {
    if (!(bytes instanceof Uint8Array) || !isPsbtMagic(bytes)) {
      try { bytes?.fill?.(0); } catch {}
      return { status: "not-psbt" };
    }
    if (bytes.length > limit) {
      try { bytes.fill(0); } catch {}
      return { status: "too-large" };
    }
    done = true;
    return { status: "complete", bytes };
  };

  const receiveUr = (text) => {
    let result = null;
    try {
      result = collector.receive(text);
    } catch {
      result = null;
    }
    if (!result || typeof result !== "object") return { status: "bad-part" };
    if (result.status === "complete") {
      const message = result.message;
      let bytes = null;
      try {
        bytes = unwrapCborBytes(message);
      } finally {
        try { message?.fill?.(0); } catch {}
      }
      if (!bytes) {
        // The collector is spent; a fresh scan starts on the next part.
        collector.reset();
        return { status: "bad-cbor" };
      }
      const accepted = accept(bytes);
      if (accepted.status !== "complete") collector.reset();
      return accepted;
    }
    switch (result.status) {
      case "progress":
      case "duplicate":
        return { status: "partial" };
      case "wrong-type":
        return { status: "wrong-type" };
      case "conflict":
        terminal = "mismatch";
        return { status: terminal };
      case "mismatch":
        return { status: "mismatch" };
      case "too-large":
        return { status: "too-large" };
      case "done":
        return { status: "done" };
      case "invalid":
        terminal = "bad-part";
        return { status: terminal };
      case "bad-part":
      case "legacy":
      default:
        return { status: "bad-part" };
    }
  };

  const receiveStatic = (text) => {
    const base64 = decodeBase64(text);
    if (base64) {
      if (isPsbtMagic(base64)) return accept(base64);
      try { base64.fill(0); } catch {}
    }
    const hex = decodeHex(text);
    if (hex) return accept(hex);
    return { status: "not-psbt" };
  };

  const receive = (text) => {
    if (terminal) return { status: terminal };
    if (done) return { status: "done" };
    if (typeof text !== "string") return { status: "not-psbt" };
    const trimmed = text.trim();
    if (/^ur:/i.test(trimmed)) return receiveUr(trimmed);
    return receiveStatic(trimmed);
  };

  const progress = () => {
    if (done) return null;
    const state = collector.state();
    if (!state || state.seqLen == null) return null;
    return { received: state.received, total: state.seqLen };
  };

  return { receive, progress, reset };
}
