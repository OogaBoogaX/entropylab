// Public-text QR payloads. Pure: no DOM, no user-facing strings, status
// codes only. A value is returned only for public text of the accepted kind.
// A private key or seed is refused, and the refusal carries no text.
import { createUrCollector } from "./ur-fountain.js";
import { hodlCborBstrRead, watchOnlyTextHasPrivateKey } from "./psbt-ur.js";
import { parseQuery, parseRecipientLine } from "./bip321.js";
import { base58checkDecode } from "./base58.js";

export const TEXT_SCAN_KINDS = Object.freeze(["lightning", "sp", "payment-code", "descriptor", "xpub"]);
export const TEXT_SCAN_MAX_CHARS = 16384;

const NUMS_POINT = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
const PHRASE_COUNTS = new Set([12, 15, 18, 21, 24]);
const STANDARD_DIGITS = new Set([48, 60, 72, 84, 96]);
const COMPACT_HEX = new Set([32, 40, 48, 56, 64]);
const COMPACT_BYTES = new Set([16, 20, 24, 28, 32]);

// 12, 15, 18, 21 or 24 letter-words, in any script, are a seed phrase.
// Japanese BIP39 separates words with an ideographic space (U+3000).
const isSeedPhrase = (text) => {
  const words = text.trim().split(/[\s　]+/u);
  if (!PHRASE_COUNTS.has(words.length)) return false;
  for (const word of words) if (!/^\p{L}+$/u.test(word)) return false;
  return true;
};

const refuse = (status) => ({ status });

// Standard SeedQR: four digits per word, each index 0–2047.
const isStandardSeedQr = (text) => {
  if (!STANDARD_DIGITS.has(text.length) || !/^\d+$/.test(text)) return false;
  for (let i = 0; i < text.length; i += 4) {
    if (Number(text.slice(i, i + 4)) > 2047) return false;
  }
  return true;
};

// Compact SeedQR: entropy as hex (12–24 words), or the byte-mode payload when
// it survived UTF-8 decoding and is not printable text. The NUMS point is the
// one 64-hex value that is not a key.
const isCompactSeedQr = (text) => {
  if (/^[0-9a-fA-F]+$/.test(text) && COMPACT_HEX.has(text.length)) return text.toLowerCase() !== NUMS_POINT;
  if (!COMPACT_BYTES.has(text.length)) return false;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code < 0x20 || code > 0x7e) return true;
  }
  return false;
};

const hasScannedSecret = (text) => watchOnlyTextHasPrivateKey(text) || isSeedPhrase(text) || isStandardSeedQr(text) || isCompactSeedQr(text);

const parenthesesBalance = (text) => {
  let depth = 0;
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (char === "(") depth += 1;
    else if (char === ")") {
      depth -= 1;
      if (depth < 0) return false;
    }
  }
  return depth === 0;
};

// Secret first, on every kind, so a scanned seed is never reported as merely
// the wrong shape. Empty and over-long text are refused after that.
const screened = (raw) => {
  const text = String(raw ?? "").trim();
  if (hasScannedSecret(text)) return refuse("private-key");
  if (!text) return refuse("wrong-kind");
  if (text.length > TEXT_SCAN_MAX_CHARS) return refuse("too-large");
  return { status: "ok", text };
};

export function classifyLightningText(raw) {
  const gate = screened(raw);
  if (gate.status !== "ok") return gate;
  let candidate = gate.text;
  const prefixed = /^lightning:(?:\/\/)?(.*)$/i.exec(candidate);
  if (prefixed) candidate = prefixed[1];
  else if (/^bitcoin:/i.test(candidate)) {
    const query = /^bitcoin:(?:\/\/)?[^?]*\?([^#]*)/i.exec(candidate);
    if (!query) return refuse("wrong-kind");
    let params;
    try {
      params = parseQuery(query[1]);
    } catch {
      return refuse("wrong-kind");
    }
    if (params.some((item) => item.key.startsWith("req-"))) return refuse("wrong-kind");
    const chosen = params.find((item) => item.key === "lightning") || params.find((item) => item.key === "lno");
    if (!chosen) return refuse("wrong-kind");
    candidate = chosen.value;
  }
  if (hasScannedSecret(candidate)) return refuse("private-key");
  if (/\s/.test(candidate) || !/^[0-9a-z+]+$/i.test(candidate)) return refuse("wrong-kind");
  const lower = candidate.toLowerCase();
  if (!/^ln(bc|tb|tbs|bcrt)/.test(lower) && !/^ln[ori]/.test(lower)) return refuse("wrong-kind");
  return { status: "ok", text: candidate };
}

export function classifySpText(raw) {
  const gate = screened(raw);
  if (gate.status !== "ok") return gate;
  const text = gate.text;
  if (/\s/.test(text)) return refuse("wrong-kind");
  try {
    parseRecipientLine(text);
  } catch {
    return refuse("wrong-kind");
  }
  return { status: "ok", text };
}

export function classifyPaymentCodeText(raw) {
  const gate = screened(raw);
  if (gate.status !== "ok") return gate;
  const text = gate.text;
  if (/\s/.test(text) || !/^[1-9A-HJ-NP-Za-km-z]+$/.test(text)) return refuse("wrong-kind");
  try {
    const bytes = base58checkDecode(text);
    if (bytes.length !== 81 || bytes[0] !== 0x47) return refuse("wrong-kind");
  } catch {
    return refuse("wrong-kind");
  }
  return { status: "ok", text };
}

export function classifyDescriptorText(raw) {
  const gate = screened(raw);
  if (gate.status !== "ok") return gate;
  const text = gate.text;
  if (/\s/.test(text) || !/^[\x21-\x7e]+$/.test(text) || !/^[a-z_]+\(/.test(text)) return refuse("wrong-kind");
  const body = text.replace(/#[a-z0-9]{8}$/, "");
  if (!body.endsWith(")") || !parenthesesBalance(body)) return refuse("wrong-kind");
  return { status: "ok", text };
}

// One extended public key, with an optional origin and derivation suffix.
// The key is capture 3: capture 2 is only the origin's last path step.
const XPUB_TEXT = /^(\[[0-9a-fA-F]{8}(\/\d+['hH]?)*\])?((?:xpub|tpub|ypub|zpub|upub|vpub|Ypub|Zpub|Upub|Vpub)[1-9A-HJ-NP-Za-km-z]{107,108})(\/(\d+['hH]?|\*|<\d+;\d+>))*$/;

export function classifyXpubText(raw) {
  const gate = screened(raw);
  if (gate.status !== "ok") return gate;
  const matched = XPUB_TEXT.exec(gate.text);
  if (!matched) return refuse("wrong-kind");
  let decoded = null;
  let publicKey = false;
  try {
    decoded = base58checkDecode(matched[3]);
    publicKey = decoded.length === 78 && (decoded[45] === 0x02 || decoded[45] === 0x03);
  } catch {
    publicKey = false;
  } finally {
    try { decoded?.fill?.(0); } catch {}
  }
  if (!publicKey) return refuse("wrong-kind");
  return { status: "ok", text: gate.text };
}

const CLASSIFIERS = {
  lightning: classifyLightningText,
  sp: classifySpText,
  "payment-code": classifyPaymentCodeText,
  descriptor: classifyDescriptorText,
  xpub: classifyXpubText,
};

export function classifyText(kind, raw) {
  const classify = CLASSIFIERS[kind];
  if (!classify) throw new Error("Unknown text scan kind.");
  return classify(raw);
}

// The silent-payment field appends one recipient line. Same address, however
// the existing line was written, is refused and the field is left unchanged.
export function appendRecipient(existing, line) {
  const address = parseRecipientLine(line)[0].address;
  for (const row of String(existing ?? "").split(/\r?\n/)) {
    const item = row.trim();
    if (!item) continue;
    try {
      if (parseRecipientLine(item)[0].address === address) return refuse("already-listed");
    } catch {
      // A line the field cannot parse is not this recipient.
    }
  }
  const prior = String(existing ?? "");
  if (!prior.trim()) return { status: "ok", value: line };
  return { status: "ok", value: prior.replace(/\s+$/, "") + "\n" + line };
}

const refusal = (status) => ({ status });

export function createTextQrReader({ accept, maxChars = TEXT_SCAN_MAX_CHARS } = {}) {
  if (!TEXT_SCAN_KINDS.includes(accept)) throw new Error("Unknown text scan kind.");
  const limit = Number.isInteger(maxChars) && maxChars > 0 ? maxChars : TEXT_SCAN_MAX_CHARS;
  const collector = accept === "descriptor" ? createUrCollector({ types: ["bytes"], maxMessageLen: limit + 16 }) : null;
  let done = false;

  const reset = () => {
    if (collector) collector.reset();
    done = false;
  };

  const acceptUrMessage = (message) => {
    let bytes = null;
    let decoded = null;
    let failed = null;
    try {
      let end = -1;
      try {
        const read = hodlCborBstrRead(message, 0);
        bytes = read[0];
        end = read[1];
      } catch {
        failed = "bad-cbor";
      }
      if (!failed && end !== message.length) failed = "bad-cbor";
      if (!failed) {
        try {
          decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        } catch {
          failed = "wrong-kind";
        }
      }
    } finally {
      try { bytes?.fill?.(0); } catch {}
      try { message?.fill?.(0); } catch {}
    }
    if (failed) {
      try { collector.reset(); } catch {}
      return refusal(failed);
    }
    const classified = classifyDescriptorText(decoded);
    if (classified.status !== "ok") {
      try { collector.reset(); } catch {}
      return refusal(classified.status);
    }
    done = true;
    return { status: "complete", text: classified.text };
  };

  const receiveUr = (text) => {
    let result = null;
    try {
      result = collector.receive(text);
    } catch {
      result = null;
    }
    if (!result || typeof result !== "object") return refusal("bad-part");
    if (result.status === "complete") return acceptUrMessage(result.message);
    switch (result.status) {
      case "progress":
      case "duplicate":
        return { status: "partial" };
      case "wrong-type":
        return refusal("unsupported-format");
      case "mismatch":
      case "conflict":
        return refusal("mismatch");
      case "too-large":
        return refusal("too-large");
      case "done":
        return { status: "done" };
      default:
        return refusal("bad-part");
    }
  };

  const receive = (text) => {
    if (done) return { status: "done" };
    if (typeof text !== "string") return refusal("wrong-kind");
    const trimmed = text.trim();
    if (/^ur:/i.test(trimmed)) {
      if (accept !== "descriptor") return refusal("unsupported-format");
      return receiveUr(trimmed);
    }
    if (/^B\$/.test(trimmed)) return refusal("unsupported-format");
    const result = classifyText(accept, trimmed);
    if (result.status === "ok") {
      done = true;
      return { status: "complete", text: result.text };
    }
    return refusal(result.status);
  };

  const progress = () => {
    if (done || !collector) return null;
    const state = collector.state();
    if (!state || state.seqLen == null) return null;
    return { received: state.received, total: state.seqLen };
  };

  return { receive, progress, reset };
}
