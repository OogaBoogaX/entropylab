// Inscription envelope detector for EntropyLab.
// Parses OP_FALSE OP_IF "ord" … OP_ENDIF in scripts and PSBT witnesses.
// Does not create inscriptions, number sats, or talk to a node.
const PROTOCOL_ID = Uint8Array.of(0x6f, 0x72, 0x64); // "ord"
const OP_IF = 0x63;
const OP_ENDIF = 0x68;
const OP_PUSHDATA1 = 0x4c;
const OP_PUSHDATA2 = 0x4d;
const OP_PUSHDATA4 = 0x4e;
const KNOWN_TAGS = {
  1: "content-type",
  2: "pointer",
  3: "parent",
  5: "metadata",
  7: "metaprotocol",
  9: "content-encoding",
  11: "delegate",
  13: "rune",
  15: "note",
  17: "properties",
  19: "property-encoding",
  66: "unbound",
  255: "nop",
};

const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const equalBytes = (a, b) => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
};
const concatBytes = (...parts) => {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};
const utf8Decode = (bytes) => {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
};
const leInteger = (bytes) => {
  let value = 0n;
  for (let i = 0; i < bytes.length; i++) value |= BigInt(bytes[i]) << BigInt(8 * i);
  return value;
};
const tagNumber = (bytes) => {
  if (!bytes.length) return null;
  if (bytes.length === 1) return bytes[0];
  if (bytes.length > 8) return null;
  const value = leInteger(bytes);
  return value <= 0xffffn ? Number(value) : null;
};

export function tokenizeScript(script) {
  if (!(script instanceof Uint8Array)) return { tokens: [], error: "script must be bytes" };
  const tokens = [];
  let i = 0;
  while (i < script.length) {
    const op = script[i++];
    if (op === 0x00) {
      tokens.push({ type: "push", bytes: new Uint8Array(), pushnum: false });
      continue;
    }
    if (op <= 0x4b) {
      if (i + op > script.length) return { tokens, error: "truncated data push" };
      tokens.push({ type: "push", bytes: script.slice(i, i + op), pushnum: false });
      i += op;
      continue;
    }
    if (op === OP_PUSHDATA1) {
      if (i >= script.length) return { tokens, error: "truncated PUSHDATA1" };
      const length = script[i++];
      if (i + length > script.length) return { tokens, error: "truncated PUSHDATA1 payload" };
      tokens.push({ type: "push", bytes: script.slice(i, i + length), pushnum: false, pushdata: 1 });
      i += length;
      continue;
    }
    if (op === OP_PUSHDATA2) {
      if (i + 2 > script.length) return { tokens, error: "truncated PUSHDATA2" };
      const length = script[i] | (script[i + 1] << 8);
      i += 2;
      if (i + length > script.length) return { tokens, error: "truncated PUSHDATA2 payload" };
      tokens.push({ type: "push", bytes: script.slice(i, i + length), pushnum: false, pushdata: 2 });
      i += length;
      continue;
    }
    if (op === OP_PUSHDATA4) {
      return { tokens, error: "PUSHDATA4 is not valid in tapscript envelopes" };
    }
    if (op >= 0x51 && op <= 0x60) {
      tokens.push({ type: "push", bytes: Uint8Array.of(op - 0x50), pushnum: true });
      continue;
    }
    if (op === 0x4f) {
      tokens.push({ type: "push", bytes: Uint8Array.of(0x81), pushnum: true });
      continue;
    }
    tokens.push({ type: "op", op });
  }
  return { tokens };
}

function fieldsFromPayload(payload) {
  const fields = [];
  let bodyStart = payload.length;
  for (let i = 0; i < payload.length; i++) {
    if (payload[i].length === 0) {
      bodyStart = i + 1;
      break;
    }
    if (i + 1 >= payload.length) {
      fields.push({ tag: payload[i], value: null, incomplete: true });
      bodyStart = payload.length;
      break;
    }
    fields.push({ tag: payload[i], value: payload[i + 1], incomplete: false });
    i += 1;
  }
  const bodyChunks = payload.slice(bodyStart);
  const byTag = new Map();
  for (const field of fields) {
    if (!field.value) continue;
    const key = bytesToHex(field.tag);
    const list = byTag.get(key) || [];
    list.push(field);
    byTag.set(key, list);
  }
  const take = (n) => {
    const list = byTag.get(n.toString(16).padStart(2, "0")) || byTag.get(bytesToHex(Uint8Array.of(n)));
    if (!list || !list.length) return null;
    return list[list.length - 1].value;
  };
  const contentType = take(1);
  const encoding = take(9);
  const metaprotocol = take(7);
  const pointer = take(2);
  const parent = take(3);
  const delegate = take(11);
  const metadata = take(5);
  const rune = take(13);
  let duplicate = false;
  for (const list of byTag.values()) if (list.length > 1) duplicate = true;
  let unrecognizedEven = false;
  for (const field of fields) {
    if (!field.tag.length) continue;
    const n = tagNumber(field.tag);
    if (n === null) continue;
    if (n % 2 === 0 && !(n in KNOWN_TAGS)) unrecognizedEven = true;
  }
  const incomplete = fields.some((field) => field.incomplete);
  const body = bodyChunks.length ? concatBytes(...bodyChunks) : new Uint8Array();
  return {
    contentType: contentType ? utf8Decode(contentType) || bytesToHex(contentType) : null,
    contentEncoding: encoding ? utf8Decode(encoding) || bytesToHex(encoding) : null,
    metaprotocol: metaprotocol ? utf8Decode(metaprotocol) || bytesToHex(metaprotocol) : null,
    pointer: pointer ? leInteger(pointer) : null,
    parent: parent ? inscriptionIdFromBytes(parent) : null,
    delegate: delegate ? inscriptionIdFromBytes(delegate) : null,
    metadataBytes: metadata ? metadata.length : 0,
    rune: rune ? bytesToHex(rune) : null,
    body,
    bodyBytes: body.length,
    duplicate,
    incomplete,
    unrecognizedEven,
  };
}

export function inscriptionIdFromBytes(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 32) return null;
  const txid = bytesToHex(bytes.slice(0, 32).slice().reverse());
  const indexBytes = bytes.slice(32);
  const index = indexBytes.length ? Number(leInteger(indexBytes)) : 0;
  return `${txid}i${index}`;
}

export function parseEnvelopes(script) {
  const { tokens, error } = tokenizeScript(script);
  const envelopes = [];
  if (!tokens.length) return { envelopes, error: error || null };
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    const next = tokens[i + 1];
    if (!(token.type === "push" && token.bytes.length === 0 && next && next.type === "op" && next.op === OP_IF)) continue;
    const protocol = tokens[i + 2];
    if (!(protocol && protocol.type === "push" && equalBytes(protocol.bytes, PROTOCOL_ID))) continue;
    const payload = [];
    let pushnum = protocol.pushnum === true;
    let j = i + 3;
    let closed = false;
    for (; j < tokens.length; j++) {
      const item = tokens[j];
      if (item.type === "op" && item.op === OP_ENDIF) {
        closed = true;
        break;
      }
      if (item.type === "push") {
        if (item.pushnum) pushnum = true;
        payload.push(item.bytes);
        continue;
      }
      closed = false;
      break;
    }
    if (!closed) continue;
    const parsed = fieldsFromPayload(payload);
    parsed.pushnum = pushnum;
    parsed.payloadBytes = payload.reduce((sum, chunk) => sum + chunk.length, 0);
    envelopes.push(parsed);
    i = j;
  }
  return { envelopes, error: error || null };
}

// Witness stacks use full Bitcoin CompactSize item lengths: an inscription
// carrying media puts its tap-leaf script in a single item, so lengths above
// 64 KiB (0xfe/0xff encodings) are normal, not errors. The strict variant
// throws on malformed data; the exported parseWitness stays tolerant and
// returns an empty stack, while callers that report scan coverage use the
// strict one so a skipped witness can never look like a completed scan.
function parseWitnessStrict(bytes) {
  if (!(bytes instanceof Uint8Array) || !bytes.length) return [];
  let offset = 0;
  const readVarInt = () => {
    if (offset >= bytes.length) throw new Error("witness ended early");
    const first = bytes[offset];
    if (first < 0xfd) {
      offset += 1;
      return first;
    }
    if (first === 0xfd) {
      if (offset + 3 > bytes.length) throw new Error("witness ended inside compact size");
      const value = bytes[offset + 1] | (bytes[offset + 2] << 8);
      offset += 3;
      return value;
    }
    if (first === 0xfe) {
      if (offset + 5 > bytes.length) throw new Error("witness ended inside compact size");
      const value = (bytes[offset + 1] | (bytes[offset + 2] << 8) | (bytes[offset + 3] << 16) | (bytes[offset + 4] << 24)) >>> 0;
      if (value <= 0xffff) throw new Error("non-canonical witness compact size");
      offset += 5;
      return value;
    }
    if (offset + 9 > bytes.length) throw new Error("witness ended inside compact size");
    let value = 0n;
    for (let i = 1; i <= 8; i++) value |= BigInt(bytes[offset + i]) << BigInt(8 * (i - 1));
    if (value <= 0xffffffffn || value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("non-canonical witness compact size");
    offset += 9;
    return Number(value);
  };
  const count = readVarInt();
  const stack = [];
  for (let i = 0; i < count; i++) {
    const length = readVarInt();
    if (offset + length > bytes.length) throw new Error("witness item overruns buffer");
    stack.push(bytes.slice(offset, offset + length));
    offset += length;
  }
  return stack;
}

export function parseWitness(bytes) {
  try {
    return parseWitnessStrict(bytes);
  } catch {
    return [];
  }
}

function taprootWitnessScriptCandidates(stack) {
  if (!stack.length) return [];
  const items = stack.slice();
  if (items[items.length - 1][0] === 0x50) items.pop();
  if (items.length >= 2) return [items[items.length - 2], ...items];
  return items;
}

export function scriptsFromPsbtInput(entries, errors) {
  const scripts = [];
  if (!Array.isArray(entries)) return scripts;
  for (const entry of entries) {
    if (entry.type === 21 && entry.val && entry.val.length >= 2) {
      scripts.push({ source: "tap-leaf", script: entry.val.slice(0, entry.val.length - 1) });
    } else if (entry.type === 8 && entry.val) {
      let stack;
      try {
        stack = parseWitnessStrict(entry.val);
      } catch (exception) {
        // A malformed witness is a coverage gap, not an empty result.
        errors?.push(exception.message || String(exception));
        continue;
      }
      for (const script of taprootWitnessScriptCandidates(stack)) scripts.push({ source: "final-witness", script });
    } else if (entry.type === 5 && entry.val) {
      scripts.push({ source: "witness-script", script: entry.val });
    } else if (entry.type === 7 && entry.val) {
      scripts.push({ source: "final-scriptsig", script: entry.val });
    }
  }
  return scripts;
}

export function inspectPsbtInscriptions(psbt) {
  const inputs = [];
  const errors = [];
  let envelopeIndex = 0;
  const list = psbt?.inputs || [];
  for (let input = 0; input < list.length; input++) {
    const found = [];
    const seen = new Set();
    try {
      for (const item of scriptsFromPsbtInput(list[input], errors)) {
        const { envelopes, error } = parseEnvelopes(item.script);
        // A tokenizer fault truncates this script's scan; report the
        // coverage gap instead of claiming a completed scan.
        if (error) errors.push(error);
        for (const envelope of envelopes) {
          const key = `${envelope.contentType}|${envelope.bodyBytes}|${bytesToHex(envelope.body.slice(0, 32))}`;
          if (seen.has(key)) continue;
          seen.add(key);
          found.push({
            ...envelope,
            source: item.source,
            input,
            envelopeIndex: envelopeIndex++,
          });
        }
      }
    } catch (exception) {
      // A malformed witness must not wipe the rest of the PSBT report.
      errors.push(exception?.message || String(exception));
    }
    inputs.push({ input, envelopes: found });
  }
  return {
    inputs,
    envelopes: inputs.flatMap((row) => row.envelopes),
    incomplete: errors.length > 0,
    errors,
  };
}

export function describeEnvelope(envelope) {
  const lines = [];
  const type = envelope.contentType || "(no content-type)";
  lines.push(`${type} · ${envelope.bodyBytes} byte${envelope.bodyBytes === 1 ? "" : "s"}`);
  if (envelope.contentEncoding) lines.push(`encoding ${envelope.contentEncoding}`);
  if (envelope.metaprotocol) lines.push(`metaprotocol ${envelope.metaprotocol}`);
  if (envelope.pointer !== null && envelope.pointer !== undefined) lines.push(`pointer ${envelope.pointer.toString()}`);
  if (envelope.parent) lines.push(`parent ${envelope.parent}`);
  if (envelope.delegate) lines.push(`delegate ${envelope.delegate}`);
  if (envelope.metadataBytes) lines.push(`metadata ${envelope.metadataBytes} bytes`);
  if (envelope.rune) lines.push(`rune ${envelope.rune}`);
  if (envelope.unrecognizedEven) lines.push("unrecognized even field — ordinals treat this as unbound");
  if (envelope.duplicate) lines.push("duplicate field");
  if (envelope.incomplete) lines.push("incomplete field");
  if (envelope.pushnum) lines.push("uses OP_1–OP_16 for a push (historically cursed)");
  const media = (envelope.contentType || "").toLowerCase();
  if (media.startsWith("image/") || media.startsWith("audio/") || media.startsWith("video/") || media === "application/octet-stream") {
    lines.push("binary payload is not rendered");
  } else if (media.startsWith("text/") || media === "application/json" || media === "application/yaml") {
    const text = utf8Decode(envelope.body);
    if (text !== null) {
      const preview = text.length > 280 ? `${text.slice(0, 280)}…` : text;
      lines.push(`text: ${preview}`);
    } else lines.push("body is not valid UTF-8");
  }
  return lines;
}

export { PROTOCOL_ID, concatBytes, bytesToHex };
