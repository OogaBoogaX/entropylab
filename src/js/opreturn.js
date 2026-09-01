// OP_RETURN detector (and builder) for EntropyLab.
// Parses nulldata outputs in a PSBT, and constructs the minimal-push
// nulldata scripts the PSBT editor's output-script builder emits.
const OP_RETURN = 0x6a;
const OP_PUSHDATA1 = 0x4c;
const OP_PUSHDATA2 = 0x4d;
const OP_PUSHDATA4 = 0x4e;

// Consensus caps a script at 10,000 bytes; the builder refuses earlier than
// that only through this limit, not through the 80-byte standardness policy
// (the editor is a construction tool, not a mempool).
const MAX_SCRIPT_SIZE = 10000;

const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

const utf8Decode = (bytes) => {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
};

function readPushes(script, start) {
  const pushes = [];
  let i = start;
  let pushnum = false;
  while (i < script.length) {
    const op = script[i++];
    if (op === 0x00) {
      pushes.push(new Uint8Array());
      continue;
    }
    if (op <= 0x4b) {
      if (i + op > script.length) return { error: "truncated data push" };
      pushes.push(script.slice(i, i + op));
      i += op;
      continue;
    }
    if (op === OP_PUSHDATA1) {
      if (i >= script.length) return { error: "truncated PUSHDATA1" };
      const length = script[i++];
      if (i + length > script.length) return { error: "truncated PUSHDATA1 payload" };
      pushes.push(script.slice(i, i + length));
      i += length;
      continue;
    }
    if (op === OP_PUSHDATA2) {
      if (i + 2 > script.length) return { error: "truncated PUSHDATA2" };
      const length = script[i] | (script[i + 1] << 8);
      i += 2;
      if (i + length > script.length) return { error: "truncated PUSHDATA2 payload" };
      pushes.push(script.slice(i, i + length));
      i += length;
      continue;
    }
    if (op === OP_PUSHDATA4) return { error: "PUSHDATA4 in OP_RETURN" };
    if (op >= 0x51 && op <= 0x60) {
      pushnum = true;
      pushes.push(Uint8Array.of(op - 0x50));
      continue;
    }
    return { error: "non-push opcode after OP_RETURN" };
  }
  return { pushes, pushnum };
}

function hintPushes(pushes) {
  if (!pushes.length) return null;
  const first = pushes[0];
  if (first.length === 1 && first[0] === 13) return "runes-style (OP_13)";
  const text = utf8Decode(first);
  if (text) {
    const head = text.slice(0, 16);
    if (/^omni/i.test(head)) return "omni-prefix";
    if (/^ord/i.test(head)) return "ord-prefix";
    if (/^RSKBLOCK/i.test(head)) return "rsk-prefix";
  }
  return null;
}

// Minimal data-push encoding, the inverse of the push reader above: the
// smallest legal opcode for the payload length (direct up to 75 bytes, then
// PUSHDATA1 / PUSHDATA2). PUSHDATA4 is never needed under the script cap.
export function encodeDataPush(data) {
  if (!(data instanceof Uint8Array)) throw new Error("A data push needs bytes.");
  let head;
  if (data.length <= 0x4b) head = Uint8Array.of(data.length);
  else if (data.length <= 0xff) head = Uint8Array.of(OP_PUSHDATA1, data.length);
  else if (data.length <= 0xffff) head = Uint8Array.of(OP_PUSHDATA2, data.length & 0xff, data.length >> 8);
  else throw new Error("A data push holds at most 65,535 bytes.");
  const out = new Uint8Array(head.length + data.length);
  out.set(head);
  out.set(data, head.length);
  return out;
}

// Builds an OP_RETURN script carrying the given payloads (one push each).
// A zero-payload call produces the bare OP_RETURN. The result stays under
// the consensus script-size cap; burning policy is the caller's concern.
export function buildOpReturnScript(pushes) {
  const list = Array.isArray(pushes) ? pushes : [pushes];
  let size = 1;
  const parts = [Uint8Array.of(OP_RETURN)];
  for (const push of list) {
    const encoded = encodeDataPush(push);
    size += encoded.length;
    parts.push(encoded);
  }
  if (size > MAX_SCRIPT_SIZE) throw new Error("The script would exceed the 10,000-byte maximum script size.");
  const script = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    script.set(part, offset);
    offset += part.length;
  }
  return script;
}

export function parseOpReturn(script) {
  if (!(script instanceof Uint8Array) || !script.length || script[0] !== OP_RETURN) return null;
  const rest = readPushes(script, 1);
  if (rest.error) {
    return {
      ok: false,
      error: rest.error,
      pushes: [],
      payload: new Uint8Array(),
      payloadBytes: 0,
      pushnum: false,
      hint: null,
    };
  }
  const payload = rest.pushes.length
    ? (() => {
        const out = new Uint8Array(rest.pushes.reduce((sum, part) => sum + part.length, 0));
        let offset = 0;
        for (const part of rest.pushes) {
          out.set(part, offset);
          offset += part.length;
        }
        return out;
      })()
    : new Uint8Array();
  return {
    ok: true,
    error: null,
    pushes: rest.pushes,
    payload,
    payloadBytes: payload.length,
    pushnum: rest.pushnum === true,
    hint: hintPushes(rest.pushes),
  };
}

export function inspectPsbtOpReturns(psbt) {
  const outputs = [];
  const list = psbt?.tx?.outputs || [];
  for (let index = 0; index < list.length; index++) {
    const output = list[index];
    const script = output?.script;
    const parsed = script instanceof Uint8Array ? parseOpReturn(script) : null;
    if (!parsed) continue;
    const amount = typeof output.amount === "bigint" ? output.amount : BigInt(output.amount || 0);
    outputs.push({
      ...parsed,
      output: index,
      amount,
      burned: amount !== 0n,
    });
  }
  return {
    outputs,
    count: outputs.length,
    payloadBytes: outputs.reduce((sum, row) => sum + row.payloadBytes, 0),
    burned: outputs.some((row) => row.burned),
  };
}

export function describeOpReturn(row) {
  const lines = [];
  lines.push(`OP_RETURN · ${row.payloadBytes} byte${row.payloadBytes === 1 ? "" : "s"} · ${row.pushes.length} push${row.pushes.length === 1 ? "" : "es"}`);
  if (row.burned) lines.push(`burns ${row.amount.toString()} sat${row.amount === 1n ? "" : "s"} — output is unspendable`);
  if (row.error) lines.push(`malformed: ${row.error}`);
  if (row.hint) lines.push(`hint: ${row.hint}`);
  if (row.pushnum) lines.push("uses OP_1–OP_16 for a push");
  if (row.ok && row.payloadBytes) {
    const text = utf8Decode(row.payload);
    if (text !== null) {
      const preview = text.length > 160 ? `${text.slice(0, 160)}…` : text;
      lines.push(`text: ${preview}`);
    } else {
      const preview = row.payloadBytes > 40 ? `${bytesToHex(row.payload.slice(0, 40))}…` : bytesToHex(row.payload);
      lines.push(`hex: ${preview}`);
    }
  }
  return lines;
}

export { bytesToHex };
