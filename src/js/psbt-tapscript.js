// Taproot script-path inspect: control block, NUMS, annex, opcode dump.

export function hodlControlBlock(bytes) {
  if (!bytes || bytes.length < 33 || (bytes.length - 33) % 32) return null;
  const nodes = [];
  for (let offset = 33; offset < bytes.length; offset += 32) nodes.push(bytes.slice(offset, offset + 32));
  return {
    leafVersion: bytes[0] & 0xfe,
    parity: bytes[0] & 1,
    internalKey: bytes.slice(1, 33),
    nodes,
    raw: bytes,
  };
}

export function hodlIsNumsKey(key, nums, hodlEq) {
  return !!(key && key.length === 32 && nums && hodlEq(key, nums));
}

export function hodlTapInternalKey(entries, hodlFind) {
  const entry = hodlFind(entries, 23).find((item) => item.keydata.length === 0);
  if (!entry) return null;
  if (entry.val.length !== 32) throw new Error("A Taproot internal key field is malformed.");
  return entry.val;
}

export function hodlTapMerkleRoot(entries, hodlFind) {
  const entry = hodlFind(entries, 24).find((item) => item.keydata.length === 0);
  if (!entry) return null;
  if (entry.val.length !== 32) throw new Error("A Taproot merkle root field is malformed.");
  return entry.val;
}

export function hodlTapLeafScripts(entries, hodlFind) {
  return hodlFind(entries, 21).map((entry) => {
    if (!entry.val.length) throw new Error("A Taproot leaf script field is empty.");
    return {
      control: hodlControlBlock(entry.keydata),
      leafVersion: entry.val[entry.val.length - 1],
      script: entry.val.slice(0, -1),
    };
  });
}

export function hodlOpcodeName(code) {
  if (code === 0) return "OP_0";
  if (code === 79) return "OP_1NEGATE";
  if (code === 81) return "OP_1";
  if (code >= 82 && code <= 96) return "OP_" + (code - 80);
  const names = {
    99: "OP_IF", 100: "OP_NOTIF", 103: "OP_ELSE", 104: "OP_ENDIF",
    105: "OP_VERIFY", 106: "OP_RETURN", 117: "OP_DROP", 118: "OP_DUP",
    135: "OP_EQUAL", 136: "OP_EQUALVERIFY", 169: "OP_HASH160", 170: "OP_HASH256",
    172: "OP_CHECKSIG", 173: "OP_CHECKSIGVERIFY", 186: "OP_CHECKSIGADD",
  };
  return names[code] || "OP_UNKNOWN_" + code;
}

export function hodlDisasmTapscript(script) {
  const tokens = [];
  let offset = 0;
  while (offset < script.length) {
    const opcode = script[offset++];
    if (opcode > 0 && opcode <= 75) {
      if (offset + opcode > script.length) { tokens.push("PUSH(truncated)"); break; }
      tokens.push("PUSH(" + opcode + ")");
      offset += opcode;
      continue;
    }
    tokens.push(hodlOpcodeName(opcode));
  }
  return tokens;
}

export function hodlLooksOrdEnvelope(script) {
  if (!script || script.length < 6) return false;
  return script[0] === 0 && script[1] === 99 && script[2] === 3 && script[3] === 111 && script[4] === 114 && script[5] === 100;
}

export function hodlTapWitnessPath(items) {
  if (!items || !items.length) return { path: "empty", annex: null, control: null, script: null };
  const stack = items.slice();
  let annex = null;
  // BIP-341: only with at least two witness elements may the last element be
  // the annex — a lone 0x50-prefixed element is a key-path signature, not an
  // annex (same rule as psbt-wasm/src/verify.rs).
  if (stack.length >= 2 && stack[stack.length - 1].length && stack[stack.length - 1][0] === 0x50) annex = stack.pop();
  if (stack.length === 1 && stack[0].length >= 64 && stack[0].length <= 65) {
    return { path: "key", annex, control: null, script: null };
  }
  if (stack.length >= 2) {
    const control = hodlControlBlock(stack[stack.length - 1]);
    if (control) return { path: "script", annex, control, script: stack[stack.length - 2] };
  }
  return { path: "unknown", annex, control: null, script: null };
}
