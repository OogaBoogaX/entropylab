// Signer availability report for the PSBT Inspector. Read only: nothing here
// signs, and nothing it computes feeds a check, a verdict or a button.
// Pure: no DOM, no network, no randomness.
import { hash160, sha256 } from "./hashes.js";

export const SIGNER_REPORT_GAP = 20;
export const SIGNER_REPORT_STEP_BUDGET = 8192;
export const SIGNER_REPORT_ROW_LIMIT = 100;

const HARDENED = 0x80000000;

const isBytes = (value) => value instanceof Uint8Array;

const eq = (a, b) => {
  if (!isBytes(a) || !isBytes(b) || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
};

const toHex = (bytes) => {
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, "0");
  return out;
};

const readU32BE = (bytes, offset) =>
  ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;

const readU32LE = (bytes, offset) =>
  (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;

const isPubkey = (bytes) =>
  isBytes(bytes) && ((bytes.length === 33 && (bytes[0] === 2 || bytes[0] === 3)) || (bytes.length === 65 && bytes[0] === 4));

const firstUnkeyed = (entries, type) => {
  for (const entry of entries) {
    if (entry && entry.type === type && isBytes(entry.keydata) && entry.keydata.length === 0 && isBytes(entry.val)) return entry.val;
  }
  return null;
};

export function signerReportFallbackPaths(network) {
  const coin = network === "mainnet" ? 0 : 1;
  const h = (n) => n + HARDENED;
  return [
    { label: `m/44h/${coin}h/0h`, path: [h(44), h(coin), h(0)] },
    { label: `m/49h/${coin}h/0h`, path: [h(49), h(coin), h(0)] },
    { label: `m/84h/${coin}h/0h`, path: [h(84), h(coin), h(0)] },
    { label: `m/48h/${coin}h/0h/1h`, path: [h(48), h(coin), h(0), h(1)] },
    { label: `m/48h/${coin}h/0h/2h`, path: [h(48), h(coin), h(0), h(2)] },
    { label: `m/87h/${coin}h/0h`, path: [h(87), h(coin), h(0)] },
    { label: `m/45h`, path: [h(45)] },
  ];
}

function parseMultisig(script, allowUncompressed) {
  if (!isBytes(script) || script.length < 4) return null;
  const mOp = script[0];
  if (mOp < 0x51 || mOp > 0x60) return null;
  const m = mOp - 0x50;
  let offset = 1;
  const keys = [];
  while (offset < script.length) {
    const op = script[offset];
    if (op === 0x21) {
      if (offset + 34 > script.length) return null;
      const key = script.slice(offset + 1, offset + 34);
      if (key[0] !== 2 && key[0] !== 3) return null;
      keys.push(key);
      offset += 34;
    } else if (op === 0x41 && allowUncompressed) {
      if (offset + 66 > script.length) return null;
      const key = script.slice(offset + 1, offset + 66);
      if (key[0] !== 4) return null;
      keys.push(key);
      offset += 66;
    } else break;
  }
  if (offset + 2 !== script.length) return null;
  const nOp = script[offset];
  if (nOp < 0x51 || nOp > 0x60) return null;
  const n = nOp - 0x50;
  if (script[offset + 1] !== 0xae) return null;
  if (keys.length !== n) return null;
  if (!(1 <= m && m <= n && n <= 16)) return null;
  const seen = new Set();
  for (const key of keys) {
    const hex = toHex(key);
    if (seen.has(hex)) return { error: "repeated-keys" };
    seen.add(hex);
  }
  return { m, n, keys };
}

export function signerReportPolicy(input) {
  const entries = Array.isArray(input?.entries) ? input.entries : [];
  if (entries.some((entry) => entry && (entry.type === 7 || entry.type === 8) && isBytes(entry.keydata) && entry.keydata.length === 0)) {
    return { kind: "finalized" };
  }
  if (input?.prevoutConflict) return { kind: "unknown", reason: "prevout-conflict" };
  const prevout = input?.prevout;
  if (!prevout || !isBytes(prevout.script)) return { kind: "unknown", reason: "no-prevout" };
  const script = prevout.script;
  const redeem = firstUnkeyed(entries, 4);
  const witness = firstUnkeyed(entries, 5);

  if (script.length === 34 && script[0] === 0x51 && script[1] === 0x20) {
    return { kind: "unsupported", reason: "taproot" };
  }
  if (script.length === 25 && script[0] === 0x76 && script[1] === 0xa9 && script[2] === 0x14 && script[23] === 0x88 && script[24] === 0xac) {
    return { kind: "single", script: "p2pkh", hash: script.slice(3, 23), compressedOnly: false, m: 1, n: 1 };
  }
  if (script.length === 22 && script[0] === 0x00 && script[1] === 0x14) {
    return { kind: "single", script: "p2wpkh", hash: script.slice(2, 22), compressedOnly: true, m: 1, n: 1 };
  }
  if (script.length === 23 && script[0] === 0xa9 && script[1] === 0x14 && script[22] === 0x87) {
    if (!redeem) return { kind: "unknown", reason: "no-script" };
    if (!eq(hash160(redeem), script.slice(2, 22))) return { kind: "unknown", reason: "script-mismatch" };
    if (redeem.length === 22 && redeem[0] === 0x00 && redeem[1] === 0x14) {
      return { kind: "single", script: "p2sh-p2wpkh", hash: redeem.slice(2, 22), compressedOnly: true, m: 1, n: 1 };
    }
    if (redeem.length === 34 && redeem[0] === 0x00 && redeem[1] === 0x20) {
      if (!witness) return { kind: "unknown", reason: "no-script" };
      if (!eq(sha256(witness), redeem.slice(2, 34))) return { kind: "unknown", reason: "script-mismatch" };
      const parsed = parseMultisig(witness, false);
      if (!parsed) return { kind: "unsupported", reason: "script-type" };
      if (parsed.error) return { kind: "unsupported", reason: parsed.error };
      return { kind: "multi", script: "p2sh-p2wsh", m: parsed.m, n: parsed.n, keys: parsed.keys };
    }
    const parsed = parseMultisig(redeem, true);
    if (!parsed) return { kind: "unsupported", reason: "script-type" };
    if (parsed.error) return { kind: "unsupported", reason: parsed.error };
    return { kind: "multi", script: "p2sh", m: parsed.m, n: parsed.n, keys: parsed.keys };
  }
  if (script.length === 34 && script[0] === 0x00 && script[1] === 0x20) {
    if (!witness) return { kind: "unknown", reason: "no-script" };
    if (!eq(sha256(witness), script.slice(2, 34))) return { kind: "unknown", reason: "script-mismatch" };
    const parsed = parseMultisig(witness, false);
    if (!parsed) return { kind: "unsupported", reason: "script-type" };
    if (parsed.error) return { kind: "unsupported", reason: parsed.error };
    return { kind: "multi", script: "p2wsh", m: parsed.m, n: parsed.n, keys: parsed.keys };
  }
  return { kind: "unsupported", reason: "script-type" };
}

// Derives `steps` from `start`, spending one budget unit per child. Returns
// the final node plus every node it created (the caller wipes them), or null
// on a throw or an exhausted budget. Never wipes `start`.
function deriveSteps(state, start, steps) {
  let node = start;
  const owned = [];
  try {
    for (const step of steps) {
      if (state.budget <= 0) {
        state.exhausted = true;
        return null;
      }
      state.budget -= 1;
      const next = node.deriveChild(step);
      if (node !== start) owned.push(node);
      node = next;
    }
    if (node !== start) owned.push(node);
    return { node, owned };
  } catch {
    if (node !== start && !owned.includes(node)) owned.push(node);
    for (const child of owned) try { child.wipePrivateData(); } catch {}
    return null;
  }
}

function sourceCacheKey(source) {
  const node = source.node;
  if (!node) return null;
  let chainCode, publicKey;
  try {
    chainCode = node.chainCode;
    publicKey = node.publicKey;
  } catch {
    return null;
  }
  if (!isBytes(chainCode) || !isBytes(publicKey)) return null;
  const input = new Uint8Array(chainCode.length + publicKey.length);
  input.set(chainCode, 0);
  input.set(publicKey, chainCode.length);
  const digest = sha256(input);
  chainCode.fill(0);
  input.fill(0);
  return toHex(digest) + (source.private === true ? ":p" : ":u");
}

function buildFallbackIndex(state, source, network) {
  const node = source.node;
  if (!node) return null;
  const map = new Map();
  const record = (leaf, label) => {
    try {
      const pubkey = leaf.publicKey;
      if (!isBytes(pubkey)) return;
      map.set(toHex(pubkey), { label, pubkey });
      map.set(toHex(hash160(pubkey)), { label, pubkey });
    } catch {}
  };
  const branches = [0, 1];
  const indexes = Array.from({ length: SIGNER_REPORT_GAP }, (_, i) => i);
  const scan = (start, labelFor) => {
    for (const branch of branches) {
      const branchChain = deriveSteps(state, start, [branch]);
      if (!branchChain) continue;
      try {
        for (const index of indexes) {
          const leaf = deriveSteps(state, branchChain.node, [index]);
          if (!leaf) continue;
          try {
            record(leaf.node, labelFor(branch, index));
          } finally {
            for (const child of leaf.owned) try { child.wipePrivateData(); } catch {}
          }
        }
      } finally {
        for (const child of branchChain.owned) try { child.wipePrivateData(); } catch {}
      }
    }
  };
  if (node.depth === 0) {
    for (const entry of signerReportFallbackPaths(network)) {
      if (source.private !== true && entry.path.some((step) => step >= HARDENED)) continue;
      const account = deriveSteps(state, node, entry.path);
      if (!account) continue;
      try {
        scan(account.node, (branch, index) => `${entry.label}/${branch}/${index}`);
      } finally {
        for (const child of account.owned) try { child.wipePrivateData(); } catch {}
      }
    }
  } else {
    scan(node, (branch, index) => `…/${branch}/${index}`);
  }
  return map;
}

function slotForPubkey(slots, policy, pubkey) {
  if (policy.kind === "multi") return slots.find((slot) => eq(slot.key, pubkey)) ?? null;
  if (policy.kind === "single") {
    if (policy.compressedOnly && pubkey.length !== 33) return null;
    if (!eq(hash160(pubkey), policy.hash)) return null;
    return slots[0];
  }
  return null;
}

export function psbtSignerReport({ inputs, sources, network, verify = () => null, budget = SIGNER_REPORT_STEP_BUDGET }) {
  const state = { budget: Number.isFinite(budget) && budget >= 0 ? budget : SIGNER_REPORT_STEP_BUDGET, exhausted: false };
  const inputList = Array.isArray(inputs) ? inputs : [];

  const seenIds = new Set();
  const uniqueSources = [];
  for (const source of Array.isArray(sources) ? sources : []) {
    if (!source || source.id === undefined || source.id === null) continue;
    const id = String(source.id);
    if (seenIds.has(id)) continue;
    seenIds.add(id);
    uniqueSources.push({ ...source, id });
  }

  const usablePrivate = (source) => source.private === true && (Array.isArray(source.pubkeys) || source.node?.hasPrivateKey === true);
  const hdSources = uniqueSources.filter((source) => source.node && typeof source.node.deriveChild === "function");
  const singleKeySources = uniqueSources.filter((source) => Array.isArray(source.pubkeys));

  const fallbackCache = new Map();
  const getFallbackIndex = (source) => {
    const key = sourceCacheKey(source);
    if (!key) return null;
    if (fallbackCache.has(key)) return fallbackCache.get(key);
    const index = buildFallbackIndex(state, source, network);
    fallbackCache.set(key, index);
    return index;
  };

  const rows = inputList.map((input, index) => {
    const policy = signerReportPolicy(input);
    if (policy.kind === "finalized" || policy.kind === "unknown" || policy.kind === "unsupported") {
      return {
        index, state: policy.kind, reason: policy.reason ?? null, script: null, m: 0, n: 0, all: false,
        signed: 0, invalid: 0, unchecked: 0, canAdd: 0, watchOnly: 0, signers: [], watchers: [],
      };
    }
    const slots = policy.kind === "multi"
      ? policy.keys.map((key) => ({ key, sig: null, private: new Map(), public: new Map() }))
      : [{ key: null, sig: null, private: new Map(), public: new Map() }];
    const entries = Array.isArray(input?.entries) ? input.entries : [];
    const record = (slot, source, path) => {
      if (usablePrivate(source)) slot.private.set(source.id, { label: source.label, path });
      else slot.public.set(source.id, { label: source.label, path });
    };

    for (const entry of entries) {
      if (!entry || entry.type !== 2 || !isPubkey(entry.keydata)) continue;
      const slot = slotForPubkey(slots, policy, entry.keydata);
      if (!slot || slot.sig !== null) continue;
      if (policy.kind === "single" && !slot.key) slot.key = entry.keydata;
      let result;
      try { result = verify(index, entry.keydata, entry.val); } catch { result = null; }
      slot.sig = result === true ? "valid" : result === false ? "invalid" : "unchecked";
    }

    for (const entry of entries) {
      if (!entry || entry.type !== 6 || !isPubkey(entry.keydata)) continue;
      const slot = slotForPubkey(slots, policy, entry.keydata);
      if (!slot) continue;
      if (policy.kind === "single" && !slot.key) slot.key = entry.keydata;
      const val = entry.val;
      if (!isBytes(val) || val.length < 4 || (val.length - 4) % 4 !== 0) continue;
      const fingerprint = readU32BE(val, 0);
      const path = [];
      for (let offset = 4; offset < val.length; offset += 4) path.push(readU32LE(val, offset));
      for (const source of hdSources) {
        const node = source.node;
        try {
          let steps;
          if (node.depth === 0) {
            if (fingerprint !== node.fingerprint) continue;
            steps = path;
          } else {
            if (path.length < 2) continue;
            steps = path.slice(-2);
            if (steps.some((step) => step >= HARDENED)) continue;
          }
          if (source.private !== true && steps.some((step) => step >= HARDENED)) continue;
          if (steps.length > state.budget) {
            state.exhausted = true;
            continue;
          }
          const chain = deriveSteps(state, node, steps);
          if (!chain) continue;
          try {
            const derived = chain.node.publicKey;
            if (derived && eq(derived, entry.keydata)) record(slot, source, null);
          } finally {
            for (const child of chain.owned) try { child.wipePrivateData(); } catch {}
          }
        } catch {}
      }
    }

    for (const source of singleKeySources) {
      for (const slot of slots) {
        if (policy.kind === "multi") {
          if (source.pubkeys.some((pubkey) => eq(pubkey, slot.key))) record(slot, source, null);
        } else {
          for (const pubkey of source.pubkeys) {
            if (!isBytes(pubkey)) continue;
            if (policy.compressedOnly && pubkey.length !== 33) continue;
            if (eq(hash160(pubkey), policy.hash)) {
              record(slot, source, null);
              if (!slot.key) slot.key = pubkey;
              break;
            }
          }
        }
      }
    }

    for (const slot of slots) {
      if (slot.private.size > 0) continue;
      for (const source of hdSources) {
        if (slot.private.has(source.id) || slot.public.has(source.id)) continue;
        const indexMap = getFallbackIndex(source);
        if (!indexMap) continue;
        const hit = policy.kind === "multi" ? indexMap.get(toHex(slot.key)) : indexMap.get(toHex(policy.hash));
        if (hit) {
          record(slot, source, hit.label);
          if (policy.kind === "single" && !slot.key) slot.key = hit.pubkey;
        }
      }
    }

    let signed = 0, invalid = 0, unchecked = 0, canAdd = 0, watchOnly = 0, uncheckedOpen = 0;
    for (const slot of slots) {
      if (slot.sig === "valid") { signed++; continue; }
      if (slot.sig === "invalid") invalid++;
      if (slot.sig === "unchecked") {
        unchecked++;
        if (slot.private.size === 0) uncheckedOpen++;
      }
      if (slot.private.size > 0) canAdd++;
      else if (slot.public.size > 0) watchOnly++;
    }

    let stateName, reason = null, all = false;
    if (signed >= policy.m) {
      stateName = "signed";
    } else if (canAdd >= policy.m - signed) {
      stateName = "ready";
      all = policy.kind === "single" ? true : slots.every((slot) => slot.sig === "valid" || slot.private.size > 0);
    } else if (signed + canAdd + uncheckedOpen >= policy.m) {
      stateName = "unknown";
      reason = "unchecked-signatures";
    } else if (state.exhausted) {
      stateName = "unknown";
      reason = "budget";
    } else {
      stateName = "short";
    }

    const signers = [];
    const signerIds = new Set();
    for (const slot of slots) {
      if (slot.sig === "valid") continue;
      for (const [id, info] of slot.private) {
        if (signerIds.has(id)) continue;
        signerIds.add(id);
        signers.push({ id, label: info.label, path: info.path });
      }
    }
    const watchers = [];
    const watcherIds = new Set();
    for (const slot of slots) {
      if (slot.sig === "valid") continue;
      if (slot.private.size > 0) continue;
      for (const [id, info] of slot.public) {
        if (watcherIds.has(id)) continue;
        watcherIds.add(id);
        watchers.push({ id, label: info.label, path: info.path });
      }
    }

    return {
      index, state: stateName, reason, script: policy.script, m: policy.m, n: policy.n, all,
      signed, invalid, unchecked, canAdd, watchOnly, signers, watchers,
    };
  });

  const summary = { total: rows.length, ready: 0, done: 0, short: 0, unknown: 0 };
  for (const row of rows) {
    if (row.state === "ready") summary.ready++;
    else if (row.state === "signed" || row.state === "finalized") summary.done++;
    else if (row.state === "short") summary.short++;
    else if (row.state === "unknown" || row.state === "unsupported") summary.unknown++;
  }

  return {
    inputs: rows,
    summary,
    searched: { paths: signerReportFallbackPaths(network).map((entry) => entry.label), gap: SIGNER_REPORT_GAP },
    exhausted: state.exhausted,
  };
}
