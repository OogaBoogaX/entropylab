// Match transaction outputs against a session key. Air-gapped: no chain.
// Scripts and addresses come from the rust-bitcoin WASM facade (./addresses.js).
import { addressFor as addressForType, p2pkhScript, p2shP2wpkhScript, p2trKeyScript, p2wpkhScript } from "./addresses.js";

export const OWNERSHIP_GAP = 50;
export const OWNERSHIP_ACCOUNTS = 3;

const SCRIPT_TYPES = [
  { id: "bip44", scriptType: "p2pkh", purpose: 44 },
  { id: "bip49", scriptType: "p2sh-p2wpkh", purpose: 49 },
  { id: "bip84", scriptType: "p2wpkh", purpose: 84 },
  { id: "bip86", scriptType: "p2tr", purpose: 86 },
];

function coinType(network) {
  return network === "testnet" ? 1 : 0;
}

// Accepts raw bytes or a hex string; always returns canonical lowercase hex.
function toHex(bytes) {
  if (!bytes) return "";
  if (typeof bytes === "string") return bytes.replace(/^0x/i, "").toLowerCase();
  const arr = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  let hex = "";
  for (let i = 0; i < arr.length; i++) hex += arr[i].toString(16).padStart(2, "0");
  return hex;
}

// Drop the parity byte of a compressed pubkey to get the x-only internal key;
// p2trKeyScript applies the BIP86 tweak to it.
function xOnlyFromCompressed(pubkey) {
  return pubkey.slice(1);
}

function scriptFor(scriptType, pubkey, network) {
  const compressed = pubkey.length === 33 ? pubkey : null;
  try {
    if (scriptType === "p2pkh") return p2pkhScript(compressed || pubkey);
    if (scriptType === "p2wpkh") return compressed ? p2wpkhScript(compressed) : null;
    if (scriptType === "p2sh-p2wpkh") return compressed ? p2shP2wpkhScript(compressed) : null;
    if (scriptType === "p2tr") return p2trKeyScript(xOnlyFromCompressed(compressed || pubkey));
  } catch {
    return null;
  }
  return null;
}

function addressFor(scriptType, pubkey, network) {
  try {
    return addressForType(scriptType, pubkey, network);
  } catch {
    return null;
  }
}

export function normalizeAddress(value) {
  const text = String(value ?? "").trim();
  if (!text) return "";
  if (/^(bc1|tb1|bcrt1)/i.test(text)) {
    if (/[A-Z]/.test(text) && /[a-z]/.test(text)) return text;
    return text.toLowerCase();
  }
  return text;
}

export function addressFromPubkey(scriptType, pubkey, network) {
  return addressFor(scriptType, pubkey, network);
}

function remember(map, address, meta) {
  if (address) {
    const key = normalizeAddress(address);
    if (key && !map.has(key)) map.set(key, meta);
  }
  if (meta.scriptHex && !map.has(meta.scriptHex)) map.set(meta.scriptHex, meta);
}

function record(map, definition, pubkey, network, extra) {
  const scriptBytes = scriptFor(definition.scriptType, pubkey, network);
  if (!scriptBytes) return;
  const address = addressFor(definition.scriptType, pubkey, network);
  remember(map, address, {
    ...extra,
    scriptType: definition.scriptType,
    bip: definition.id,
    scriptHex: toHex(scriptBytes),
    address: address || "",
  });
}

export function indexSingleKey(priv, network, getPublicKey) {
  const map = new Map();
  if (!priv || !getPublicKey) return map;
  const compressed = getPublicKey(priv, true);
  const uncompressed = getPublicKey(priv, false);
  for (const definition of SCRIPT_TYPES) record(map, definition, compressed, network, {
    role: "key",
    chain: "key",
    index: null,
    path: "session key",
  });
  record(map, SCRIPT_TYPES[0], uncompressed, network, {
    role: "key",
    chain: "key",
    index: null,
    path: "session key (uncompressed)",
  });
  return map;
}

export function indexHdKey(root, network, options = {}) {
  const map = new Map();
  if (!root) return map;
  const gap = Number.isFinite(options.gap) ? options.gap : OWNERSHIP_GAP;
  const accounts = Number.isFinite(options.accounts) ? options.accounts : OWNERSHIP_ACCOUNTS;
  const coin = coinType(network);
  const scanAccountNode = (node, pathPrefix, account) => {
    for (const definition of SCRIPT_TYPES) {
      for (const [chain, role] of [[0, "receive"], [1, "change"]]) {
        for (let index = 0; index < gap; index++) {
          let child;
          try {
            child = node.derive(`m/${chain}/${index}`);
          } catch {
            continue;
          }
          const pubkey = child.publicKey;
          if (!pubkey) continue;
          record(map, definition, pubkey, network, {
            role,
            chain: role,
            index,
            account,
            path: `${pathPrefix}/${chain}/${index}`,
          });
        }
      }
    }
  };
  if (root.depth && root.depth !== 0) {
    scanAccountNode(root, "m", null);
    return map;
  }
  for (const definition of SCRIPT_TYPES) {
    for (let account = 0; account < accounts; account++) {
      let node;
      try {
        node = root.derive(`m/${definition.purpose}'/${coin}'/${account}'`);
      } catch {
        continue;
      }
      for (const [chain, role] of [[0, "receive"], [1, "change"]]) {
        for (let index = 0; index < gap; index++) {
          let child;
          try {
            child = node.derive(`m/${chain}/${index}`);
          } catch {
            continue;
          }
          const pubkey = child.publicKey;
          if (!pubkey) continue;
          record(map, definition, pubkey, network, {
            role,
            chain: role,
            index,
            account,
            path: `m/${definition.purpose}h/${coin}h/${account}h/${chain}/${index}`,
          });
        }
      }
    }
  }
  return map;
}

export function matchOwnership(map, addressOrScript) {
  if (!map || !map.size) return { state: "no-session" };
  if (addressOrScript instanceof Uint8Array) {
    const hit = map.get(toHex(addressOrScript));
    if (hit) return { state: "ours", ...hit };
    return { state: "external", searched: map.size };
  }
  const key = normalizeAddress(addressOrScript);
  if (!key) return { state: "empty" };
  if (key.startsWith("script ")) {
    const hex = key.slice(7).replace(/\s/g, "").toLowerCase();
    const hit = map.get(hex);
    if (hit) return { state: "ours", ...hit };
  }
  const hit = map.get(key);
  if (!hit) return { state: "external", searched: map.size };
  return { state: "ours", ...hit };
}

export function pathLabel(path) {
  if (!Array.isArray(path)) return "";
  return path.map((index) => (index & 0x80000000) ? `${index & 0x7fffffff}h` : String(index)).join("/");
}

export { SCRIPT_TYPES };
