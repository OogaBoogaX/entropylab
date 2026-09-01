// BIP-352 Silent Payments calculator.
// Deterministic only: same inputs → same outputs. No entropy is invented.
// Curve ops go through the libsecp256k1 WASM facade (./secp256k1.js),
// hashes through the bitcoin_hashes WASM facade (./hashes.js).
import { hash160, sha256 } from "./hashes.js";
import { bech32mDecode, bech32mEncode, fromWords, toWords } from "./bech32.js";
import { HDKey } from "./hdkey.js";
import { secp256k1 } from "./secp256k1.js";

export const BIP352_PURPOSE = 352;
export const BIP352_K_MAX = 2323;
export const BIP352_BECH32_LIMIT = 1023;
export const NUMS_H = Uint8Array.from(
  "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0".match(/../g).map((b) => parseInt(b, 16)),
);
const ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const Point = secp256k1.Point;

const textEncoder = new TextEncoder();
const hexToBytes = (hex) => {
  if (typeof hex !== "string" || hex.length % 2 || /[^0-9a-f]/i.test(hex)) throw new Error("Invalid hexadecimal input.");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
};
const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const bytesToBig = (bytes) => BigInt("0x" + bytesToHex(bytes));
const bigToBytes32 = (value) => {
  if (value < 0n) throw new Error("Negative scalar.");
  const hex = value.toString(16).padStart(64, "0");
  if (hex.length > 64) throw new Error("Scalar does not fit in 32 bytes.");
  return hexToBytes(hex);
};
const equalBytes = (a, b) => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
};

export function taggedHash(tag, ...chunks) {
  const tagHash = sha256(textEncoder.encode(tag));
  let total = 64;
  for (const chunk of chunks) total += chunk.length;
  const bytes = new Uint8Array(total);
  bytes.set(tagHash, 0);
  bytes.set(tagHash, 32);
  let offset = 64;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return sha256(bytes);
}

export function serUint32(value) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) throw new Error("ser32 value out of range.");
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

const scalarFromBytes = (bytes) => {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) throw new Error("Scalar must be 32 bytes.");
  const value = bytesToBig(bytes);
  if (value === 0n || value >= ORDER) throw new Error("Scalar is out of the secp256k1 range.");
  return value;
};

const reduceScalar = (value) => {
  const n = ((value % ORDER) + ORDER) % ORDER;
  if (n === 0n) throw new Error("Scalar is out of the secp256k1 range.");
  return n;
};

const pointFromBytes = (bytes) => Point.fromBytes(bytes);
const pointFromXOnly = (xonly) => {
  if (!(xonly instanceof Uint8Array) || xonly.length !== 32) throw new Error("X-only public key must be 32 bytes.");
  const compressed = new Uint8Array(33);
  compressed[0] = 0x02;
  compressed.set(xonly, 1);
  return Point.fromBytes(compressed);
};
const pointToCompressed = (point) => point.toBytes(true);
const pointToXOnly = (point) => point.toBytes(true).slice(1);
const pointHasEvenY = (point) => point.toBytes(true)[0] === 0x02;
const negatePoint = (point) => {
  const bytes = point.toBytes(true);
  bytes[0] = bytes[0] === 2 ? 3 : 2;
  return Point.fromBytes(bytes);
};
const pointMultiply = (point, scalar) => point.multiply(reduceScalar(scalar));
const pointAdd = (a, b) => {
  try {
    return a.add(b);
  } catch {
    return null;
  }
};
const sumPoints = (points) => {
  let acc = null;
  for (const point of points) {
    if (!point) continue;
    acc = acc ? pointAdd(acc, point) : point;
  }
  return acc;
};

const readCompactSize = (bytes, offset) => {
  if (offset >= bytes.length) throw new Error("Witness ended early.");
  const first = bytes[offset];
  if (first < 0xfd) return [first, offset + 1];
  if (first === 0xfd) {
    if (offset + 3 > bytes.length) throw new Error("Witness ended inside a compact size.");
    const value = bytes[offset + 1] | (bytes[offset + 2] << 8);
    if (value < 0xfd) throw new Error("Non-minimal compact size.");
    return [value, offset + 3];
  }
  if (first === 0xfe) {
    if (offset + 5 > bytes.length) throw new Error("Witness ended inside a compact size.");
    const value = bytes[offset + 1] | (bytes[offset + 2] << 8) | (bytes[offset + 3] << 16) | (bytes[offset + 4] << 24);
    if (value < 0x10000) throw new Error("Non-minimal compact size.");
    return [value >>> 0, offset + 5];
  }
  throw new Error("Witness compact size is too large.");
};

export function parseWitnessHex(hex) {
  if (!hex) return [];
  const bytes = hexToBytes(hex);
  let offset = 0;
  const [count, afterCount] = readCompactSize(bytes, offset);
  offset = afterCount;
  const stack = [];
  for (let i = 0; i < count; i++) {
    const [length, afterLength] = readCompactSize(bytes, offset);
    offset = afterLength;
    if (offset + length > bytes.length) throw new Error("Witness item overruns the buffer.");
    stack.push(bytes.slice(offset, offset + length));
    offset += length;
  }
  return stack;
}

export function serializeOutpoint(txid, vout) {
  const hash = hexToBytes(txid);
  if (hash.length !== 32) throw new Error("Outpoint txid must be 32 bytes.");
  if (!Number.isInteger(vout) || vout < 0 || vout > 0xffffffff) throw new Error("Outpoint vout out of range.");
  const out = new Uint8Array(36);
  for (let i = 0; i < 32; i++) out[i] = hash[31 - i];
  out[32] = vout & 0xff;
  out[33] = (vout >>> 8) & 0xff;
  out[34] = (vout >>> 16) & 0xff;
  out[35] = (vout >>> 24) & 0xff;
  return out;
}

export const isP2pkh = (spk) => spk.length === 25 && spk[0] === 0x76 && spk[1] === 0xa9 && spk[2] === 0x14 && spk[23] === 0x88 && spk[24] === 0xac;
export const isP2sh = (spk) => spk.length === 23 && spk[0] === 0xa9 && spk[1] === 0x14 && spk[22] === 0x87;
export const isP2wpkh = (spk) => spk.length === 22 && spk[0] === 0x00 && spk[1] === 0x14;
export const isP2tr = (spk) => spk.length === 34 && spk[0] === 0x51 && spk[1] === 0x20;

const compressedPointOrNull = (bytes) => {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 33 || (bytes[0] !== 2 && bytes[0] !== 3)) return null;
  try {
    return Point.fromBytes(bytes);
  } catch {
    return null;
  }
};

export function extractInputPubKey(vin) {
  const prevout = vinPrevoutScript(vin);
  const scriptSig = vin.scriptSig instanceof Uint8Array ? vin.scriptSig : hexToBytes(vin.scriptSig || "");
  const witness = Array.isArray(vin.witness) ? vin.witness : parseWitnessHex(vin.txinwitness || "");
  if (isP2pkh(prevout)) {
    const spkHash = prevout.slice(3, 23);
    for (let i = scriptSig.length; i >= 33; i--) {
      const candidate = scriptSig.slice(i - 33, i);
      if (!equalBytes(hash160(candidate), spkHash)) continue;
      const point = compressedPointOrNull(candidate);
      if (point) return { point, isTaproot: false };
    }
  }
  if (isP2sh(prevout)) {
    const redeem = scriptSig.slice(1);
    if (isP2wpkh(redeem) && witness.length) {
      const point = compressedPointOrNull(witness[witness.length - 1]);
      if (point) return { point, isTaproot: false };
    }
  }
  if (isP2wpkh(prevout) && witness.length) {
    const point = compressedPointOrNull(witness[witness.length - 1]);
    if (point) return { point, isTaproot: false };
  }
  if (isP2tr(prevout) && witness.length) {
    const stack = witness.slice();
    if (stack.length > 1 && stack[stack.length - 1][0] === 0x50) stack.pop();
    if (stack.length > 1) {
      const control = stack[stack.length - 1];
      if (control.length >= 33 && equalBytes(control.slice(1, 33), NUMS_H)) return null;
    }
    try {
      return { point: pointFromXOnly(prevout.slice(2)), isTaproot: true };
    } catch {
      return null;
    }
  }
  return null;
}

export function inputHash(outpoints, sumPoint) {
  if (!outpoints.length) throw new Error("Silent payment input hash needs at least one outpoint.");
  const serialized = outpoints.map((outpoint) => serializeOutpoint(outpoint.txid, outpoint.vout));
  serialized.sort((a, b) => {
    for (let i = 0; i < 36; i++) if (a[i] !== b[i]) return a[i] - b[i];
    return 0;
  });
  return taggedHash("BIP0352/Inputs", serialized[0], pointToCompressed(sumPoint));
}

export function hrpForNetwork(network) {
  return network === "testnet" || network === "signet" || network === "regtest" ? "tsp" : "sp";
}

export function encodeSilentPaymentAddress(scanPoint, spendPoint, hrp = "sp", version = 0) {
  if (version < 0 || version > 30) throw new Error("Silent payment address version must be 0–30.");
  const payload = new Uint8Array(66);
  payload.set(pointToCompressed(scanPoint), 0);
  payload.set(pointToCompressed(spendPoint), 33);
  const words = [version, ...toWords(payload)];
  return bech32mEncode(hrp, words);
}

export function decodeSilentPaymentAddress(address, expectedHrp) {
  if (typeof address !== "string" || !address) throw new Error("Silent payment address is empty.");
  const lower = address.toLowerCase();
  const decoded = bech32mDecode(lower);
  if (!decoded) throw new Error("Not a Bech32m silent payment address.");
  const { prefix: hrp, words } = decoded;
  if (expectedHrp && hrp !== expectedHrp) throw new Error(`Silent payment address HRP is ${hrp}, expected ${expectedHrp}.`);
  if (hrp !== "sp" && hrp !== "tsp") throw new Error(`Unknown silent payment HRP: ${hrp}.`);
  if (!words.length) throw new Error("Silent payment address has no data.");
  const version = words[0];
  if (version === 31) throw new Error("Silent payment address version 31 is reserved.");
  if (version > 30) throw new Error("Silent payment address version is unsupported.");
  const payload = fromWords(words.slice(1));
  if (version === 0 && payload.length !== 66) throw new Error("Silent payment v0 address payload must be 66 bytes.");
  if (payload.length < 66) throw new Error("Silent payment address payload is too short.");
  return {
    hrp,
    version,
    scan: pointFromBytes(payload.slice(0, 33)),
    spend: pointFromBytes(payload.slice(33, 66)),
  };
}

export function generateLabel(scanPriv, m) {
  const scalar = scanPriv instanceof Uint8Array ? scalarFromBytes(scanPriv) : scanPriv;
  return scalarFromBytes(taggedHash("BIP0352/Label", bigToBytes32(scalar), serUint32(m)));
}

export function labeledSpendPoint(scanPriv, spendPoint, m) {
  const label = generateLabel(scanPriv, m);
  const tweak = Point.BASE.multiply(label);
  const labeled = pointAdd(spendPoint, tweak);
  if (!labeled) throw new Error("Label tweak produced the point at infinity.");
  return labeled;
}

export function createLabeledSilentPaymentAddress(scanPriv, spendPoint, m, hrp = "sp") {
  const scanBytes = scanPriv instanceof Uint8Array ? scanPriv : bigToBytes32(scanPriv);
  const scanPoint = Point.fromBytes(secp256k1.getPublicKey(scanBytes, true));
  return encodeSilentPaymentAddress(scanPoint, labeledSpendPoint(scanBytes, spendPoint, m), hrp);
}

export function deriveSilentPaymentKeys(masterSeed, { coinType = 0, account = 0 } = {}) {
  if (!(masterSeed instanceof Uint8Array) || !masterSeed.length) throw new Error("BIP-352 derivation needs a BIP32 master seed.");
  if (!Number.isInteger(coinType) || coinType < 0 || coinType > 0x7fffffff) throw new Error("coin_type is out of range.");
  if (!Number.isInteger(account) || account < 0 || account > 0x7fffffff) throw new Error("account is out of range.");
  const root = HDKey.fromMasterSeed(masterSeed);
  if (!root.privateKey) throw new Error("Watch-only keys cannot derive BIP-352 scan/spend paths (they are hardened).");
  const scanPath = `m/${BIP352_PURPOSE}'/${coinType}'/${account}'/1'/0`;
  const spendPath = `m/${BIP352_PURPOSE}'/${coinType}'/${account}'/0'/0`;
  const scanNode = root.derive(scanPath);
  const spendNode = root.derive(spendPath);
  if (!scanNode.privateKey || !spendNode.privateKey) throw new Error("BIP-352 child keys are missing private material.");
  const scanPriv = scanNode.privateKey.slice();
  const spendPriv = spendNode.privateKey.slice();
  const scanPub = secp256k1.getPublicKey(scanPriv, true);
  const spendPub = secp256k1.getPublicKey(spendPriv, true);
  const keys = {
    coinType,
    account,
    scanPath,
    spendPath,
    scanPriv,
    spendPriv,
    scanPub,
    spendPub,
    scanPoint: Point.fromBytes(scanPub),
    spendPoint: Point.fromBytes(spendPub),
    fingerprint: root.fingerprint,
  };
  // The result owns fresh slices; the derivation nodes are dead copies.
  scanNode.wipePrivateData();
  spendNode.wipePrivateData();
  root.wipePrivateData();
  return keys;
}

const encodeKeyExpression = (hrp, payload) => {
  const words = [0, ...toWords(payload)];
  return bech32mEncode(hrp, words);
};

export function encodeSpscan(scanPriv, spendPub, network = "mainnet") {
  const payload = new Uint8Array(65);
  payload.set(scanPriv instanceof Uint8Array ? scanPriv : bigToBytes32(scanPriv), 0);
  payload.set(spendPub, 32);
  try {
    return encodeKeyExpression(network === "mainnet" ? "spscan" : "tspscan", payload);
  } finally {
    payload.fill(0); // embeds the scan private key
  }
}

export function encodeSpspend(scanPriv, spendPriv, network = "mainnet") {
  const payload = new Uint8Array(64);
  payload.set(scanPriv instanceof Uint8Array ? scanPriv : bigToBytes32(scanPriv), 0);
  payload.set(spendPriv instanceof Uint8Array ? spendPriv : bigToBytes32(spendPriv), 32);
  try {
    return encodeKeyExpression(network === "mainnet" ? "spspend" : "tspspend", payload);
  } finally {
    payload.fill(0); // embeds both private keys
  }
}

export function formatSpDescriptor(keyExpression, origin) {
  if (origin) return `sp([${origin}]${keyExpression})`;
  return `sp(${keyExpression})`;
}

export function p2trAddressFromXonly(xonly, network = "mainnet") {
  const key = typeof xonly === "string" ? hexToBytes(xonly) : xonly;
  if (key.length !== 32) throw new Error("Taproot output key must be 32 bytes.");
  const hrp = network === "mainnet" ? "bc" : "tb";
  return bech32mEncode(hrp, [1, ...toWords(key)]);
}

// The prevout's scriptPubKey bytes (BIP352 input-key eligibility tests the
// script type), not the txid/vout pair "prevout" means elsewhere.
const vinPrevoutScript = (vin) => (vin.prevout instanceof Uint8Array ? vin.prevout : hexToBytes(typeof vin.prevout === "string" ? vin.prevout : vin.prevout.scriptPubKey.hex));

const normalizeVin = (vin) => ({
  txid: vin.txid,
  vout: vin.vout,
  scriptSig: vin.scriptSig || "",
  txinwitness: vin.txinwitness || "",
  prevout: vinPrevoutScript(vin),
  private_key: vin.private_key,
});

export function eligibleInputKeys(vins) {
  const pubkeys = [];
  const privkeys = [];
  for (const raw of vins) {
    const vin = normalizeVin(raw);
    const extracted = extractInputPubKey(vin);
    if (!extracted) continue;
    pubkeys.push(extracted);
    if (vin.private_key) {
      privkeys.push({
        scalar: scalarFromBytes(typeof vin.private_key === "string" ? hexToBytes(vin.private_key) : vin.private_key),
        isTaproot: extracted.isTaproot,
      });
    }
  }
  return { pubkeys, privkeys };
}

export function createSilentPaymentOutputs(vins, recipients, { hrp = "sp" } = {}) {
  const { pubkeys, privkeys } = eligibleInputKeys(vins);
  if (!pubkeys.length) return { outputs: [], inputPubKeys: [], inputPrivateKeySum: null, sharedSecrets: [] };
  if (privkeys.length !== pubkeys.length) throw new Error("Sending needs a private key for every eligible input.");
  const negated = privkeys.map(({ scalar, isTaproot }) => {
    let k = scalar;
    if (isTaproot) {
      const pub = Point.fromBytes(secp256k1.getPublicKey(bigToBytes32(k), true));
      if (!pointHasEvenY(pub)) k = ORDER - k;
    }
    return k;
  });
  let aSum = 0n;
  for (const k of negated) aSum = (aSum + k) % ORDER;
  if (aSum === 0n) {
    return {
      outputs: [],
      inputPubKeys: pubkeys.map((entry) => bytesToHex(pointToCompressed(entry.point))),
      inputPrivateKeySum: "0".repeat(64),
      sharedSecrets: [],
    };
  }
  const A = Point.BASE.multiply(aSum);
  const outpoints = vins.map((vin) => ({ txid: vin.txid, vout: vin.vout }));
  const hash = scalarFromBytes(inputHash(outpoints, A));
  const groups = [];
  const groupIndex = new Map();
  for (const recipient of recipients) {
    const count = recipient.count ?? 1;
    if (!Number.isInteger(count) || count < 1) throw new Error("Recipient count must be a positive integer.");
    const decoded = decodeSilentPaymentAddress(recipient.address, hrp);
    const scanHex = bytesToHex(pointToCompressed(decoded.scan));
    let group = groupIndex.get(scanHex);
    if (!group) {
      group = { scan: decoded.scan, scanHex, spends: [], size: 0 };
      groupIndex.set(scanHex, group);
      groups.push(group);
    }
    group.spends.push({ spend: decoded.spend, count });
    group.size += count;
  }
  // The K_max check runs on the summed counts, before any expansion, so a
  // huge pasted count fails instead of allocating an attacker-sized array.
  if (groups.some((group) => group.size > BIP352_K_MAX)) {
    return {
      outputs: [],
      inputPubKeys: pubkeys.map((entry) => bytesToHex(pointToCompressed(entry.point))),
      inputPrivateKeySum: bytesToHex(bigToBytes32(aSum)),
      sharedSecrets: null,
    };
  }
  const ecdhScalar = reduceScalar(hash * aSum);
  const outputs = [];
  const sharedSecrets = [];
  const seenScan = new Set();
  for (const group of groups) {
    const secretPoint = pointMultiply(group.scan, ecdhScalar);
    const secretHex = bytesToHex(pointToCompressed(secretPoint));
    if (!seenScan.has(group.scanHex)) {
      sharedSecrets.push(secretHex);
      seenScan.add(group.scanHex);
    }
    // Per-group expansion is bounded by K_max after the check above.
    let k = 0;
    for (const { spend, count } of group.spends) {
      for (let copy = 0; copy < count; copy++, k++) {
        const tK = scalarFromBytes(taggedHash("BIP0352/SharedSecret", pointToCompressed(secretPoint), serUint32(k)));
        const tweaked = pointAdd(spend, Point.BASE.multiply(tK));
        if (!tweaked) throw new Error("Silent payment output is the point at infinity.");
        outputs.push(bytesToHex(pointToXOnly(tweaked)));
      }
    }
  }
  return {
    outputs: [...new Set(outputs)],
    inputPubKeys: pubkeys.map((entry) => bytesToHex(pointToCompressed(entry.point))),
    inputPrivateKeySum: bytesToHex(bigToBytes32(aSum)),
    sharedSecrets,
  };
}

export function scanSilentPaymentOutputs({ scanPriv, spendPub, vins, outputs, labels = [] }) {
  const scanScalar = scanPriv instanceof Uint8Array ? scalarFromBytes(scanPriv) : scanPriv;
  const spendPoint = spendPub instanceof Uint8Array ? Point.fromBytes(spendPub) : spendPub;
  const { pubkeys } = eligibleInputKeys(vins);
  if (!pubkeys.length) return { outputs: [], inputPubKeySum: null, tweak: null, sharedSecret: null };
  const A = sumPoints(pubkeys.map((entry) => entry.point));
  if (!A) return { outputs: [], inputPubKeySum: null, tweak: null, sharedSecret: null };
  const hashBytes = inputHash(vins.map((vin) => ({ txid: vin.txid, vout: vin.vout })), A);
  const hash = scalarFromBytes(hashBytes);
  const tweakPoint = pointMultiply(A, hash);
  const shared = pointMultiply(A, reduceScalar(hash * scanScalar));
  const labelMap = new Map();
  for (const m of labels) {
    const scalar = generateLabel(scanScalar, m);
    const point = Point.BASE.multiply(scalar);
    labelMap.set(bytesToHex(pointToCompressed(point)), { scalar, m });
  }
  const remaining = outputs.map((item) => (typeof item === "string" ? hexToBytes(item) : item)).map((bytes) => bytes.slice());
  const found = [];
  let k = 0;
  scan: while (k < BIP352_K_MAX) {
    const tK = scalarFromBytes(taggedHash("BIP0352/SharedSecret", pointToCompressed(shared), serUint32(k)));
    const P_k = pointAdd(spendPoint, Point.BASE.multiply(tK));
    if (!P_k) throw new Error("Silent payment scan tweak is the point at infinity.");
    const pkX = pointToXOnly(P_k);
    for (let i = 0; i < remaining.length; i++) {
      const output = remaining[i];
      if (equalBytes(pkX, output)) {
        found.push({ pub_key: bytesToHex(pkX), priv_key_tweak: bytesToHex(bigToBytes32(tK)), label: null });
        remaining.splice(i, 1);
        k += 1;
        continue scan;
      }
      if (labelMap.size) {
        const outputPoint = pointFromXOnly(output);
        let labelPoint = pointAdd(outputPoint, negatePoint(P_k));
        let labelHex = labelPoint ? bytesToHex(pointToCompressed(labelPoint)) : "";
        if (!labelMap.has(labelHex)) {
          labelPoint = pointAdd(negatePoint(outputPoint), negatePoint(P_k));
          labelHex = labelPoint ? bytesToHex(pointToCompressed(labelPoint)) : "";
        }
        if (labelMap.has(labelHex)) {
          const { scalar: labelScalar, m } = labelMap.get(labelHex);
          const P_km = pointAdd(P_k, Point.BASE.multiply(labelScalar));
          found.push({
            pub_key: bytesToHex(pointToXOnly(P_km)),
            priv_key_tweak: bytesToHex(bigToBytes32((tK + labelScalar) % ORDER)),
            label: m,
          });
          remaining.splice(i, 1);
          k += 1;
          continue scan;
        }
      }
    }
    break;
  }
  return {
    outputs: found,
    inputPubKeySum: bytesToHex(pointToCompressed(A)),
    tweak: bytesToHex(pointToCompressed(tweakPoint)),
    sharedSecret: bytesToHex(pointToCompressed(shared)),
  };
}

export function spendPrivForOutput(spendPriv, tweak) {
  const spend = spendPriv instanceof Uint8Array ? scalarFromBytes(spendPriv) : spendPriv;
  const t = tweak instanceof Uint8Array ? scalarFromBytes(tweak) : typeof tweak === "string" ? scalarFromBytes(hexToBytes(tweak)) : tweak;
  let full = (spend + t) % ORDER;
  if (full === 0n) throw new Error("Spend key + tweak is zero.");
  const pub = Point.fromBytes(secp256k1.getPublicKey(bigToBytes32(full), true));
  if (!pointHasEvenY(pub)) full = ORDER - full;
  return bigToBytes32(full);
}

export { hexToBytes, bytesToHex, scalarFromBytes, Point };
